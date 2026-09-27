"""PostgreSQL 端到端集成测试 + 并发回归。

需要运行中的 PostgreSQL 与 FastAPI 依赖：

    DATABASE_URL=postgresql://consent:consent@localhost:5432/consent \\
        python3 -m unittest tests.test_api

缺少 fastapi/psycopg 依赖时自动跳过；PostgreSQL 不可达则报错。
测试直接调用 ASGI 应用（httpx in-process），无需启动 uvicorn。
每个用例使用唯一主体，避免与既有数据冲突。

覆盖：
* 五个核心接口（/decisions/evaluate、/grants、/revocations、/tasks、
  只读产品查询）的 PostgreSQL 端到端：默认查询必须 200 返回 deny/no_grant，
  写入提交、追溯撤销沿血缘传播、只读事务与连接池复用；
* 同一主体写操作的并发回归：咨询锁 + REPEATABLE READ 下不丢写、无 5xx，
  撤销传播与任务登记交错时最终状态一致；
* 可控交错回归（锁顺序语义）：协调连接持有主体会话级咨询锁，借助
  pg_locks 轮询精确安排各写请求进入锁等待队列的次序，验证写事务的
  快照建立在拿到主体锁之后——
    - 撤销先获锁提交：早已排队（请求先于撤销提交到达）的任务登记即
      deny/revoked，不得沿用旧许可快照登记 allow；
    - 任务先获锁登记：撤销响应的 affected_receipts 恰好列出其获得主体锁
      之前已登记且被本次撤销失效的回执，不多不少；
    - 产物阻断状态与 as_of_seq 历史回放保持一致。
"""
import os
import threading
import time
import unittest
import uuid

try:
    from fastapi.testclient import TestClient
    import psycopg
except ImportError:  # pragma: no cover
    TestClient = None
    psycopg = None

if psycopg is not None:
    from app import db
    from app.db import init_pool, shutdown_pool
    from app.main import app


class SubjectLockCoordinator:
    """在独立连接上持有主体会话级咨询锁，阻塞该主体的所有写请求。

    用于确定性交错：先持锁让各写请求进入锁等待队列（通过 pg_locks
    观测），再按既定顺序放行。会话级锁与应用写路径使用的
    ``pg_advisory_lock(hashtext(subject))`` 共用同一锁空间。
    """

    def __init__(self, subject):
        self.subject = subject
        self.ready = threading.Event()
        self._release = threading.Event()
        self._done = threading.Event()
        self.errors: list = []
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        try:
            assert db.pool is not None
            with db.pool.connection() as conn:
                conn.execute("SELECT pg_advisory_lock(hashtext(%s))",
                             (self.subject,))
                conn.commit()
                self.ready.set()
                self._release.wait(timeout=30)
                conn.execute("SELECT pg_advisory_unlock(hashtext(%s))",
                             (self.subject,))
                conn.commit()
        except Exception:  # pragma: no cover - 仅用于暴露协调器故障
            import traceback
            self.errors.append(traceback.format_exc())
            self.ready.set()
        finally:
            self._done.set()

    def __enter__(self):
        self._thread.start()
        if not self.ready.wait(timeout=10):
            raise AssertionError("协调器未能获取主体咨询锁")
        return self

    def release(self):
        self._release.set()

    def __exit__(self, *exc):
        self._release.set()  # 异常路径同样放行，避免协调器空等到超时
        self._done.wait(timeout=10)
        return False


def wait_advisory_waiters(subject, n, timeout=10):
    """轮询 pg_locks，直到该主体咨询锁键上出现 n 个等待中的请求。

    咨询锁键为 ``pg_advisory_lock(hashtext(subject))`` 的 64 位键，
    在 pg_locks 中拆为 classid（高 32 位）与 objid（低 32 位）。
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        with db.pool.connection() as conn:
            cnt = conn.execute(
                """SELECT count(*) AS n FROM pg_locks
                   WHERE locktype='advisory' AND NOT granted
                     AND (classid::bigint << 32 | objid::bigint)
                         = hashtext(%s)::bigint""",
                (subject,)).fetchone()["n"]
        if cnt >= n:
            return
        time.sleep(0.02)
    raise AssertionError(f"等待超时：主体 {subject} 上未出现 {n} 个咨询锁等待者")


@unittest.skipIf(TestClient is None, "缺少 fastapi/psycopg 依赖")
class ApiIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault(
            "DATABASE_URL", "postgresql://consent:consent@localhost:5432/consent")
        for attempt in range(30):
            try:
                init_pool()
                break
            except Exception:
                if attempt == 29:
                    raise
                time.sleep(1)
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        shutdown_pool()

    def setUp(self):
        self.subject = "test-" + uuid.uuid4().hex[:12]
        # 幂等键是全局主键，固定键（t1/a 等）在多次运行 / 共用库上会冲突，
        # 按测试前缀清理上一轮残留，保证测试可独立、重复运行。
        self._cleanup_global_keys()

    def tearDown(self):
        self._cleanup_global_keys()

    def _cleanup_global_keys(self):
        assert db.pool is not None
        with db.pool.connection() as conn:
            # products.task_key 外键引用 receipts：先删产物（血缘行级联）。
            conn.execute(
                "DELETE FROM products WHERE task_key IN "
                "('t1','t2','a','b','c','d','e')")
            # 处置台账表引用 receipts：按固定回执键先清全部追加记录。
            conn.execute(
                """
                DELETE FROM remediation_item_products WHERE item_id IN (
                    SELECT item_id FROM remediation_items
                    WHERE receipt_key IN ('t1','t2','a','b','c','d','e'))
                """)
            conn.execute(
                """
                DELETE FROM remediation_submissions WHERE item_id IN (
                    SELECT item_id FROM remediation_items
                    WHERE receipt_key IN ('t1','t2','a','b','c','d','e'))
                """)
            conn.execute(
                """
                DELETE FROM remediation_reviews WHERE item_id IN (
                    SELECT item_id FROM remediation_items
                    WHERE receipt_key IN ('t1','t2','a','b','c','d','e'))
                """)
            conn.execute(
                """
                DELETE FROM remediation_cancellations WHERE item_id IN (
                    SELECT item_id FROM remediation_items
                    WHERE receipt_key IN ('t1','t2','a','b','c','d','e'))
                """)
            conn.execute(
                "DELETE FROM remediation_items WHERE receipt_key IN "
                "('t1','t2','a','b','c','d','e')")
            conn.execute("DELETE FROM receipts WHERE idempotency_key IN "
                         "('t1','t2','a','b','c','d','e')")

    def _grant(self, gid, **kw):
        body = {"subject_id": self.subject, "grant_id": gid,
                "category": "email", "purpose": "marketing",
                "recipient": "partner-a",
                "valid_from": "2026-01-01T00:00:00Z"}
        body.update(kw)
        r = self.client.post("/grants", json=body)
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()

    def _eval(self, use_at="2026-05-01T00:00:00Z", **extra):
        body = {"subject_id": self.subject, "category": "email",
                "purpose": "marketing", "recipient": "partner-a",
                "use_at": use_at}
        body.update(extra)
        return self.client.post("/decisions/evaluate", json=body)

    def _task(self, key, product=None, groups=None, subject=None, **kw):
        subject = subject or self.subject
        body = {"subject_id": subject, "category": "email",
                "purpose": "marketing", "recipient": "partner-a",
                "use_at": "2026-05-01T00:00:00Z"}
        if product is not None:
            body["products"] = [{"product_id": product,
                                 "groups": groups
                                 or [[{"kind": "receipt", "ref": key}]]}]
        body.update(kw)
        return self.client.post("/tasks", json=body,
                                headers={"Idempotency-Key": key})

    # ------------------------------------------------------ 端到端：默认拒绝
    def test_empty_evaluate_returns_200_deny_no_grant(self):
        """回归核心 500：无事件只读查询必须 200 且 deny/no_grant。"""
        r = self._eval()
        self.assertEqual(r.status_code, 200, r.text)
        data = r.json()
        self.assertEqual(data["decision"], "deny")
        self.assertEqual(data["hit"], "none")
        self.assertEqual(data["basis"]["kind"], "none")
        self.assertEqual(data["basis"]["reason"], "no_grant")

        # 只读查询不得写入任何事件。
        events = self.client.get(
            f"/subjects/{self.subject}/events").json()["events"]
        self.assertEqual(events, [])

    def test_default_deny_then_allow_then_revoke(self):
        self.assertEqual(self._eval().json()["decision"], "deny")
        self._grant("g1")
        self.assertEqual(self._eval().json()["decision"], "allow")

        r = self.client.post("/revocations", json={
            "subject_id": self.subject, "grant_id": "g1",
            "business_effective_at": "2026-01-15T00:00:00Z"})
        self.assertEqual(r.status_code, 201, r.text)
        d = self._eval().json()
        self.assertEqual(d["decision"], "deny")
        self.assertEqual(d["hit"], "revocation")

        # 撤销业务生效时间晚于 use_at，不影响该次使用
        s2 = "test-" + uuid.uuid4().hex[:8]
        body = {"subject_id": s2, "grant_id": "g", "category": "email",
                "purpose": "marketing", "recipient": "partner-a",
                "valid_from": "2026-01-01T00:00:00Z"}
        self.client.post("/grants", json=body)
        self.client.post("/revocations", json={
            "subject_id": s2, "grant_id": "g",
            "business_effective_at": "2026-08-01T00:00:00Z"})
        r = self.client.post("/decisions/evaluate", json={
            "subject_id": s2, "category": "email", "purpose": "marketing",
            "recipient": "partner-a", "use_at": "2026-05-01T00:00:00Z"})
        self.assertEqual(r.json()["decision"], "allow")

    def test_idempotent_task_registration_and_propagation(self):
        g1 = self._grant("g1")
        g2 = self._grant("g2")

        def task(key, product, groups):
            return self.client.post("/tasks", json={
                "subject_id": self.subject, "category": "email",
                "purpose": "marketing", "recipient": "partner-a",
                "use_at": "2026-05-01T00:00:00Z",
                "products": [{"product_id": product, "groups": groups}]},
                headers={"Idempotency-Key": key})

        r1 = task("t1", "p1", [[{"kind": "receipt", "ref": "t1"}]])
        self.assertEqual(r1.status_code, 201, r1.text)
        self.assertEqual(r1.json()["receipt"]["decision"], "allow")
        self.assertEqual(r1.json()["receipt"]["basis_grant_id"], "g2")
        self.assertEqual(r1.json()["products"][0]["status"], "active")

        # p2 有两组替代依据：t1 或 t2
        r2 = task("t2", "p2", [[{"kind": "receipt", "ref": "t1"}],
                               [{"kind": "receipt", "ref": "t2"}]])
        self.assertEqual(r2.status_code, 201, r2.text)

        # 幂等：同 key 同负载 -> 200 + replay
        r1b = task("t1", "p1", [[{"kind": "receipt", "ref": "t1"}]])
        self.assertEqual(r1b.status_code, 200)
        self.assertTrue(r1b.json()["idempotent_replay"])

        # 幂等冲突：同 key 不同负载
        rc = self.client.post("/tasks", json={
            "subject_id": self.subject, "category": "email",
            "purpose": "other", "recipient": "partner-a",
            "use_at": "2026-05-01T00:00:00Z"},
            headers={"Idempotency-Key": "t1"})
        self.assertEqual(rc.status_code, 409)

        # 撤销旧许可 g1：命中的是 g2，产物仍存活
        self.client.post("/revocations", json={
            "subject_id": self.subject, "grant_id": "g1",
            "business_effective_at": "2026-01-15T00:00:00Z"})
        st = self.client.get(
            f"/subjects/{self.subject}/products/p2").json()
        self.assertEqual(st["status"], "active")

        # 撤销命中的 g2：p1 阻断；p2 两组皆失效才阻断
        rev = self.client.post("/revocations", json={
            "subject_id": self.subject, "grant_id": "g2",
            "business_effective_at": "2026-01-15T00:00:00Z"}).json()
        rev_seq = rev["event"]["seq"]

        p1 = self.client.get(
            f"/subjects/{self.subject}/products/p1").json()
        self.assertEqual(p1["status"], "blocked")
        self.assertEqual(p1["invalidating_events"], [rev_seq])

        p2 = self.client.get(
            f"/subjects/{self.subject}/products/p2").json()
        self.assertEqual(p2["status"], "blocked")
        self.assertEqual(p2["invalidating_events"], [rev_seq])
        self.assertIn("explanation", p2)

        # 回执查询同样反映追溯失效。
        receipt = self.client.get("/receipts/t1").json()
        self.assertEqual(receipt["decision"], "allow")
        self.assertFalse(receipt["currently_valid"])
        self.assertEqual(receipt["invalidating_events"], [rev_seq])

        # 历史回放：回到 g2 撤销之前 -> 旧记录仍 active
        old = self.client.get(
            f"/subjects/{self.subject}/products/p1?as_of_seq={rev_seq - 1}"
        ).json()
        self.assertEqual(old["status"], "active")

        # 事件登记处只增不改：许可/撤销数量与序号单调
        events = self.client.get(
            f"/subjects/{self.subject}/events").json()["events"]
        seqs = [e["seq"] for e in events]
        self.assertEqual(seqs, sorted(seqs))
        self.assertGreaterEqual(len(events), 4)

    def test_product_lineage_chain_and_cycle_rejected(self):
        self._grant("g1")
        def task(key, product, groups):
            return self.client.post("/tasks", json={
                "subject_id": self.subject, "category": "email",
                "purpose": "marketing", "recipient": "partner-a",
                "use_at": "2026-05-01T00:00:00Z",
                "products": [{"product_id": product, "groups": groups}]},
                headers={"Idempotency-Key": key})

        self.assertEqual(task("a", "pa",
                              [[{"kind": "receipt", "ref": "a"}]]).status_code,
                         201)
        self.assertEqual(task("b", "pb",
                              [[{"kind": "product", "ref": "pa"}]]).status_code,
                         201)
        # 同批声明的新产物互相引用，合法 DAG
        r = self.client.post("/tasks", json={
            "subject_id": self.subject, "category": "email",
            "purpose": "marketing", "recipient": "partner-a",
            "use_at": "2026-05-01T00:00:00Z",
            "products": [
                {"product_id": "pc", "groups": [[{"kind": "product",
                                                  "ref": "pd"}]]},
                {"product_id": "pd", "groups": [[{"kind": "receipt",
                                                  "ref": "b"}]]}]},
            headers={"Idempotency-Key": "c"})
        self.assertEqual(r.status_code, 201, r.text)

        # 引用未知产物 -> 422
        r = task("d", "pe", [[{"kind": "product", "ref": "nope"}]])
        self.assertEqual(r.status_code, 422)

        # 自环 -> 422
        r = task("e", "pf", [[{"kind": "product", "ref": "pf"}]])
        self.assertEqual(r.status_code, 422)

    def test_half_open_window(self):
        self._grant("g1", valid_from="2026-01-01T00:00:00Z",
                    valid_to="2026-06-01T00:00:00Z")
        self.assertEqual(
            self._eval("2026-05-31T23:59:59Z").json()["decision"], "allow")
        # 上界排除
        self.assertEqual(
            self._eval("2026-06-01T00:00:00Z").json()["decision"], "deny")

        # 非法半开区间
        r = self.client.post("/grants", json={
            "subject_id": self.subject + "-x", "grant_id": "gx",
            "category": "email", "purpose": "marketing",
            "recipient": "partner-a",
            "valid_from": "2026-06-01T00:00:00Z",
            "valid_to": "2026-01-01T00:00:00Z"})
        self.assertEqual(r.status_code, 422)

    def test_revoke_unknown_grant_404_and_duplicate_grant_409(self):
        r = self.client.post("/revocations", json={
            "subject_id": self.subject, "grant_id": "ghost",
            "business_effective_at": "2026-01-01T00:00:00Z"})
        self.assertEqual(r.status_code, 404)

        self._grant("dup")
        r = self.client.post("/grants", json={
            "subject_id": self.subject, "grant_id": "dup",
            "category": "email", "purpose": "marketing",
            "recipient": "partner-a",
            "valid_from": "2026-01-01T00:00:00Z"})
        self.assertEqual(r.status_code, 409)

    # ------------------------------------------------ 端到端：deny 回执登记
    def test_deny_task_without_grant_is_persisted_and_blocks_lineage(self):
        """无许可登记任务：201 落库 deny/no_grant，回执可查并阻断下游。"""
        tag = self.subject[-6:]
        key = f"deny-{tag}"
        r = self._task(key, f"denyp-{tag}",
                       [[{"kind": "receipt", "ref": key}]])
        self.assertEqual(r.status_code, 201, r.text)
        body = r.json()
        self.assertFalse(body["idempotent_replay"])
        self.assertEqual(body["receipt"]["decision"], "deny")
        self.assertEqual(body["receipt"]["basis_reason"], "no_grant")
        self.assertFalse(body["receipt"]["currently_valid"])
        self.assertEqual(body["products"][0]["status"], "blocked")
        self.assertEqual(body["products"][0]["invalidating_events"], [])

        # 独立只读接口验证提交确实落库。
        got = self.client.get(f"/receipts/{key}")
        self.assertEqual(got.status_code, 200, got.text)
        self.assertEqual(got.json()["decision"], "deny")
        prod = self.client.get(
            f"/subjects/{self.subject}/products/denyp-{tag}").json()
        self.assertEqual(prod["status"], "blocked")

    # ------------------------------------------ 事务属性与连接池复用回归
    def test_transaction_settings_and_pool_reuse(self):
        """REPEATABLE READ + 只读属性在真实连接上生效，且不跨复用泄漏。"""
        assert db.pool is not None
        # 只读事务：PostgreSQL 拒绝写操作，隔离级别为 repeatable read。
        with db.transaction(read_only=True) as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT current_setting('transaction_isolation') AS x"
                ).fetchone()["x"],
                "repeatable read")
            self.assertEqual(
                conn.execute(
                    "SELECT current_setting('transaction_read_only') AS x"
                ).fetchone()["x"],
                "on")
            with self.assertRaises(psycopg.errors.ReadOnlySqlTransaction):
                conn.execute(
                    "CREATE TEMP TABLE pool_leak_probe(x int)")

        # 读写事务：连接池复用同一连接后不得残留只读 / 隔离属性
        # （写成功即证明 READ ONLY 没有泄漏）。
        with db.transaction() as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT current_setting('transaction_read_only') AS x"
                ).fetchone()["x"],
                "off")
            conn.execute(
                "CREATE TEMP TABLE pool_leak_probe(x int)")
            conn.execute("INSERT INTO pool_leak_probe VALUES (1)")
            self.assertEqual(
                conn.execute("SELECT count(*) AS n FROM pool_leak_probe"
                             ).fetchone()["n"], 1)

        # 归还后再次以只读方式取出，属性仍能被重新正确设置（幂等）。
        with db.transaction(read_only=True) as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT current_setting('transaction_read_only') AS x"
                ).fetchone()["x"],
                "on")

    def test_failed_write_rolls_back_and_connection_is_reusable(self):
        """写事务冲突回滚：唯一索引冲突后同主体仍可继续登记其他许可。"""
        self._grant("g1")
        dup = self.client.post("/grants", json={
            "subject_id": self.subject, "grant_id": "g1",
            "category": "email", "purpose": "marketing",
            "recipient": "partner-a",
            "valid_from": "2026-01-01T00:00:00Z"})
        self.assertEqual(dup.status_code, 409)
        ok = self.client.post("/grants", json={
            "subject_id": self.subject, "grant_id": "g2",
            "category": "email", "purpose": "marketing",
            "recipient": "partner-a",
            "valid_from": "2026-01-01T00:00:00Z"})
        self.assertEqual(ok.status_code, 201, ok.text)
        events = self.client.get(
            f"/subjects/{self.subject}/events").json()["events"]
        self.assertEqual(sorted(e["grant_id"] for e in events), ["g1", "g2"])

    # ---------------------------------------------------------- 并发回归
    def test_concurrent_grants_same_subject_all_commit(self):
        """同主体并发追加许可：咨询锁串行化，零丢失、零 5xx。"""
        n = 12
        barrier = threading.Barrier(n)
        results: list = [None] * n

        def worker(i):
            barrier.wait()
            body = {"subject_id": self.subject,
                    "grant_id": f"cg-{i}", "category": "email",
                    "purpose": "marketing", "recipient": "partner-a",
                    "valid_from": f"2026-01-{i + 1:02d}T00:00:00Z"}
            results[i] = self.client.post("/grants", json=body)

        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        statuses = [r.status_code for r in results]
        self.assertTrue(all(s == 201 for s in statuses),
                        f"存在非 201 响应: {statuses}")
        seqs = [r.json()["seq"] for r in results]
        self.assertEqual(len(set(seqs)), n, "许可序号重复 -> 存在丢失写")
        events = self.client.get(
            f"/subjects/{self.subject}/events").json()["events"]
        self.assertEqual(len(events), n)

    def test_concurrent_idempotent_task_races(self):
        """同一幂等键并发登记：恰好一次落库，其余 200 重放，绝不 5xx。"""
        self._grant("g1")
        tag = self.subject[-6:]
        key = f"race-{tag}"
        pid = f"racep-{tag}"
        n = 8
        barrier = threading.Barrier(n)
        results: list = [None] * n
        payload = {"subject_id": self.subject, "category": "email",
                   "purpose": "marketing", "recipient": "partner-a",
                   "use_at": "2026-05-01T00:00:00Z",
                   "products": [{"product_id": pid,
                                 "groups": [[{"kind": "receipt",
                                             "ref": key}]]}]}

        def worker(i):
            barrier.wait()
            results[i] = self.client.post(
                "/tasks", json=payload,
                headers={"Idempotency-Key": key})

        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        statuses = sorted(r.status_code for r in results)
        self.assertTrue(all(s in (200, 201) for s in statuses),
                        f"存在非 200/201 响应: {statuses}")
        self.assertEqual(statuses.count(201), 1,
                         "同幂等键必须恰好创建一次")
        self.assertEqual(statuses.count(200), n - 1)
        for r in results:
            body = r.json()
            self.assertEqual(body["receipt"]["decision"], "allow")
            self.assertEqual(body["products"][0]["status"], "active")

        # 数据库中也只应有一条回执与一个产物。
        with db.pool.connection() as conn:
            n_receipts = conn.execute(
                "SELECT count(*) AS n FROM receipts "
                "WHERE idempotency_key=%s", (key,)).fetchone()["n"]
            n_products = conn.execute(
                "SELECT count(*) AS n FROM products WHERE subject_id=%s",
                (self.subject,)).fetchone()["n"]
        self.assertEqual(n_receipts, 1)
        self.assertEqual(n_products, 1)

    def test_revocation_after_tasks_propagates_to_all(self):
        """任务先全部登记（allow），撤销随后提交：回执与产物追溯失效。"""
        tag = self.subject[-6:]
        k, p = f"after-{tag}-", f"afterp-{tag}-"
        self._grant("g1")
        n_tasks = 5
        for i in range(n_tasks):
            key = f"{k}{i}"
            r = self._task(
                key, f"{p}{i}",
                [[{"kind": "receipt", "ref": key}]])
            self.assertEqual(r.status_code, 201, r.text)
            self.assertEqual(r.json()["receipt"]["decision"], "allow")

        rev = self.client.post("/revocations", json={
            "subject_id": self.subject, "grant_id": "g1",
            "business_effective_at": "2026-01-15T00:00:00Z"})
        self.assertEqual(rev.status_code, 201, rev.text)
        rev_seq = rev.json()["event"]["seq"]
        affected = rev.json()["affected_receipts"]
        self.assertEqual(sorted(affected),
                         sorted(f"{k}{i}" for i in range(n_tasks)))

        for i in range(n_tasks):
            receipt = self.client.get(f"/receipts/{k}{i}").json()
            self.assertFalse(receipt["currently_valid"])
            self.assertEqual(receipt["invalidating_events"], [rev_seq])
            prod = self.client.get(
                f"/subjects/{self.subject}/products/{p}{i}").json()
            self.assertEqual(prod["status"], "blocked")
            self.assertEqual(prod["invalidating_events"], [rev_seq])

    def test_revocation_committed_first_tasks_register_deny(self):
        """撤销先提交，随后登记的任务：登记即 deny/revoked 且事务可见撤销。"""
        tag = self.subject[-6:]
        self._grant("g1")
        rev = self.client.post("/revocations", json={
            "subject_id": self.subject, "grant_id": "g1",
            "business_effective_at": "2026-01-15T00:00:00Z"})
        rev_seq = rev.json()["event"]["seq"]

        r = self._task(
            f"denytask-{tag}", f"denyp-{tag}",
            [[{"kind": "receipt", "ref": f"denytask-{tag}"}]])
        self.assertEqual(r.status_code, 201, r.text)
        body = r.json()
        self.assertEqual(body["receipt"]["decision"], "deny")
        self.assertEqual(body["receipt"]["basis_reason"], "revoked")
        self.assertEqual(body["receipt"]["basis_seq"], rev_seq)
        self.assertFalse(body["receipt"]["currently_valid"])
        self.assertEqual(body["products"][0]["status"], "blocked")
        # 登记即拒绝的回执失效事件集合恒为空（领域语义）。
        self.assertEqual(body["products"][0]["invalidating_events"], [])

    def test_concurrent_revocation_and_tasks_serialized_final_consistent(self):
        """撤销与任务在主体咨询锁上并发：不报错、不丢写，最终状态自洽。

        协调连接持有 / 释放主体咨询锁，制造任务线程与撤销请求的真实交错。
        每个任务的状态只可能是两种合法串行化结果之一：
          a) 先登记（allow）后被撤销追溯失效（失效事件 = rev_seq）；
          b) 撤销先提交，登记即 deny/revoked（失效事件集合为空）。
        """
        self._grant("g1")
        tag = self.subject[-6:]
        k, p = f"race-{tag}-", f"racep-{tag}-"
        n_tasks = 12
        task_results: list = []
        revocation_holder: dict = {}
        gate = threading.Event()      # 协调器就绪后放行请求线程
        release_lock = threading.Event()  # 释放咨询锁，让排队者争抢
        coord_errors: list = []

        def coordinator():
            """在独立事务中持有主体咨询锁，阻塞所有同主体写请求。"""
            try:
                assert db.pool is not None
                with db.pool.connection() as conn:
                    conn.execute(
                        "SELECT pg_advisory_lock(hashtext(%s))",
                        (self.subject,))
                    gate.set()
                    release_lock.wait(timeout=10)
                    # 于持锁事务内释放会话级咨询锁并提交。
                    conn.execute(
                        "SELECT pg_advisory_unlock(hashtext(%s))",
                        (self.subject,))
                    conn.commit()
            except Exception:  # pragma: no cover - 仅用于暴露协调器故障
                import traceback
                coord_errors.append(traceback.format_exc())
                gate.set()

        def register(i):
            key = f"{k}{i}"
            r = self._task(
                key, f"{p}{i}",
                [[{"kind": "receipt", "ref": key}]])
            task_results.append((i, r))

        def revoke():
            r = self.client.post("/revocations", json={
                "subject_id": self.subject, "grant_id": "g1",
                "business_effective_at": "2026-01-15T00:00:00Z"})
            revocation_holder["response"] = r

        coord = threading.Thread(target=coordinator)
        coord.start()
        self.assertTrue(gate.wait(timeout=10), "协调器未能持锁")

        workers = ([threading.Thread(target=register, args=(i,))
                    for i in range(n_tasks)]
                   + [threading.Thread(target=revoke)])
        for t in workers:
            t.start()
        # 给线程时间全部进入并阻塞在咨询锁上。
        time.sleep(0.5)
        release_lock.set()
        for t in workers:
            t.join()
        coord.join(timeout=10)
        self.assertEqual(coord_errors, [])

        rev_resp = revocation_holder["response"]
        self.assertEqual(rev_resp.status_code, 201, rev_resp.text)
        rev_seq = rev_resp.json()["event"]["seq"]
        self.assertEqual(len(task_results), n_tasks)
        self.assertTrue(
            all(r.status_code == 201 for _, r in task_results),
            [r.status_code for _, r in task_results])

        n_before = n_after = 0
        before_keys: list[str] = []
        for i, r in task_results:
            key = f"{k}{i}"
            receipt = self.client.get(f"/receipts/{key}").json()
            prod = self.client.get(
                f"/subjects/{self.subject}/products/{p}{i}").json()
            self.assertEqual(prod["status"], "blocked")
            self.assertFalse(receipt["currently_valid"])
            if receipt["decision"] == "allow":
                n_before += 1
                before_keys.append(key)
                self.assertEqual(prod["invalidating_events"], [rev_seq])
            else:
                n_after += 1
                self.assertEqual(receipt["basis"]["reason"], "revoked")
                self.assertEqual(prod["invalidating_events"], [])

        # 锁先于快照：撤销事务的快照在其获得主体锁之后才建立，因此
        # affected_receipts 恰好等于先于它（按锁顺序）登记的 allow 回执，
        # 不多不少；在撤销之后获锁的任务登记即 deny/revoked，不在其中。
        affected = rev_resp.json()["affected_receipts"]
        self.assertEqual(sorted(affected), sorted(before_keys),
                         f"affected={affected} 应恰好等于先登记的 allow 回执集合")
        for key in affected:
            receipt = self.client.get(f"/receipts/{key}").json()
            self.assertFalse(receipt["currently_valid"])
        self.assertEqual(n_before + n_after, n_tasks)

    # -------------------------------------- 可控交错：锁顺序 = 快照读取顺序
    def test_interleave_revocation_first_queued_task_registers_deny(self):
        """撤销先获锁提交：早已排队的任务不得沿用旧快照，登记即 deny/revoked。

        交错编排（由协调锁 + pg_locks 精确控制）：
          1. 协调器持有主体锁；
          2. 撤销请求到达并进入锁等待（其事务尚未开始）；
          3. 任务请求到达并排在撤销之后（其请求先于撤销提交到达）；
          4. 放行 -> 撤销先获锁提交，任务后获锁。
        任务的快照必须建立在撤销提交之后：登记 deny/revoked、依据为本次
        撤销；撤销获锁时尚无任何回执，affected_receipts 为空。
        """
        self._grant("g1")
        tag = self.subject[-6:]
        key, pid = f"qdeny-{tag}", f"qdenyp-{tag}"
        out: dict = {}

        def revoke():
            out["rev"] = self.client.post("/revocations", json={
                "subject_id": self.subject, "grant_id": "g1",
                "business_effective_at": "2026-01-15T00:00:00Z"})

        def task():
            out["task"] = self._task(
                key, pid, [[{"kind": "receipt", "ref": key}]])

        with SubjectLockCoordinator(self.subject) as coord:
            t_rev = threading.Thread(target=revoke)
            t_task = threading.Thread(target=task)
            t_rev.start()
            wait_advisory_waiters(self.subject, 1)   # 撤销已排队
            t_task.start()
            wait_advisory_waiters(self.subject, 2)   # 任务已排队（撤销尚未提交）
            coord.release()                          # 锁顺序：撤销 -> 任务
            t_rev.join()
            t_task.join()
        self.assertEqual(coord.errors, [])

        rev = out["rev"]
        self.assertEqual(rev.status_code, 201, rev.text)
        rev_seq = rev.json()["event"]["seq"]
        # 撤销获锁时没有任何已登记回执。
        self.assertEqual(rev.json()["affected_receipts"], [])

        resp = out["task"]
        self.assertEqual(resp.status_code, 201, resp.text)
        body = resp.json()
        # 任务请求虽先于撤销提交到达，但获锁更晚 -> 必须看到已提交的撤销。
        self.assertEqual(body["receipt"]["decision"], "deny")
        self.assertEqual(body["receipt"]["basis_reason"], "revoked")
        self.assertEqual(body["receipt"]["basis_seq"], rev_seq)
        self.assertFalse(body["receipt"]["currently_valid"])
        self.assertEqual(body["products"][0]["status"], "blocked")
        # 登记即拒绝的回执失效事件集合恒为空（领域语义）。
        self.assertEqual(body["products"][0]["invalidating_events"], [])

        # 独立只读接口复核：回执与重放口径一致。
        receipt = self.client.get(f"/receipts/{key}").json()
        self.assertEqual(receipt["decision"], "deny")
        self.assertEqual(receipt["basis"]["reason"], "revoked")
        self.assertEqual(receipt["basis"]["seq"], rev_seq)
        d = self._eval().json()
        self.assertEqual(d["decision"], "deny")
        self.assertEqual(d["hit"], "revocation")

    def test_interleave_task_first_revocation_lists_exactly_registered(self):
        """任务先获锁登记：撤销响应恰好列出其获锁前已登记的失效回执。

        交错编排：协调器持锁 -> 任务排队 -> 撤销排队 -> 放行
        （锁顺序：任务 -> 撤销）。任务登记 allow 并提交后撤销才获锁，
        撤销的传播扫描必须看到该回执：affected_receipts 恰为 [key]，
        产物阻断与 as_of_seq 历史回放保持一致。
        """
        self._grant("g1")
        tag = self.subject[-6:]
        key, pid = f"qallow-{tag}", f"qallowp-{tag}"
        out: dict = {}

        def task():
            out["task"] = self._task(
                key, pid, [[{"kind": "receipt", "ref": key}]])

        def revoke():
            out["rev"] = self.client.post("/revocations", json={
                "subject_id": self.subject, "grant_id": "g1",
                "business_effective_at": "2026-01-15T00:00:00Z"})

        with SubjectLockCoordinator(self.subject) as coord:
            t_task = threading.Thread(target=task)
            t_rev = threading.Thread(target=revoke)
            t_task.start()
            wait_advisory_waiters(self.subject, 1)   # 任务已排队
            t_rev.start()
            wait_advisory_waiters(self.subject, 2)   # 撤销排在任务之后
            coord.release()                          # 锁顺序：任务 -> 撤销
            t_task.join()
            t_rev.join()
        self.assertEqual(coord.errors, [])

        resp = out["task"]
        self.assertEqual(resp.status_code, 201, resp.text)
        self.assertEqual(resp.json()["receipt"]["decision"], "allow")
        self.assertEqual(resp.json()["products"][0]["status"], "active")

        rev = out["rev"]
        self.assertEqual(rev.status_code, 201, rev.text)
        rev_seq = rev.json()["event"]["seq"]
        # 撤销获锁之前恰好登记了 key 这一个被本次撤销失效的回执。
        self.assertEqual(rev.json()["affected_receipts"], [key])
        blocked = rev.json()["blocked_products"]
        self.assertEqual([b["product_id"] for b in blocked], [pid])
        self.assertEqual(blocked[0]["invalidating_events"], [rev_seq])

        # 当前重放：回执失效、产物阻断，失效事件为本次撤销。
        receipt = self.client.get(f"/receipts/{key}").json()
        self.assertEqual(receipt["decision"], "allow")  # 旧记录不可改写
        self.assertFalse(receipt["currently_valid"])
        self.assertEqual(receipt["invalidating_events"], [rev_seq])
        prod = self.client.get(
            f"/subjects/{self.subject}/products/{pid}").json()
        self.assertEqual(prod["status"], "blocked")
        self.assertEqual(prod["invalidating_events"], [rev_seq])

        # 历史回放：回到撤销之前，回执与产物仍为登记时的有效状态。
        old = self.client.get(
            f"/subjects/{self.subject}/products/{pid}?as_of_seq={rev_seq - 1}"
        ).json()
        self.assertEqual(old["status"], "active")

    def test_interleave_mixed_queue_revocation_affected_exact(self):
        """混合队列：撤销的 affected_receipts 恰好覆盖其获锁前登记的回执。

        编排：k0 先行登记（无竞争）；协调器持锁后依次排入 k1、撤销、k2
        （锁顺序：k1 -> 撤销 -> k2）。撤销获锁时 k0、k1 已提交 ->
        affected_receipts 恰为 {k0, k1}；k2 在撤销之后获锁 ->
        登记即 deny/revoked，不在 affected 中。三个产物的阻断状态与
        历史回放均与各自回执口径一致。
        """
        self._grant("g1")
        tag = self.subject[-6:]
        k0, k1, k2 = (f"m0-{tag}", f"m1-{tag}", f"m2-{tag}")
        p0, p1, p2 = (f"m0p-{tag}", f"m1p-{tag}", f"m2p-{tag}")

        r0 = self._task(k0, p0, [[{"kind": "receipt", "ref": k0}]])
        self.assertEqual(r0.status_code, 201, r0.text)
        self.assertEqual(r0.json()["receipt"]["decision"], "allow")

        out: dict = {}

        def task1():
            out["t1"] = self._task(k1, p1, [[{"kind": "receipt", "ref": k1}]])

        def revoke():
            out["rev"] = self.client.post("/revocations", json={
                "subject_id": self.subject, "grant_id": "g1",
                "business_effective_at": "2026-01-15T00:00:00Z"})

        def task2():
            out["t2"] = self._task(k2, p2, [[{"kind": "receipt", "ref": k2}]])

        with SubjectLockCoordinator(self.subject) as coord:
            threads = [threading.Thread(target=t) for t in (task1, revoke, task2)]
            for i, t in enumerate(threads, start=1):
                t.start()
                wait_advisory_waiters(self.subject, i)
            coord.release()  # 锁顺序：k1 -> 撤销 -> k2
            for t in threads:
                t.join()
        self.assertEqual(coord.errors, [])

        rev = out["rev"]
        self.assertEqual(rev.status_code, 201, rev.text)
        rev_seq = rev.json()["event"]["seq"]
        # 恰好覆盖获锁前已登记且被本次撤销失效的回执：k0（放行前登记）、
        # k1（锁顺序在撤销之前）；k2 在撤销之后获锁，不在其中。
        self.assertEqual(sorted(rev.json()["affected_receipts"]), [k0, k1])
        blocked_pids = sorted(b["product_id"]
                              for b in rev.json()["blocked_products"])
        self.assertEqual(blocked_pids, [p0, p1])

        # k1：先获锁登记 allow，随后被本次撤销追溯失效。
        r1 = out["t1"]
        self.assertEqual(r1.status_code, 201, r1.text)
        self.assertEqual(r1.json()["receipt"]["decision"], "allow")
        receipt1 = self.client.get(f"/receipts/{k1}").json()
        self.assertFalse(receipt1["currently_valid"])
        self.assertEqual(receipt1["invalidating_events"], [rev_seq])
        prod1 = self.client.get(
            f"/subjects/{self.subject}/products/{p1}").json()
        self.assertEqual(prod1["status"], "blocked")
        self.assertEqual(prod1["invalidating_events"], [rev_seq])

        # k2：撤销提交后才获锁 -> 登记即 deny/revoked，依据为本次撤销。
        r2 = out["t2"]
        self.assertEqual(r2.status_code, 201, r2.text)
        self.assertEqual(r2.json()["receipt"]["decision"], "deny")
        self.assertEqual(r2.json()["receipt"]["basis_reason"], "revoked")
        self.assertEqual(r2.json()["receipt"]["basis_seq"], rev_seq)
        prod2 = self.client.get(
            f"/subjects/{self.subject}/products/{p2}").json()
        self.assertEqual(prod2["status"], "blocked")
        self.assertEqual(prod2["invalidating_events"], [])

        # 历史回放：撤销之前 k0/k1 的产物均 active；k2 的回执登记即拒绝，
        # 任意回放时点都永久失效（失效事件集合恒为空，与回放时点无关）。
        for pid in (p0, p1):
            old = self.client.get(
                f"/subjects/{self.subject}/products/{pid}"
                f"?as_of_seq={rev_seq - 1}").json()
            self.assertEqual(old["status"], "active")
        old2 = self.client.get(
            f"/subjects/{self.subject}/products/{p2}"
            f"?as_of_seq={rev_seq - 1}").json()
        self.assertEqual(old2["status"], "blocked")
        self.assertEqual(old2["invalidating_events"], [])

    def test_concurrent_readers_while_writing(self):
        """写入进行时并发只读重放：始终 200（快照一致），默认拒绝先行。"""
        stop = threading.Event()
        errors: list = []

        def reader():
            i = 0
            while not stop.is_set():
                r = self._eval()  # 只读事务
                if r.status_code != 200:
                    errors.append((i, r.status_code, r.text[:200]))
                    return
                i += 1

        tag = self.subject[-6:]
        readers = [threading.Thread(target=reader) for _ in range(4)]
        for t in readers:
            t.start()
        try:
            for i in range(6):
                self._grant(f"rw-{tag}-{i}")
                key = f"rw-t-{tag}-{i}"
                self._task(
                    key, f"rw-p-{tag}-{i}",
                    [[{"kind": "receipt", "ref": key}]])
                self.client.post("/revocations", json={
                    "subject_id": self.subject, "grant_id": f"rw-{tag}-{i}",
                    "business_effective_at": "2026-01-15T00:00:00Z"})
        finally:
            stop.set()
            for t in readers:
                t.join()
        self.assertEqual(errors, [])

    def test_concurrent_different_subjects_do_not_block_each_other(self):
        """不同主体并行：咨询锁按主体分区，两侧均快速成功。"""
        subjects = ["test-" + uuid.uuid4().hex[:12] for _ in range(2)]
        for s in subjects:
            self.client.post("/grants", json={
                "subject_id": s, "grant_id": "g", "category": "email",
                "purpose": "marketing", "recipient": "partner-a",
                "valid_from": "2026-01-01T00:00:00Z"})

        stop = threading.Event()

        def worker(s, out, idx=0):
            while not stop.is_set():
                key = f"k-{s[-4:]}-{idx}"
                pid = f"p-{s[-4:]}-{idx}"
                r = self.client.post("/tasks", json={
                    "subject_id": s, "category": "email",
                    "purpose": "marketing", "recipient": "partner-a",
                    "use_at": "2026-05-01T00:00:00Z",
                    "products": [{"product_id": pid,
                                  "groups": [[{"kind": "receipt",
                                               "ref": key}]]}]},
                    headers={"Idempotency-Key": key})
                if r.status_code != 201:
                    out.append(r.status_code)
                    return
                idx += 1

        outs = [[], []]
        threads = [threading.Thread(target=worker, args=(s, o))
                   for s, o in zip(subjects, outs)]
        for t in threads:
            t.start()
        time.sleep(1.5)
        stop.set()
        for t in threads:
            t.join()
        self.assertEqual(outs[0], [])
        self.assertEqual(outs[1], [])


# 本地配置的处置台账令牌（与 config.py 默认值一致）。
ADMIN_H = {"Authorization": "Bearer dev-admin-token"}
RA_H = {"Authorization": "Bearer dev-token-a"}        # partner-a
RB_H = {"Authorization": "Bearer dev-token-b"}        # partner-b
NOAUTH_H = {}
BADTOKEN_H = {"Authorization": "Bearer nope"}


@unittest.skipIf(TestClient is None, "缺少 fastapi/psycopg 依赖")
class RemediationApiTests(unittest.TestCase):
    """撤销处置台账端到端：开立 / 查询 / 提交 / 复核 / 恢复取消 / 重开。"""

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault(
            "DATABASE_URL", "postgresql://consent:consent@localhost:5432/consent")
        for attempt in range(30):
            try:
                init_pool()
                break
            except Exception:
                if attempt == 29:
                    raise
                time.sleep(1)
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        shutdown_pool()

    def setUp(self):
        self.subject = "rm-" + uuid.uuid4().hex[:12]
        self.tag = uuid.uuid4().hex[:8]

    def k(self, name: str) -> str:
        """全局唯一回执键 / 幂等键（receipts 主键全局而非按主体）。"""
        return f"{name}-{self.tag}"

    def _grant(self, gid, recipient="partner-a"):
        gid = f"{gid}-{self.tag}"
        r = self.client.post("/grants", json={
            "subject_id": self.subject, "grant_id": gid,
            "category": "email", "purpose": "marketing",
            "recipient": recipient,
            "valid_from": "2026-01-01T00:00:00Z"})
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()

    def _task(self, key, product, recipient="partner-a", groups=None):
        body = {"subject_id": self.subject, "category": "email",
                "purpose": "marketing", "recipient": recipient,
                "use_at": "2026-05-01T00:00:00Z"}
        if product is not None:
            body["products"] = [{"product_id": product,
                                 "groups": groups
                                 or [[{"kind": "receipt", "ref": key}]]}]
        r = self.client.post("/tasks", json=body,
                             headers={"Idempotency-Key": key})
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()

    def _revoke(self, gid, bea="2026-01-15T00:00:00Z"):
        r = self.client.post("/revocations", json={
            "subject_id": self.subject, "grant_id": f"{gid}-{self.tag}",
            "business_effective_at": bea})
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()

    def _case(self, headers=RA_H, recipient=None):
        url = f"/subjects/{self.subject}/remediation"
        if recipient:
            url += f"?recipient={recipient}"
        return self.client.get(url, headers=headers)

    def _submit(self, item_id, version, key, declaration, evidence,
                headers=RA_H):
        return self.client.post(
            f"/remediation/items/{item_id}/submissions",
            json={"version": version, "cease_declaration": declaration,
                  "evidence": evidence},
            headers={**headers, "Idempotency-Key": key})

    def _review(self, item_id, version, action, comment=None):
        return self.client.post(
            f"/remediation/items/{item_id}/reviews",
            json={"version": version, "action": action, "comment": comment},
            headers=ADMIN_H)

    # ------------------------------------------------ 开立与鉴权
    def test_revocation_opens_items_and_requires_token(self):
        self._grant("g1")
        key, pid = self.k("k1"), self.k("p1")
        self._task(key, pid)
        rev = self._revoke("g1")
        opened = rev["remediation_items"]
        self.assertEqual(len(opened), 1)
        item_id = opened[0]["item_id"]
        self.assertEqual(opened[0]["receipt_key"], key)
        self.assertEqual(opened[0]["recipient"], "partner-a")
        self.assertEqual(opened[0]["products"], [pid])

        # 无令牌 / 坏令牌 -> 401。
        self.assertEqual(self._case(headers=NOAUTH_H).status_code, 401)
        self.assertEqual(self._case(headers=BADTOKEN_H).status_code, 401)
        # 其他接收方不得查询；接收方令牌冒充他人 -> 403。
        self.assertEqual(self._case(headers=RB_H).status_code, 200)
        rb = self._case(headers=RB_H).json()
        self.assertEqual(rb["items"], [])  # partner-b 无处置项
        r = self.client.get(
            f"/subjects/{self.subject}/remediation?recipient=partner-b",
            headers=RA_H)
        self.assertEqual(r.status_code, 403)
        # 管理员必须指定 recipient -> 422。
        self.assertEqual(self._case(headers=ADMIN_H).status_code, 422)
        # 管理员可查询任一接收方。
        r = self.client.get(
            f"/subjects/{self.subject}/remediation?recipient=partner-a",
            headers=ADMIN_H)
        self.assertEqual(r.status_code, 200, r.text)
        case = r.json()
        self.assertEqual(case["status"], "pending")
        self.assertEqual(case["open_item_ids"], [item_id])
        self.assertEqual(case["items"][0]["status"], "open")

    def test_recipient_cannot_review_admin_cannot_submit(self):
        self._grant("g1")
        key, pid = self.k("k1"), self.k("p1")
        self._task(key, pid)
        item_id = self._revoke("g1")["remediation_items"][0]["item_id"]
        # 接收方复核 -> 403
        r = self.client.post(
            f"/remediation/items/{item_id}/reviews",
            json={"version": 1, "action": "approve"}, headers=RA_H)
        self.assertEqual(r.status_code, 403)
        # 管理员提交 -> 403（尚无提交，管理员无权）
        r = self._submit(item_id, 1, self.k("sk"), "x",
                         [{"product_id": pid, "summary": "y"}],
                         headers=ADMIN_H)
        self.assertEqual(r.status_code, 403)
        # 未知处置项 -> 404
        self.assertEqual(self.client.post(
            "/remediation/items/99999999/reviews",
            json={"version": 1, "action": "approve"},
            headers=ADMIN_H).status_code, 404)

    # ------------------------------------------------ 提交、版本与幂等
    def test_submission_version_reject_resubmit_approve_and_close(self):
        self._grant("g1")
        key, pid = self.k("k1"), self.k("p1")
        self._task(key, pid)
        item_id = self._revoke("g1")["remediation_items"][0]["item_id"]

        # 证据必须覆盖全部关联产物。
        r = self._submit(item_id, 1, self.k("s1"), "停止使用", [])
        self.assertEqual(r.status_code, 422, r.text)
        r = self._submit(item_id, 1, self.k("s2"), "停止使用",
                         [{"product_id": self.k("nope"), "summary": "x"}])
        self.assertEqual(r.status_code, 422, r.text)

        sk1 = self.k("s1")
        body = {"version": 1, "cease_declaration": "已停止使用",
                "evidence": [{"product_id": pid, "summary": "已清除"}]}
        r = self.client.post(
            f"/remediation/items/{item_id}/submissions",
            json=body, headers={**RA_H, "Idempotency-Key": sk1})
        self.assertEqual(r.status_code, 201, r.text)
        self.assertFalse(r.json()["idempotent_replay"])
        self.assertEqual(r.json()["item_status"], "submitted")

        # 同键同内容重放 -> 200；同键不同内容 -> 409。
        r2 = self.client.post(
            f"/remediation/items/{item_id}/submissions",
            json=body, headers={**RA_H, "Idempotency-Key": sk1})
        self.assertEqual(r2.status_code, 200)
        self.assertTrue(r2.json()["idempotent_replay"])
        r3 = self.client.post(
            f"/remediation/items/{item_id}/submissions",
            json={**body, "cease_declaration": "改写了"},
            headers={**RA_H, "Idempotency-Key": sk1})
        self.assertEqual(r3.status_code, 409)

        # 缺幂等键 -> 422；过期版本 -> 409；待复核补证 -> 409。
        r = self.client.post(
            f"/remediation/items/{item_id}/submissions", json=body,
            headers=RA_H)
        self.assertEqual(r.status_code, 422)
        r = self._submit(item_id, 2, self.k("s3"), "x",
                         [{"product_id": pid, "summary": "y"}])
        self.assertEqual(r.status_code, 409)
        r = self._submit(item_id, 1, self.k("s4"), "x",
                         [{"product_id": pid, "summary": "y"}])
        self.assertEqual(r.status_code, 409)

        # 管理员复核不存在的版本 -> 409（过期 / 无此版本）。
        self.assertEqual(self._review(item_id, 2, "approve").status_code, 409)

        # 驳回版本 1；驳回决定不得重复，接收方补证版本 2。
        r = self._review(item_id, 1, "reject", comment="证据不足")
        self.assertEqual(r.status_code, 201, r.text)
        self.assertEqual(r.json()["item_status"], "rejected")
        self.assertEqual(self._review(item_id, 1, "approve").status_code, 409)
        r = self._submit(item_id, 2, self.k("s5"), "已停止并通知下游",
                         [{"product_id": pid, "summary": "清除+审计日志"}])
        self.assertEqual(r.status_code, 201, r.text)

        # 批准版本 2 -> 处置项 approved、案件结案；证据与复核历史追加保留。
        r = self._review(item_id, 2, "approve", comment="ok")
        self.assertEqual(r.status_code, 201, r.text)
        case = self.client.get(
            f"/subjects/{self.subject}/remediation?recipient=partner-a",
            headers=ADMIN_H).json()
        self.assertEqual(case["status"], "closed")
        self.assertEqual(case["open_item_ids"], [])
        view = case["items"][0]
        self.assertEqual(view["status"], "approved")
        self.assertEqual([s["version"] for s in view["submissions"]], [1, 2])
        self.assertEqual([rev["action"] for rev in view["reviews"]],
                         ["rejected", "approved"])
        self.assertEqual(view["submissions"][1]["evidence"][0]["summary"],
                         "清除+审计日志")

        # 结案后再次提交 / 复核 -> 409。
        r = self._submit(item_id, 3, self.k("s6"), "x",
                         [{"product_id": pid, "summary": "y"}])
        self.assertEqual(r.status_code, 409)
        self.assertEqual(self._review(item_id, 2, "reject").status_code, 409)

    # ---------------------------------------- 恢复有效取消、再失效重开、不可变
    def test_grant_restores_cancels_then_new_invalidation_reopens(self):
        self._grant("g1")
        key, pid = self.k("k1"), self.k("p1")
        self._task(key, pid)
        rev = self._revoke("g1")
        rev_seq = rev["event"]["seq"]
        item_id = rev["remediation_items"][0]["item_id"]

        # 当前处置台账恰有一项。
        self.assertEqual(len(self._case().json()["items"]), 1)
        # 撤销未知许可 -> 404 回滚，处置项数量不变（撤销回滚不留处置记录）。
        bad = self.client.post("/revocations", json={
            "subject_id": self.subject, "grant_id": self.k("ghost"),
            "business_effective_at": "2026-01-01T00:00:00Z"})
        self.assertEqual(bad.status_code, 404)
        self.assertEqual(len(self._case().json()["items"]), 1)

        # 新许可恢复回执有效 -> 未结处置项取消，案件结案。
        r = self._grant("g2")
        self.assertEqual(
            [c["item_id"] for c in r["cancelled_remediation_items"]],
            [item_id])
        receipt = self.client.get(f"/receipts/{key}").json()
        self.assertTrue(receipt["currently_valid"])
        case = self._case().json()
        self.assertEqual(case["status"], "closed")
        self.assertEqual(case["items"][0]["status"], "cancelled")
        self.assertIsNotNone(case["items"][0]["cancellation"])
        # 已取消项不能提交 / 复核。
        r = self._submit(item_id, 1, self.k("s1"), "x",
                         [{"product_id": pid, "summary": "y"}])
        self.assertEqual(r.status_code, 409)
        self.assertEqual(self._review(item_id, 1, "approve").status_code, 409)

        # 再次失效：另开新处置项，案件重新待处置。
        rev2 = self._revoke("g2", bea="2026-01-20T00:00:00Z")
        new_items = rev2["remediation_items"]
        self.assertEqual(len(new_items), 1)
        new_id = new_items[0]["item_id"]
        self.assertNotEqual(new_id, item_id)
        self.assertEqual(new_items[0]["products"], [pid])
        case = self._case().json()
        self.assertEqual(case["status"], "pending")
        self.assertEqual(case["open_item_ids"], [new_id])
        # 旧取消项仍保留，新项版本从头计起。
        statuses = {i["item_id"]: i["status"] for i in case["items"]}
        self.assertEqual(statuses, {item_id: "cancelled", new_id: "open"})
        r = self._submit(new_id, 1, self.k("s2"), "停止",
                         [{"product_id": pid, "summary": "清除"}])
        self.assertEqual(r.status_code, 201, r.text)

        # 结案 / 取消不改变原回执、产物阻断与历史回放。
        receipt = self.client.get(f"/receipts/{key}").json()
        self.assertEqual(receipt["decision"], "allow")  # 旧回执不可改写
        self.assertFalse(receipt["currently_valid"])
        self.assertEqual(receipt["invalidating_events"],
                         [rev2["event"]["seq"]])
        prod = self.client.get(
            f"/subjects/{self.subject}/products/{pid}").json()
        self.assertEqual(prod["status"], "blocked")
        old = self.client.get(
            f"/subjects/{self.subject}/products/{pid}?as_of_seq={rev_seq - 1}"
        ).json()
        self.assertEqual(old["status"], "active")  # 历史回放不受台账影响

    def test_multiple_items_all_approved_then_closed_and_rerevoke_dup(self):
        """同一接收方多项须全部获批才结案；未恢复重复撤销不重复开立。"""
        self._grant("g1")
        k1, k2 = self.k("k1"), self.k("k2")
        p1, p2 = self.k("p1"), self.k("p2")
        self._task(k1, p1)
        self._task(k2, p2)
        rev = self._revoke("g1")
        items = {o["receipt_key"]: o["item_id"]
                 for o in rev["remediation_items"]}
        self.assertEqual(len(items), 2)
        id1, id2 = items[k1], items[k2]

        # 仅批准一项：仍未结案。
        r = self._submit(id1, 1, self.k("sa"), "停",
                         [{"product_id": p1, "summary": "清"}])
        self.assertEqual(r.status_code, 201)
        self.assertEqual(self._review(id1, 1, "approve").status_code, 201)
        case = self._case().json()
        self.assertEqual(case["status"], "pending")
        self.assertEqual(case["open_item_ids"], [id2])

        # 未恢复有效时再次撤销（另一生效时间）：不重复开立。
        rev2 = self._revoke("g1", bea="2026-02-01T00:00:00Z")
        self.assertEqual(rev2["remediation_items"], [])

        r = self._submit(id2, 1, self.k("sb"), "停",
                         [{"product_id": p2, "summary": "清"}])
        self.assertEqual(r.status_code, 201)
        self.assertEqual(self._review(id2, 1, "approve").status_code, 201)
        case = self._case().json()
        self.assertEqual(case["status"], "closed")

    def test_two_recipients_cases_independent_and_product_chain(self):
        """不同接收方处置台账相互独立；血缘链产物关联到叶子回执项。"""
        # partner-a 的许可 / 回执 / 链状产物（同一任务声明 pa1 与 pa2，
        # pa2 依赖 pa1，只有一个回执 -> 一个处置项）。
        self._grant("ga", recipient="partner-a")
        p1, p2, ka = self.k("pa1"), self.k("pa2"), self.k("ka")
        body = {"subject_id": self.subject, "category": "email",
                "purpose": "marketing", "recipient": "partner-a",
                "use_at": "2026-05-01T00:00:00Z",
                "products": [
                    {"product_id": p1,
                     "groups": [[{"kind": "receipt", "ref": ka}]]},
                    {"product_id": p2,
                     "groups": [[{"kind": "product", "ref": p1}]]}]}
        r = self.client.post("/tasks", json=body,
                             headers={"Idempotency-Key": ka})
        self.assertEqual(r.status_code, 201, r.text)
        self._revoke("ga")

        case_a = self._case(headers=RA_H).json()
        self.assertEqual(case_a["recipient"], "partner-a")
        self.assertEqual(len(case_a["items"]), 1)
        # 沿血缘本次新阻断的产物：pa1 与 pa2 都关联到该处置项。
        self.assertEqual(case_a["items"][0]["products"], [p1, p2])
        case_b = self._case(headers=RB_H).json()
        self.assertEqual(case_b["items"], [])
        self.assertEqual(case_b["status"], "closed")  # 无处置项视为无待办


@unittest.skipIf(TestClient is None, "缺少 fastapi/psycopg 依赖")
class DeletionApiTests(unittest.TestCase):
    """删除请求端到端：可定位阻断、下游先删批次、幂等、过期标记与不可变。"""

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault(
            "DATABASE_URL", "postgresql://consent:consent@localhost:5432/consent")
        for attempt in range(30):
            try:
                init_pool()
                break
            except Exception:
                if attempt == 29:
                    raise
                time.sleep(1)
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        shutdown_pool()

    def setUp(self):
        self.subject = "del-" + uuid.uuid4().hex[:12]
        self.tag = uuid.uuid4().hex[:8]

    def k(self, name: str) -> str:
        """全局唯一键（删除请求幂等键 / 回执键均为全局主键）。"""
        return f"{name}-{self.tag}"

    def _grant(self, gid, recipient="partner-a"):
        r = self.client.post("/grants", json={
            "subject_id": self.subject, "grant_id": gid,
            "category": "email", "purpose": "marketing",
            "recipient": recipient,
            "valid_from": "2026-01-01T00:00:00Z"})
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()

    def _task(self, key, products):
        r = self.client.post("/tasks", json={
            "subject_id": self.subject, "category": "email",
            "purpose": "marketing", "recipient": "partner-a",
            "use_at": "2026-05-01T00:00:00Z", "products": products},
            headers={"Idempotency-Key": key})
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()

    def _revoke(self, gid, bea="2026-01-15T00:00:00Z"):
        r = self.client.post("/revocations", json={
            "subject_id": self.subject, "grant_id": gid,
            "business_effective_at": bea})
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()

    def _delreq(self, key, product_ids=(), expected=(201,)):
        r = self.client.post("/deletion-requests", json={
            "subject_id": self.subject, "product_ids": list(product_ids),
            "requested_at": "2026-09-26T08:00:00Z"},
            headers={"Idempotency-Key": key})
        self.assertIn(r.status_code, expected, r.text)
        return r

    def _remediate_all(self):
        """提交并批准当前全部未结处置项（证据逐项覆盖其关联产物）。"""
        case = self.client.get(
            f"/subjects/{self.subject}/remediation", headers=RA_H).json()
        for iid in case["open_item_ids"]:
            item = next(i for i in case["items"] if i["item_id"] == iid)
            evidence = [{"product_id": p, "summary": "已清除"}
                        for p in item["products"]]
            r = self.client.post(
                f"/remediation/items/{iid}/submissions",
                json={"version": 1, "cease_declaration": "已停止使用",
                      "evidence": evidence},
                headers={**RA_H, "Idempotency-Key": self.k(f"rem-{iid}")})
            self.assertEqual(r.status_code, 201, r.text)
            r = self.client.post(
                f"/remediation/items/{iid}/reviews",
                json={"version": 1, "action": "approve"}, headers=ADMIN_H)
            self.assertEqual(r.status_code, 201, r.text)

    # -------------------------------------------- 阻断 -> 放行 -> 过期 全周期
    def test_full_lifecycle_blocked_then_planned_then_stale(self):
        self._grant("g1")
        t1 = self.k("t1")
        p1, p2, p3 = self.k("p1"), self.k("p2"), self.k("p3")
        # 链状产物：p1 <- p2 <- p3（同批登记，t1 为叶子回执）。
        self._task(t1, [
            {"product_id": p1, "groups": [[{"kind": "receipt", "ref": t1}]]},
            {"product_id": p2, "groups": [[{"kind": "product", "ref": p1}]]},
            {"product_id": p3, "groups": [[{"kind": "product", "ref": p2}]]}])

        # 1) 活动许可仍在 -> blocked，原因可定位（许可 + 回执 + 受影响产物）。
        body = self._delreq(self.k("d1")).json()
        self.assertEqual(body["status"], "blocked")
        self.assertFalse(body["idempotent_replay"])
        self.assertEqual(body["batches"], [])
        self.assertEqual(body["scope"], [p1, p2, p3])
        self.assertEqual(len(body["blockers"]), 1)
        b0 = body["blockers"][0]
        self.assertEqual(b0["kind"], "active_grant")
        self.assertEqual(b0["grant_id"], "g1")
        self.assertEqual(b0["receipt_key"], t1)
        self.assertEqual(b0["products"], [p1, p2, p3])
        self.assertIn("grant_seq", b0)
        blocked_id = body["request_id"]

        # 2) 追溯撤销 -> 许可失效，但出现未结处置（同样可定位）。
        rev = self._revoke("g1")
        rev_seq = rev["event"]["seq"]
        body = self._delreq(self.k("d2")).json()
        self.assertEqual(body["status"], "blocked")
        self.assertEqual({b["kind"] for b in body["blockers"]},
                         {"open_remediation"})
        b0 = body["blockers"][0]
        self.assertEqual(b0["receipt_key"], t1)
        self.assertEqual(b0["status"], "open")
        self.assertEqual(b0["products"], [p1, p2, p3])
        self.assertIn("item_id", b0)

        # 3) 处置结案 -> planned：下游先删，同层稳定排序，记录 basis_seq。
        self._remediate_all()
        plan = self._delreq(self.k("d3")).json()
        self.assertEqual(plan["status"], "planned")
        self.assertEqual(plan["blockers"], [])
        self.assertEqual(plan["batches"], [
            {"batch_no": 1, "product_ids": [p3]},
            {"batch_no": 2, "product_ids": [p2]},
            {"batch_no": 3, "product_ids": [p1]}])
        self.assertEqual(plan["basis_seq"], rev_seq)
        self.assertFalse(plan["stale"])
        rid = plan["request_id"]

        # 4) GET 与 POST 口径一致；同键重放 200 原计划；同键异内容 409。
        got = self.client.get(f"/deletion-requests/{rid}")
        self.assertEqual(got.status_code, 200, got.text)
        self.assertEqual(got.json()["batches"], plan["batches"])
        self.assertFalse(got.json()["stale"])
        replay = self._delreq(self.k("d3"), expected=(200,)).json()
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(replay["request_id"], rid)
        self.assertEqual(replay["batches"], plan["batches"])
        conflict = self.client.post("/deletion-requests", json={
            "subject_id": self.subject, "product_ids": [p1],
            "requested_at": "2026-09-26T08:00:00Z"},
            headers={"Idempotency-Key": self.k("d3")})
        self.assertEqual(conflict.status_code, 409)

        # 5) 新许可 -> 快照变化：GET 标记过期并要求重新评估，历史计划不改写。
        self._grant("g2")
        got = self.client.get(f"/deletion-requests/{rid}").json()
        self.assertTrue(got["stale"])
        self.assertIsNotNone(got["detail"])
        self.assertGreater(got["current_seq"], got["basis_seq"])
        self.assertEqual(got["batches"], plan["batches"])
        # 此前的 blocked 请求同样按 basis_seq 标记过期。
        got_blocked = self.client.get(
            f"/deletion-requests/{blocked_id}").json()
        self.assertTrue(got_blocked["stale"])
        self.assertEqual(got_blocked["status"], "blocked")

        # 6) 重新评估（新幂等键）：许可恢复有效 -> 再次被活动许可阻断。
        body = self._delreq(self.k("d4")).json()
        self.assertEqual(body["status"], "blocked")
        self.assertEqual(body["blockers"][0]["kind"], "active_grant")
        self.assertEqual(body["blockers"][0]["grant_id"], "g2")

        # 7) 历史回执与历史回放不被改写；产物仍在（未真实执行删除）。
        receipt = self.client.get(f"/receipts/{t1}").json()
        self.assertEqual(receipt["decision"], "allow")
        old = self.client.get(
            f"/subjects/{self.subject}/products/{p1}?as_of_seq={rev_seq - 1}"
        ).json()
        self.assertEqual(old["status"], "active")
        cur = self.client.get(
            f"/subjects/{self.subject}/products/{p1}")
        self.assertEqual(cur.status_code, 200)

    # -------------------------------------------- 范围展开、校验与空主体
    def test_partial_scope_validation_and_empty_subject(self):
        self._grant("g1")
        t1, t2 = self.k("t1"), self.k("t2")
        pa, pb, pc = self.k("pa"), self.k("pb"), self.k("pc")
        self._task(t1, [
            {"product_id": pa, "groups": [[{"kind": "receipt", "ref": t1}]]},
            {"product_id": pb, "groups": [[{"kind": "product", "ref": pa}]]}])
        self._task(t2, [
            {"product_id": pc, "groups": [[{"kind": "receipt", "ref": t2}]]}])

        # 请求删除 pa：实际范围含下游 pb，不含独立产物 pc。
        body = self._delreq(self.k("d1"), [pa]).json()
        self.assertEqual(body["status"], "blocked")  # g1 仍有效
        self.assertEqual(body["product_ids"], [pa])
        self.assertEqual(body["scope"], [pa, pb])
        self.assertEqual(body["blockers"][0]["products"], [pa, pb])

        # 请求范围归一化：顺序 / 重复不影响指纹，同键重放原计划。
        replay = self.client.post("/deletion-requests", json={
            "subject_id": self.subject,
            "product_ids": [pa, pa],
            "requested_at": "2026-09-26T08:00:00Z"},
            headers={"Idempotency-Key": self.k("d1")})
        self.assertEqual(replay.status_code, 200)
        self.assertTrue(replay.json()["idempotent_replay"])

        # 未知产物 -> 422；缺幂等键 -> 422；未知请求 -> 404。
        self._delreq(self.k("d2"), ["ghost"], expected=(422,))
        r = self.client.post("/deletion-requests", json={
            "subject_id": self.subject, "product_ids": [],
            "requested_at": "2026-09-26T08:00:00Z"})
        self.assertEqual(r.status_code, 422)
        self.assertEqual(self.client.get(
            "/deletion-requests/99999999").status_code, 404)

        # 无产物主体：空范围 -> 空计划（无可删内容）。
        r = self.client.post("/deletion-requests", json={
            "subject_id": "del-empty-" + uuid.uuid4().hex[:8],
            "product_ids": [],
            "requested_at": "2026-09-26T08:00:00Z"},
            headers={"Idempotency-Key": self.k("d-empty")})
        self.assertEqual(r.status_code, 201, r.text)
        body = r.json()
        self.assertEqual(body["status"], "planned")
        self.assertEqual(body["scope"], [])
        self.assertEqual(body["batches"], [])

    # ---------------------------------------------------------- 并发幂等
    def test_blocked_by_open_remediation_goes_stale_after_closure(self):
        """回归：处置结案（无新许可 / 撤销）后，历史 blocked 查询必须过期。"""
        self._grant("g1")
        t1 = self.k("t1")
        p1, p2 = self.k("p1"), self.k("p2")
        self._task(t1, [
            {"product_id": p1, "groups": [[{"kind": "receipt", "ref": t1}]]},
            {"product_id": p2, "groups": [[{"kind": "product", "ref": p1}]]}])
        rev = self._revoke("g1")
        rev_seq = rev["event"]["seq"]

        # 1) 删除请求被 open_remediation 阻断（回执 + 处置项可定位）。
        body = self._delreq(self.k("d1")).json()
        self.assertEqual(body["status"], "blocked")
        self.assertEqual([b["kind"] for b in body["blockers"]],
                         ["open_remediation"])
        b0 = body["blockers"][0]
        iid = b0["item_id"]
        rid = body["request_id"]
        self.assertEqual(body["basis_seq"], rev_seq)
        self.assertFalse(body["stale"])

        # 2) 处置仍未结时 GET 口径一致：stale=false、历史 blocked 保留。
        got = self.client.get(f"/deletion-requests/{rid}")
        self.assertEqual(got.status_code, 200, got.text)
        self.assertFalse(got.json()["stale"])
        self.assertEqual(got.json()["status"], "blocked")

        # 3) 提交并批准关联处置（不新增许可或撤销）：仅处置台账追加记录。
        evidence = [{"product_id": p, "summary": "已清除"}
                    for p in b0["products"]]
        r = self.client.post(
            f"/remediation/items/{iid}/submissions",
            json={"version": 1, "cease_declaration": "已停止使用",
                  "evidence": evidence},
            headers={**RA_H, "Idempotency-Key": self.k(f"rem-{iid}")})
        self.assertEqual(r.status_code, 201, r.text)
        r = self.client.post(
            f"/remediation/items/{iid}/reviews",
            json={"version": 1, "action": "approve"}, headers=ADMIN_H)
        self.assertEqual(r.status_code, 201, r.text)

        # 4) GET 复用登记回执 / 下游闭包 / 处置派生重新评估：
        #    stale=true，提示新幂等键；current_seq 未变；历史记录原样保留。
        got = self.client.get(f"/deletion-requests/{rid}").json()
        self.assertTrue(got["stale"])
        self.assertIsNotNone(got["detail"])
        self.assertIn("新的幂等键", got["detail"])
        self.assertEqual(got["current_seq"], rev_seq)
        self.assertEqual(got["basis_seq"], rev_seq)
        self.assertEqual(got["status"], "blocked")
        self.assertEqual([b["kind"] for b in got["blockers"]],
                         ["open_remediation"])
        self.assertEqual(got["blockers"][0]["item_id"], iid)
        self.assertEqual(got["batches"], [])

        # 5) 同键重放响应不变（200，历史 blocked 计划与回执不改写）。
        replay = self._delreq(self.k("d1"), expected=(200,)).json()
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(replay["request_id"], rid)
        self.assertEqual(replay["status"], "blocked")
        self.assertEqual(replay["blockers"], body["blockers"])
        self.assertEqual(replay["batches"], [])
        self.assertTrue(replay["stale"])

        # 6) 新幂等键重新评估：处置已结案 -> planned，下游先删批次。
        plan = self._delreq(self.k("d2")).json()
        self.assertEqual(plan["status"], "planned")
        self.assertEqual(plan["blockers"], [])
        self.assertFalse(plan["stale"])
        self.assertEqual(plan["batches"], [
            {"batch_no": 1, "product_ids": [p2]},
            {"batch_no": 2, "product_ids": [p1]}])

        # 7) 追加式共存：旧请求仍历史 blocked + stale；新请求 planned 不 stale。
        old = self.client.get(f"/deletion-requests/{rid}").json()
        self.assertTrue(old["stale"])
        self.assertEqual(old["status"], "blocked")
        new = self.client.get(
            f"/deletion-requests/{plan['request_id']}").json()
        self.assertFalse(new["stale"])
        self.assertEqual(new["status"], "planned")
        self.assertEqual(new["batches"], plan["batches"])

    def test_remediation_submitted_without_closure_not_stale(self):
        """提交 / 驳回（处置项仍未结）不改变结论：stale 保持 false。"""
        self._grant("g1")
        t1 = self.k("t1")
        p1 = self.k("p1")
        self._task(t1, [{"product_id": p1,
                         "groups": [[{"kind": "receipt", "ref": t1}]]}])
        self._revoke("g1")
        body = self._delreq(self.k("d1")).json()
        iid = body["blockers"][0]["item_id"]
        rid = body["request_id"]

        r = self.client.post(
            f"/remediation/items/{iid}/submissions",
            json={"version": 1, "cease_declaration": "已停止使用",
                  "evidence": [{"product_id": p1, "summary": "已清除"}]},
            headers={**RA_H, "Idempotency-Key": self.k("sub-1")})
        self.assertEqual(r.status_code, 201, r.text)
        got = self.client.get(f"/deletion-requests/{rid}").json()
        self.assertFalse(got["stale"])
        # 历史阻断记录保留登记时状态（open），不可变；当前处置状态查台账。
        self.assertEqual(got["blockers"][0]["status"], "open")
        case = self.client.get(
            f"/subjects/{self.subject}/remediation",
            headers=RA_H).json()
        item = next(i for i in case["items"] if i["item_id"] == iid)
        self.assertEqual(item["status"], "submitted")

        r = self.client.post(
            f"/remediation/items/{iid}/reviews",
            json={"version": 1, "action": "reject", "comment": "补证"},
            headers=ADMIN_H)
        self.assertEqual(r.status_code, 201, r.text)
        got = self.client.get(f"/deletion-requests/{rid}").json()
        self.assertFalse(got["stale"])

    # ---------------------------------------------------------- 并发幂等
    def test_concurrent_same_key_exactly_once(self):
        """同一幂等键并发提交删除请求：恰好一次登记，其余 200 重放。"""
        self._grant("g1")
        t1, p1 = self.k("t1"), self.k("p1")
        self._task(t1, [{"product_id": p1,
                         "groups": [[{"kind": "receipt", "ref": t1}]]}])
        key = self.k("d-race")
        payload = {"subject_id": self.subject, "product_ids": [],
                   "requested_at": "2026-09-26T08:00:00Z"}
        n = 6
        barrier = threading.Barrier(n)
        results: list = [None] * n

        def worker(i):
            barrier.wait()
            results[i] = self.client.post(
                "/deletion-requests", json=payload,
                headers={"Idempotency-Key": key})

        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        statuses = sorted(r.status_code for r in results)
        self.assertEqual(statuses.count(201), 1,
                         f"同幂等键必须恰好登记一次: {statuses}")
        self.assertEqual(statuses.count(200), n - 1)
        ids = {r.json()["request_id"] for r in results}
        self.assertEqual(len(ids), 1)

# ---------------------------------------------------------------- 合规证明
# 合规证明签名密钥（与 config.py / docker-compose.yml 默认值一致）。
ATTEST_KEY = "dev-attestation-hmac-key"


@unittest.skipIf(TestClient is None, "缺少 fastapi/psycopg 依赖")
class AttestationApiTests(unittest.TestCase):
    """合规证明端到端：快照重放、签名验签、幂等、不可变、校验与并发一致性。"""

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault(
            "DATABASE_URL", "postgresql://consent:consent@localhost:5432/consent")
        for attempt in range(30):
            try:
                init_pool()
                break
            except Exception:
                if attempt == 29:
                    raise
                time.sleep(1)
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        shutdown_pool()

    def setUp(self):
        self.subject = "att-" + uuid.uuid4().hex[:12]
        self.tag = uuid.uuid4().hex[:8]

    def k(self, name: str) -> str:
        return f"{name}-{self.tag}"

    def _grant(self, gid, recipient="partner-a"):
        r = self.client.post("/grants", json={
            "subject_id": self.subject, "grant_id": gid,
            "category": "email", "purpose": "marketing",
            "recipient": recipient,
            "valid_from": "2026-01-01T00:00:00Z"})
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()

    def _task(self, key, products, recipient="partner-a"):
        r = self.client.post("/tasks", json={
            "subject_id": self.subject, "category": "email",
            "purpose": "marketing", "recipient": recipient,
            "use_at": "2026-05-01T00:00:00Z", "products": products},
            headers={"Idempotency-Key": key})
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()

    def _revoke(self, gid, bea="2026-01-15T00:00:00Z"):
        r = self.client.post("/revocations", json={
            "subject_id": self.subject, "grant_id": gid,
            "business_effective_at": bea})
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()

    def _attest(self, key, pids, *, as_of_seq, use_at="2026-05-01T00:00:00Z",
                expected=(201,)):
        r = self.client.post("/attestations", json={
            "subject_id": self.subject, "product_ids": pids,
            "use_at": use_at, "as_of_seq": as_of_seq},
            headers={"Idempotency-Key": key})
        self.assertIn(r.status_code, expected, r.text)
        return r

    def _verify(self, body):
        return self.client.post("/attestations/verify", json=body)

    # ------------------------------------------------ 全周期：allow -> 撤销 -> 处置
    def test_attestation_full_lifecycle_replay_sign_verify_immutable(self):
        g1 = self._grant("g1")["seq"]
        t1 = self.k("t1")
        p1, p2 = self.k("p1"), self.k("p2")
        # p1 <- t1；p2 依赖 p1（链状血缘）。
        self._task(t1, [
            {"product_id": p1, "groups": [[{"kind": "receipt", "ref": t1}]]},
            {"product_id": p2, "groups": [[{"kind": "product", "ref": p1}]]}])
        rev = self._revoke("g1")
        rev_seq = rev["event"]["seq"]

        # 1) 撤销后的证明：p1/p2 blocked，删除结论 blocked（未结处置）。
        r = self._attest(self.k("a1"), [p1, p2], as_of_seq=rev_seq)
        body = r.json()
        self.assertFalse(body["idempotent_replay"])
        self.assertEqual(body["as_of_seq"], rev_seq)
        self.assertEqual(body["basis_seq"], rev_seq)
        self.assertEqual(body["signature_alg"], "HMAC-SHA256")
        claim = body["claim"]
        self.assertEqual(claim["version"], "1.0")
        self.assertEqual(claim["product_ids"], [p1, p2])
        self.assertEqual(claim["products"][p1]["status"], "blocked")
        self.assertEqual(claim["products"][p1]["invalidating_events"],
                         [rev_seq])
        self.assertEqual(claim["products"][p1]["receipts"],
                         [{"receipt_key": t1, "currently_valid": False,
                           "invalidating_events": [rev_seq]}])
        items = claim["products"][p1]["remediation_items"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["status"], "open")
        self.assertEqual(items[0]["receipt_key"], t1)
        self.assertEqual(claim["deletion"]["status"], "blocked")
        self.assertEqual(
            [b["kind"] for b in claim["deletion"]["blockers"]],
            ["open_remediation"])
        self.assertEqual(claim["deletion"]["scope"], [p1, p2])
        self.assertEqual(claim["deletion"]["batches"], [])
        # 声明不含服务端生成时间 / 自由文本等可变字段。
        self.assertNotIn("created_at", claim)

        # 2) GET 返回保存的同一字节 / 摘要 / 签名（不按当前状态重放）。
        aid = body["attestation_id"]
        got = self.client.get(f"/attestations/{aid}")
        self.assertEqual(got.status_code, 200, got.text)
        g = got.json()
        self.assertEqual(g["claim"], claim)
        self.assertEqual(g["claim_canonical"], body["claim_canonical"])
        self.assertEqual(g["digest"], body["digest"])
        self.assertEqual(g["signature"], body["signature"])
        self.assertNotIn("idempotent_replay", g)

        # 3) 独立验签：claim_canonical 原样通过。
        vr = self._verify({"claim_canonical": g["claim_canonical"],
                           "digest": g["digest"], "signature": g["signature"]})
        self.assertEqual(vr.status_code, 200, vr.text)
        vb = vr.json()
        self.assertTrue(vb["valid"])
        self.assertTrue(vb["digest_ok"])
        self.assertTrue(vb["signature_ok"])
        self.assertEqual(vb["digest"], g["digest"])

        # 3b) 用 claim 对象验签（固定字段重规范化，字节一致）。
        vr = self._verify({"claim": claim, "digest": g["digest"],
                           "signature": g["signature"]})
        self.assertTrue(vr.json()["valid"])

        # 4) 篡改字节：摘要与签名均失败（claim_canonical 中改产品 ID）。
        tampered = g["claim_canonical"].replace(p2, self.k("pX"), 1)
        vr = self._verify({"claim_canonical": tampered,
                           "digest": g["digest"], "signature": g["signature"]})
        self.assertEqual(vr.status_code, 200)
        vb = vr.json()
        self.assertFalse(vb["valid"])
        self.assertFalse(vb["digest_ok"])
        self.assertFalse(vb["signature_ok"])

        # 4b) 篡改 claim 对象（as_of_seq 改大）：同样验签失败。
        bad_claim = {**claim, "as_of_seq": rev_seq + 100}
        vr = self._verify({"claim": bad_claim, "digest": g["digest"],
                           "signature": g["signature"]})
        self.assertFalse(vr.json()["valid"])

        # 4c) 仅摘要 / 签名错误分别定位。
        bad_digest = "0" * 64
        vr = self._verify({"claim_canonical": g["claim_canonical"],
                           "digest": bad_digest, "signature": g["signature"]})
        vb = vr.json()
        self.assertFalse(vb["valid"])
        self.assertFalse(vb["digest_ok"])
        self.assertTrue(vb["signature_ok"])
        vr = self._verify({"claim_canonical": g["claim_canonical"],
                           "digest": g["digest"], "signature": "0" * 64})
        vb = vr.json()
        self.assertFalse(vb["valid"])
        self.assertTrue(vb["digest_ok"])
        self.assertFalse(vb["signature_ok"])

        # 4d) 非十六进制摘要 / 签名、缺声明、未知 alg -> 422。
        self.assertEqual(self._verify(
            {"claim_canonical": g["claim_canonical"], "digest": "zz",
             "signature": g["signature"]}).status_code, 422)
        self.assertEqual(self._verify(
            {"digest": g["digest"], "signature": g["signature"]}).status_code,
            422)
        self.assertEqual(self._verify(
            {"claim_canonical": g["claim_canonical"], "digest": g["digest"],
             "signature": g["signature"], "alg": "RSA-SHA256"}).status_code,
            422)

        # 5) 历史快照证明：as_of_seq 回到撤销前 -> active / planned，
        #    且与撤销后证明共存（追加式，互不影响）。
        old = self._attest(self.k("a0"), [p1, p2], as_of_seq=g1).json()
        self.assertEqual(old["claim"]["products"][p1]["status"], "active")
        self.assertEqual(
            old["claim"]["products"][p1]["receipts"][0]
            ["currently_valid"], True)
        self.assertEqual(
            old["claim"]["products"][p1]["remediation_items"], [])
        self.assertEqual(old["claim"]["deletion"]["status"], "blocked")
        self.assertEqual(
            [b["kind"] for b in old["claim"]["deletion"]["blockers"]],
            ["active_grant"])
        b0 = old["claim"]["deletion"]["blockers"][0]
        self.assertEqual(b0["grant_id"], "g1")
        self.assertEqual(b0["grant_seq"], g1)
        self.assertEqual(b0["receipt_key"], t1)
        self.assertEqual(b0["products"], [p1, p2])
        # 旧证明自身验签通过。
        vr = self._verify({"claim_canonical": old["claim_canonical"],
                           "digest": old["digest"],
                           "signature": old["signature"]})
        self.assertTrue(vr.json()["valid"])

        # 6) 处置结案（提交 + 批准）后：先前证明字节 / 签名原样不变；
        #    新快照证明转为 planned 并给下游先删批次。
        case = self.client.get(
            f"/subjects/{self.subject}/remediation", headers=RA_H).json()
        for iid in case["open_item_ids"]:
            item = next(i for i in case["items"] if i["item_id"] == iid)
            ev = [{"product_id": p, "summary": "已清除"}
                  for p in item["products"]]
            rr = self.client.post(
                f"/remediation/items/{iid}/submissions",
                json={"version": 1, "cease_declaration": "已停止使用",
                      "evidence": ev},
                headers={**RA_H, "Idempotency-Key": self.k(f"s-{iid}")})
            self.assertEqual(rr.status_code, 201, rr.text)
            rr = self.client.post(
                f"/remediation/items/{iid}/reviews",
                json={"version": 1, "action": "approve"}, headers=ADMIN_H)
            self.assertEqual(rr.status_code, 201, rr.text)
        # 既有证明（撤销后、处置前）逐字节保留且仍可验签。
        g_again = self.client.get(f"/attestations/{aid}").json()
        self.assertEqual(g_again["digest"], g["digest"])
        self.assertEqual(g_again["signature"], g["signature"])
        self.assertEqual(g_again["claim"], claim)
        # 新证明：无阻断 -> planned，批次下游先删（p2 先于 p1）。
        planned = self._attest(self.k("a2"), [p1, p2],
                               as_of_seq=rev_seq).json()
        self.assertEqual(planned["claim"]["deletion"]["status"], "planned")
        self.assertEqual(planned["claim"]["deletion"]["blockers"], [])
        self.assertEqual(planned["claim"]["deletion"]["batches"],
                         [{"batch_no": 1, "product_ids": [p2]},
                          {"batch_no": 2, "product_ids": [p1]}])
        # 处置项仍被引用，但状态已是 approved（结案依据进入声明）。
        self.assertEqual(
            planned["claim"]["products"][p1]["remediation_items"][0]
            ["status"], "approved")
        # 新证明内容与旧证明不同（快照台账状态不同），各自验签。
        self.assertNotEqual(planned["digest"], g["digest"])
        vr = self._verify({"claim_canonical": planned["claim_canonical"],
                           "digest": planned["digest"],
                           "signature": planned["signature"]})
        self.assertTrue(vr.json()["valid"])

    # ------------------------------------------------ 幂等与校验
    def test_idempotent_replay_conflict_and_validation(self):
        gseq = self._grant("g1")["seq"]
        t1, p1 = self.k("t1"), self.k("p1")
        self._task(t1, [{"product_id": p1,
                         "groups": [[{"kind": "receipt", "ref": t1}]]}])
        body = {"subject_id": self.subject, "product_ids": [p1],
                "use_at": "2026-05-01T00:00:00Z", "as_of_seq": gseq}

        # 缺幂等键 -> 422；空产品范围 -> 422。
        self.assertEqual(self.client.post("/attestations", json=body
                                          ).status_code, 422)
        empty = {**body, "product_ids": []}
        self.assertEqual(self.client.post(
            "/attestations", json=empty,
            headers={"Idempotency-Key": self.k("e")}).status_code, 422)

        # 首次 201；同键同内容（范围乱序去重）-> 200 重放同一证明。
        r1 = self.client.post("/attestations", json=body,
                              headers={"Idempotency-Key": self.k("i1")})
        self.assertEqual(r1.status_code, 201, r1.text)
        replay = self.client.post(
            "/attestations",
            json={**body, "product_ids": [p1, p1]},
            headers={"Idempotency-Key": self.k("i1")})
        self.assertEqual(replay.status_code, 200)
        self.assertTrue(replay.json()["idempotent_replay"])
        self.assertEqual(replay.json()["attestation_id"],
                         r1.json()["attestation_id"])
        self.assertEqual(replay.json()["digest"], r1.json()["digest"])

        # 同键异内容（use_at 不同）-> 409。
        self.assertEqual(self.client.post(
            "/attestations", json={**body, "use_at": "2026-06-01T00:00:00Z"},
            headers={"Idempotency-Key": self.k("i1")}).status_code, 409)
        # 新键同内容 -> 独立新证明（声明内容一致 -> 摘要一致，ID 不同）。
        r3 = self.client.post(
            "/attestations", json=body,
            headers={"Idempotency-Key": self.k("i2")})
        self.assertEqual(r3.status_code, 201)
        self.assertEqual(r3.json()["digest"], r1.json()["digest"])
        self.assertEqual(r3.json()["signature"], r1.json()["signature"])

        # 未知产品 -> 422；越界 as_of_seq -> 422。
        self.assertEqual(self.client.post(
            "/attestations", json={**body, "product_ids": [self.k("ghost")]},
            headers={"Idempotency-Key": self.k("u1")}).status_code, 422)
        self.assertEqual(self.client.post(
            "/attestations", json=body,
            headers={"Idempotency-Key": self.k("u2")}).status_code, 201)
        far = self.client.post(
            "/attestations", json={**body, "as_of_seq": 999_999_999},
            headers={"Idempotency-Key": self.k("u3")})
        self.assertEqual(far.status_code, 422, far.text)

        # 未知证明 -> 404。
        self.assertEqual(self.client.get(
            "/attestations/99999999").status_code, 404)

    def test_as_of_seq_before_product_recorded_is_rejected(self):
        """产品在 as_of_seq 之后才登记：快照中尚不存在 -> 422。"""
        gseq = self._grant("g1")["seq"]
        t1, p1 = self.k("t1"), self.k("p1")
        task = self._task(t1, [{"product_id": p1,
                               "groups": [[{"kind": "receipt",
                                            "ref": t1}]]}])
        # 任务 / 产物登记不产生事件序号；追加一条无关事件制造更晚序号，
        # 但保证 recorded_seq（回执登记时主体最大事件序号）= gseq 之后
        # 仍 <= gseq——这里直接用边界：recorded_seq == gseq 时允许。
        r = self._attest(self.k("ok"), [p1], as_of_seq=gseq)
        self.assertEqual(r.status_code, 201, r.text)
        # 撤销后再登记新产物：新产品 recorded_seq > gseq，回到 gseq 拒绝。
        rev = self._revoke("g1")
        t2, p3 = self.k("t2"), self.k("p3")
        self._task(t2, [{"product_id": p3,
                         "groups": [[{"kind": "receipt", "ref": t2}]]}])
        r = self._attest(self.k("early"), [p3], as_of_seq=gseq,
                         expected=(422,))
        self.assertIn("登记序号", r.text)
        # 在撤销快照（含新产品）上则允许，且声明反映其 blocked 状态。
        r = self._attest(self.k("cur"), [p3], as_of_seq=rev["event"]["seq"])
        self.assertEqual(r.status_code, 201, r.text)
        self.assertEqual(r.json()["claim"]["products"][p3]["status"],
                         "blocked")

    def test_empty_subject_scope_planned_empty(self):
        """无事件主体：as_of_seq 越界（无任何事件）-> 422；有事件但无产物
        时引用未知产物 -> 422（空范围在 Pydantic 层即被拒）。"""
        s = "att-empty-" + uuid.uuid4().hex[:8]
        r = self.client.post("/attestations", json={
            "subject_id": s, "product_ids": ["x"],
            "use_at": "2026-05-01T00:00:00Z", "as_of_seq": 1},
            headers={"Idempotency-Key": self.k("empty")})
        self.assertEqual(r.status_code, 422)  # 越界（当前最大序号为 0）

    # ------------------------------------------------ 并发追加下的快照一致性
    def test_concurrent_appends_snapshot_consistency(self):
        """并发追加事件时，as_of_seq 快照证明必须与独立只读回放完全一致。

        多个证明请求与许可 / 撤销追加在主体咨询锁上并发：每个证明在持锁
        后的 REPEATABLE READ 快照中重放，故其内容必须等于“在该 as_of_seq
        下独立调用只读产品接口”得到的状态（不会读到半提交状态，也不会
        沿用持锁前的旧快照）。
        """
        self._grant("g1")
        t1, p1 = self.k("t1"), self.k("p1")
        self._task(t1, [{"product_id": p1,
                         "groups": [[{"kind": "receipt", "ref": t1}]]}])
        current = self.client.get(
            f"/subjects/{self.subject}/events").json()["events"]
        seq_after_task = max(e["seq"] for e in current)

        results: list = []
        gate = threading.Event()
        release_lock = threading.Event()
        coord_errors: list = []

        def coordinator():
            try:
                assert db.pool is not None
                with db.pool.connection() as conn:
                    conn.execute("SELECT pg_advisory_lock(hashtext(%s))",
                                 (self.subject,))
                    conn.commit()
                    gate.set()
                    release_lock.wait(timeout=15)
                    conn.execute("SELECT pg_advisory_unlock(hashtext(%s))",
                                 (self.subject,))
                    conn.commit()
            except Exception:  # pragma: no cover
                import traceback
                coord_errors.append(traceback.format_exc())
                gate.set()

        def attest(i):
            results.append(("att", i, self.client.post(
                "/attestations", json={
                    "subject_id": self.subject, "product_ids": [p1],
                    "use_at": "2026-05-01T00:00:00Z",
                    "as_of_seq": seq_after_task},
                headers={"Idempotency-Key": self.k(f"c-att-{i}")})))

        def revoke(i):
            results.append(("rev", i, self.client.post("/revocations", json={
                "subject_id": self.subject, "grant_id": "g1",
                "business_effective_at": "2026-01-15T00:00:00Z"})))

        coord = threading.Thread(target=coordinator)
        coord.start()
        self.assertTrue(gate.wait(timeout=10), "协调器未能持锁")
        workers = ([threading.Thread(target=attest, args=(i,))
                    for i in range(4)]
                   + [threading.Thread(target=revoke, args=(0,))])
        for t in workers:
            t.start()
        time.sleep(0.5)
        release_lock.set()
        for t in workers:
            t.join()
        coord.join(timeout=10)
        self.assertEqual(coord_errors, [])

        atts = [r for kind, _, r in results if kind == "att"]
        revs = [r for kind, _, r in results if kind == "rev"]
        self.assertEqual(len(revs), 1)
        self.assertEqual(revs[0].status_code, 201, revs[0].text)
        self.assertTrue(all(r.status_code == 201 for r in atts),
                        [r.status_code for r in atts])

        # 所有证明锚定同一 as_of_seq（撤销前）：声明逐字节相同、
        # 与撤销是否先提交无关（锁先于快照保证重放口径一致）。
        digests = {r.json()["digest"] for r in atts}
        self.assertEqual(len(digests), 1, f"同快照证明摘要不一致: {digests}")
        claim0 = atts[0].json()["claim"]
        self.assertEqual(claim0["products"][p1]["status"], "active")
        self.assertEqual(claim0["products"][p1]["receipts"][0]
                         ["currently_valid"], True)
        self.assertEqual(claim0["deletion"]["status"], "blocked")
        self.assertEqual(
            [b["kind"] for b in claim0["deletion"]["blockers"]],
            ["active_grant"])

        # 与独立只读 as_of_seq 回放口径完全一致。
        prod_old = self.client.get(
            f"/subjects/{self.subject}/products/{p1}"
            f"?as_of_seq={seq_after_task}").json()
        self.assertEqual(prod_old["status"], "active")
        self.assertEqual(prod_old["invalidating_events"], [])

        # 证明全部可独立验签。
        for r in atts:
            b = r.json()
            vr = self._verify({"claim_canonical": b["claim_canonical"],
                               "digest": b["digest"],
                               "signature": b["signature"]})
            self.assertTrue(vr.json()["valid"], vr.text)

        # 撤销提交后的“当前”证明与历史证明不同：blocked + open_remediation，
        # 历史证明摘要不变（后续事件不改写既有证明）。
        rev_seq = revs[0].json()["event"]["seq"]
        cur = self._attest(self.k("c-after"), [p1], as_of_seq=rev_seq).json()
        self.assertEqual(cur["claim"]["products"][p1]["status"], "blocked")
        self.assertEqual(
            [b["kind"] for b in cur["claim"]["deletion"]["blockers"]],
            ["open_remediation"])
        self.assertNotIn(cur["digest"], digests)
        for r in atts:
            got = self.client.get(
                f"/attestations/{r.json()['attestation_id']}").json()
            self.assertEqual(got["digest"], r.json()["digest"])
            self.assertEqual(got["claim"], claim0)

    def test_tampered_stored_bytes_not_returned_but_verify_stays_statefree(self):
        """验签端点不读数据库：篡改保存字节后，验签仅以提交字节为准。

        直接改写底层存储中的 claim_bytes，模拟持久层被篡改：GET 取出的
        篡改字节与原签名不再匹配（验签失败），且验签过程不依赖任何业务
        状态——用未篡改的原 claim_canonical + 原签名仍通过。
        """
        gseq = self._grant("g1")["seq"]
        t1, p1 = self.k("t1"), self.k("p1")
        self._task(t1, [{"product_id": p1,
                         "groups": [[{"kind": "receipt", "ref": t1}]]}])
        b = self._attest(self.k("t"), [p1], as_of_seq=gseq).json()
        original_canonical = b["claim_canonical"]

        assert db.pool is not None
        with db.pool.connection() as conn:
            conn.execute(
                "UPDATE attestations SET claim_bytes = %s "
                "WHERE attestation_id=%s",
                (original_canonical.replace(
                    '"status":"active"', '"status":"blocked"', 1).encode(),
                 b["attestation_id"]))
            conn.commit()
        got = self.client.get(
            f"/attestations/{b['attestation_id']}").json()
        self.assertEqual(got["claim"]["products"][p1]["status"], "blocked")
        # 保存的原签名对篡改字节验签失败（digest_ok=False）。
        vr = self._verify({"claim_canonical": got["claim_canonical"],
                           "digest": got["digest"],
                           "signature": got["signature"]})
        self.assertFalse(vr.json()["valid"])
        # 验签不读业务状态：未篡改字节 + 原签名照常通过。
        vr = self._verify({"claim_canonical": original_canonical,
                           "digest": b["digest"],
                           "signature": b["signature"]})
        self.assertTrue(vr.json()["valid"])


@unittest.skipIf(TestClient is None, "缺少 fastapi/psycopg 依赖")
class ComplianceDiffApiTests(unittest.TestCase):
    """合规状态双时点差异报告端到端：双时点重放、added/removed/changed/
    unchanged 分类、翻转原因定位、校验拒绝、只读性、后续事件不改变报告，
    以及并发追加事件下两侧快照一致、跨主体事件不误纳入。"""

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault(
            "DATABASE_URL", "postgresql://consent:consent@localhost:5432/consent")
        for attempt in range(30):
            try:
                init_pool()
                break
            except Exception:
                if attempt == 29:
                    raise
                time.sleep(1)
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        shutdown_pool()

    def setUp(self):
        self.subject = "diff-" + uuid.uuid4().hex[:12]
        self.tag = uuid.uuid4().hex[:8]

    def k(self, name: str) -> str:
        return f"{name}-{self.tag}"

    def _grant(self, gid, recipient="partner-a", category="email"):
        r = self.client.post("/grants", json={
            "subject_id": self.subject, "grant_id": gid,
            "category": category, "purpose": "marketing",
            "recipient": recipient,
            "valid_from": "2026-01-01T00:00:00Z"})
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()

    def _task(self, key, products, recipient="partner-a"):
        r = self.client.post("/tasks", json={
            "subject_id": self.subject, "category": "email",
            "purpose": "marketing", "recipient": recipient,
            "use_at": "2026-05-01T00:00:00Z", "products": products},
            headers={"Idempotency-Key": key})
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()

    def _revoke(self, gid, bea="2026-01-15T00:00:00Z"):
        r = self.client.post("/revocations", json={
            "subject_id": self.subject, "grant_id": gid,
            "business_effective_at": bea})
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()

    def _diff(self, pids, from_seq, to_seq, expected=(200,)):
        r = self.client.post("/compliance-diffs", json={
            "subject_id": self.subject, "product_ids": pids,
            "use_at": "2026-05-01T00:00:00Z",
            "from_seq": from_seq, "to_seq": to_seq})
        self.assertIn(r.status_code, expected, r.text)
        return r

    # ------------------------------------------------ 全周期：分类与翻转原因
    def test_diff_lifecycle_classification_and_locatable_reasons(self):
        g1 = self._grant("g1")["seq"]
        t1, p1, p2 = self.k("t1"), self.k("p1"), self.k("p2")
        self._task(t1, [
            {"product_id": p1, "groups": [[{"kind": "receipt", "ref": t1}]]},
            {"product_id": p2, "groups": [[{"kind": "product", "ref": p1}]]}])
        rev_seq = self._revoke("g1")["event"]["seq"]

        # ---- diff(g1, rev)：追溯撤销落入区间，范围乱序提交 -> 稳定排序输出。
        d = self._diff([p2, p1, p1], g1, rev_seq).json()
        self.assertEqual(d["subject_id"], self.subject)
        self.assertEqual(d["from_seq"], g1)
        self.assertEqual(d["to_seq"], rev_seq)
        self.assertEqual(d["from_basis_seq"], g1)
        self.assertEqual(d["to_basis_seq"], rev_seq)
        self.assertEqual([p["product_id"] for p in d["products"]], [p1, p2])
        for entry, expect_receipts in ((d["products"][0], [t1]),
                                       (d["products"][1], [t1])):
            self.assertEqual(entry["classification"], "changed")
            self.assertEqual(entry["from"]["presence"], "present")
            self.assertEqual(entry["from"]["status"], "active")
            self.assertEqual(entry["to"]["status"], "blocked")
            self.assertEqual(entry["to"]["invalidating_events"], [rev_seq])
            flip = entry["flip_reasons"][0]
            self.assertEqual(flip["kind"], "status_flip")
            self.assertEqual(flip["from_status"], "active")
            self.assertEqual(flip["to_status"], "blocked")
            self.assertEqual(flip["causing_receipts"], expect_receipts)
        # 传递回执：valid -> invalid，翻转原因定位到撤销事件（含业务生效时间）。
        rec = d["products"][0]["receipts"][0]
        self.assertEqual(rec["receipt_key"], t1)
        self.assertEqual(rec["classification"], "changed")
        self.assertEqual(rec["decision"], "allow")
        self.assertEqual(rec["basis"]["grant_id"], "g1")
        self.assertEqual(rec["basis"]["seq"], g1)
        self.assertTrue(rec["from"]["currently_valid"])
        self.assertFalse(rec["to"]["currently_valid"])
        self.assertEqual(rec["to"]["invalidating_events"], [rev_seq])
        self.assertEqual(rec["to"]["hit_grant"],
                         {"grant_id": "g1", "grant_seq": g1})
        self.assertEqual(rec["flip_reasons"][0]["kind"], "revoked")
        self.assertEqual(rec["flip_reasons"][0]["revocation_seq"], rev_seq)
        self.assertEqual(rec["flip_reasons"][0]["grant_id"], "g1")
        # 处置项：added，开立于 rev_seq，取消记录（更晚序号）对该侧不可见。
        self.assertEqual(len(d["remediation_items"]), 1)
        item = d["remediation_items"][0]
        self.assertEqual(item["classification"], "added")
        self.assertEqual(item["receipt_key"], t1)
        self.assertEqual(item["revocation_seq"], rev_seq)
        self.assertEqual(item["from"], {"presence": "absent"})
        self.assertEqual(item["to"]["status"], "open")
        self.assertEqual(item["flip_reasons"],
                         [{"kind": "opened", "revocation_seq": rev_seq}])
        self.assertEqual(item["products"], [p1, p2])
        # 删除结论：active_grant(g1) -> open_remediation，阻断身份可定位。
        self.assertEqual(d["deletion"]["classification"], "changed")
        self.assertEqual(d["deletion"]["from"]["status"], "blocked")
        self.assertEqual([b["kind"] for b in d["deletion"]["from"]["blockers"]],
                         ["active_grant"])
        self.assertEqual(d["deletion"]["from"]["blockers"][0]["grant_id"], "g1")
        self.assertEqual([b["kind"] for b in d["deletion"]["to"]["blockers"]],
                         ["open_remediation"])
        kinds = [r["kind"] for r in d["deletion"]["flip_reasons"]]
        self.assertIn("blocker_removed", kinds)
        self.assertIn("blocker_added", kinds)
        # 汇总计数（removed 恒 0：只追加）。
        self.assertEqual(d["summary"]["products"],
                         {"added": 0, "removed": 0, "changed": 2,
                          "unchanged": 0})
        self.assertEqual(d["summary"]["receipts"]["changed"], 1)
        self.assertEqual(d["summary"]["remediation_items"]["added"], 1)
        self.assertEqual(d["summary"]["deletion"], "changed")

        # ---- 恢复许可 + 新产品：diff(rev, g2) 回摆；diff(g1, g2) 见 added。
        g2 = self._grant("g2")["seq"]
        t2, p3 = self.k("t2"), self.k("p3")
        self._task(t2, [{"product_id": p3,
                         "groups": [[{"kind": "receipt", "ref": t2}]]}])

        d2 = self._diff([p1], rev_seq, g2).json()
        rec2 = d2["products"][0]["receipts"][0]
        self.assertEqual(rec2["classification"], "changed")
        self.assertFalse(rec2["from"]["currently_valid"])
        self.assertTrue(rec2["to"]["currently_valid"])
        self.assertEqual(rec2["flip_reasons"],
                         [{"kind": "hit_grant_changed",
                           "from_grant": {"grant_id": "g1", "grant_seq": g1},
                           "to_grant": {"grant_id": "g2", "grant_seq": g2}}])
        self.assertEqual(d2["products"][0]["to"]["status"], "active")
        item2 = d2["remediation_items"][0]
        self.assertEqual(item2["classification"], "changed")
        self.assertEqual(item2["from"]["status"], "open")
        self.assertEqual(item2["to"]["status"], "cancelled")
        self.assertEqual(item2["flip_reasons"],
                         [{"kind": "cancelled", "grant_seq": g2}])
        self.assertEqual([b["kind"] for b in d2["deletion"]["to"]["blockers"]],
                         ["active_grant"])
        self.assertEqual(d2["deletion"]["to"]["blockers"][0]["grant_id"], "g2")

        # p3 在 from 侧尚未登记 -> absent / added；p1 两侧均 active
        # （unchanged），但其回执命中许可 g1 -> g2（changed）。
        d3 = self._diff([p1, p3], g1, g2).json()
        by_pid = {p["product_id"]: p for p in d3["products"]}
        self.assertEqual(by_pid["p1"]["classification"], "unchanged")
        self.assertEqual(by_pid["p1"]["receipts"][0]["classification"],
                         "changed")
        p3e = by_pid["p3"]
        self.assertEqual(p3e["classification"], "added")
        self.assertEqual(p3e["from"], {"presence": "absent"})
        self.assertEqual(p3e["to"]["status"], "active")
        self.assertEqual(p3e["flip_reasons"][0]["kind"], "registered")
        self.assertEqual(p3e["receipts"][0]["classification"], "added")
        self.assertEqual(p3e["receipts"][0]["from"], {"presence": "absent"})
        self.assertEqual(d3["summary"]["products"]["added"], 1)
        self.assertEqual(d3["summary"]["products"]["unchanged"], 1)
        # 删除结论：两侧均 blocked，但命中许可身份 g1 -> g2 变化。
        self.assertEqual(d3["deletion"]["classification"], "changed")
        self.assertEqual(d3["deletion"]["from"]["status"], "blocked")
        self.assertEqual(d3["deletion"]["to"]["status"], "blocked")

        # ---- 后续事件不改变报告：再追加许可 / 撤销后重发同一 diff 完全一致。
        again = self._diff([p2, p1, p1], g1, rev_seq).json()
        self.assertEqual(again, d)
        self._grant("g3")
        self._revoke("g3")
        after = self._diff([p2, p1, p1], g1, rev_seq).json()
        self.assertEqual(after, d)

        # ---- 两侧与独立只读 as_of_seq 回放口径一致。
        prod_from = self.client.get(
            f"/subjects/{self.subject}/products/{p1}?as_of_seq={g1}").json()
        prod_to = self.client.get(
            f"/subjects/{self.subject}/products/{p1}?as_of_seq={rev_seq}"
        ).json()
        self.assertEqual(prod_from["status"], d["products"][0]["from"]["status"])
        self.assertEqual(prod_to["status"], d["products"][0]["to"]["status"])
        self.assertEqual(prod_to["invalidating_events"],
                         d["products"][0]["to"]["invalidating_events"])

    # ------------------------------------------------ 校验拒绝
    def test_diff_validation_rejections(self):
        g1 = self._grant("g1")["seq"]
        t1, p1 = self.k("t1"), self.k("p1")
        self._task(t1, [{"product_id": p1,
                         "groups": [[{"kind": "receipt", "ref": t1}]]}])
        g2 = self._grant("g2")["seq"]
        g3 = self._grant("g3")["seq"]
        t2, p2 = self.k("t2"), self.k("p2")
        self._task(t2, [{"product_id": p2,
                         "groups": [[{"kind": "receipt", "ref": t2}]]}])
        base = {"subject_id": self.subject, "product_ids": [p1],
                "use_at": "2026-05-01T00:00:00Z",
                "from_seq": g1, "to_seq": g2}

        def post(body):
            return self.client.post("/compliance-diffs", json=body)

        # 空产品范围 / 空字符串产品 ID -> 422。
        self.assertEqual(post({**base, "product_ids": []}).status_code, 422)
        self.assertEqual(post({**base, "product_ids": [""]}).status_code, 422)
        # from_seq >= to_seq -> 422；from_seq=0 -> 422。
        self.assertEqual(post({**base, "from_seq": g2,
                               "to_seq": g2}).status_code, 422)
        self.assertEqual(post({**base, "from_seq": g3,
                               "to_seq": g2}).status_code, 422)
        self.assertEqual(post({**base, "from_seq": 0}).status_code, 422)
        # 未来序号（超过当前全局最大事件序号）-> 422。
        self.assertEqual(post({**base, "to_seq": 999_999_999}).status_code,
                         422)
        # 未知产品 -> 422。
        self.assertEqual(post({**base, "product_ids": [self.k("ghost")]}
                              ).status_code, 422)
        # 产品在 to_seq 之后才登记（两侧快照均不存在）-> 422。
        # p2 的 recorded_seq = g3（登记时主体最大事件序号）。
        r = post({**base, "product_ids": [p2], "from_seq": g1, "to_seq": g2})
        self.assertEqual(r.status_code, 422, r.text)
        # to_seq 覆盖其登记序号后允许：from 侧 absent -> added。
        ok = self._diff([p2], g1, g3).json()
        self.assertEqual(ok["products"][0]["classification"], "added")

    # ---------------------------------------- 跨主体事件不误纳入 / 无关事件不变
    def test_diff_cross_subject_events_not_included(self):
        g1 = self._grant("g1")["seq"]
        t1, p1 = self.k("t1"), self.k("p1")
        self._task(t1, [{"product_id": p1,
                         "groups": [[{"kind": "receipt", "ref": t1}]]}])
        # 另一主体在同一全局序号空间内追加许可与撤销（序号穿插）。
        other = "diff-x-" + uuid.uuid4().hex[:8]
        r = self.client.post("/grants", json={
            "subject_id": other, "grant_id": "gx", "category": "email",
            "purpose": "marketing", "recipient": "partner-a",
            "valid_from": "2026-01-01T00:00:00Z"})
        self.assertEqual(r.status_code, 201, r.text)
        r = self.client.post("/revocations", json={
            "subject_id": other, "grant_id": "gx",
            "business_effective_at": "2026-01-15T00:00:00Z"})
        self.assertEqual(r.status_code, 201, r.text)
        other_rev_seq = r.json()["event"]["seq"]
        # 本主体一条与回执四元组无关的许可（同序号空间）。
        unrelated = self._grant("g9", recipient="partner-b",
                                category="location")["seq"]

        # 区间覆盖跨主体事件与无关事件：报告全部 unchanged，且
        # to_basis_seq 只计本主体事件（仍为本主体许可 g1 的序号）。
        d = self._diff([p1], g1, unrelated).json()
        self.assertGreater(unrelated, other_rev_seq)  # 区间确实覆盖它们
        self.assertEqual(d["to_basis_seq"], g1)
        self.assertEqual(d["products"][0]["classification"], "unchanged")
        self.assertEqual(d["products"][0]["receipts"][0]["classification"],
                         "unchanged")
        self.assertEqual(d["remediation_items"], [])
        self.assertEqual(d["deletion"]["classification"], "unchanged")
        self.assertEqual(d["deletion"]["flip_reasons"], [])
        self.assertEqual(d["summary"]["products"]["unchanged"], 1)

    # ------------------------------------------------ 处置提交反映与事件有界
    def test_diff_remediation_submission_reflected_but_events_bounded(self):
        g1 = self._grant("g1")["seq"]
        t1, p1 = self.k("t1"), self.k("p1")
        self._task(t1, [{"product_id": p1,
                         "groups": [[{"kind": "receipt", "ref": t1}]]}])
        rev_seq = self._revoke("g1")["event"]["seq"]
        d1 = self._diff([p1], g1, rev_seq).json()
        item = d1["remediation_items"][0]
        self.assertEqual(item["to"]["status"], "open")
        self.assertEqual(d1["deletion"]["to"]["status"], "blocked")
        iid = item["item_id"]

        # 提交 + 批准（不产生许可 / 撤销事件）：重发 diff 按请求快照反映
        # 最新处置状态（文档化语义），删除结论 to 侧随之放行。
        r = self.client.post(
            f"/remediation/items/{iid}/submissions",
            json={"version": 1, "cease_declaration": "已停止使用",
                  "evidence": [{"product_id": p1, "summary": "已清除"}]},
            headers={**RA_H, "Idempotency-Key": self.k("s1")})
        self.assertEqual(r.status_code, 201, r.text)
        r = self.client.post(f"/remediation/items/{iid}/reviews",
                             json={"version": 1, "action": "approve"},
                             headers=ADMIN_H)
        self.assertEqual(r.status_code, 201, r.text)
        d2 = self._diff([p1], g1, rev_seq).json()
        self.assertEqual(d2["remediation_items"][0]["to"]["status"],
                         "approved")
        self.assertEqual(d2["deletion"]["to"]["status"], "planned")
        # 事件驱动的部分（产品 / 回执重放与分类）不受处置提交影响。
        self.assertEqual(d2["products"], d1["products"])

        # 追加恢复许可（新事件，序号越界于 to_seq）：报告不再变化。
        self._grant("g2")
        d3 = self._diff([p1], g1, rev_seq).json()
        self.assertEqual(d3, d2)

    # ------------------------------------------------ 只读性与可重复性
    def test_diff_is_read_only_and_repeatable(self):
        g1 = self._grant("g1")["seq"]
        t1, p1 = self.k("t1"), self.k("p1")
        self._task(t1, [{"product_id": p1,
                         "groups": [[{"kind": "receipt", "ref": t1}]]}])
        rev_seq = self._revoke("g1")["event"]["seq"]

        def table_counts():
            assert db.pool is not None
            with db.pool.connection() as conn:
                row = conn.execute(
                    """SELECT
                         (SELECT count(*) FROM events) AS events,
                         (SELECT count(*) FROM receipts) AS receipts,
                         (SELECT count(*) FROM products) AS products,
                         (SELECT count(*) FROM remediation_items) AS items,
                         (SELECT count(*) FROM deletion_requests) AS deletions,
                         (SELECT count(*) FROM attestations) AS attestations"""
                ).fetchone()
            return dict(row)

        before = table_counts()
        d1 = self._diff([p1], g1, rev_seq).json()
        d2 = self._diff([p1], g1, rev_seq).json()
        self.assertEqual(d1, d2)  # 可重复：同一 (from, to) 报告逐字节一致
        self.assertEqual(table_counts(), before)  # 不写入任何业务表
        events = self.client.get(
            f"/subjects/{self.subject}/events").json()["events"]
        self.assertEqual(len(events), 2)  # 只有许可与撤销两条事件

    # ------------------------------------------------ 并发追加下的一致性
    def test_diff_concurrent_appends_report_stable(self):
        """并发追加事件（含跨主体）时，同一 (from_seq, to_seq) 的报告不变。

        差异报告在单个 REPEATABLE READ 只读快照中按固定序号上界重放：
        并发提交的许可 / 撤销（序号均大于 to_seq）对报告不可见；跨主体
        事件也不会误纳入。全部并发读者的响应必须与基线逐字节一致。
        """
        g1 = self._grant("g1")["seq"]
        t1, p1 = self.k("t1"), self.k("p1")
        self._task(t1, [{"product_id": p1,
                         "groups": [[{"kind": "receipt", "ref": t1}]]}])
        rev_seq = self._revoke("g1")["event"]["seq"]
        baseline = self._diff([p1], g1, rev_seq).json()

        n_readers = 6
        barrier = threading.Barrier(n_readers + 2)
        diff_responses: list = []
        append_responses: list = []

        def reader(_):
            barrier.wait()
            diff_responses.append(self.client.post("/compliance-diffs", json={
                "subject_id": self.subject, "product_ids": [p1],
                "use_at": "2026-05-01T00:00:00Z",
                "from_seq": g1, "to_seq": rev_seq}))

        def appender():
            # 同主体并发追加：恢复许可 + 再撤销（序号均 > to_seq）。
            barrier.wait()
            append_responses.append(self.client.post("/grants", json={
                "subject_id": self.subject, "grant_id": "g2",
                "category": "email", "purpose": "marketing",
                "recipient": "partner-a",
                "valid_from": "2026-01-01T00:00:00Z"}))
            append_responses.append(self.client.post("/revocations", json={
                "subject_id": self.subject, "grant_id": "g2",
                "business_effective_at": "2026-01-15T00:00:00Z"}))

        def cross_subject():
            # 跨主体并发追加：同一全局序号空间，不得误纳入本主体报告。
            barrier.wait()
            other = "diff-cx-" + uuid.uuid4().hex[:8]
            append_responses.append(self.client.post("/grants", json={
                "subject_id": other, "grant_id": "gx", "category": "email",
                "purpose": "marketing", "recipient": "partner-a",
                "valid_from": "2026-01-01T00:00:00Z"}))

        threads = ([threading.Thread(target=reader, args=(i,))
                    for i in range(n_readers)]
                   + [threading.Thread(target=appender),
                      threading.Thread(target=cross_subject)])
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertTrue(all(r.status_code == 201 for r in append_responses),
                        [r.status_code for r in append_responses])
        self.assertEqual(len(diff_responses), n_readers)
        for r in diff_responses:
            self.assertEqual(r.status_code, 200, r.text)
            self.assertEqual(r.json(), baseline)  # 后续事件不改变报告

        # 并发追加落库后：同一 diff 仍与基线一致；两侧与独立只读回放一致。
        self.assertEqual(self._diff([p1], g1, rev_seq).json(), baseline)
        prod_to = self.client.get(
            f"/subjects/{self.subject}/products/{p1}?as_of_seq={rev_seq}"
        ).json()
        self.assertEqual(prod_to["status"],
                         baseline["products"][0]["to"]["status"])
        events = self.client.get(
            f"/subjects/{self.subject}/events").json()["events"]
        self.assertEqual(len(events), 4)  # g1/rev + 并发追加的 g2/rev


if __name__ == "__main__":
    unittest.main()