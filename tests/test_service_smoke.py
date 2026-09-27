"""服务层端到端冒烟测试：以内存仓储替身 + 虚拟连接运行完整业务场景。

不依赖 psycopg / pydantic，仅标准库。目的：在没有 PostgreSQL 的环境中
也能验证 service.py 的编排（事件追加、确定性重放、幂等、血缘引用、
无环校验、追溯撤销传播、撤销处置台账开立 / 取消、证据提交与复核、
历史回放）。

同主体写串行化由路由层通过 ``app.db.transaction(lock_subject=...)`` 在
事务开始前获取会话级咨询锁实现（见 app/db.py），不在服务层内发 SQL；
其正确性由 tests/test_api.py 的 PostgreSQL 并发回归覆盖。此处的虚拟
连接用于断言服务层不再绕过仓储直接执行任何 SQL。
"""
import json
import unittest
from datetime import datetime, timezone
from types import ModuleType, SimpleNamespace
import sys

# 离线环境下注入最小 psycopg 桩（生产容器安装真实 psycopg）。
try:  # pragma: no cover
    import psycopg  # noqa: F401
except ImportError:
    _stub = ModuleType("psycopg")

    class _UniqueViolation(Exception):
        pass

    class _OperationalError(Exception):
        pass

    _errors = ModuleType("psycopg.errors")
    _errors.UniqueViolation = _UniqueViolation
    _errors.OperationalError = _OperationalError
    _stub.errors = _errors

    class _IsolationLevel:
        REPEATABLE_READ = "REPEATABLE_READ"
        SERIALIZABLE = "SERIALIZABLE"

    _stub.IsolationLevel = _IsolationLevel
    sys.modules["psycopg"] = _stub
    sys.modules["psycopg.errors"] = _errors

from app import service as svc_mod
from app.repository import Repo
from app.domain import Event


def dt(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


# ------------------------------------------------------------- 内存连接/仓储
class FakeConn:
    """服务层不应直接执行任何 SQL（持久化全部经过仓储接口）。"""

    def __init__(self, bag):
        self.bag = bag

    def execute(self, sql, params=None):
        raise AssertionError(f"未预期 SQL: {sql}")


class InMemoryRepo:
    """与 Repo 方法签名一致的内存实现；只追加。"""
    def __init__(self, bag, conn):
        self.bag = bag
        self.conn = conn

    def insert_grant(self, *, subject_id, grant_id, category, purpose,
                     recipient, valid_from, valid_to, recorded_at):
        for e in self.bag["events"]:
            if (e["subject_id"], e["grant_id"], e["event_type"]) == \
               (subject_id, grant_id, "grant"):
                from app.errors import conflict
                raise conflict("dup grant")
        return self._event_row(dict(
            subject_id=subject_id, event_type="grant", grant_id=grant_id,
            category=category, purpose=purpose, recipient=recipient,
            valid_from=valid_from, valid_to=valid_to, revoke_grant=None,
            business_effective_at=None, recorded_at=recorded_at))

    def find_grant(self, subject_id, grant_id):
        for e in self.bag["events"]:
            if (e["subject_id"], e["grant_id"], e["event_type"]) == \
               (subject_id, grant_id, "grant"):
                return e
        return None

    def insert_revocation(self, *, subject_id, grant_id,
                          business_effective_at, recorded_at):
        return self._event_row(dict(
            subject_id=subject_id, event_type="revocation",
            grant_id=f"rev-n", category=None, purpose=None, recipient=None,
            valid_from=None, valid_to=None, revoke_grant=grant_id,
            business_effective_at=business_effective_at,
            recorded_at=recorded_at))

    def list_events(self, subject_id, as_of_seq=None):
        rows = [e for e in self.bag["events"] if e["subject_id"] == subject_id]
        if as_of_seq is not None:
            rows = [e for e in rows if e["seq"] <= as_of_seq]
        return sorted(rows, key=lambda e: e["seq"])

    def max_event_seq(self):
        return max([e["seq"] for e in self.bag["events"]] + [0])

    def get_receipt(self, key):
        return self.bag["receipts"].get(key)

    def get_receipts_for_subject(self, subject_id):
        return [r for r in self.bag["receipts"].values()
                if r["subject_id"] == subject_id]

    def insert_receipt(self, **kw):
        kw["recorded_seq"] = max(
            [e["seq"] for e in self.bag["events"]] + [0])
        row = dict(kw)
        row["idempotency_key"] = kw["key"]
        # 镜像真实列名（SQL 插入参数为 fingerprint，列为 request_fingerprint）
        row["request_fingerprint"] = kw["fingerprint"]
        self.bag["receipts"][kw["key"]] = row
        return row

    def insert_product(self, *, subject_id, product_id, task_key, description,
                       recorded_seq, recorded_at):
        key = (subject_id, product_id)
        if key in self.bag["products"]:
            from app.errors import conflict
            raise conflict("dup product")
        row = dict(subject_id=subject_id, product_id=product_id,
                   task_key=task_key, description=description,
                   recorded_seq=recorded_seq, recorded_at=recorded_at)
        self.bag["products"][key] = row
        return row

    def insert_group(self, subject_id, product_id, ord_):
        gid = self.bag["gid_seq"] = self.bag["gid_seq"] + 1
        self.bag["groups"].append(dict(group_id=gid, subject_id=subject_id,
                                       product_id=product_id, ord=ord_))
        return gid

    def insert_input(self, group_id, ord_, kind, ref):
        self.bag["inputs"].append(dict(group_id=group_id, ord=ord_,
                                       input_kind=kind, input_ref=ref))

    def list_products_for_subject(self, subject_id):
        return [p for p in self.bag["products"].values()
                if p["subject_id"] == subject_id]

    def list_groups(self, subject_id):
        return [g for g in self.bag["groups"]
                if g["subject_id"] == subject_id]

    def list_inputs_for_groups(self, group_ids):
        wanted = set(group_ids)
        return [i for i in self.bag["inputs"] if i["group_id"] in wanted]

    def list_products_by_task(self, task_key):
        return [p for p in self.bag["products"].values()
                if p["task_key"] == task_key]

    # ----------------------------------------------------- 处置台账（内存）
    def insert_remediation_item(self, *, subject_id, receipt_key, recipient,
                                revocation_seq, opened_at):
        iid = self.bag["item_seq"] = self.bag["item_seq"] + 1
        self.bag["rem_items"][iid] = dict(
            item_id=iid, subject_id=subject_id, receipt_key=receipt_key,
            recipient=recipient, revocation_seq=revocation_seq,
            opened_at=opened_at)
        return iid

    def insert_remediation_item_product(self, item_id, product_id):
        self.bag["rem_item_products"].append(
            dict(item_id=item_id, product_id=product_id))

    def insert_remediation_cancellation(self, *, item_id, grant_seq,
                                        cancelled_at):
        self.bag["rem_cancels"][item_id] = dict(
            item_id=item_id, grant_seq=grant_seq, cancelled_at=cancelled_at)

    def get_remediation_item(self, item_id):
        return self.bag["rem_items"].get(item_id)

    def list_remediation_items(self, subject_id):
        return [i for i in self.bag["rem_items"].values()
                if i["subject_id"] == subject_id]

    def list_remediation_item_products(self, item_ids):
        wanted = set(item_ids)
        return [p for p in self.bag["rem_item_products"]
                if p["item_id"] in wanted]

    def list_remediation_submissions(self, item_ids):
        wanted = set(item_ids)
        return [s for s in self.bag["rem_subs"] if s["item_id"] in wanted]

    def list_remediation_reviews(self, item_ids):
        wanted = set(item_ids)
        return [r for r in self.bag["rem_reviews"] if r["item_id"] in wanted]

    def list_remediation_cancellations(self, item_ids):
        wanted = set(item_ids)
        return [c for c in self.bag["rem_cancels"].values()
                if c["item_id"] in wanted]

    def get_submission_by_key(self, key):
        for s in self.bag["rem_subs"]:
            if s["idempotency_key"] == key:
                return s
        return None

    def insert_remediation_submission(self, *, item_id, version,
                                      idempotency_key, cease_declaration,
                                      evidence_json, fingerprint, submitted_by,
                                      submitted_at):
        row = dict(
            submission_id=len(self.bag["rem_subs"]) + 1,
            item_id=item_id, version=version,
            idempotency_key=idempotency_key,
            cease_declaration=cease_declaration,
            evidence=json.loads(evidence_json),
            request_fingerprint=fingerprint, submitted_by=submitted_by,
            submitted_at=submitted_at)
        self.bag["rem_subs"].append(row)
        return row

    def insert_remediation_review(self, *, item_id, version, action, comment,
                                  reviewed_at):
        row = dict(review_id=len(self.bag["rem_reviews"]) + 1,
                   item_id=item_id, version=version, action=action,
                   comment=comment, reviewed_at=reviewed_at)
        self.bag["rem_reviews"].append(row)
        return row

    # ----------------------------------------------------- 删除请求（内存）
    def insert_deletion_request(self, *, key, subject_id, product_ids_json,
                                scope_json, requested_at, status, basis_seq,
                                fingerprint, created_at):
        rid = self.bag["del_seq"] = self.bag["del_seq"] + 1
        row = dict(request_id=rid, idempotency_key=key, subject_id=subject_id,
                   product_ids=json.loads(product_ids_json),
                   scope=json.loads(scope_json), requested_at=requested_at,
                   status=status, basis_seq=basis_seq,
                   request_fingerprint=fingerprint, created_at=created_at)
        self.bag["del_requests"][rid] = row
        self.bag["del_by_key"][key] = rid
        return row

    def get_deletion_request(self, request_id):
        return self.bag["del_requests"].get(request_id)

    def get_deletion_request_by_key(self, key):
        rid = self.bag["del_by_key"].get(key)
        return self.bag["del_requests"].get(rid) if rid is not None else None

    def insert_deletion_batch(self, *, request_id, batch_no, product_id):
        self.bag["del_batches"].append(dict(
            request_id=request_id, batch_no=batch_no, product_id=product_id))

    def list_deletion_batches(self, request_id):
        rows = [b for b in self.bag["del_batches"]
                if b["request_id"] == request_id]
        return sorted(rows, key=lambda b: (b["batch_no"], b["product_id"]))

    def insert_deletion_blocker(self, *, request_id, ord_, kind, detail_json):
        self.bag["del_blockers"].append(dict(
            request_id=request_id, ord=ord_, kind=kind,
            detail=json.loads(detail_json)))

    def list_deletion_blockers(self, request_id):
        rows = [b for b in self.bag["del_blockers"]
                if b["request_id"] == request_id]
        return sorted(rows, key=lambda b: b["ord"])

    def _event_row(self, d):
        d["seq"] = self.bag["seq"] = self.bag["seq"] + 1
        self.bag["events"].append(d)
        return d


def make_service():
    bag = {"events": [], "receipts": {}, "products": {}, "groups": [],
           "inputs": [], "seq": 0, "gid_seq": 0,
           "rem_items": {}, "rem_item_products": [], "rem_subs": [],
           "rem_reviews": [], "rem_cancels": {}, "item_seq": 0,
           "del_requests": {}, "del_by_key": {}, "del_batches": [],
           "del_blockers": [], "del_seq": 0}
    conn = FakeConn(bag)
    svc = svc_mod.Service(conn)
    svc.repo = InMemoryRepo(bag, conn)  # 替换为内存仓储
    return svc, bag


# ------------------------------------------------------------- 轻量请求模型
def grant_req(subject, gid, vf=None, vt=None):
    return SimpleNamespace(subject_id=subject, grant_id=gid,
                           category="email", purpose="marketing",
                           recipient="partner-a",
                           valid_from=vf, valid_to=vt)


def revoke_req(subject, gid, bea):
    return SimpleNamespace(subject_id=subject, grant_id=gid,
                           business_effective_at=bea)


def eval_req(subject, use_at, as_of=None, recipient="partner-a"):
    return SimpleNamespace(subject_id=subject, category="email",
                           purpose="marketing", recipient=recipient,
                           use_at=use_at, as_of=as_of)


def inp(kind, ref):
    return SimpleNamespace(kind=kind, ref=ref)


def product(pid, groups, description=None):
    g = [[inp(k, r) for k, r in grp] for grp in groups]

    def normalized_groups():
        return [[f"receipt:{i.ref}" if i.kind == "receipt" else i.ref
                 for i in grp] for grp in g]

    return SimpleNamespace(product_id=pid, description=description,
                           groups=g, normalized_groups=normalized_groups)


def task_req(subject, products, use_at=dt("2026-05-01T00:00:00Z"),
             recipient="partner-a"):
    return SimpleNamespace(subject_id=subject, category="email",
                           purpose="marketing", recipient=recipient,
                           use_at=use_at, products=products)


def evidence(*pairs):
    return [SimpleNamespace(product_id=pid, summary=summary)
            for pid, summary in pairs]


def submission_req(version, declaration, pairs):
    return SimpleNamespace(version=version, cease_declaration=declaration,
                           evidence=evidence(*pairs))


def review_req(version, action, comment=None):
    return SimpleNamespace(version=version, action=action, comment=comment)


def deletion_req(subject, product_ids, requested_at=None):
    return SimpleNamespace(
        subject_id=subject, product_ids=product_ids,
        requested_at=requested_at or dt("2026-09-26T08:00:00Z"))


def diff_req(subject, product_ids, from_seq, to_seq,
             use_at=dt("2026-05-01T00:00:00Z")):
    return SimpleNamespace(subject_id=subject, product_ids=product_ids,
                           use_at=use_at, from_seq=from_seq, to_seq=to_seq)


class ServiceSmokeTests(unittest.TestCase):
    def test_full_lifecycle(self):
        svc, bag = make_service()
        s = "user-x"

        # 1. 默认拒绝
        self.assertEqual(
            svc.evaluate(eval_req(s, dt("2026-05-01T00:00:00Z")))["decision"],
            "deny")

        # 2. 追加两个重叠许可
        g1 = svc.append_grant(grant_req(s, "g1"))
        g2 = svc.append_grant(grant_req(s, "g2"))

        # 3. 登记 task-1 / p1
        r1 = svc.register_task("t1", task_req(s, [
            product("p1", [ [("receipt", "t1")] ])]))
        self.assertEqual(r1["receipt"]["decision"], "allow")
        self.assertEqual(r1["receipt"]["basis_grant_id"], "g2")  # 最新许可
        self.assertEqual(r1["products"][0]["status"], "active")

        # 4. 登记 task-2 / p2，两组替代依据 t1、t2
        r2 = svc.register_task("t2", task_req(s, [
            product("p2", [ [("receipt", "t1")], [("receipt", "t2")] ])]))
        self.assertEqual(r2["products"][0]["status"], "active")

        # 5. 幂等：同 key 同负载 -> replay
        r1b = svc.register_task("t1", task_req(s, [
            product("p1", [ [("receipt", "t1")] ])]))
        self.assertTrue(r1b["idempotent_replay"])
        # 幂等冲突
        from app.errors import ApiError
        with self.assertRaises(ApiError) as cm:
            svc.register_task("t1", task_req(
                s, [], recipient="partner-other"))
        self.assertEqual(cm.exception.status_code, 409)

        # 6. 撤销旧许可 g1：命中的是 g2，产物存活
        svc.append_revocation(revoke_req(s, "g1", dt("2026-01-15T00:00:00Z")))
        st = svc.get_product(s, "p2")
        self.assertEqual(st["status"], "active")

        # 7. 追溯撤销 g2 -> 两个回执失效，p1/p2 阻断
        rev = svc.append_revocation(
            revoke_req(s, "g2", dt("2026-01-15T00:00:00Z")))
        rev_seq = rev["event"]["seq"]
        self.assertIn("t1", rev["affected_receipts"])
        self.assertIn("t2", rev["affected_receipts"])
        pids_blocked = {p["product_id"] for p in rev["blocked_products"]}
        self.assertEqual(pids_blocked, {"p1", "p2"})

        p2 = svc.get_product(s, "p2")
        self.assertEqual(p2["status"], "blocked")
        self.assertEqual(p2["invalidating_events"], [rev_seq])

        # 8. 历史回放：as_of_seq 回到 g2 撤销前 -> 旧记录仍 active
        old = svc.get_product(s, "p2", as_of_seq=rev_seq - 1)
        self.assertEqual(old["status"], "active")
        # 旧事件记录本身未被改写：回执 decision 仍为 allow
        receipt = svc.get_receipt("t1")
        self.assertEqual(receipt["decision"], "allow")
        self.assertFalse(receipt["currently_valid"])
        self.assertEqual(receipt["invalidating_events"], [rev_seq])

        # 9. 事件只追加：4 个事件且序号单调
        seqs = [e["seq"] for e in bag["events"]]
        self.assertEqual(seqs, sorted(seqs))
        self.assertEqual(len(bag["events"]), 4)

    def test_future_effective_revocation_does_not_invalidate_past_use(self):
        svc, _ = make_service()
        s = "user-y"
        svc.append_grant(grant_req(s, "g1"))
        r = svc.register_task("t", task_req(s, [
            product("p", [ [("receipt", "t")] ])]))
        self.assertEqual(r["products"][0]["status"], "active")
        svc.append_revocation(revoke_req(s, "g1", dt("2026-12-31T00:00:00Z")))
        st = svc.get_product(s, "p")
        self.assertEqual(st["status"], "active")  # 5 月使用早于撤销生效

    def test_unknown_refs_and_cycles_rejected(self):
        from app.errors import ApiError
        svc, _ = make_service()
        s = "user-z"
        svc.append_grant(grant_req(s, "g1"))

        # 未知回执引用
        with self.assertRaises(ApiError) as cm:
            svc.register_task("t", task_req(s, [
                product("p", [ [("receipt", "ghost")] ])]))
        self.assertEqual(cm.exception.status_code, 422)

        # 未知产物引用
        with self.assertRaises(ApiError):
            svc.register_task("t", task_req(s, [
                product("p", [ [("product", "ghost")] ])]))

        # 自环
        with self.assertRaises(ApiError):
            svc.register_task("t", task_req(s, [
                product("p", [ [("product", "p")] ])]))

        # 同批合法 DAG：p2 -> p1 -> t
        r = svc.register_task("t", task_req(s, [
            product("p1", [ [("receipt", "t")] ]),
            product("p2", [ [("product", "p1")] ])]))
        statuses = {p["product_id"]: p["status"] for p in r["products"]}
        self.assertEqual(statuses, {"p1": "active", "p2": "active"})

        # 缺幂等键
        with self.assertRaises(ApiError) as cm:
            svc.register_task("", task_req(s, []))
        self.assertEqual(cm.exception.status_code, 422)

    def test_deny_receipt_blocks_downstream_but_no_invalidating_events(self):
        svc, _ = make_service()
        s = "user-q"
        # 无许可：登记即拒绝；回执仍持久化
        r = svc.register_task("t", task_req(s, [
            product("p", [ [("receipt", "t")] ])]))
        self.assertEqual(r["receipt"]["decision"], "deny")
        self.assertEqual(r["products"][0]["status"], "blocked")
        self.assertEqual(r["products"][0]["invalidating_events"], [])

    def test_revoke_missing_grant_404(self):
        from app.errors import ApiError
        svc, _ = make_service()
        with self.assertRaises(ApiError) as cm:
            svc.append_revocation(revoke_req(
                "user-m", "nope", dt("2026-01-01T00:00:00Z")))
        self.assertEqual(cm.exception.status_code, 404)

    # ------------------------------------------------------- 处置台账生命周期
    def test_remediation_ledger_full_lifecycle(self):
        from app.errors import ApiError
        svc, _ = make_service()
        s = "user-r"
        svc.append_grant(grant_req(s, "g1"))
        svc.register_task("t1", task_req(s, [
            product("p1", [[("receipt", "t1")]])]))

        # 追溯撤销：开立处置项，归属回执接收方，关联沿血缘新阻断的产物。
        rev = svc.append_revocation(
            revoke_req(s, "g1", dt("2026-01-15T00:00:00Z")))
        opened = rev["remediation_items"]
        self.assertEqual(len(opened), 1)
        item_id = opened[0]["item_id"]
        self.assertEqual(opened[0]["receipt_key"], "t1")
        self.assertEqual(opened[0]["recipient"], "partner-a")
        self.assertEqual(opened[0]["products"], ["p1"])

        case = svc.get_remediation_case(s, "partner-a")
        self.assertEqual(case["status"], "pending")
        self.assertEqual(case["open_item_ids"], [item_id])
        self.assertEqual(case["items"][0]["status"], "open")

        # 首次提交：版本 1；证据必须逐项覆盖关联产物。
        r = svc.submit_remediation(
            item_id, "partner-a", "k1",
            submission_req(1, "已停止使用", [("p1", "已删除报表")]))
        self.assertFalse(r["idempotent_replay"])
        self.assertEqual(r["item_status"], "submitted")

        # 同键重放返回原结果；过期版本拒绝。
        r2 = svc.submit_remediation(
            item_id, "partner-a", "k1",
            submission_req(1, "已停止使用", [("p1", "已删除报表")]))
        self.assertTrue(r2["idempotent_replay"])
        with self.assertRaises(ApiError) as cm:
            svc.submit_remediation(
                item_id, "partner-a", "k2",
                submission_req(2, "x", [("p1", "y")]))
        self.assertEqual(cm.exception.status_code, 409)
        # 待复核期间补证也拒绝。
        with self.assertRaises(ApiError):
            svc.submit_remediation(
                item_id, "partner-a", "k3",
                submission_req(1, "x", [("p1", "y")]))
        # 证据漏产物 -> 422；他人令牌 -> 403。
        with self.assertRaises(ApiError) as cm:
            svc.submit_remediation(
                item_id, "partner-a", "k4",
                submission_req(1, "x", []))
        self.assertEqual(cm.exception.status_code, 422)
        with self.assertRaises(ApiError) as cm:
            svc.submit_remediation(
                item_id, "partner-b", "k5",
                submission_req(1, "x", [("p1", "y")]))
        self.assertEqual(cm.exception.status_code, 403)

        # 驳回版本 1 后可补证版本 2，再批准 -> 结案。
        rej = svc.review_remediation(item_id, review_req(1, "reject", "不足"))
        self.assertEqual(rej["item_status"], "rejected")
        with self.assertRaises(ApiError):  # 驳回版本不得再复核
            svc.review_remediation(item_id, review_req(1, "approve"))
        svc.submit_remediation(
            item_id, "partner-a", "k6",
            submission_req(2, "已停止使用并通知下游",
                           [("p1", "清除记录+审计日志")]))
        appr = svc.review_remediation(item_id, review_req(2, "approve", "ok"))
        self.assertEqual(appr["item_status"], "approved")
        case = svc.get_remediation_case(s, "partner-a")
        self.assertEqual(case["status"], "closed")
        self.assertEqual(case["open_item_ids"], [])
        # 证据与复核决定均追加保留（两个版本、两条决定）。
        view = case["items"][0]
        self.assertEqual([x["version"] for x in view["submissions"]], [1, 2])
        self.assertEqual([x["action"] for x in view["reviews"]],
                         ["rejected", "approved"])

        # 新许可恢复回执有效：已获批的处置项不取消。
        svc.append_grant(grant_req(s, "g2"))
        receipt = svc.get_receipt("t1")
        self.assertTrue(receipt["currently_valid"])
        case = svc.get_remediation_case(s, "partner-a")
        self.assertEqual(case["items"][0]["status"], "approved")
        self.assertEqual(case["status"], "closed")

        # 再次失效：另开新处置项（不复用、不重复），结案状态重新 pending。
        rev2 = svc.append_revocation(
            revoke_req(s, "g2", dt("2026-01-20T00:00:00Z")))
        new_items = rev2["remediation_items"]
        self.assertEqual(len(new_items), 1)
        self.assertNotEqual(new_items[0]["item_id"], item_id)
        self.assertEqual(new_items[0]["products"], ["p1"])
        case = svc.get_remediation_case(s, "partner-a")
        self.assertEqual(case["status"], "pending")
        self.assertEqual(len(case["items"]), 2)

    def test_remediation_rerevoke_without_restore_no_duplicate_then_cancel(self):
        from app.errors import ApiError
        svc, _ = make_service()
        s = "user-r2"
        svc.append_grant(grant_req(s, "g1"))
        svc.register_task("t", task_req(s, [
            product("p", [[("receipt", "t")]])]))
        rev1 = svc.append_revocation(
            revoke_req(s, "g1", dt("2026-01-15T00:00:00Z")))
        self.assertEqual(len(rev1["remediation_items"]), 1)
        iid = rev1["remediation_items"][0]["item_id"]

        # 再次撤销同一许可：回执未恢复有效，不重复开立。
        rev2 = svc.append_revocation(
            revoke_req(s, "g1", dt("2026-02-15T00:00:00Z")))
        self.assertEqual(rev2["remediation_items"], [])

        # 后续许可恢复有效：未结处置项被取消；再次失效另开新项。
        g2 = svc.append_grant(grant_req(s, "g2"))
        self.assertEqual(
            [c["item_id"] for c in g2["cancelled_remediation_items"]], [iid])
        case = svc.get_remediation_case(s, "partner-a")
        self.assertEqual(case["status"], "closed")
        self.assertEqual(case["items"][0]["status"], "cancelled")

        rev3 = svc.append_revocation(
            revoke_req(s, "g2", dt("2026-01-20T00:00:00Z")))
        self.assertEqual(len(rev3["remediation_items"]), 1)
        self.assertNotEqual(rev3["remediation_items"][0]["item_id"], iid)
        case = svc.get_remediation_case(s, "partner-a")
        self.assertEqual(case["status"], "pending")

        # 已取消的处置项不能再提交 / 复核。
        with self.assertRaises(ApiError) as cm:
            svc.submit_remediation(
                iid, "partner-a", "k",
                submission_req(1, "x", [("p", "y")]))
        self.assertEqual(cm.exception.status_code, 409)
        with self.assertRaises(ApiError) as cm:
            svc.review_remediation(iid, review_req(1, "approve"))
        self.assertEqual(cm.exception.status_code, 409)

    # ------------------------------------------------------- 删除请求生命周期
    def test_deletion_request_lifecycle(self):
        from app.errors import ApiError
        svc, _ = make_service()
        s = "user-del"
        svc.append_grant(grant_req(s, "g1"))
        # 链状产物：p1 <- p2（p2 依赖 p1），叶子回执 t1。
        svc.register_task("t1", task_req(s, [
            product("p1", [[("receipt", "t1")]]),
            product("p2", [[("product", "p1")]])]))

        # 1) 活动许可仍在 -> blocked，原因可定位到许可 / 回执 / 受影响产物。
        r = svc.create_deletion_request("d1", deletion_req(s, []))
        self.assertFalse(r["idempotent_replay"])
        self.assertEqual(r["status"], "blocked")
        self.assertEqual(r["batches"], [])
        self.assertEqual(r["scope"], ["p1", "p2"])
        self.assertEqual(len(r["blockers"]), 1)
        b0 = r["blockers"][0]
        self.assertEqual(b0["kind"], "active_grant")
        self.assertEqual(b0["grant_id"], "g1")
        self.assertEqual(b0["receipt_key"], "t1")
        self.assertEqual(b0["products"], ["p1", "p2"])

        # 同键同内容重放原计划；同键异内容 409。
        r2 = svc.create_deletion_request("d1", deletion_req(s, []))
        self.assertTrue(r2["idempotent_replay"])
        self.assertEqual(r2["request_id"], r["request_id"])
        self.assertEqual(r2["blockers"], r["blockers"])
        with self.assertRaises(ApiError) as cm:
            svc.create_deletion_request("d1", deletion_req(s, ["p1"]))
        self.assertEqual(cm.exception.status_code, 409)

        # 2) 追溯撤销 -> 许可失效，但出现未结处置。
        rev = svc.append_revocation(
            revoke_req(s, "g1", dt("2026-01-15T00:00:00Z")))
        rev_seq = rev["event"]["seq"]
        r3 = svc.create_deletion_request("d2", deletion_req(s, []))
        self.assertEqual(r3["status"], "blocked")
        self.assertEqual({b["kind"] for b in r3["blockers"]},
                         {"open_remediation"})
        self.assertEqual(r3["blockers"][0]["receipt_key"], "t1")
        self.assertEqual(r3["blockers"][0]["status"], "open")

        # 3) 处置结案后 -> planned：下游先删，同层稳定排序，记录 basis_seq。
        case = svc.get_remediation_case(s, "partner-a")
        iid = case["open_item_ids"][0]
        svc.submit_remediation(
            iid, "partner-a", "sk1",
            submission_req(1, "已停止使用", [("p1", "清"), ("p2", "清")]))
        svc.review_remediation(iid, review_req(1, "approve"))
        r4 = svc.create_deletion_request("d3", deletion_req(s, []))
        self.assertEqual(r4["status"], "planned")
        self.assertEqual(r4["blockers"], [])
        self.assertEqual(r4["batches"],
                         [{"batch_no": 1, "product_ids": ["p2"]},
                          {"batch_no": 2, "product_ids": ["p1"]}])
        self.assertEqual(r4["basis_seq"], rev_seq)
        self.assertFalse(r4["stale"])

        # 4) 查询：无新事件 -> 未过期；新许可 -> 过期且历史计划不改写。
        got = svc.get_deletion_request(r4["request_id"])
        self.assertNotIn("idempotent_replay", got)
        self.assertFalse(got["stale"])
        svc.append_grant(grant_req(s, "g2"))
        got2 = svc.get_deletion_request(r4["request_id"])
        self.assertTrue(got2["stale"])
        self.assertIsNotNone(got2["detail"])
        self.assertEqual(got2["batches"], r4["batches"])  # 原计划保留
        self.assertGreater(got2["current_seq"], got2["basis_seq"])

        # 5) 历史回执与回放不被改写；产物仍在（未真实执行删除）。
        receipt = svc.get_receipt("t1")
        self.assertEqual(receipt["decision"], "allow")
        old = svc.get_product(s, "p1", as_of_seq=rev_seq - 1)
        self.assertEqual(old["status"], "active")

        # 6) 未知请求 -> 404；未知产物 -> 422；缺幂等键 -> 422。
        with self.assertRaises(ApiError) as cm:
            svc.get_deletion_request(99999)
        self.assertEqual(cm.exception.status_code, 404)
        with self.assertRaises(ApiError) as cm:
            svc.create_deletion_request("d9", deletion_req(s, ["ghost"]))
        self.assertEqual(cm.exception.status_code, 422)
        with self.assertRaises(ApiError) as cm:
            svc.create_deletion_request("", deletion_req(s, []))
        self.assertEqual(cm.exception.status_code, 422)

    def test_deletion_blocked_by_remediation_goes_stale_after_closure(self):
        """回归：open_remediation 阻断的删除请求，处置结案后查询必须过期。

        处置提交 / 获批不产生许可 / 撤销事件（basis_seq 不变），旧实现仅
        比较事件序号，故结案后 GET 仍返回 stale=false 与历史 blocked。
        """
        from app.errors import ApiError
        svc, _ = make_service()
        s = "user-del-rem"
        svc.append_grant(grant_req(s, "g1"))
        svc.register_task("t1", task_req(s, [
            product("p1", [[("receipt", "t1")]]),
            product("p2", [[("product", "p1")]])]))
        # 追溯撤销：回执失效并开立未结处置项。
        svc.append_revocation(
            revoke_req(s, "g1", dt("2026-01-15T00:00:00Z")))

        # 1) 删除请求被 open_remediation 阻断，登记回执（basis_seq 固定）。
        r = svc.create_deletion_request("d1", deletion_req(s, []))
        self.assertEqual(r["status"], "blocked")
        self.assertEqual([b["kind"] for b in r["blockers"]],
                         ["open_remediation"])
        iid = r["blockers"][0]["item_id"]
        rid = r["request_id"]
        basis_seq = r["basis_seq"]

        got = svc.get_deletion_request(rid)
        self.assertFalse(got["stale"])
        self.assertEqual(got["status"], "blocked")
        self.assertIsNone(got["detail"])

        # 2) 接收方提交、管理员批准：处置结案，且无新增许可 / 撤销。
        svc.submit_remediation(
            iid, "partner-a", "sk1",
            submission_req(1, "已停止使用", [("p1", "清"), ("p2", "清")]))
        svc.review_remediation(iid, review_req(1, "approve"))

        # 3) GET 复用登记回执 + 下游闭包 + 处置派生重新评估：结论已变化，
        #    stale=true 并要求用新幂等键重新评估；历史记录原样保留。
        got = svc.get_deletion_request(rid)
        self.assertTrue(got["stale"])
        self.assertEqual(got["current_seq"], basis_seq)  # 无新事件！
        self.assertEqual(got["status"], "blocked")       # 历史状态不改写
        self.assertEqual([b["kind"] for b in got["blockers"]],
                         ["open_remediation"])            # 历史阻断原因保留
        self.assertIn("新的幂等键", got["detail"])

        # 4) 同键重放响应不变（原历史计划 / 阻断 / 回执，只追加不重算入库）。
        replay = svc.create_deletion_request("d1", deletion_req(s, []))
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(replay["request_id"], rid)
        self.assertEqual(replay["status"], "blocked")
        self.assertEqual(replay["blockers"], r["blockers"])
        self.assertEqual(replay["batches"], [])

        # 5) 新幂等键重新评估：处置已结案 -> planned，下游先删批次。
        r2 = svc.create_deletion_request("d2", deletion_req(s, []))
        self.assertEqual(r2["status"], "planned")
        self.assertFalse(r2["stale"])
        self.assertEqual(r2["blockers"], [])
        self.assertEqual(r2["batches"],
                         [{"batch_no": 1, "product_ids": ["p2"]},
                          {"batch_no": 2, "product_ids": ["p1"]}])

        # 6) 旧请求仍是历史 blocked + stale；新请求未过期（追加式共存）。
        got_old = svc.get_deletion_request(rid)
        self.assertTrue(got_old["stale"])
        self.assertEqual(got_old["status"], "blocked")
        got_new = svc.get_deletion_request(r2["request_id"])
        self.assertFalse(got_new["stale"])
        self.assertEqual(got_new["status"], "planned")

    def test_deletion_remediation_open_state_keeps_not_stale(self):
        """未结处置项仅在 open/submitted/rejected 间流转时结论不变、不过期。"""
        svc, _ = make_service()
        s = "user-del-rem2"
        svc.append_grant(grant_req(s, "g1"))
        svc.register_task("t1", task_req(s, [
            product("p1", [[("receipt", "t1")]])]))
        svc.append_revocation(
            revoke_req(s, "g1", dt("2026-01-15T00:00:00Z")))
        r = svc.create_deletion_request("d1", deletion_req(s, []))
        iid = r["blockers"][0]["item_id"]
        # 提交待复核：同一处置项，阻断身份不变。
        svc.submit_remediation(
            iid, "partner-a", "sk1",
            submission_req(1, "已停止使用", [("p1", "清")]))
        got = svc.get_deletion_request(r["request_id"])
        self.assertFalse(got["stale"])
        self.assertEqual(got["status"], "blocked")
        # 驳回后仍未结：结论依旧不变。
        svc.review_remediation(iid, review_req(1, "reject"))
        got = svc.get_deletion_request(r["request_id"])
        self.assertFalse(got["stale"])

    def test_deletion_blocked_until_grant_restores_receipt(self):
        """许可恢复有效 -> 处置项取消（结案）-> 但回执重新被活动许可阻断。

        此时历史 open_remediation 阻断消失、active_grant 阻断出现：阻断身份
        变化（仍为 blocked），同样 stale=true。
        """
        svc, _ = make_service()
        s = "user-del-restore"
        svc.append_grant(grant_req(s, "g1"))
        svc.register_task("t1", task_req(s, [
            product("p1", [[("receipt", "t1")]])]))
        svc.append_revocation(
            revoke_req(s, "g1", dt("2026-01-15T00:00:00Z")))
        r = svc.create_deletion_request("d1", deletion_req(s, []))
        self.assertEqual([b["kind"] for b in r["blockers"]],
                         ["open_remediation"])
        rid = r["request_id"]
        # 新许可覆盖同一使用：回执恢复有效，未结处置项在同事务被取消，
        # 但删除范围重新被活动许可阻断（身份不同）。
        svc.append_grant(grant_req(s, "g2"))
        got = svc.get_deletion_request(rid)
        self.assertTrue(got["stale"])
        self.assertEqual(got["status"], "blocked")  # 历史状态不改写
        # 新幂等键重评：active_grant（g2）阻断。
        r2 = svc.create_deletion_request("d2", deletion_req(s, []))
        self.assertEqual(r2["status"], "blocked")
        self.assertEqual([b["kind"] for b in r2["blockers"]], ["active_grant"])
        self.assertEqual(r2["blockers"][0]["grant_id"], "g2")

    def test_deletion_not_stale_when_conclusion_unchanged(self):
        """结论不变时即使事件序号变化也不标记过期。"""
        svc, _ = make_service()
        s = "user-del-neutral"
        svc.append_grant(grant_req(s, "g1"))
        svc.register_task("t1", task_req(s, [
            product("p1", [[("receipt", "t1")]])]))
        svc.append_revocation(
            revoke_req(s, "g1", dt("2026-01-15T00:00:00Z")))
        r = svc.create_deletion_request("d1", deletion_req(s, []))
        rid = r["request_id"]
        # 追加一条与既有撤销结论无关的新许可（不覆盖 t1 的用途/接收方）：
        # open_remediation 阻断身份不变，结论仍 blocked -> 不标记过期。
        svc.append_grant(SimpleNamespace(
            subject_id=s, grant_id="g9", category="location",
            purpose="marketing", recipient="partner-b",
            valid_from=dt("2026-01-01T00:00:00Z"), valid_to=None))
        got = svc.get_deletion_request(rid)
        self.assertFalse(got["stale"])
        self.assertGreater(got["current_seq"], got["basis_seq"])
        self.assertEqual([b["kind"] for b in got["blockers"]],
                         ["open_remediation"])

    def test_deletion_request_partial_scope_and_empty_subject(self):
        svc, _ = make_service()
        s = "user-del2"
        svc.append_grant(grant_req(s, "g1"))
        svc.register_task("t1", task_req(s, [
            product("pa", [[("receipt", "t1")]]),
            product("pb", [[("product", "pa")]])]))
        svc.register_task("t2", task_req(s, [
            product("pc", [[("receipt", "t2")]])]))

        # 请求删除 pa：范围含下游 pb，不含独立产物 pc。
        r = svc.create_deletion_request("d1", deletion_req(s, ["pa"]))
        self.assertEqual(r["scope"], ["pa", "pb"])
        self.assertEqual(r["blockers"][0]["products"], ["pa", "pb"])

        # 无产物主体：空范围 -> 空计划。
        r2 = svc.create_deletion_request("d2", deletion_req("user-empty", []))
        self.assertEqual(r2["status"], "planned")
        self.assertEqual(r2["scope"], [])
        self.assertEqual(r2["batches"], [])

    def test_remediation_only_newly_blocked_products_linked(self):
        """仅关联在本次撤销中转为阻断的产物；未阻断产物不关联。"""
        svc, _ = make_service()
        s = "user-r3"
        svc.append_grant(grant_req(s, "g1"))
        svc.append_grant(grant_req(s, "g2"))
        # t1 命中 g2；p1 仅依赖 t1。
        svc.register_task("t1", task_req(s, [
            product("p1", [[("receipt", "t1")]])]))
        # t2 命中 g2；p2 有两组替代依据 [t1] 或 [t2]。
        svc.register_task("t2", task_req(s, [
            product("p2", [[("receipt", "t1")],
                           [("receipt", "t2")]])]))
        # 撤销 g1（未命中）：无处置项、无新阻断。
        r1 = svc.append_revocation(
            revoke_req(s, "g1", dt("2026-01-15T00:00:00Z")))
        self.assertEqual(r1["remediation_items"], [])
        # 撤销 g2：t1/t2 均失效；p1、p2 本次阻断，两项处置项各关联对应血缘产物。
        r2 = svc.append_revocation(
            revoke_req(s, "g2", dt("2026-01-15T00:00:00Z")))
        opened = {o["receipt_key"]: o["products"]
                  for o in r2["remediation_items"]}
        self.assertEqual(opened["t1"], ["p1", "p2"])
        self.assertEqual(opened["t2"], ["p2"])

    # ------------------------------------------------------- 合规差异报告
    def _build_diff_scenario(self, s):
        """许可 -> 任务/产物 -> 追溯撤销 -> 新许可恢复 -> 新任务/产物。

        事件序号：g1=1，撤销=2，g2=3；p1/p2 recorded_seq=1，p3 recorded_seq=3。
        """
        svc, _ = make_service()
        svc.append_grant(grant_req(s, "g1"))
        svc.register_task("t1", task_req(s, [
            product("p1", [[("receipt", "t1")]]),
            product("p2", [[("product", "p1")]])]))
        rev = svc.append_revocation(
            revoke_req(s, "g1", dt("2026-01-15T00:00:00Z")))
        svc.append_grant(grant_req(s, "g2"))
        svc.register_task("t2", task_req(s, [
            product("p3", [[("receipt", "t2")]])]))
        return svc, rev["event"]["seq"]

    def test_compliance_diff_two_bound_replay(self):
        svc, rev_seq = self._build_diff_scenario("user-diff")
        s = "user-diff"

        # ---- diff(1, 2)：撤销落入区间 -> 回执 / 产物翻转、处置开立、删除结论翻转。
        # 在全部事件（含 seq=3 的恢复许可）之后签发：取消记录 grant_seq=3 对
        # to=2 一侧不可见（后续事件不改变报告）。
        d = svc.compliance_diff(diff_req(s, ["p1", "p2"], 1, 2))
        self.assertEqual(d["from_seq"], 1)
        self.assertEqual(d["to_seq"], 2)
        self.assertEqual(d["from_basis_seq"], 1)
        self.assertEqual(d["to_basis_seq"], 2)
        self.assertEqual([p["product_id"] for p in d["products"]],
                         ["p1", "p2"])  # 按产品 ID 稳定排序
        p1 = d["products"][0]
        self.assertEqual(p1["classification"], "changed")
        self.assertEqual(p1["from"]["status"], "active")
        self.assertEqual(p1["to"]["status"], "blocked")
        self.assertEqual(p1["to"]["invalidating_events"], [rev_seq])
        flip = p1["flip_reasons"][0]
        self.assertEqual(flip["kind"], "status_flip")
        self.assertEqual(flip["causing_receipts"], ["t1"])
        # 传递回执：valid -> invalid，翻转原因定位到撤销事件。
        r1 = p1["receipts"][0]
        self.assertEqual(r1["receipt_key"], "t1")
        self.assertEqual(r1["classification"], "changed")
        self.assertEqual(r1["decision"], "allow")
        self.assertEqual(r1["basis"]["grant_id"], "g1")
        self.assertTrue(r1["from"]["currently_valid"])
        self.assertFalse(r1["to"]["currently_valid"])
        self.assertEqual(r1["to"]["invalidating_events"], [rev_seq])
        self.assertEqual(r1["flip_reasons"][0]["kind"], "revoked")
        self.assertEqual(r1["flip_reasons"][0]["revocation_seq"], rev_seq)
        self.assertEqual(r1["flip_reasons"][0]["grant_id"], "g1")
        # 处置项：added（开立于 seq=2）；取消（grant_seq=3）对该侧不可见。
        self.assertEqual(len(d["remediation_items"]), 1)
        item = d["remediation_items"][0]
        self.assertEqual(item["classification"], "added")
        self.assertEqual(item["from"], {"presence": "absent"})
        self.assertEqual(item["to"]["status"], "open")
        self.assertEqual(item["flip_reasons"],
                         [{"kind": "opened", "revocation_seq": rev_seq}])
        # 删除结论：active_grant(g1) -> open_remediation。
        self.assertEqual(d["deletion"]["classification"], "changed")
        self.assertEqual(d["deletion"]["from"]["status"], "blocked")
        self.assertEqual([b["kind"] for b in d["deletion"]["from"]["blockers"]],
                         ["active_grant"])
        self.assertEqual([b["kind"] for b in d["deletion"]["to"]["blockers"]],
                         ["open_remediation"])
        kinds = [r["kind"] for r in d["deletion"]["flip_reasons"]]
        self.assertIn("blocker_removed", kinds)
        self.assertIn("blocker_added", kinds)
        # 汇总计数。
        self.assertEqual(d["summary"]["products"],
                         {"added": 0, "removed": 0, "changed": 2,
                          "unchanged": 0})
        self.assertEqual(d["summary"]["remediation_items"]["added"], 1)
        self.assertEqual(d["summary"]["deletion"], "changed")

        # ---- diff(2, 3)：恢复许可落入区间 -> 回执恢复、处置取消、结论回摆。
        d2 = svc.compliance_diff(diff_req(s, ["p1"], 2, 3))
        p1 = d2["products"][0]
        self.assertEqual(p1["classification"], "changed")
        self.assertEqual(p1["from"]["status"], "blocked")
        self.assertEqual(p1["to"]["status"], "active")
        r1 = p1["receipts"][0]
        self.assertEqual(r1["classification"], "changed")
        self.assertFalse(r1["from"]["currently_valid"])
        self.assertTrue(r1["to"]["currently_valid"])
        self.assertEqual(r1["flip_reasons"],
                         [{"kind": "hit_grant_changed",
                           "from_grant": {"grant_id": "g1", "grant_seq": 1},
                           "to_grant": {"grant_id": "g2", "grant_seq": 3}}])
        item = d2["remediation_items"][0]
        self.assertEqual(item["classification"], "changed")
        self.assertEqual(item["from"]["status"], "open")
        self.assertEqual(item["to"]["status"], "cancelled")
        self.assertEqual(item["flip_reasons"],
                         [{"kind": "cancelled", "grant_seq": 3}])
        self.assertEqual([b["kind"] for b in d2["deletion"]["to"]["blockers"]],
                         ["active_grant"])
        self.assertEqual(
            d2["deletion"]["to"]["blockers"][0]["grant_id"], "g2")

        # ---- diff(1, 3)：p3 在 from 侧尚未登记 -> absent / added；
        #    p1 两侧均 active（unchanged），但其回执命中许可变化（changed）。
        d3 = svc.compliance_diff(diff_req(s, ["p1", "p3"], 1, 3))
        by_pid = {p["product_id"]: p for p in d3["products"]}
        self.assertEqual(by_pid["p1"]["classification"], "unchanged")
        self.assertEqual(by_pid["p1"]["receipts"][0]["classification"],
                         "changed")
        # 两侧均有效、命中许可被更新许可取代：仅 hit_grant_changed 原因。
        self.assertEqual(
            by_pid["p1"]["receipts"][0]["flip_reasons"],
            [{"kind": "hit_grant_changed",
              "from_grant": {"grant_id": "g1", "grant_seq": 1},
              "to_grant": {"grant_id": "g2", "grant_seq": 3}}])
        p3 = by_pid["p3"]
        self.assertEqual(p3["classification"], "added")
        self.assertEqual(p3["from"], {"presence": "absent"})
        self.assertEqual(p3["to"]["status"], "active")
        self.assertEqual(p3["flip_reasons"][0]["kind"], "registered")
        self.assertEqual(p3["receipts"][0]["classification"], "added")
        self.assertEqual(p3["receipts"][0]["from"], {"presence": "absent"})
        # 删除结论：两侧均 blocked，但命中许可身份 g1 -> g2 变化。
        self.assertEqual(d3["deletion"]["classification"], "changed")
        self.assertEqual(d3["deletion"]["from"]["status"], "blocked")
        self.assertEqual(d3["deletion"]["to"]["status"], "blocked")
        self.assertEqual(d3["summary"]["products"]["added"], 1)
        self.assertEqual(d3["summary"]["products"]["unchanged"], 1)

        # ---- 后续事件不改变报告：追加新许可 / 撤销后重发同一 diff 完全一致。
        before = svc.compliance_diff(diff_req(s, ["p1", "p2"], 1, 2))
        svc.append_grant(grant_req(s, "g3"))
        svc.append_revocation(revoke_req(s, "g2", dt("2026-02-01T00:00:00Z")))
        after = svc.compliance_diff(diff_req(s, ["p1", "p2"], 1, 2))
        self.assertEqual(before, after)

    def test_compliance_diff_rerevocation_and_deny_receipt(self):
        """invalid -> invalid（换许可再被撤销）与登记即拒绝回执的差异口径。"""
        svc, _ = make_service()
        s = "user-diff3"
        svc.append_grant(grant_req(s, "g1"))                    # seq=1
        svc.register_task("t1", task_req(s, [
            product("p1", [[("receipt", "t1")]])]))
        svc.append_revocation(revoke_req(s, "g1", dt("2026-01-15T00:00:00Z")))
        svc.append_grant(grant_req(s, "g2"))                    # seq=3
        rev2 = svc.append_revocation(
            revoke_req(s, "g2", dt("2026-02-01T00:00:00Z")))    # seq=4
        # 撤销后登记：回执为 deny（永久无效，失效事件集合为空）。
        svc.register_task("t2", task_req(s, [
            product("p2", [[("receipt", "t2")]])]))

        # diff(2, 4)：t1 两侧均失效，但失效事件与命中许可都变化。
        d = svc.compliance_diff(diff_req(s, ["p1"], 2, 4))
        rec = d["products"][0]["receipts"][0]
        self.assertEqual(rec["classification"], "changed")
        self.assertEqual(rec["from"]["invalidating_events"], [2])
        self.assertEqual(rec["to"]["invalidating_events"],
                         [rev2["event"]["seq"]])
        self.assertEqual(
            [r["kind"] for r in rec["flip_reasons"]],
            ["revoked", "hit_grant_changed"])
        # 产品两侧均 blocked 但失效事件集合变化 -> changed。
        p1 = d["products"][0]
        self.assertEqual(p1["classification"], "changed")
        self.assertEqual(p1["flip_reasons"][0]["kind"],
                         "invalidating_events_changed")

        # diff(1, 4)：deny 回执 t2 在 from 侧不存在 -> added；两侧恒无效。
        d = svc.compliance_diff(diff_req(s, ["p2"], 1, 4))
        rec = d["products"][0]["receipts"][0]
        self.assertEqual(rec["classification"], "added")
        self.assertEqual(rec["decision"], "deny")
        self.assertEqual(rec["to"]["currently_valid"], False)
        self.assertEqual(rec["to"]["invalidating_events"], [])
        self.assertIsNone(rec["to"]["hit_grant"])
        # diff(4, 4+?) 不可行（需 from<to），改测 deny 回执两侧一致：
        svc.append_grant(grant_req(s, "g3"))                    # seq=5
        d = svc.compliance_diff(diff_req(s, ["p2"], 4, 5))
        rec = d["products"][0]["receipts"][0]
        self.assertEqual(rec["classification"], "unchanged")
        self.assertEqual(d["products"][0]["classification"], "unchanged")

    def test_compliance_diff_validation_and_unchanged(self):
        from app.errors import ApiError
        svc, _ = make_service()
        s = "user-diff2"
        svc.append_grant(grant_req(s, "g1"))
        svc.register_task("t1", task_req(s, [
            product("p1", [[("receipt", "t1")]])]))

        # from_seq >= to_seq -> 422；未来序号 -> 422；未知产品 -> 422。
        with self.assertRaises(ApiError) as cm:
            svc.compliance_diff(diff_req(s, ["p1"], 1, 1))
        self.assertEqual(cm.exception.status_code, 422)
        with self.assertRaises(ApiError) as cm:
            svc.compliance_diff(diff_req(s, ["p1"], 1, 999))
        self.assertEqual(cm.exception.status_code, 422)
        with self.assertRaises(ApiError) as cm:
            svc.compliance_diff(diff_req(s, ["ghost"], 1, 1 + 1))
        self.assertEqual(cm.exception.status_code, 422)

        # 追加一条与回执四元组无关的许可（seq=2）：diff(1, 2) 全部 unchanged。
        svc.append_grant(SimpleNamespace(
            subject_id=s, grant_id="g9", category="location",
            purpose="marketing", recipient="partner-b",
            valid_from=dt("2026-01-01T00:00:00Z"), valid_to=None))
        d = svc.compliance_diff(diff_req(s, ["p1"], 1, 2))
        self.assertEqual(d["products"][0]["classification"], "unchanged")
        self.assertEqual(d["products"][0]["receipts"][0]["classification"],
                         "unchanged")
        self.assertEqual(d["remediation_items"], [])
        self.assertEqual(d["deletion"]["classification"], "unchanged")
        self.assertEqual(d["deletion"]["flip_reasons"], [])

        # 晚于 to_seq 登记的产品：两侧快照均不存在 -> 422。
        svc.append_grant(grant_req(s, "g3"))  # seq=3
        svc.register_task("t2", task_req(s, [
            product("p2", [[("receipt", "t2")]])]))  # recorded_seq=3
        with self.assertRaises(ApiError) as cm:
            svc.compliance_diff(diff_req(s, ["p2"], 1, 2))
        self.assertEqual(cm.exception.status_code, 422)
        # to_seq 覆盖其登记序号后允许（from 侧 absent -> added）。
        d = svc.compliance_diff(diff_req(s, ["p2"], 1, 3))
        self.assertEqual(d["products"][0]["classification"], "added")


if __name__ == "__main__":
    unittest.main()
