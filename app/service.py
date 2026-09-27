"""业务服务层：追加事件、确定性重放、幂等登记、血缘阻断传播。

并发控制
~~~~~~~~
决策登记与同一主体的撤销（以及许可追加）由**调用方**（路由层）通过
``app.db.transaction(lock_subject=subject_id)`` 串行化：在 REPEATABLE READ
事务开始**之前**先获取该主体的会话级咨询锁
``pg_advisory_lock(hashtext(subject_id))``，事务提交 / 回滚后释放。

* 不同主体互不阻塞；
* 同一主体的写操作严格按锁获取顺序串行；由于 REPEATABLE READ 的快照在
  事务内第一条语句执行时建立，**先取锁再开事务**才能保证每个写事务读到
  锁顺序上前一个写者已提交的状态（撤销先提交则后续登记即 deny/revoked；
  任务先登记则撤销的传播扫描恰好看到此前已登记的全部回执）。

事务隔离级别为 REPEATABLE READ，保证一次登记 / 重放内看到一致快照。
所有持久化操作均为 INSERT，历史记录永不改写。
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Optional

from . import attestation as attestation_mod
from . import domain
from .errors import conflict, forbidden, not_found, unprocessable
from .repository import Repo, event_from_row


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def utc(dt: datetime) -> datetime:
    """归一化带时区的 UTC 时间（无时区则视为 UTC）。"""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def fingerprint(payload: dict) -> str:
    """幂等请求指纹：归一化 JSON（时间转 UTC ISO）后取 SHA-256。"""
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _decision_payload(t: dict) -> dict:
    return {
        "subject_id": t["subject_id"],
        "category": t["category"],
        "purpose": t["purpose"],
        "recipient": t["recipient"],
        "use_at": utc(t["use_at"]).isoformat(),
        "products": [
            {
                "product_id": p.product_id,
                "description": p.description,
                "groups": [[
                    {"kind": i.kind, "ref": i.ref} for i in group
                ] for group in p.groups],
            }
            for p in t["products"]
        ],
    }


def _event_dict(ev: domain.Event) -> dict:
    d = {
        "seq": ev.seq, "event_type": ev.event_type,
        "grant_id": ev.grant_id, "recorded_at": ev.recorded_at,
    }
    if ev.event_type == "grant":
        d.update(category=ev.category, purpose=ev.purpose,
                 recipient=ev.recipient, valid_from=ev.valid_from,
                 valid_to=ev.valid_to)
    else:
        d.update(revoke_grant=ev.revoke_grant,
                 business_effective_at=ev.business_effective_at)
    return d


def _basis(dec: domain.Decision) -> dict:
    b = dec.basis()
    b["reason"] = dec.reason
    return b


class Service:
    def __init__(self, conn):
        self.conn = conn
        self.repo = Repo(conn)

    # ============================================================== 内部
    def _subject_events(self, subject_id: str) -> list[domain.Event]:
        rows = self.repo.list_events(subject_id)
        return [event_from_row(r) for r in rows]

    def _load_product_graph(self, subject_id: str):
        """返回 (products, receipts_states 所需行, 产品映射信息)。"""
        products_rows = self.repo.list_products_for_subject(subject_id)
        groups_rows = self.repo.list_groups(subject_id)
        inputs = self.repo.list_inputs_for_groups(
            [g["group_id"] for g in groups_rows])
        inputs_by_group: dict[int, list[dict]] = {}
        for inp in inputs:
            inputs_by_group.setdefault(inp["group_id"], []).append(inp)
        products: dict[str, list[list[str]]] = {}
        product_meta: dict[str, dict] = {}
        for p in products_rows:
            products[p["product_id"]] = []
            product_meta[p["product_id"]] = p
        for g in groups_rows:
            refs = []
            for inp in inputs_by_group.get(g["group_id"], []):
                if inp["input_kind"] == "receipt":
                    refs.append(f"receipt:{inp['input_ref']}")
                else:
                    refs.append(inp["input_ref"])
            products.setdefault(g["product_id"], []).append(refs)
        return products, product_meta, products_rows, groups_rows, inputs_by_group

    def _receipt_state(self, row: dict, events: list[domain.Event],
                       as_of: Optional[str],
                       as_of_seq: Optional[int]) -> domain.ReceiptState:
        if row["decision"] == "deny":
            # 登记时即被拒绝：永久无效，失效事件集合为空。
            return domain.ReceiptState(row["idempotency_key"], False, (),
                                       f"registered deny ({row['basis_reason']})")
        dec = domain.decide(
            events,
            subject_id=row["subject_id"], category=row["category"],
            purpose=row["purpose"], recipient=row["recipient"],
            use_at=utc(row["use_at"]).isoformat(),
            as_of=as_of, as_of_seq=as_of_seq)
        if dec.outcome == "allow":
            return domain.ReceiptState(row["idempotency_key"], True)
        # 既有 allow 决策被补录撤销追溯失效。
        return domain.ReceiptState(
            row["idempotency_key"], False,
            (dec.revocation.seq,) if dec.reason == "revoked" else (),
            dec.reason)

    def _evaluate_subject_products(self, subject_id: str, *,
                                   as_of: Optional[str] = None,
                                   as_of_seq: Optional[int] = None,
                                   restrict_products: Optional[set[str]] = None):
        events = self._subject_events(subject_id)
        receipt_rows = self.repo.get_receipts_for_subject(subject_id)
        receipts = {
            r["idempotency_key"]:
                self._receipt_state(r, events, as_of, as_of_seq)
            for r in receipt_rows
        }
        products, meta, _, _, _ = self._load_product_graph(subject_id)
        evaluations = domain.evaluate_product_graph(products, receipts)
        if restrict_products is not None:
            evaluations = {k: v for k, v in evaluations.items()
                           if k in restrict_products}
        return receipts, products, evaluations, meta

    # ============================================================== 追加许可
    def append_grant(self, req, recorded_at: Optional[datetime] = None) -> dict:
        recorded_at = utc(recorded_at or now_utc())
        vf = utc(req.valid_from) if req.valid_from else None
        vt = utc(req.valid_to) if req.valid_to else None
        # 许可追加前的回执状态：用于识别由失效恢复有效的回执，取消其未结
        # 处置项（与许可在同一事务内提交，回滚则取消记录同样不存在）。
        before_receipts, _, _, _ = self._evaluate_subject_products(
            req.subject_id)
        row = self.repo.insert_grant(
            subject_id=req.subject_id, grant_id=req.grant_id,
            category=req.category, purpose=req.purpose,
            recipient=req.recipient, valid_from=vf, valid_to=vt,
            recorded_at=recorded_at)
        ev = event_from_row(row)

        cancelled = self._cancel_items_restored_by_grant(
            req.subject_id, ev.seq, recorded_at, before_receipts)
        return {**_event_dict(ev),
                "cancelled_remediation_items": cancelled}

    def _cancel_items_restored_by_grant(self, subject_id: str,
                                        grant_seq: int, cancelled_at,
                                        before_receipts: dict) -> list[dict]:
        """比较许可追加前后状态，为失效 -> 有效的回执取消未结处置项。"""
        after_receipts, _, _, _ = self._evaluate_subject_products(subject_id)
        restored = {key for key, st in after_receipts.items()
                    if not before_receipts[key].valid and st.valid}
        if not restored:
            return []
        state = self._remediation_state(subject_id)
        cancelled: list[dict] = []
        for iid in sorted(state):
            entry = state[iid]
            if (entry["item"]["receipt_key"] in restored
                    and entry["status"] in domain.REMEDIATION_UNRESOLVED):
                self.repo.insert_remediation_cancellation(
                    item_id=iid, grant_seq=grant_seq, cancelled_at=cancelled_at)
                cancelled.append({
                    "item_id": iid,
                    "receipt_key": entry["item"]["receipt_key"]})
        return cancelled

    # ============================================================== 撤销
    def append_revocation(self, req, recorded_at: Optional[datetime] = None):
        recorded_at = utc(recorded_at or now_utc())
        bea = utc(req.business_effective_at)
        grant_row = self.repo.find_grant(req.subject_id, req.grant_id)
        if grant_row is None:
            raise not_found(f"主体 {req.subject_id} 下不存在许可 {req.grant_id}")
        row = self.repo.insert_revocation(
            subject_id=req.subject_id, grant_id=req.grant_id,
            business_effective_at=bea, recorded_at=recorded_at)
        ev = event_from_row(row)

        # 同一事务内比较撤销前后的回执与产物状态：before = 不含本次撤销
        # 事件的重放（as_of_seq=ev.seq-1），after = 当前全部事件。
        before_receipts, _, before_evals, _ = self._evaluate_subject_products(
            req.subject_id, as_of_seq=ev.seq - 1)
        receipts, products, evaluations, meta = self._evaluate_subject_products(
            req.subject_id)
        affected_receipts = sorted(
            k for k, st in receipts.items()
            if not st.valid and ev.seq in st.invalidating_seqs)
        blocked = [
            {"product_id": pid,
             "invalidating_events": list(node.invalidating_seqs),
             "explanation": node.explanation_groups}
            for pid, node in evaluations.items()
            if not node.active and ev.seq in node.invalidating_seqs
        ]
        blocked.sort(key=lambda b: (len(b["invalidating_events"]),
                                     b["invalidating_events"], b["product_id"]))

        opened = self._open_items_invalidated_by_revocation(
            req.subject_id, ev.seq, recorded_at, before_receipts, receipts,
            products, before_evals, evaluations)
        return {"event": _event_dict(ev),
                "affected_receipts": affected_receipts,
                "blocked_products": blocked,
                "remediation_items": opened}

    def _open_items_invalidated_by_revocation(
            self, subject_id: str, revocation_seq: int, opened_at,
            before_receipts: dict, after_receipts: dict,
            products: dict, before_evals: dict,
            after_evals: dict) -> list[dict]:
        """为本次撤销中由有效转为失效的回执开立处置项（与撤销同事务）。

        * 只处理 有效 -> 失效 的回执；未恢复有效即再次被撤销的回执保持
          失效，前后都无效，不重复开立；
        * 关联产物：沿该回执血缘（传递依赖）在本次撤销中转为阻断的产物。
        """
        newly_invalid = sorted(
            key for key, st in after_receipts.items()
            if before_receipts[key].valid and not st.valid)
        if not newly_invalid:
            return []
        newly_blocked = {
            pid for pid, node in after_evals.items()
            if before_evals[pid].active and not node.active}
        lineage = {pid: domain.transitive_receipts(products, pid)
                   for pid in newly_blocked}
        receipt_rows = {
            r["idempotency_key"]: r
            for r in self.repo.get_receipts_for_subject(subject_id)}
        opened: list[dict] = []
        for key in newly_invalid:
            recipient = receipt_rows[key]["recipient"]
            item_id = self.repo.insert_remediation_item(
                subject_id=subject_id, receipt_key=key, recipient=recipient,
                revocation_seq=revocation_seq, opened_at=opened_at)
            linked = sorted(pid for pid in newly_blocked
                            if key in lineage[pid])
            for pid in linked:
                self.repo.insert_remediation_item_product(item_id, pid)
            opened.append({"item_id": item_id, "receipt_key": key,
                           "recipient": recipient, "products": linked})
        return opened

    # ============================================================== 只读重放
    def evaluate(self, req, as_of_override: Optional[datetime] = None,
                 as_of_seq: Optional[int] = None) -> dict:
        as_of_dt = as_of_override or req.as_of
        as_of_iso = utc(as_of_dt).isoformat() if as_of_dt else None
        events = self._subject_events(req.subject_id)
        dec = domain.decide(
            events,
            subject_id=req.subject_id, category=req.category,
            purpose=req.purpose, recipient=req.recipient,
            use_at=utc(req.use_at).isoformat(),
            as_of=as_of_iso, as_of_seq=as_of_seq)
        if dec.outcome == "allow":
            hit = "grant"
        elif dec.reason == "revoked":
            hit = "revocation"
        else:
            hit = "none"
        return {
            "subject_id": req.subject_id,
            "use_at": utc(req.use_at).isoformat(),
            "as_of": as_of_iso,
            "as_of_seq": as_of_seq,
            "decision": dec.outcome,
            "basis": _basis(dec),
            "hit": hit,
        }

    # ============================================================== 登记任务
    def register_task(self, key: str, req,
                      decided_at: Optional[datetime] = None) -> dict:
        if not key:
            raise unprocessable("缺少 Idempotency-Key 头")
        decided_at = utc(decided_at or now_utc())
        payload = _decision_payload({
            "subject_id": req.subject_id, "category": req.category,
            "purpose": req.purpose, "recipient": req.recipient,
            "use_at": req.use_at, "products": req.products})
        fp = fingerprint(payload)

        existing = self.repo.get_receipt(key)
        if existing is not None:
            return self._replay_idempotent(existing, fp, req)

        # 同一批次内 product_id 不得重复。
        pids = [p.product_id for p in req.products]
        if len(pids) != len(set(pids)):
            raise unprocessable("同一任务批次中 product_id 重复")

        # 以当前最新事件重放，登记回执（默认拒绝语义由 domain 保证）。
        events = self._subject_events(req.subject_id)
        dec = domain.decide(
            events,
            subject_id=req.subject_id, category=req.category,
            purpose=req.purpose, recipient=req.recipient,
            use_at=utc(req.use_at).isoformat())

        # 构建血缘图（含本批新产物）并校验引用与无环。
        graph, known_receipts = self._build_batch_graph(req, key)
        cycle = domain.detect_cycle(graph, known_receipts)
        if cycle:
            raise unprocessable("血缘存在环: " + " -> ".join(cycle))

        # 记录回执（即使 deny 也登记，作为不可变决策回执）。
        recorded_row = self.repo.insert_receipt(
            key=key, subject_id=req.subject_id, category=req.category,
            purpose=req.purpose, recipient=req.recipient,
            use_at=utc(req.use_at), decided_at=decided_at,
            decision=dec.outcome,
            basis_grant_id=dec.grant.grant_id if dec.grant else None,
            basis_seq=(dec.grant.seq if dec.outcome == "allow"
                       else (dec.revocation.seq
                             if dec.reason == "revoked" else None)),
            basis_reason=dec.reason, fingerprint=fp,
            recorded_seq=max((e.seq for e in events), default=0),
            recorded_at=decided_at)

        # 登记产物与血缘（全 INSERT）。
        for idx, spec in enumerate(req.products):
            self.repo.insert_product(
                subject_id=req.subject_id, product_id=spec.product_id,
                task_key=key, description=spec.description,
                recorded_seq=recorded_row["recorded_seq"],
                recorded_at=decided_at)
            for gidx, group in enumerate(spec.groups):
                gid = self.repo.insert_group(
                    req.subject_id, spec.product_id, gidx)
                for iidx, inp in enumerate(group):
                    self.repo.insert_input(gid, iidx, inp.kind, inp.ref)

        return self._task_response(req.subject_id, key, set(pids),
                                   replayed=False, fp_match=True)

    def _replay_idempotent(self, existing: dict, fp: str, req) -> dict:
        if existing["request_fingerprint"] != fp:
            raise conflict("Idempotency-Key 已用于不同的请求内容")
        pids = {p["product_id"] for p in
                self.repo.list_products_by_task(existing["idempotency_key"])}
        return self._task_response(req.subject_id,
                                   existing["idempotency_key"], pids,
                                   replayed=True, fp_match=True)

    def _build_batch_graph(self, req, task_key: str):
        """合并既有血缘与本批产物，返回 (图引用结构, 已知回执键集合)。"""
        existing_products, _, _, groups_rows, inputs_by_group = \
            self._load_product_graph(req.subject_id)
        graph = {pid: [list(refs) for refs in groups]
                 for pid, groups in existing_products.items()}

        known_receipts = {
            r["idempotency_key"]
            for r in self.repo.get_receipts_for_subject(req.subject_id)}
        known_products = set(graph.keys())

        new_pids = set()
        for spec in req.products:
            if spec.product_id in known_products:
                raise conflict(f"产物 {spec.product_id} 已存在")
            new_pids.add(spec.product_id)
        known_products |= new_pids
        known_receipts.add(task_key)  # 本任务回执本身（同一事务内先建后引）

        for spec in req.products:
            refs_groups = spec.normalized_groups()
            for refs in refs_groups:
                for ref in refs:
                    if ref.startswith("receipt:"):
                        rkey = ref[len("receipt:"):]
                        if rkey not in known_receipts:
                            raise unprocessable(
                                f"未知回执引用: {rkey}")
                    elif ref not in known_products:
                        raise unprocessable(
                            f"未知产物引用: {ref}（须同主体且已登记或同批声明）")
            graph[spec.product_id] = refs_groups
        return graph, known_receipts

    def _task_response(self, subject_id: str, key: str,
                       pids: set[str], replayed: bool, fp_match: bool) -> dict:
        receipt_row = self.repo.get_receipt(key)
        receipts, _, evaluations, _ = self._evaluate_subject_products(
            subject_id, restrict_products=pids)
        receipt_state = receipts[key]
        products_out = []
        for pid in sorted(pids):
            node = evaluations[pid]
            products_out.append({
                "product_id": pid,
                "status": "active" if node.active else "blocked",
                "invalidating_events": list(node.invalidating_seqs),
                "explanation": node.explanation_groups,
            })
        return {
            "idempotency_key": key,
            "idempotent_replay": replayed,
            "receipt": {
                "idempotency_key": receipt_row["idempotency_key"],
                "decision": receipt_row["decision"],
                "basis_reason": receipt_row["basis_reason"],
                "basis_grant_id": receipt_row["basis_grant_id"],
                "basis_seq": receipt_row["basis_seq"],
                "use_at": utc(receipt_row["use_at"]).isoformat(),
                "decided_at": utc(receipt_row["decided_at"]).isoformat(),
                "recorded_seq": receipt_row["recorded_seq"],
                "currently_valid": receipt_state.valid,
                "invalidating_events": list(receipt_state.invalidating_seqs),
            },
            "products": products_out,
        }

    # ============================================================== 查询
    def get_receipt(self, key: str) -> dict:
        row = self.repo.get_receipt(key)
        if row is None:
            raise not_found(f"回执 {key} 不存在")
        events = self._subject_events(row["subject_id"])
        state = self._receipt_state(row, events, None, None)
        return {
            "idempotency_key": row["idempotency_key"],
            "subject_id": row["subject_id"],
            "category": row["category"],
            "purpose": row["purpose"],
            "recipient": row["recipient"],
            "use_at": utc(row["use_at"]).isoformat(),
            "decided_at": utc(row["decided_at"]).isoformat(),
            "decision": row["decision"],
            "basis": {
                "grant_id": row["basis_grant_id"],
                "seq": row["basis_seq"],
                "reason": row["basis_reason"],
            },
            "recorded_seq": row["recorded_seq"],
            "recorded_at": utc(row["recorded_at"]).isoformat(),
            "currently_valid": state.valid,
            "invalidating_events": list(state.invalidating_seqs),
        }

    def get_product(self, subject_id: str, product_id: str,
                    as_of: Optional[datetime] = None,
                    as_of_seq: Optional[int] = None) -> dict:
        as_of_iso = utc(as_of).isoformat() if as_of else None
        receipts, graph, evaluations, meta = self._evaluate_subject_products(
            subject_id, as_of=as_of_iso, as_of_seq=as_of_seq)
        if product_id not in graph:
            raise not_found(f"主体 {subject_id} 下不存在产物 {product_id}")
        node = evaluations[product_id]
        return {
            "subject_id": subject_id,
            "product_id": product_id,
            "description": meta[product_id]["description"],
            "status": "active" if node.active else "blocked",
            "invalidating_events": list(node.invalidating_seqs),
            "explanation": node.explanation_groups,
            "as_of": as_of_iso,
            "as_of_seq": as_of_seq,
        }

    def list_events(self, subject_id: str,
                    as_of_seq: Optional[int] = None) -> list[dict]:
        rows = self.repo.list_events(subject_id, as_of_seq)
        return [_event_dict(event_from_row(r)) for r in rows]

    # ============================================================== 处置台账
    def remediation_item_subject(self, item_id: int) -> str:
        """供路由在取主体咨询锁前定位处置项所属主体。"""
        item = self.repo.get_remediation_item(item_id)
        if item is None:
            raise not_found(f"处置项 {item_id} 不存在")
        return item["subject_id"]

    def _remediation_state(self, subject_id: str,
                           cancel_upto_grant_seq: Optional[int] = None
                           ) -> dict[int, dict]:
        """加载主体全部处置项及其追加记录，派生每项状态。

        :param cancel_upto_grant_seq: 不为 None 时，取消记录按事件序号上界
            过滤（``grant_seq`` 超过上界的取消对该侧不可见）——双时点差异
            报告按序号上界重放取消；提交 / 复核不携带事件序号（不是事件），
            始终按请求快照原样计入。
        """
        items = self.repo.list_remediation_items(subject_id)
        if not items:
            return {}
        ids = [i["item_id"] for i in items]
        prows = self.repo.list_remediation_item_products(ids)
        srows = self.repo.list_remediation_submissions(ids)
        rrows = self.repo.list_remediation_reviews(ids)
        crows = self.repo.list_remediation_cancellations(ids)

        products_by_item: dict[int, list[str]] = {}
        for p in prows:
            products_by_item.setdefault(p["item_id"], []).append(p["product_id"])
        subs_by_item: dict[int, list[dict]] = {}
        for s in srows:
            subs_by_item.setdefault(s["item_id"], []).append(s)
        reviews_by_item: dict[int, dict[int, dict]] = {}
        for r in rrows:
            reviews_by_item.setdefault(r["item_id"], {})[r["version"]] = r
        cancel_by_item = {c["item_id"]: c for c in crows}

        state: dict[int, dict] = {}
        for item in items:
            iid = item["item_id"]
            subs = subs_by_item.get(iid, [])
            reviews = reviews_by_item.get(iid, {})
            cancel = cancel_by_item.get(iid)
            if (cancel is not None and cancel_upto_grant_seq is not None
                    and cancel["grant_seq"] > cancel_upto_grant_seq):
                # 序号上界之外的取消记录对该侧不可见（后续事件不改变报告）。
                cancel = None
            status = domain.remediation_item_status(
                cancelled=cancel is not None,
                submission_versions=[s["version"] for s in subs],
                reviews={v: r["action"] for v, r in reviews.items()})
            state[iid] = {"item": item, "status": status,
                          "products": products_by_item.get(iid, []),
                          "submissions": subs, "reviews": reviews,
                          "cancellation": cancel}
        return state

    def get_remediation_case(self, subject_id: str, recipient: str) -> dict:
        """接收方（或管理员按 ?recipient=）查询处置台账。

        返回未结项、各处置项的提交证据与复核历史；该接收方在该主体下的
        全部处置项均了结（获批 / 取消）才显示 closed，后续新增失效重新
        pending。
        """
        state = self._remediation_state(subject_id)
        entries = [e for e in state.values()
                   if e["item"]["recipient"] == recipient]
        entries.sort(key=lambda e: e["item"]["item_id"])
        statuses = [e["status"] for e in entries]
        return {
            "subject_id": subject_id,
            "recipient": recipient,
            "status": domain.remediation_case_status(statuses),
            "open_item_ids": [e["item"]["item_id"] for e in entries
                              if e["status"] in domain.REMEDIATION_UNRESOLVED],
            "items": [self._remediation_item_dict(e) for e in entries],
        }

    def submit_remediation(self, item_id: int, recipient: str, key: str,
                           req) -> dict:
        """接收方逐项提交停止使用声明与关联产物清除证据（幂等、按版本）。"""
        if not key:
            raise unprocessable("缺少 Idempotency-Key 头")
        item = self.repo.get_remediation_item(item_id)
        if item is None:
            raise not_found(f"处置项 {item_id} 不存在")
        if item["recipient"] != recipient:
            raise forbidden("只能提交自己的处置项")

        evidence = [{"product_id": e.product_id, "summary": e.summary}
                    for e in req.evidence]
        fp = fingerprint({
            "item_id": item_id, "version": req.version,
            "cease_declaration": req.cease_declaration,
            "evidence": evidence})
        existing = self.repo.get_submission_by_key(key)
        if existing is not None:
            if existing["request_fingerprint"] != fp:
                raise conflict("Idempotency-Key 已用于不同的请求内容")
            return self._submission_result(existing, item, replayed=True)

        entry = self._remediation_state(item["subject_id"])[item_id]
        status = entry["status"]
        expected_version = max(
            (s["version"] for s in entry["submissions"]), default=0) + 1

        # 请求内容校验（与处置项当前状态无关，恒为 422）。
        given = [e["product_id"] for e in evidence]
        if len(given) != len(set(given)):
            raise unprocessable("证据中 product_id 重复")
        if set(given) != set(entry["products"]):
            raise unprocessable(
                "证据必须逐项覆盖全部关联产物，且不得包含无关产物")

        if status == "cancelled":
            raise conflict("处置项已取消（回执已恢复有效），无需提交")
        if status == "approved":
            raise conflict("处置项已获批结案，不能再次提交")
        if status == "submitted":
            raise conflict("当前版本待复核；驳回后方可提交补证版本")
        if req.version != expected_version:
            raise conflict(
                f"过期版本：当前应提交 version={expected_version}")

        row = self.repo.insert_remediation_submission(
            item_id=item_id, version=req.version, idempotency_key=key,
            cease_declaration=req.cease_declaration,
            evidence_json=json.dumps(evidence, ensure_ascii=False),
            fingerprint=fp, submitted_by=recipient, submitted_at=now_utc())
        return self._submission_result(row, item, replayed=False)

    def review_remediation(self, item_id: int, req) -> dict:
        """管理员按版本批准 / 驳回；驳回后接收方可提交补证版本。"""
        item = self.repo.get_remediation_item(item_id)
        if item is None:
            raise not_found(f"处置项 {item_id} 不存在")
        entry = self._remediation_state(item["subject_id"])[item_id]
        status = entry["status"]
        if status == "cancelled":
            raise conflict("处置项已取消，无需复核")
        if status == "approved":
            raise conflict("处置项已获批结案，不能再次复核")
        if status == "open":
            raise conflict("处置项尚无提交，无法复核")
        latest = max(s["version"] for s in entry["submissions"])
        if req.version != latest:
            raise conflict(
                f"过期版本：只能复核最新提交版本 version={latest}")
        if status == "rejected":
            # 最新版本已有驳回决定：该版本不得再复核，等待补证新版本。
            raise conflict("该版本已复核（驳回），请复核补证后的新版本")

        action = "approved" if req.action == "approve" else "rejected"
        row = self.repo.insert_remediation_review(
            item_id=item_id, version=req.version, action=action,
            comment=req.comment, reviewed_at=now_utc())
        return {
            "item_id": item_id,
            "receipt_key": item["receipt_key"],
            "item_status": action,
            "review": _review_dict(row),
        }

    def _submission_result(self, sub: dict, item: dict,
                           replayed: bool) -> dict:
        entry = self._remediation_state(item["subject_id"])[item["item_id"]]
        return {
            "idempotent_replay": replayed,
            "item_id": item["item_id"],
            "receipt_key": item["receipt_key"],
            "item_status": entry["status"],
            "submission": _submission_dict(sub),
        }

    def _remediation_item_dict(self, entry: dict) -> dict:
        item = entry["item"]
        cancel = entry["cancellation"]
        return {
            "item_id": item["item_id"],
            "receipt_key": item["receipt_key"],
            "recipient": item["recipient"],
            "status": entry["status"],
            "revocation_seq": item["revocation_seq"],
            "opened_at": utc(item["opened_at"]).isoformat(),
            "products": list(entry["products"]),
            "cancellation": (
                {"grant_seq": cancel["grant_seq"],
                 "cancelled_at": utc(cancel["cancelled_at"]).isoformat()}
                if cancel else None),
            "submissions": [_submission_dict(s) for s in entry["submissions"]],
            "reviews": [_review_dict(r) for r in
                        sorted(entry["reviews"].values(),
                               key=lambda r: r["version"])],
        }

    # ============================================================== 删除请求
    def create_deletion_request(self, key: str, req,
                                created_at: Optional[datetime] = None) -> dict:
        """幂等登记删除请求并在同一快照内评估、生成删除计划。

        * 请求范围归一化（排序去重）；空范围表示主体全部产物。实际删除
          范围 = 请求范围 ∪ 全部传递下游产物（删除一个产物必须连带删除
          由它派生的一切，且下游先删）；
        * 目标范围仍有活动许可（范围上游血缘中当前仍有效的回执）或未结
          处置（范围血缘内回执的处置项未了结）时，登记 blocked 请求并
          保存可定位的阻断原因；
        * 否则按依赖反向拓扑生成“下游先删、同层稳定排序”的删除批次，
          并记录登记时点的主体事件序号 basis_seq；
        * 请求与计划只追加、不可变；同键同内容重放原结果，异内容 409。
          查询时按当前事件重放与处置台账状态重新派生结论并与历史结论比较，
          结论变化（含处置结案）才标记 stale。本方法不修改任何回执，也不
          真实执行删除。
        """
        if not key:
            raise unprocessable("缺少 Idempotency-Key 头")
        created_at = utc(created_at or now_utc())
        requested_at = utc(req.requested_at)
        requested = sorted(set(req.product_ids))
        fp = fingerprint({
            "subject_id": req.subject_id,
            "product_ids": requested,
            "requested_at": requested_at.isoformat()})

        existing = self.repo.get_deletion_request_by_key(key)
        if existing is not None:
            if existing["request_fingerprint"] != fp:
                raise conflict("Idempotency-Key 已用于不同的请求内容")
            return self._deletion_request_result(existing, replayed=True)

        products, _, _, _, _ = self._load_product_graph(req.subject_id)
        unknown = [pid for pid in requested if pid not in products]
        if unknown:
            raise unprocessable("未知产物: " + ", ".join(unknown))
        events = self._subject_events(req.subject_id)
        scope, blockers = self._deletion_evaluation(
            req.subject_id, products, requested, events)
        status = "blocked" if blockers else "planned"
        basis_seq = max((e.seq for e in events), default=0)
        row = self.repo.insert_deletion_request(
            key=key, subject_id=req.subject_id,
            product_ids_json=json.dumps(requested, ensure_ascii=False),
            scope_json=json.dumps(scope, ensure_ascii=False),
            requested_at=requested_at, status=status, basis_seq=basis_seq,
            fingerprint=fp, created_at=created_at)
        if blockers:
            for ord_, blocker in enumerate(blockers):
                self.repo.insert_deletion_blocker(
                    request_id=row["request_id"], ord_=ord_,
                    kind=blocker["kind"],
                    detail_json=json.dumps(blocker, ensure_ascii=False))
        else:
            for batch_no, pids in enumerate(
                    domain.deletion_batches(products, scope), start=1):
                for pid in pids:
                    self.repo.insert_deletion_batch(
                        request_id=row["request_id"], batch_no=batch_no,
                        product_id=pid)
        return self._deletion_request_result(row, replayed=False)

    def _deletion_evaluation(self, subject_id: str, products: dict,
                              requested: list[str],
                              events: list[domain.Event]) -> tuple[list[str],
                                                                  list[dict]]:
        """删除评估（登记与查询复用同一逻辑）：归一化范围 + 下游闭包 + 阻断。

        * 空请求范围表示主体全部产物（以当前全部已知产物为种子）；
        * 实际范围 = 种子 ∪ 沿当前血缘展开的全部传递下游；
        * 阻断原因（活动许可 / 未结处置）由当前事件重放与处置追加记录即时
          派生。
        """
        seeds = requested or sorted(products)
        scope = sorted(domain.downstream_closure(products, seeds))
        blockers = self._deletion_blockers(subject_id, products, scope, events)
        return scope, blockers

    def _deletion_blockers(self, subject_id: str, products: dict,
                           scope: list[str],
                           events: list[domain.Event]) -> list[dict]:
        """目标删除范围的阻断原因（可定位）：活动许可与未结处置。"""
        return self._blockers_from(
            scope, events, products=products,
            receipt_rows=self.repo.get_receipts_for_subject(subject_id),
            remediation_entries=self._remediation_state(subject_id).values())

    def _blockers_from(self, scope: list[str], events: list[domain.Event],
                       *, products: dict, receipt_rows: list[dict],
                       remediation_entries) -> list[dict]:
        """阻断派生（删除请求与合规证明共用，后者注入 as_of_seq 快照输入）。

        :param products: 快照时点的血缘图（合规证明只含 recorded_seq <=
            as_of_seq 的产物；删除请求为当前完整图）；
        :param receipt_rows: 快照时点（recorded_seq <= as_of_seq）已登记的
            回执；合规证明注入过滤后的集合，删除请求注入全部回执；
        :param remediation_entries: 快照时点已开立（撤销序号 <= as_of_seq）
            的处置项派生条目；删除请求注入全部条目。
        """
        if not scope:
            return []
        # 范围内每个产物 -> 其传递依赖的回执（反向索引，用于定位受影响产物）。
        receipt_products: dict[str, set[str]] = {}
        for pid in scope:
            for rkey in domain.transitive_receipts(products, pid):
                receipt_products.setdefault(rkey, set()).add(pid)
        receipt_rows = {r["idempotency_key"]: r for r in receipt_rows}
        blockers: list[dict] = []
        # 活动许可：回执当前重放仍有效 -> 当前命中的许可即为阻断原因。
        for rkey in sorted(receipt_products):
            row = receipt_rows.get(rkey)
            if row is None or row["decision"] != "allow":
                continue
            dec = domain.decide(
                events, subject_id=row["subject_id"],
                category=row["category"], purpose=row["purpose"],
                recipient=row["recipient"],
                use_at=utc(row["use_at"]).isoformat())
            if dec.outcome != "allow":
                continue
            blockers.append({
                "kind": "active_grant",
                "grant_id": dec.grant.grant_id,
                "grant_seq": dec.grant.seq,
                "category": row["category"],
                "purpose": row["purpose"],
                "recipient": row["recipient"],
                "receipt_key": rkey,
                "products": sorted(receipt_products[rkey]),
            })
        # 未结处置：范围血缘内回执的处置项尚未了结（open/submitted/rejected）。
        for entry in sorted(remediation_entries,
                            key=lambda e: e["item"]["item_id"]):
            rkey = entry["item"]["receipt_key"]
            if (entry["status"] in domain.REMEDIATION_UNRESOLVED
                    and rkey in receipt_products):
                blockers.append({
                    "kind": "open_remediation",
                    "item_id": entry["item"]["item_id"],
                    "receipt_key": rkey,
                    "recipient": entry["item"]["recipient"],
                    "status": entry["status"],
                    "products": sorted(receipt_products[rkey]),
                })
        return blockers

    def get_deletion_request(self, request_id: int) -> dict:
        """查询删除计划并即时重新评估结论是否仍然成立。

        复用登记回执（归一化范围）、下游闭包与处置派生逻辑，按当前事件
        重放与处置台账追加记录重新派生结论，与历史阻断 / 批次结论比较：

        * 结论一致（同样 blocked 且阻断原因身份相同，或同样 planned）->
          ``stale:false``——即使登记后追加过与结论无关的许可 / 撤销；
        * 结论变化（处置结案解除阻断、新许可 / 撤销改变阻断原因、planned
          变为 blocked 或反之）-> ``stale:true``，提示用**新的幂等键**重新
          提交以重新评估。

        过期判定即时计算；已登记的状态、批次与阻断原因只追加、从不改写。
        """
        row = self.repo.get_deletion_request(request_id)
        if row is None:
            raise not_found(f"删除请求 {request_id} 不存在")
        return self._deletion_request_result(row, replayed=None)

    def _current_deletion_conclusion(self, row: dict) -> tuple:
        """按当前状态重放删除评估，返回当前结论签名。

        复用登记回执中**已闭包展开的归一化范围**（scope：登记时的下游闭包，
        追加保存、不随后续新登记产物扩张），再用与登记完全相同的阻断派生
        逻辑在当前事件重放与处置台账追加记录上评估（活动许可重放 + 处置项
        状态机）。处置提交 / 复核不产生主体事件，但同样会改变这里的结论。
        """
        subject_id = row["subject_id"]
        products, _, _, _, _ = self._load_product_graph(subject_id)
        events = self._subject_events(subject_id)
        blockers = self._deletion_blockers(subject_id, products,
                                           list(row["scope"]), events)
        status = "blocked" if blockers else "planned"
        return domain.deletion_conclusion(status, blockers)

    def _deletion_request_result(self, row: dict,
                                 replayed: Optional[bool]) -> dict:
        request_id = row["request_id"]
        batches: dict[int, list[str]] = {}
        for b in self.repo.list_deletion_batches(request_id):
            batches.setdefault(b["batch_no"], []).append(b["product_id"])
        blockers = [bl["detail"]
                    for bl in self.repo.list_deletion_blockers(request_id)]
        events = self._subject_events(row["subject_id"])
        current_seq = max((e.seq for e in events), default=0)
        # 过期 = 历史结论与按当前状态重新派生的结论不一致。处置结案 / 新许可
        # / 新撤销改变结论时为 True；仅事件序号变化但结论不变时保持 False。
        historical = domain.deletion_conclusion(row["status"], blockers)
        current = self._current_deletion_conclusion(row)
        stale = historical != current
        result = {
            "request_id": request_id,
            "idempotency_key": row["idempotency_key"],
            "subject_id": row["subject_id"],
            "requested_at": utc(row["requested_at"]).isoformat(),
            "product_ids": list(row["product_ids"]),
            "scope": list(row["scope"]),
            "status": row["status"],
            "basis_seq": row["basis_seq"],
            "current_seq": current_seq,
            "stale": stale,
            "detail": (
                "登记时的删除结论已不再反映当前状态（许可 / 撤销重放或处置"
                "结案情况已变化）；历史计划保持不变，请使用新的幂等键重新"
                "提交删除请求以重新评估"
                if stale else None),
            "batches": [{"batch_no": no, "product_ids": pids}
                        for no, pids in sorted(batches.items())],
            "blockers": blockers,
        }
        if replayed is not None:
            result["idempotent_replay"] = replayed
        return result

    # ============================================================== 合规证明
    def create_attestation(self, key: str, req,
                           created_at: Optional[datetime] = None,
                           hmac_key: Optional[str] = None) -> dict:
        """幂等生成合规证明：在同一 REPEATABLE READ 快照内重放全部依据。

        路由在事务开始**之前**已获取主体咨询锁，故本方法看到的
        REPEATABLE READ 快照建立在同主体此前已提交的全部事件 / 台账
        追加之后：并发追加事件时，快照要么完整包含、要么完全不包含
        某次提交，证明内容与 as_of_seq 口径一致，绝不读到半提交状态。

        * 产品范围必须非空、全部为快照时点（recorded_seq <= as_of_seq）
          已登记的主体产物；as_of_seq 必须为已存在的全局事件序号；
        * 同键同内容重放原证明（返回保存的字节 / 摘要 / 签名，200），
          同键异内容 409；证明只追加，后续事件永不改写既有证明；
        * 声明按固定字段规范序列化，保存 SHA-256 摘要与本地密钥
          HMAC-SHA256 签名，返回可独立验签的字节。
        """
        if not key:
            raise unprocessable("缺少 Idempotency-Key 头")
        created_at = utc(created_at or now_utc())
        use_at = utc(req.use_at)
        requested = sorted(set(req.product_ids))
        as_of_seq = req.as_of_seq
        fp = fingerprint({
            "subject_id": req.subject_id,
            "product_ids": requested,
            "use_at": use_at.isoformat(),
            "as_of_seq": as_of_seq})

        existing = self.repo.get_attestation_by_key(key)
        if existing is not None:
            if existing["request_fingerprint"] != fp:
                raise conflict("Idempotency-Key 已用于不同的请求内容")
            return self._attestation_result(existing, replayed=True)

        # 越界 as_of_seq：序号是全局单调序号，不存在的“未来序号”拒绝。
        max_seq = self.repo.max_event_seq()
        if as_of_seq > max_seq:
            raise unprocessable(
                f"as_of_seq 越界：当前最大事件序号为 {max_seq}")

        all_products, _, products_rows, _, _ = self._load_product_graph(
            req.subject_id)
        unknown = [pid for pid in requested if pid not in all_products]
        if unknown:
            raise unprocessable("未知产物: " + ", ".join(unknown))
        recorded_seq_by_pid = {p["product_id"]: p["recorded_seq"]
                               for p in products_rows}
        future = [pid for pid in requested
                  if recorded_seq_by_pid[pid] > as_of_seq]
        if future:
            raise unprocessable(
                "as_of_seq 早于以下产物的登记序号（快照中尚不存在）: "
                + ", ".join(sorted(future)))

        # ---- 同一快照内重放：许可 / 撤销（截至 as_of_seq 的事件） ----
        events = self._subject_events(req.subject_id)  # 全部事件
        visible_events = [e for e in events if e.seq <= as_of_seq]
        # 生成时主体可见最大事件序号（as_of_seq 是全局序号上界，主体在该
        # 时点可能没有自己的事件）。
        basis_seq = max((e.seq for e in visible_events), default=0)

        # 快照时点已登记的回执（recorded_seq <= as_of_seq）。
        receipt_rows = [r for r in
                        self.repo.get_receipts_for_subject(req.subject_id)
                        if r["recorded_seq"] <= as_of_seq]
        receipts = {
            r["idempotency_key"]:
                self._receipt_state(r, events, None, as_of_seq)
            for r in receipt_rows}

        # 快照时点血缘图：仅含 as_of_seq 前登记的产物。
        horizon_pids = {pid for pid in all_products
                        if recorded_seq_by_pid[pid] <= as_of_seq}
        products = {pid: groups for pid, groups in all_products.items()
                    if pid in horizon_pids}
        evaluations = domain.evaluate_product_graph(products, receipts)

        # ---- 处置状态：快照时点已开立（撤销序号 <= as_of_seq）的处置项 ----
        entries = [e for e in self._remediation_state(req.subject_id).values()
                   if e["item"]["revocation_seq"] <= as_of_seq]
        entries.sort(key=lambda e: e["item"]["item_id"])
        entry_by_id = {e["item"]["item_id"]: e for e in entries}

        # ---- 逐产品声明：稳定标识 + 血缘回执依据 + 关联处置 ----
        product_entries = [
            self._attestation_product(pid, products, receipts, evaluations,
                                      entry_by_id)
            for pid in requested]

        # ---- 删除结论：快照血缘闭包 + 阻断依据 / 删除批次 ----
        scope = sorted(domain.downstream_closure(products, requested))
        blockers = self._blockers_from(
            scope, visible_events, products=products,
            receipt_rows=receipt_rows, remediation_entries=entries)
        deletion = {"scope": scope}
        if blockers:
            deletion["status"] = "blocked"
            deletion["blockers"] = blockers
            deletion["batches"] = []
        else:
            deletion["status"] = "planned"
            deletion["blockers"] = []
            deletion["batches"] = [
                {"batch_no": no, "product_ids": pids}
                for no, pids in enumerate(
                    domain.deletion_batches(products, scope), start=1)]

        claim = attestation_mod.build_claim(
            subject_id=req.subject_id, use_at=use_at.isoformat(),
            as_of_seq=as_of_seq, basis_seq=basis_seq,
            product_ids=requested,
            products={pid: entry for pid, entry
                      in zip(requested, product_entries)},
            deletion=deletion)
        claim_bytes = attestation_mod.canonical_bytes(claim)
        claim_digest = attestation_mod.digest(claim_bytes)
        claim_signature = attestation_mod.sign(
            claim_bytes, hmac_key if hmac_key is not None
            else config.ATTESTATION_HMAC_KEY)
        row = self.repo.insert_attestation(
            key=key, subject_id=req.subject_id, use_at=use_at,
            as_of_seq=as_of_seq, basis_seq=basis_seq,
            claim_bytes=claim_bytes,
            claim_json=claim_bytes.decode("utf-8"),
            claim_digest=claim_digest, claim_signature=claim_signature,
            fingerprint=fp, created_at=created_at)
        return self._attestation_result(row, replayed=False)

    def _attestation_product(self, pid: str, products: dict,
                             receipts: dict, evaluations: dict,
                             entry_by_id: dict) -> dict:
        """单个范围内产品的声明片段：血缘回执依据、状态、处置依据。"""
        node = evaluations[pid]
        receipt_keys = sorted(domain.transitive_receipts(products, pid))
        receipt_entries = []
        for rkey in receipt_keys:
            st = receipts[rkey]
            receipt_entries.append({
                "receipt_key": rkey,
                "currently_valid": st.valid,
                "invalidating_events": list(st.invalidating_seqs)})
        linked_items = sorted(
            iid for iid, e in entry_by_id.items()
            if e["item"]["receipt_key"] in receipt_keys)
        remediation_entries = []
        for iid in linked_items:
            item = entry_by_id[iid]["item"]
            remediation_entries.append({
                "item_id": iid,
                "receipt_key": item["receipt_key"],
                "recipient": item["recipient"],
                "status": entry_by_id[iid]["status"],
                "revocation_seq": item["revocation_seq"]})
        return {
            "status": "active" if node.active else "blocked",
            "invalidating_events": list(node.invalidating_seqs),
            "receipts": receipt_entries,
            "remediation_items": remediation_entries}

    def get_attestation(self, attestation_id: int) -> dict:
        """取回既有证明。

        直接返回登记时保存的声明字节 / 摘要 / 签名（只追加、不可变），
        不按当前事件重放：后续追加的许可 / 撤销 / 处置记录永不改写
        既有证明。
        """
        row = self.repo.get_attestation(attestation_id)
        if row is None:
            raise not_found(f"合规证明 {attestation_id} 不存在")
        return self._attestation_result(row, replayed=None)

    def _attestation_result(self, row: dict,
                            replayed: Optional[bool]) -> dict:
        # 声明始终以保存的规范字节为准解析（不读取 JSONB 列，避免
        # PostgreSQL 重序列化改变键序 / 空白导致验签失败）。
        claim = json.loads(bytes(row["claim_bytes"]).decode("utf-8"))
        result = {
            "attestation_id": row["attestation_id"],
            "idempotency_key": row["idempotency_key"],
            "subject_id": row["subject_id"],
            "use_at": utc(row["use_at"]).isoformat(),
            "as_of_seq": row["as_of_seq"],
            "basis_seq": row["basis_seq"],
            "claim": claim,
            "claim_canonical": bytes(row["claim_bytes"]).decode("utf-8"),
            "digest": row["claim_digest"],
            "signature": row["claim_signature"],
            "digest_alg": attestation_mod.DIGEST_ALG,
            "signature_alg": row["signature_alg"],
            "created_at": utc(row["created_at"]).isoformat()}
        if replayed is not None:
            result["idempotent_replay"] = replayed
        return result

    # ============================================================== 合规差异报告
    def compliance_diff(self, req) -> dict:
        """合规状态双时点差异报告（只读；不写任何业务表）。

        路由在同一个 REPEATABLE READ 只读快照中调用本方法：分别按两条全局
        事件序号上界（``from_seq < to_seq``）重放许可 / 撤销、决策回执、
        血缘产品、处置项与删除结论，返回每个产品及其传递回执的
        added / removed / changed / unchanged 分类、两侧稳定依据与状态翻转
        原因。

        * 两侧口径完全由事件序号界定：事件本身、回执（recorded_seq）、
          产物（recorded_seq）、处置项开立（revocation_seq）与取消
          （grant_seq）均按上界过滤——后续追加事件永不改变同一
          (from_seq, to_seq) 的报告；处置证据提交 / 复核不携带事件序号
          （不是事件），按请求快照原样计入两侧处置状态；
        * from 侧尚未登记的产品标为 absent（分类 added）；未知产品或超过
          当前最大事件序号的未来序号一律 422；
        * 结果按产品 ID、回执键与事件序号稳定排序。
        """
        requested = sorted(set(req.product_ids))
        use_at = utc(req.use_at)
        from_seq, to_seq = req.from_seq, req.to_seq
        if from_seq >= to_seq:
            raise unprocessable("序号上界要求 from_seq < to_seq")
        # 未来序号：序号是全局单调序号，超过当前最大序号的 to_seq 在任何
        # 主体的快照中都无意义，必须拒绝（from_seq < to_seq 随之合法）。
        max_seq = self.repo.max_event_seq()
        if to_seq > max_seq:
            raise unprocessable(
                f"to_seq 越界：当前最大事件序号为 {max_seq}")

        all_products, meta, products_rows, _, _ = self._load_product_graph(
            req.subject_id)
        unknown = [pid for pid in requested if pid not in all_products]
        if unknown:
            raise unprocessable("未知产物: " + ", ".join(unknown))
        recorded_seq_by_pid = {p["product_id"]: p["recorded_seq"]
                               for p in products_rows}
        future = [pid for pid in requested
                  if recorded_seq_by_pid[pid] > to_seq]
        if future:
            raise unprocessable(
                "to_seq 早于以下产物的登记序号（两侧快照中均不存在）: "
                + ", ".join(sorted(future)))

        events = self._subject_events(req.subject_id)
        events_by_seq = {e.seq: e for e in events}
        receipt_rows = {
            r["idempotency_key"]: r
            for r in self.repo.get_receipts_for_subject(req.subject_id)}

        from_side = self._diff_side(req.subject_id, from_seq, events,
                                    receipt_rows, all_products,
                                    recorded_seq_by_pid, requested)
        to_side = self._diff_side(req.subject_id, to_seq, events,
                                  receipt_rows, all_products,
                                  recorded_seq_by_pid, requested)

        # ---- 逐产品差异：传递回执在完整血缘图上取（产品于 to 侧必存在） ----
        product_entries = []
        receipt_class_union: dict[str, str] = {}
        for pid in requested:
            entry, receipt_classes = self._diff_product(
                pid, meta[pid], all_products, receipt_rows,
                from_side, to_side, events_by_seq)
            product_entries.append(entry)
            receipt_class_union.update(receipt_classes)

        # ---- 处置项差异：范围为全部请求产品的传递回执并集 ----
        scope_receipts: set[str] = set()
        for pid in requested:
            scope_receipts |= domain.transitive_receipts(all_products, pid)
        remediation_entries = self._diff_remediation(
            from_side, to_side, scope_receipts)

        deletion = self._diff_deletion(from_side["deletion"],
                                       to_side["deletion"])

        return {
            "subject_id": req.subject_id,
            "use_at": use_at.isoformat(),
            "from_seq": from_seq,
            "to_seq": to_seq,
            "from_basis_seq": from_side["basis_seq"],
            "to_basis_seq": to_side["basis_seq"],
            "summary": {
                "products": _class_counts(
                    p["classification"] for p in product_entries),
                "receipts": _class_counts(receipt_class_union.values()),
                "remediation_items": _class_counts(
                    e["classification"] for e in remediation_entries),
                "deletion": deletion["classification"],
            },
            "products": product_entries,
            "remediation_items": remediation_entries,
            "deletion": deletion,
        }

    def _diff_side(self, subject_id: str, bound: int,
                   events: list[domain.Event], receipt_rows: dict,
                   all_products: dict, recorded_seq_by_pid: dict,
                   requested: list[str]) -> dict:
        """在单一事件序号上界一侧重放全部依据（同一快照内被调用两次）。

        回执 / 产物按 recorded_seq、处置项按 revocation_seq（开立）与
        grant_seq（取消）过滤到上界；许可 / 撤销重放只取 seq <= bound 的
        事件。返回该侧的回执快照、产物评估、处置条目与删除结论。
        """
        visible_events = [e for e in events if e.seq <= bound]
        basis_seq = max((e.seq for e in visible_events), default=0)
        side_rows = [r for r in receipt_rows.values()
                     if r["recorded_seq"] <= bound]
        receipt_snaps = {
            r["idempotency_key"]: self._diff_receipt_snapshot(r, events, bound)
            for r in side_rows}
        receipt_states = {
            key: domain.ReceiptState(key, snap["currently_valid"],
                                     tuple(snap["invalidating_events"]),
                                     snap["detail"])
            for key, snap in receipt_snaps.items()}
        present_pids = {pid for pid in all_products
                        if recorded_seq_by_pid[pid] <= bound}
        graph = {pid: groups for pid, groups in all_products.items()
                 if pid in present_pids}
        evaluations = domain.evaluate_product_graph(graph, receipt_states)
        remediation = {
            e["item"]["item_id"]: e
            for e in self._remediation_state(
                subject_id, cancel_upto_grant_seq=bound).values()
            if e["item"]["revocation_seq"] <= bound}
        seeds = [pid for pid in requested if pid in present_pids]
        scope = sorted(domain.downstream_closure(graph, seeds))
        blockers = self._blockers_from(
            scope, visible_events, products=graph, receipt_rows=side_rows,
            remediation_entries=remediation.values())
        deletion = {
            "scope": scope,
            "status": "blocked" if blockers else "planned",
            "blockers": blockers,
            "batches": [] if blockers else [
                {"batch_no": no, "product_ids": pids}
                for no, pids in enumerate(
                    domain.deletion_batches(graph, scope), start=1)],
        }
        return {"bound": bound, "basis_seq": basis_seq,
                "receipts": receipt_snaps, "evaluations": evaluations,
                "present_pids": present_pids, "remediation": remediation,
                "deletion": deletion}

    def _diff_receipt_snapshot(self, row: dict, events: list[domain.Event],
                               bound: int) -> dict:
        """回执在序号上界一侧的重放快照（含命中许可这一稳定依据）。"""
        if row["decision"] == "deny":
            # 登记时即被拒绝：永久无效，失效事件集合为空。
            return {"currently_valid": False, "invalidating_events": [],
                    "hit_grant": None,
                    "detail": f"registered deny ({row['basis_reason']})"}
        dec = domain.decide(
            events,
            subject_id=row["subject_id"], category=row["category"],
            purpose=row["purpose"], recipient=row["recipient"],
            use_at=utc(row["use_at"]).isoformat(), as_of_seq=bound)
        hit = ({"grant_id": dec.grant.grant_id, "grant_seq": dec.grant.seq}
               if dec.grant is not None else None)
        if dec.outcome == "allow":
            return {"currently_valid": True, "invalidating_events": [],
                    "hit_grant": hit, "detail": ""}
        return {"currently_valid": False,
                "invalidating_events":
                    [dec.revocation.seq] if dec.reason == "revoked" else [],
                "hit_grant": hit, "detail": dec.reason}

    def _diff_product(self, pid: str, meta_row: dict, all_products: dict,
                      receipt_rows: dict, from_side: dict, to_side: dict,
                      events_by_seq: dict) -> tuple[dict, dict]:
        """单个产品的双时点差异（含其传递回执），返回 (产品条目, 回执分类)。"""
        from_present = pid in from_side["present_pids"]
        to_present = pid in to_side["present_pids"]
        from_view = self._product_view(from_side, pid, from_present)
        to_view = self._product_view(to_side, pid, to_present)
        classification = domain.classify_change(
            from_present, to_present,
            _product_state_key(from_view), _product_state_key(to_view))

        # 传递回执：产品的血缘登记后不可变，任一侧存在的闭包相同。
        receipt_entries = []
        receipt_classes: dict[str, str] = {}
        for rkey in sorted(domain.transitive_receipts(all_products, pid)):
            entry = self._diff_receipt(rkey, receipt_rows[rkey],
                                       from_side, to_side, events_by_seq)
            receipt_entries.append(entry)
            receipt_classes[rkey] = entry["classification"]

        reasons: list[dict] = []
        if classification == "added":
            reasons.append({"kind": "registered",
                            "recorded_seq": meta_row["recorded_seq"],
                            "task_key": meta_row["task_key"]})
        elif classification == "changed":
            if from_view["status"] != to_view["status"]:
                reasons.append({
                    "kind": "status_flip",
                    "from_status": from_view["status"],
                    "to_status": to_view["status"],
                    "invalidating_events": to_view["invalidating_events"],
                    "causing_receipts": sorted(
                        k for k, c in receipt_classes.items()
                        if c != "unchanged")})
            else:
                reasons.append({
                    "kind": "invalidating_events_changed",
                    "from_invalidating_events":
                        from_view["invalidating_events"],
                    "to_invalidating_events": to_view["invalidating_events"]})
        return ({
            "product_id": pid,
            "classification": classification,
            "recorded_seq": meta_row["recorded_seq"],
            "task_key": meta_row["task_key"],
            "from": from_view,
            "to": to_view,
            "flip_reasons": reasons,
            "receipts": receipt_entries,
        }, receipt_classes)

    @staticmethod
    def _product_view(side: dict, pid: str, present: bool) -> dict:
        if not present:
            return {"presence": "absent"}
        node = side["evaluations"][pid]
        return {"presence": "present",
                "status": "active" if node.active else "blocked",
                "invalidating_events": list(node.invalidating_seqs)}

    def _diff_receipt(self, rkey: str, row: dict, from_side: dict,
                      to_side: dict, events_by_seq: dict) -> dict:
        """单条传递回执的双时点差异：分类、两侧重放状态与翻转原因。"""
        from_snap = from_side["receipts"].get(rkey)
        to_snap = to_side["receipts"].get(rkey)
        from_view = self._receipt_view(from_snap)
        to_view = self._receipt_view(to_snap)
        classification = domain.classify_change(
            from_snap is not None, to_snap is not None,
            _receipt_state_key(from_snap), _receipt_state_key(to_snap))

        reasons: list[dict] = []
        if classification == "added":
            reasons.append({"kind": "registered",
                            "recorded_seq": row["recorded_seq"]})
        elif classification == "changed":
            from_inv = set(from_snap["invalidating_events"])
            to_inv = set(to_snap["invalidating_events"])
            for seq in sorted(to_inv - from_inv):
                ev = events_by_seq[seq]
                reasons.append({
                    "kind": "revoked", "revocation_seq": seq,
                    "grant_id": ev.revoke_grant,
                    "business_effective_at": ev.business_effective_at})
            if from_snap["hit_grant"] != to_snap["hit_grant"]:
                # 命中许可变化：新许可恢复有效（invalid -> valid）或同四元组
                # 的更新许可取代旧命中（两侧有效性可能不变）。
                reasons.append({"kind": "hit_grant_changed",
                                "from_grant": from_snap["hit_grant"],
                                "to_grant": to_snap["hit_grant"]})
        return {
            "receipt_key": rkey,
            "classification": classification,
            "decision": row["decision"],
            "basis": {"grant_id": row["basis_grant_id"],
                      "seq": row["basis_seq"],
                      "reason": row["basis_reason"]},
            "use_at": utc(row["use_at"]).isoformat(),
            "recorded_seq": row["recorded_seq"],
            "from": from_view,
            "to": to_view,
            "flip_reasons": reasons,
        }

    @staticmethod
    def _receipt_view(snap: Optional[dict]) -> dict:
        if snap is None:
            return {"presence": "absent"}
        return {"presence": "present",
                "currently_valid": snap["currently_valid"],
                "invalidating_events": list(snap["invalidating_events"]),
                "hit_grant": snap["hit_grant"]}

    def _diff_remediation(self, from_side: dict, to_side: dict,
                          scope_receipts: set[str]) -> list[dict]:
        """范围内回执的处置项双时点差异（按 item_id 稳定排序）。

        两侧状态差异只能来自序号可定位的记录：开立（revocation_seq 落入
        (from, to] -> added）与取消（grant_seq 落入 (from, to] -> changed）；
        提交 / 复核不携带事件序号，两侧一致。
        """
        entries: list[dict] = []
        item_ids = sorted(set(from_side["remediation"])
                          | set(to_side["remediation"]))
        for iid in item_ids:
            from_entry = from_side["remediation"].get(iid)
            to_entry = to_side["remediation"].get(iid)
            item = (to_entry or from_entry)["item"]
            if item["receipt_key"] not in scope_receipts:
                continue
            classification = domain.classify_change(
                from_entry is not None, to_entry is not None,
                from_entry["status"] if from_entry else None,
                to_entry["status"] if to_entry else None)
            reasons: list[dict] = []
            if classification == "added":
                reasons.append({"kind": "opened",
                                "revocation_seq": item["revocation_seq"]})
            elif classification == "changed":
                cancel = to_entry["cancellation"]
                if cancel is not None:
                    reasons.append({"kind": "cancelled",
                                    "grant_seq": cancel["grant_seq"]})
                else:  # 防御性：序号可定位记录之外的状态差异。
                    reasons.append({"kind": "status_flip",
                                    "from_status": from_entry["status"],
                                    "to_status": to_entry["status"]})
            entries.append({
                "item_id": iid,
                "receipt_key": item["receipt_key"],
                "recipient": item["recipient"],
                "revocation_seq": item["revocation_seq"],
                "products": sorted((to_entry or from_entry)["products"]),
                "classification": classification,
                "from": _remediation_view(from_entry),
                "to": _remediation_view(to_entry),
                "flip_reasons": reasons,
            })
        return entries

    def _diff_deletion(self, from_del: dict, to_del: dict) -> dict:
        """删除结论的双时点差异：状态、阻断原因身份、范围与批次比较。"""
        from_ids = {domain.deletion_blocker_identity(b): b
                    for b in from_del["blockers"]}
        to_ids = {domain.deletion_blocker_identity(b): b
                  for b in to_del["blockers"]}
        changed = (from_del["status"] != to_del["status"]
                   or set(from_ids) != set(to_ids)
                   or from_del["scope"] != to_del["scope"]
                   or from_del["batches"] != to_del["batches"])
        reasons: list[dict] = []
        if from_del["status"] != to_del["status"]:
            reasons.append({"kind": "status_flip",
                            "from_status": from_del["status"],
                            "to_status": to_del["status"]})
        for ident in sorted(set(to_ids) - set(from_ids)):
            reasons.append({"kind": "blocker_added",
                            "blocker": to_ids[ident]})
        for ident in sorted(set(from_ids) - set(to_ids)):
            reasons.append({"kind": "blocker_removed",
                            "blocker": from_ids[ident]})
        from_scope, to_scope = set(from_del["scope"]), set(to_del["scope"])
        if from_scope != to_scope:
            reasons.append({
                "kind": "scope_changed",
                "added": sorted(to_scope - from_scope),
                "removed": sorted(from_scope - to_scope)})
        return {"classification": "changed" if changed else "unchanged",
                "from": from_del, "to": to_del, "flip_reasons": reasons}


def _product_state_key(view: dict):
    """产品差异比较键：派生状态 + 失效事件集合。"""
    if view["presence"] == "absent":
        return None
    return (view["status"], tuple(view["invalidating_events"]))


def _receipt_state_key(snap: Optional[dict]):
    """回执差异比较键：有效性 + 失效事件集合 + 当前命中许可身份。"""
    if snap is None:
        return None
    hit = snap["hit_grant"]
    return (snap["currently_valid"], tuple(snap["invalidating_events"]),
            hit["grant_seq"] if hit else None)


def _remediation_view(entry: Optional[dict]) -> dict:
    if entry is None:
        return {"presence": "absent"}
    return {"presence": "present", "status": entry["status"]}


def _class_counts(classifications) -> dict:
    """分类计数（added / removed / changed / unchanged）。"""
    counts = {c: 0 for c in domain.DIFF_CLASSIFICATIONS}
    for c in classifications:
        counts[c] += 1
    return counts


def _submission_dict(sub: dict) -> dict:
    return {
        "submission_id": sub["submission_id"],
        "item_id": sub["item_id"],
        "version": sub["version"],
        "idempotency_key": sub["idempotency_key"],
        "cease_declaration": sub["cease_declaration"],
        "evidence": sub["evidence"],
        "submitted_by": sub["submitted_by"],
        "submitted_at": utc(sub["submitted_at"]).isoformat(),
    }


def _review_dict(r: dict) -> dict:
    return {
        "review_id": r["review_id"],
        "item_id": r["item_id"],
        "version": r["version"],
        "action": r["action"],
        "comment": r["comment"],
        "reviewed_at": utc(r["reviewed_at"]).isoformat(),
    }
