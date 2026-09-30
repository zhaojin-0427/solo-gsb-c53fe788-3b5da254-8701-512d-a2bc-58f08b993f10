"""纯领域逻辑：合规状态双时点差异报告。

在固定的业务使用时点 ``use_at`` 下，对同一主体分别按两条**全局事件
录入序号上界** ``from_seq`` / ``to_seq`` 重放全部依据（许可、撤销、
决策回执、血缘产品、处置项、删除结论），比较两个快照的派生状态。

快照视图（由服务层在**同一个 REPEATABLE READ 事务**中各做一次过滤重放
得到，本模块不触碰数据库）的结构约定见 :func:`build_compliance_diff`。

分类
----
* ``added``     —— 该实体只在 to 侧存在：产品在 from_seq 之后才登记
                  （产品级标记为 ``absent``，见下），或回执 / 处置项 /
                  阻断原因在两条上界之间进入视野；
* ``removed``   —— 该实体只在 from 侧存在（只追加模型中产品 / 回执不会
                  消失；此分类用于处置项取消与删除阻断原因消失）；
* ``changed``   —— 两侧都存在但稳定签名不同（状态翻转或依据切换）；
* ``unchanged`` —— 两侧都存在且稳定签名一致。

**from 侧尚未登记的产品**（``recorded_seq > from_seq`` 且
``recorded_seq <= to_seq``）不套用 added，而是单独标记 ``absent``：
其产品级 ``from_*`` 依据为 null；血缘中的传递回执在 from 侧快照同样
尚不存在，一并以 ``absent`` 分类返回。

“稳定依据”只含确定性派生标识（状态、失效事件序号、命中许可 / 撤销
序号、处置项状态与开立 / 取消序号、阻断原因身份），不含服务端生成
时间等可变内容，故同参数报告逐次一致、后续事件不改变报告。
"""
from __future__ import annotations

from typing import Iterable, Optional

# 差异分类（added/removed/changed/unchanged）与 from 侧缺席标记。
DIFF_ADDED = "added"
DIFF_REMOVED = "removed"
DIFF_CHANGED = "changed"
DIFF_UNCHANGED = "unchanged"
DIFF_ABSENT = "absent"


# ============================================================ 稳定签名
def receipt_signature(view: Optional[dict]) -> Optional[tuple]:
    """回执侧依据的稳定签名：None 表示该侧快照中回执尚不存在。

    纳入签名的都是确定性派生字段：重放结论、命中许可 / 撤销序号与
    失效事件序号集合。登记即 deny 的回执永久无效且失效事件为空。
    """
    if view is None:
        return None
    return (
        view["decision"],
        view["currently_valid"],
        view["basis_kind"],
        view.get("basis_seq"),
        view.get("grant_id"),
        tuple(sorted(view.get("invalidating_events", ()))),
    )


def product_signature(view: Optional[dict]) -> Optional[tuple]:
    """产品侧依据的稳定签名：状态 + 失效事件序号集合。"""
    if view is None:
        return None
    return (
        view["status"],
        tuple(sorted(view.get("invalidating_events", ()))),
    )


def remediation_item_signature(view: Optional[dict]) -> Optional[tuple]:
    """处置项侧依据的稳定签名。

    处置项一旦开立，其开立依据（撤销序号）不变；状态机派生的当前状态
    与取消依据许可序号进入签名——获批 / 取消等台账流转因此可被定位。
    """
    if view is None:
        return None
    return (
        view["status"],
        view["revocation_seq"],
        view.get("cancelled_by_grant_seq"),
    )


# ============================================================ 通用分类
def classify_entity(from_view: Optional[dict], to_view: Optional[dict],
                    signature) -> str:
    """比较两侧视图给出 added/removed/changed/unchanged 分类。

    :param signature: ``view -> 可比较元组`` 的稳定签名函数；
                      None 视图表示实体在该侧快照中不存在。
    """
    if from_view is None and to_view is None:
        raise ValueError("两侧视图均为 None，无可分类实体")
    if from_view is None:
        return DIFF_ADDED
    if to_view is None:
        return DIFF_REMOVED
    return (DIFF_UNCHANGED
            if signature(from_view) == signature(to_view)
            else DIFF_CHANGED)


def diff_keyed(from_map: dict, to_map: dict, signature) -> dict[str, str]:
    """对以稳定键（产品 ID / 回执键 / 处置项 ID）索引的两侧视图集合分类。

    返回 键 -> 分类；只出现在一侧的键分别记 added / removed。
    """
    out: dict[str, str] = {}
    for key in set(from_map) | set(to_map):
        out[key] = classify_entity(from_map.get(key), to_map.get(key),
                                   signature)
    return out


# ============================================================ 翻转原因
def receipt_flip_reasons(from_view: Optional[dict],
                         to_view: Optional[dict]) -> list[dict]:
    """回执两侧依据差异的可定位原因（按原因代码稳定排序由调用方保证）。

    每条原因引用具体事件序号（许可 / 撤销）或登记态，足以解释
    valid -> invalid（追溯撤销命中）、invalid -> valid（新许可恢复）、
    命中许可切换等翻转。
    """
    if from_view is not None and to_view is not None:
        if receipt_signature(from_view) == receipt_signature(to_view):
            return []
    reasons: list[dict] = []
    fv, tv = from_view, to_view

    # 进入视野（产品 / 回执在 from 侧之后才登记）。
    if fv is None and tv is not None:
        reasons.append({
            "code": "entered_scope",
            "message": "回执在 from_seq 之后才登记，from 侧快照中不存在",
            "recorded_seq": tv.get("recorded_seq")})
        return reasons
    if fv is not None and tv is None:
        reasons.append({
            "code": "left_scope",
            "message": "回执在 to 侧快照中不存在",
            "recorded_seq": fv.get("recorded_seq")})
        return reasons

    # 追溯撤销命中：有效 -> 失效。
    if fv["currently_valid"] and not tv["currently_valid"]:
        if tv["basis_kind"] == "revocation":
            reasons.append({
                "code": "revocation_took_effect",
                "message": ("to 侧上界新纳入的追溯撤销在 use_at 业务生效，"
                            "回执由有效转为失效"),
                "revocation_seq": tv.get("basis_seq"),
                "grant_id": tv.get("grant_id")})
        else:
            reasons.append({
                "code": "grant_no_longer_in_force",
                "message": "命中许可在 to 侧重放中不再成立",
                "grant_id": fv.get("grant_id")})

    # 新许可恢复：失效 -> 有效（许可序号是稳定依据）。
    if not fv["currently_valid"] and tv["currently_valid"]:
        reasons.append({
            "code": "grant_restored",
            "message": ("to 侧上界新纳入的许可覆盖该使用，回执由失效恢复"
                        "有效"),
            "grant_id": tv.get("grant_id"),
            "grant_seq": tv.get("basis_seq")})

    # 命中许可 / 撤销依据切换（状态可能不变）。
    if (fv["currently_valid"] == tv["currently_valid"]
            and (fv.get("basis_seq") != tv.get("basis_seq")
                 or fv.get("grant_id") != tv.get("grant_id")
                 or fv["basis_kind"] != tv["basis_kind"])):
        reasons.append({
            "code": "basis_switched",
            "message": "重放命中的稳定依据发生切换",
            "from_basis": {"kind": fv["basis_kind"],
                           "seq": fv.get("basis_seq"),
                           "grant_id": fv.get("grant_id")},
            "to_basis": {"kind": tv["basis_kind"],
                         "seq": tv.get("basis_seq"),
                         "grant_id": tv.get("grant_id")}})

    # 失效事件集合变化（追加撤销 / 恢复都会体现；去重后按序号排序）。
    added_seqs = sorted(
        set(tv.get("invalidating_events", ()))
        - set(fv.get("invalidating_events", ())))
    removed_seqs = sorted(
        set(fv.get("invalidating_events", ()))
        - set(tv.get("invalidating_events", ())))
    if added_seqs:
        reasons.append({"code": "invalidating_events_added",
                        "message": "to 侧新增命中的失效（撤销）事件",
                        "event_seqs": added_seqs})
    if removed_seqs:
        reasons.append({"code": "invalidating_events_removed",
                        "message": "to 侧失效（撤销）事件不再命中",
                        "event_seqs": removed_seqs})
    return reasons


def product_flip_reasons(from_view: Optional[dict],
                         to_view: Optional[dict],
                         receipt_diffs: Iterable[dict]) -> list[dict]:
    """产品级状态翻转原因：自身缺席 + 沿血缘的回执翻转定位。

    血缘图为只追加 DAG，已登记产品的依据结构不会变化，故产品翻转必由
    血缘传递回执（叶子）的重放翻转驱动——这里汇总该产品传递回执中
    changed/added/removed/absent 的条目及产品失效事件集合差异，使
    “血缘 / 处置变化可定位”。
    """
    reasons: list[dict] = []
    if from_view is None and to_view is not None:
        reasons.append({
            "code": "product_recorded_between",
            "message": ("产品在 from_seq 之后、to_seq 之前登记，"
                        "from 侧标记为 absent"),
            "recorded_seq": to_view.get("recorded_seq")})
        return reasons
    if from_view is None or to_view is None:
        return reasons

    f_active = from_view["status"] == "active"
    t_active = to_view["status"] == "active"
    flipped = [d for d in receipt_diffs
               if d["classification"] in
               (DIFF_CHANGED, DIFF_ADDED, DIFF_REMOVED, DIFF_ABSENT)]
    if f_active and not t_active:
        reasons.append({
            "code": "lineage_receipts_invalidated",
            "message": "血缘传递回执在 to 侧重放中失效，产品由 active 转为 blocked",
            "receipt_keys": sorted(
                d["receipt_key"] for d in flipped
                if _to_invalid(d))})
    if not f_active and t_active:
        reasons.append({
            "code": "lineage_receipts_restored",
            "message": "血缘传递回执在 to 侧重放中恢复，产品由 blocked 转为 active",
            "receipt_keys": sorted(
                d["receipt_key"] for d in flipped
                if _to_valid(d))})
    added_seqs = sorted(
        set(to_view.get("invalidating_events", ()))
        - set(from_view.get("invalidating_events", ())))
    removed_seqs = sorted(
        set(from_view.get("invalidating_events", ()))
        - set(to_view.get("invalidating_events", ())))
    if added_seqs:
        reasons.append({"code": "invalidating_events_added",
                        "message": "to 侧产品失效事件集合新增",
                        "event_seqs": added_seqs})
    if removed_seqs:
        reasons.append({"code": "invalidating_events_removed",
                        "message": "to 侧产品失效事件集合移除",
                        "event_seqs": removed_seqs})
    return reasons


def _to_invalid(receipt_diff: dict) -> bool:
    tv = receipt_diff.get("to")
    return tv is not None and not tv.get("currently_valid")


def _to_valid(receipt_diff: dict) -> bool:
    tv = receipt_diff.get("to")
    return tv is not None and bool(tv.get("currently_valid"))


def remediation_item_flip_reasons(from_view: Optional[dict],
                                  to_view: Optional[dict]) -> list[dict]:
    """处置项差异原因：开立（新增）、取消、状态流转（可定位到状态身份）。"""
    if from_view is not None and to_view is not None:
        if remediation_item_signature(from_view) == \
                remediation_item_signature(to_view):
            return []
    reasons: list[dict] = []
    if from_view is None and to_view is not None:
        reasons.append({
            "code": "item_opened",
            "message": "to 侧上界内撤销新使回执失效，处置项开立",
            "revocation_seq": to_view["revocation_seq"]})
        return reasons
    if from_view is not None and to_view is None:
        # 只追加模型中处置项不会消失；保留防御性分支（分类为 removed）。
        reasons.append({
            "code": "item_no_longer_present",
            "message": "处置项在 to 侧快照中不存在",
            "revocation_seq": from_view["revocation_seq"]})
        return reasons
    if (from_view.get("cancelled_by_grant_seq") is None
            and to_view.get("cancelled_by_grant_seq") is not None):
        reasons.append({
            "code": "item_cancelled",
            "message": "新许可使回执恢复有效，未结处置项被取消",
            "grant_seq": to_view.get("cancelled_by_grant_seq")})
    if from_view["status"] != to_view["status"]:
        reasons.append({
            "code": "remediation_status_changed",
            "message": "处置项台账状态流转",
            "from_status": from_view["status"],
            "to_status": to_view["status"]})
    return reasons


# ============================================================ 删除结论
def blocker_identity(blocker: dict) -> tuple:
    """删除阻断原因的稳定身份（与 domain.deletion_blocker_identity 同口径）。"""
    if blocker["kind"] == "active_grant":
        return ("active_grant", blocker["receipt_key"],
                blocker.get("grant_id"), blocker.get("grant_seq"))
    return ("open_remediation", blocker["item_id"])


def diff_blockers(from_blockers: Iterable[dict],
                  to_blockers: Iterable[dict]) -> list[dict]:
    """按身份比较两侧阻断原因，逐条给出 added/removed/changed/unchanged。

    阻断原因身份（:func:`blocker_identity`）已吸收同一未结处置项在
    open/submitted/rejected 间的流转与 active_grant 命中许可切换：
    身份相同即 unchanged（其余明细随侧依据返回），身份消失即 removed，
    新身份即 added。结果按身份稳定排序。
    """
    f_map = {blocker_identity(b): b for b in from_blockers}
    t_map = {blocker_identity(b): b for b in to_blockers}
    out: list[dict] = []
    for ident in sorted(set(f_map) | set(t_map)):
        f, t = f_map.get(ident), t_map.get(ident)
        if f is None:
            classification = DIFF_ADDED
        elif t is None:
            classification = DIFF_REMOVED
        else:
            classification = DIFF_UNCHANGED  # 身份相同即同一阻断原因
        out.append({"identity": list(ident),
                    "classification": classification,
                    "from": f, "to": t})
    return out


def deletion_status_changed(from_status: str, to_status: str) -> bool:
    return from_status != to_status
