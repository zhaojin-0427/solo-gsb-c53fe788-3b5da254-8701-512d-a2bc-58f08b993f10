"""纯领域逻辑：事件重放决策与血缘阻断传播。

本模块不依赖 psycopg / FastAPI，仅使用标准库，便于离线单元测试。

时间语义（双时点确定性重放）
---------------------------
每条事件有两个时间：

* ``recorded_at`` —— 录入时间（系统知道该事件的时间，对应 ``as_of``）；
* 许可的 ``[valid_from, valid_to)`` 与撤销的 ``business_effective_at``
  —— 业务生效时间（对应 ``use_at``）。

决策 ``decide(use_at, as_of)`` 只看到 ``recorded_at <= as_of`` 的事件，
再判断其业务效力在 ``use_at`` 是否成立。后补录的撤销（recorded_at 晚于
既有决策）不改变历史回执本身，而是让“当前重放”判定该回执失效并沿血缘传播。

确定性规则
~~~~~~~~~~
* 同一类别 / 目的 / 接收方且 ``use_at`` 落在半开有效区间内的许可中，
  取录入序号 ``seq`` 最大者（最新登记的许可）；
* 该许可若存在撤销且 ``business_effective_at <= use_at``，
  撤销在业务上生效，取其中 seq 最小者（最早登记的生效撤销）作为命中依据；
* 其余情况默认拒绝（no_grant）。

失效事件集合
~~~~~~~~~~~~
失效事件只可能是撤销事件。一个失效依据组的失效事件集合 = 组内所有失效
输入的失效事件集合之并。解释排序：先按失效事件数最少，再按事件 ID
（seq）字典序。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

# 业务上的“无限早”：许可未指定 valid_from 时使用。
NEG_INFINITY = "0001-01-01T00:00:00+00:00"

DENY_REASONS = ("no_grant", "revoked")


@dataclass(frozen=True)
class Event:
    seq: int
    subject_id: str
    event_type: str  # 'grant' | 'revocation'
    grant_id: str
    category: Optional[str] = None
    purpose: Optional[str] = None
    recipient: Optional[str] = None
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    revoke_grant: Optional[str] = None
    business_effective_at: Optional[str] = None
    recorded_at: Optional[str] = None


def _le(a: Optional[str], b: str) -> bool:
    """a <= b，None 视为负无穷（无下界）。"""
    return a is None or a <= b


def _lt(x: str, y: Optional[str]) -> bool:
    """x < y，None 视为正无穷（半开区间上界开放）。"""
    return y is None or x < y


def grant_covers(ev: Event, use_at: str, category: str,
                 purpose: str, recipient: str) -> bool:
    """use_at 是否落在许可的半开有效区间 [valid_from, valid_to) 且四元组匹配。"""
    if ev.event_type != "grant":
        return False
    if (ev.category, ev.purpose, ev.recipient) != (category, purpose, recipient):
        return False
    return _le(ev.valid_from, use_at) and _lt(use_at, ev.valid_to)


def revocation_effective(ev: Event, use_at: str, grant_id: str) -> bool:
    """撤销是否在 use_at 业务生效并指向给定 grant_id。"""
    return (
        ev.event_type == "revocation"
        and ev.revoke_grant == grant_id
        and ev.business_effective_at is not None
        and ev.business_effective_at <= use_at
    )


@dataclass(frozen=True)
class Decision:
    """一次确定性重放的结果。"""
    outcome: str  # 'allow' | 'deny'
    reason: str   # 'grant'（allow）| 'revoked' | 'no_grant'（deny）
    grant: Optional[Event] = None
    revocation: Optional[Event] = None

    def basis(self) -> dict:
        if self.outcome == "allow":
            return {"kind": "grant", "seq": self.grant.seq,
                    "grant_id": self.grant.grant_id}
        if self.reason == "revoked":
            return {"kind": "revocation", "seq": self.revocation.seq,
                    "grant_id": self.grant.grant_id,
                    "business_effective_at": self.revocation.business_effective_at}
        return {"kind": "none", "reason": "no_grant"}


def decide(events: Iterable[Event], *, subject_id: str, category: str,
           purpose: str, recipient: str, use_at: str,
           as_of: Optional[str] = None,
           as_of_seq: Optional[int] = None) -> Decision:
    """按 (use_at, as_of) 确定性重放决策。

    ``as_of_seq`` 优先于 ``as_of``；两者都为 None 时视为“当前最新”，
    即取全部已录入事件。任何情况下默认拒绝。
    """
    visible = []
    for ev in events:
        if ev.subject_id != subject_id:
            continue
        if as_of_seq is not None:
            if ev.seq <= as_of_seq:
                visible.append(ev)
        elif as_of is None or (ev.recorded_at is not None
                               and ev.recorded_at <= as_of):
            visible.append(ev)

    # 命中许可：最新登记（seq 最大）者。
    grant: Optional[Event] = None
    for ev in visible:
        if grant_covers(ev, use_at, category, purpose, recipient):
            if grant is None or ev.seq > grant.seq:
                grant = ev
    if grant is None:
        return Decision("deny", "no_grant")

    # 撤销必须在 as_of 前已录入（visible 已保证），且在 use_at 业务生效。
    revocation: Optional[Event] = None
    for ev in visible:
        if revocation_effective(ev, use_at, grant.grant_id):
            if revocation is None or ev.seq < revocation.seq:
                revocation = ev
    if revocation is not None:
        return Decision("deny", "revoked", grant=grant, revocation=revocation)
    return Decision("allow", "grant", grant=grant)


# ---------------------------------------------------------------- 血缘传播

@dataclass
class ReceiptState:
    """决策回执在某 as_of 下的重放状态。"""
    key: str
    valid: bool
    invalidating_seqs: tuple[int, ...] = ()
    detail: str = ""  # 无效时的人类可读原因


@dataclass
class NodeEvaluation:
    """产物（或任意血缘节点）的阻断评估结果。"""
    active: bool
    invalidating_seqs: tuple[int, ...]
    explanation_groups: list[dict] = field(default_factory=list)


def _sort_key(seqs: tuple[int, ...]):
    """解释排序键：先按失效事件数，再按事件 ID（seq）字典序。"""
    return (len(seqs), sorted(seqs))


def detect_cycle(products: dict[str, list[list[str]]],
                 receipt_keys: set[str]) -> Optional[list[str]]:
    """检测同主体产物血缘中的环。

    :param products: product_id -> 依据组列表；每组是输入引用列表，
                     以 ``"receipt:<key>"`` 或 ``"<product_id>"`` 表示。
    :param receipt_keys: 已知回执引用集合（叶子，不展开）。
    :return: 无环返回 None；有环返回构成环的节点路径。
    """
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {pid: WHITE for pid in products}
    stack: list[str] = []

    def visit(node: str):
        color[node] = GRAY
        stack.append(node)
        for group in products.get(node, ()):
            for ref in group:
                if ref.startswith("receipt:"):
                    continue  # 回执是叶子；未解析引用由服务层拦截。
                child = ref
                if child not in products:
                    continue
                if color[child] == GRAY:
                    return stack[stack.index(child):] + [child]
                if color[child] == WHITE:
                    found = visit(child)
                    if found:
                        return found
        stack.pop()
        color[node] = BLACK
        return None

    for pid in products:
        if color[pid] == WHITE:
            found = visit(pid)
            if found:
                return found
    return None


def evaluate_product_graph(
    products: dict[str, list[list[str]]],
    receipts: dict[str, ReceiptState],
) -> dict[str, NodeEvaluation]:
    """对所有产物做 DAG 血缘传播评估。

    * 回执叶子：valid=True 不贡献失效事件；valid=False 贡献其
      ``invalidating_seqs``（登记即拒绝的回执为空集合）。
    * 依据组：组内任一输入失效则整组失效，失效集合 = 各失效输入集合之并。
    * 产物：至少一组存活则存活（取存活组解释为空集）；全部失效才阻断，
      解释取失效事件数最少、再按事件 ID 字典序排序的组。
    """
    memo: dict[str, NodeEvaluation] = {}

    def eval_node(node: str, path: tuple[str, ...]) -> NodeEvaluation:
        if node in memo:
            return memo[node]
        if node.startswith("receipt:"):
            key = node[len("receipt:"):]
            rs = receipts.get(key)
            if rs is None or rs.valid:
                memo[node] = NodeEvaluation(True, ())
            else:
                memo[node] = NodeEvaluation(False, rs.invalidating_seqs, [
                    {"input_kind": "receipt", "input_ref": key,
                     "detail": rs.detail}])
            return memo[node]

        if node in path:  # 防御性：登记时已拦截环，此处不应触发。
            raise ValueError(f"lineage cycle at product {node}")

        groups = products.get(node, [])
        group_reports: list[dict] = []
        alive = False
        for idx, refs in enumerate(groups):
            failed_inputs: list[dict] = []
            union: set[int] = set()
            for ref in refs:
                sub = eval_node(ref, path + (node,))
                if not sub.active:
                    union.update(sub.invalidating_seqs)
                    failed_inputs.append({
                        "input_kind": ("receipt" if ref.startswith("receipt:")
                                       else "product"),
                        "input_ref": (ref[len("receipt:"):]
                                      if ref.startswith("receipt:") else ref),
                        "invalidating_events": sorted(sub.invalidating_seqs),
                        "explanation": sub.explanation_groups,
                    })
            seqs = tuple(sorted(union))
            if not failed_inputs:
                alive = True
                group_reports.append({"group_index": idx, "active": True,
                                      "invalidating_events": []})
            else:
                group_reports.append({"group_index": idx, "active": False,
                                      "invalidating_events": list(seqs),
                                      "failed_inputs": failed_inputs})

        if alive:
            result = NodeEvaluation(True, (),
                                    [g for g in group_reports if g["active"]])
        else:
            best_key = None
            best = None
            for g in group_reports:
                seqs = tuple(g["invalidating_events"])
                k = _sort_key(seqs)
                if best is None or k < best_key:
                    best_key, best = k, g
            result = NodeEvaluation(False, tuple(best["invalidating_events"]),
                                    group_reports)
            result.explanation_groups = [best]
        memo[node] = result
        return result

    for pid in products:
        eval_node(pid, ())
    return {pid: memo[pid] for pid in products}


def transitive_receipts(products: dict[str, list[list[str]]],
                        product_id: str) -> set[str]:
    """产物血缘中全部传递依赖的回执键集合（沿 DAG 向下展开所有产物）。"""
    found: set[str] = set()
    visited = {product_id}
    stack = [product_id]
    while stack:
        node = stack.pop()
        for group in products.get(node, ()):
            for ref in group:
                if ref.startswith("receipt:"):
                    found.add(ref[len("receipt:"):])
                elif ref not in visited:
                    visited.add(ref)
                    stack.append(ref)
    return found


# ---------------------------------------------------------------- 删除计划
def downstream_closure(products: dict[str, list[list[str]]],
                       seeds: Iterable[str]) -> set[str]:
    """从种子产物出发沿“被引用”方向找出全部传递下游产物（含种子本身）。

    删除一个产物时，所有由它派生（直接或间接引用它）的下游产物都必须
    一并删除；本函数给出这一闭包。不存在的产物引用被忽略。
    """
    dependents: dict[str, list[str]] = {}
    for pid, groups in products.items():
        for group in groups:
            for ref in group:
                if not ref.startswith("receipt:"):
                    dependents.setdefault(ref, []).append(pid)
    found = set(seeds)
    stack = list(found)
    while stack:
        node = stack.pop()
        for dep in dependents.get(node, ()):
            if dep not in found:
                found.add(dep)
                stack.append(dep)
    return found


def deletion_batches(products: dict[str, list[list[str]]],
                     scope: Iterable[str]) -> list[list[str]]:
    """把删除范围分层为“下游先删”的删除批次。

    第 1 批是范围内最下游的产物（范围内没有其他产物依赖它）；一个产物的
    全部范围内下游都排入更早批次后，它才进入后续批次。同批内按
    product_id 字典序稳定排序。范围为 DAG（登记时已做无环校验）。
    """
    members = set(scope)
    dependents: dict[str, set[str]] = {pid: set() for pid in members}
    for pid in members:
        for group in products.get(pid, ()):
            for ref in group:
                if not ref.startswith("receipt:") and ref in members:
                    dependents[ref].add(pid)
    memo: dict[str, int] = {}

    def level(pid: str, path: tuple[str, ...]) -> int:
        if pid in memo:
            return memo[pid]
        if pid in path:  # 防御性：登记时已拦截环，此处不应触发。
            raise ValueError(f"lineage cycle at product {pid}")
        deps = dependents.get(pid, ())
        lv = 0 if not deps else 1 + max(level(d, path + (pid,)) for d in deps)
        memo[pid] = lv
        return lv

    by_level: dict[int, list[str]] = {}
    for pid in members:
        by_level.setdefault(level(pid, ()), []).append(pid)
    return [sorted(by_level[lv]) for lv in sorted(by_level)]


# ---------------------------------------------------------------- 删除结论
# 删除请求登记时评估一次并只追加保存（状态 / 批次 / 阻断原因）；查询时复用
# 登记回执的归一化范围，按当前事件重放与处置台账派生“当前结论”，与历史
# 结论比较：只有结论变化（planned <-> blocked，或阻断原因身份变化）才标记
# stale。仅追加新事件但结论不变（例如与范围无关的许可 / 撤销）不会误报过期。
def deletion_blocker_identity(blocker: dict) -> tuple:
    """阻断原因的稳定身份：用于比较登记时与当前重放的结论。

    * ``active_grant``：按回执键 + 当前命中许可定位（许可随重放变化即身份变化）；
    * ``open_remediation``：按处置项 ID 定位（同一项在 open/submitted/rejected
      之间流转仍属同一阻断原因，获批 / 取消后消失）。
    """
    if blocker["kind"] == "active_grant":
        return ("active_grant", blocker["receipt_key"],
                blocker.get("grant_id"), blocker.get("grant_seq"))
    return ("open_remediation", blocker["item_id"])


def deletion_conclusion(status: str, blockers: Iterable[dict]) -> tuple:
    """删除请求的结论签名：(是否阻断, 排序后的阻断原因身份集合)。

    与批次分层、受影响产物等细节无关——处置结案使阻断原因消失（或新增阻断
    原因）即视为结论变化，需要用新幂等键重新评估。
    """
    return (status == "blocked",
            tuple(sorted(deletion_blocker_identity(b) for b in blockers)))


# ---------------------------------------------------------------- 双时点差异
# 合规状态双时点差异报告的分类：实体（产品 / 回执 / 处置项）在 from / to 两条
# 事件序号上界下的存在性与状态比较。本系统只追加，故 removed 实际不会出现，
# 保留该分类以使结果集完备（未来若引入过期清除语义时口径不变）。
DIFF_CLASSIFICATIONS = ("added", "removed", "changed", "unchanged")


def classify_change(from_present: bool, to_present: bool,
                    from_state, to_state) -> str:
    """双时点差异分类：added / removed / changed / unchanged。

    * 仅 to 侧存在 -> ``added``；仅 from 侧存在 -> ``removed``；
    * 两侧均存在：状态比较键不同 -> ``changed``，否则 ``unchanged``。

    :param from_state/to_state: 各侧的状态比较键（可比较的任意值；
        两侧均不存在时不得调用——该实体不属于差异报告范围）。
    """
    if not from_present and not to_present:
        raise ValueError("两侧均不存在的实体不参与差异分类")
    if not from_present:
        return "added"
    if not to_present:
        return "removed"
    return "changed" if from_state != to_state else "unchanged"


# ---------------------------------------------------------------- 处置台账
# 处置项状态机（全部由追加记录派生，不改写任何行）：
#   open       已开立，接收方尚未提交；
#   submitted  最新提交版本待复核；
#   rejected   最新版本被驳回，可补证下一版本；
#   approved   最新版本已获批（结案）；
#   cancelled  后续许可使回执恢复有效，未结处置项被取消。
REMEDIATION_UNRESOLVED = ("open", "submitted", "rejected")
REMEDIATION_RESOLVED = ("approved", "cancelled")


def remediation_item_status(*, cancelled: bool,
                            submission_versions: list[int],
                            reviews: dict[int, str]) -> str:
    """由追加记录派生单个处置项的状态。

    :param cancelled: 是否存在取消记录（后续许可恢复有效）；
    :param submission_versions: 已提交的证据版本列表；
    :param reviews: 版本 -> 复核动作（'approved' / 'rejected'）。
    """
    if cancelled:
        return "cancelled"
    if not submission_versions:
        return "open"
    latest = max(submission_versions)
    action = reviews.get(latest)
    if action == "approved":
        return "approved"
    if action == "rejected":
        return "rejected"
    return "submitted"


def remediation_case_status(item_statuses: Iterable[str]) -> str:
    """（主体, 接收方）维度结案状态：全部处置项均了结（获批或已取消）才结案。

    取消的处置项视为已了结（回执恢复有效，无需处置）；一旦后续新增失效
    开立新项，状态重新变为 pending。
    """
    return ("closed" if all(s in REMEDIATION_RESOLVED for s in item_statuses)
            else "pending")
