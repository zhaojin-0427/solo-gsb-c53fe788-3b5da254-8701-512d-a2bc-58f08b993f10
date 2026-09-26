"""领域逻辑单元测试（仅标准库）：覆盖确定性重放与血缘阻断传播。"""
import unittest

from app.domain import (Decision, Event, ReceiptState, decide,
                        deletion_batches, detect_cycle, downstream_closure,
                        evaluate_product_graph)

SUB = "user-1"
T0 = "2026-01-01T00:00:00+00:00"
T1 = "2026-02-01T00:00:00+00:00"
T2 = "2026-03-01T00:00:00+00:00"
T3 = "2026-06-01T00:00:00+00:00"


def grant(seq, gid, vf=T0, vt=None, recorded=T0, cat="email",
          purpose="marketing", recipient="partner-a"):
    return Event(seq, SUB, "grant", gid, cat, purpose, recipient,
                 vf, vt, None, None, recorded)


def revocation(seq, gid, bea, recorded):
    return Event(seq, SUB, "revocation", f"rev-{seq}", None, None, None,
                 None, None, gid, bea, recorded)


KW = dict(subject_id=SUB, category="email", purpose="marketing",
          recipient="partner-a")


class DecideTests(unittest.TestCase):
    def test_default_deny_when_no_grant(self):
        d = decide([], use_at=T1, **KW)
        self.assertEqual(d.outcome, "deny")
        self.assertEqual(d.reason, "no_grant")

    def test_allow_inside_window(self):
        d = decide([grant(1, "g1", T0, T3, recorded=T0)], use_at=T2, **KW)
        self.assertEqual(d.outcome, "allow")
        self.assertEqual(d.basis()["grant_id"], "g1")

    def test_half_open_upper_bound_excluded(self):
        # use_at == valid_to 不在 [vf, vt) 内
        d = decide([grant(1, "g1", T0, T3, recorded=T0)], use_at=T3, **KW)
        self.assertEqual(d.outcome, "deny")

    def test_half_open_lower_bound_included(self):
        d = decide([grant(1, "g1", T1, T3, recorded=T0)], use_at=T1, **KW)
        self.assertEqual(d.outcome, "allow")

    def test_open_ended_grant(self):
        d = decide([grant(1, "g1")], use_at=T3, **KW)
        self.assertEqual(d.outcome, "allow")

    def test_category_purpose_recipient_must_match(self):
        d = decide([grant(1, "g1")], use_at=T2,
                   subject_id=SUB, category="email", purpose="marketing",
                   recipient="partner-b")
        self.assertEqual(d.outcome, "deny")

    def test_revocation_effective_at_use_time(self):
        # business_effective_at <= use_at => 撤销命中（半开点：相等即生效）
        evs = [grant(1, "g1", T0, None, recorded=T0),
               revocation(2, "g1", bea=T2, recorded=T2)]
        d = decide(evs, use_at=T2, **KW)
        self.assertEqual(d.outcome, "deny")
        self.assertEqual(d.reason, "revoked")
        self.assertEqual(d.basis()["seq"], 2)

    def test_revocation_after_use_time_does_not_count(self):
        evs = [grant(1, "g1", recorded=T0),
               revocation(2, "g1", bea=T3, recorded=T3)]
        d = decide(evs, use_at=T2, **KW)
        self.assertEqual(d.outcome, "allow")

    def test_as_of_hides_late_recorded_revocation(self):
        # 撤销录入于 T3，按 T2 的 as_of 重放看不到 -> 允许
        evs = [grant(1, "g1", recorded=T0),
               revocation(2, "g1", bea=T0, recorded=T3)]
        d = decide(evs, use_at=T2, as_of=T2, **KW)
        self.assertEqual(d.outcome, "allow")
        # 当前（as_of 更晚）重放 -> 追溯撤销命中
        d2 = decide(evs, use_at=T2, as_of=T3, **KW)
        self.assertEqual(d2.outcome, "deny")
        self.assertEqual(d2.reason, "revoked")

    def test_as_of_seq_cutoff(self):
        evs = [grant(1, "g1", recorded=T0),
               revocation(2, "g1", bea=T0, recorded=T3)]
        d = decide(evs, use_at=T2, as_of_seq=1, **KW)
        self.assertEqual(d.outcome, "allow")
        d = decide(evs, use_at=T2, as_of_seq=2, **KW)
        self.assertEqual(d.outcome, "deny")

    def test_latest_grant_wins(self):
        # 两个重叠许可，取 seq 最大者；撤销只挂在旧许可上不影响新许可
        evs = [grant(1, "g1", T0, None, recorded=T0),
               grant(2, "g2", T0, None, recorded=T1),
               revocation(3, "g1", bea=T0, recorded=T1)]
        d = decide(evs, use_at=T2, **KW)
        self.assertEqual(d.outcome, "allow")
        self.assertEqual(d.basis()["grant_id"], "g2")

    def test_revocation_of_winning_grant_denies_with_earliest_rev(self):
        evs = [grant(1, "g1", T0, None, recorded=T0),
               revocation(2, "g1", bea=T0, recorded=T1),
               revocation(3, "g1", bea=T0, recorded=T2)]
        d = decide(evs, use_at=T2, **KW)
        self.assertEqual(d.outcome, "deny")
        self.assertEqual(d.basis()["seq"], 2)  # 最早登记的生效撤销

    def test_subject_isolation(self):
        other = Event(1, "other-user", "grant", "g9", "email", "marketing",
                      "partner-a", T0, None, None, None, T0)
        d = decide([other], use_at=T2, **KW)
        self.assertEqual(d.outcome, "deny")


class LineageTests(unittest.TestCase):
    def _eval(self, products, receipts):
        return evaluate_product_graph(products, receipts)

    def test_active_product_with_valid_receipt(self):
        receipts = {"r1": ReceiptState("r1", True)}
        out = self._eval({"p1": [["receipt:r1"]]}, receipts)
        self.assertTrue(out["p1"].active)
        self.assertEqual(out["p1"].invalidating_seqs, ())

    def test_blocked_product_carries_revocation_seq(self):
        receipts = {"r1": ReceiptState("r1", False, (7,))}
        out = self._eval({"p1": [["receipt:r1"]]}, receipts)
        self.assertFalse(out["p1"].active)
        self.assertEqual(out["p1"].invalidating_seqs, (7,))

    def test_registered_deny_receipt_blocks_but_has_empty_event_set(self):
        receipts = {"r1": ReceiptState("r1", False, (), "registered deny")}
        out = self._eval({"p1": [["receipt:r1"]]}, receipts)
        self.assertFalse(out["p1"].active)
        self.assertEqual(out["p1"].invalidating_seqs, ())

    def test_alternative_group_keeps_product_active(self):
        # 两组替代依据：第一组被撤销，第二组仍存活 -> 产物 active
        receipts = {"r1": ReceiptState("r1", False, (7,)),
                    "r2": ReceiptState("r2", True)}
        out = self._eval({"p1": [["receipt:r1"], ["receipt:r2"]]}, receipts)
        self.assertTrue(out["p1"].active)

    def test_all_groups_fail_blocks_product(self):
        receipts = {"r1": ReceiptState("r1", False, (7,)),
                    "r2": ReceiptState("r2", False, (8,))}
        out = self._eval({"p1": [["receipt:r1"], ["receipt:r2"]]}, receipts)
        self.assertFalse(out["p1"].active)
        # 解释取失效事件数最少（都是 1 个），再按事件 ID -> seq 7
        self.assertEqual(out["p1"].invalidating_seqs, (7,))

    def test_explanation_prefers_fewer_events(self):
        # 组1：单撤销 seq 9（1 个事件）；组2：撤销 7、8 并集（2 个事件）
        receipts = {"a": ReceiptState("a", False, (9,)),
                    "b": ReceiptState("b", False, (7,)),
                    "c": ReceiptState("c", False, (8,))}
        products = {"p": [["receipt:a"], ["receipt:b", "receipt:c"]]}
        out = self._eval(products, receipts)
        self.assertFalse(out["p"].active)
        self.assertEqual(out["p"].invalidating_seqs, (9,))  # 事件数最少优先

    def test_group_union_of_invalidating_events(self):
        receipts = {"b": ReceiptState("b", False, (7,)),
                    "c": ReceiptState("c", False, (8,))}
        out = self._eval({"p": [["receipt:b", "receipt:c"]]}, receipts)
        self.assertEqual(out["p"].invalidating_seqs, (7, 8))

    def test_propagation_through_product_chain(self):
        receipts = {"r1": ReceiptState("r1", False, (7,))}
        products = {"p1": [["receipt:r1"]],
                    "p2": [["p1"]],
                    "p3": [["p2"]]}
        out = self._eval(products, receipts)
        self.assertFalse(out["p3"].active)
        self.assertEqual(out["p3"].invalidating_seqs, (7,))

    def test_propagation_diamond_alternative_survives(self):
        receipts = {"r1": ReceiptState("r1", False, (7,)),
                    "r2": ReceiptState("r2", True)}
        products = {"p1": [["receipt:r1"]],
                    "p2": [["receipt:r2"]],
                    "p3": [["p1"], ["p2"]]}
        out = self._eval(products, receipts)
        self.assertFalse(out["p1"].active)
        self.assertTrue(out["p2"].active)
        self.assertTrue(out["p3"].active)  # 替代组 p2 存活

    def test_cycle_detection(self):
        receipts = {"r1": ReceiptState("r1", True)}
        products = {"p1": [["p2"]], "p2": [["p1"]]}
        cyc = detect_cycle(products, {"r1"})
        self.assertIsNotNone(cyc)
        self.assertIn("p1", cyc)

    def test_self_loop_detection(self):
        products = {"p1": [["p1"]]}
        self.assertIsNotNone(detect_cycle(products, set()))

    def test_dag_has_no_cycle(self):
        products = {"p1": [["receipt:r1"]],
                    "p2": [["p1", "receipt:r1"]],
                    "p3": [["p1", "p2"]]}
        self.assertIsNone(detect_cycle(products, {"r1"}))


class TransitiveReceiptsTests(unittest.TestCase):
    def test_collects_leaves_through_product_chain_and_groups(self):
        from app.domain import transitive_receipts
        products = {
            "p1": [["receipt:r1"]],
            "p2": [["receipt:r2", "p1"]],          # 组内混合
            "p3": [["p1"], ["p2", "receipt:r3"]],  # 多组替代依据
        }
        self.assertEqual(transitive_receipts(products, "p3"),
                         {"r1", "r2", "r3"})

    def test_unknown_ref_ignored(self):
        from app.domain import transitive_receipts
        products = {"p1": [["p2"], ["receipt:r1"]]}
        self.assertEqual(transitive_receipts(products, "p1"), {"r1"})


class DeletionPlanTests(unittest.TestCase):
    PRODUCTS = {"p1": [["receipt:r1"]],
                "p2": [["p1"]],
                "p3": [["p2"], ["receipt:r2"]],
                "p4": [["receipt:r3"]]}

    def test_downstream_closure_expands_transitively(self):
        self.assertEqual(downstream_closure(self.PRODUCTS, {"p1"}),
                         {"p1", "p2", "p3"})
        # 最下游产物的闭包只有自身；独立产物互不影响。
        self.assertEqual(downstream_closure(self.PRODUCTS, {"p3"}), {"p3"})
        self.assertEqual(downstream_closure(self.PRODUCTS, {"p1", "p4"}),
                         {"p1", "p2", "p3", "p4"})
        self.assertEqual(downstream_closure(self.PRODUCTS, set()), set())

    def test_deletion_batches_downstream_first_stable_order(self):
        # 菱形：p1 <- p2、p1 <- p3、p2/p3 <- p4；同层按 product_id 字典序。
        products = {"p1": [["receipt:r1"]],
                    "p2": [["p1"]],
                    "p3": [["p1"]],
                    "p4": [["p2", "p3"]]}
        self.assertEqual(deletion_batches(products, {"p1", "p2", "p3", "p4"}),
                         [["p4"], ["p2", "p3"], ["p1"]])

    def test_deletion_batches_only_scope_internal_edges(self):
        # 范围外的依赖边不影响分层：p3 在范围外时 p2 成为最下游。
        self.assertEqual(deletion_batches(self.PRODUCTS, {"p1", "p2"}),
                         [["p2"], ["p1"]])
        self.assertEqual(deletion_batches(self.PRODUCTS, {"p1"}), [["p1"]])
        self.assertEqual(deletion_batches(self.PRODUCTS, []), [])


class DeletionConclusionTests(unittest.TestCase):
    """历史结论与当前结论的比较：处置结案 / 阻断身份变化才算过期。"""

    AG = {"kind": "active_grant", "receipt_key": "t1",
          "grant_id": "g1", "grant_seq": 1, "products": ["p1"]}
    AG2 = {"kind": "active_grant", "receipt_key": "t1",
           "grant_id": "g2", "grant_seq": 3, "products": ["p1"]}
    REM = {"kind": "open_remediation", "item_id": 7, "receipt_key": "t1",
           "recipient": "partner-a", "status": "open",
           "products": ["p1"]}

    def test_identical_conclusions_not_stale(self):
        from app.domain import deletion_conclusion
        # 同一未结处置项在 open -> submitted -> rejected 间流转仍是同一阻断。
        for status in ("open", "submitted", "rejected"):
            blocker = dict(self.REM, status=status)
            self.assertEqual(
                deletion_conclusion("blocked", [blocker]),
                deletion_conclusion("blocked", [dict(self.REM)]))
        # 受影响产物集合等细节变化不影响身份；顺序无关。
        rem_b = dict(self.REM, products=["p1", "p2"])
        self.assertEqual(
            deletion_conclusion("blocked", [self.AG, rem_b]),
            deletion_conclusion("blocked", [rem_b, self.AG]))
        self.assertEqual(deletion_conclusion("planned", []),
                         deletion_conclusion("planned", []))

    def test_remediation_closure_changes_conclusion(self):
        from app.domain import deletion_conclusion
        # 处置获批 / 取消后阻断原因消失：blocked -> planned = 结论变化。
        self.assertNotEqual(
            deletion_conclusion("blocked", [self.REM]),
            deletion_conclusion("planned", []))

    def test_blocker_identity_changes_detected(self):
        from app.domain import deletion_conclusion
        # 命中许可切换（新许可 / 撤销使重放结论变化）。
        self.assertNotEqual(
            deletion_conclusion("blocked", [self.AG]),
            deletion_conclusion("blocked", [self.AG2]))
        # 不同处置项（再失效另开新项）。
        rem2 = dict(self.REM, item_id=8)
        self.assertNotEqual(
            deletion_conclusion("blocked", [self.REM]),
            deletion_conclusion("blocked", [rem2]))
        # 阻断原因种类变化。
        self.assertNotEqual(
            deletion_conclusion("blocked", [self.AG]),
            deletion_conclusion("blocked", [self.REM]))
        # planned -> blocked（登记放行后出现新阻断）。
        self.assertNotEqual(
            deletion_conclusion("planned", []),
            deletion_conclusion("blocked", [self.AG]))


class RemediationStatusTests(unittest.TestCase):
    def test_status_progression(self):
        from app.domain import remediation_item_status as st
        self.assertEqual(st(cancelled=False, submission_versions=[],
                            reviews={}), "open")
        self.assertEqual(st(cancelled=False, submission_versions=[1],
                            reviews={}), "submitted")
        self.assertEqual(st(cancelled=False, submission_versions=[1],
                            reviews={1: "rejected"}), "rejected")
        self.assertEqual(st(cancelled=False, submission_versions=[1, 2],
                            reviews={1: "rejected"}), "submitted")
        self.assertEqual(st(cancelled=False, submission_versions=[1, 2],
                            reviews={1: "rejected", 2: "approved"}),
                         "approved")
        # 取消优先于其他状态（未结项被取消）。
        self.assertEqual(st(cancelled=True, submission_versions=[1],
                            reviews={1: "submitted"}), "cancelled")

    def test_case_status(self):
        from app.domain import remediation_case_status as cs
        self.assertEqual(cs(["open"]), "pending")
        self.assertEqual(cs(["submitted", "approved"]), "pending")
        self.assertEqual(cs(["approved"]), "closed")
        self.assertEqual(cs(["approved", "cancelled"]), "closed")
        self.assertEqual(cs([]), "closed")


if __name__ == "__main__":
    unittest.main()
