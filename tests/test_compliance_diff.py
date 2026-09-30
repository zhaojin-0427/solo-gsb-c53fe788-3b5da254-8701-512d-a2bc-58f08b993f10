"""合规状态双时点差异的纯领域逻辑单元测试（仅标准库）。"""
import unittest

from app import compliance_diff as cdiff


def receipt_view(key, *, valid, basis="grant", basis_seq=1, grant_id="g1",
                 invalid=(), recorded_seq=1, decision="allow", reason="grant"):
    return {"receipt_key": key, "recorded_seq": recorded_seq,
            "decision": decision, "currently_valid": valid,
            "invalidating_events": list(invalid), "basis_kind": basis,
            "basis_seq": basis_seq, "grant_id": grant_id, "reason": reason}


def product_view(pid, status="active", invalid=(), recorded_seq=1):
    return {"product_id": pid, "recorded_seq": recorded_seq,
            "status": status, "invalidating_events": list(invalid),
            "explanation": []}


def item_view(iid, *, status="open", revocation_seq=3, cancel=None,
              receipt_key="t1", recipient="partner-a"):
    return {"item_id": iid, "receipt_key": receipt_key,
            "recipient": recipient, "revocation_seq": revocation_seq,
            "status": status, "cancelled_by_grant_seq": cancel}


class ClassifyTests(unittest.TestCase):
    def test_classify_entity_four_way(self):
        f = receipt_view("t1", valid=True)
        t_same = receipt_view("t1", valid=True)
        t_flip = receipt_view("t1", valid=False, basis="revocation",
                              basis_seq=4, invalid=(4,), reason="revoked")
        self.assertEqual(cdiff.classify_entity(
            None, f, cdiff.receipt_signature), cdiff.DIFF_ADDED)
        self.assertEqual(cdiff.classify_entity(
            f, None, cdiff.receipt_signature), cdiff.DIFF_REMOVED)
        self.assertEqual(cdiff.classify_entity(
            f, t_same, cdiff.receipt_signature), cdiff.DIFF_UNCHANGED)
        self.assertEqual(cdiff.classify_entity(
            f, t_flip, cdiff.receipt_signature), cdiff.DIFF_CHANGED)

    def test_both_none_rejected(self):
        with self.assertRaises(ValueError):
            cdiff.classify_entity(None, None, cdiff.receipt_signature)

    def test_diff_keyed_union(self):
        fm = {"a": product_view("a"), "b": product_view("b")}
        tm = {"a": product_view("a"),
              "c": product_view("c", status="blocked")}
        out = cdiff.diff_keyed(fm, tm, cdiff.product_signature)
        self.assertEqual(out["a"], cdiff.DIFF_UNCHANGED)
        self.assertEqual(out["b"], cdiff.DIFF_REMOVED)
        self.assertEqual(out["c"], cdiff.DIFF_ADDED)

    def test_invalidating_event_set_change_is_changed(self):
        f = receipt_view("t1", valid=False, basis="revocation",
                         basis_seq=4, invalid=(4,), reason="revoked")
        t = receipt_view("t1", valid=False, basis="revocation",
                         basis_seq=4, invalid=(4, 9), reason="revoked")
        self.assertEqual(cdiff.classify_entity(
            f, t, cdiff.receipt_signature), cdiff.DIFF_CHANGED)


class ReceiptFlipReasonTests(unittest.TestCase):
    def test_entered_scope_when_from_missing(self):
        t = receipt_view("t1", valid=True, recorded_seq=5)
        reasons = cdiff.receipt_flip_reasons(None, t)
        self.assertEqual([r["code"] for r in reasons], ["entered_scope"])
        self.assertEqual(reasons[0]["recorded_seq"], 5)

    def test_revocation_took_effect(self):
        f = receipt_view("t1", valid=True, basis="grant", basis_seq=1)
        t = receipt_view("t1", valid=False, basis="revocation",
                         basis_seq=4, invalid=(4,), reason="revoked")
        codes = [r["code"] for r in cdiff.receipt_flip_reasons(f, t)]
        self.assertIn("revocation_took_effect", codes)
        self.assertIn("invalidating_events_added", codes)
        rev = next(r for r in cdiff.receipt_flip_reasons(f, t)
                   if r["code"] == "revocation_took_effect")
        self.assertEqual(rev["revocation_seq"], 4)

    def test_grant_restored(self):
        f = receipt_view("t1", valid=False, basis="revocation",
                         basis_seq=4, invalid=(4,), reason="revoked")
        t = receipt_view("t1", valid=True, basis="grant", basis_seq=7,
                         grant_id="g3", invalid=())
        reasons = cdiff.receipt_flip_reasons(f, t)
        codes = [r["code"] for r in reasons]
        self.assertIn("grant_restored", codes)
        self.assertIn("invalidating_events_removed", codes)

    def test_basis_switched_without_flip(self):
        f = receipt_view("t1", valid=True, basis="grant", basis_seq=1,
                         grant_id="g1")
        t = receipt_view("t1", valid=True, basis="grant", basis_seq=7,
                         grant_id="g3")
        reasons = cdiff.receipt_flip_reasons(f, t)
        self.assertEqual([r["code"] for r in reasons], ["basis_switched"])
        self.assertEqual(reasons[0]["from_basis"]["grant_id"], "g1")
        self.assertEqual(reasons[0]["to_basis"]["grant_id"], "g3")

    def test_unchanged_no_reasons(self):
        f = receipt_view("t1", valid=False, basis="revocation",
                         basis_seq=4, invalid=(4,), reason="revoked")
        self.assertEqual(cdiff.receipt_flip_reasons(f, dict(f)), [])


class ProductFlipReasonTests(unittest.TestCase):
    def test_absent_product_recorded_between(self):
        t = product_view("p1", recorded_seq=6)
        reasons = cdiff.product_flip_reasons(None, t, [])
        self.assertEqual([r["code"] for r in reasons],
                         ["product_recorded_between"])

    def test_lineage_invalidation_and_event_set(self):
        f = product_view("p1", "active")
        t = product_view("p1", "blocked", invalid=(8,))
        receipt_diffs = [{
            "receipt_key": "t1", "classification": cdiff.DIFF_CHANGED,
            "to": {"currently_valid": False}}]
        codes = [r["code"]
                 for r in cdiff.product_flip_reasons(f, t, receipt_diffs)]
        self.assertIn("lineage_receipts_invalidated", codes)
        self.assertIn("invalidating_events_added", codes)

    def test_lineage_restored(self):
        f = product_view("p1", "blocked", invalid=(8,))
        t = product_view("p1", "active")
        receipt_diffs = [{
            "receipt_key": "t1", "classification": cdiff.DIFF_CHANGED,
            "to": {"currently_valid": True}}]
        codes = [r["code"]
                 for r in cdiff.product_flip_reasons(f, t, receipt_diffs)]
        self.assertIn("lineage_receipts_restored", codes)
        self.assertIn("invalidating_events_removed", codes)


class ItemFlipReasonTests(unittest.TestCase):
    def test_item_opened(self):
        t = item_view(1, status="open", revocation_seq=8)
        reasons = cdiff.remediation_item_flip_reasons(None, t)
        self.assertEqual([r["code"] for r in reasons], ["item_opened"])

    def test_item_cancelled_by_grant(self):
        f = item_view(1, status="open")
        t = item_view(1, status="cancelled", cancel=12)
        codes = [r["code"]
                 for r in cdiff.remediation_item_flip_reasons(f, t)]
        self.assertIn("item_cancelled", codes)

    def test_status_flow_reported(self):
        f = item_view(1, status="submitted")
        t = item_view(1, status="approved")
        reasons = cdiff.remediation_item_flip_reasons(f, t)
        self.assertEqual([r["code"] for r in reasons],
                         ["remediation_status_changed"])
        self.assertEqual(reasons[0]["from_status"], "submitted")
        self.assertEqual(reasons[0]["to_status"], "approved")

    def test_open_to_submitted_same_identity_signature(self):
        # 同一未结处置项 open/submitted 仅台账流转：签名中含状态，仍可定位。
        f = item_view(1, status="open")
        t = item_view(1, status="submitted")
        self.assertNotEqual(cdiff.remediation_item_signature(f),
                            cdiff.remediation_item_signature(t))


class BlockerDiffTests(unittest.TestCase):
    AG1 = {"kind": "active_grant", "receipt_key": "t1", "grant_id": "g1",
           "grant_seq": 1, "products": ["p1"]}
    AG3 = {"kind": "active_grant", "receipt_key": "t1", "grant_id": "g3",
           "grant_seq": 7, "products": ["p1"]}
    REM = {"kind": "open_remediation", "item_id": 5, "receipt_key": "t1",
           "recipient": "partner-a", "status": "open",
           "products": ["p1"]}

    def test_identical_identities_unchanged_and_sorted(self):
        out = cdiff.diff_blockers([self.REM, self.AG1], [self.AG1, self.REM])
        self.assertEqual([d["classification"] for d in out],
                         [cdiff.DIFF_UNCHANGED, cdiff.DIFF_UNCHANGED])
        # 按身份（元组）稳定排序：active_grant < open_remediation。
        self.assertEqual(out[0]["identity"][0], "active_grant")

    def test_grant_switch_is_removed_plus_added(self):
        out = cdiff.diff_blockers([self.AG1], [self.AG3])
        kinds = {(tuple(d["identity"])[2] if d["identity"][0]
                  == "active_grant" else d["identity"][1]):
                 d["classification"] for d in out}
        self.assertEqual(kinds, {"g1": cdiff.DIFF_REMOVED,
                                 "g3": cdiff.DIFF_ADDED})

    def test_new_remediation_added(self):
        out = cdiff.diff_blockers([], [self.REM])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["classification"], cdiff.DIFF_ADDED)
        self.assertEqual(out[0]["identity"], ["open_remediation", 5])

    def test_resolved_remediation_removed(self):
        out = cdiff.diff_blockers([self.REM], [])
        self.assertEqual(out[0]["classification"], cdiff.DIFF_REMOVED)

    def test_deletion_status_changed(self):
        self.assertTrue(cdiff.deletion_status_changed("blocked", "planned"))
        self.assertFalse(cdiff.deletion_status_changed("planned", "planned"))


if __name__ == "__main__":
    unittest.main()
