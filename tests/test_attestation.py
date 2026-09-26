"""合规证明纯逻辑单元测试（仅标准库）：规范化序列化、摘要、HMAC 与独立验签。

不依赖 psycopg / FastAPI / PostgreSQL，可用
``python3 -m unittest tests.test_attestation -v`` 直接运行。
"""
import json
import unittest

from app import attestation as a


class CanonicalSerializationTests(unittest.TestCase):
    def test_fixed_field_serialization_is_deterministic(self):
        """嵌套 / 乱序 / 列表顺序保持 + 键固定排序 -> 逐字节确定。"""
        c1 = {"subject_id": "u1", "as_of_seq": 3,
              "products": {"p2": {"status": "blocked"},
                           "p1": {"status": "active"}},
              "deletion": {"scope": ["p1", "p2"], "batches": []}}
        c2 = {"deletion": {"batches": [], "scope": ["p1", "p2"]},
              "products": {"p1": {"status": "active"},
                           "p2": {"status": "blocked"}},
              "as_of_seq": 3, "subject_id": "u1"}
        self.assertEqual(a.canonical_bytes(c1), a.canonical_bytes(c2))
        blob = a.canonical_bytes(c1).decode("utf-8")
        # 紧凑分隔符、键按字典序（subject_id 在 use_at 之后，as_of_seq 最前）。
        self.assertEqual(
            blob,
            '{"as_of_seq":3,"deletion":{"batches":[],"scope":["p1","p2"]},'
            '"products":{"p1":{"status":"active"},"p2":{"status":"blocked"}},'
            '"subject_id":"u1"}')

    def test_unicode_not_escaped(self):
        blob = a.canonical_bytes({"m": "中文"}).decode("utf-8")
        self.assertEqual(blob, '{"m":"中文"}')

    def test_non_object_rejected(self):
        with self.assertRaises(a.AttestationFormatError):
            a.canonical_bytes(["not", "object"])
        with self.assertRaises(a.AttestationFormatError):
            a.canonical_bytes("string")


class DigestSignVerifyTests(unittest.TestCase):
    def setUp(self):
        self.claim = {"version": "1.0", "subject_id": "u1",
                      "use_at": "2026-05-01T00:00:00+00:00",
                      "as_of_seq": 2, "basis_seq": 2,
                      "product_ids": ["p1"],
                      "products": {"p1": {"status": "active",
                                          "invalidating_events": [],
                                          "receipts": [
                                              {"receipt_key": "t1",
                                               "currently_valid": True,
                                               "invalidating_events": []}],
                                          "remediation_items": []}},
                      "deletion": {"scope": ["p1"], "status": "planned",
                                   "blockers": [],
                                   "batches": [{"batch_no": 1,
                                                "product_ids": ["p1"]}]}}
        self.bytes_ = a.canonical_bytes(self.claim)
        self.digest_ = a.digest(self.bytes_)
        self.sig = a.sign(self.bytes_, "secret-key")

    def test_roundtrip_valid(self):
        r = a.verify_bundle(claim_bytes=self.bytes_, digest_hex=self.digest_,
                            signature_hex=self.sig, key="secret-key")
        self.assertTrue(r["valid"])
        self.assertTrue(r["digest_ok"])
        self.assertTrue(r["signature_ok"])
        self.assertEqual(r["digest_alg"], "SHA-256")
        self.assertEqual(r["signature_alg"], "HMAC-SHA256")
        # 摘要为 64 位小写十六进制 SHA-256。
        self.assertEqual(len(self.digest_), 64)
        int(self.digest_, 16)

    def test_tampered_single_byte_detected(self):
        """篡改任一字节：摘要与签名均失败（即便仍为合法 JSON）。"""
        tampered = self.bytes_.replace(b'"u1"', b'"u2"', 1)
        self.assertNotEqual(tampered, self.bytes_)
        r = a.verify_bundle(claim_bytes=tampered, digest_hex=self.digest_,
                            signature_hex=self.sig, key="secret-key")
        self.assertFalse(r["valid"])
        self.assertFalse(r["digest_ok"])
        self.assertFalse(r["signature_ok"])
        self.assertNotEqual(r["digest"], self.digest_)

    def test_digest_tampered_but_signature_ok(self):
        """只篡改摘要（换用另一字节的真摘要）：digest_ok=False。"""
        other = a.canonical_bytes({**self.claim, "basis_seq": 9})
        r = a.verify_bundle(claim_bytes=self.bytes_,
                            digest_hex=a.digest(other),
                            signature_hex=self.sig, key="secret-key")
        self.assertFalse(r["valid"])
        self.assertFalse(r["digest_ok"])
        self.assertTrue(r["signature_ok"])

    def test_wrong_key_signature_fails(self):
        r = a.verify_bundle(claim_bytes=self.bytes_, digest_hex=self.digest_,
                            signature_hex=self.sig, key="other-key")
        self.assertFalse(r["valid"])
        self.assertTrue(r["digest_ok"])
        self.assertFalse(r["signature_ok"])

    def test_non_hex_hex_rejected(self):
        with self.assertRaises(a.AttestationFormatError):
            a.verify_bundle(claim_bytes=self.bytes_, digest_hex="zz",
                            signature_hex=self.sig, key="k")
        with self.assertRaises(a.AttestationFormatError):
            a.verify_bundle(claim_bytes=self.bytes_, digest_hex=self.digest_,
                            signature_hex="not-hex!", key="k")

    def test_resolve_claim_bytes_canonical_passthrough(self):
        # claim_canonical 原样参与验签（不重新规范化）。
        cb = a.resolve_claim_bytes(claim=None,
                                   claim_canonical=self.bytes_.decode())
        self.assertEqual(cb, self.bytes_)
        # claim 对象按固定字段重新序列化。
        cb2 = a.resolve_claim_bytes(claim=self.claim, claim_canonical=None)
        self.assertEqual(cb2, self.bytes_)
        with self.assertRaises(a.AttestationFormatError):
            a.resolve_claim_bytes(claim=None, claim_canonical=None)

    def test_reserialized_json_is_byte_identical_to_original(self):
        """声明经任意 JSON 解析后按固定字段重序列化，字节必须一致。

        这是“客户端可独立验签”的基础：把返回的 claim 对象原样回传，
        服务端重新规范化得到的字节与签名输入逐字节相同。
        """
        reparsed = json.loads(self.bytes_.decode("utf-8"))
        self.assertEqual(a.canonical_bytes(reparsed), self.bytes_)

    def test_build_claim_contains_only_stable_fields(self):
        claim = a.build_claim(
            subject_id="u1", use_at="2026-05-01T00:00:00+00:00",
            as_of_seq=2, basis_seq=2, product_ids=["p1"],
            products={"p1": {"status": "active"}},
            deletion={"status": "planned"})
        self.assertEqual(set(claim),
                         {"version", "subject_id", "use_at", "as_of_seq",
                          "basis_seq", "product_ids", "products", "deletion"})
        self.assertEqual(claim["version"], a.ATTESTATION_VERSION)


if __name__ == "__main__":
    unittest.main()
