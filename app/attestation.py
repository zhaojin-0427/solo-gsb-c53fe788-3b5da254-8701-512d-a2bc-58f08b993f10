"""合规证明：规范化声明、SHA-256 摘要、本地密钥 HMAC 签名与独立验签。

本模块只依赖标准库，不读取数据库或任何可变业务状态——验签仅凭声明字节、
摘要、签名与配置的本地 HMAC 密钥即可独立完成（见 :func:`verify_bundle`）。

规范化序列化（canonical JSON）
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
声明必须按**固定字段**序列化，任何重放都得到逐字节相同的结果：

``json.dumps(claim, sort_keys=True, ensure_ascii=False, separators=(",", ":"))``
后取 UTF-8 字节。摘要（SHA-256）与签名（HMAC-SHA256）的输入都是这串字节；
数据库同时原样保存该字节串（``claim_bytes``），GET 返回的声明由该字节串
解析得到，绝不经过 JSONB 重新序列化（键序 / 空白变化会使验签失败）。

签名输入
~~~~~~~~
``HMAC_SHA256(key, claim_bytes)``：HMAC 本身已对声明内容鉴权，同时保存
独立的 SHA-256 摘要用于篡改定位（验签分别报告 ``digest_ok`` 与
``signature_ok``）。
"""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Optional

ATTESTATION_VERSION = "1.0"
SIGNATURE_ALG = "HMAC-SHA256"
DIGEST_ALG = "SHA-256"


class AttestationFormatError(ValueError):
    """验签输入格式非法（非十六进制摘要 / 签名、非对象声明等）。"""


def canonical_bytes(claim: dict) -> bytes:
    """声明 -> 固定序列化字节（规范 JSON，UTF-8）。

    要求 claim 是 JSON 对象；禁用 NaN/Infinity（非标准 JSON），保证
    任意实现重序列化结果一致。
    """
    if not isinstance(claim, dict):
        raise AttestationFormatError("声明必须是 JSON 对象")
    blob = json.dumps(claim, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False)
    return blob.encode("utf-8")


def digest(claim_bytes: bytes) -> str:
    """规范字节的 SHA-256 摘要（小写十六进制）。"""
    return hashlib.sha256(claim_bytes).hexdigest()


def sign(claim_bytes: bytes, key: str) -> str:
    """以本地密钥对规范字节计算 HMAC-SHA256（小写十六进制）。"""
    return hmac.new(key.encode("utf-8"), claim_bytes,
                    hashlib.sha256).hexdigest()


def _hex_eq(a: str, b: str) -> bool:
    """常量时间比较两个小写十六进制串（长度不同立即失败时不泄露内容）。"""
    return hmac.compare_digest(a.encode("ascii"), b.encode("ascii"))


def verify_bundle(*, claim_bytes: bytes, digest_hex: str,
                  signature_hex: str, key: str) -> dict:
    """独立验签：只依赖声明字节、摘要、签名与配置密钥，不读取业务状态。

    返回 ``{"valid", "digest_ok", "signature_ok", "digest", "alg"}``。
    摘要 / 签名不是合法十六进制时抛 :class:`AttestationFormatError`
    （调用方映射为 422）；字节被篡改或密钥不匹配时各项如实返回 False。
    """
    digest_hex = digest_hex.strip().lower()
    signature_hex = signature_hex.strip().lower()
    try:
        bytes.fromhex(digest_hex)
        bytes.fromhex(signature_hex)
    except ValueError as exc:
        raise AttestationFormatError("摘要 / 签名必须是十六进制字符串") from exc
    computed = digest(claim_bytes)
    digest_ok = _hex_eq(computed, digest_hex)
    expected_sig = sign(claim_bytes, key)
    signature_ok = _hex_eq(expected_sig, signature_hex)
    return {"valid": digest_ok and signature_ok,
            "digest_ok": digest_ok,
            "signature_ok": signature_ok,
            "digest_alg": DIGEST_ALG,
            "signature_alg": SIGNATURE_ALG,
            "digest": computed}


def resolve_claim_bytes(*, claim: Optional[dict],
                        claim_canonical: Optional[str]) -> bytes:
    """从验签请求中取规范字节：优先 claim_canonical（原样 UTF-8 字节），
    否则对 claim 对象做规范序列化。两者皆无 / 皆空 -> 422。
    """
    if claim_canonical is not None and claim_canonical != "":
        return claim_canonical.encode("utf-8")
    if claim is not None:
        return canonical_bytes(claim)
    raise AttestationFormatError(
        "必须提供 claim（声明对象）或 claim_canonical（规范字节字符串）")


def build_claim(*, subject_id: str, use_at: str, as_of_seq: int,
                basis_seq: int, product_ids: list[str],
                products: dict[str, dict], deletion: dict) -> dict:
    """组装固定字段的声明对象（列表须已由调用方按稳定标识排序）。

    字段集合固定（见模块文档与 README §4.8），只含稳定标识与依据：
    主体、产品范围、使用 / 快照时点、每个产品的血缘回执依据与处置状态、
    以及删除结论（范围闭包、阻断依据或删除批次）。声明不含服务端生成
    时间、自由文本等可变内容，故同快照重放逐字节一致。
    """
    return {
        "version": ATTESTATION_VERSION,
        "subject_id": subject_id,
        "use_at": use_at,
        "as_of_seq": as_of_seq,
        "basis_seq": basis_seq,
        "product_ids": list(product_ids),
        "products": products,
        "deletion": deletion,
    }
