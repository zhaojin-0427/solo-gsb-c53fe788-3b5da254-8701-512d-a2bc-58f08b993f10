"""Pydantic 请求 / 响应模型。"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class GrantRequest(BaseModel):
    subject_id: str = Field(..., min_length=1, description="数据主体")
    grant_id: str = Field(..., min_length=1, description="许可 ID（主体内唯一）")
    category: str = Field(..., min_length=1, description="数据类别")
    purpose: str = Field(..., min_length=1, description="处理目的")
    recipient: str = Field(..., min_length=1, description="接收方")
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None

    @field_validator("valid_to")
    @classmethod
    def _half_open(cls, v, info):
        vf = info.data.get("valid_from")
        if v is not None and vf is not None and not vf < v:
            raise ValueError("半开区间要求 valid_from < valid_to")
        return v


class RevokeRequest(BaseModel):
    subject_id: str = Field(..., min_length=1)
    grant_id: str = Field(..., min_length=1, description="被撤销的许可 ID")
    business_effective_at: datetime = Field(
        ..., description="撤销业务生效时间；可早于当前（追溯撤销）")


class EvaluateRequest(BaseModel):
    subject_id: str
    category: str
    purpose: str
    recipient: str
    use_at: datetime = Field(..., description="数据使用时点")
    as_of: Optional[datetime] = Field(
        None, description="重放时点（默认取最新已录入事件）")


class GroupInput(BaseModel):
    kind: str = Field(..., pattern="^(receipt|product)$")
    ref: str = Field(..., min_length=1)


class ProductSpec(BaseModel):
    product_id: str = Field(..., min_length=1)
    description: Optional[str] = None
    # 至少一组；每组至少一个输入。多个组即“替代依据组”。
    groups: list[list[GroupInput]] = Field(..., min_length=1)

    @field_validator("groups")
    @classmethod
    def _non_empty_groups(cls, v):
        for i, group in enumerate(v):
            if not group:
                raise ValueError(f"第 {i} 个依据组为空（每组至少一个输入）")
        return v

    def normalized_groups(self) -> list[list[str]]:
        return [[f"receipt:{i.ref}" if i.kind == "receipt" else i.ref
                 for i in group] for group in self.groups]


class TaskRequest(BaseModel):
    subject_id: str
    category: str
    purpose: str
    recipient: str
    use_at: datetime
    products: list[ProductSpec] = Field(default_factory=list)


# ------------------------------------------------------------- 处置台账
class EvidenceEntry(BaseModel):
    product_id: str = Field(..., min_length=1, description="关联产物 ID")
    summary: str = Field(..., min_length=1, description="清除证据摘要")


class RemediationSubmissionRequest(BaseModel):
    version: int = Field(
        ..., ge=1, description="提交版本：首次为 1，驳回后补证逐次递增")
    cease_declaration: str = Field(..., min_length=1,
                                   description="停止使用声明")
    evidence: list[EvidenceEntry] = Field(
        default_factory=list,
        description="关联产物的清除证据摘要（须逐项覆盖全部关联产物）")


class RemediationReviewRequest(BaseModel):
    version: int = Field(..., ge=1,
                         description="复核的提交版本（须为最新版本）")
    action: str = Field(..., pattern="^(approve|reject)$",
                        description="批准或驳回")
    comment: Optional[str] = None


# ------------------------------------------------------------- 删除请求
class DeletionRequestCreate(BaseModel):
    subject_id: str = Field(..., min_length=1, description="数据主体")
    product_ids: list[str] = Field(
        default_factory=list,
        description="目标产物；空列表表示该主体全部产物")
    requested_at: datetime = Field(..., description="客户端请求时间")


# ------------------------------------------------------------- 合规证明
class AttestationCreate(BaseModel):
    subject_id: str = Field(..., min_length=1, description="数据主体")
    product_ids: list[str] = Field(
        ..., description="产品范围；必须非空，且均为主体已知产物")
    use_at: datetime = Field(..., description="证明锚定的使用时点")
    as_of_seq: int = Field(
        ..., ge=1, description="重放上界（录入序号）；必须为当前可见序号")

    @field_validator("product_ids")
    @classmethod
    def _non_empty_products(cls, v):
        if not v:
            raise ValueError("产品范围不能为空")
        if any(not pid or not isinstance(pid, str) for pid in v):
            raise ValueError("产品 ID 不能为空")
        return v


class AttestationVerifyRequest(BaseModel):
    """独立验签请求：声明字节 + 摘要 + 签名（可选 alg，默认 HMAC-SHA256）。

    两种提交声明的方式（二选一）：
      * ``claim_canonical``：服务端此前返回的规范字节字符串（原样参与验签）；
      * ``claim``：声明 JSON 对象，服务端按固定字段重新规范序列化。
    验签不读取任何业务状态，仅依赖配置的本地 HMAC 密钥。
    """
    claim: Optional[dict] = Field(
        None, description="声明对象（与 claim_canonical 二选一）")
    claim_canonical: Optional[str] = Field(
        None, description="服务端返回的规范声明字节字符串")
    digest: str = Field(..., min_length=1, description="声明字节的 SHA-256 摘要")
    signature: str = Field(..., min_length=1,
                           description="本地密钥对声明字节的 HMAC-SHA256 签名")
    alg: Optional[str] = Field(
        None, description="签名算法标识；缺省/固定为 HMAC-SHA256")


# ------------------------------------------------------------- 合规差异报告
class ComplianceDiffCreate(BaseModel):
    """合规状态双时点差异报告请求（只读，不落库，无需幂等键）。

    在两条全局事件序号上界（``from_seq`` < ``to_seq``）下分别重放并比较：
    from 侧尚未登记的产品标为 absent（分类 added）；未知产品或超过当前
    最大事件序号的未来序号由服务端拒绝（422）。
    """
    subject_id: str = Field(..., min_length=1, description="数据主体")
    product_ids: list[str] = Field(
        ..., description="产品范围；必须非空，且均为主体已知产物")
    use_at: datetime = Field(..., description="报告锚定的使用时点")
    from_seq: int = Field(..., ge=1,
                          description="from 侧重放的事件序号上界")
    to_seq: int = Field(..., ge=1,
                        description="to 侧重放的事件序号上界；必须大于 from_seq")

    @field_validator("product_ids")
    @classmethod
    def _non_empty_products(cls, v):
        if not v:
            raise ValueError("产品范围不能为空")
        if any(not pid or not isinstance(pid, str) for pid in v):
            raise ValueError("产品 ID 不能为空")
        return v

    @field_validator("to_seq")
    @classmethod
    def _ordered_bounds(cls, v, info):
        from_seq = info.data.get("from_seq")
        if from_seq is not None and not from_seq < v:
            raise ValueError("序号上界要求 from_seq < to_seq")
        return v
