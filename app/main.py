"""FastAPI 应用与路由。

写入端点（许可追加 / 撤销 / 任务登记）在 REPEATABLE READ 读写事务中执行，
并通过 ``transaction(lock_subject=subject_id)`` 在事务开始**之前**获取
主体级会话咨询锁（pg_advisory_lock）：REPEATABLE READ 的快照在事务内
第一条语句执行时建立，先取锁再开事务才能保证同主体写入按锁获取顺序
读取彼此已提交的状态——撤销先提交则后续任务登记即 deny/revoked；
任务先登记则撤销的 affected_receipts 恰好覆盖此前已登记的失效回执。
只读端点使用 REPEATABLE READ 只读事务做历史重放，任何旧记录都不会被改写。

事务通过 :func:`app.db.transaction` 开启：psycopg3 的隔离级别 / 只读写法
是事务开始前在连接上设置属性（``Connection.transaction()`` 不接受这些
参数），由该上下文统一设置并在连接归还连接池前恢复。
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

import psycopg
from fastapi import FastAPI, Header, Query, Request
from fastapi.responses import JSONResponse

from . import config, db
from . import attestation as attestation_mod
from .db import init_pool, shutdown_pool, transaction
from .errors import ApiError, forbidden, unauthorized, unprocessable
from .schemas import (AttestationCreate, AttestationVerifyRequest,
                      DeletionRequestCreate, EvaluateRequest, GrantRequest,
                      RemediationReviewRequest, RemediationSubmissionRequest,
                      RevokeRequest, TaskRequest)
from .service import Service


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_pool()
    try:
        yield
    finally:
        shutdown_pool()


app = FastAPI(
    title="可撤回数据用途许可与派生阻断 API",
    version="1.0.0",
    lifespan=lifespan,
    description=(
        "追加事件登记许可（grant）与撤销（revocation）；"
        "按 use_at / as_of 双时点确定性重放决策（默认拒绝）；"
        "幂等登记决策回执、派生产物与无环血缘；"
        "追溯撤销沿血缘传播，全部替代依据组失效才阻断产物；"
        "撤销同事务开立处置台账，接收方按版本提交停止使用声明与清除证据，"
        "管理员复核结案；幂等登记删除请求并生成下游先删删除计划；"
        "合规证明在同一快照内重放全部依据，规范化声明附 SHA-256 摘要与"
        "本地密钥 HMAC-SHA256 签名，可独立验签，后续事件不改写既有证明。"
    ),
)


@app.exception_handler(ApiError)
async def _api_error(_: Request, exc: ApiError):
    return JSONResponse(status_code=exc.status_code,
                        content={"error": {"code": exc.code,
                                           "message": exc.message}})


# ---------------------------------------------------------------- 健康检查
@app.get("/health", tags=["system"])
def health():
    with db.pool.connection() as conn:
        conn.execute("SELECT 1").fetchone()
    return {"status": "ok"}


# ---------------------------------------------------------------- 事件追加
@app.post("/grants", status_code=201, tags=["events"])
def create_grant(req: GrantRequest):
    with transaction(lock_subject=req.subject_id) as conn:
        result = Service(conn).append_grant(req)
    return result


@app.post("/revocations", status_code=201, tags=["events"])
def create_revocation(req: RevokeRequest):
    with transaction(lock_subject=req.subject_id) as conn:
        result = Service(conn).append_revocation(req)
    return result


@app.get("/subjects/{subject_id}/events", tags=["events"])
def list_subject_events(subject_id: str,
                        as_of_seq: Optional[int] = Query(None, ge=1)):
    with transaction(read_only=True) as conn:
        return {"subject_id": subject_id,
                "events": Service(conn).list_events(subject_id, as_of_seq)}


# ---------------------------------------------------------------- 决策重放
@app.post("/decisions/evaluate", tags=["decisions"])
def evaluate_decision(req: EvaluateRequest,
                      as_of_seq: Optional[int] = Query(None, ge=1)):
    """按 use_at（请求体）与 as_of（请求体或 ?as_of_seq）确定性重放。"""
    with transaction(read_only=True) as conn:
        return Service(conn).evaluate(req, as_of_seq=as_of_seq)


# ---------------------------------------------------------------- 任务登记
# 幂等键是全局主键，而主体咨询锁按主体分区：不同主体并发使用同一幂等键时
# 互不可见，可能同时未查到既有回执而撞 receipts_pkey。这不是真正的冲突——
# 回滚后用新事务重试：重试时先查到已提交的回执，走正常的幂等重放
# （负载不同则 409）。同主体的并发登记由主体锁串行化，在锁内即可看到
# 先提交的回执，不会触发该冲突。
_TASK_MAX_ATTEMPTS = 5


@app.post("/tasks", status_code=201, tags=["tasks"])
def register_task(req: TaskRequest,
                  idempotency_key: Optional[str] = Header(
                      None, alias="Idempotency-Key")):
    """幂等登记决策回执 + 派生产物 + 血缘。

    同一 Idempotency-Key 的重复请求返回首次结果（幂等重放）；
    请求体不同则 409。与同一主体的撤销 / 追加串行。
    """
    key = idempotency_key or ""
    for attempt in range(1, _TASK_MAX_ATTEMPTS + 1):
        try:
            with transaction(lock_subject=req.subject_id) as conn:
                result = Service(conn).register_task(key, req)
            break
        except psycopg.errors.UniqueViolation as exc:
            if exc.diag.constraint_name != "receipts_pkey" or attempt == _TASK_MAX_ATTEMPTS:
                raise
            # 跨主体的同键并发事务抢先提交：整笔事务已回滚，带新快照重试。
    if result["idempotent_replay"]:
        return JSONResponse(status_code=200, content=result)
    return result


@app.get("/receipts/{key}", tags=["tasks"])
def get_receipt(key: str):
    with transaction(read_only=True) as conn:
        return Service(conn).get_receipt(key)


@app.get("/subjects/{subject_id}/products/{product_id}", tags=["tasks"])
def get_product(subject_id: str, product_id: str,
                as_of: Optional[datetime] = None,
                as_of_seq: Optional[int] = Query(None, ge=1)):
    with transaction(read_only=True) as conn:
        return Service(conn).get_product(
            subject_id, product_id, as_of=as_of, as_of_seq=as_of_seq)


# ---------------------------------------------------------------- 处置台账
def _auth_role(authorization: Optional[str]) -> tuple[str, Optional[str]]:
    """校验本地配置的 Bearer 令牌，返回 (role, recipient)。

    * 管理员令牌 -> ("admin", None)，可执行复核、按接收方查询；
    * 接收方令牌 -> ("recipient", <接收方>)，只能查询 / 提交自己的处置项。
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise unauthorized("缺少 Authorization: Bearer <令牌> 头")
    token = authorization[len("Bearer "):].strip()
    if token == config.ADMIN_TOKEN:
        return "admin", None
    recipient = config.RECIPIENT_TOKENS.get(token)
    if recipient is not None:
        return "recipient", recipient
    raise unauthorized("令牌无效")


def _require_role(authorization: Optional[str], want: str):
    role, recipient = _auth_role(authorization)
    if role != want:
        if want == "admin":
            raise forbidden("仅管理员令牌可执行复核")
        raise forbidden("仅接收方令牌可提交处置证据")
    return recipient


@app.get("/subjects/{subject_id}/remediation", tags=["remediation"])
def get_remediation_case(subject_id: str,
                         recipient: Optional[str] = Query(
                             None, description="管理员查询时指定接收方"),
                         authorization: Optional[str] = Header(None)):
    """查询处置台账：未结项、提交证据、复核历史与结案状态。

    接收方令牌只可查询本接收方；管理员令牌需用 ``?recipient=`` 指定接收方。
    """
    role, token_recipient = _auth_role(authorization)
    if role == "recipient":
        if recipient is not None and recipient != token_recipient:
            raise forbidden("接收方只能查询自己的处置项")
        recipient = token_recipient
    elif recipient is None:
        raise unprocessable("管理员查询需指定 ?recipient=")
    with transaction(read_only=True) as conn:
        return Service(conn).get_remediation_case(subject_id, recipient)


# 幂等键全局唯一而主体锁按主体分区：不同主体并发使用同一幂等键时可能
# 撞上 remediation_submissions_idem_uidx，回滚新事务重试即可（同任务
# 登记的 receipts_pkey 处理）。
_SUBMISSION_MAX_ATTEMPTS = 5


@app.post("/remediation/items/{item_id}/submissions", status_code=201,
          tags=["remediation"])
def submit_remediation(item_id: int, req: RemediationSubmissionRequest,
                       idempotency_key: Optional[str] = Header(
                           None, alias="Idempotency-Key"),
                       authorization: Optional[str] = Header(None)):
    """接收方提交停止使用声明与关联产物清除证据（逐项、按版本、幂等）。"""
    recipient = _require_role(authorization, "recipient")
    # 先用只读事务定位处置项所属主体，再在主体咨询锁内开启写事务：
    # 提交与同主体的撤销 / 许可追加串行，版本判定不产生竞态。
    with transaction(read_only=True) as conn:
        subject_id = Service(conn).remediation_item_subject(item_id)
    key = idempotency_key or ""
    for attempt in range(1, _SUBMISSION_MAX_ATTEMPTS + 1):
        try:
            with transaction(lock_subject=subject_id) as conn:
                result = Service(conn).submit_remediation(
                    item_id, recipient, key, req)
            break
        except psycopg.errors.UniqueViolation as exc:
            if (exc.diag.constraint_name
                    != "remediation_submissions_idem_uidx"
                    or attempt == _SUBMISSION_MAX_ATTEMPTS):
                raise
            # 跨主体的同键并发事务抢先提交：整笔事务已回滚，带新快照重试。
    if result["idempotent_replay"]:
        return JSONResponse(status_code=200, content=result)
    return result


@app.post("/remediation/items/{item_id}/reviews", status_code=201,
          tags=["remediation"])
def review_remediation(item_id: int, req: RemediationReviewRequest,
                       authorization: Optional[str] = Header(None)):
    """管理员按版本批准 / 驳回；驳回后接收方可提交补证版本。"""
    _require_role(authorization, "admin")
    with transaction(read_only=True) as conn:
        subject_id = Service(conn).remediation_item_subject(item_id)
    with transaction(lock_subject=subject_id) as conn:
        return Service(conn).review_remediation(item_id, req)


# ---------------------------------------------------------------- 删除请求
# 幂等键全局唯一而主体锁按主体分区：不同主体并发使用同一幂等键时可能撞上
# deletion_requests_idem_uidx，回滚新事务重试即可（同任务登记的
# receipts_pkey 处理）。
_DELETION_MAX_ATTEMPTS = 5


@app.post("/deletion-requests", status_code=201, tags=["deletion"])
def create_deletion_request(req: DeletionRequestCreate,
                            idempotency_key: Optional[str] = Header(
                                None, alias="Idempotency-Key")):
    """幂等登记删除请求并生成删除计划（不真实执行删除）。

    目标范围仍有活动许可或未结处置时登记为 blocked 并返回可定位的
    阻断原因；否则生成下游先删、同层稳定排序的删除批次并记录
    basis_seq。同一 Idempotency-Key 重放返回原计划；负载不同则 409。
    """
    key = idempotency_key or ""
    for attempt in range(1, _DELETION_MAX_ATTEMPTS + 1):
        try:
            with transaction(lock_subject=req.subject_id) as conn:
                result = Service(conn).create_deletion_request(key, req)
            break
        except psycopg.errors.UniqueViolation as exc:
            if (exc.diag.constraint_name != "deletion_requests_idem_uidx"
                    or attempt == _DELETION_MAX_ATTEMPTS):
                raise
            # 跨主体的同键并发事务抢先提交：整笔事务已回滚，带新快照重试。
    if result["idempotent_replay"]:
        return JSONResponse(status_code=200, content=result)
    return result


@app.get("/deletion-requests/{request_id}", tags=["deletion"])
def get_deletion_request(request_id: int):
    """查询删除计划。

    复用登记时保存的范围 / 下游闭包回执，按当前事件重放与处置台账状态
    重新派生结论并与历史结论比较：结论变化（许可 / 撤销改变阻断，或处置
    提交获批 / 取消结案解除阻断）时标记 stale 并要求用新幂等键重新评估；
    历史状态、批次与阻断原因从不改写。
    """
    with transaction(read_only=True) as conn:
        return Service(conn).get_deletion_request(request_id)


# ---------------------------------------------------------------- 合规证明
# 幂等键全局唯一而主体锁按主体分区：不同主体并发使用同一幂等键时可能撞上
# attestations_idem_uidx，回滚新事务重试即可（同任务登记的 receipts_pkey
# 处理）。
_ATTESTATION_MAX_ATTEMPTS = 5


@app.post("/attestations", status_code=201, tags=["attestations"])
def create_attestation(req: AttestationCreate,
                       idempotency_key: Optional[str] = Header(
                           None, alias="Idempotency-Key")):
    """幂等生成合规证明。

    在主体咨询锁保护的同一 REPEATABLE READ 快照内重放许可、撤销、回执
    血缘、处置状态与删除结论，生成只含稳定标识与依据的规范化 JSON 声明；
    声明按固定字段序列化，保存 SHA-256 摘要与本地密钥 HMAC-SHA256 签名，
    返回可独立验签的字节。同键同内容重放原证明，异内容 409；后续事件
    追加不改写既有证明。
    """
    key = idempotency_key or ""
    for attempt in range(1, _ATTESTATION_MAX_ATTEMPTS + 1):
        try:
            with transaction(lock_subject=req.subject_id) as conn:
                result = Service(conn).create_attestation(
                    key, req, hmac_key=config.ATTESTATION_HMAC_KEY)
            break
        except psycopg.errors.UniqueViolation as exc:
            if (exc.diag.constraint_name != "attestations_idem_uidx"
                    or attempt == _ATTESTATION_MAX_ATTEMPTS):
                raise
            # 跨主体的同键并发事务抢先提交：整笔事务已回滚，带新快照重试。
    if result["idempotent_replay"]:
        return JSONResponse(status_code=200, content=result)
    return result


# 注意：/attestations/verify 必须声明在 /attestations/{attestation_id} 之前，
# 否则 "verify" 会匹配整型路径参数（FastAPI 按声明顺序匹配）。
@app.post("/attestations/verify", tags=["attestations"])
def verify_attestation(req: AttestationVerifyRequest):
    """独立验签：只依赖声明、摘要、签名与配置密钥，不读取业务状态 / 数据库。

    返回 ``valid``（摘要与签名均通过）、``digest_ok``、``signature_ok``
    与重算摘要。声明字节可直接提交 ``claim_canonical``（GET/POST 返回的
    规范字符串原样参与），或提交 ``claim`` 对象由服务端按固定字段重新
    规范化。篡改任一字节、摘要不匹配或密钥不符时相应字段为 false。
    """
    if req.alg is not None and req.alg != attestation_mod.SIGNATURE_ALG:
        raise unprocessable(
            f"不支持的签名算法: {req.alg}（仅 {attestation_mod.SIGNATURE_ALG}）")
    try:
        claim_bytes = attestation_mod.resolve_claim_bytes(
            claim=req.claim, claim_canonical=req.claim_canonical)
        result = attestation_mod.verify_bundle(
            claim_bytes=claim_bytes, digest_hex=req.digest,
            signature_hex=req.signature, key=config.ATTESTATION_HMAC_KEY)
    except attestation_mod.AttestationFormatError as exc:
        raise unprocessable(str(exc))
    return result


@app.get("/attestations/{attestation_id}", tags=["attestations"])
def get_attestation(attestation_id: int):
    """取回既有合规证明（保存的字节 / 摘要 / 签名；不按当前状态重放）。"""
    with transaction(read_only=True) as conn:
        return Service(conn).get_attestation(attestation_id)
