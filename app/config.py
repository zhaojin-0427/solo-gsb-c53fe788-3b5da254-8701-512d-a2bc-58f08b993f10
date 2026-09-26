"""运行配置（全部可通过环境变量覆盖）。"""
from __future__ import annotations

import os
from urllib.parse import quote_plus


def _database_url() -> str:
    explicit = os.getenv("DATABASE_URL")
    if explicit:
        return explicit
    user = os.getenv("POSTGRES_USER", "consent")
    password = quote_plus(os.getenv("POSTGRES_PASSWORD", "consent"))
    db = os.getenv("POSTGRES_DB", "consent")
    host = os.getenv("POSTGRES_HOST", "db")
    port = os.getenv("POSTGRES_PORT", "5432")
    return f"postgresql://{user}:{password}@{host}:{port}/{db}"


DATABASE_URL = _database_url()
DB_POOL_MIN = int(os.getenv("DB_POOL_MIN", "1"))
DB_POOL_MAX = int(os.getenv("DB_POOL_MAX", "10"))
# 启动时建表（幂等 CREATE IF NOT EXISTS）。
AUTO_SCHEMA = os.getenv("AUTO_SCHEMA", "1") != "0"

# ---------------------------------------------------------------- 处置台账令牌
# 本地配置的访问令牌（生产部署务必通过环境变量覆盖默认值）：
#   REMEDIATION_ADMIN_TOKEN       管理员令牌（执行复核）；
#   REMEDIATION_RECIPIENT_TOKENS  接收方令牌，格式 “接收方=令牌,接收方2=令牌2”。
ADMIN_TOKEN = os.getenv("REMEDIATION_ADMIN_TOKEN", "dev-admin-token")


def _recipient_tokens() -> dict[str, str]:
    """解析接收方令牌配置，返回 令牌 -> 接收方 映射。"""
    raw = os.getenv("REMEDIATION_RECIPIENT_TOKENS",
                    "partner-a=dev-token-a,partner-b=dev-token-b")
    tokens: dict[str, str] = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair:
            continue
        recipient, sep, token = pair.partition("=")
        recipient, token = recipient.strip(), token.strip()
        if not sep or not recipient or not token:
            raise ValueError(
                "REMEDIATION_RECIPIENT_TOKENS 格式应为 '接收方=令牌,...'，"
                f"得到片段: {pair!r}")
        tokens[token] = recipient
    return tokens


RECIPIENT_TOKENS = _recipient_tokens()

# ---------------------------------------------------------------- 合规证明密钥
# 合规证明声明的 HMAC-SHA256 签名密钥（本地配置；仅服务端持有）。
# 验签只依赖声明字节、摘要、签名与此密钥（ATTESTATION_HMAC_KEY），
# 不读取数据库或任何可变业务状态。生产部署务必通过环境变量覆盖默认值：
# 更换密钥后旧签名无法通过新密钥验签（反之亦然）。
ATTESTATION_HMAC_KEY = os.getenv(
    "ATTESTATION_HMAC_KEY", "dev-attestation-hmac-key")
