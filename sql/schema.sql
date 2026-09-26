-- 可撤回数据用途许可与派生阻断 API —— 数据库结构
-- 设计要点：
--   * 所有写入均为 INSERT（append-only），不存在 UPDATE / DELETE，历史不可改写。
--   * events 是许可与撤销的唯一追加事件登记处，seq 为不可变录入序号（单调递增）。
--   * 许可有效区间为半开区间 [valid_from, valid_to)：valid_to 为 NULL 表示开放。
--   *  receipts / products / product_groups / group_inputs 只追加登记
--     决策回执、派生产物、替代依据组及其血缘输入；当前状态由事件重放派生。

CREATE TABLE IF NOT EXISTS events (
    seq          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    subject_id   TEXT        NOT NULL,
    event_type   TEXT        NOT NULL CHECK (event_type IN ('grant', 'revocation')),
    grant_id     TEXT        NOT NULL,
    category     TEXT,
    purpose      TEXT,
    recipient    TEXT,
    valid_from   TIMESTAMPTZ,
    valid_to     TIMESTAMPTZ,
    revoke_grant TEXT,
    business_effective_at TIMESTAMPTZ,
    recorded_at  TIMESTAMPTZ NOT NULL
);

-- 同一主体下 grant_id 唯一：撤销通过 grant_id 定位许可。
CREATE UNIQUE INDEX IF NOT EXISTS events_grant_uidx
    ON events (subject_id, grant_id)
    WHERE event_type = 'grant';

-- 重放查询：按主体取出按序号排列的事件。
CREATE INDEX IF NOT EXISTS events_subject_seq_idx
    ON events (subject_id, seq);
-- 撤销传播 / 事件列表：按录入时间过滤 as_of。
CREATE INDEX IF NOT EXISTS events_recorded_idx
    ON events (recorded_at);

-- 决策回执（幂等键 = 任务回执键；内容不可变，状态随时由事件重放重新判定）。
CREATE TABLE IF NOT EXISTS receipts (
    idempotency_key TEXT PRIMARY KEY,
    subject_id      TEXT        NOT NULL,
    category        TEXT        NOT NULL,
    purpose         TEXT        NOT NULL,
    recipient       TEXT        NOT NULL,
    use_at          TIMESTAMPTZ NOT NULL,
    decided_at      TIMESTAMPTZ NOT NULL,
    decision        TEXT        NOT NULL CHECK (decision IN ('allow', 'deny')),
    basis_grant_id  TEXT,
    basis_seq       BIGINT,
    basis_reason    TEXT        NOT NULL,
    request_fingerprint TEXT    NOT NULL,
    recorded_seq    BIGINT      NOT NULL,
    recorded_at     TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS receipts_subject_idx
    ON receipts (subject_id);

-- 派生产物（每个任务批次内可声明多个）。
CREATE TABLE IF NOT EXISTS products (
    subject_id   TEXT        NOT NULL,
    product_id   TEXT        NOT NULL,
    task_key     TEXT        NOT NULL REFERENCES receipts(idempotency_key),
    description  TEXT,
    recorded_seq BIGINT      NOT NULL,
    recorded_at  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (subject_id, product_id)
);
CREATE INDEX IF NOT EXISTS products_task_idx
    ON products (task_key);

-- 一个产物可有多组替代依据；任一组成立则产物存活，全部失效才阻断。
CREATE TABLE IF NOT EXISTS product_groups (
    group_id     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    subject_id   TEXT        NOT NULL,
    product_id   TEXT        NOT NULL,
    ord          INTEGER     NOT NULL,
    FOREIGN KEY (subject_id, product_id)
        REFERENCES products (subject_id, product_id) ON DELETE CASCADE,
    UNIQUE (subject_id, product_id, ord)
);
CREATE INDEX IF NOT EXISTS product_groups_product_idx
    ON product_groups (subject_id, product_id);

-- 血缘 DAG 的边：依据组 -> 输入（决策回执或上游产物），全部同主体。
CREATE TABLE IF NOT EXISTS group_inputs (
    group_id     BIGINT      NOT NULL REFERENCES product_groups(group_id) ON DELETE CASCADE,
    ord          INTEGER     NOT NULL,
    input_kind   TEXT        NOT NULL CHECK (input_kind IN ('receipt', 'product')),
    input_ref    TEXT        NOT NULL,
    PRIMARY KEY (group_id, ord)
);
CREATE INDEX IF NOT EXISTS group_inputs_ref_idx
    ON group_inputs (input_kind, input_ref);

-- ---------------------------------------------------------------- 撤销处置台账
-- 追溯撤销使 allow 回执由有效转为失效时，在同一事务内开立处置项；
-- 处置项归属回执的接收方。全部表只追加：状态（open/submitted/rejected/
-- approved/cancelled）由这些记录派生，结案不改写任何既有行。
CREATE TABLE IF NOT EXISTS remediation_items (
    item_id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    subject_id     TEXT        NOT NULL,
    receipt_key    TEXT        NOT NULL REFERENCES receipts(idempotency_key),
    recipient      TEXT        NOT NULL,
    revocation_seq BIGINT      NOT NULL,  -- 开立依据的撤销事件序号
    opened_at      TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS remediation_items_subject_idx
    ON remediation_items (subject_id);
CREATE INDEX IF NOT EXISTS remediation_items_receipt_idx
    ON remediation_items (receipt_key);

-- 处置项关联的产物：沿该回执血缘在本次撤销中转为阻断的产物。
CREATE TABLE IF NOT EXISTS remediation_item_products (
    item_id    BIGINT NOT NULL REFERENCES remediation_items(item_id),
    product_id TEXT   NOT NULL,
    PRIMARY KEY (item_id, product_id)
);

-- 接收方提交：停止使用声明 + 关联产物的清除证据摘要（按版本追加）。
-- 幂等键全局唯一：同键同内容重放返回原结果，同键不同内容拒绝。
CREATE TABLE IF NOT EXISTS remediation_submissions (
    submission_id  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    item_id        BIGINT NOT NULL REFERENCES remediation_items(item_id),
    version        INTEGER NOT NULL,
    idempotency_key TEXT   NOT NULL,
    cease_declaration TEXT NOT NULL,
    evidence       JSONB   NOT NULL,  -- [{"product_id", "summary"}]
    request_fingerprint TEXT NOT NULL,
    submitted_by   TEXT    NOT NULL,
    submitted_at   TIMESTAMPTZ NOT NULL,
    UNIQUE (item_id, version),
    CONSTRAINT remediation_submissions_idem_uidx UNIQUE (idempotency_key)
);

-- 复核决定：按提交版本批准 / 驳回，每个版本至多一条，追加保存。
CREATE TABLE IF NOT EXISTS remediation_reviews (
    review_id  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    item_id    BIGINT NOT NULL REFERENCES remediation_items(item_id),
    version    INTEGER NOT NULL,
    action     TEXT   NOT NULL CHECK (action IN ('approved', 'rejected')),
    comment    TEXT,
    reviewed_at TIMESTAMPTZ NOT NULL,
    UNIQUE (item_id, version)
);

-- 后续许可使回执恢复有效时取消未结处置项（追加取消记录，不改写处置项）。
CREATE TABLE IF NOT EXISTS remediation_cancellations (
    item_id      BIGINT PRIMARY KEY REFERENCES remediation_items(item_id),
    grant_seq    BIGINT NOT NULL,  -- 使回执恢复有效的许可事件序号
    cancelled_at TIMESTAMPTZ NOT NULL
);

-- ---------------------------------------------------------------- 删除请求与删除计划
-- 删除请求以幂等键登记，内容不可变；评估结果（删除批次 / 阻断原因）随请求
-- 一并只追加保存。查询时按 basis_seq 与当前事件序号比较即时派生“过期”标记，
-- 从不改写历史计划，也从不真实执行删除。
CREATE TABLE IF NOT EXISTS deletion_requests (
    request_id      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    idempotency_key TEXT        NOT NULL,
    subject_id      TEXT        NOT NULL,
    product_ids     JSONB       NOT NULL,  -- 归一化请求范围（排序去重；[] = 主体全部产物）
    scope           JSONB       NOT NULL,  -- 登记时锁定的实际删除范围（含传递下游）
    requested_at    TIMESTAMPTZ NOT NULL,  -- 客户端请求时间
    status          TEXT        NOT NULL CHECK (status IN ('planned', 'blocked')),
    basis_seq       BIGINT      NOT NULL,  -- 登记时主体事件序号快照
    request_fingerprint TEXT    NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL,
    CONSTRAINT deletion_requests_idem_uidx UNIQUE (idempotency_key)
);
CREATE INDEX IF NOT EXISTS deletion_requests_subject_idx
    ON deletion_requests (subject_id);

-- 删除批次：按依赖反向拓扑（下游先删），同批内按 product_id 字典序稳定排序。
CREATE TABLE IF NOT EXISTS deletion_batches (
    request_id BIGINT  NOT NULL REFERENCES deletion_requests(request_id),
    batch_no   INTEGER NOT NULL,
    product_id TEXT    NOT NULL,
    PRIMARY KEY (request_id, batch_no, product_id)
);

-- 阻断原因（可定位）：active_grant（活动许可）/ open_remediation（未结处置）。
CREATE TABLE IF NOT EXISTS deletion_blockers (
    request_id BIGINT  NOT NULL REFERENCES deletion_requests(request_id),
    ord        INTEGER NOT NULL,
    kind       TEXT    NOT NULL CHECK (kind IN ('active_grant', 'open_remediation')),
    detail     JSONB   NOT NULL,
    PRIMARY KEY (request_id, ord)
);

-- ---------------------------------------------------------------- 合规证明
-- 合规证明以幂等键登记，内容只追加、永不变。证明在主体咨询锁保护的
-- REPEATABLE READ 快照中一次性重放许可 / 撤销 / 回执血缘 / 处置状态 /
-- 删除结论生成；声明按固定字段规范序列化（claim_bytes 原样保存，绝不经
-- JSONB 重序列化），同时保存 SHA-256 摘要与本地密钥 HMAC-SHA256 签名。
-- 后续事件追加不影响既有证明：GET 直接返回保存的字节 / 摘要 / 签名，
-- 验签只依赖这些字节与配置密钥，不读取任何可变业务状态。
CREATE TABLE IF NOT EXISTS attestations (
    attestation_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    idempotency_key TEXT        NOT NULL,
    subject_id      TEXT        NOT NULL,
    use_at          TIMESTAMPTZ NOT NULL,  -- 证明锚定的使用时点
    as_of_seq       BIGINT      NOT NULL,  -- 重放上界（固定快照）
    basis_seq       BIGINT      NOT NULL,  -- 生成时主体可见最大事件序号
    claim_bytes     BYTEA       NOT NULL,  -- 规范序列化的声明原文（签名输入）
    claim           JSONB       NOT NULL,  -- 声明内容（仅备查；验签以 claim_bytes 为准）
    claim_digest    TEXT        NOT NULL,  -- SHA-256(claim_bytes) 小写十六进制
    claim_signature TEXT        NOT NULL,  -- HMAC-SHA256(key, claim_bytes)
    signature_alg   TEXT        NOT NULL DEFAULT 'HMAC-SHA256',
    request_fingerprint TEXT    NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL,
    CONSTRAINT attestations_idem_uidx UNIQUE (idempotency_key)
);
CREATE INDEX IF NOT EXISTS attestations_subject_idx
    ON attestations (subject_id);
