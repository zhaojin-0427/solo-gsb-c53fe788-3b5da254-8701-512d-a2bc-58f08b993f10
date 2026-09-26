"""数据访问层：只追加（INSERT）的 PostgreSQL 读写。"""
from __future__ import annotations

from typing import Optional

import psycopg

from .domain import Event


def _iso(dt) -> Optional[str]:
    return dt.isoformat() if dt is not None else None


def event_from_row(row) -> Event:
    return Event(
        seq=row["seq"],
        subject_id=row["subject_id"],
        event_type=row["event_type"],
        grant_id=row["grant_id"],
        category=row["category"],
        purpose=row["purpose"],
        recipient=row["recipient"],
        valid_from=_iso(row["valid_from"]),
        valid_to=_iso(row["valid_to"]),
        revoke_grant=row["revoke_grant"],
        business_effective_at=_iso(row["business_effective_at"]),
        recorded_at=_iso(row["recorded_at"]),
    )


class Repo:
    def __init__(self, conn):
        self.conn = conn

    # ----------------------------------------------------------- 事件追加
    def insert_grant(self, *, subject_id, grant_id, category, purpose,
                     recipient, valid_from, valid_to, recorded_at) -> dict:
        try:
            row = self.conn.execute(
                """
                INSERT INTO events
                  (subject_id, event_type, grant_id, category, purpose,
                   recipient, valid_from, valid_to, revoke_grant,
                   business_effective_at, recorded_at)
                VALUES (%s, 'grant', %s, %s, %s, %s, %s, %s, NULL, NULL, %s)
                RETURNING *
                """,
                (subject_id, grant_id, category, purpose, recipient,
                 valid_from, valid_to, recorded_at),
            ).fetchone()
        except psycopg.errors.UniqueViolation as e:
            _raise_duplicate_grant(e)
        return row

    def find_grant(self, subject_id: str, grant_id: str) -> Optional[dict]:
        return self.conn.execute(
            """SELECT * FROM events
               WHERE subject_id=%s AND grant_id=%s AND event_type='grant'""",
            (subject_id, grant_id),
        ).fetchone()

    def insert_revocation(self, *, subject_id, grant_id,
                          business_effective_at, recorded_at) -> dict:
        return self.conn.execute(
            """
            INSERT INTO events
              (subject_id, event_type, grant_id, category, purpose,
               recipient, valid_from, valid_to, revoke_grant,
               business_effective_at, recorded_at)
            VALUES (%s, 'revocation', %s, NULL, NULL, NULL, NULL, NULL,
                    %s, %s, %s)
            RETURNING *
            """,
            (subject_id, grant_id, grant_id, business_effective_at,
             recorded_at),
        ).fetchone()

    def list_events(self, subject_id: str,
                    as_of_seq: Optional[int] = None) -> list[dict]:
        if as_of_seq is not None:
            return self.conn.execute(
                "SELECT * FROM events WHERE subject_id=%s AND seq<=%s ORDER BY seq",
                (subject_id, as_of_seq)).fetchall()
        return self.conn.execute(
            "SELECT * FROM events WHERE subject_id=%s ORDER BY seq",
            (subject_id,)).fetchall()

    def max_event_seq(self) -> int:
        """全部主体的最大事件录入序号（无事件返回 0）。

        合规证明的 as_of_seq 上界校验依赖它：序号是全局单调序号，
        “未来序号”在任何主体的快照中都无意义，必须拒绝。
        """
        row = self.conn.execute(
            "SELECT COALESCE(max(seq), 0) AS max_seq FROM events").fetchone()
        return row["max_seq"]

    # ----------------------------------------------------------- 回执
    def get_receipt(self, key: str) -> Optional[dict]:
        return self.conn.execute(
            "SELECT * FROM receipts WHERE idempotency_key=%s", (key,)
        ).fetchone()

    def get_receipts_for_subject(self, subject_id: str) -> list[dict]:
        return self.conn.execute(
            "SELECT * FROM receipts WHERE subject_id=%s", (subject_id,)
        ).fetchall()

    def insert_receipt(self, *, key, subject_id, category, purpose, recipient,
                       use_at, decided_at, decision, basis_grant_id, basis_seq,
                       basis_reason, fingerprint, recorded_seq, recorded_at):
        return self.conn.execute(
            """
            INSERT INTO receipts
              (idempotency_key, subject_id, category, purpose, recipient,
               use_at, decided_at, decision, basis_grant_id, basis_seq,
               basis_reason, request_fingerprint, recorded_seq, recorded_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            RETURNING *
            """,
            (key, subject_id, category, purpose, recipient, use_at,
             decided_at, decision, basis_grant_id, basis_seq, basis_reason,
             fingerprint, recorded_seq, recorded_at),
        ).fetchone()

    # ----------------------------------------------------------- 产物 / 血缘
    def insert_product(self, *, subject_id, product_id, task_key, description,
                       recorded_seq, recorded_at):
        try:
            row = self.conn.execute(
                """
                INSERT INTO products
                  (subject_id, product_id, task_key, description,
                   recorded_seq, recorded_at)
                VALUES (%s,%s,%s,%s,%s,%s)
                RETURNING *
                """,
                (subject_id, product_id, task_key, description,
                 recorded_seq, recorded_at),
            ).fetchone()
        except psycopg.errors.UniqueViolation as e:
            _raise_duplicate_product(e)
        return row

    def insert_group(self, subject_id: str, product_id: str, ord_: int) -> int:
        return self.conn.execute(
            """INSERT INTO product_groups (subject_id, product_id, ord)
               VALUES (%s,%s,%s) RETURNING group_id""",
            (subject_id, product_id, ord_),
        ).fetchone()["group_id"]

    def insert_input(self, group_id: int, ord_: int, kind: str, ref: str):
        self.conn.execute(
            """INSERT INTO group_inputs (group_id, ord, input_kind, input_ref)
               VALUES (%s,%s,%s,%s)""",
            (group_id, ord_, kind, ref),
        )

    def list_products_for_subject(self, subject_id: str) -> list[dict]:
        return self.conn.execute(
            "SELECT * FROM products WHERE subject_id=%s ORDER BY product_id",
            (subject_id,)).fetchall()

    def list_groups(self, subject_id: str) -> list[dict]:
        return self.conn.execute(
            "SELECT * FROM product_groups WHERE subject_id=%s ORDER BY product_id, ord",
            (subject_id,)).fetchall()

    def list_inputs_for_groups(self, group_ids: list[int]) -> list[dict]:
        if not group_ids:
            return []
        return self.conn.execute(
            "SELECT * FROM group_inputs WHERE group_id = ANY(%s) ORDER BY group_id, ord",
            (group_ids,)).fetchall()

    def list_products_by_task(self, task_key: str) -> list[dict]:
        return self.conn.execute(
            "SELECT * FROM products WHERE task_key=%s ORDER BY product_id",
            (task_key,)).fetchall()

    # ----------------------------------------------------------- 处置台账
    def insert_remediation_item(self, *, subject_id, receipt_key, recipient,
                                revocation_seq, opened_at) -> int:
        return self.conn.execute(
            """
            INSERT INTO remediation_items
              (subject_id, receipt_key, recipient, revocation_seq, opened_at)
            VALUES (%s,%s,%s,%s,%s)
            RETURNING item_id
            """,
            (subject_id, receipt_key, recipient, revocation_seq, opened_at),
        ).fetchone()["item_id"]

    def insert_remediation_item_product(self, item_id: int,
                                         product_id: str) -> None:
        self.conn.execute(
            """INSERT INTO remediation_item_products (item_id, product_id)
               VALUES (%s,%s)""",
            (item_id, product_id))

    def insert_remediation_cancellation(self, *, item_id, grant_seq,
                                         cancelled_at) -> None:
        self.conn.execute(
            """
            INSERT INTO remediation_cancellations
              (item_id, grant_seq, cancelled_at)
            VALUES (%s,%s,%s)
            """,
            (item_id, grant_seq, cancelled_at))

    def get_remediation_item(self, item_id: int) -> Optional[dict]:
        return self.conn.execute(
            "SELECT * FROM remediation_items WHERE item_id=%s", (item_id,)
        ).fetchone()

    def list_remediation_items(self, subject_id: str) -> list[dict]:
        return self.conn.execute(
            """SELECT * FROM remediation_items
               WHERE subject_id=%s ORDER BY item_id""",
            (subject_id,)).fetchall()

    def list_remediation_item_products(self, item_ids: list[int]) -> list[dict]:
        if not item_ids:
            return []
        return self.conn.execute(
            """SELECT * FROM remediation_item_products
               WHERE item_id = ANY(%s) ORDER BY item_id, product_id""",
            (item_ids,)).fetchall()

    def list_remediation_submissions(self, item_ids: list[int]) -> list[dict]:
        if not item_ids:
            return []
        return self.conn.execute(
            """SELECT * FROM remediation_submissions
               WHERE item_id = ANY(%s) ORDER BY item_id, version""",
            (item_ids,)).fetchall()

    def list_remediation_reviews(self, item_ids: list[int]) -> list[dict]:
        if not item_ids:
            return []
        return self.conn.execute(
            """SELECT * FROM remediation_reviews
               WHERE item_id = ANY(%s) ORDER BY item_id, version""",
            (item_ids,)).fetchall()

    def list_remediation_cancellations(self, item_ids: list[int]) -> list[dict]:
        if not item_ids:
            return []
        return self.conn.execute(
            """SELECT * FROM remediation_cancellations
               WHERE item_id = ANY(%s)""",
            (item_ids,)).fetchall()

    def get_submission_by_key(self, key: str) -> Optional[dict]:
        return self.conn.execute(
            "SELECT * FROM remediation_submissions WHERE idempotency_key=%s",
            (key,)).fetchone()

    def insert_remediation_submission(self, *, item_id, version,
                                      idempotency_key, cease_declaration,
                                      evidence_json, fingerprint, submitted_by,
                                      submitted_at) -> dict:
        return self.conn.execute(
            """
            INSERT INTO remediation_submissions
              (item_id, version, idempotency_key, cease_declaration, evidence,
               request_fingerprint, submitted_by, submitted_at)
            VALUES (%s,%s,%s,%s,%s::jsonb,%s,%s,%s)
            RETURNING *
            """,
            (item_id, version, idempotency_key, cease_declaration,
             evidence_json, fingerprint, submitted_by, submitted_at),
        ).fetchone()

    def insert_remediation_review(self, *, item_id, version, action, comment,
                                   reviewed_at) -> dict:
        return self.conn.execute(
            """
            INSERT INTO remediation_reviews
              (item_id, version, action, comment, reviewed_at)
            VALUES (%s,%s,%s,%s,%s)
            RETURNING *
            """,
            (item_id, version, action, comment, reviewed_at),
        ).fetchone()

    # ----------------------------------------------------------- 删除请求
    def insert_deletion_request(self, *, key, subject_id, product_ids_json,
                                scope_json, requested_at, status, basis_seq,
                                fingerprint, created_at) -> dict:
        return self.conn.execute(
            """
            INSERT INTO deletion_requests
              (idempotency_key, subject_id, product_ids, scope, requested_at,
               status, basis_seq, request_fingerprint, created_at)
            VALUES (%s,%s,%s::jsonb,%s::jsonb,%s,%s,%s,%s,%s)
            RETURNING *
            """,
            (key, subject_id, product_ids_json, scope_json, requested_at,
             status, basis_seq, fingerprint, created_at),
        ).fetchone()

    def get_deletion_request(self, request_id: int) -> Optional[dict]:
        return self.conn.execute(
            "SELECT * FROM deletion_requests WHERE request_id=%s",
            (request_id,)).fetchone()

    def get_deletion_request_by_key(self, key: str) -> Optional[dict]:
        return self.conn.execute(
            "SELECT * FROM deletion_requests WHERE idempotency_key=%s",
            (key,)).fetchone()

    def insert_deletion_batch(self, *, request_id, batch_no,
                              product_id) -> None:
        self.conn.execute(
            """INSERT INTO deletion_batches (request_id, batch_no, product_id)
               VALUES (%s,%s,%s)""",
            (request_id, batch_no, product_id))

    def list_deletion_batches(self, request_id: int) -> list[dict]:
        return self.conn.execute(
            """SELECT * FROM deletion_batches
               WHERE request_id=%s ORDER BY batch_no, product_id""",
            (request_id,)).fetchall()

    def insert_deletion_blocker(self, *, request_id, ord_, kind,
                                detail_json) -> None:
        self.conn.execute(
            """INSERT INTO deletion_blockers (request_id, ord, kind, detail)
               VALUES (%s,%s,%s,%s::jsonb)""",
            (request_id, ord_, kind, detail_json))

    def list_deletion_blockers(self, request_id: int) -> list[dict]:
        return self.conn.execute(
            """SELECT * FROM deletion_blockers
               WHERE request_id=%s ORDER BY ord""",
            (request_id,)).fetchall()

    # ----------------------------------------------------------- 合规证明
    def insert_attestation(self, *, key, subject_id, use_at, as_of_seq,
                           basis_seq, claim_bytes, claim_json, claim_digest,
                           claim_signature, fingerprint, created_at) -> dict:
        return self.conn.execute(
            """
            INSERT INTO attestations
              (idempotency_key, subject_id, use_at, as_of_seq, basis_seq,
               claim_bytes, claim, claim_digest, claim_signature,
               signature_alg, request_fingerprint, created_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s,'HMAC-SHA256',%s,%s)
            RETURNING *
            """,
            (key, subject_id, use_at, as_of_seq, basis_seq, claim_bytes,
             claim_json, claim_digest, claim_signature, fingerprint,
             created_at),
        ).fetchone()

    def get_attestation(self, attestation_id: int) -> Optional[dict]:
        return self.conn.execute(
            "SELECT * FROM attestations WHERE attestation_id=%s",
            (attestation_id,)).fetchone()

    def get_attestation_by_key(self, key: str) -> Optional[dict]:
        return self.conn.execute(
            "SELECT * FROM attestations WHERE idempotency_key=%s",
            (key,)).fetchone()


def _raise_duplicate_grant(exc):
    # 延迟导入以避免循环依赖。
    from .errors import conflict
    raise conflict("grant_id 已存在于该主体（许可不可改写）") from exc


def _raise_duplicate_product(exc):
    from .errors import conflict
    raise conflict("product_id 已存在于该主体（产物登记不可改写）") from exc
