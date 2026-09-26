"""PostgreSQL 连接管理：psycopg3 连接池 + 启动建表。

psycopg3 的事务属性（隔离级别、只读）是**连接属性**，必须在事务开始前
设置在连接上，``Connection.transaction()`` 本身只接受
``savepoint_name`` / ``force_rollback``（不同于 psycopg2 的
``set_isolation_level`` / ``transaction(isolation_level=...)`` 写法）。
``transaction()`` 上下文统一在 :func:`transaction` 中设置这些属性并在
事务结束、连接归还连接池前恢复，避免只读 / 隔离级别属性泄漏给复用同一
连接的后续请求。

同主体写串行化（锁先于快照）
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
REPEATABLE READ 的快照在事务内**第一条语句**执行时即建立。若在事务内用
``SELECT pg_advisory_xact_lock(...)`` 取锁，快照会在**真正拿到锁之前**就
固定：排队期间其他事务提交的撤销 / 回执对该事务不可见，导致撤销的
``affected_receipts`` 漏数、任务登记沿用旧许可。

因此 :func:`transaction` 支持 ``lock_subject``：在事务开始**之前**于连接上
获取**会话级**咨询锁 ``pg_advisory_lock(hashtext(subject_id))``（会话级锁
跨事务持有，与事务级咨询锁共用同一锁空间、互相排斥），随后才开启
REPEATABLE READ 事务——快照在持锁之后建立，同主体写入按锁获取顺序读取
各自已提交状态。事务提交 / 回滚后、连接归还连接池前释放该锁。
"""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from . import config

pool: ConnectionPool | None = None

_SCHEMA_PATH = Path(__file__).resolve().parent.parent / "sql" / "schema.sql"

# 会话级咨询锁：与 pg_advisory_xact_lock 共用同一锁空间，但跨事务持有，
# 可在事务（快照）开始前获取、提交 / 回滚后释放。
LOCK_SUBJECT_SQL = "SELECT pg_advisory_lock(hashtext(%s))"
# 归还连接前释放本会话持有的全部咨询锁，避免泄漏给复用该连接的后续请求。
UNLOCK_ALL_SQL = "SELECT pg_advisory_unlock_all()"


def init_pool() -> ConnectionPool:
    global pool
    if pool is None:
        pool = ConnectionPool(
            config.DATABASE_URL,
            min_size=config.DB_POOL_MIN,
            max_size=config.DB_POOL_MAX,
            kwargs={"row_factory": dict_row},
            open=True,
        )
        # 等待数据库就绪（compose 下应用可能先于数据库启动）。
        for attempt in range(60):
            try:
                with pool.connection() as conn:
                    conn.execute("SELECT 1")
                break
            except psycopg.OperationalError:
                if attempt == 59:
                    raise
                import time
                time.sleep(1)
        if config.AUTO_SCHEMA:
            apply_schema()
    return pool


def apply_schema() -> None:
    sql = _SCHEMA_PATH.read_text(encoding="utf-8")
    assert pool is not None
    with pool.connection() as conn:
        conn.execute(sql)
        conn.commit()


@contextmanager
def transaction(*, read_only: bool = False,
                isolation_level: psycopg.IsolationLevel =
                psycopg.IsolationLevel.REPEATABLE_READ,
                lock_subject: Optional[str] = None) -> Iterator[
                    psycopg.Connection]:
    """从连接池取连接并以 psycopg3 正确方式开启事务。

    * 隔离级别 / 只读属性在事务开始**前**设置到连接上，psycopg3 会据此
      发出 ``BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY/READ WRITE``；
    * 传入 ``lock_subject`` 时，先在事务**之外**获取该主体的会话级咨询锁
      （独立的短隐式事务，立即提交；锁本身由会话持有，不随提交释放），
      再开启 REPEATABLE READ 事务——保证事务快照建立在拿到主体锁之后，
      同主体写入严格按锁获取顺序看到彼此已提交的状态；
    * 连接在连接池中的获取 / 归还语义不变：正常退出提交，异常回滚；
    * 退出时把连接属性恢复为服务端默认（``None``）并释放会话级咨询锁，
      防止污染复用该连接的后续请求（例如只读属性泄漏导致后续写事务失败，
      或咨询锁泄漏导致同主体写入被永久阻塞）。
    """
    assert pool is not None, "连接池尚未初始化"
    with pool.connection() as conn:
        try:
            if lock_subject is not None:
                # 锁先于快照：pg_advisory_lock 在事务外获取并立即提交该
                # 隐式事务；会话级锁跨事务持有，直到下方显式释放。
                conn.execute(LOCK_SUBJECT_SQL, (lock_subject,))
                conn.commit()
            conn.isolation_level = isolation_level
            conn.read_only = read_only
            with conn.transaction():
                yield conn
        finally:
            # 仅在连接空闲（事务已提交 / 回滚）时恢复，psycopg3 不允许
            # 在事务进行中修改这些属性。
            if conn.pgconn.transaction_status == psycopg.pq.TransactionStatus.IDLE:
                conn.isolation_level = None
                conn.read_only = None
                if lock_subject is not None:
                    conn.execute(UNLOCK_ALL_SQL)
                    conn.commit()


def shutdown_pool() -> None:
    global pool
    if pool is not None:
        pool.close()
        pool = None
