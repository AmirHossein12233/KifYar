from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent

DATABASE_PATH = Path(
    os.getenv(
        "KIFYAR_DATABASE_PATH",
        str(BASE_DIR / "kifyar.db"),
    )
)


PASSWORD_ITERATIONS = 120_000


def get_connection() -> sqlite3.Connection:
    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    conn = sqlite3.connect(
        DATABASE_PATH,
        timeout=30,
    )

    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")

    return conn


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_ITERATIONS,
    )

    return (
        f"pbkdf2_sha256${PASSWORD_ITERATIONS}$"
        f"{salt.hex()}${digest.hex()}"
    )


def verify_password(
    password: str,
    stored_hash: str,
) -> bool:

    try:
        algorithm, iterations, salt_hex, digest_hex = (
            stored_hash.split("$")
        )

        if algorithm != "pbkdf2_sha256":
            return False

        iterations = int(iterations)

        salt = bytes.fromhex(salt_hex)

        expected = bytes.fromhex(digest_hex)

        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
        )

        return hmac.compare_digest(
            actual,
            expected,
        )

    except Exception:
        return False


def _ensure_column(
    conn: sqlite3.Connection,
    table: str,
    column: str,
    definition: str,
) -> None:

    columns = conn.execute(
        f"PRAGMA table_info({table})"
    ).fetchall()

    existing = {
        row["name"]
        for row in columns
    }

    if column not in existing:
        conn.execute(
            f"""
            ALTER TABLE {table}
            ADD COLUMN {column} {definition}
            """
        )


def initialize_admin_logs_table() -> None:

    with get_connection() as conn:

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS admin_action_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                transfer_id INTEGER,
                status_before TEXT,
                status_after TEXT,
                amount REAL,
                request_id TEXT,
                created_at TEXT NOT NULL
            )
            """
        )

        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_admin_logs_created
            ON admin_action_logs(created_at DESC)
            """
        )

        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_admin_logs_transfer
            ON admin_action_logs(transfer_id)
            """
        )


def initialize_database() -> None:

    with get_connection() as conn:

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT UNIQUE,
                name TEXT,
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                amount REAL NOT NULL,
                transaction_type TEXT NOT NULL,
                category TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS bank_cards (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                holder_name TEXT NOT NULL,
                bank_name TEXT NOT NULL,
                card_number TEXT NOT NULL,
                is_default INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT,
                FOREIGN KEY(user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS wallet_deposits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                card_id INTEGER NOT NULL,
                amount REAL NOT NULL,
                request_id TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'completed',
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE,
                FOREIGN KEY(card_id)
                    REFERENCES bank_cards(id)
                    ON DELETE CASCADE
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS card_transfers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                card_id INTEGER NOT NULL,
                amount REAL NOT NULL,
                request_id TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE,
                FOREIGN KEY(card_id)
                    REFERENCES bank_cards(id)
                    ON DELETE CASCADE
            )
            """
        )

        _ensure_column(
            conn,
            "users",
            "is_admin",
            "INTEGER NOT NULL DEFAULT 0",
        )

        _ensure_column(
            conn,
            "users",
            "email",
            "TEXT",
        )

        _ensure_column(
            conn,
            "users",
            "name",
            "TEXT",
        )

        _ensure_column(
            conn,
            "users",
            "updated_at",
            "TEXT",
        )

        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_transactions_user_created
            ON transactions(user_id, created_at DESC)
            """
        )

        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_bank_cards_user
            ON bank_cards(user_id)
            """
        )

        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_wallet_deposits_user
            ON wallet_deposits(user_id)
            """
        )

        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_card_transfers_user_status
            ON card_transfers(user_id, status)
            """
        )

        conn.execute(
            """
            UPDATE users
            SET updated_at = created_at
            WHERE updated_at IS NULL
            """
        )

    initialize_admin_logs_table()


# =========================================================
# USERS
# =========================================================

def create_user(
    username: str,
    password: str,
    email: str | None = None,
    name: str | None = None,
) -> int:

    created_at = now_iso()

    password_hash = hash_password(password)

    with get_connection() as conn:

        cursor = conn.execute(
            """
            INSERT INTO users (
                username,
                email,
                name,
                password_hash,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                username,
                email,
                name,
                password_hash,
                created_at,
                created_at,
            ),
        )

        return int(cursor.lastrowid)


def find_user_by_id(
    user_id: int,
) -> dict[str, Any] | None:

    with get_connection() as conn:

        row = conn.execute(
            """
            SELECT *
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()

    return dict(row) if row else None


def find_user_by_username(
    username: str,
) -> dict[str, Any] | None:

    with get_connection() as conn:

        row = conn.execute(
            """
            SELECT *
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()

    return dict(row) if row else None


def find_user_by_email(
    email: str,
) -> dict[str, Any] | None:

    with get_connection() as conn:

        row = conn.execute(
            """
            SELECT *
            FROM users
            WHERE email = ?
            """,
            (email,),
        ).fetchone()

    return dict(row) if row else None


def verify_user_password(
    username: str,
    password: str,
) -> dict[str, Any] | None:

    user = find_user_by_username(username)

    if not user:
        return None

    if not verify_password(
        password,
        user["password_hash"],
    ):
        return None

    return user


def update_user_name(
    user_id: int,
    name: str,
) -> bool:

    with get_connection() as conn:

        cursor = conn.execute(
            """
            UPDATE users
            SET name = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                name,
                now_iso(),
                user_id,
            ),
        )

    return cursor.rowcount > 0


def update_user_password(
    user_id: int,
    new_password: str,
) -> bool:

    password_hash = hash_password(
        new_password
    )

    with get_connection() as conn:

        cursor = conn.execute(
            """
            UPDATE users
            SET password_hash = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                password_hash,
                now_iso(),
                user_id,
            ),
        )

    return cursor.rowcount > 0


def delete_user(
    user_id: int,
) -> bool:

    with get_connection() as conn:

        cursor = conn.execute(
            """
            DELETE FROM users
            WHERE id = ?
            """,
            (user_id,),
        )

    return cursor.rowcount > 0


# =========================================================
# ADMIN USERS
# =========================================================

def is_user_admin(
    user_id: int,
) -> bool:

    with get_connection() as conn:

        row = conn.execute(
            """
            SELECT is_admin
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()

    return bool(row["is_admin"]) if row else False


def set_user_admin(
    user_id: int,
    is_admin: bool,
) -> bool:

    with get_connection() as conn:

        cursor = conn.execute(
            """
            UPDATE users
            SET is_admin = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                1 if is_admin else 0,
                now_iso(),
                user_id,
            ),
        )

    return cursor.rowcount > 0


def get_users() -> list[dict[str, Any]]:

    with get_connection() as conn:

        rows = conn.execute(
            """
            SELECT
                id,
                username,
                email,
                name,
                is_admin,
                created_at,
                updated_at
            FROM users
            ORDER BY id DESC
            """
        ).fetchall()

    return [dict(row) for row in rows]


# =========================================================
# TRANSACTIONS
# =========================================================

def add_transaction(
    user_id: int,
    title: str,
    amount: float,
    transaction_type: str,
    category: str | None = None,
) -> int:

    created_at = now_iso()

    with get_connection() as conn:

        cursor = conn.execute(
            """
            INSERT INTO transactions (
                user_id,
                title,
                amount,
                transaction_type,
                category,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                title,
                amount,
                transaction_type,
                category,
                created_at,
            ),
        )

        return int(cursor.lastrowid)


def delete_transactions(
    user_id: int,
) -> int:

    with get_connection() as conn:

        cursor = conn.execute(
            """
            DELETE FROM transactions
            WHERE user_id = ?
            """,
            (user_id,),
        )

    return cursor.rowcount


def get_transactions(
    user_id: int,
    limit: int = 200,
) -> list[dict[str, Any]]:

    limit = max(
        1,
        min(int(limit), 1000),
    )

    with get_connection() as conn:

        rows = conn.execute(
            """
            SELECT
                id,
                user_id,
                title,
                amount,
                transaction_type,
                category,
                created_at
            FROM transactions
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (
                user_id,
                limit,
            ),
        ).fetchall()

    return [dict(row) for row in rows]


def get_balance(
    user_id: int,
) -> float:

    with get_connection() as conn:

        row = conn.execute(
            """
            SELECT
                COALESCE(
                    SUM(
                        CASE
                            WHEN transaction_type = 'income'
                                THEN amount
                            WHEN transaction_type = 'expense'
                                THEN -amount
                            ELSE 0
                        END
                    ),
                    0
                ) AS balance
            FROM transactions
            WHERE user_id = ?
            """,
            (user_id,),
        ).fetchone()

    return float(row["balance"] or 0)


def add_wallet_balance_with_transaction(
    user_id: int,
    amount: float,
    title: str = "افزایش موجودی",
    category: str = "wallet",
) -> float:

    if amount <= 0:
        raise ValueError("amount must be positive")

    with get_connection() as conn:

        conn.execute("BEGIN IMMEDIATE")

        conn.execute(
            """
            INSERT INTO transactions (
                user_id,
                title,
                amount,
                transaction_type,
                category,
                created_at
            )
            VALUES (?, ?, ?, 'income', ?, ?)
            """,
            (
                user_id,
                title,
                amount,
                category,
                now_iso(),
            ),
        )

        row = conn.execute(
            """
            SELECT
                COALESCE(
                    SUM(
                        CASE
                            WHEN transaction_type = 'income'
                                THEN amount
                            WHEN transaction_type = 'expense'
                                THEN -amount
                            ELSE 0
                        END
                    ),
                    0
                ) AS balance
            FROM transactions
            WHERE user_id = ?
            """,
            (user_id,),
        ).fetchone()

        return float(row["balance"] or 0)


def subtract_wallet_balance_with_transaction(
    user_id: int,
    amount: float,
    title: str = "کاهش موجودی",
    category: str = "wallet",
) -> float:

    if amount <= 0:
        raise ValueError("amount must be positive")

    with get_connection() as conn:

        conn.execute("BEGIN IMMEDIATE")

        row = conn.execute(
            """
            SELECT
                COALESCE(
                    SUM(
                        CASE
                            WHEN transaction_type = 'income'
                                THEN amount
                            WHEN transaction_type = 'expense'
                                THEN -amount
                            ELSE 0
                        END
                    ),
                    0
                ) AS balance
            FROM transactions
            WHERE user_id = ?
            """,
            (user_id,),
        ).fetchone()

        balance = float(
            row["balance"] or 0
        )

        if balance < amount:
            raise ValueError(
                "موجودی کافی نیست"
            )

        conn.execute(
            """
            INSERT INTO transactions (
                user_id,
                title,
                amount,
                transaction_type,
                category,
                created_at
            )
            VALUES (?, ?, ?, 'expense', ?, ?)
            """,
            (
                user_id,
                title,
                amount,
                category,
                now_iso(),
            ),
        )

        return balance - amount


# =========================================================
# BANK CARDS
# =========================================================

def normalize_card_number(
    card_number: str,
) -> str:

    digits = "".join(
        char
        for char in str(card_number)
        if char.isdigit()
    )

    return digits


def mask_card_number(
    card_number: str,
) -> str:

    digits = normalize_card_number(
        card_number
    )

    if len(digits) <= 4:
        return digits

    return (
        "**** **** **** "
        + digits[-4:]
    )


def add_bank_card(
    user_id: int,
    holder_name: str,
    bank_name: str,
    card_number: str,
) -> int:

    card_number = normalize_card_number(
        card_number
    )

    if len(card_number) != 16:
        raise ValueError(
            "شماره کارت باید ۱۶ رقمی باشد"
        )

    created_at = now_iso()

    with get_connection() as conn:

        existing = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM bank_cards
            WHERE user_id = ?
            """,
            (user_id,),
        ).fetchone()

        is_default = (
            1
            if int(existing["count"]) == 0
            else 0
        )

        cursor = conn.execute(
            """
            INSERT INTO bank_cards (
                user_id,
                holder_name,
                bank_name,
                card_number,
                is_default,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                holder_name,
                bank_name,
                card_number,
                is_default,
                created_at,
                created_at,
            ),
        )

        return int(cursor.lastrowid)


def get_bank_cards(
    user_id: int,
) -> list[dict[str, Any]]:

    with get_connection() as conn:

        rows = conn.execute(
            """
            SELECT
                id,
                user_id,
                holder_name,
                bank_name,
                card_number,
                is_default,
                created_at,
                updated_at
            FROM bank_cards
            WHERE user_id = ?
            ORDER BY is_default DESC, id DESC
            """,
            (user_id,),
        ).fetchall()

    result = []

    for row in rows:

        item = dict(row)

        item["masked_card_number"] = (
            mask_card_number(
                item["card_number"]
            )
        )

        item.pop(
            "card_number",
            None,
        )

        result.append(item)

    return result


def get_bank_card(
    user_id: int,
    card_id: int,
) -> dict[str, Any] | None:

    with get_connection() as conn:

        row = conn.execute(
            """
            SELECT *
            FROM bank_cards
            WHERE id = ?
              AND user_id = ?
            """,
            (
                card_id,
                user_id,
            ),
        ).fetchone()

    return dict(row) if row else None


def set_default_bank_card(
    user_id: int,
    card_id: int,
) -> bool:

    with get_connection() as conn:

        card = conn.execute(
            """
            SELECT id
            FROM bank_cards
            WHERE id = ?
              AND user_id = ?
            """,
            (
                card_id,
                user_id,
            ),
        ).fetchone()

        if not card:
            return False

        conn.execute(
            """
            UPDATE bank_cards
            SET is_default = 0,
                updated_at = ?
            WHERE user_id = ?
            """,
            (
                now_iso(),
                user_id,
            ),
        )

        conn.execute(
            """
            UPDATE bank_cards
            SET is_default = 1,
                updated_at = ?
            WHERE id = ?
              AND user_id = ?
            """,
            (
                now_iso(),
                card_id,
                user_id,
            ),
        )

        return True


def delete_bank_card(
    user_id: int,
    card_id: int,
) -> bool:

    with get_connection() as conn:

        cursor = conn.execute(
            """
            DELETE FROM bank_cards
            WHERE id = ?
              AND user_id = ?
            """,
            (
                card_id,
                user_id,
            ),
        )

        return cursor.rowcount > 0


# =========================================================
# DEPOSITS
# =========================================================

def deposit_by_card_once(
    user_id: int,
    card_id: int,
    amount: float,
    request_id: str,
) -> dict[str, Any]:

    if amount <= 0:
        raise ValueError(
            "مبلغ نامعتبر است"
        )

    with get_connection() as conn:

        conn.execute("BEGIN IMMEDIATE")

        existing = conn.execute(
            """
            SELECT *
            FROM wallet_deposits
            WHERE request_id = ?
            """,
            (request_id,),
        ).fetchone()

        if existing:

            row = conn.execute(
                """
                SELECT
                    COALESCE(
                        SUM(
                            CASE
                                WHEN transaction_type = 'income'
                                    THEN amount
                                WHEN transaction_type = 'expense'
                                    THEN -amount
                                ELSE 0
                            END
                        ),
                        0
                    ) AS balance
                FROM transactions
                WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()

            return {
                "deposit": dict(existing),
                "balance": float(
                    row["balance"] or 0
                ),
                "duplicate": True,
            }

        card = conn.execute(
            """
            SELECT *
            FROM bank_cards
            WHERE id = ?
              AND user_id = ?
            """,
            (
                card_id,
                user_id,
            ),
        ).fetchone()

        if not card:
            raise ValueError(
                "کارت بانکی پیدا نشد"
            )

        created_at = now_iso()

        cursor = conn.execute(
            """
            INSERT INTO wallet_deposits (
                user_id,
                card_id,
                amount,
                request_id,
                status,
                created_at
            )
            VALUES (?, ?, ?, ?, 'completed', ?)
            """,
            (
                user_id,
                card_id,
                amount,
                request_id,
                created_at,
            ),
        )

        deposit_id = int(
            cursor.lastrowid
        )

        conn.execute(
            """
            INSERT INTO transactions (
                user_id,
                title,
                amount,
                transaction_type,
                category,
                created_at
            )
            VALUES (
                ?,
                'شارژ کیف پول',
                ?,
                'income',
                'deposit',
                ?
            )
            """,
            (
                user_id,
                amount,
                created_at,
            ),
        )

        row = conn.execute(
            """
            SELECT
                COALESCE(
                    SUM(
                        CASE
                            WHEN transaction_type = 'income'
                                THEN amount
                            WHEN transaction_type = 'expense'
                                THEN -amount
                            ELSE 0
                        END
                    ),
                    0
                ) AS balance
            FROM transactions
            WHERE user_id = ?
            """,
            (user_id,),
        ).fetchone()

        return {
            "deposit_id": deposit_id,
            "balance": float(
                row["balance"] or 0
            ),
            "duplicate": False,
        }


# =========================================================
# CARD TRANSFERS
# =========================================================

def transfer_wallet_to_card_once(
    user_id: int,
    card_id: int,
    amount: float,
    request_id: str,
) -> dict[str, Any]:

    if amount <= 0:
        raise ValueError(
            "مبلغ نامعتبر است"
        )

    with get_connection() as conn:

        conn.execute("BEGIN IMMEDIATE")

        existing = conn.execute(
            """
            SELECT *
            FROM card_transfers
            WHERE request_id = ?
            """,
            (request_id,),
        ).fetchone()

        if existing:

            row = conn.execute(
                """
                SELECT
                    COALESCE(
                        SUM(
                            CASE
                                WHEN transaction_type = 'income'
                                    THEN amount
                                WHEN transaction_type = 'expense'
                                    THEN -amount
                                ELSE 0
                            END
                        ),
                        0
                    ) AS balance
                FROM transactions
                WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()

            return {
                "transfer": dict(existing),
                "balance": float(
                    row["balance"] or 0
                ),
                "duplicate": True,
            }

        card = conn.execute(
            """
            SELECT *
            FROM bank_cards
            WHERE id = ?
              AND user_id = ?
            """,
            (
                card_id,
                user_id,
            ),
        ).fetchone()

        if not card:
            raise ValueError(
                "کارت بانکی پیدا نشد"
            )

        balance_row = conn.execute(
            """
            SELECT
                COALESCE(
                    SUM(
                        CASE
                            WHEN transaction_type = 'income'
                                THEN amount
                            WHEN transaction_type = 'expense'
                                THEN -amount
                            ELSE 0
                        END
                    ),
                    0
                ) AS balance
            FROM transactions
            WHERE user_id = ?
            """,
            (user_id,),
        ).fetchone()

        balance = float(
            balance_row["balance"] or 0
        )

        if balance < amount:
            raise ValueError(
                "موجودی کافی نیست"
            )

        created_at = now_iso()

        cursor = conn.execute(
            """
            INSERT INTO card_transfers (
                user_id,
                card_id,
                amount,
                request_id,
                status,
                created_at,
                updated_at
            )
            VALUES (
                ?, ?, ?, ?, 'pending', ?, ?
            )
            """,
            (
                user_id,
                card_id,
                amount,
                request_id,
                created_at,
                created_at,
            ),
        )

        transfer_id = int(
            cursor.lastrowid
        )

        conn.execute(
            """
            INSERT INTO transactions (
                user_id,
                title,
                amount,
                transaction_type,
                category,
                created_at
            )
            VALUES (
                ?,
                'انتقال به کارت',
                ?,
                'expense',
                'card_transfer',
                ?
            )
            """,
            (
                user_id,
                amount,
                created_at,
            ),
        )

        return {
            "transfer_id": transfer_id,
            "balance": balance - amount,
            "duplicate": False,
        }


def get_card_transfer_requests(
    user_id: int,
    limit: int = 200,
) -> list[dict[str, Any]]:

    limit = max(
        1,
        min(int(limit), 1000),
    )

    with get_connection() as conn:

        rows = conn.execute(
            """
            SELECT
                ct.id,
                ct.user_id,
                ct.card_id,
                ct.amount,
                ct.request_id,
                ct.status,
                ct.created_at,
                ct.updated_at,
                bc.bank_name,
                bc.holder_name
            FROM card_transfers ct
            JOIN bank_cards bc
                ON bc.id = ct.card_id
            WHERE ct.user_id = ?
            ORDER BY ct.id DESC
            LIMIT ?
            """,
            (
                user_id,
                limit,
            ),
        ).fetchall()

    result = []

    for row in rows:

        item = dict(row)

        item["masked_card_number"] = (
            mask_card_number(
                get_card_number_for_transfer(
                    item["card_id"]
                )
            )
        )

        result.append(item)

    return result


def get_card_number_for_transfer(
    card_id: int,
) -> str:

    with get_connection() as conn:

        row = conn.execute(
            """
            SELECT card_number
            FROM bank_cards
            WHERE id = ?
            """,
            (card_id,),
        ).fetchone()

    return (
        str(row["card_number"])
        if row
        else ""
    )


def get_card_transfer_request(
    user_id: int,
    transfer_id: int,
) -> dict[str, Any] | None:

    with get_connection() as conn:

        row = conn.execute(
            """
            SELECT
                ct.id,
                ct.user_id,
                ct.card_id,
                ct.amount,
                ct.request_id,
                ct.status,
                ct.created_at,
                ct.updated_at,
                bc.bank_name,
                bc.holder_name,
                bc.card_number
            FROM card_transfers ct
            JOIN bank_cards bc
                ON bc.id = ct.card_id
            WHERE ct.id = ?
              AND ct.user_id = ?
            """,
            (
                transfer_id,
                user_id,
            ),
        ).fetchone()

    if not row:
        return None

    item = dict(row)

    item["masked_card_number"] = (
        mask_card_number(
            item["card_number"]
        )
    )

    item.pop(
        "card_number",
        None,
    )

    return item


def get_card_transfer_request_by_id(
    transfer_id: int,
) -> dict[str, Any] | None:

    with get_connection() as conn:

        row = conn.execute(
            """
            SELECT
                ct.id,
                ct.user_id,
                ct.card_id,
                ct.amount,
                ct.request_id,
                ct.status,
                ct.created_at,
                ct.updated_at,
                u.username,
                u.name,
                u.email,
                bc.bank_name,
                bc.holder_name,
                bc.card_number
            FROM card_transfers ct
            JOIN users u
                ON u.id = ct.user_id
            JOIN bank_cards bc
                ON bc.id = ct.card_id
            WHERE ct.id = ?
            """,
            (transfer_id,),
        ).fetchone()

    if not row:
        return None

    item = dict(row)

    item["masked_card_number"] = (
        mask_card_number(
            item["card_number"]
        )
    )

    item.pop(
        "card_number",
        None,
    )

    return item


def get_all_card_transfer_requests(
    limit: int = 200,
) -> list[dict[str, Any]]:

    limit = max(
        1,
        min(int(limit), 1000),
    )

    with get_connection() as conn:

        rows = conn.execute(
            """
            SELECT
                ct.id,
                ct.user_id,
                ct.card_id,
                ct.amount,
                ct.request_id,
                ct.status,
                ct.created_at,
                ct.updated_at,

                u.username,
                u.name,
                u.email,

                bc.bank_name,
                bc.holder_name,
                bc.card_number

            FROM card_transfers ct

            JOIN users u
                ON u.id = ct.user_id

            JOIN bank_cards bc
                ON bc.id = ct.card_id

            ORDER BY ct.id DESC

            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    result = []

    for row in rows:

        item = dict(row)

        item["masked_card_number"] = (
            mask_card_number(
                item["card_number"]
            )
        )

        item.pop(
            "card_number",
            None,
        )

        result.append(item)

    return result


def update_card_transfer_status(
    transfer_id: int,
    new_status: str,
) -> bool:

    allowed = {
        "pending",
        "completed",
        "failed",
        "cancelled",
    }

    if new_status not in allowed:
        raise ValueError(
            "وضعیت نامعتبر است"
        )

    with get_connection() as conn:

        conn.execute("BEGIN IMMEDIATE")

        row = conn.execute(
            """
            SELECT *
            FROM card_transfers
            WHERE id = ?
            """,
            (transfer_id,),
        ).fetchone()

        if not row:
            return False

        old_status = row["status"]

        if old_status == new_status:
            return True

        if old_status != "pending":
            raise ValueError(
                "این درخواست قبلاً پردازش شده است"
            )

        if new_status in {
            "failed",
            "cancelled",
        }:

            refund_title = (
                "بازگشت وجه انتقال کارت"
            )

            conn.execute(
                """
                INSERT INTO transactions (
                    user_id,
                    title,
                    amount,
                    transaction_type,
                    category,
                    created_at
                )
                VALUES (
                    ?,
                    ?,
                    ?,
                    'income',
                    'card_transfer_refund',
                    ?
                )
                """,
                (
                    row["user_id"],
                    refund_title,
                    row["amount"],
                    now_iso(),
                ),
            )

        conn.execute(
            """
            UPDATE card_transfers
            SET status = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                new_status,
                now_iso(),
                transfer_id,
            ),
        )

        return True


# =========================================================
# ADMIN ACTION LOGS
# =========================================================

def add_admin_action_log(
    action: str,
    transfer_id: int | None,
    status_before: str | None,
    status_after: str | None,
    amount: float | None,
    request_id: str | None,
) -> int:

    with get_connection() as conn:

        cursor = conn.execute(
            """
            INSERT INTO admin_action_logs (
                action,
                transfer_id,
                status_before,
                status_after,
                amount,
                request_id,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                action,
                transfer_id,
                status_before,
                status_after,
                amount,
                request_id,
                now_iso(),
            ),
        )

        return int(cursor.lastrowid)


def get_admin_action_logs(
    limit: int = 200,
) -> list[dict[str, Any]]:

    limit = max(
        1,
        min(int(limit), 1000),
    )

    with get_connection() as conn:

        rows = conn.execute(
            """
            SELECT
                id,
                action,
                transfer_id,
                status_before,
                status_after,
                amount,
                request_id,
                created_at
            FROM admin_action_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [
        dict(row)
        for row in rows
    ]


initialize_database()