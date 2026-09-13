from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


# =========================================================
# DATABASE CONFIG
# =========================================================

BASE_DIR = Path(__file__).resolve().parent

DATABASE_PATH = Path(
    os.getenv(
        "KIFYAR_DATABASE_PATH",
        str(BASE_DIR / "kifyar.db"),
    )
)


# =========================================================
# CONNECTION
# =========================================================

def get_connection() -> sqlite3.Connection:

    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=30,
    )

    connection.row_factory = sqlite3.Row

    connection.execute(
        "PRAGMA foreign_keys = ON"
    )

    connection.execute(
        "PRAGMA busy_timeout = 30000"
    )

    return connection


# =========================================================
# TIME
# =========================================================

def utc_now() -> str:

    return datetime.now(
        timezone.utc
    ).isoformat()


# =========================================================
# PASSWORD HELPERS
# =========================================================

def hash_password(
    password: str,
) -> str:

    salt = secrets.token_bytes(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        120_000,
    )

    return (
        salt.hex()
        + ":"
        + digest.hex()
    )


def verify_password(
    password: str,
    password_hash: str,
) -> bool:

    try:

        salt_hex, digest_hex = (
            password_hash.split(
                ":",
                1,
            )
        )

        salt = bytes.fromhex(
            salt_hex
        )

        expected = bytes.fromhex(
            digest_hex
        )

        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            120_000,
        )

        return secrets.compare_digest(
            actual,
            expected,
        )

    except Exception:

        return False


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

def initialize_database():

    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    connection = get_connection()

    try:

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                username TEXT UNIQUE NOT NULL,

                email TEXT UNIQUE,

                name TEXT NOT NULL DEFAULT '',

                password_hash TEXT NOT NULL,

                is_admin INTEGER NOT NULL DEFAULT 0,

                created_at TEXT NOT NULL,

                updated_at TEXT NOT NULL
            )
            """
        )


        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                user_id INTEGER NOT NULL,

                title TEXT NOT NULL,

                amount REAL NOT NULL,

                transaction_type TEXT NOT NULL,

                category TEXT NOT NULL DEFAULT 'other',

                created_at TEXT NOT NULL,

                FOREIGN KEY (
                    user_id
                )
                REFERENCES users(id)
                ON DELETE CASCADE
            )
            """
        )


        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS bank_cards (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                user_id INTEGER NOT NULL,

                holder_name TEXT NOT NULL,

                bank_name TEXT NOT NULL,

                card_number TEXT NOT NULL,

                is_default INTEGER NOT NULL DEFAULT 0,

                created_at TEXT NOT NULL,

                updated_at TEXT NOT NULL,

                FOREIGN KEY (
                    user_id
                )
                REFERENCES users(id)
                ON DELETE CASCADE
            )
            """
        )


        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS wallet_deposits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                user_id INTEGER NOT NULL,

                card_id INTEGER NOT NULL,

                amount REAL NOT NULL,

                request_id TEXT NOT NULL UNIQUE,

                status TEXT NOT NULL DEFAULT 'completed',

                created_at TEXT NOT NULL,

                FOREIGN KEY (
                    user_id
                )
                REFERENCES users(id)
                ON DELETE CASCADE,

                FOREIGN KEY (
                    card_id
                )
                REFERENCES bank_cards(id)
                ON DELETE CASCADE
            )
            """
        )


        connection.execute(
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

                FOREIGN KEY (
                    user_id
                )
                REFERENCES users(id)
                ON DELETE CASCADE,

                FOREIGN KEY (
                    card_id
                )
                REFERENCES bank_cards(id)
                ON DELETE CASCADE
            )
            """
        )


        # -------------------------------------------------
        # MIGRATIONS
        # -------------------------------------------------

        _ensure_column(
            connection,
            "users",
            "is_admin",
            "INTEGER NOT NULL DEFAULT 0",
        )

        _ensure_column(
            connection,
            "users",
            "email",
            "TEXT",
        )

        _ensure_column(
            connection,
            "users",
            "name",
            "TEXT NOT NULL DEFAULT ''",
        )

        _ensure_column(
            connection,
            "users",
            "updated_at",
            "TEXT",
        )


        # -------------------------------------------------
        # INDEXES
        # -------------------------------------------------

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_transactions_user
            ON transactions(user_id)
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_transactions_created
            ON transactions(created_at)
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_cards_user
            ON bank_cards(user_id)
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_deposits_user
            ON wallet_deposits(user_id)
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_card_transfers_user
            ON card_transfers(user_id)
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_card_transfers_status
            ON card_transfers(status)
            """
        )


        # -------------------------------------------------
        # FIX OLD NULL UPDATED_AT
        # -------------------------------------------------

        now = utc_now()

        connection.execute(
            """
            UPDATE users
            SET updated_at = ?
            WHERE updated_at IS NULL
               OR updated_at = ''
            """,
            (now,),
        )


        connection.commit()

    finally:

        connection.close()


# =========================================================
# MIGRATION HELPER
# =========================================================

def _ensure_column(
    connection: sqlite3.Connection,
    table_name: str,
    column_name: str,
    column_definition: str,
):

    columns = connection.execute(
        f"PRAGMA table_info({table_name})"
    ).fetchall()

    existing = {
        row["name"]
        for row in columns
    }

    if column_name not in existing:

        connection.execute(
            f"""
            ALTER TABLE {table_name}
            ADD COLUMN {column_name}
            {column_definition}
            """
        )


# =========================================================
# USER HELPERS
# =========================================================

def create_user(
    username: str,
    password: str,
    email: Optional[str] = None,
    name: str = "",
) -> int:

    username = username.strip()

    email = (
        email.strip().lower()
        if email
        else None
    )

    name = name.strip()

    if not username:
        raise ValueError(
            "نام کاربری الزامی است."
        )

    if not password:
        raise ValueError(
            "رمز عبور الزامی است."
        )

    now = utc_now()

    password_hash = hash_password(
        password
    )

    connection = get_connection()

    try:

        cursor = connection.execute(
            """
            INSERT INTO users (
                username,
                email,
                name,
                password_hash,
                is_admin,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, 0, ?, ?)
            """,
            (
                username,
                email,
                name,
                password_hash,
                now,
                now,
            ),
        )

        connection.commit()

        return int(
            cursor.lastrowid
        )

    except sqlite3.IntegrityError as exc:

        raise ValueError(
            "نام کاربری یا ایمیل قبلاً استفاده شده است."
        ) from exc

    finally:

        connection.close()


def find_user_by_id(
    user_id: int,
) -> Optional[dict[str, Any]]:

    connection = get_connection()

    try:

        row = connection.execute(
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
            WHERE id = ?
            LIMIT 1
            """,
            (user_id,),
        ).fetchone()

        if row is None:
            return None

        return dict(row)

    finally:

        connection.close()


def find_user_by_username(
    username: str,
) -> Optional[dict[str, Any]]:

    connection = get_connection()

    try:

        row = connection.execute(
            """
            SELECT *
            FROM users
            WHERE username = ?
            LIMIT 1
            """,
            (
                username.strip(),
            ),
        ).fetchone()

        if row is None:
            return None

        return dict(row)

    finally:

        connection.close()


def find_user_by_email(
    email: str,
) -> Optional[dict[str, Any]]:

    connection = get_connection()

    try:

        row = connection.execute(
            """
            SELECT *
            FROM users
            WHERE LOWER(email) = LOWER(?)
            LIMIT 1
            """,
            (
                email.strip(),
            ),
        ).fetchone()

        if row is None:
            return None

        return dict(row)

    finally:

        connection.close()


def verify_user_password(
    username: str,
    password: str,
) -> Optional[dict[str, Any]]:

    user = find_user_by_username(
        username
    )

    if user is None:
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

    name = name.strip()

    if not name:
        return False

    connection = get_connection()

    try:

        cursor = connection.execute(
            """
            UPDATE users
            SET
                name = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                name,
                utc_now(),
                user_id,
            ),
        )

        connection.commit()

        return cursor.rowcount > 0

    finally:

        connection.close()


def update_user_password(
    user_id: int,
    current_password: str,
    new_password: str,
):

    connection = get_connection()

    try:

        row = connection.execute(
            """
            SELECT password_hash
            FROM users
            WHERE id = ?
            LIMIT 1
            """,
            (user_id,),
        ).fetchone()

        if row is None:
            raise ValueError(
                "کاربر پیدا نشد."
            )

        if not verify_password(
            current_password,
            row["password_hash"],
        ):
            raise ValueError(
                "رمز عبور فعلی نادرست است."
            )

        if len(new_password) < 4:
            raise ValueError(
                "رمز عبور جدید باید حداقل ۴ کاراکتر باشد."
            )

        new_hash = hash_password(
            new_password
        )

        connection.execute(
            """
            UPDATE users
            SET
                password_hash = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                new_hash,
                utc_now(),
                user_id,
            ),
        )

        connection.commit()

    finally:

        connection.close()


def delete_user(
    user_id: int,
):

    connection = get_connection()

    try:

        connection.execute(
            """
            DELETE FROM users
            WHERE id = ?
            """,
            (user_id,),
        )

        connection.commit()

    finally:

        connection.close()


# =========================================================
# ADMIN HELPERS
# =========================================================

def is_user_admin(
    user_id: int,
) -> bool:

    connection = get_connection()

    try:

        row = connection.execute(
            """
            SELECT is_admin
            FROM users
            WHERE id = ?
            LIMIT 1
            """,
            (user_id,),
        ).fetchone()

        if row is None:
            return False

        return bool(
            row["is_admin"]
        )

    finally:

        connection.close()


def set_user_admin(
    user_id: int,
    is_admin: bool = True,
) -> bool:

    connection = get_connection()

    try:

        cursor = connection.execute(
            """
            UPDATE users
            SET
                is_admin = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                1 if is_admin else 0,
                utc_now(),
                user_id,
            ),
        )

        connection.commit()

        return cursor.rowcount > 0

    finally:

        connection.close()


# =========================================================
# TRANSACTIONS
# =========================================================

def add_transaction(
    user_id: int,
    title: str,
    amount: float,
    transaction_type: str,
    category: str = "other",
) -> int:

    if amount <= 0:
        raise ValueError(
            "مبلغ باید بیشتر از صفر باشد."
        )

    transaction_type = (
        transaction_type
        .strip()
        .lower()
    )

    if transaction_type not in {
        "income",
        "expense",
    }:
        raise ValueError(
            "نوع تراکنش نامعتبر است."
        )

    connection = get_connection()

    try:

        cursor = connection.execute(
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
                title.strip(),
                float(amount),
                transaction_type,
                category.strip() or "other",
                utc_now(),
            ),
        )

        connection.commit()

        return int(
            cursor.lastrowid
        )

    finally:

        connection.close()


def delete_transactions(
    user_id: int,
):

    connection = get_connection()

    try:

        connection.execute(
            """
            DELETE FROM transactions
            WHERE user_id = ?
            """,
            (user_id,),
        )

        connection.commit()

    finally:

        connection.close()


def get_transactions(
    user_id: int,
) -> list[dict[str, Any]]:

    connection = get_connection()

    try:

        rows = connection.execute(
            """
            SELECT
                id,
                title,
                amount,
                transaction_type,
                category,
                created_at
            FROM transactions
            WHERE user_id = ?
            ORDER BY id DESC
            """,
            (user_id,),
        ).fetchall()

        return [
            dict(row)
            for row in rows
        ]

    finally:

        connection.close()


# =========================================================
# BALANCE
# =========================================================

def get_balance(
    user_id: int,
) -> float:

    connection = get_connection()

    try:

        row = connection.execute(
            """
            SELECT
                COALESCE(
                    SUM(
                        CASE
                            WHEN transaction_type = 'income'
                            THEN amount
                            ELSE -amount
                        END
                    ),
                    0
                ) AS balance
            FROM transactions
            WHERE user_id = ?
            """,
            (user_id,),
        ).fetchone()

        return float(
            row["balance"] or 0
        )

    finally:

        connection.close()


# =========================================================
# WALLET ADD
# =========================================================

def add_wallet_balance_with_transaction(
    user_id: int,
    amount: float,
):

    if amount <= 0:
        raise ValueError(
            "مبلغ نامعتبر است."
        )

    connection = get_connection()

    try:

        connection.execute(
            "BEGIN IMMEDIATE"
        )

        cursor = connection.execute(
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
                "افزایش موجودی کیف پول",
                float(amount),
                "income",
                "wallet",
                utc_now(),
            ),
        )

        transaction_id = int(
            cursor.lastrowid
        )

        connection.commit()

        balance = get_balance(
            user_id
        )

        return {
            "success": True,
            "transaction_id": transaction_id,
            "amount": float(amount),
            "balance": balance,
        }

    except Exception:

        connection.rollback()

        raise

    finally:

        connection.close()


# =========================================================
# WALLET SUBTRACT
# =========================================================

def subtract_wallet_balance_with_transaction(
    user_id: int,
    amount: float,
    title: str = "کاهش موجودی کیف پول",
    category: str = "wallet",
):

    if amount <= 0:
        raise ValueError(
            "مبلغ نامعتبر است."
        )

    connection = get_connection()

    try:

        connection.execute(
            "BEGIN IMMEDIATE"
        )

        row = connection.execute(
            """
            SELECT
                COALESCE(
                    SUM(
                        CASE
                            WHEN transaction_type = 'income'
                            THEN amount
                            ELSE -amount
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

        if amount > balance:

            raise ValueError(
                "موجودی کیف پول کافی نیست."
            )

        cursor = connection.execute(
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
                float(amount),
                "expense",
                category,
                utc_now(),
            ),
        )

        transaction_id = int(
            cursor.lastrowid
        )

        connection.commit()

        new_balance = get_balance(
            user_id
        )

        return {
            "success": True,
            "transaction_id": transaction_id,
            "amount": float(amount),
            "balance": new_balance,
        }

    except Exception:

        connection.rollback()

        raise

    finally:

        connection.close()


# =========================================================
# BANK CARD HELPERS
# =========================================================

def normalize_card_number(
    card_number: str,
) -> str:

    return "".join(
        ch
        for ch in str(card_number)
        if ch.isdigit()
    )


def mask_card_number(
    card_number: str,
) -> str:

    digits = normalize_card_number(
        card_number
    )

    if len(digits) <= 4:

        return (
            "**** "
            + digits
        )

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

    holder_name = holder_name.strip()

    bank_name = bank_name.strip()

    card_number = normalize_card_number(
        card_number
    )

    if not holder_name:
        raise ValueError(
            "نام صاحب کارت الزامی است."
        )

    if not bank_name:
        raise ValueError(
            "نام بانک الزامی است."
        )

    if len(card_number) < 4:
        raise ValueError(
            "شماره کارت نامعتبر است."
        )

    connection = get_connection()

    try:

        count_row = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM bank_cards
            WHERE user_id = ?
            """,
            (user_id,),
        ).fetchone()

        is_first = (
            int(count_row["count"]) == 0
        )

        now = utc_now()

        cursor = connection.execute(
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
                1 if is_first else 0,
                now,
                now,
            ),
        )

        connection.commit()

        return int(
            cursor.lastrowid
        )

    finally:

        connection.close()


def get_bank_cards(
    user_id: int,
) -> list[dict[str, Any]]:

    connection = get_connection()

    try:

        rows = connection.execute(
            """
            SELECT
                id,
                holder_name,
                bank_name,
                card_number,
                is_default,
                created_at,
                updated_at
            FROM bank_cards
            WHERE user_id = ?
            ORDER BY
                is_default DESC,
                id DESC
            """,
            (user_id,),
        ).fetchall()

        result = []

        for row in rows:

            item = dict(row)

            item[
                "masked_card_number"
            ] = mask_card_number(
                item["card_number"]
            )

            item.pop(
                "card_number",
                None,
            )

            result.append(item)

        return result

    finally:

        connection.close()


def get_bank_card(
    user_id: int,
    card_id: int,
) -> Optional[dict[str, Any]]:

    connection = get_connection()

    try:

        row = connection.execute(
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
            WHERE id = ?
              AND user_id = ?
            LIMIT 1
            """,
            (
                card_id,
                user_id,
            ),
        ).fetchone()

        if row is None:
            return None

        item = dict(row)

        item[
            "masked_card_number"
        ] = mask_card_number(
            item["card_number"]
        )

        item.pop(
            "card_number",
            None,
        )

        return item

    finally:

        connection.close()


def set_default_bank_card(
    user_id: int,
    card_id: int,
) -> bool:

    connection = get_connection()

    try:

        connection.execute(
            "BEGIN IMMEDIATE"
        )

        exists = connection.execute(
            """
            SELECT id
            FROM bank_cards
            WHERE id = ?
              AND user_id = ?
            LIMIT 1
            """,
            (
                card_id,
                user_id,
            ),
        ).fetchone()

        if exists is None:

            connection.rollback()

            return False

        connection.execute(
            """
            UPDATE bank_cards
            SET
                is_default = 0,
                updated_at = ?
            WHERE user_id = ?
            """,
            (
                utc_now(),
                user_id,
            ),
        )

        cursor = connection.execute(
            """
            UPDATE bank_cards
            SET
                is_default = 1,
                updated_at = ?
            WHERE id = ?
              AND user_id = ?
            """,
            (
                utc_now(),
                card_id,
                user_id,
            ),
        )

        connection.commit()

        return cursor.rowcount > 0

    except Exception:

        connection.rollback()

        raise

    finally:

        connection.close()


def delete_bank_card(
    user_id: int,
    card_id: int,
) -> bool:

    connection = get_connection()

    try:

        cursor = connection.execute(
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

        connection.commit()

        return cursor.rowcount > 0

    finally:

        connection.close()


# =========================================================
# DEPOSIT
# =========================================================

def deposit_by_card_once(
    user_id: int,
    card_id: int,
    amount: float,
    request_id: str,
):

    if amount <= 0:
        raise ValueError(
            "مبلغ نامعتبر است."
        )

    connection = get_connection()

    try:

        connection.execute(
            "BEGIN IMMEDIATE"
        )

        existing = connection.execute(
            """
            SELECT *
            FROM wallet_deposits
            WHERE request_id = ?
            LIMIT 1
            """,
            (
                request_id,
            ),
        ).fetchone()

        if existing is not None:

            balance_row = connection.execute(
                """
                SELECT
                    COALESCE(
                        SUM(
                            CASE
                                WHEN transaction_type = 'income'
                                THEN amount
                                ELSE -amount
                            END
                        ),
                        0
                    ) AS balance
                FROM transactions
                WHERE user_id = ?
                """,
                (
                    user_id,
                ),
            ).fetchone()

            connection.commit()

            return {
                "success": True,
                "duplicate": True,
                "deposit_id": existing["id"],
                "amount": existing["amount"],
                "status": existing["status"],
                "balance": float(
                    balance_row["balance"] or 0
                ),
            }


        card = connection.execute(
            """
            SELECT id
            FROM bank_cards
            WHERE id = ?
              AND user_id = ?
            LIMIT 1
            """,
            (
                card_id,
                user_id,
            ),
        ).fetchone()

        if card is None:

            raise ValueError(
                "کارت بانکی پیدا نشد."
            )


        now = utc_now()

        cursor = connection.execute(
            """
            INSERT INTO wallet_deposits (
                user_id,
                card_id,
                amount,
                request_id,
                status,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                card_id,
                float(amount),
                request_id,
                "completed",
                now,
            ),
        )

        deposit_id = int(
            cursor.lastrowid
        )


        transaction_cursor = connection.execute(
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
                "واریز به کیف پول",
                float(amount),
                "income",
                "deposit",
                now,
            ),
        )

        transaction_id = int(
            transaction_cursor.lastrowid
        )


        balance_row = connection.execute(
            """
            SELECT
                COALESCE(
                    SUM(
                        CASE
                            WHEN transaction_type = 'income'
                            THEN amount
                            ELSE -amount
                        END
                    ),
                    0
                ) AS balance
            FROM transactions
            WHERE user_id = ?
            """,
            (
                user_id,
            ),
        ).fetchone()

        balance = float(
            balance_row["balance"] or 0
        )


        connection.commit()

        return {
            "success": True,
            "duplicate": False,
            "deposit_id": deposit_id,
            "transaction_id": transaction_id,
            "amount": float(amount),
            "status": "completed",
            "balance": balance,
        }

    except Exception:

        connection.rollback()

        raise

    finally:

        connection.close()


# =========================================================
# CARD TRANSFER
# =========================================================

def transfer_wallet_to_card_once(
    user_id: int,
    card_id: int,
    amount: float,
    request_id: str,
):

    if amount <= 0:
        raise ValueError(
            "مبلغ نامعتبر است."
        )

    connection = get_connection()

    try:

        connection.execute(
            "BEGIN IMMEDIATE"
        )


        # -------------------------------------------------
        # DUPLICATE REQUEST
        # -------------------------------------------------

        existing = connection.execute(
            """
            SELECT *
            FROM card_transfers
            WHERE request_id = ?
            LIMIT 1
            """,
            (
                request_id,
            ),
        ).fetchone()


        if existing is not None:

            balance_row = connection.execute(
                """
                SELECT
                    COALESCE(
                        SUM(
                            CASE
                                WHEN transaction_type = 'income'
                                THEN amount
                                ELSE -amount
                            END
                        ),
                        0
                    ) AS balance
                FROM transactions
                WHERE user_id = ?
                """,
                (
                    user_id,
                ),
            ).fetchone()

            connection.commit()

            return {
                "success": True,
                "duplicate": True,
                "transfer_id": existing["id"],
                "amount": existing["amount"],
                "status": existing["status"],
                "balance": float(
                    balance_row["balance"] or 0
                ),
            }


        # -------------------------------------------------
        # CARD CHECK
        # -------------------------------------------------

        card = connection.execute(
            """
            SELECT
                id,
                user_id
            FROM bank_cards
            WHERE id = ?
              AND user_id = ?
            LIMIT 1
            """,
            (
                card_id,
                user_id,
            ),
        ).fetchone()


        if card is None:

            raise ValueError(
                "کارت بانکی پیدا نشد."
            )


        # -------------------------------------------------
        # BALANCE CHECK
        # -------------------------------------------------

        balance_row = connection.execute(
            """
            SELECT
                COALESCE(
                    SUM(
                        CASE
                            WHEN transaction_type = 'income'
                            THEN amount
                            ELSE -amount
                        END
                    ),
                    0
                ) AS balance
            FROM transactions
            WHERE user_id = ?
            """,
            (
                user_id,
            ),
        ).fetchone()


        balance = float(
            balance_row["balance"] or 0
        )


        if amount > balance:

            raise ValueError(
                "موجودی کیف پول کافی نیست."
            )


        # -------------------------------------------------
        # CREATE TRANSFER
        # -------------------------------------------------

        now = utc_now()

        cursor = connection.execute(
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
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                card_id,
                float(amount),
                request_id,
                "pending",
                now,
                now,
            ),
        )

        transfer_id = int(
            cursor.lastrowid
        )


        # -------------------------------------------------
        # RESERVE / DEDUCT MONEY
        # -------------------------------------------------

        transaction_cursor = connection.execute(
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
                "انتقال به کارت",
                float(amount),
                "expense",
                "card_transfer",
                now,
            ),
        )

        transaction_id = int(
            transaction_cursor.lastrowid
        )


        # -------------------------------------------------
        # NEW BALANCE
        # -------------------------------------------------

        new_balance_row = connection.execute(
            """
            SELECT
                COALESCE(
                    SUM(
                        CASE
                            WHEN transaction_type = 'income'
                            THEN amount
                            ELSE -amount
                        END
                    ),
                    0
                ) AS balance
            FROM transactions
            WHERE user_id = ?
            """,
            (
                user_id,
            ),
        ).fetchone()


        new_balance = float(
            new_balance_row["balance"] or 0
        )


        connection.commit()


        return {
            "success": True,
            "duplicate": False,
            "transfer_id": transfer_id,
            "transaction_id": transaction_id,
            "amount": float(amount),
            "status": "pending",
            "balance": new_balance,
        }

    except Exception:

        connection.rollback()

        raise

    finally:

        connection.close()


# =========================================================
# USER TRANSFER REQUEST
# =========================================================

def get_card_transfer_requests(
    user_id: int,
) -> list[dict[str, Any]]:

    connection = get_connection()

    try:

        rows = connection.execute(
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

                bc.holder_name,
                bc.bank_name,
                bc.card_number

            FROM card_transfers ct

            LEFT JOIN bank_cards bc
                ON bc.id = ct.card_id

            WHERE ct.user_id = ?

            ORDER BY ct.id DESC
            """,
            (
                user_id,
            ),
        ).fetchall()


        result = []

        for row in rows:

            item = dict(row)

            item[
                "masked_card_number"
            ] = mask_card_number(
                item.get(
                    "card_number",
                    "",
                )
            )

            item.pop(
                "card_number",
                None,
            )

            result.append(item)

        return result

    finally:

        connection.close()


def get_card_transfer_request(
    user_id: int,
    transfer_id: int,
) -> Optional[dict[str, Any]]:

    connection = get_connection()

    try:

        row = connection.execute(
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

                bc.holder_name,
                bc.bank_name,
                bc.card_number

            FROM card_transfers ct

            LEFT JOIN bank_cards bc
                ON bc.id = ct.card_id

            WHERE ct.id = ?
              AND ct.user_id = ?

            LIMIT 1
            """,
            (
                transfer_id,
                user_id,
            ),
        ).fetchone()


        if row is None:
            return None


        item = dict(row)

        item[
            "masked_card_number"
        ] = mask_card_number(
            item.get(
                "card_number",
                "",
            )
        )

        item.pop(
            "card_number",
            None
        )

        return item

    finally:

        connection.close()


# =========================================================
# ADMIN TRANSFER REQUESTS
# =========================================================

def get_all_card_transfer_requests(
    limit: int = 200,
) -> list[dict[str, Any]]:

    connection = get_connection()

    try:

        rows = connection.execute(
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

                bc.holder_name,
                bc.bank_name,
                bc.card_number

            FROM card_transfers ct

            LEFT JOIN users u
                ON u.id = ct.user_id

            LEFT JOIN bank_cards bc
                ON bc.id = ct.card_id

            ORDER BY ct.id DESC

            LIMIT ?
            """,
            (
                int(limit),
            ),
        ).fetchall()


        result = []

        for row in rows:

            item = dict(row)

            item[
                "masked_card_number"
            ] = mask_card_number(
                item.get(
                    "card_number",
                    "",
                )
            )

            item.pop(
                "card_number",
                None
            )

            result.append(item)

        return result

    finally:

        connection.close()


def get_card_transfer_request_by_id(
    transfer_id: int,
) -> Optional[dict[str, Any]]:

    connection = get_connection()

    try:

        row = connection.execute(
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

                bc.holder_name,
                bc.bank_name,
                bc.card_number

            FROM card_transfers ct

            LEFT JOIN users u
                ON u.id = ct.user_id

            LEFT JOIN bank_cards bc
                ON bc.id = ct.card_id

            WHERE ct.id = ?

            LIMIT 1
            """,
            (
                transfer_id,
            ),
        ).fetchone()


        if row is None:
            return None


        item = dict(row)

        item[
            "masked_card_number"
        ] = mask_card_number(
            item.get(
                "card_number",
                "",
            )
        )

        item.pop(
            "card_number",
            None
        )

        return item

    finally:

        connection.close()


# =========================================================
# TRANSFER STATUS
# =========================================================

def update_card_transfer_status(
    transfer_id: int,
    status: str,
) -> bool:

    status = (
        status
        .strip()
        .lower()
    )


    allowed = {
        "pending",
        "completed",
        "failed",
        "cancelled",
    }


    if status not in allowed:

        raise ValueError(
            "وضعیت انتقال نامعتبر است."
        )


    connection = get_connection()

    try:

        connection.execute(
            "BEGIN IMMEDIATE"
        )


        transfer = connection.execute(
            """
            SELECT *
            FROM card_transfers
            WHERE id = ?
            LIMIT 1
            """,
            (
                transfer_id,
            ),
        ).fetchone()


        if transfer is None:

            connection.rollback()

            return False


        current_status = (
            str(
                transfer["status"]
            )
            .strip()
            .lower()
        )


        # -------------------------------------------------
        # SAME STATUS
        # -------------------------------------------------

        if current_status == status:

            connection.commit()

            return True


        # -------------------------------------------------
        # TERMINAL STATUS
        # -------------------------------------------------

        terminal_statuses = {
            "completed",
            "failed",
            "cancelled",
        }


        if current_status in terminal_statuses:

            raise ValueError(
                "این درخواست قبلاً نهایی شده و قابل تغییر نیست."
            )


        # -------------------------------------------------
        # ONLY PENDING CAN MOVE
        # -------------------------------------------------

        if current_status != "pending":

            raise ValueError(
                "وضعیت فعلی درخواست قابل تغییر نیست."
            )


        now = utc_now()


        # -------------------------------------------------
        # COMPLETE
        # -------------------------------------------------

        if status == "completed":

            connection.execute(
                """
                UPDATE card_transfers
                SET
                    status = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    "completed",
                    now,
                    transfer_id,
                ),
            )

            connection.commit()

            return True


        # -------------------------------------------------
        # FAILED / CANCELLED
        #
        # Money was already deducted when the request
        # was created.
        #
        # Therefore refund it exactly once.
        # -------------------------------------------------

        if status in {
            "failed",
            "cancelled",
        }:

            amount = float(
                transfer["amount"]
            )

            user_id = int(
                transfer["user_id"]
            )


            # ---------------------------------------------
            # Check whether refund already exists
            # ---------------------------------------------

            refund_category = (
                "card_transfer_refund"
            )


            existing_refund = connection.execute(
                """
                SELECT id
                FROM transactions
                WHERE user_id = ?
                  AND category = ?
                  AND title = ?
                  AND amount = ?
                LIMIT 1
                """,
                (
                    user_id,
                    refund_category,
                    "بازگشت وجه انتقال کارت",
                    amount,
                ),
            ).fetchone()


            if existing_refund is None:

                connection.execute(
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
                        "بازگشت وجه انتقال کارت",
                        amount,
                        "income",
                        refund_category,
                        now,
                    ),
                )


            connection.execute(
                """
                UPDATE card_transfers
                SET
                    status = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    status,
                    now,
                    transfer_id,
                ),
            )


            connection.commit()

            return True


        connection.rollback()

        raise ValueError(
            "تغییر وضعیت انجام نشد."
        )

    except Exception:

        connection.rollback()

        raise

    finally:

        connection.close()


# =========================================================
# ADMIN USER LIST
# =========================================================

def get_users(
    limit: int = 200,
) -> list[dict[str, Any]]:

    connection = get_connection()

    try:

        rows = connection.execute(
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
            LIMIT ?
            """,
            (
                int(limit),
            ),
        ).fetchall()

        return [
            dict(row)
            for row in rows
        ]

    finally:

        connection.close()


# =========================================================
# END
# =========================================================