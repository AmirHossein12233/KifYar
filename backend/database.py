from __future__ import annotations

import hashlib
import os
import secrets
from datetime import datetime, timezone
from typing import Any

import psycopg
from psycopg.rows import dict_row


DATABASE_URL = os.getenv("DATABASE_URL")

PASSWORD_ITERATIONS = 120_000


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_connection():
    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL روی سرور تنظیم نشده است."
        )

    return psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row,
        connect_timeout=20,
    )


# ============================================================
# Password
# ============================================================

def hash_password(
    password: str,
    salt: bytes | None = None,
) -> str:

    if salt is None:
        salt = secrets.token_bytes(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_ITERATIONS,
    )

    return (
        salt.hex()
        + ":"
        + digest.hex()
    )


def verify_password(
    password: str,
    stored_password: str,
) -> bool:

    try:
        salt_hex, digest_hex = (
            stored_password.split(":", 1)
        )

        salt = bytes.fromhex(salt_hex)

        calculated = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            PASSWORD_ITERATIONS,
        )

        return calculated.hex() == digest_hex

    except Exception:
        return False


def verify_user_password(
    username: str,
    password: str,
) -> dict[str, Any] | None:

    user = find_user_by_username(username)

    if not user:
        user = find_user_by_email(username)

    if not user:
        return None

    if not verify_password(
        password,
        user["password_hash"],
    ):
        return None

    return user


# ============================================================
# Database initialization
# ============================================================

def initialize_database() -> None:

    with get_connection() as conn:

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id BIGSERIAL PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                full_name TEXT NOT NULL DEFAULT '',
                balance DOUBLE PRECISION NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS transactions (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL,
                title TEXT NOT NULL,
                amount DOUBLE PRECISION NOT NULL,
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
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL,
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
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL,
                amount DOUBLE PRECISION NOT NULL,
                request_id TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'completed',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS card_transfers (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL,
                card_id BIGINT NOT NULL,
                amount DOUBLE PRECISION NOT NULL,
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

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS admin_action_logs (
                id BIGSERIAL PRIMARY KEY,
                admin_name TEXT NOT NULL,
                action TEXT NOT NULL,
                target_id BIGINT,
                details TEXT,
                created_at TEXT NOT NULL
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS notifications (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                notification_type TEXT NOT NULL DEFAULT 'general',
                transfer_id BIGINT,
                is_read INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            )
            """
        )

        # =====================================================
        # New settlement columns
        # =====================================================

        conn.execute(
            """
            ALTER TABLE card_transfers
            ADD COLUMN IF NOT EXISTS provider TEXT
            """
        )

        conn.execute(
            """
            ALTER TABLE card_transfers
            ADD COLUMN IF NOT EXISTS provider_transfer_id TEXT
            """
        )

        conn.execute(
            """
            ALTER TABLE card_transfers
            ADD COLUMN IF NOT EXISTS provider_status TEXT
            """
        )

        conn.execute(
            """
            ALTER TABLE card_transfers
            ADD COLUMN IF NOT EXISTS reserved_amount
            DOUBLE PRECISION NOT NULL DEFAULT 0
            """
        )

        conn.execute(
            """
            ALTER TABLE card_transfers
            ADD COLUMN IF NOT EXISTS failure_reason TEXT
            """
        )

        conn.execute(
            """
            ALTER TABLE card_transfers
            ADD COLUMN IF NOT EXISTS processed_at TEXT
            """
        )

        # =====================================================
        # Payout attempts
        # =====================================================

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS payout_attempts (
                id BIGSERIAL PRIMARY KEY,
                transfer_id BIGINT NOT NULL,
                provider TEXT NOT NULL,
                provider_transfer_id TEXT,
                amount DOUBLE PRECISION NOT NULL,
                status TEXT NOT NULL,
                response_data TEXT,
                error_message TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(transfer_id)
                    REFERENCES card_transfers(id)
                    ON DELETE CASCADE
            )
            """
        )

        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_payout_attempts_transfer_id
            ON payout_attempts(transfer_id)
            """
        )

        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_card_transfers_provider_transfer_id
            ON card_transfers(provider_transfer_id)
            """
        )


# ============================================================
# Users
# ============================================================

def create_user(
    username: str,
    email: str,
    password: str,
    full_name: str = "",
) -> int:

    created_at = now_iso()

    password_hash = hash_password(password)

    with get_connection() as conn:

        row = conn.execute(
            """
            INSERT INTO users (
                username,
                email,
                password_hash,
                full_name,
                balance,
                created_at,
                updated_at
            )
            VALUES (
                %s, %s, %s, %s, 0, %s, %s
            )
            RETURNING id
            """,
            (
                username,
                email,
                password_hash,
                full_name,
                created_at,
                created_at,
            ),
        ).fetchone()

    return int(row["id"])


def find_user_by_id(
    user_id: int,
) -> dict[str, Any] | None:

    with get_connection() as conn:

        row = conn.execute(
            """
            SELECT *
            FROM users
            WHERE id = %s
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
            WHERE username = %s
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
            WHERE email = %s
            """,
            (email,),
        ).fetchone()

    return dict(row) if row else None


def update_user_name(
    user_id: int,
    full_name: str,
) -> dict[str, Any]:

    with get_connection() as conn:

        conn.execute(
            """
            UPDATE users
            SET
                full_name = %s,
                updated_at = %s
            WHERE id = %s
            """,
            (
                full_name,
                now_iso(),
                user_id,
            ),
        )

    user = find_user_by_id(user_id)

    if not user:
        raise ValueError(
            "کاربر پیدا نشد."
        )

    return user


def update_user_password(
    user_id: int,
    new_password: str,
) -> None:

    password_hash = hash_password(
        new_password
    )

    with get_connection() as conn:

        conn.execute(
            """
            UPDATE users
            SET
                password_hash = %s,
                updated_at = %s
            WHERE id = %s
            """,
            (
                password_hash,
                now_iso(),
                user_id,
            ),
        )


def delete_user(
    user_id: int,
) -> None:

    with get_connection() as conn:

        conn.execute(
            """
            DELETE FROM users
            WHERE id = %s
            """,
            (user_id,),
        )


# ============================================================
# Balance helpers
# ============================================================

def get_balance(
    user_id: int,
) -> float:

    with get_connection() as conn:

        row = conn.execute(
            """
            SELECT COALESCE(
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
            WHERE user_id = %s
            """,
            (user_id,),
        ).fetchone()

    return float(
        row["balance"] or 0
    )


def get_reserved_amount(
    user_id: int,
) -> float:

    with get_connection() as conn:

        row = conn.execute(
            """
            SELECT COALESCE(
                SUM(reserved_amount),
                0
            ) AS reserved
            FROM card_transfers
            WHERE user_id = %s
              AND status IN (
                  'pending',
                  'approved',
                  'processing'
              )
            """,
            (user_id,),
        ).fetchone()

    return float(
        row["reserved"] or 0
    )


def get_available_balance(
    user_id: int,
) -> float:

    balance = get_balance(user_id)

    reserved = get_reserved_amount(
        user_id
    )

    return max(
        0.0,
        balance - reserved,
    )


# ============================================================
# Transactions
# ============================================================

def add_transaction(
    user_id: int,
    title: str,
    amount: float,
    transaction_type: str,
    category: str | None = None,
) -> int:

    created_at = now_iso()

    with get_connection() as conn:

        row = conn.execute(
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
                %s, %s, %s, %s, %s, %s
            )
            RETURNING id
            """,
            (
                user_id,
                title,
                amount,
                transaction_type,
                category,
                created_at,
            ),
        ).fetchone()

    return int(row["id"])


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
            SELECT *
            FROM transactions
            WHERE user_id = %s
            ORDER BY id DESC
            LIMIT %s
            """,
            (
                user_id,
                limit,
            ),
        ).fetchall()

    return [
        dict(row)
        for row in rows
    ]


# ============================================================
# Wallet
# ============================================================

def add_wallet_balance_with_transaction(
    user_id: int,
    amount: float,
    title: str = "افزایش موجودی",
    category: str = "wallet",
) -> dict[str, Any]:

    if amount <= 0:
        raise ValueError(
            "مبلغ نامعتبر است."
        )

    created_at = now_iso()

    with get_connection() as conn:

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
                %s,
                %s,
                %s,
                'income',
                %s,
                %s
            )
            """,
            (
                user_id,
                title,
                amount,
                category,
                created_at,
            ),
        )

        balance_row = conn.execute(
            """
            SELECT COALESCE(
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
            WHERE user_id = %s
            """,
            (user_id,),
        ).fetchone()

    return {
        "success": True,
        "balance": float(
            balance_row["balance"] or 0
        ),
    }


def subtract_wallet_balance_with_transaction(
    user_id: int,
    amount: float,
    title: str = "کاهش موجودی",
    category: str = "wallet",
) -> dict[str, Any]:

    if amount <= 0:
        raise ValueError(
            "مبلغ نامعتبر است."
        )

    with get_connection() as conn:

        balance_row = conn.execute(
            """
            SELECT COALESCE(
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
            WHERE user_id = %s
            """,
            (user_id,),
        ).fetchone()

        balance = float(
            balance_row["balance"] or 0
        )

        if balance < amount:
            raise ValueError(
                "موجودی کافی نیست."
            )

        created_at = now_iso()

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
                %s,
                %s,
                %s,
                'expense',
                %s,
                %s
            )
            """,
            (
                user_id,
                title,
                amount,
                category,
                created_at,
            ),
        )

        new_balance = balance - amount

    return {
        "success": True,
        "balance": new_balance,
    }


# ============================================================
# Bank cards
# ============================================================

def mask_card_number(
    card_number: str,
) -> str:

    digits = "".join(
        char
        for char in str(card_number)
        if char.isdigit()
    )

    if len(digits) <= 4:
        return digits

    return (
        "*" * (len(digits) - 4)
        + digits[-4:]
    )


def add_bank_card(
    user_id: int,
    holder_name: str,
    bank_name: str,
    card_number: str,
    is_default: bool = False,
) -> int:

    created_at = now_iso()

    with get_connection() as conn:

        if is_default:

            conn.execute(
                """
                UPDATE bank_cards
                SET
                    is_default = 0,
                    updated_at = %s
                WHERE user_id = %s
                """,
                (
                    created_at,
                    user_id,
                ),
            )

        row = conn.execute(
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
            VALUES (
                %s, %s, %s, %s, %s, %s, %s
            )
            RETURNING id
            """,
            (
                user_id,
                holder_name,
                bank_name,
                card_number,
                1 if is_default else 0,
                created_at,
                created_at,
            ),
        ).fetchone()

    return int(row["id"])


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
            WHERE user_id = %s
            ORDER BY is_default DESC, id DESC
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


def set_default_bank_card(
    user_id: int,
    card_id: int,
) -> None:

    with get_connection() as conn:

        card = conn.execute(
            """
            SELECT id
            FROM bank_cards
            WHERE id = %s
              AND user_id = %s
            """,
            (
                card_id,
                user_id,
            ),
        ).fetchone()

        if not card:
            raise ValueError(
                "کارت بانکی پیدا نشد."
            )

        conn.execute(
            """
            UPDATE bank_cards
            SET
                is_default = 0,
                updated_at = %s
            WHERE user_id = %s
            """,
            (
                now_iso(),
                user_id,
            ),
        )

        conn.execute(
            """
            UPDATE bank_cards
            SET
                is_default = 1,
                updated_at = %s
            WHERE id = %s
              AND user_id = %s
            """,
            (
                now_iso(),
                card_id,
                user_id,
            ),
        )


def delete_bank_card(
    user_id: int,
    card_id: int,
) -> None:

    with get_connection() as conn:

        conn.execute(
            """
            DELETE FROM bank_cards
            WHERE id = %s
              AND user_id = %s
            """,
            (
                card_id,
                user_id,
            ),
        )


# ============================================================
# Deposits
# ============================================================

def deposit_by_card_once(
    user_id: int,
    amount: float,
    request_id: str,
) -> dict[str, Any]:

    if amount <= 0:
        raise ValueError(
            "مبلغ نامعتبر است."
        )

    with get_connection() as conn:

        existing = conn.execute(
            """
            SELECT *
            FROM wallet_deposits
            WHERE request_id = %s
            """,
            (request_id,),
        ).fetchone()

        if existing:

            balance = get_balance(
                user_id
            )

            return {
                "success": True,
                "duplicate": True,
                "deposit": dict(existing),
                "balance": balance,
            }

        created_at = now_iso()

        row = conn.execute(
            """
            INSERT INTO wallet_deposits (
                user_id,
                amount,
                request_id,
                status,
                created_at,
                updated_at
            )
            VALUES (
                %s, %s, %s,
                'completed',
                %s, %s
            )
            RETURNING id
            """,
            (
                user_id,
                amount,
                request_id,
                created_at,
                created_at,
            ),
        ).fetchone()

        deposit_id = int(
            row["id"]
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
                %s,
                'افزایش موجودی از کارت',
                %s,
                'income',
                'card_deposit',
                %s
            )
            """,
            (
                user_id,
                amount,
                created_at,
            ),
        )

        balance = get_balance(
            user_id
        )

    return {
        "success": True,
        "duplicate": False,
        "deposit_id": deposit_id,
        "balance": balance,
    }


# ============================================================
# Card transfer / settlement
# ============================================================

def transfer_wallet_to_card_once(
    user_id: int,
    card_id: int,
    amount: float,
    request_id: str,
) -> dict[str, Any]:

    if amount <= 0:
        raise ValueError(
            "مبلغ نامعتبر است."
        )

    if not request_id:
        raise ValueError(
            "شناسه درخواست الزامی است."
        )

    with get_connection() as conn:

        # -----------------------------------------------------
        # Idempotency
        # -----------------------------------------------------

        existing = conn.execute(
            """
            SELECT *
            FROM card_transfers
            WHERE request_id = %s
            """,
            (request_id,),
        ).fetchone()

        if existing:

            reserved = get_reserved_amount(
                user_id
            )

            balance = get_balance(
                user_id
            )

            available = max(
                0.0,
                balance - reserved,
            )

            return {
                "success": True,
                "duplicate": True,
                "transfer": dict(existing),
                "transfer_id": int(
                    existing["id"]
                ),
                "balance": balance,
                "available_balance": available,
            }

        # -----------------------------------------------------
        # Card validation
        # -----------------------------------------------------

        card = conn.execute(
            """
            SELECT *
            FROM bank_cards
            WHERE id = %s
              AND user_id = %s
            """,
            (
                card_id,
                user_id,
            ),
        ).fetchone()

        if not card:
            raise ValueError(
                "کارت بانکی پیدا نشد."
            )

        # -----------------------------------------------------
        # Balance
        # -----------------------------------------------------

        balance_row = conn.execute(
            """
            SELECT COALESCE(
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
            WHERE user_id = %s
            """,
            (user_id,),
        ).fetchone()

        balance = float(
            balance_row["balance"] or 0
        )

        # -----------------------------------------------------
        # Existing reservations
        # -----------------------------------------------------

        reserved_row = conn.execute(
            """
            SELECT COALESCE(
                SUM(reserved_amount),
                0
            ) AS reserved
            FROM card_transfers
            WHERE user_id = %s
              AND status IN (
                  'pending',
                  'approved',
                  'processing'
              )
            """,
            (user_id,),
        ).fetchone()

        reserved = float(
            reserved_row["reserved"] or 0
        )

        available_balance = (
            balance - reserved
        )

        if available_balance < amount:
            raise ValueError(
                "موجودی قابل برداشت کافی نیست."
            )

        # -----------------------------------------------------
        # Create pending transfer
        # -----------------------------------------------------

        created_at = now_iso()

        row = conn.execute(
            """
            INSERT INTO card_transfers (
                user_id,
                card_id,
                amount,
                request_id,
                status,
                provider,
                provider_transfer_id,
                provider_status,
                reserved_amount,
                failure_reason,
                created_at,
                updated_at,
                processed_at
            )
            VALUES (
                %s,
                %s,
                %s,
                %s,
                'pending',
                NULL,
                NULL,
                NULL,
                %s,
                NULL,
                %s,
                %s,
                NULL
            )
            RETURNING id
            """,
            (
                user_id,
                card_id,
                amount,
                request_id,
                amount,
                created_at,
                created_at,
            ),
        ).fetchone()

        transfer_id = int(
            row["id"]
        )

        # -----------------------------------------------------
        # Notification
        # -----------------------------------------------------

        conn.execute(
            """
            INSERT INTO notifications (
                user_id,
                title,
                message,
                notification_type,
                transfer_id,
                is_read,
                created_at
            )
            VALUES (
                %s,
                %s,
                %s,
                %s,
                %s,
                0,
                %s
            )
            """,
            (
                user_id,
                "درخواست تسویه ثبت شد",
                (
                    f"درخواست تسویه "
                    f"{amount:,.0f} تومان ثبت شد "
                    f"و مبلغ آن رزرو شد."
                ),
                "transfer",
                transfer_id,
                created_at,
            ),
        )

        new_available_balance = (
            available_balance - amount
        )

    return {
        "success": True,
        "duplicate": False,
        "transfer_id": transfer_id,
        "balance": balance,
        "reserved_amount": amount,
        "available_balance": new_available_balance,
        "status": "pending",
    }


# ============================================================
# Transfer requests
# ============================================================

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
                ct.provider,
                ct.provider_transfer_id,
                ct.provider_status,
                ct.reserved_amount,
                ct.failure_reason,
                ct.created_at,
                ct.updated_at,
                ct.processed_at,
                bc.bank_name,
                bc.holder_name,
                bc.card_number
            FROM card_transfers ct
            LEFT JOIN bank_cards bc
                ON bc.id = ct.card_id
            WHERE ct.id = %s
              AND ct.user_id = %s
            """,
            (
                transfer_id,
                user_id,
            ),
        ).fetchone()

    if not row:
        return None

    item = dict(row)

    if item.get("card_number"):
        item[
            "masked_card_number"
        ] = mask_card_number(
            item["card_number"]
        )

    item.pop(
        "card_number",
        None,
    )

    item[
        "status_text"
    ] = transfer_status_text(
        item.get("status")
    )

    return item


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
                ct.provider,
                ct.provider_transfer_id,
                ct.provider_status,
                ct.reserved_amount,
                ct.failure_reason,
                ct.created_at,
                ct.updated_at,
                ct.processed_at,
                bc.bank_name,
                bc.holder_name,
                bc.card_number
            FROM card_transfers ct
            LEFT JOIN bank_cards bc
                ON bc.id = ct.card_id
            WHERE ct.user_id = %s
            ORDER BY ct.id DESC
            LIMIT %s
            """,
            (
                user_id,
                limit,
            ),
        ).fetchall()

    result = []

    for row in rows:

        item = dict(row)

        if item.get("card_number"):
            item[
                "masked_card_number"
            ] = mask_card_number(
                item["card_number"]
            )

        item.pop(
            "card_number",
            None,
        )

        item[
            "status_text"
        ] = transfer_status_text(
            item.get("status")
        )

        result.append(item)

    return result


def transfer_status_text(
    status: str | None,
) -> str:

    values = {
        "pending": "در انتظار بررسی",
        "approved": "تأیید شده",
        "processing": "در حال تسویه",
        "completed": "تسویه انجام شد",
        "failed": "تسویه ناموفق",
        "rejected": "رد شده",
    }

    return values.get(
        status or "",
        "نامشخص",
    )


# ============================================================
# Admin settlement operations
# ============================================================

def approve_card_transfer(
    transfer_id: int,
) -> dict[str, Any]:

    with get_connection() as conn:

        row = conn.execute(
            """
            SELECT *
            FROM card_transfers
            WHERE id = %s
            FOR UPDATE
            """,
            (transfer_id,),
        ).fetchone()

        if not row:
            raise ValueError(
                "درخواست تسویه پیدا نشد."
            )

        status = row["status"]

        if status != "pending":
            raise ValueError(
                "این درخواست در وضعیت قابل تأیید نیست."
            )

        updated_at = now_iso()

        conn.execute(
            """
            UPDATE card_transfers
            SET
                status = 'approved',
                updated_at = %s
            WHERE id = %s
            """,
            (
                updated_at,
                transfer_id,
            ),
        )

        conn.execute(
            """
            INSERT INTO notifications (
                user_id,
                title,
                message,
                notification_type,
                transfer_id,
                is_read,
                created_at
            )
            VALUES (
                %s,
                %s,
                %s,
                'transfer',
                %s,
                0,
                %s
            )
            """,
            (
                row["user_id"],
                "درخواست تسویه تأیید شد",
                (
                    "درخواست تسویه شما تأیید شد "
                    "و آماده پردازش است."
                ),
                transfer_id,
                updated_at,
            ),
        )

    return {
        "success": True,
        "transfer_id": transfer_id,
        "status": "approved",
    }


def reject_card_transfer(
    transfer_id: int,
    reason: str,
) -> dict[str, Any]:

    reason = (
        reason.strip()
        if reason
        else "درخواست تسویه رد شد."
    )

    with get_connection() as conn:

        row = conn.execute(
            """
            SELECT *
            FROM card_transfers
            WHERE id = %s
            FOR UPDATE
            """,
            (transfer_id,),
        ).fetchone()

        if not row:
            raise ValueError(
                "درخواست تسویه پیدا نشد."
            )

        if row["status"] not in (
            "pending",
            "approved",
        ):
            raise ValueError(
                "این درخواست قابل رد نیست."
            )

        updated_at = now_iso()

        conn.execute(
            """
            UPDATE card_transfers
            SET
                status = 'rejected',
                reserved_amount = 0,
                failure_reason = %s,
                updated_at = %s,
                processed_at = %s
            WHERE id = %s
            """,
            (
                reason,
                updated_at,
                updated_at,
                transfer_id,
            ),
        )

        conn.execute(
            """
            INSERT INTO notifications (
                user_id,
                title,
                message,
                notification_type,
                transfer_id,
                is_read,
                created_at
            )
            VALUES (
                %s,
                %s,
                %s,
                'transfer',
                %s,
                0,
                %s
            )
            """,
            (
                row["user_id"],
                "درخواست تسویه رد شد",
                reason,
                transfer_id,
                updated_at,
            ),
        )

    return {
        "success": True,
        "transfer_id": transfer_id,
        "status": "rejected",
    }


def mark_transfer_processing(
    transfer_id: int,
) -> dict[str, Any]:

    with get_connection() as conn:

        row = conn.execute(
            """
            SELECT *
            FROM card_transfers
            WHERE id = %s
            FOR UPDATE
            """,
            (transfer_id,),
        ).fetchone()

        if not row:
            raise ValueError(
                "درخواست تسویه پیدا نشد."
            )

        if row["status"] != "approved":
            raise ValueError(
                "درخواست باید ابتدا تأیید شود."
            )

        updated_at = now_iso()

        conn.execute(
            """
            UPDATE card_transfers
            SET
                status = 'processing',
                updated_at = %s
            WHERE id = %s
            """,
            (
                updated_at,
                transfer_id,
            ),
        )

    return {
        "success": True,
        "transfer_id": transfer_id,
        "status": "processing",
    }


def complete_card_transfer(
    transfer_id: int,
    provider_transfer_id: str,
    provider_status: str = "completed",
) -> dict[str, Any]:

    if not provider_transfer_id:
        raise ValueError(
            "شناسه تراکنش Provider الزامی است."
        )

    with get_connection() as conn:

        row = conn.execute(
            """
            SELECT *
            FROM card_transfers
            WHERE id = %s
            FOR UPDATE
            """,
            (transfer_id,),
        ).fetchone()

        if not row:
            raise ValueError(
                "درخواست تسویه پیدا نشد."
            )

        if row["status"] != "processing":
            raise ValueError(
                "درخواست در وضعیت processing نیست."
            )

        updated_at = now_iso()

        conn.execute(
            """
            UPDATE card_transfers
            SET
                status = 'completed',
                provider_transfer_id = %s,
                provider_status = %s,
                reserved_amount = 0,
                updated_at = %s,
                processed_at = %s
            WHERE id = %s
            """,
            (
                provider_transfer_id,
                provider_status,
                updated_at,
                updated_at,
                transfer_id,
            ),
        )

        conn.execute(
            """
            INSERT INTO notifications (
                user_id,
                title,
                message,
                notification_type,
                transfer_id,
                is_read,
                created_at
            )
            VALUES (
                %s,
                %s,
                %s,
                'transfer',
                %s,
                0,
                %s
            )
            """,
            (
                row["user_id"],
                "تسویه انجام شد",
                (
                    f"تسویه مبلغ "
                    f"{row['amount']:,.0f} تومان "
                    "با موفقیت انجام شد."
                ),
                transfer_id,
                updated_at,
            ),
        )

    return {
        "success": True,
        "transfer_id": transfer_id,
        "status": "completed",
        "provider_transfer_id":
            provider_transfer_id,
    }


def fail_card_transfer(
    transfer_id: int,
    reason: str,
) -> dict[str, Any]:

    reason = (
        reason.strip()
        if reason
        else "تسویه ناموفق بود."
    )

    with get_connection() as conn:

        row = conn.execute(
            """
            SELECT *
            FROM card_transfers
            WHERE id = %s
            FOR UPDATE
            """,
            (transfer_id,),
        ).fetchone()

        if not row:
            raise ValueError(
                "درخواست تسویه پیدا نشد."
            )

        if row["status"] != "processing":
            raise ValueError(
                "درخواست در وضعیت processing نیست."
            )

        updated_at = now_iso()

        conn.execute(
            """
            UPDATE card_transfers
            SET
                status = 'failed',
                reserved_amount = 0,
                failure_reason = %s,
                updated_at = %s,
                processed_at = %s
            WHERE id = %s
            """,
            (
                reason,
                updated_at,
                updated_at,
                transfer_id,
            ),
        )

        conn.execute(
            """
            INSERT INTO notifications (
                user_id,
                title,
                message,
                notification_type,
                transfer_id,
                is_read,
                created_at
            )
            VALUES (
                %s,
                %s,
                %s,
                'transfer',
                %s,
                0,
                %s
            )
            """,
            (
                row["user_id"],
                "تسویه ناموفق بود",
                (
                    "مبلغ رزرو‌شده آزاد شد. "
                    + reason
                ),
                transfer_id,
                updated_at,
            ),
        )

    return {
        "success": True,
        "transfer_id": transfer_id,
        "status": "failed",
        "failure_reason": reason,
    }


# ============================================================
# Payout attempts
# ============================================================

def create_payout_attempt(
    transfer_id: int,
    provider: str,
    amount: float,
) -> int:

    created_at = now_iso()

    with get_connection() as conn:

        row = conn.execute(
            """
            INSERT INTO payout_attempts (
                transfer_id,
                provider,
                provider_transfer_id,
                amount,
                status,
                response_data,
                error_message,
                created_at,
                updated_at
            )
            VALUES (
                %s,
                %s,
                NULL,
                %s,
                'created',
                NULL,
                NULL,
                %s,
                %s
            )
            RETURNING id
            """,
            (
                transfer_id,
                provider,
                amount,
                created_at,
                created_at,
            ),
        ).fetchone()

    return int(row["id"])


def update_payout_attempt(
    attempt_id: int,
    status: str,
    provider_transfer_id: str | None = None,
    response_data: str | None = None,
    error_message: str | None = None,
) -> None:

    with get_connection() as conn:

        conn.execute(
            """
            UPDATE payout_attempts
            SET
                status = %s,
                provider_transfer_id = %s,
                response_data = %s,
                error_message = %s,
                updated_at = %s
            WHERE id = %s
            """,
            (
                status,
                provider_transfer_id,
                response_data,
                error_message,
                now_iso(),
                attempt_id,
            ),
        )


def get_payout_attempts(
    transfer_id: int,
) -> list[dict[str, Any]]:

    with get_connection() as conn:

        rows = conn.execute(
            """
            SELECT *
            FROM payout_attempts
            WHERE transfer_id = %s
            ORDER BY id DESC
            """,
            (transfer_id,),
        ).fetchall()

    return [
        dict(row)
        for row in rows
    ]


# ============================================================
# Notifications
# ============================================================

def get_notifications(
    user_id: int,
    limit: int = 100,
) -> list[dict[str, Any]]:

    limit = max(
        1,
        min(int(limit), 500),
    )

    with get_connection() as conn:

        rows = conn.execute(
            """
            SELECT *
            FROM notifications
            WHERE user_id = %s
            ORDER BY id DESC
            LIMIT %s
            """,
            (
                user_id,
                limit,
            ),
        ).fetchall()

    return [
        dict(row)
        for row in rows
    ]


def get_unread_notification_count(
    user_id: int,
) -> int:

    with get_connection() as conn:

        row = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM notifications
            WHERE user_id = %s
              AND is_read = 0
            """,
            (user_id,),
        ).fetchone()

    return int(
        row["count"] or 0
    )


def mark_notification_as_read(
    user_id: int,
    notification_id: int,
) -> None:

    with get_connection() as conn:

        conn.execute(
            """
            UPDATE notifications
            SET is_read = 1
            WHERE id = %s
              AND user_id = %s
            """,
            (
                notification_id,
                user_id,
            ),
        )


def mark_all_notifications_as_read(
    user_id: int,
) -> None:

    with get_connection() as conn:

        conn.execute(
            """
            UPDATE notifications
            SET is_read = 1
            WHERE user_id = %s
            """,
            (user_id,),
        )


def delete_notification(
    user_id: int,
    notification_id: int,
) -> None:

    with get_connection() as conn:

        conn.execute(
            """
            DELETE FROM notifications
            WHERE id = %s
              AND user_id = %s
            """,
            (
                notification_id,
                user_id,
            ),
        )