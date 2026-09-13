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


# =========================================================
# Connection
# =========================================================

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


# =========================================================
# Helpers
# =========================================================

def now_iso() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def hash_password(
    password: str,
    salt: bytes | None = None,
) -> tuple[str, str]:

    if salt is None:
        salt = secrets.token_bytes(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_ITERATIONS,
    )

    return (
        digest.hex(),
        salt.hex(),
    )


def verify_password(
    password: str,
    password_hash: str,
    salt_hex: str,
) -> bool:

    try:
        salt = bytes.fromhex(salt_hex)

        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            PASSWORD_ITERATIONS,
        )

        return secrets.compare_digest(
            digest.hex(),
            password_hash,
        )

    except Exception:
        return False


def mask_card_number(
    card_number: str,
) -> str:

    value = str(card_number or "")

    digits = "".join(
        character
        for character in value
        if character.isdigit()
    )

    if len(digits) <= 4:
        return digits

    return (
        "**** **** **** "
        + digits[-4:]
    )


# =========================================================
# Database initialization
# =========================================================

def initialize_database() -> None:

    with get_connection() as conn:

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id BIGSERIAL PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                full_name TEXT NOT NULL DEFAULT '',
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
                card_id BIGINT NOT NULL,
                amount DOUBLE PRECISION NOT NULL,
                request_id TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'completed',
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
                target_type TEXT,
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
                notification_type TEXT NOT NULL DEFAULT 'system',
                transfer_id BIGINT,
                is_read INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE,
                FOREIGN KEY(transfer_id)
                    REFERENCES card_transfers(id)
                    ON DELETE CASCADE
            )
            """
        )

        conn.commit()


# =========================================================
# Users
# =========================================================

def create_user(
    username: str,
    email: str,
    password: str,
    full_name: str = "",
) -> int:

    password_hash, password_salt = hash_password(
        password
    )

    created_at = now_iso()

    with get_connection() as conn:

        row = conn.execute(
            """
            INSERT INTO users (
                username,
                email,
                password_hash,
                password_salt,
                full_name,
                created_at,
                updated_at
            )
            VALUES (
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s
            )
            RETURNING id
            """,
            (
                username,
                email,
                password_hash,
                password_salt,
                full_name,
                created_at,
                created_at,
            ),
        ).fetchone()

        conn.commit()

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


def verify_user_password(
    username: str,
    password: str,
) -> dict[str, Any] | None:

    user = find_user_by_username(
        username
    )

    if not user:
        return None

    valid = verify_password(
        password,
        user["password_hash"],
        user["password_salt"],
    )

    if not valid:
        return None

    return user


def update_user_name(
    user_id: int,
    full_name: str,
) -> dict[str, Any] | None:

    updated_at = now_iso()

    with get_connection() as conn:

        row = conn.execute(
            """
            UPDATE users
            SET
                full_name = %s,
                updated_at = %s
            WHERE id = %s
            RETURNING *
            """,
            (
                full_name,
                updated_at,
                user_id,
            ),
        ).fetchone()

        conn.commit()

    return dict(row) if row else None


def update_user_password(
    user_id: int,
    new_password: str,
) -> bool:

    password_hash, password_salt = hash_password(
        new_password
    )

    updated_at = now_iso()

    with get_connection() as conn:

        result = conn.execute(
            """
            UPDATE users
            SET
                password_hash = %s,
                password_salt = %s,
                updated_at = %s
            WHERE id = %s
            """,
            (
                password_hash,
                password_salt,
                updated_at,
                user_id,
            ),
        )

        conn.commit()

        return result.rowcount > 0


def delete_user(
    user_id: int,
) -> bool:

    with get_connection() as conn:

        result = conn.execute(
            """
            DELETE FROM users
            WHERE id = %s
            """,
            (user_id,),
        )

        conn.commit()

        return result.rowcount > 0


# =========================================================
# Balance
# =========================================================

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


# =========================================================
# Transactions
# =========================================================

def add_transaction(
    user_id: int,
    title: str,
    amount: float,
    transaction_type: str,
    category: str | None = None,
) -> dict[str, Any]:

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
                %s,
                %s,
                %s,
                %s,
                %s,
                %s
            )
            RETURNING *
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

        conn.commit()

    return dict(row)


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


def add_wallet_balance_with_transaction(
    user_id: int,
    amount: float,
    title: str = "افزایش موجودی",
    category: str = "wallet",
) -> dict[str, Any]:

    if amount <= 0:
        raise ValueError(
            "مبلغ نامعتبر است"
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

        conn.commit()

    return {
        "success": True,
        "balance": get_balance(user_id),
    }


def subtract_wallet_balance_with_transaction(
    user_id: int,
    amount: float,
    title: str = "کاهش موجودی",
    category: str = "wallet",
) -> dict[str, Any]:

    if amount <= 0:
        raise ValueError(
            "مبلغ نامعتبر است"
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
                "موجودی کافی نیست"
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

        conn.commit()

    return {
        "success": True,
        "balance": get_balance(user_id),
    }


# =========================================================
# Bank cards
# =========================================================

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
            ORDER BY
                is_default DESC,
                id DESC
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


def add_bank_card(
    user_id: int,
    holder_name: str,
    bank_name: str,
    card_number: str,
) -> dict[str, Any]:

    created_at = now_iso()

    with get_connection() as conn:

        existing = conn.execute(
            """
            SELECT id
            FROM bank_cards
            WHERE user_id = %s
              AND card_number = %s
            """,
            (
                user_id,
                card_number,
            ),
        ).fetchone()

        if existing:
            raise ValueError(
                "این کارت قبلاً ثبت شده است"
            )

        count_row = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM bank_cards
            WHERE user_id = %s
            """,
            (user_id,),
        ).fetchone()

        is_default = (
            1
            if int(count_row["count"] or 0) == 0
            else 0
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
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s
            )
            RETURNING *
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
        ).fetchone()

        conn.commit()

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


def set_default_bank_card(
    user_id: int,
    card_id: int,
) -> dict[str, Any]:

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
                "کارت بانکی پیدا نشد"
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

        row = conn.execute(
            """
            UPDATE bank_cards
            SET
                is_default = 1,
                updated_at = %s
            WHERE id = %s
              AND user_id = %s
            RETURNING *
            """,
            (
                now_iso(),
                card_id,
                user_id,
            ),
        ).fetchone()

        conn.commit()

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


def delete_bank_card(
    user_id: int,
    card_id: int,
) -> bool:

    with get_connection() as conn:

        result = conn.execute(
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

        conn.commit()

        return result.rowcount > 0


# =========================================================
# Wallet deposit
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

        existing = conn.execute(
            """
            SELECT *
            FROM wallet_deposits
            WHERE request_id = %s
            """,
            (request_id,),
        ).fetchone()

        if existing:

            return {
                "deposit": dict(existing),
                "balance": get_balance(user_id),
                "duplicate": True,
            }

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
                "کارت بانکی پیدا نشد"
            )

        created_at = now_iso()

        row = conn.execute(
            """
            INSERT INTO wallet_deposits (
                user_id,
                card_id,
                amount,
                request_id,
                status,
                created_at,
                updated_at
            )
            VALUES (
                %s,
                %s,
                %s,
                %s,
                'completed',
                %s,
                %s
            )
            RETURNING *
            """,
            (
                user_id,
                card_id,
                amount,
                request_id,
                created_at,
                created_at,
            ),
        ).fetchone()

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
                'افزایش موجودی با کارت',
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

        conn.commit()

        balance = get_balance(
            user_id
        )

    return {
        "deposit": dict(row),
        "balance": balance,
        "duplicate": False,
    }


# =========================================================
# Card transfer
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

        # -----------------------------------------
        # جلوگیری از ثبت دوباره همان درخواست
        # -----------------------------------------

        existing = conn.execute(
            """
            SELECT
                ct.*,
                bc.bank_name,
                bc.holder_name,
                bc.card_number
            FROM card_transfers ct
            LEFT JOIN bank_cards bc
                ON bc.id = ct.card_id
            WHERE ct.request_id = %s
            """,
            (request_id,),
        ).fetchone()

        if existing:

            item = dict(existing)

            if item.get("card_number"):
                item["masked_card_number"] = (
                    mask_card_number(
                        item["card_number"]
                    )
                )

            item.pop(
                "card_number",
                None,
            )

            balance = get_balance(
                user_id
            )

            return {
                "success": True,
                "transfer": item,
                "transfer_id": int(
                    item["id"]
                ),
                "balance": balance,
                "duplicate": True,
            }

        # -----------------------------------------
        # بررسی کارت
        # -----------------------------------------

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
                "کارت بانکی پیدا نشد"
            )

        # -----------------------------------------
        # بررسی موجودی
        # -----------------------------------------

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
                "موجودی کافی نیست"
            )

        created_at = now_iso()

        # -----------------------------------------
        # ایجاد درخواست انتقال
        # -----------------------------------------

        row = conn.execute(
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
                %s,
                %s,
                %s,
                %s,
                'pending',
                %s,
                %s
            )
            RETURNING *
            """,
            (
                user_id,
                card_id,
                amount,
                request_id,
                created_at,
                created_at,
            ),
        ).fetchone()

        transfer_id = int(
            row["id"]
        )

        # -----------------------------------------
        # کسر موجودی
        # -----------------------------------------

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
                'card_transfer',
                %s
            )
            """,
            (
                user_id,
                "انتقال به کارت",
                amount,
                created_at,
            ),
        )

        # -----------------------------------------
        # اعلان برای کاربر
        # -----------------------------------------

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
                "درخواست انتقال ثبت شد",
                (
                    f"درخواست انتقال "
                    f"{amount:,.0f} تومان "
                    "ثبت شد و در انتظار "
                    "بررسی است."
                ),
                "transfer",
                transfer_id,
                created_at,
            ),
        )

        conn.commit()

        new_balance = balance - amount

    transfer = dict(row)

    transfer["bank_name"] = (
        card["bank_name"]
    )

    transfer["holder_name"] = (
        card["holder_name"]
    )

    transfer["masked_card_number"] = (
        mask_card_number(
            card["card_number"]
        )
    )

    return {
        "success": True,
        "transfer": transfer,
        "transfer_id": transfer_id,
        "balance": new_balance,
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

        card_number = item.get(
            "card_number"
        )

        if card_number:
            item["masked_card_number"] = (
                mask_card_number(
                    card_number
                )
            )
        else:
            item["masked_card_number"] = (
                "کارت حذف شده"
            )

        item.pop(
            "card_number",
            None,
        )

        status = (
            item.get("status")
            or "pending"
        )

        item["status"] = status

        if status == "pending":
            item["status_text"] = (
                "در انتظار بررسی"
            )
        elif status == "approved":
            item["status_text"] = (
                "تأیید شده"
            )
        elif status == "completed":
            item["status_text"] = (
                "انجام شده"
            )
        elif status == "rejected":
            item["status_text"] = (
                "رد شده"
            )
        elif status == "failed":
            item["status_text"] = (
                "ناموفق"
            )
        else:
            item["status_text"] = status

        result.append(item)

    return result


def get_card_transfer_request(
    user_id: int,
    transfer_id: int,
) -> dict[str, Any] | None:

    with get_connection() as conn:

        row = conn.execute(
            """
            SELECT
                ct.*,
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
        item["masked_card_number"] = (
            mask_card_number(
                item["card_number"]
            )
        )
    else:
        item["masked_card_number"] = (
            "کارت حذف شده"
        )

    item.pop(
        "card_number",
        None,
    )

    return item


def update_card_transfer_status(
    transfer_id: int,
    status: str,
) -> dict[str, Any] | None:

    allowed_statuses = {
        "pending",
        "approved",
        "completed",
        "rejected",
        "failed",
    }

    if status not in allowed_statuses:
        raise ValueError(
            "وضعیت انتقال نامعتبر است"
        )

    updated_at = now_iso()

    with get_connection() as conn:

        row = conn.execute(
            """
            UPDATE card_transfers
            SET
                status = %s,
                updated_at = %s
            WHERE id = %s
            RETURNING *
            """,
            (
                status,
                updated_at,
                transfer_id,
            ),
        ).fetchone()

        conn.commit()

    if not row:
        return None

    return dict(row)


def get_all_card_transfer_requests(
    limit: int = 500,
) -> list[dict[str, Any]]:

    limit = max(
        1,
        min(int(limit), 2000),
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
                u.email,
                u.full_name,
                bc.bank_name,
                bc.holder_name,
                bc.card_number
            FROM card_transfers ct
            LEFT JOIN users u
                ON u.id = ct.user_id
            LEFT JOIN bank_cards bc
                ON bc.id = ct.card_id
            ORDER BY ct.id DESC
            LIMIT %s
            """,
            (limit,),
        ).fetchall()

    result = []

    for row in rows:

        item = dict(row)

        if item.get("card_number"):
            item["masked_card_number"] = (
                mask_card_number(
                    item["card_number"]
                )
            )
        else:
            item["masked_card_number"] = (
                "کارت حذف شده"
            )

        item.pop(
            "card_number",
            None,
        )

        result.append(item)

    return result


# =========================================================
# Notifications
# =========================================================

def get_notifications(
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
) -> bool:

    with get_connection() as conn:

        result = conn.execute(
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

        conn.commit()

        return result.rowcount > 0


def mark_all_notifications_as_read(
    user_id: int,
) -> int:

    with get_connection() as conn:

        result = conn.execute(
            """
            UPDATE notifications
            SET is_read = 1
            WHERE user_id = %s
              AND is_read = 0
            """,
            (user_id,),
        )

        conn.commit()

        return result.rowcount


def delete_notification(
    user_id: int,
    notification_id: int,
) -> bool:

    with get_connection() as conn:

        result = conn.execute(
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

        conn.commit()

        return result.rowcount > 0


# =========================================================
# Admin logs
# =========================================================

def add_admin_action_log(
    admin_name: str,
    action: str,
    target_type: str | None = None,
    target_id: int | None = None,
    details: str | None = None,
) -> dict[str, Any]:

    created_at = now_iso()

    with get_connection() as conn:

        row = conn.execute(
            """
            INSERT INTO admin_action_logs (
                admin_name,
                action,
                target_type,
                target_id,
                details,
                created_at
            )
            VALUES (
                %s,
                %s,
                %s,
                %s,
                %s,
                %s
            )
            RETURNING *
            """,
            (
                admin_name,
                action,
                target_type,
                target_id,
                details,
                created_at,
            ),
        ).fetchone()

        conn.commit()

    return dict(row)