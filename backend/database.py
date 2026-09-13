from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


# =========================================================
# PATH
# =========================================================

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "kifyar.db"


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
        "PRAGMA journal_mode = WAL"
    )

    return connection


def now_iso() -> str:

    return datetime.now(
        timezone.utc
    ).isoformat()


# =========================================================
# PASSWORD
# =========================================================

def hash_password(
    password: str,
) -> str:

    return hashlib.sha256(
        password.encode("utf-8")
    ).hexdigest()


def verify_password(
    password: str,
    password_hash: str,
) -> bool:

    password = str(
        password
    )

    password_hash = str(
        password_hash
    )

    # رمز یک بار هش شده
    single_hash = hash_password(
        password
    )

    if single_hash == password_hash:
        return True

    # سازگاری با حساب‌های قدیمی که
    # رمز عبور آنها دوبار هش شده است
    double_hash = hash_password(
        single_hash
    )

    if double_hash == password_hash:
        return True

    return False


# =========================================================
# INITIALIZE DATABASE
# =========================================================

def initialize_database() -> None:

    connection = get_connection()

    try:

        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                name TEXT,
                email TEXT UNIQUE,
                password_hash TEXT,
                created_at TEXT
            );

            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT DEFAULT '',
                amount REAL NOT NULL DEFAULT 0,
                transaction_type TEXT NOT NULL,
                category TEXT DEFAULT 'other',
                description TEXT DEFAULT '',
                created_at TEXT,
                FOREIGN KEY (user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS bank_cards (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                holder_name TEXT DEFAULT '',
                bank_name TEXT DEFAULT '',
                card_number TEXT NOT NULL,
                title TEXT DEFAULT '',
                is_default INTEGER DEFAULT 0,
                created_at TEXT,
                FOREIGN KEY (user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS wallet_deposits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                request_id TEXT UNIQUE NOT NULL,
                card_id INTEGER,
                amount REAL NOT NULL,
                status TEXT DEFAULT 'completed',
                created_at TEXT,
                FOREIGN KEY (user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS card_transfers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                request_id TEXT UNIQUE NOT NULL,
                card_id INTEGER NOT NULL,
                amount REAL NOT NULL,
                status TEXT DEFAULT 'pending',
                created_at TEXT,
                updated_at TEXT,
                FOREIGN KEY (user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE,
                FOREIGN KEY (card_id)
                    REFERENCES bank_cards(id)
                    ON DELETE CASCADE
            );
            """
        )

        migrate_database(
            connection
        )

        connection.commit()

    finally:

        connection.close()


# =========================================================
# MIGRATION
# =========================================================

def migrate_database(
    connection: sqlite3.Connection,
) -> None:

    # -----------------------------------------------------
    # USERS
    # -----------------------------------------------------

    user_columns = {
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(users)"
        ).fetchall()
    }

    required_user_columns = {
        "username": "TEXT",
        "name": "TEXT",
        "email": "TEXT",
        "password_hash": "TEXT",
        "created_at": "TEXT",
    }

    for column, definition in (
        required_user_columns.items()
    ):

        if column not in user_columns:

            try:

                connection.execute(
                    f"""
                    ALTER TABLE users
                    ADD COLUMN {column} {definition}
                    """
                )

            except sqlite3.OperationalError:

                pass

    # -----------------------------------------------------
    # TRANSACTIONS
    # -----------------------------------------------------

    transaction_columns = {
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(transactions)"
        ).fetchall()
    }

    required_transaction_columns = {
        "title": "TEXT DEFAULT ''",
        "amount": "REAL DEFAULT 0",
        "transaction_type": "TEXT DEFAULT 'expense'",
        "category": "TEXT DEFAULT 'other'",
        "description": "TEXT DEFAULT ''",
        "created_at": "TEXT",
    }

    for column, definition in (
        required_transaction_columns.items()
    ):

        if column not in transaction_columns:

            try:

                connection.execute(
                    f"""
                    ALTER TABLE transactions
                    ADD COLUMN {column} {definition}
                    """
                )

            except sqlite3.OperationalError:

                pass

    # -----------------------------------------------------
    # BANK CARDS
    # -----------------------------------------------------

    card_columns = {
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(bank_cards)"
        ).fetchall()
    }

    required_card_columns = {
        "holder_name": "TEXT DEFAULT ''",
        "bank_name": "TEXT DEFAULT ''",
        "card_number": "TEXT",
        "title": "TEXT DEFAULT ''",
        "is_default": "INTEGER DEFAULT 0",
        "created_at": "TEXT",
    }

    for column, definition in (
        required_card_columns.items()
    ):

        if column not in card_columns:

            try:

                connection.execute(
                    f"""
                    ALTER TABLE bank_cards
                    ADD COLUMN {column} {definition}
                    """
                )

            except sqlite3.OperationalError:

                pass

    # -----------------------------------------------------
    # WALLET DEPOSITS
    # -----------------------------------------------------

    deposit_columns = {
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(wallet_deposits)"
        ).fetchall()
    }

    required_deposit_columns = {
        "request_id": "TEXT",
        "card_id": "INTEGER",
        "amount": "REAL DEFAULT 0",
        "status": "TEXT DEFAULT 'completed'",
        "created_at": "TEXT",
    }

    for column, definition in (
        required_deposit_columns.items()
    ):

        if column not in deposit_columns:

            try:

                connection.execute(
                    f"""
                    ALTER TABLE wallet_deposits
                    ADD COLUMN {column} {definition}
                    """
                )

            except sqlite3.OperationalError:

                pass

    # -----------------------------------------------------
    # CARD TRANSFERS
    # -----------------------------------------------------

    transfer_columns = {
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(card_transfers)"
        ).fetchall()
    }

    required_transfer_columns = {
        "request_id": "TEXT",
        "card_id": "INTEGER",
        "amount": "REAL DEFAULT 0",
        "status": "TEXT DEFAULT 'pending'",
        "created_at": "TEXT",
        "updated_at": "TEXT",
    }

    for column, definition in (
        required_transfer_columns.items()
    ):

        if column not in transfer_columns:

            try:

                connection.execute(
                    f"""
                    ALTER TABLE card_transfers
                    ADD COLUMN {column} {definition}
                    """
                )

            except sqlite3.OperationalError:

                pass


# =========================================================
# USERS
# =========================================================

def create_user(
    username: str,
    email: str,
    password: str,
) -> dict[str, Any]:

    username = str(
        username
    ).strip()

    email = str(
        email
    ).strip().lower()

    password = str(
        password
    )

    connection = get_connection()

    try:

        created_at = now_iso()

        cursor = connection.execute(
            """
            INSERT INTO users
            (
                username,
                name,
                email,
                password_hash,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                username,
                username,
                email,
                hash_password(password),
                created_at,
            ),
        )

        connection.commit()

        return {
            "id": cursor.lastrowid,
            "username": username,
            "name": username,
            "email": email,
            "created_at": created_at,
        }

    finally:

        connection.close()


def find_user(
    identifier: str,
) -> Optional[dict[str, Any]]:

    value = str(
        identifier
    ).strip()

    if not value:

        return None

    connection = get_connection()

    try:

        row = connection.execute(
            """
            SELECT *
            FROM users
            WHERE
                LOWER(email) = LOWER(?)
                OR LOWER(username) = LOWER(?)
            LIMIT 1
            """,
            (
                value,
                value,
            ),
        ).fetchone()

        if row is None:

            return None

        return dict(row)

    finally:

        connection.close()


def find_user_by_id(
    user_id: int,
) -> Optional[dict[str, Any]]:

    connection = get_connection()

    try:

        row = connection.execute(
            """
            SELECT *
            FROM users
            WHERE id = ?
            LIMIT 1
            """,
            (
                int(user_id),
            ),
        ).fetchone()

        if row is None:

            return None

        return dict(row)

    finally:

        connection.close()


def get_user_by_id(
    user_id: int,
) -> Optional[dict[str, Any]]:

    return find_user_by_id(
        user_id
    )


# =========================================================
# USER NAME
# =========================================================

def update_user_name(
    user_id: int,
    name: str,
) -> bool:

    name = str(
        name
    ).strip()

    connection = get_connection()

    try:

        cursor = connection.execute(
            """
            UPDATE users
            SET name = ?,
                username = ?
            WHERE id = ?
            """,
            (
                name,
                name,
                int(user_id),
            ),
        )

        connection.commit()

        return cursor.rowcount > 0

    finally:

        connection.close()


# =========================================================
# PASSWORD CHANGE
# =========================================================

def update_user_password(
    user_id: int,
    current_password: str,
    new_password: str,
) -> bool:

    connection = get_connection()

    try:

        row = connection.execute(
            """
            SELECT password_hash
            FROM users
            WHERE id = ?
            LIMIT 1
            """,
            (
                int(user_id),
            ),
        ).fetchone()

        if row is None:

            raise ValueError(
                "کاربر پیدا نشد."
            )

        current_hash = row["password_hash"]

        if not current_hash:

            raise ValueError(
                "رمز عبور کاربر ثبت نشده است."
            )

        if not verify_password(
            current_password,
            current_hash,
        ):

            raise ValueError(
                "رمز عبور فعلی اشتباه است."
            )

        connection.execute(
            """
            UPDATE users
            SET password_hash = ?
            WHERE id = ?
            """,
            (
                hash_password(
                    new_password
                ),
                int(user_id),
            ),
        )

        connection.commit()

        return True

    finally:

        connection.close()


# =========================================================
# DELETE USER
# =========================================================

def delete_user(
    user_id: int,
) -> bool:

    connection = get_connection()

    try:

        cursor = connection.execute(
            """
            DELETE FROM users
            WHERE id = ?
            """,
            (
                int(user_id),
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
    title: str = "",
    amount: float = 0,
    transaction_type: str = "expense",
    category: str = "other",
    description: str = "",
    connection: Optional[
        sqlite3.Connection
    ] = None,
) -> int:

    own_connection = (
        connection is None
    )

    if own_connection:

        connection = get_connection()

    try:

        cursor = connection.execute(
            """
            INSERT INTO transactions
            (
                user_id,
                title,
                amount,
                transaction_type,
                category,
                description,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(user_id),
                str(title),
                float(amount),
                str(transaction_type),
                str(category),
                str(description),
                now_iso(),
            ),
        )

        if own_connection:

            connection.commit()

        return int(
            cursor.lastrowid
        )

    finally:

        if own_connection:

            connection.close()


def get_transactions(
    user_id: int,
    limit: int = 200,
) -> list[dict[str, Any]]:

    connection = get_connection()

    try:

        rows = connection.execute(
            """
            SELECT *
            FROM transactions
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (
                int(user_id),
                int(limit),
            ),
        ).fetchall()

        return [
            dict(row)
            for row in rows
        ]

    finally:

        connection.close()


def delete_transactions(
    user_id: int,
) -> int:

    connection = get_connection()

    try:

        cursor = connection.execute(
            """
            DELETE FROM transactions
            WHERE user_id = ?
            """,
            (
                int(user_id),
            ),
        )

        connection.commit()

        return cursor.rowcount

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

        return get_balance_from_connection(
            connection,
            user_id,
        )

    finally:

        connection.close()


def get_wallet_balance(
    user_id: int,
) -> float:

    return get_balance(
        user_id
    )


def get_balance_from_connection(
    connection: sqlite3.Connection,
    user_id: int,
) -> float:

    row = connection.execute(
        """
        SELECT
            COALESCE(
                SUM(
                    CASE
                        WHEN transaction_type
                            IN ('income', 'deposit')
                        THEN amount

                        WHEN transaction_type
                            IN ('expense', 'withdrawal')
                        THEN -amount

                        ELSE 0
                    END
                ),
                0
            ) AS balance
        FROM transactions
        WHERE user_id = ?
        """,
        (
            int(user_id),
        ),
    ).fetchone()

    return float(
        row["balance"] or 0
    )


# =========================================================
# WALLET ADD
# =========================================================

def add_wallet_balance_with_transaction(
    user_id: int,
    amount: float,
    title: str = "افزایش موجودی",
    category: str = "deposit",
) -> dict[str, Any]:

    amount = float(
        amount
    )

    if amount <= 0:

        raise ValueError(
            "مبلغ باید بیشتر از صفر باشد."
        )

    connection = get_connection()

    try:

        transaction_id = add_transaction(
            user_id=user_id,
            title=title,
            amount=amount,
            transaction_type="income",
            category=category,
            connection=connection,
        )

        connection.commit()

        return {
            "success": True,
            "transaction_id": transaction_id,
            "amount": amount,
            "balance":
                get_balance_from_connection(
                    connection,
                    user_id,
                ),
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
    title: str = "کاهش موجودی",
    category: str = "expense",
) -> dict[str, Any]:

    amount = float(
        amount
    )

    if amount <= 0:

        raise ValueError(
            "مبلغ باید بیشتر از صفر باشد."
        )

    connection = get_connection()

    try:

        balance = get_balance_from_connection(
            connection,
            user_id,
        )

        if balance < amount:

            raise ValueError(
                "موجودی کافی نیست."
            )

        transaction_id = add_transaction(
            user_id=user_id,
            title=title,
            amount=amount,
            transaction_type="expense",
            category=category,
            connection=connection,
        )

        connection.commit()

        return {
            "success": True,
            "transaction_id": transaction_id,
            "amount": amount,
            "balance":
                get_balance_from_connection(
                    connection,
                    user_id,
                ),
        }

    except Exception:

        connection.rollback()

        raise

    finally:

        connection.close()


# =========================================================
# BANK CARDS
# =========================================================

def mask_card_number(
    card_number: str,
) -> str:

    digits = "".join(
        ch
        for ch in str(card_number)
        if ch.isdigit()
    )

    if len(digits) <= 4:

        return "****"

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

    digits = "".join(
        ch
        for ch in str(card_number)
        if ch.isdigit()
    )

    if len(digits) != 16:

        raise ValueError(
            "شماره کارت باید 16 رقم باشد."
        )

    connection = get_connection()

    try:

        existing = connection.execute(
            """
            SELECT id
            FROM bank_cards
            WHERE user_id = ?
            AND card_number = ?
            LIMIT 1
            """,
            (
                int(user_id),
                digits,
            ),
        ).fetchone()

        if existing is not None:

            raise ValueError(
                "این کارت قبلاً ثبت شده است."
            )

        count_row = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM bank_cards
            WHERE user_id = ?
            """,
            (
                int(user_id),
            ),
        ).fetchone()

        is_first = (
            int(count_row["count"]) == 0
        )

        cursor = connection.execute(
            """
            INSERT INTO bank_cards
            (
                user_id,
                holder_name,
                bank_name,
                card_number,
                title,
                is_default,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(user_id),
                str(holder_name).strip(),
                str(bank_name).strip(),
                digits,
                str(bank_name).strip(),
                1 if is_first else 0,
                now_iso(),
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
            SELECT *
            FROM bank_cards
            WHERE user_id = ?
            ORDER BY
                is_default DESC,
                id DESC
            """,
            (
                int(user_id),
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

            result.append(
                item
            )

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
            SELECT *
            FROM bank_cards
            WHERE id = ?
            AND user_id = ?
            LIMIT 1
            """,
            (
                int(card_id),
                int(user_id),
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

        card = connection.execute(
            """
            SELECT id
            FROM bank_cards
            WHERE id = ?
            AND user_id = ?
            LIMIT 1
            """,
            (
                int(card_id),
                int(user_id),
            ),
        ).fetchone()

        if card is None:

            return False

        connection.execute(
            """
            UPDATE bank_cards
            SET is_default = 0
            WHERE user_id = ?
            """,
            (
                int(user_id),
            ),
        )

        connection.execute(
            """
            UPDATE bank_cards
            SET is_default = 1
            WHERE id = ?
            AND user_id = ?
            """,
            (
                int(card_id),
                int(user_id),
            ),
        )

        connection.commit()

        return True

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
                int(card_id),
                int(user_id),
            ),
        )

        connection.commit()

        return cursor.rowcount > 0

    finally:

        connection.close()


# =========================================================
# CARD DEPOSIT
# =========================================================

def deposit_by_card_once(
    user_id: int,
    card_id: int,
    amount: float,
    request_id: str,
) -> dict[str, Any]:

    amount = float(
        amount
    )

    if amount <= 0:

        raise ValueError(
            "مبلغ باید بیشتر از صفر باشد."
        )

    connection = get_connection()

    try:

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

            return {
                "success": True,
                "duplicate": True,
                "deposit": dict(existing),
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
                int(card_id),
                int(user_id),
            ),
        ).fetchone()

        if card is None:

            raise ValueError(
                "کارت بانکی پیدا نشد."
            )

        created_at = now_iso()

        connection.execute(
            """
            INSERT INTO wallet_deposits
            (
                user_id,
                request_id,
                card_id,
                amount,
                status,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                int(user_id),
                request_id,
                int(card_id),
                amount,
                "completed",
                created_at,
            ),
        )

        transaction_id = add_transaction(
            user_id=user_id,
            title="واریز با کارت",
            amount=amount,
            transaction_type="income",
            category="deposit",
            connection=connection,
        )

        connection.commit()

        return {
            "success": True,
            "duplicate": False,
            "request_id": request_id,
            "transaction_id": transaction_id,
            "amount": amount,
            "balance":
                get_balance_from_connection(
                    connection,
                    user_id,
                ),
        }

    except Exception:

        connection.rollback()

        raise

    finally:

        connection.close()


# =========================================================
# WALLET -> CARD
# =========================================================

def transfer_wallet_to_card_once(
    user_id: int,
    card_id: int,
    amount: float,
    request_id: str,
) -> dict[str, Any]:

    amount = float(
        amount
    )

    if amount <= 0:

        raise ValueError(
            "مبلغ باید بیشتر از صفر باشد."
        )

    connection = get_connection()

    try:

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

            return {
                "success": True,
                "duplicate": True,
                "transfer": dict(existing),
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
                int(card_id),
                int(user_id),
            ),
        ).fetchone()

        if card is None:

            raise ValueError(
                "کارت بانکی پیدا نشد."
            )

        balance = get_balance_from_connection(
            connection,
            user_id,
        )

        if balance < amount:

            raise ValueError(
                "موجودی کیف پول کافی نیست."
            )

        created_at = now_iso()

        cursor = connection.execute(
            """
            INSERT INTO card_transfers
            (
                user_id,
                request_id,
                card_id,
                amount,
                status,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(user_id),
                request_id,
                int(card_id),
                amount,
                "pending",
                created_at,
                created_at,
            ),
        )

        transfer_id = int(
            cursor.lastrowid
        )

        add_transaction(
            user_id=user_id,
            title="انتقال به کارت",
            amount=amount,
            transaction_type="expense",
            category="transfer",
            description="درخواست انتقال به کارت بانکی",
            connection=connection,
        )

        connection.commit()

        return {
            "success": True,
            "duplicate": False,
            "transfer_id": transfer_id,
            "request_id": request_id,
            "amount": amount,
            "status": "pending",
            "balance":
                get_balance_from_connection(
                    connection,
                    user_id,
                ),
        }

    except Exception:

        connection.rollback()

        raise

    finally:

        connection.close()


# =========================================================
# CARD TRANSFER GET
# =========================================================

def get_card_transfer_requests(
    user_id: int,
    limit: int = 100,
) -> list[dict[str, Any]]:

    connection = get_connection()

    try:

        rows = connection.execute(
            """
            SELECT
                ct.*,
                bc.holder_name,
                bc.bank_name,
                bc.card_number
            FROM card_transfers ct
            LEFT JOIN bank_cards bc
                ON bc.id = ct.card_id
            WHERE ct.user_id = ?
            ORDER BY ct.id DESC
            LIMIT ?
            """,
            (
                int(user_id),
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
                None,
            )

            result.append(
                item
            )

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
                ct.*,
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
                int(transfer_id),
                int(user_id),
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
            None,
        )

        return item

    finally:

        connection.close()


def update_card_transfer_status(
    transfer_id: int,
    status: str,
) -> bool:

    allowed = {
        "pending",
        "completed",
        "failed",
        "cancelled",
    }

    status = str(
        status
    ).strip().lower()

    if status not in allowed:

        raise ValueError(
            "وضعیت انتقال نامعتبر است."
        )

    connection = get_connection()

    try:

        cursor = connection.execute(
            """
            UPDATE card_transfers
            SET status = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                status,
                now_iso(),
                int(transfer_id),
            ),
        )

        connection.commit()

        return cursor.rowcount > 0

    finally:

        connection.close()


# =========================================================
# START
# =========================================================

initialize_database()
