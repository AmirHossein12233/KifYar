from __future__ import annotations

import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.database import (
    initialize_database,
    get_connection,
    find_user_by_id,
    update_user_name,
    update_user_password,
    delete_user,
    verify_user_password,
    get_balance,
    get_available_balance,
    get_reserved_amount,
    get_transactions,
    add_wallet_balance_with_transaction,
    get_bank_cards,
    add_bank_card,
    set_default_bank_card,
    delete_bank_card,
    transfer_wallet_to_card_once,
    get_card_transfer_request,
    get_card_transfer_requests,
    approve_card_transfer,
    reject_card_transfer,
    mark_transfer_processing,
    complete_card_transfer,
    fail_card_transfer,
    get_notifications,
    get_unread_notification_count,
    mark_notification_as_read,
    mark_all_notifications_as_read,
    delete_notification,
)

from backend.auth import router as auth_router


# ============================================================
# SETTINGS
# ============================================================

APP_NAME = "KifYar"
APP_VERSION = "1.0.0"

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()

FRONTEND_URL = os.getenv(
    "FRONTEND_URL",
    "https://kifyar-web.onrender.com",
).strip()

ADMIN_KEY = os.getenv("ADMIN_KEY", "").strip()

ZARINPAL_MERCHANT_ID = os.getenv(
    "ZARINPAL_MERCHANT_ID",
    "",
).strip()

ZARINPAL_CALLBACK_URL = os.getenv(
    "ZARINPAL_CALLBACK_URL",
    "https://kifyar-api.onrender.com/api/payment/zarinpal/callback",
).strip()

ZARINPAL_SANDBOX = (
    os.getenv("ZARINPAL_SANDBOX", "false")
    .strip()
    .lower()
    in {"1", "true", "yes", "on"}
)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ============================================================
# SESSION
# ============================================================

try:
    from backend.session import require_session_user_id
except Exception:

    def require_session_user_id(request: Request) -> int:
        authorization = request.headers.get(
            "Authorization",
            "",
        )

        if not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=401,
                detail="ورود لازم است.",
            )

        token = authorization[7:].strip()

        if not token:
            raise HTTPException(
                status_code=401,
                detail="توکن نامعتبر است.",
            )

        try:
            from backend.auth import tokens
        except Exception:
            raise HTTPException(
                status_code=500,
                detail="سیستم ورود در دسترس نیست.",
            )

        user_id = tokens.get(token)

        if user_id is None:
            raise HTTPException(
                status_code=401,
                detail="جلسه ورود معتبر نیست.",
            )

        return int(user_id)


# ============================================================
# DATABASE EXTRA SCHEMA
# ============================================================

def ensure_runtime_schema() -> None:

    with get_connection() as conn:

        conn.execute(
            """
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS is_admin
            BOOLEAN NOT NULL DEFAULT FALSE
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS zarinpal_payments (
                id BIGSERIAL PRIMARY KEY,

                user_id BIGINT NOT NULL,

                amount_toman DOUBLE PRECISION NOT NULL,

                amount_rial BIGINT NOT NULL,

                request_id TEXT NOT NULL UNIQUE,

                authority TEXT UNIQUE,

                status TEXT NOT NULL DEFAULT 'created',

                ref_id TEXT,

                response_code INTEGER,

                fee DOUBLE PRECISION,

                error_message TEXT,

                created_at TEXT NOT NULL,

                updated_at TEXT NOT NULL,

                paid_at TEXT,

                CONSTRAINT fk_zarinpal_user
                    FOREIGN KEY (user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            )
            """
        )

        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_zarinpal_user
            ON zarinpal_payments(user_id)
            """
        )

        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_zarinpal_authority
            ON zarinpal_payments(authority)
            """
        )


# ============================================================
# APP LIFESPAN
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):

    if not DATABASE_URL:

        print(
            "WARNING: DATABASE_URL تنظیم نشده است."
        )

    else:

        initialize_database()

        ensure_runtime_schema()

        print(
            "KifYar database initialized successfully."
        )

    yield


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    lifespan=lifespan,
)


# ============================================================
# CORS
# ============================================================

allowed_origins = [
    FRONTEND_URL,
    "https://kifyar-web.onrender.com",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(
        dict.fromkeys(allowed_origins)
    ),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# MODELS
# ============================================================

class NameUpdateRequest(BaseModel):
    full_name: str = Field(
        default="",
        max_length=100,
    )


class PasswordUpdateRequest(BaseModel):
    current_password: str
    new_password: str = Field(
        min_length=6,
        max_length=200,
    )


class AddCardRequest(BaseModel):
    card_number: str
    title: str = Field(
        default="",
        max_length=100,
    )


class DepositRequest(BaseModel):
    amount: float = Field(gt=0)
    request_id: str | None = None


class TransferRequest(BaseModel):
    card_id: int = Field(gt=0)
    amount: float = Field(gt=0)


class WithdrawRequest(BaseModel):
    card_id: int = Field(gt=0)
    amount: float = Field(gt=0)


class AdminActionRequest(BaseModel):
    reason: str = Field(
        default="",
        max_length=500,
    )


class ZarinPalRequest(BaseModel):
    amount: float = Field(gt=0)

    description: str = Field(
        default="افزایش موجودی کیف‌یار",
        max_length=500,
    )


# ============================================================
# BASIC
# ============================================================

@app.get("/")
def root():

    return {
        "ok": True,
        "success": True,
        "app": APP_NAME,
        "version": APP_VERSION,
        "database": bool(DATABASE_URL),
        "frontend": bool(FRONTEND_URL),
    }


@app.get("/health")
def health():

    return {
        "ok": True,
        "success": True,
        "app": APP_NAME,
        "version": APP_VERSION,
        "database": bool(DATABASE_URL),
        "frontend": bool(FRONTEND_URL),
        "zarinpal_configured": bool(
            ZARINPAL_MERCHANT_ID
        ),
        "time": now_iso(),
    }


# ============================================================
# USER HELPERS
# ============================================================

def get_current_user(
    request: Request,
) -> dict[str, Any]:

    user_id = require_session_user_id(
        request
    )

    user = find_user_by_id(user_id)

    if not user:

        raise HTTPException(
            status_code=404,
            detail="کاربر پیدا نشد.",
        )

    return user


def public_user(
    user: dict[str, Any],
) -> dict[str, Any]:

    return {
        "id": user.get("id"),
        "username": user.get("username"),
        "email": user.get("email"),
        "name": user.get(
            "full_name",
            "",
        ),
        "full_name": user.get(
            "full_name",
            "",
        ),
        "is_admin": bool(
            user.get(
                "is_admin",
                False,
            )
        ),
        "created_at": user.get(
            "created_at"
        ),
    }


# ============================================================
# ADMIN AUTH
# ============================================================

def require_admin(
    request: Request,
) -> None:

    if not ADMIN_KEY:

        raise HTTPException(
            status_code=503,
            detail="ADMIN_KEY روی سرور تنظیم نشده است.",
        )

    supplied = request.headers.get(
        "X-Admin-Key",
        "",
    )

    if not supplied:

        raise HTTPException(
            status_code=401,
            detail="کلید مدیر ارسال نشده است.",
        )

    if not secrets.compare_digest(
        supplied,
        ADMIN_KEY,
    ):

        raise HTTPException(
            status_code=403,
            detail="کلید مدیر نامعتبر است.",
        )


# ============================================================
# BALANCE
# ============================================================

@app.get("/api/balance")
def api_balance(
    request: Request,
):

    user_id = require_session_user_id(
        request
    )

    balance = get_balance(user_id)

    reserved = get_reserved_amount(
        user_id
    )

    available = get_available_balance(
        user_id
    )

    return {
        "success": True,
        "balance": balance,
        "reserved": reserved,
        "available": available,
    }


# ============================================================
# TRANSACTIONS
# ============================================================

@app.get("/api/transactions")
def api_transactions(
    request: Request,
):

    user_id = require_session_user_id(
        request
    )

    transactions = get_transactions(
        user_id
    )

    return {
        "success": True,
        "transactions": transactions,
    }


# ============================================================
# PROFILE
# ============================================================

@app.get("/api/profile")
def api_profile(
    request: Request,
):

    user = get_current_user(
        request
    )

    return {
        "success": True,
        "user": public_user(user),
    }


@app.put("/api/profile")
def api_update_profile(
    payload: NameUpdateRequest,
    request: Request,
):

    user_id = require_session_user_id(
        request
    )

    name = payload.full_name.strip()

    update_user_name(
        user_id,
        name,
    )

    user = find_user_by_id(
        user_id
    )

    return {
        "success": True,
        "user": public_user(user),
    }


# ============================================================
# CHANGE PASSWORD
# ============================================================

@app.post("/api/change-password")
def api_change_password(
    payload: PasswordUpdateRequest,
    request: Request,
):

    user_id = require_session_user_id(
        request
    )

    user = find_user_by_id(
        user_id
    )

    if not user:

        raise HTTPException(
            status_code=404,
            detail="کاربر پیدا نشد.",
        )

    verified = verify_user_password(
        user["username"],
        payload.current_password,
    )

    if not verified:

        raise HTTPException(
            status_code=400,
            detail="رمز فعلی اشتباه است.",
        )

    update_user_password(
        user_id,
        payload.new_password,
    )

    return {
        "success": True,
        "message": "رمز عبور با موفقیت تغییر کرد.",
    }


# ============================================================
# DELETE ACCOUNT
# ============================================================

@app.delete("/api/account")
def api_delete_account(
    request: Request,
):

    user_id = require_session_user_id(
        request
    )

    result = delete_user(
        user_id
    )

    return {
        "success": True,
        "deleted": result,
        "message": "حساب کاربری حذف شد.",
    }


# ============================================================
# BANK CARDS
# ============================================================

@app.get("/api/cards")
def api_cards(
    request: Request,
):

    user_id = require_session_user_id(
        request
    )

    return {
        "success": True,
        "cards": get_bank_cards(user_id),
    }


@app.post("/api/cards")
def api_add_card(
    payload: AddCardRequest,
    request: Request,
):

    user_id = require_session_user_id(
        request
    )

    card_number = "".join(
        ch
        for ch in payload.card_number
        if ch.isdigit()
    )

    if len(card_number) != 16:

        raise HTTPException(
            status_code=400,
            detail="شماره کارت باید ۱۶ رقم باشد.",
        )

    card_id = add_bank_card(
        user_id=user_id,
        card_number=card_number,
        title=payload.title.strip(),
    )

    return {
        "success": True,
        "card_id": card_id,
        "cards": get_bank_cards(user_id),
    }


@app.post(
    "/api/cards/{card_id}/default"
)
def api_default_card(
    card_id: int,
    request: Request,
):

    user_id = require_session_user_id(
        request
    )

    result = set_default_bank_card(
        user_id,
        card_id,
    )

    return {
        "success": True,
        "result": result,
        "cards": get_bank_cards(user_id),
    }


@app.delete(
    "/api/cards/{card_id}"
)
def api_delete_card(
    card_id: int,
    request: Request,
):

    user_id = require_session_user_id(
        request
    )

    result = delete_bank_card(
        user_id,
        card_id,
    )

    return {
        "success": True,
        "result": result,
        "cards": get_bank_cards(user_id),
    }


# ============================================================
# MANUAL DEPOSIT
# ============================================================

@app.post("/api/deposit")
def api_deposit(
    payload: DepositRequest,
    request: Request,
):

    user_id = require_session_user_id(
        request
    )

    amount = float(
        payload.amount
    )

    request_id = (
        payload.request_id.strip()
        if payload.request_id
        else secrets.token_urlsafe(24)
    )

    result = add_wallet_balance_with_transaction(
        user_id,
        amount,
        request_id,
    )

    return {
        "success": True,
        "result": result,
        "balance": get_balance(user_id),
        "available": get_available_balance(
            user_id
        ),
    }


# ============================================================
# TRANSFERS
# ============================================================

@app.post("/api/transfers")
def api_create_transfer(
    payload: TransferRequest,
    request: Request,
):

    user_id = require_session_user_id(
        request
    )

    available = get_available_balance(
        user_id
    )

    if payload.amount > available:

        raise HTTPException(
            status_code=400,
            detail="موجودی قابل برداشت کافی نیست.",
        )

    try:

        result = transfer_wallet_to_card_once(
            user_id=user_id,
            card_id=payload.card_id,
            amount=float(
                payload.amount
            ),
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    return {
        "success": True,
        "transfer": result,
        "balance": get_balance(
            user_id
        ),
        "reserved": get_reserved_amount(
            user_id
        ),
        "available": get_available_balance(
            user_id
        ),
    }


@app.get("/api/transfers")
def api_transfers(
    request: Request,
):

    user_id = require_session_user_id(
        request
    )

    return {
        "success": True,
        "transfers": get_card_transfer_requests(
            user_id
        ),
    }


@app.get(
    "/api/transfers/{transfer_id}"
)
def api_transfer(
    transfer_id: int,
    request: Request,
):

    user_id = require_session_user_id(
        request
    )

    transfer = get_card_transfer_request(
        transfer_id,
        user_id=user_id,
    )

    if not transfer:

        raise HTTPException(
            status_code=404,
            detail="درخواست انتقال پیدا نشد.",
        )

    return {
        "success": True,
        "transfer": transfer,
    }


# ============================================================
# WITHDRAW
# ============================================================

@app.post("/api/withdraw")
def api_withdraw(
    payload: WithdrawRequest,
    request: Request,
):

    user_id = require_session_user_id(
        request
    )

    amount = float(
        payload.amount
    )

    if amount <= 0:

        raise HTTPException(
            status_code=400,
            detail="مبلغ برداشت نامعتبر است.",
        )

    if amount < 1000:

        raise HTTPException(
            status_code=400,
            detail="حداقل مبلغ برداشت ۱۰۰۰ تومان است.",
        )

    available = get_available_balance(
        user_id
    )

    if amount > available:

        raise HTTPException(
            status_code=400,
            detail="موجودی قابل برداشت کافی نیست.",
        )

    cards = get_bank_cards(
        user_id
    )

    selected_card = None

    for card in cards:

        try:
            card_id = int(
                card.get("id")
            )
        except (
            TypeError,
            ValueError,
        ):
            continue

        if card_id == int(
            payload.card_id
        ):

            selected_card = card
            break

    if selected_card is None:

        raise HTTPException(
            status_code=404,
            detail=(
                "کارت بانکی پیدا نشد "
                "یا متعلق به این حساب نیست."
            ),
        )

    try:

        result = transfer_wallet_to_card_once(
            user_id=user_id,
            card_id=payload.card_id,
            amount=amount,
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except Exception as exc:

        print(
            "WITHDRAW ERROR:",
            repr(exc),
        )

        raise HTTPException(
            status_code=500,
            detail="ثبت درخواست برداشت انجام نشد.",
        )

    return {
        "success": True,
        "message": (
            "درخواست برداشت ثبت شد "
            "و مبلغ رزرو شد."
        ),
        "withdrawal": result,
        "amount": amount,
        "balance": get_balance(
            user_id
        ),
        "reserved": get_reserved_amount(
            user_id
        ),
        "available": get_available_balance(
            user_id
        ),
    }


# ============================================================
# MY WITHDRAWALS
# ============================================================

@app.get("/api/withdrawals")
def api_withdrawals(
    request: Request,
):

    user_id = require_session_user_id(
        request
    )

    return {
        "success": True,
        "withdrawals": get_card_transfer_requests(
            user_id
        ),
    }


@app.get(
    "/api/withdrawals/{withdrawal_id}"
)
def api_withdrawal(
    withdrawal_id: int,
    request: Request,
):

    user_id = require_session_user_id(
        request
    )

    withdrawal = get_card_transfer_request(
        withdrawal_id,
        user_id=user_id,
    )

    if not withdrawal:

        raise HTTPException(
            status_code=404,
            detail="درخواست برداشت پیدا نشد.",
        )

    return {
        "success": True,
        "withdrawal": withdrawal,
    }


# ============================================================
# NOTIFICATIONS
# ============================================================

@app.get("/api/notifications")
def api_notifications(
    request: Request,
):

    user_id = require_session_user_id(
        request
    )

    return {
        "success": True,
        "notifications": get_notifications(
            user_id
        ),
    }


@app.get(
    "/api/notifications/unread-count"
)
def api_unread_count(
    request: Request,
):

    user_id = require_session_user_id(
        request
    )

    return {
        "success": True,
        "count": get_unread_notification_count(
            user_id
        ),
    }


@app.post(
    "/api/notifications/{notification_id}/read"
)
def api_read_notification(
    notification_id: int,
    request: Request,
):

    user_id = require_session_user_id(
        request
    )

    result = mark_notification_as_read(
        user_id,
        notification_id,
    )

    return {
        "success": True,
        "result": result,
    }


@app.post(
    "/api/notifications/read-all"
)
def api_read_all_notifications(
    request: Request,
):

    user_id = require_session_user_id(
        request
    )

    result = mark_all_notifications_as_read(
        user_id
    )

    return {
        "success": True,
        "result": result,
    }


@app.delete(
    "/api/notifications/{notification_id}"
)
def api_delete_notification(
    notification_id: int,
    request: Request,
):

    user_id = require_session_user_id(
        request
    )

    result = delete_notification(
        user_id,
        notification_id,
    )

    return {
        "success": True,
        "result": result,
    }


# ============================================================
# ZARINPAL
# ============================================================

def zarinpal_urls():

    if ZARINPAL_SANDBOX:

        return {
            "request": (
                "https://sandbox.zarinpal.com"
                "/pg/v4/payment/request.json"
            ),
            "verify": (
                "https://sandbox.zarinpal.com"
                "/pg/v4/payment/verify.json"
            ),
            "start": (
                "https://sandbox.zarinpal.com"
                "/pg/StartPay/"
            ),
        }

    return {
        "request": (
            "https://payment.zarinpal.com"
            "/pg/v4/payment/request.json"
        ),
        "verify": (
            "https://payment.zarinpal.com"
            "/pg/v4/payment/verify.json"
        ),
        "start": (
            "https://www.zarinpal.com"
            "/pg/StartPay/"
        ),
    }


def create_zarinpal_payment(
    user_id: int,
    amount_toman: float,
    amount_rial: int,
    request_id: str,
) -> int:

    with get_connection() as conn:

        row = conn.execute(
            """
            INSERT INTO zarinpal_payments (
                user_id,
                amount_toman,
                amount_rial,
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
                %s,
                %s,
                %s
            )
            RETURNING id
            """,
            (
                user_id,
                amount_toman,
                amount_rial,
                request_id,
                "created",
                now_iso(),
                now_iso(),
            ),
        ).fetchone()

        return int(
            row["id"]
        )


def get_zarinpal_payment(
    payment_id: int,
) -> dict[str, Any] | None:

    with get_connection() as conn:

        row = conn.execute(
            """
            SELECT *
            FROM zarinpal_payments
            WHERE id = %s
            """,
            (payment_id,),
        ).fetchone()

        if not row:
            return None

        return dict(row)


def update_zarinpal_payment(
    payment_id: int,
    **fields: Any,
) -> None:

    if not fields:
        return

    fields["updated_at"] = now_iso()

    allowed = {
        "authority",
        "status",
        "ref_id",
        "response_code",
        "fee",
        "error_message",
        "paid_at",
        "updated_at",
    }

    fields = {
        key: value
        for key, value in fields.items()
        if key in allowed
    }

    if not fields:
        return

    columns = []

    values = []

    for key, value in fields.items():

        columns.append(
            f"{key} = %s"
        )

        values.append(value)

    values.append(
        payment_id
    )

    with get_connection() as conn:

        conn.execute(
            f"""
            UPDATE zarinpal_payments
            SET {", ".join(columns)}
            WHERE id = %s
            """,
            tuple(values),
        )


@app.post(
    "/api/payment/zarinpal/request"
)
async def api_zarinpal_request(
    payload: ZarinPalRequest,
    request: Request,
):

    user_id = require_session_user_id(
        request
    )

    if not ZARINPAL_MERCHANT_ID:

        raise HTTPException(
            status_code=503,
            detail=(
                "ZARINPAL_MERCHANT_ID "
                "روی سرور تنظیم نشده است."
            ),
        )

    amount_toman = float(
        payload.amount
    )

    if amount_toman < 1000:

        raise HTTPException(
            status_code=400,
            detail="حداقل مبلغ پرداخت ۱۰۰۰ تومان است.",
        )

    amount_rial = int(
        round(
            amount_toman * 10
        )
    )

    request_id = secrets.token_urlsafe(
        24
    )

    payment_id = create_zarinpal_payment(
        user_id,
        amount_toman,
        amount_rial,
        request_id,
    )

    urls = zarinpal_urls()

    body = {
        "merchant_id":
            ZARINPAL_MERCHANT_ID,

        "amount":
            amount_rial,

        "description":
            payload.description,

        "callback_url":
            (
                f"{ZARINPAL_CALLBACK_URL}"
                f"?payment_id={payment_id}"
            ),

        "metadata": {},
    }

    try:

        async with httpx.AsyncClient(
            timeout=30
        ) as client:

            response = await client.post(
                urls["request"],
                json=body,
                headers={
                    "Content-Type":
                        "application/json",
                    "Accept":
                        "application/json",
                },
            )

            response.raise_for_status()

            data = response.json()

    except Exception as exc:

        update_zarinpal_payment(
            payment_id,
            status="failed",
            error_message=str(exc),
        )

        raise HTTPException(
            status_code=502,
            detail="ارتباط با زرین‌پال برقرار نشد.",
        )

    data_block = (
        data.get("data")
        or {}
    )

    code = data_block.get(
        "code"
    )

    authority = data_block.get(
        "authority"
    )

    if code != 100 or not authority:

        update_zarinpal_payment(
            payment_id,
            status="failed",
            response_code=code,
            error_message=str(
                data.get("errors")
                or {}
            ),
        )

        raise HTTPException(
            status_code=400,
            detail=(
                "زرین‌پال درخواست پرداخت را "
                "قبول نکرد."
            ),
        )

    update_zarinpal_payment(
        payment_id,
        authority=authority,
        status="gateway_created",
        response_code=code,
    )

    return {
        "success": True,
        "payment_id": payment_id,
        "authority": authority,
        "amount_toman": amount_toman,
        "amount_rial": amount_rial,
        "payment_url": (
            f"{urls['start']}"
            f"{authority}"
        ),
    }


# ============================================================
# ZARINPAL CALLBACK
# ============================================================

@app.get(
    "/api/payment/zarinpal/callback"
)
async def api_zarinpal_callback(
    request: Request,
):

    payment_id_raw = (
        request.query_params.get(
            "payment_id"
        )
    )

    authority = (
        request.query_params.get(
            "Authority"
        )
    )

    status = (
        request.query_params.get(
            "Status"
        )
    )

    if not payment_id_raw:

        raise HTTPException(
            status_code=400,
            detail="شناسه پرداخت ارسال نشده است.",
        )

    try:

        payment_id = int(
            payment_id_raw
        )

    except ValueError:

        raise HTTPException(
            status_code=400,
            detail="شناسه پرداخت نامعتبر است.",
        )

    payment = get_zarinpal_payment(
        payment_id
    )

    if not payment:

        raise HTTPException(
            status_code=404,
            detail="پرداخت پیدا نشد.",
        )

    if payment["status"] == "completed":

        return {
            "success": True,
            "message":
                "پرداخت قبلاً ثبت شده است.",
            "payment_id":
                payment_id,
            "ref_id":
                payment.get("ref_id"),
        }

    if status != "OK":

        update_zarinpal_payment(
            payment_id,
            authority=authority,
            status="cancelled",
            error_message=(
                "پرداخت تکمیل نشد."
            ),
        )

        return {
            "success": False,
            "message":
                "پرداخت لغو یا ناموفق شد.",
            "payment_id":
                payment_id,
        }

    if not authority:

        raise HTTPException(
            status_code=400,
            detail="Authority دریافت نشد.",
        )

    if not ZARINPAL_MERCHANT_ID:

        raise HTTPException(
            status_code=503,
            detail="تنظیمات زرین‌پال ناقص است.",
        )

    urls = zarinpal_urls()

    verify_body = {
        "merchant_id":
            ZARINPAL_MERCHANT_ID,

        "amount":
            int(
                payment["amount_rial"]
            ),

        "authority":
            authority,
    }

    try:

        async with httpx.AsyncClient(
            timeout=30
        ) as client:

            response = await client.post(
                urls["verify"],
                json=verify_body,
                headers={
                    "Content-Type":
                        "application/json",
                    "Accept":
                        "application/json",
                },
            )

            response.raise_for_status()

            result = response.json()

    except Exception as exc:

        update_zarinpal_payment(
            payment_id,
            authority=authority,
            status="verify_error",
            error_message=str(exc),
        )

        raise HTTPException(
            status_code=502,
            detail=(
                "استعلام پرداخت از "
                "زرین‌پال ناموفق بود."
            ),
        )

    data_block = (
        result.get("data")
        or {}
    )

    verify_code = data_block.get(
        "code"
    )

    ref_id = data_block.get(
        "ref_id"
    )

    if verify_code not in {
        100,
        101,
    }:

        update_zarinpal_payment(
            payment_id,
            authority=authority,
            status="verify_failed",
            response_code=verify_code,
            error_message=str(
                result.get("errors")
                or {}
            ),
        )

        return {
            "success": False,
            "message":
                "پرداخت تأیید نشد.",
            "code":
                verify_code,
            "payment_id":
                payment_id,
        }

    latest = get_zarinpal_payment(
        payment_id
    )

    if not latest:

        raise HTTPException(
            status_code=404,
            detail="پرداخت پیدا نشد.",
        )

    if latest["status"] == "completed":

        return {
            "success": True,
            "message":
                "پرداخت قبلاً ثبت شده است.",
            "payment_id":
                payment_id,
            "ref_id":
                latest.get("ref_id"),
        }

    user_id = int(
        latest["user_id"]
    )

    amount_toman = float(
        latest["amount_toman"]
    )

    add_wallet_balance_with_transaction(
        user_id,
        amount_toman,
        f"zarinpal:{payment_id}",
    )

    update_zarinpal_payment(
        payment_id,
        authority=authority,
        status="completed",
        response_code=verify_code,
        ref_id=(
            str(ref_id)
            if ref_id is not None
            else None
        ),
        paid_at=now_iso(),
    )

    return {
        "success": True,
        "message":
            "پرداخت تأیید شد و موجودی افزایش یافت.",
        "payment_id":
            payment_id,
        "ref_id":
            ref_id,
        "amount_toman":
            amount_toman,
        "balance":
            get_balance(user_id),
        "available":
            get_available_balance(
                user_id
            ),
    }


@app.get(
    "/api/payment/zarinpal/{payment_id}"
)
def api_zarinpal_status(
    payment_id: int,
    request: Request,
):

    user_id = require_session_user_id(
        request
    )

    payment = get_zarinpal_payment(
        payment_id
    )

    if not payment:

        raise HTTPException(
            status_code=404,
            detail="پرداخت پیدا نشد.",
        )

    if int(
        payment["user_id"]
    ) != int(user_id):

        raise HTTPException(
            status_code=403,
            detail="دسترسی غیرمجاز.",
        )

    return {
        "success": True,
        "payment": payment,
    }


# ============================================================
# ADMIN SETTLEMENTS
# ============================================================

@app.get(
    "/api/admin/settlements"
)
def admin_settlements(
    request: Request,
):

    require_admin(request)

    transfers = get_card_transfer_requests(
        None
    )

    return {
        "success": True,
        "transfers": transfers,
        "total": len(transfers),
        "pending": sum(
            1
            for item in transfers
            if item.get("status")
            == "pending"
        ),
        "processing": sum(
            1
            for item in transfers
            if item.get("status")
            == "processing"
        ),
        "completed": sum(
            1
            for item in transfers
            if item.get("status")
            == "completed"
        ),
    }


@app.post(
    "/api/admin/settlements/{transfer_id}/approve"
)
def admin_approve_settlement(
    transfer_id: int,
    request: Request,
):

    require_admin(request)

    result = approve_card_transfer(
        transfer_id
    )

    return {
        "success": True,
        "transfer": result,
    }


@app.post(
    "/api/admin/settlements/{transfer_id}/reject"
)
def admin_reject_settlement(
    transfer_id: int,
    payload: AdminActionRequest,
    request: Request,
):

    require_admin(request)

    result = reject_card_transfer(
        transfer_id,
        payload.reason.strip(),
    )

    return {
        "success": True,
        "transfer": result,
    }


@app.post(
    "/api/admin/settlements/{transfer_id}/processing"
)
def admin_processing_settlement(
    transfer_id: int,
    request: Request,
):

    require_admin(request)

    result = mark_transfer_processing(
        transfer_id
    )

    return {
        "success": True,
        "transfer": result,
    }


@app.post(
    "/api/admin/settlements/{transfer_id}/complete"
)
def admin_complete_settlement(
    transfer_id: int,
    request: Request,
):

    require_admin(request)

    result = complete_card_transfer(
        transfer_id,
        provider_transfer_id=None,
        provider_status="manual_completed",
    )

    return {
        "success": True,
        "transfer": result,
    }


@app.post(
    "/api/admin/settlements/{transfer_id}/fail"
)
def admin_fail_settlement(
    transfer_id: int,
    payload: AdminActionRequest,
    request: Request,
):

    require_admin(request)

    result = fail_card_transfer(
        transfer_id,
        payload.reason.strip(),
    )

    return {
        "success": True,
        "transfer": result,
    }


# ============================================================
# ADMIN USERS
# ============================================================

@app.get(
    "/api/admin/users"
)
def admin_users(
    request: Request,
):

    require_admin(request)

    with get_connection() as conn:

        rows = conn.execute(
            """
            SELECT
                id,
                username,
                email,
                full_name,
                balance,
                is_admin,
                created_at,
                updated_at
            FROM users
            ORDER BY id DESC
            """
        ).fetchall()

    return {
        "success": True,
        "users": [
            dict(row)
            for row in rows
        ],
    }


# ============================================================
# ADMIN ZARINPAL PAYMENTS
# ============================================================

@app.get(
    "/api/admin/payments/zarinpal"
)
def admin_zarinpal_payments(
    request: Request,
):

    require_admin(request)

    with get_connection() as conn:

        rows = conn.execute(
            """
            SELECT
                id,
                user_id,
                amount_toman,
                amount_rial,
                request_id,
                authority,
                status,
                ref_id,
                response_code,
                fee,
                error_message,
                created_at,
                updated_at,
                paid_at
            FROM zarinpal_payments
            ORDER BY id DESC
            LIMIT 500
            """
        ).fetchall()

    return {
        "success": True,
        "payments": [
            dict(row)
            for row in rows
        ],
    }


# ============================================================
# ROUTES DEBUG
# ============================================================

@app.get("/api/routes")
def api_routes():

    return {
        "success": True,
        "routes": [
            route.path
            for route in app.routes
            if hasattr(route, "path")
        ],
    }


# ============================================================
# AUTH ROUTER
# ============================================================

app.include_router(
    auth_router
)