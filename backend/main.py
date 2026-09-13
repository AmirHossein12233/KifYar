from __future__ import annotations

import os
import uuid
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.database import (
    add_admin_action_log,
    add_bank_card,
    add_transaction,
    add_wallet_balance_with_transaction,
    delete_bank_card,
    delete_notification,
    delete_transactions,
    delete_user,
    deposit_by_card_once,
    find_user_by_id,
    get_admin_action_logs,
    get_balance,
    get_bank_card,
    get_bank_cards,
    get_card_transfer_request,
    get_card_transfer_request_by_id,
    get_card_transfer_requests,
    get_all_card_transfer_requests,
    get_notifications,
    get_unread_notification_count,
    get_transactions,
    initialize_database,
    mark_all_notifications_as_read,
    mark_notification_as_read,
    set_default_bank_card,
    subtract_wallet_balance_with_transaction,
    transfer_wallet_to_card_once,
    update_card_transfer_status,
    update_user_name,
    update_user_password,
    verify_user_password,
)

from backend.session import (
    require_session_user_id,
)


app = FastAPI(
    title="KifYar API",
    version="1.0.0",
)


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "https://kifyar-web.onrender.com",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# MODELS
# =========================================================

class ProfileUpdateRequest(BaseModel):
    name: str = Field(
        min_length=1,
        max_length=100,
    )


class PasswordChangeRequest(BaseModel):
    current_password: str

    new_password: str = Field(
        min_length=6,
        max_length=200,
    )


class TransactionRequest(BaseModel):
    title: str
    amount: float
    transaction_type: str
    category: Optional[str] = None


class BankCardRequest(BaseModel):
    holder_name: str
    bank_name: str
    card_number: str


class CardDepositRequest(BaseModel):
    card_id: int
    amount: float
    request_id: str


class WalletAmountRequest(BaseModel):
    amount: float


class WalletWithdrawRequest(BaseModel):
    amount: float


class WalletCardTransferRequest(BaseModel):
    card_id: int
    amount: float
    request_id: str


class TransferStatusRequest(BaseModel):
    status: str


# =========================================================
# HELPERS
# =========================================================

def normalize_request_id(
    request_id: str | None,
) -> str:

    if request_id:
        value = request_id.strip()

        if value:
            return value[:200]

    return str(uuid.uuid4())


def validate_amount(
    amount: float,
) -> float:

    if amount <= 0:
        raise HTTPException(
            status_code=400,
            detail="مبلغ باید بیشتر از صفر باشد.",
        )

    if amount > 100_000_000:
        raise HTTPException(
            status_code=400,
            detail="حداکثر مبلغ ۱۰۰٬۰۰۰٬۰۰۰ تومان است.",
        )

    return float(amount)


def require_admin(
    x_admin_key: Optional[str] = Header(
        default=None,
    ),
) -> str:

    expected_key = os.getenv(
        "KIFYAR_ADMIN_KEY"
    )

    if not expected_key:
        raise HTTPException(
            status_code=503,
            detail="KIFYAR_ADMIN_KEY روی سرور تنظیم نشده است.",
        )

    if not x_admin_key:
        raise HTTPException(
            status_code=401,
            detail="کلید مدیریت ارسال نشده است.",
        )

    if x_admin_key != expected_key:
        raise HTTPException(
            status_code=403,
            detail="کلید مدیریت نادرست است.",
        )

    return x_admin_key


def get_action_name(
    status: str,
) -> str:

    actions = {
        "completed": "تأیید انتقال",
        "failed": "رد انتقال",
        "cancelled": "لغو انتقال",
        "pending": "بازگردانی به انتظار",
    }

    return actions.get(
        status,
        "تغییر وضعیت انتقال",
    )


# =========================================================
# BASIC
# =========================================================

@app.get("/")
def root():

    return {
        "name": "KifYar API",
        "status": "ok",
    }


@app.get("/health")
def health():

    return {
        "status": "ok",
    }


# =========================================================
# PROFILE
# =========================================================

@app.get("/api/profile")
def get_profile():

    user_id = require_session_user_id()

    user = find_user_by_id(
        user_id
    )

    if not user:
        raise HTTPException(
            status_code=404,
            detail="کاربر پیدا نشد.",
        )

    return {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "name": user["name"],
        "is_admin": bool(
            user["is_admin"]
        ),
        "created_at": user["created_at"],
    }


@app.put("/api/profile")
def update_profile(
    payload: ProfileUpdateRequest,
):

    user_id = require_session_user_id()

    ok = update_user_name(
        user_id,
        payload.name.strip(),
    )

    if not ok:
        raise HTTPException(
            status_code=404,
            detail="کاربر پیدا نشد.",
        )

    return {
        "message": "پروفایل با موفقیت بروزرسانی شد.",
    }


@app.put("/api/password")
def change_password(
    payload: PasswordChangeRequest,
):

    user_id = require_session_user_id()

    user = find_user_by_id(
        user_id
    )

    if not user:
        raise HTTPException(
            status_code=404,
            detail="کاربر پیدا نشد.",
        )

    if not verify_user_password(
        user["username"],
        payload.current_password,
    ):
        raise HTTPException(
            status_code=400,
            detail="رمز عبور فعلی صحیح نیست.",
        )

    update_user_password(
        user_id,
        payload.new_password,
    )

    return {
        "message": "رمز عبور با موفقیت تغییر کرد.",
    }


@app.delete("/api/account")
def remove_account():

    user_id = require_session_user_id()

    ok = delete_user(
        user_id
    )

    if not ok:
        raise HTTPException(
            status_code=404,
            detail="کاربر پیدا نشد.",
        )

    return {
        "message": "حساب کاربری حذف شد.",
    }


# =========================================================
# WALLET
# =========================================================

@app.get("/api/wallet/balance")
def wallet_balance():

    user_id = require_session_user_id()

    return {
        "balance": get_balance(
            user_id
        ),
    }


@app.post("/api/wallet/add")
def wallet_add(
    payload: WalletAmountRequest,
):

    user_id = require_session_user_id()

    amount = validate_amount(
        payload.amount
    )

    balance = add_wallet_balance_with_transaction(
        user_id,
        amount,
    )

    return {
        "message": "موجودی افزایش یافت.",
        "balance": balance,
    }


@app.post("/api/wallet/subtract")
def wallet_subtract(
    payload: WalletAmountRequest,
):

    user_id = require_session_user_id()

    amount = validate_amount(
        payload.amount
    )

    try:

        balance = subtract_wallet_balance_with_transaction(
            user_id,
            amount,
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    return {
        "message": "موجودی کاهش یافت.",
        "balance": balance,
    }


@app.post("/api/wallet/deposit")
def wallet_deposit(
    payload: CardDepositRequest,
):

    user_id = require_session_user_id()

    amount = validate_amount(
        payload.amount
    )

    request_id = normalize_request_id(
        payload.request_id
    )

    try:

        result = deposit_by_card_once(
            user_id=user_id,
            card_id=payload.card_id,
            amount=amount,
            request_id=request_id,
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    return result


@app.post("/api/wallet/withdraw")
def wallet_withdraw(
    payload: WalletWithdrawRequest,
):

    user_id = require_session_user_id()

    amount = validate_amount(
        payload.amount
    )

    try:

        balance = subtract_wallet_balance_with_transaction(
            user_id,
            amount,
            title="برداشت از کیف پول",
            category="withdraw",
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    return {
        "message": "برداشت ثبت شد.",
        "balance": balance,
    }


@app.post("/api/wallet/transfer-to-card")
def wallet_transfer_to_card(
    payload: WalletCardTransferRequest,
):

    user_id = require_session_user_id()

    amount = validate_amount(
        payload.amount
    )

    request_id = normalize_request_id(
        payload.request_id
    )

    try:

        result = transfer_wallet_to_card_once(
            user_id=user_id,
            card_id=payload.card_id,
            amount=amount,
            request_id=request_id,
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    return result


@app.get("/api/wallet/card-transfers")
def wallet_card_transfers():

    user_id = require_session_user_id()

    return get_card_transfer_requests(
        user_id
    )


@app.get("/api/wallet/card-transfers/{transfer_id}")
def wallet_card_transfer(
    transfer_id: int,
):

    user_id = require_session_user_id()

    transfer = get_card_transfer_request(
        user_id,
        transfer_id,
    )

    if not transfer:
        raise HTTPException(
            status_code=404,
            detail="درخواست انتقال پیدا نشد.",
        )

    return transfer


# =========================================================
# NOTIFICATIONS
# =========================================================

@app.get("/api/notifications")
def notifications(
    limit: int = 100,
):

    user_id = require_session_user_id()

    if limit < 1:
        limit = 1

    if limit > 200:
        limit = 200

    return get_notifications(
        user_id=user_id,
        limit=limit,
    )


@app.get("/api/notifications/unread-count")
def notification_unread_count():

    user_id = require_session_user_id()

    return {
        "unread_count": get_unread_notification_count(
            user_id
        ),
    }


@app.patch(
    "/api/notifications/{notification_id}/read"
)
def notification_read(
    notification_id: int,
):

    user_id = require_session_user_id()

    ok = mark_notification_as_read(
        user_id=user_id,
        notification_id=notification_id,
    )

    if not ok:
        raise HTTPException(
            status_code=404,
            detail="اعلان پیدا نشد.",
        )

    return {
        "message": "اعلان به عنوان خوانده‌شده ثبت شد.",
    }


@app.patch(
    "/api/notifications/read-all"
)
def notifications_read_all():

    user_id = require_session_user_id()

    count = mark_all_notifications_as_read(
        user_id
    )

    return {
        "message": "همه اعلان‌ها خوانده شدند.",
        "updated": count,
    }


@app.delete(
    "/api/notifications/{notification_id}"
)
def notification_delete(
    notification_id: int,
):

    user_id = require_session_user_id()

    ok = delete_notification(
        user_id=user_id,
        notification_id=notification_id,
    )

    if not ok:
        raise HTTPException(
            status_code=404,
            detail="اعلان پیدا نشد.",
        )

    return {
        "message": "اعلان حذف شد.",
    }


# =========================================================
# TRANSACTIONS
# =========================================================

@app.get("/api/transactions")
def transactions():

    user_id = require_session_user_id()

    return get_transactions(
        user_id
    )


@app.post("/api/transactions")
def create_transaction(
    payload: TransactionRequest,
):

    user_id = require_session_user_id()

    if payload.amount <= 0:
        raise HTTPException(
            status_code=400,
            detail="مبلغ نامعتبر است.",
        )

    if payload.transaction_type not in {
        "income",
        "expense",
    }:
        raise HTTPException(
            status_code=400,
            detail="نوع تراکنش نامعتبر است.",
        )

    transaction_id = add_transaction(
        user_id=user_id,
        title=payload.title,
        amount=payload.amount,
        transaction_type=payload.transaction_type,
        category=payload.category,
    )

    return {
        "id": transaction_id,
        "message": "تراکنش ثبت شد.",
    }


# =========================================================
# CARDS
# =========================================================

@app.get("/api/cards")
def cards():

    user_id = require_session_user_id()

    return get_bank_cards(
        user_id
    )


@app.post("/api/cards")
def create_card(
    payload: BankCardRequest,
):

    user_id = require_session_user_id()

    try:

        card_id = add_bank_card(
            user_id=user_id,
            holder_name=payload.holder_name.strip(),
            bank_name=payload.bank_name.strip(),
            card_number=payload.card_number,
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    return {
        "id": card_id,
        "message": "کارت بانکی اضافه شد.",
    }


@app.put("/api/cards/{card_id}/default")
def default_card(
    card_id: int,
):

    user_id = require_session_user_id()

    ok = set_default_bank_card(
        user_id,
        card_id,
    )

    if not ok:
        raise HTTPException(
            status_code=404,
            detail="کارت پیدا نشد.",
        )

    return {
        "message": "کارت پیش‌فرض شد.",
    }


@app.delete("/api/cards/{card_id}")
def remove_card(
    card_id: int,
):

    user_id = require_session_user_id()

    ok = delete_bank_card(
        user_id,
        card_id,
    )

    if not ok:
        raise HTTPException(
            status_code=404,
            detail="کارت پیدا نشد.",
        )

    return {
        "message": "کارت حذف شد.",
    }


# =========================================================
# ADMIN - TRANSFERS
# =========================================================

@app.get("/api/admin/card-transfers")
def admin_card_transfers():

    require_admin()

    return get_all_card_transfer_requests()


@app.get("/api/admin/card-transfers/{transfer_id}")
def admin_card_transfer(
    transfer_id: int,
):

    require_admin()

    transfer = get_card_transfer_request_by_id(
        transfer_id
    )

    if not transfer:
        raise HTTPException(
            status_code=404,
            detail="درخواست انتقال پیدا نشد.",
        )

    return transfer


@app.patch(
    "/api/admin/card-transfers/{transfer_id}/status"
)
def admin_update_transfer_status(
    transfer_id: int,
    payload: TransferStatusRequest,
):

    require_admin()

    new_status = payload.status.strip().lower()

    allowed = {
        "pending",
        "completed",
        "failed",
        "cancelled",
    }

    if new_status not in allowed:
        raise HTTPException(
            status_code=400,
            detail="وضعیت نامعتبر است.",
        )

    transfer = get_card_transfer_request_by_id(
        transfer_id
    )

    if not transfer:
        raise HTTPException(
            status_code=404,
            detail="درخواست انتقال پیدا نشد.",
        )

    old_status = transfer["status"]

    if old_status == new_status:
        return transfer

    try:

        ok = update_card_transfer_status(
            transfer_id,
            new_status,
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    if not ok:
        raise HTTPException(
            status_code=404,
            detail="درخواست انتقال پیدا نشد.",
        )

    add_admin_action_log(
        action=get_action_name(
            new_status
        ),
        transfer_id=transfer_id,
        status_before=old_status,
        status_after=new_status,
        amount=float(
            transfer["amount"]
        ),
        request_id=transfer["request_id"],
    )

    updated = get_card_transfer_request_by_id(
        transfer_id
    )

    return updated


# =========================================================
# ADMIN - AUDIT LOGS
# =========================================================

@app.get("/api/admin/logs")
def admin_logs(
    limit: int = 200,
):

    require_admin()

    if limit < 1:
        limit = 1

    if limit > 1000:
        limit = 1000

    return get_admin_action_logs(
        limit
    )


@app.get("/api/admin/logs/{log_id}")
def admin_log(
    log_id: int,
):

    require_admin()

    logs = get_admin_action_logs(
        1000
    )

    for log in logs:

        if int(log["id"]) == log_id:
            return log

    raise HTTPException(
        status_code=404,
        detail="گزارش پیدا نشد.",
    )


# =========================================================
# STARTUP
# =========================================================

@app.on_event("startup")
def startup():

    initialize_database()