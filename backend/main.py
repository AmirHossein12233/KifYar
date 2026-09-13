from __future__ import annotations

import uuid
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.auth import router as auth_router
from backend.database import (
    add_bank_card,
    add_transaction,
    add_wallet_balance_with_transaction,
    delete_bank_card,
    delete_transactions,
    delete_user,
    deposit_by_card_once,
    find_user_by_id,
    get_balance,
    get_bank_card,
    get_bank_cards,
    get_card_transfer_request,
    get_card_transfer_requests,
    get_transactions,
    initialize_database,
    set_default_bank_card,
    subtract_wallet_balance_with_transaction,
    transfer_wallet_to_card_once,
    update_card_transfer_status,
    update_user_name,
    update_user_password,
)
from backend.session import require_session_user_id


# =========================================================
# APP
# =========================================================

app = FastAPI(
    title="KifYar",
    version="1.0.0",
)


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        # Local development
        "http://127.0.0.1:5500",
        "http://localhost:5500",

        # KifYar online frontend
        "https://kifyar-web.onrender.com",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# AUTH ROUTER
# =========================================================

app.include_router(
    auth_router
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

    current_password: str = Field(
        min_length=1,
        max_length=200,
    )

    new_password: str = Field(
        min_length=4,
        max_length=200,
    )


class TransactionRequest(BaseModel):

    title: str = Field(
        min_length=1,
        max_length=200,
    )

    amount: float

    transaction_type: str = Field(
        min_length=1,
        max_length=50,
    )

    category: str = Field(
        default="other",
        max_length=100,
    )


class BankCardRequest(BaseModel):

    holder_name: str = Field(
        min_length=1,
        max_length=100,
    )

    bank_name: str = Field(
        min_length=1,
        max_length=100,
    )

    card_number: str = Field(
        min_length=4,
        max_length=30,
    )


class CardDepositRequest(BaseModel):

    card_id: int

    amount: float

    request_id: Optional[str] = None


class WalletAmountRequest(BaseModel):

    amount: float


class WalletWithdrawRequest(BaseModel):

    amount: float


class WalletCardTransferRequest(BaseModel):

    card_id: int

    amount: float

    request_id: Optional[str] = None


class TransferStatusRequest(BaseModel):

    status: str


# =========================================================
# HELPERS
# =========================================================

def normalize_request_id(
    request_id: Optional[str],
) -> str:

    if request_id is None:

        return str(
            uuid.uuid4()
        )

    value = str(
        request_id
    ).strip()

    if not value:

        return str(
            uuid.uuid4()
        )

    if len(value) > 100:

        raise HTTPException(
            status_code=400,
            detail="شناسه درخواست نامعتبر است.",
        )

    return value


def validate_amount(
    amount: float,
):

    try:

        amount = float(amount)

    except Exception:

        raise HTTPException(
            status_code=400,
            detail="مبلغ نامعتبر است.",
        )

    if amount <= 0:

        raise HTTPException(
            status_code=400,
            detail="مبلغ باید بیشتر از صفر باشد.",
        )

    if amount > 100_000_000:

        raise HTTPException(
            status_code=400,
            detail="مبلغ بیشتر از حد مجاز است.",
        )

    return amount


# =========================================================
# STARTUP
# =========================================================

@app.on_event("startup")
def startup():

    initialize_database()


# =========================================================
# ROOT
# =========================================================

@app.get("/")
def root():

    return {
        "ok": True,
        "success": True,
        "app": "KifYar",
        "version": "1.0.0",
        "message": "KifYar API is running.",
    }


# =========================================================
# HEALTH
# =========================================================

@app.get("/health")
def health():

    database_ok = False

    frontend_ok = True

    try:

        initialize_database()

        database_ok = True

    except Exception:

        database_ok = False

    return {
        "ok": (
            database_ok
            and frontend_ok
        ),
        "success": True,
        "app": "KifYar",
        "version": "1.0.0",
        "database": database_ok,
        "frontend": frontend_ok,
    }


# =========================================================
# PROFILE
# =========================================================

@app.get("/api/profile")
def get_profile(
    user_id: int = require_session_user_id,
):

    user = find_user_by_id(
        user_id
    )

    if user is None:

        raise HTTPException(
            status_code=404,
            detail="کاربر پیدا نشد.",
        )

    return {
        "success": True,
        "user": user,
    }


@app.put("/api/profile")
def update_profile(
    data: ProfileUpdateRequest,
    user_id: int = require_session_user_id,
):

    name = data.name.strip()

    if not name:

        raise HTTPException(
            status_code=400,
            detail="نام نمی‌تواند خالی باشد.",
        )

    updated = update_user_name(
        user_id,
        name,
    )

    if not updated:

        raise HTTPException(
            status_code=404,
            detail="کاربر پیدا نشد.",
        )

    user = find_user_by_id(
        user_id
    )

    return {
        "success": True,
        "user": user,
        "message": "پروفایل با موفقیت بروزرسانی شد.",
    }


# =========================================================
# PASSWORD
# =========================================================

@app.put("/api/password")
def change_password(
    data: PasswordChangeRequest,
    user_id: int = require_session_user_id,
):

    try:

        update_user_password(
            user_id=user_id,
            current_password=data.current_password,
            new_password=data.new_password,
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    return {
        "success": True,
        "message": "رمز عبور با موفقیت تغییر کرد.",
    }


# =========================================================
# DELETE ACCOUNT
# =========================================================

@app.delete("/api/account")
def delete_account(
    user_id: int = require_session_user_id,
):

    try:

        delete_transactions(
            user_id
        )

        delete_user(
            user_id
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )

    return {
        "success": True,
        "message": "حساب کاربری حذف شد.",
    }


# =========================================================
# WALLET BALANCE
# =========================================================

@app.get("/api/wallet/balance")
def wallet_balance(
    user_id: int = require_session_user_id,
):

    balance = get_balance(
        user_id
    )

    return {
        "success": True,
        "balance": balance,
    }


# =========================================================
# WALLET ADD
# =========================================================

@app.post("/api/wallet/add")
def wallet_add(
    data: WalletAmountRequest,
    user_id: int = require_session_user_id,
):

    amount = validate_amount(
        data.amount
    )

    try:

        result = add_wallet_balance_with_transaction(
            user_id=user_id,
            amount=amount,
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )

    return result


# =========================================================
# WALLET SUBTRACT
# =========================================================

@app.post("/api/wallet/subtract")
def wallet_subtract(
    data: WalletAmountRequest,
    user_id: int = require_session_user_id,
):

    amount = validate_amount(
        data.amount
    )

    try:

        result = subtract_wallet_balance_with_transaction(
            user_id=user_id,
            amount=amount,
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )

    return result


# =========================================================
# CARD DEPOSIT
# =========================================================

@app.post("/api/wallet/deposit")
def wallet_deposit(
    data: CardDepositRequest,
    user_id: int = require_session_user_id,
):

    amount = validate_amount(
        data.amount
    )

    request_id = normalize_request_id(
        data.request_id
    )

    try:

        result = deposit_by_card_once(
            user_id=user_id,
            card_id=data.card_id,
            amount=amount,
            request_id=request_id,
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )

    return result


# =========================================================
# WALLET WITHDRAW
# =========================================================

@app.post("/api/wallet/withdraw")
def wallet_withdraw(
    data: WalletWithdrawRequest,
    user_id: int = require_session_user_id,
):

    amount = validate_amount(
        data.amount
    )

    try:

        result = subtract_wallet_balance_with_transaction(
            user_id=user_id,
            amount=amount,
            title="برداشت از کیف پول",
            category="withdraw",
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )

    return result


# =========================================================
# WALLET -> CARD
# =========================================================

@app.post("/api/wallet/transfer-to-card")
def wallet_transfer_to_card(
    data: WalletCardTransferRequest,
    user_id: int = require_session_user_id,
):

    amount = validate_amount(
        data.amount
    )

    request_id = normalize_request_id(
        data.request_id
    )

    try:

        result = transfer_wallet_to_card_once(
            user_id=user_id,
            card_id=data.card_id,
            amount=amount,
            request_id=request_id,
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )

    return result


# =========================================================
# CARD TRANSFER LIST
# =========================================================

@app.get("/api/wallet/card-transfers")
def wallet_card_transfers(
    user_id: int = require_session_user_id,
):

    transfers = get_card_transfer_requests(
        user_id
    )

    return {
        "success": True,
        "transfers": transfers,
    }


# =========================================================
# SINGLE CARD TRANSFER
# =========================================================

@app.get(
    "/api/wallet/card-transfers/{transfer_id}"
)
def wallet_card_transfer(
    transfer_id: int,
    user_id: int = require_session_user_id,
):

    transfer = get_card_transfer_request(
        user_id=user_id,
        transfer_id=transfer_id,
    )

    if transfer is None:

        raise HTTPException(
            status_code=404,
            detail="درخواست انتقال پیدا نشد.",
        )

    return {
        "success": True,
        "transfer": transfer,
    }


# =========================================================
# UPDATE CARD TRANSFER STATUS
# =========================================================

@app.patch(
    "/api/wallet/card-transfers/{transfer_id}/status"
)
def change_card_transfer_status(
    transfer_id: int,
    data: TransferStatusRequest,
    user_id: int = require_session_user_id,
):

    transfer = get_card_transfer_request(
        user_id=user_id,
        transfer_id=transfer_id,
    )

    if transfer is None:

        raise HTTPException(
            status_code=404,
            detail="درخواست انتقال پیدا نشد.",
        )

    status = data.status.strip().lower()

    try:

        updated = update_card_transfer_status(
            transfer_id=transfer_id,
            status=status,
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    if not updated:

        raise HTTPException(
            status_code=404,
            detail="درخواست انتقال پیدا نشد.",
        )

    result = get_card_transfer_request(
        user_id=user_id,
        transfer_id=transfer_id,
    )

    return {
        "success": True,
        "transfer": result,
        "message": "وضعیت درخواست بروزرسانی شد.",
    }


# =========================================================
# TRANSACTIONS
# =========================================================

@app.get("/api/transactions")
def transactions(
    user_id: int = require_session_user_id,
):

    items = get_transactions(
        user_id
    )

    return {
        "success": True,
        "transactions": items,
    }


@app.post("/api/transactions")
def create_transaction(
    data: TransactionRequest,
    user_id: int = require_session_user_id,
):

    amount = validate_amount(
        data.amount
    )

    transaction_type = (
        data.transaction_type
        .strip()
        .lower()
    )

    if transaction_type not in {
        "income",
        "expense",
    }:

        raise HTTPException(
            status_code=400,
            detail="نوع تراکنش باید income یا expense باشد.",
        )

    title = data.title.strip()

    category = (
        data.category.strip()
        or "other"
    )

    try:

        transaction_id = add_transaction(
            user_id=user_id,
            title=title,
            amount=amount,
            transaction_type=transaction_type,
            category=category,
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )

    return {
        "success": True,
        "transaction_id": transaction_id,
        "message": "تراکنش ثبت شد.",
    }


# =========================================================
# BANK CARDS
# =========================================================

@app.get("/api/cards")
def cards(
    user_id: int = require_session_user_id,
):

    items = get_bank_cards(
        user_id
    )

    return {
        "success": True,
        "cards": items,
    }


@app.post("/api/cards")
def create_card(
    data: BankCardRequest,
    user_id: int = require_session_user_id,
):

    holder_name = (
        data.holder_name.strip()
    )

    bank_name = (
        data.bank_name.strip()
    )

    card_number = "".join(
        ch
        for ch in data.card_number
        if ch.isdigit()
    )

    if len(card_number) < 4:

        raise HTTPException(
            status_code=400,
            detail="شماره کارت نامعتبر است.",
        )

    try:

        card_id = add_bank_card(
            user_id=user_id,
            holder_name=holder_name,
            bank_name=bank_name,
            card_number=card_number,
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )

    card = get_bank_card(
        user_id=user_id,
        card_id=card_id,
    )

    return {
        "success": True,
        "card": card,
        "message": "کارت بانکی اضافه شد.",
    }


# =========================================================
# DEFAULT CARD
# =========================================================

@app.put("/api/cards/{card_id}/default")
def default_card(
    card_id: int,
    user_id: int = require_session_user_id,
):

    updated = set_default_bank_card(
        user_id=user_id,
        card_id=card_id,
    )

    if not updated:

        raise HTTPException(
            status_code=404,
            detail="کارت بانکی پیدا نشد.",
        )

    card = get_bank_card(
        user_id=user_id,
        card_id=card_id,
    )

    return {
        "success": True,
        "card": card,
        "message": "کارت پیش‌فرض تغییر کرد.",
    }


# =========================================================
# DELETE CARD
# =========================================================

@app.delete("/api/cards/{card_id}")
def remove_card(
    card_id: int,
    user_id: int = require_session_user_id,
):

    card = get_bank_card(
        user_id=user_id,
        card_id=card_id,
    )

    if card is None:

        raise HTTPException(
            status_code=404,
            detail="کارت بانکی پیدا نشد.",
        )

    deleted = delete_bank_card(
        user_id=user_id,
        card_id=card_id,
    )

    if not deleted:

        raise HTTPException(
            status_code=404,
            detail="کارت بانکی پیدا نشد.",
        )

    return {
        "success": True,
        "message": "کارت بانکی حذف شد.",
    }
