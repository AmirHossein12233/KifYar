from __future__ import annotations

import hashlib
import secrets

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from backend.database import (
    create_user,
    find_user,
    get_user_by_id,
    verify_password,
)


router = APIRouter(prefix="/api", tags=["auth"])

# token -> user_id
tokens: dict[str, int] = {}


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def create_token(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    tokens[token] = int(user_id)
    return token


def remove_token(token: str) -> None:
    tokens.pop(token, None)


def get_bearer_token(
    authorization: str | None,
) -> str:
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="ورود لازم است.",
        )

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="توکن نامعتبر است.",
        )

    token = authorization[7:].strip()

    if not token:
        raise HTTPException(
            status_code=401,
            detail="توکن نامعتبر است.",
        )

    return token


def require_user_id(
    authorization: str | None,
) -> int:
    token = get_bearer_token(authorization)

    user_id = tokens.get(token)

    if user_id is None:
        raise HTTPException(
            status_code=401,
            detail="جلسه ورود معتبر نیست.",
        )

    return int(user_id)


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class LogoutRequest(BaseModel):
    pass


@router.post("/register")
def register(data: RegisterRequest):
    username = data.username.strip()
    email = data.email.strip().lower()
    password = data.password

    if not username:
        raise HTTPException(
            status_code=400,
            detail="نام کاربری الزامی است.",
        )

    if not email:
        raise HTTPException(
            status_code=400,
            detail="ایمیل الزامی است.",
        )

    if not password:
        raise HTTPException(
            status_code=400,
            detail="رمز عبور الزامی است.",
        )

    if len(password) < 6:
        raise HTTPException(
            status_code=400,
            detail="رمز عبور باید حداقل ۶ کاراکتر باشد.",
        )

    existing_user = find_user(email)

    if existing_user is not None:
        raise HTTPException(
            status_code=409,
            detail="این ایمیل قبلاً ثبت شده است.",
        )

    password_hash = hash_password(password)

    user_id = create_user(
        username=username,
        email=email,
        password_hash=password_hash,
    )

    return {
        "success": True,
        "message": "ثبت‌نام با موفقیت انجام شد.",
        "user": {
            "id": user_id,
            "username": username,
            "email": email,
        },
    }


@router.post("/login")
def login(data: LoginRequest):
    email = data.email.strip().lower()
    password = data.password

    if not email or not password:
        raise HTTPException(
            status_code=400,
            detail="ایمیل و رمز عبور الزامی هستند.",
        )

    user = find_user(email)

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="ایمیل یا رمز عبور اشتباه است.",
        )

    stored_password = user.get("password_hash")

    if not stored_password:
        raise HTTPException(
            status_code=401,
            detail="ایمیل یا رمز عبور اشتباه است.",
        )

    if not verify_password(password, stored_password):
        raise HTTPException(
            status_code=401,
            detail="ایمیل یا رمز عبور اشتباه است.",
        )

    # توکن‌های قبلی همین کاربر حذف شوند
    old_tokens = [
        token
        for token, user_id in tokens.items()
        if int(user_id) == int(user["id"])
    ]

    for token in old_tokens:
        tokens.pop(token, None)

    token = create_token(int(user["id"]))

    return {
        "success": True,
        "message": "ورود موفق بود.",
        "token": token,
        "access_token": token,
        "user": {
            "id": int(user["id"]),
            "username": user.get("username"),
            "email": user.get("email"),
        },
    }


@router.get("/me")
def me(
    authorization: str | None = Header(default=None),
):
    user_id = require_user_id(authorization)

    user = get_user_by_id(user_id)

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="کاربر پیدا نشد.",
        )

    return {
        "success": True,
        "user": user,
    }


@router.post("/logout")
def logout(
    authorization: str | None = Header(default=None),
):
    token = get_bearer_token(authorization)

    remove_token(token)

    return {
        "success": True,
        "message": "با موفقیت خارج شدید.",
    }