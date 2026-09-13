from __future__ import annotations

import secrets
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel

from backend.database import (
    create_user,
    find_user_by_email,
    find_user_by_id,
    find_user_by_username,
    verify_user_password,
)


# =========================================================
# ROUTER
# =========================================================

router = APIRouter(
    prefix="/api",
    tags=["auth"],
)


# =========================================================
# TOKENS
# =========================================================

# token -> user_id
tokens: dict[str, int] = {}


# =========================================================
# USER LOOKUP
# =========================================================

def user_to_public_dict(
    user: dict[str, Any],
) -> dict[str, Any]:

    return {
        "id": int(user["id"]),
        "username": user.get("username"),
        "name": user.get(
            "full_name",
            "",
        ),
        "full_name": user.get(
            "full_name",
            "",
        ),
        "email": user.get("email"),
        "is_admin": bool(
            user.get(
                "is_admin",
                False,
            )
        ),
        "created_at": user.get(
            "created_at"
        ),
        "updated_at": user.get(
            "updated_at"
        ),
    }


def find_user(
    identifier: str,
) -> dict[str, Any] | None:
    """
    پیدا کردن کاربر با ایمیل یا نام کاربری.
    """

    value = str(
        identifier
    ).strip()

    if not value:
        return None

    user = find_user_by_email(
        value.lower()
    )

    if user is not None:
        return user

    return find_user_by_username(
        value
    )


# =========================================================
# TOKEN FUNCTIONS
# =========================================================

def create_token(
    user_id: int,
) -> str:

    token = secrets.token_urlsafe(
        32
    )

    tokens[token] = int(
        user_id
    )

    return token


def remove_token(
    token: str,
) -> None:

    tokens.pop(
        token,
        None,
    )


def get_bearer_token(
    authorization: str | None,
) -> str:

    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="ورود لازم است.",
        )

    if not authorization.startswith(
        "Bearer "
    ):
        raise HTTPException(
            status_code=401,
            detail="توکن نامعتبر است.",
        )

    token = authorization[
        7:
    ].strip()

    if not token:
        raise HTTPException(
            status_code=401,
            detail="توکن نامعتبر است.",
        )

    return token


def require_user_id(
    authorization: str | None,
) -> int:

    token = get_bearer_token(
        authorization
    )

    user_id = tokens.get(
        token
    )

    if user_id is None:
        raise HTTPException(
            status_code=401,
            detail="جلسه ورود معتبر نیست.",
        )

    return int(
        user_id
    )


# =========================================================
# REGISTER MODEL
# =========================================================

class RegisterRequest(BaseModel):

    username: str

    email: str

    password: str

    full_name: str = ""


# =========================================================
# LOGIN MODEL
# =========================================================

class LoginRequest(BaseModel):

    email: str | None = None

    username: str | None = None

    identifier: str | None = None

    password: str | None = None


# =========================================================
# LOGOUT MODEL
# =========================================================

class LogoutRequest(BaseModel):
    pass


# =========================================================
# REGISTER
# =========================================================

@router.post(
    "/register"
)
def register(
    data: RegisterRequest,
):

    username = (
        data.username.strip()
    )

    email = (
        data.email.strip().lower()
    )

    password = data.password

    full_name = (
        data.full_name.strip()
    )

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
            detail=(
                "رمز عبور باید حداقل "
                "۶ کاراکتر باشد."
            ),
        )

    # -----------------------------------------------------
    # Duplicate username
    # -----------------------------------------------------

    existing_user = (
        find_user_by_username(
            username
        )
    )

    if existing_user is not None:
        raise HTTPException(
            status_code=409,
            detail=(
                "این نام کاربری "
                "قبلاً ثبت شده است."
            ),
        )

    # -----------------------------------------------------
    # Duplicate email
    # -----------------------------------------------------

    existing_user = (
        find_user_by_email(
            email
        )
    )

    if existing_user is not None:
        raise HTTPException(
            status_code=409,
            detail=(
                "این ایمیل "
                "قبلاً ثبت شده است."
            ),
        )

    # -----------------------------------------------------
    # Create user
    # -----------------------------------------------------

    try:

        user_id = create_user(
            username=username,
            email=email,
            password=password,
            full_name=full_name,
        )

    except Exception as exc:

        error_text = str(
            exc
        ).lower()

        if (
            "unique" in error_text
            or "duplicate" in error_text
            or "already exists" in error_text
        ):
            raise HTTPException(
                status_code=409,
                detail=(
                    "این ایمیل یا "
                    "نام کاربری قبلاً "
                    "ثبت شده است."
                ),
            ) from exc

        raise HTTPException(
            status_code=500,
            detail="ثبت‌نام انجام نشد.",
        ) from exc

    user = find_user_by_id(
        int(user_id)
    )

    if user is None:
        raise HTTPException(
            status_code=500,
            detail="کاربر ایجاد نشد.",
        )

    return {
        "success": True,
        "message": (
            "ثبت‌نام با موفقیت انجام شد."
        ),
        "user": user_to_public_dict(
            user
        ),
    }


# =========================================================
# LOGIN
# =========================================================

@router.post(
    "/login"
)
async def login(
    request: Request,
):

    # -----------------------------------------------------
    # Read JSON
    # -----------------------------------------------------

    try:

        body = await request.json()

    except Exception as exc:

        raise HTTPException(
            status_code=400,
            detail=(
                "بدنه درخواست "
                "ورود نامعتبر است."
            ),
        ) from exc

    if not isinstance(
        body,
        dict,
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "اطلاعات ورود "
                "نامعتبر است."
            ),
        )

    # -----------------------------------------------------
    # Read fields
    # -----------------------------------------------------

    email = body.get(
        "email"
    )

    username = body.get(
        "username"
    )

    identifier = body.get(
        "identifier"
    )

    password = body.get(
        "password"
    )

    # -----------------------------------------------------
    # Normalize
    # -----------------------------------------------------

    email = (
        str(email).strip().lower()
        if email is not None
        else ""
    )

    username = (
        str(username).strip()
        if username is not None
        else ""
    )

    identifier = (
        str(identifier).strip()
        if identifier is not None
        else ""
    )

    password = (
        str(password)
        if password is not None
        else ""
    )

    login_identifier = (
        email
        or identifier
        or username
    )

    if not login_identifier:
        raise HTTPException(
            status_code=400,
            detail=(
                "ایمیل یا نام کاربری "
                "الزامی است."
            ),
        )

    if not password:
        raise HTTPException(
            status_code=400,
            detail=(
                "رمز عبور الزامی است."
            ),
        )

    # -----------------------------------------------------
    # Find user
    # -----------------------------------------------------

    user = find_user(
        login_identifier
    )

    if user is None:
        raise HTTPException(
            status_code=401,
            detail=(
                "ایمیل یا نام کاربری "
                "یا رمز عبور اشتباه است."
            ),
        )

    # -----------------------------------------------------
    # Verify password
    # -----------------------------------------------------

    try:

        verified_user = (
            verify_user_password(
                login_identifier,
                password,
            )
        )

    except Exception:

        verified_user = None

    if verified_user is None:
        raise HTTPException(
            status_code=401,
            detail=(
                "ایمیل یا نام کاربری "
                "یا رمز عبور اشتباه است."
            ),
        )

    # -----------------------------------------------------
    # Remove old tokens
    # -----------------------------------------------------

    old_tokens = [
        token
        for token, stored_user_id
        in tokens.items()
        if int(stored_user_id)
        == int(user["id"])
    ]

    for token in old_tokens:

        tokens.pop(
            token,
            None,
        )

    # -----------------------------------------------------
    # Create new token
    # -----------------------------------------------------

    token = create_token(
        int(user["id"])
    )

    # -----------------------------------------------------
    # Response
    # -----------------------------------------------------

    return {
        "success": True,
        "message": "ورود موفق بود.",
        "token": token,
        "access_token": token,
        "user": user_to_public_dict(
            user
        ),
    }


# =========================================================
# CURRENT USER
# =========================================================

@router.get(
    "/me"
)
def me(
    authorization: str | None = Header(
        default=None
    ),
):

    user_id = require_user_id(
        authorization
    )

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
        "user": user_to_public_dict(
            user
        ),
    }


# =========================================================
# LOGOUT
# =========================================================

@router.post(
    "/logout"
)
def logout(
    authorization: str | None = Header(
        default=None
    ),
):

    token = get_bearer_token(
        authorization
    )

    remove_token(
        token
    )

    return {
        "success": True,
        "message": (
            "با موفقیت خارج شدید."
        ),
    }