from __future__ import annotations

import secrets
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel

from backend.database import (
    create_user,
    find_user_by_id,
    get_connection,
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
# DATABASE USER LOOKUP
# =========================================================

def find_user(
    identifier: str,
) -> dict[str, Any] | None:
    """
    پیدا کردن کاربر با ایمیل یا نام کاربری.

    این تابع داخل auth.py قرار گرفته تا با database.py فعلی
    که تابع find_user ندارد، سازگار باشد.
    """

    value = str(identifier).strip()

    if not value:
        return None

    connection = get_connection()

    try:
        row = connection.execute(
            """
            SELECT
                id,
                username,
                email,
                name,
                password_hash,
                is_admin,
                created_at,
                updated_at
            FROM users
            WHERE LOWER(email) = LOWER(?)
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


# =========================================================
# TOKEN FUNCTIONS
# =========================================================

def create_token(
    user_id: int,
) -> str:

    token = secrets.token_urlsafe(32)

    tokens[token] = int(user_id)

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

    token = get_bearer_token(
        authorization
    )

    user_id = tokens.get(token)

    if user_id is None:
        raise HTTPException(
            status_code=401,
            detail="جلسه ورود معتبر نیست.",
        )

    return int(user_id)


# =========================================================
# REGISTER MODEL
# =========================================================

class RegisterRequest(BaseModel):

    username: str

    email: str

    password: str


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

    # بررسی ایمیل یا نام کاربری تکراری
    existing_user = find_user(email)

    if existing_user is None:
        existing_user = find_user(username)

    if existing_user is not None:
        raise HTTPException(
            status_code=409,
            detail="این ایمیل یا نام کاربری قبلاً ثبت شده است.",
        )

    # create_user خودش رمز را هش می‌کند.
    try:

        user = create_user(
            username=username,
            email=email,
            password=password,
        )

    except Exception as exc:

        error_text = str(exc).lower()

        if (
            "unique" in error_text
            or "already exists" in error_text
            or "duplicate" in error_text
        ):
            raise HTTPException(
                status_code=409,
                detail="این ایمیل یا نام کاربری قبلاً ثبت شده است.",
            )

        raise HTTPException(
            status_code=500,
            detail="ثبت‌نام انجام نشد.",
        ) from exc

    if user is None:
        raise HTTPException(
            status_code=500,
            detail="کاربر ایجاد نشد.",
        )

    return {
        "success": True,
        "message": "ثبت‌نام با موفقیت انجام شد.",
        "user": {
            "id": int(user["id"]),
            "username": user.get("username"),
            "name": user.get("name"),
            "email": user.get("email"),
            "created_at": user.get("created_at"),
        },
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
            detail="بدنه درخواست ورود نامعتبر است.",
        ) from exc

    if not isinstance(body, dict):
        raise HTTPException(
            status_code=400,
            detail="اطلاعات ورود نامعتبر است.",
        )

    # -----------------------------------------------------
    # Read possible field names
    # -----------------------------------------------------

    email = body.get("email")

    username = body.get("username")

    identifier = body.get("identifier")

    password = body.get("password")

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

    # -----------------------------------------------------
    # Determine identifier
    # -----------------------------------------------------

    login_identifier = (
        email
        or identifier
        or username
    )

    if not login_identifier:
        raise HTTPException(
            status_code=400,
            detail="ایمیل یا نام کاربری الزامی است.",
        )

    if not password:
        raise HTTPException(
            status_code=400,
            detail="رمز عبور الزامی است.",
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
            detail="ایمیل یا نام کاربری یا رمز عبور اشتباه است.",
        )

    # -----------------------------------------------------
    # Verify password
    # -----------------------------------------------------

    try:

        valid_password = verify_user_password(
            int(user["id"]),
            password,
        )

    except TypeError:

        # سازگاری در صورتی که ترتیب آرگومان تابع
        # database.py متفاوت باشد.
        try:

            valid_password = verify_user_password(
                password,
                int(user["id"]),
            )

        except Exception:

            valid_password = False

    except Exception:

        valid_password = False

    if not valid_password:
        raise HTTPException(
            status_code=401,
            detail="ایمیل یا نام کاربری یا رمز عبور اشتباه است.",
        )

    # -----------------------------------------------------
    # Remove old tokens
    # -----------------------------------------------------

    old_tokens = [
        token
        for token, stored_user_id in tokens.items()
        if int(stored_user_id) == int(user["id"])
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
        "user": {
            "id": int(user["id"]),
            "username": user.get("username"),
            "name": user.get("name"),
            "email": user.get("email"),
            "is_admin": bool(
                user.get("is_admin", 0)
            ),
        },
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
        "user": user,
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
        "message": "با موفقیت خارج شدید.",
    }