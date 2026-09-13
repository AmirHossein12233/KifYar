from __future__ import annotations

import secrets

from fastapi import (
    APIRouter,
    Header,
    HTTPException,
    Request,
)
from pydantic import BaseModel

from backend.database import (
    create_user,
    find_user,
    get_user_by_id,
    verify_password,
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

class RegisterRequest(
    BaseModel
):

    username: str

    email: str

    password: str


# =========================================================
# LOGIN MODEL
# =========================================================

class LoginRequest(
    BaseModel
):

    email: str | None = None

    username: str | None = None

    identifier: str | None = None

    password: str | None = None


# =========================================================
# LOGOUT MODEL
# =========================================================

class LogoutRequest(
    BaseModel
):
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
        data.username
        .strip()
    )

    email = (
        data.email
        .strip()
        .lower()
    )

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

    existing_user = find_user(
        email
    )

    if existing_user is not None:

        raise HTTPException(
            status_code=409,
            detail="این ایمیل یا نام کاربری قبلاً ثبت شده است.",
        )

    # مهم:
    # رمز را اینجا هش نمی‌کنیم.
    # create_user خودش هش می‌کند.
    user = create_user(
        username=username,
        email=email,
        password=password,
    )

    return {
        "success": True,
        "message": "ثبت‌نام با موفقیت انجام شد.",
        "user": {
            "id": int(
                user["id"]
            ),
            "username": user.get(
                "username"
            ),
            "name": user.get(
                "name"
            ),
            "email": user.get(
                "email"
            ),
            "created_at": user.get(
                "created_at"
            ),
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

    except Exception:

        raise HTTPException(
            status_code=400,
            detail="بدنه درخواست ورود نامعتبر است.",
        )

    if not isinstance(
        body,
        dict,
    ):

        raise HTTPException(
            status_code=400,
            detail="اطلاعات ورود نامعتبر است.",
        )

    # -----------------------------------------------------
    # Read possible field names
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
    # Stored password
    # -----------------------------------------------------

    stored_password = user.get(
        "password_hash"
    )

    if not stored_password:

        raise HTTPException(
            status_code=401,
            detail="رمز عبور این حساب ثبت نشده است.",
        )

    # -----------------------------------------------------
    # Verify
    # -----------------------------------------------------

    try:

        valid_password = verify_password(
            password,
            stored_password,
        )

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
        for token, stored_user_id
        in tokens.items()
        if int(
            stored_user_id
        ) == int(
            user["id"]
        )
    ]

    for token in old_tokens:

        tokens.pop(
            token,
            None,
        )

    # -----------------------------------------------------
    # New token
    # -----------------------------------------------------

    token = create_token(
        int(
            user["id"]
        )
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
            "id": int(
                user["id"]
            ),
            "username": user.get(
                "username"
            ),
            "name": user.get(
                "name"
            ),
            "email": user.get(
                "email"
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

    user = get_user_by_id(
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
