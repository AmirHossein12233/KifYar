from __future__ import annotations

from fastapi import HTTPException, Request

from backend.auth import tokens


def get_authenticated_user(
    request: Request,
):
    authorization = request.headers.get(
        "Authorization"
    )

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

    token = authorization[7:].strip()

    if not token:
        raise HTTPException(
            status_code=401,
            detail="توکن نامعتبر است.",
        )

    user_id = tokens.get(
        token
    )

    if user_id is None:
        raise HTTPException(
            status_code=401,
            detail="جلسه ورود معتبر نیست.",
        )

    return {
        "user_id": int(user_id),
        "token": token,
    }


def require_session_user_id(
    request: Request,
) -> int:
    authenticated_user = (
        get_authenticated_user(
            request
        )
    )

    return int(
        authenticated_user["user_id"]
    )
