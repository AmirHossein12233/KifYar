from __future__ import annotations

import os
from typing import Any


class SEPProvider:

    def __init__(self) -> None:

        self.merchant_id = os.getenv(
            "SEP_MERCHANT_ID",
            "",
        ).strip()

        self.api_key = os.getenv(
            "SEP_API_KEY",
            "",
        ).strip()

    def is_configured(self) -> bool:

        return bool(
            self.merchant_id
            and self.api_key
        )

    def create_payout(
        self,
        *,
        amount: float,
        destination_card: str,
        request_id: str,
    ) -> dict[str, Any]:

        if amount <= 0:
            raise ValueError(
                "مبلغ تسویه نامعتبر است."
            )

        if not request_id:
            raise ValueError(
                "شناسه درخواست مشخص نشده است."
            )

        # =====================================================
        # مهم:
        #
        # تا وقتی مستندات رسمی سرویس تسویه SEP مشخص نشده،
        # هیچ درخواست بانکی ارسال نمی‌کنیم.
        #
        # همچنین شماره کارت ماسک‌شده نباید به Provider ارسال شود.
        # =====================================================

        return {
            "success": False,
            "status": "provider_not_connected",
            "provider": "sep",
            "request_id": request_id,
            "message": (
                "سرویس تسویه سپ هنوز به API رسمی "
                "متصل نشده است."
            ),
        }

    def get_payout_status(
        self,
        provider_transfer_id: str,
    ) -> dict[str, Any]:

        if not provider_transfer_id:
            raise ValueError(
                "شناسه تراکنش Provider مشخص نشده است."
            )

        return {
            "success": False,
            "status": "provider_not_connected",
            "provider": "sep",
            "provider_transfer_id":
                provider_transfer_id,
            "message": (
                "استعلام تسویه سپ هنوز پیاده‌سازی نشده است."
            ),
        }