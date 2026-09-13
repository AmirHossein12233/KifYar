from __future__ import annotations

from typing import Any

from backend.database import (
    approve_card_transfer,
    create_payout_attempt,
    fail_card_transfer,
    get_card_transfer_request,
    mark_transfer_processing,
    complete_card_transfer,
    update_payout_attempt,
)
from backend.providers.sep import SEPProvider


class SettlementService:
    """
    سرویس مرکزی مدیریت تسویه KifYar.

    این کلاس مسئول مدیریت چرخه درخواست است:

        pending
            ↓
        approved
            ↓
        processing
            ↓
        completed

    در صورت خطا:

        processing
            ↓
        failed

    نکته:
    این سرویس هنوز مستقیماً پول واقعی منتقل نمی‌کند.
    انتقال واقعی فقط بعد از اتصال به API رسمی Provider انجام می‌شود.
    """

    def __init__(self) -> None:
        self.sep = SEPProvider()

    # ---------------------------------------------------------
    # دریافت درخواست
    # ---------------------------------------------------------

    def get_transfer(
        self,
        user_id: int,
        transfer_id: int,
    ) -> dict[str, Any]:

        transfer = get_card_transfer_request(
            user_id=user_id,
            transfer_id=transfer_id,
        )

        if not transfer:
            raise ValueError(
                "درخواست تسویه پیدا نشد."
            )

        return transfer

    # ---------------------------------------------------------
    # تأیید
    # ---------------------------------------------------------

    def approve(
        self,
        transfer_id: int,
    ) -> dict[str, Any]:

        return approve_card_transfer(
            transfer_id=transfer_id,
        )

    # ---------------------------------------------------------
    # شروع پردازش
    # ---------------------------------------------------------

    def start_processing(
        self,
        transfer_id: int,
    ) -> dict[str, Any]:

        transfer = self._get_transfer_for_admin(
            transfer_id
        )

        if transfer["status"] != "approved":
            raise ValueError(
                "درخواست باید ابتدا تأیید شود."
            )

        result = mark_transfer_processing(
            transfer_id=transfer_id,
        )

        return result

    # ---------------------------------------------------------
    # ارسال به Provider
    # ---------------------------------------------------------

    def process(
        self,
        transfer_id: int,
    ) -> dict[str, Any]:

        transfer = self._get_transfer_for_admin(
            transfer_id
        )

        status = transfer["status"]

        if status == "approved":
            mark_transfer_processing(
                transfer_id=transfer_id
            )

            transfer = self._get_transfer_for_admin(
                transfer_id
            )

        elif status != "processing":
            raise ValueError(
                "درخواست باید در وضعیت approved یا processing باشد."
            )

        amount = float(
            transfer["amount"]
        )

        card_number = ""

        if transfer.get("masked_card_number"):
            card_number = str(
                transfer["masked_card_number"]
            )

        attempt_id = create_payout_attempt(
            transfer_id=transfer_id,
            provider="sep",
            amount=amount,
        )

        # -----------------------------------------------------
        # فعلاً API واقعی سپ را صدا نمی‌زنیم.
        #
        # دلیل:
        # Endpoint و قرارداد API باید دقیقاً از مستندات
        # رسمی سرویس تسویه فعال‌شده برای پذیرنده گرفته شود.
        # -----------------------------------------------------

        provider_result = self.sep.create_payout(
            amount=amount,
            destination_card=card_number,
            request_id=transfer["request_id"],
        )

        if not provider_result.get("success"):
            error_message = provider_result.get(
                "message",
                "Provider درخواست را انجام نداد.",
            )

            update_payout_attempt(
                attempt_id=attempt_id,
                status="failed",
                response_data=str(
                    provider_result
                ),
                error_message=error_message,
            )

            fail_card_transfer(
                transfer_id=transfer_id,
                reason=error_message,
            )

            return {
                "success": False,
                "status": "failed",
                "transfer_id": transfer_id,
                "message": error_message,
            }

        provider_transfer_id = provider_result.get(
            "provider_transfer_id"
        )

        if not provider_transfer_id:
            error_message = (
                "Provider شناسه تراکنش برنگرداند."
            )

            update_payout_attempt(
                attempt_id=attempt_id,
                status="failed",
                response_data=str(
                    provider_result
                ),
                error_message=error_message,
            )

            fail_card_transfer(
                transfer_id=transfer_id,
                reason=error_message,
            )

            return {
                "success": False,
                "status": "failed",
                "transfer_id": transfer_id,
                "message": error_message,
            }

        update_payout_attempt(
            attempt_id=attempt_id,
            status="submitted",
            provider_transfer_id=(
                provider_transfer_id
            ),
            response_data=str(
                provider_result
            ),
        )

        return {
            "success": True,
            "status": "processing",
            "transfer_id": transfer_id,
            "provider": "sep",
            "provider_transfer_id":
                provider_transfer_id,
        }

    # ---------------------------------------------------------
    # ثبت موفقیت Provider
    # ---------------------------------------------------------

    def complete(
        self,
        transfer_id: int,
        provider_transfer_id: str,
        provider_status: str = "completed",
    ) -> dict[str, Any]:

        if not provider_transfer_id:
            raise ValueError(
                "شناسه تراکنش Provider الزامی است."
            )

        transfer = self._get_transfer_for_admin(
            transfer_id
        )

        if transfer["status"] != "processing":
            raise ValueError(
                "درخواست در وضعیت processing نیست."
            )

        result = complete_card_transfer(
            transfer_id=transfer_id,
            provider_transfer_id=(
                provider_transfer_id
            ),
            provider_status=provider_status,
        )

        return result

    # ---------------------------------------------------------
    # شکست
    # ---------------------------------------------------------

    def fail(
        self,
        transfer_id: int,
        reason: str,
    ) -> dict[str, Any]:

        if not reason.strip():
            reason = "تسویه ناموفق بود."

        return fail_card_transfer(
            transfer_id=transfer_id,
            reason=reason,
        )

    # ---------------------------------------------------------
    # Helper
    # ---------------------------------------------------------

    def _get_transfer_for_admin(
        self,
        transfer_id: int,
    ) -> dict[str, Any]:

        transfer = None

        # get_card_transfer_request به user_id نیاز دارد،
        # بنابراین برای عملیات مدیریت، مستقیماً از DB استفاده
        # نمی‌کنیم و خطا را به شکل کنترل‌شده مدیریت می‌کنیم.

        from backend.database import get_connection

        with get_connection() as conn:

            row = conn.execute(
                """
                SELECT
                    ct.id,
                    ct.user_id,
                    ct.card_id,
                    ct.amount,
                    ct.request_id,
                    ct.status,
                    ct.provider,
                    ct.provider_transfer_id,
                    ct.provider_status,
                    ct.reserved_amount,
                    ct.failure_reason,
                    ct.created_at,
                    ct.updated_at,
                    ct.processed_at,
                    bc.bank_name,
                    bc.holder_name,
                    bc.card_number
                FROM card_transfers ct
                LEFT JOIN bank_cards bc
                    ON bc.id = ct.card_id
                WHERE ct.id = %s
                """,
                (transfer_id,),
            ).fetchone()

        if not row:
            raise ValueError(
                "درخواست تسویه پیدا نشد."
            )

        transfer = dict(row)

        if transfer.get("card_number"):
            from backend.database import mask_card_number

            transfer[
                "masked_card_number"
            ] = mask_card_number(
                transfer["card_number"]
            )

        transfer.pop(
            "card_number",
            None,
        )

        return transfer


settlement_service = SettlementService()