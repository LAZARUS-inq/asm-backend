import hashlib
import hmac
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.api.v1.deps import get_current_user
from app.core.config import settings
from app.db.session import get_db
from app.models.models import PlanTier, User

router = APIRouter(prefix="/billing", tags=["billing"])

NOWPAYMENTS_API = "https://api.nowpayments.io/v1"

PLANS = {
    "starter": {"price": 49, "plan": PlanTier.starter, "description": "ASM Starter — 5 domains, daily scans"},
    "pro":     {"price": 199, "plan": PlanTier.pro,     "description": "ASM Pro — 25 domains, hourly scans"},
}


@router.post("/checkout")
async def create_checkout(
    plan: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if plan not in PLANS:
        raise HTTPException(status_code=400, detail="Invalid plan")

    p = PLANS[plan]

    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"{NOWPAYMENTS_API}/invoice",
            headers={"x-api-key": settings.nowpayments_api_key, "Content-Type": "application/json"},
            json={
                "price_amount": p["price"],
                "price_currency": "usd",
                "pay_currency": "usdtbsc",
                "order_id": f"{plan}_{current_user.id}",
                "order_description": p["description"],
                "ipn_callback_url": f"{settings.api_base_url}/api/v1/billing/webhook",
                "success_url": f"{settings.frontend_url}/billing/success",
                "cancel_url": f"{settings.frontend_url}/billing/cancel",
            },
        )

    if r.status_code != 200:
        raise HTTPException(status_code=502, detail=f"NOWPayments error: {r.text}")

    data = r.json()
    return {
        "checkout_url": data.get("invoice_url"),
        "payment_id": data.get("id"),
        "plan": plan,
        "amount_usd": p["price"],
    }


@router.get("/plans")
def get_plans(current_user: User = Depends(get_current_user)):
    return {
        "current_plan": current_user.plan,
        "plans": [
            {
                "id": "starter",
                "name": "Starter",
                "price": 49,
                "domains": 5,
                "scan_interval": "Daily",
                "features": ["5 domains", "Daily scans", "Email alerts", "Finding history"],
            },
            {
                "id": "pro",
                "name": "Pro",
                "price": 199,
                "domains": 25,
                "scan_interval": "Hourly",
                "features": ["25 domains", "Hourly scans", "Slack alerts", "API access", "PDF reports"],
            },
        ],
    }


@router.post("/webhook")
async def nowpayments_webhook(request: Request, db: Session = Depends(get_db)):
    payload = await request.json()

    payment_status = payload.get("payment_status")
    order_id = payload.get("order_id", "")

    if payment_status not in ("finished", "confirmed"):
        return {"status": "ignored"}

    # order_id format: "starter_<user_uuid>" or "pro_<user_uuid>"
    parts = order_id.split("_", 1)
    if len(parts) != 2:
        return {"status": "invalid order_id"}

    plan_name, user_id_str = parts
    if plan_name not in PLANS:
        return {"status": "invalid plan"}

    from uuid import UUID
    try:
        user_id = UUID(user_id_str)
    except ValueError:
        return {"status": "invalid user_id"}

    user = db.query(User).filter(User.id == user_id).first()
    if user:
        user.plan = PLANS[plan_name]["plan"]
        db.commit()

    return {"status": "ok"}