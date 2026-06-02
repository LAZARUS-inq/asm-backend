import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.api.v1.deps import get_current_user
from app.core.config import settings
from app.core.plans import PLAN_SPECS, PAID_PLAN_KEYS, domain_limit, effective_plan, scan_interval_hours, utcnow
from app.db.session import get_db
from app.models.models import User
from app.schemas.schemas import BillingPlansResponse, CheckoutResponse, PlanInfoResponse
from app.services.plan_service import activate_paid_plan, parse_billing_order_id, verify_nowpayments_signature

router = APIRouter(prefix="/billing", tags=["billing"])

NOWPAYMENTS_API = "https://api.nowpayments.io/v1"


def _days_remaining(expires_at) -> int | None:
    if not expires_at:
        return None
    delta = expires_at - utcnow()
    return max(0, delta.days)


def _billing_plans_response(user: User) -> BillingPlansResponse:
    eff = effective_plan(user)
    return BillingPlansResponse(
        current_plan=user.plan,
        effective_plan=eff,
        plan_expires_at=user.plan_expires_at,
        days_remaining=_days_remaining(user.plan_expires_at),
        domain_limit=domain_limit(eff),
        scan_interval_hours=scan_interval_hours(eff),
        plans=[
            PlanInfoResponse(
                id=key,
                name=spec.name,
                price=spec.price_usd,
                domains=spec.domain_limit,
                scan_interval=spec.scan_interval_label,
                scan_interval_hours=spec.scan_interval_hours,
                features=list(spec.features),
            )
            for key, spec in PLAN_SPECS.items()
            if key != "free"
        ],
    )


@router.post("/checkout", response_model=CheckoutResponse)
async def create_checkout(
    plan: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if plan not in PAID_PLAN_KEYS:
        raise HTTPException(status_code=400, detail="Invalid plan")

    spec = PLAN_SPECS[plan]

    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"{NOWPAYMENTS_API}/invoice",
            headers={"x-api-key": settings.nowpayments_api_key, "Content-Type": "application/json"},
            json={
                "price_amount": spec.price_usd,
                "price_currency": "usd",
                "pay_currency": "usdtbsc",
                "order_id": f"{plan}_{current_user.id}",
                "order_description": f"ASM {spec.name} — {spec.domain_limit} domains, {spec.scan_interval_label.lower()} scans",
                "ipn_callback_url": f"{settings.api_base_url}/api/v1/billing/webhook",
                "success_url": f"{settings.frontend_url}/billing/success?plan={plan}",
                "cancel_url": f"{settings.frontend_url}/billing/cancel",
            },
        )

    if r.status_code != 200:
        raise HTTPException(status_code=502, detail=f"NOWPayments error: {r.text}")

    data = r.json()
    return CheckoutResponse(
        checkout_url=data.get("invoice_url") or "",
        payment_id=data.get("id"),
        plan=plan,
        amount_usd=spec.price_usd,
    )


@router.get("/plans", response_model=BillingPlansResponse)
def get_plans(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from app.services.plan_service import refresh_user_plan

    refresh_user_plan(current_user, db)
    db.refresh(current_user)
    return _billing_plans_response(current_user)


@router.post("/webhook")
async def nowpayments_webhook(request: Request, db: Session = Depends(get_db)):
    payload = await request.json()
    signature = request.headers.get("x-nowpayments-sig")

    if settings.nowpayments_ipn_secret:
        if not verify_nowpayments_signature(payload, signature, settings.nowpayments_ipn_secret):
            raise HTTPException(status_code=400, detail="Invalid IPN signature")
    elif settings.environment == "production":
        raise HTTPException(status_code=500, detail="IPN secret not configured")

    payment_status = payload.get("payment_status")
    order_id = payload.get("order_id", "")

    if payment_status not in ("finished", "confirmed"):
        return {"status": "ignored"}

    parsed = parse_billing_order_id(order_id)
    if not parsed:
        return {"status": "invalid order_id"}

    plan_name, user_id = parsed
    user = db.query(User).filter(User.id == user_id).first()
    if user:
        activate_paid_plan(user, plan_name, db)

    return {"status": "ok"}
