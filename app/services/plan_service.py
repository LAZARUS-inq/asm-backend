"""Activate, expire, and sync subscription plans."""
from __future__ import annotations

import uuid
from datetime import timedelta

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.plans import (
    PAID_PLAN_KEYS,
    PLAN_SPECS,
    _aware_utc,
    effective_plan,
    scan_interval_hours,
    utcnow,
)
from app.models.models import Domain, PlanTier, User, Workspace


def refresh_user_plan(user: User, db: Session) -> PlanTier:
    """Downgrade expired paid plans and sync domain scan intervals."""
    expires = _aware_utc(user.plan_expires_at)
    if user.plan != PlanTier.free and expires and expires <= utcnow():
        user.plan = PlanTier.free
        user.plan_expires_at = None
        db.commit()
        db.refresh(user)
        sync_domain_scan_intervals(user, db)
    return effective_plan(user)


def activate_paid_plan(user: User, plan_key: str, db: Session) -> None:
    if plan_key not in PAID_PLAN_KEYS:
        raise ValueError(f"Invalid paid plan: {plan_key}")

    spec = PLAN_SPECS[plan_key]
    now = utcnow()
    base = now
    current_expires = _aware_utc(user.plan_expires_at)
    if current_expires and current_expires > now and user.plan == spec.id:
        base = current_expires

    user.plan = spec.id
    user.plan_expires_at = base + timedelta(days=settings.plan_subscription_days)
    db.commit()
    db.refresh(user)
    sync_domain_scan_intervals(user, db)


def sync_domain_scan_intervals(user: User, db: Session) -> None:
    interval = scan_interval_hours(effective_plan(user))
    ws_ids = [
        row[0]
        for row in db.query(Workspace.id).filter(Workspace.owner_id == user.id).all()
    ]
    if not ws_ids:
        return
    db.query(Domain).filter(Domain.workspace_id.in_(ws_ids)).update(
        {Domain.scan_interval_hours: interval},
        synchronize_session=False,
    )
    db.commit()


def expire_due_plans(db: Session) -> int:
    """Downgrade all users whose paid plan expired. Returns count downgraded."""
    now = utcnow()
    expired = (
        db.query(User)
        .filter(
            User.plan != PlanTier.free,
            User.plan_expires_at.isnot(None),
            User.plan_expires_at <= now,
        )
        .all()
    )
    for user in expired:
        user.plan = PlanTier.free
        user.plan_expires_at = None
        sync_domain_scan_intervals(user, db)
    if expired:
        db.commit()
    return len(expired)


def verify_nowpayments_signature(payload: dict, signature: str | None, secret: str) -> bool:
    import hashlib
    import hmac
    import json

    if not signature or not secret:
        return False
    sorted_msg = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    digest = hmac.new(secret.encode(), sorted_msg.encode(), hashlib.sha512).hexdigest()
    return hmac.compare_digest(digest, signature)


def parse_billing_order_id(order_id: str) -> tuple[str, uuid.UUID] | None:
    for plan_key in PAID_PLAN_KEYS:
        prefix = f"{plan_key}_"
        if order_id.startswith(prefix):
            try:
                return plan_key, uuid.UUID(order_id[len(prefix) :])
            except ValueError:
                return None
    return None
