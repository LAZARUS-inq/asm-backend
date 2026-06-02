"""Subscription plan limits and scan cadence."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from app.models.models import PlanTier


@dataclass(frozen=True)
class PlanSpec:
    id: PlanTier
    name: str
    price_usd: int
    domain_limit: int
    scan_interval_hours: int
    scan_interval_label: str
    features: tuple[str, ...]


PLAN_SPECS: dict[str, PlanSpec] = {
    "free": PlanSpec(
        id=PlanTier.free,
        name="Free",
        price_usd=0,
        domain_limit=1,
        scan_interval_hours=168,
        scan_interval_label="Weekly",
        features=("1 domain", "Weekly scans", "Finding history (7 days)"),
    ),
    "starter": PlanSpec(
        id=PlanTier.starter,
        name="Starter",
        price_usd=49,
        domain_limit=5,
        scan_interval_hours=24,
        scan_interval_label="Daily",
        features=("5 domains", "Daily scans", "Email alerts", "Finding history"),
    ),
    "pro": PlanSpec(
        id=PlanTier.pro,
        name="Pro",
        price_usd=199,
        domain_limit=25,
        scan_interval_hours=1,
        scan_interval_label="Hourly",
        features=("25 domains", "Hourly scans", "Slack alerts", "API access", "PDF reports"),
    ),
}

PAID_PLAN_KEYS = ("starter", "pro")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def effective_plan(user) -> PlanTier:
    """Paid plan is active only while plan_expires_at is in the future."""
    if user.plan == PlanTier.free:
        return PlanTier.free
    expires = _aware_utc(getattr(user, "plan_expires_at", None))
    if expires is not None and expires <= utcnow():
        return PlanTier.free
    return user.plan


def domain_limit(plan: PlanTier) -> int:
    for spec in PLAN_SPECS.values():
        if spec.id == plan:
            return spec.domain_limit
    return PLAN_SPECS["free"].domain_limit


def scan_interval_hours(plan: PlanTier) -> int:
    for spec in PLAN_SPECS.values():
        if spec.id == plan:
            return spec.scan_interval_hours
    return PLAN_SPECS["free"].scan_interval_hours


def plan_key_for_tier(plan: PlanTier) -> str:
    for key, spec in PLAN_SPECS.items():
        if spec.id == plan:
            return key
    return "free"
