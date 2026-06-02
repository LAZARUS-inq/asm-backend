import pytest
from datetime import timedelta

from app.core.plans import PLAN_SPECS, effective_plan, scan_interval_hours, utcnow, _aware_utc
from app.models.models import PlanTier, User
from app.services.plan_service import (
    activate_paid_plan,
    expire_due_plans,
    parse_billing_order_id,
    refresh_user_plan,
    verify_nowpayments_signature,
)


def test_effective_plan_expired():
    user = User(
        email="a@b.com",
        hashed_password="x",
        plan=PlanTier.starter,
        plan_expires_at=utcnow() - timedelta(days=1),
    )
    assert effective_plan(user) == PlanTier.free


def test_scan_interval_by_plan():
    assert scan_interval_hours(PlanTier.free) == 168
    assert scan_interval_hours(PlanTier.starter) == 24
    assert scan_interval_hours(PlanTier.pro) == 1


def test_parse_order_id():
    uid = "12345678-1234-5678-1234-567812345678"
    plan_key, parsed = parse_billing_order_id(f"starter_{uid}")
    assert plan_key == "starter"
    assert str(parsed) == uid


def test_activate_extends_subscription(db_session):
    user = User(email="pay@x.com", hashed_password="x", plan=PlanTier.free)
    db_session.add(user)
    db_session.commit()
    activate_paid_plan(user, "starter", db_session)
    db_session.refresh(user)
    assert user.plan == PlanTier.starter
    assert user.plan_expires_at is not None
    assert _aware_utc(user.plan_expires_at) > utcnow()


def test_refresh_downgrades_expired(db_session):
    user = User(
        email="old@x.com",
        hashed_password="x",
        plan=PlanTier.pro,
        plan_expires_at=utcnow() - timedelta(hours=1),
    )
    db_session.add(user)
    db_session.commit()
    assert refresh_user_plan(user, db_session) == PlanTier.free
    db_session.refresh(user)
    assert user.plan == PlanTier.free


@pytest.fixture
def db_session():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.db.session import Base

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    db = Session()
    try:
        yield db
    finally:
        db.close()


def test_ipn_signature():
    secret = "test-secret"
    payload = {"payment_status": "finished", "order_id": "starter_x"}
    import hashlib
    import hmac
    import json

    msg = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    sig = hmac.new(secret.encode(), msg.encode(), hashlib.sha512).hexdigest()
    assert verify_nowpayments_signature(payload, sig, secret)
