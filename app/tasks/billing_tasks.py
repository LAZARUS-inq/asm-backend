from celery import shared_task
from celery.utils.log import get_task_logger

from app.db.session import SessionLocal
from app.services.plan_service import expire_due_plans

logger = get_task_logger(__name__)


@shared_task(name="app.tasks.billing_tasks.expire_due_plans")
def expire_due_plans_task() -> dict:
    db = SessionLocal()
    try:
        count = expire_due_plans(db)
        logger.info(f"expire_due_plans: downgraded {count} user(s)")
        return {"expired": count}
    finally:
        db.close()
