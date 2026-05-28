from celery import Celery
from celery.schedules import crontab

from app.core.config import settings

celery_app = Celery(
    "asm",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["app.tasks.scan_tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,                  # re-queue if worker crashes
    worker_prefetch_multiplier=1,         # fair dispatch for long tasks
    result_expires=86400,                 # 1 day
)

# Periodic beat schedule — reschedule due domains every 10 min
celery_app.conf.beat_schedule = {
    "schedule-due-scans": {
        "task": "app.tasks.scan_tasks.schedule_due_scans",
        "schedule": crontab(minute="*/10"),
    },
}
