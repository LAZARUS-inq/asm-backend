import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.v1.deps import get_current_user
from app.db.session import get_db
from app.models.models import Domain, Finding, PlanTier, ScanJob, ScanStatus, User, Workspace
from app.schemas.schemas import DomainCreate, DomainResponse, ScanStatusResponse
from app.tasks.scan_tasks import run_full_scan

router = APIRouter(prefix="/workspaces/{workspace_id}/domains", tags=["domains"])

PLAN_DOMAIN_LIMITS = {
    PlanTier.free: 1,
    PlanTier.starter: 5,
    PlanTier.pro: 25,
}


def _parse_uuid(val: str) -> uuid.UUID:
    try:
        return uuid.UUID(val)
    except ValueError:
        raise HTTPException(status_code=404, detail="Not found")


def _get_workspace(workspace_id: str, user: User, db: Session) -> Workspace:
    ws = db.query(Workspace).filter(
        Workspace.id == _parse_uuid(workspace_id),
        Workspace.owner_id == user.id,
    ).first()
    if not ws:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return ws


@router.post("", response_model=DomainResponse, status_code=status.HTTP_201_CREATED)
def add_domain(
    workspace_id: str,
    payload: DomainCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    ws = _get_workspace(workspace_id, current_user, db)

    existing_count = db.query(Domain).filter(Domain.workspace_id == ws.id).count()
    limit = PLAN_DOMAIN_LIMITS[current_user.plan]
    if existing_count >= limit:
        raise HTTPException(
            status_code=402,
            detail=f"Plan limit reached ({limit} domains). Upgrade to add more.",
        )

    if db.query(Domain).filter(Domain.workspace_id == ws.id, Domain.fqdn == payload.fqdn).first():
        raise HTTPException(status_code=400, detail="Domain already exists in this workspace")

    domain = Domain(workspace_id=ws.id, **payload.model_dump())
    db.add(domain)
    db.commit()
    db.refresh(domain)

    try:
        run_full_scan.delay(str(domain.id))
    except Exception:
        pass  # Celery worker not running locally — task skipped

    return domain


@router.get("", response_model=list[DomainResponse])
def list_domains(
    workspace_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    ws = _get_workspace(workspace_id, current_user, db)
    return db.query(Domain).filter(Domain.workspace_id == ws.id).all()


@router.delete("/{domain_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_domain(
    workspace_id: str,
    domain_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    ws = _get_workspace(workspace_id, current_user, db)
    domain = db.query(Domain).filter(
        Domain.id == _parse_uuid(domain_id),
        Domain.workspace_id == ws.id,
    ).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    db.delete(domain)
    db.commit()


@router.post("/{domain_id}/scan", response_model=dict)
def trigger_scan(
    workspace_id: str,
    domain_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    ws = _get_workspace(workspace_id, current_user, db)
    domain = db.query(Domain).filter(
        Domain.id == _parse_uuid(domain_id),
        Domain.workspace_id == ws.id,
    ).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    job = ScanJob(
        domain_id=domain.id,
        status=ScanStatus.pending,
        current_stage="queued",
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    try:
        task = run_full_scan.delay(str(domain.id), str(job.id))
        job.celery_task_id = task.id or ""
        db.commit()
        return {
            "task_id": task.id,
            "job_id": str(job.id),
            "status": "queued",
            "current_stage": "queued",
        }
    except Exception:
        job.status = ScanStatus.failed
        job.current_stage = "failed"
        job.error_message = "worker_unavailable"
        db.commit()
        return {"task_id": None, "job_id": str(job.id), "status": "worker_unavailable"}


@router.get("/{domain_id}/scan/status", response_model=ScanStatusResponse)
def get_scan_status(
    workspace_id: str,
    domain_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    ws = _get_workspace(workspace_id, current_user, db)
    domain = db.query(Domain).filter(
        Domain.id == _parse_uuid(domain_id),
        Domain.workspace_id == ws.id,
    ).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    job = (
        db.query(ScanJob)
        .filter(ScanJob.domain_id == domain.id)
        .order_by(ScanJob.created_at.desc())
        .first()
    )

    if not job:
        return ScanStatusResponse(active=False, fqdn=domain.fqdn)

    active = job.status in (ScanStatus.pending, ScanStatus.running)
    findings_count = (
        db.query(Finding).filter(Finding.scan_job_id == job.id).count()
    )

    return ScanStatusResponse(
        active=active,
        job_id=job.id,
        status=job.status,
        current_stage=job.current_stage or "",
        findings_count=findings_count,
        fqdn=domain.fqdn,
        started_at=job.started_at,
        error_message=job.error_message or "",
    )