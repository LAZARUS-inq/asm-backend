import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.v1.deps import get_current_user
from app.db.session import get_db
from app.models.models import Domain, PlanTier, User, Workspace
from app.schemas.schemas import DomainCreate, DomainResponse
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

    try:
        task = run_full_scan.delay(str(domain.id))
        return {"task_id": task.id, "status": "queued"}
    except Exception:
        return {"task_id": None, "status": "worker_unavailable"}