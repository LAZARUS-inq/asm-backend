import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.v1.deps import get_current_user
from app.db.session import get_db
from app.models.models import Domain, Finding, ScanJob, User, Workspace
from app.schemas.schemas import FindingResponse, FindingUpdate

router = APIRouter(prefix="/workspaces/{workspace_id}/findings", tags=["findings"])


def _parse_uuid(val: str) -> uuid.UUID:
    try:
        return uuid.UUID(val)
    except ValueError:
        raise HTTPException(status_code=404, detail="Not found")


def _assert_workspace_access(workspace_id: str, user: User, db: Session) -> Workspace:
    ws = db.query(Workspace).filter(
        Workspace.id == _parse_uuid(workspace_id),
        Workspace.owner_id == user.id,
    ).first()
    if not ws:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return ws


@router.get("", response_model=list[FindingResponse])
def list_findings(
    workspace_id: str,
    severity: str | None = None,
    finding_type: str | None = None,
    is_resolved: bool | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    ws = _assert_workspace_access(workspace_id, current_user, db)

    domain_ids = [d.id for d in db.query(Domain.id).filter(Domain.workspace_id == ws.id)]
    scan_job_ids = [
        j.id for j in db.query(ScanJob.id).filter(ScanJob.domain_id.in_(domain_ids))
    ]

    q = db.query(Finding).filter(Finding.scan_job_id.in_(scan_job_ids))

    if severity:
        q = q.filter(Finding.severity == severity)
    if finding_type:
        q = q.filter(Finding.finding_type == finding_type)
    if is_resolved is not None:
        q = q.filter(Finding.is_resolved == is_resolved)

    return q.order_by(Finding.risk_score.desc()).all()


@router.patch("/{finding_id}", response_model=FindingResponse)
def update_finding(
    workspace_id: str,
    finding_id: str,
    payload: FindingUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    ws = _assert_workspace_access(workspace_id, current_user, db)

    domain_ids = [d.id for d in db.query(Domain.id).filter(Domain.workspace_id == ws.id)]
    scan_job_ids = [
        j.id for j in db.query(ScanJob.id).filter(ScanJob.domain_id.in_(domain_ids))
    ]

    finding = db.query(Finding).filter(
        Finding.id == _parse_uuid(finding_id),
        Finding.scan_job_id.in_(scan_job_ids),
    ).first()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if payload.is_resolved is not None:
        finding.is_resolved = payload.is_resolved

    db.commit()
    db.refresh(finding)
    return finding