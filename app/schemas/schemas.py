import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, field_validator

from app.models.models import PlanTier, ScanStatus, Severity


# ──────────────────────────────────────────────
# Auth
# ──────────────────────────────────────────────

class UserRegister(BaseModel):
    email: EmailStr
    password: str
    full_name: str = ""

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class MagicLinkRequest(BaseModel):
    email: EmailStr


class MagicLinkVerify(BaseModel):
    token: str


class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    full_name: str
    plan: PlanTier
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


# ──────────────────────────────────────────────
# Workspace
# ──────────────────────────────────────────────

class WorkspaceCreate(BaseModel):
    name: str


class WorkspaceResponse(BaseModel):
    id: uuid.UUID
    name: str
    created_at: datetime

    model_config = {"from_attributes": True}


# ──────────────────────────────────────────────
# Domain
# ──────────────────────────────────────────────

class DomainCreate(BaseModel):
    fqdn: str
    scan_interval_hours: int = 24

    @field_validator("fqdn")
    @classmethod
    def clean_fqdn(cls, v: str) -> str:
        v = v.lower().strip().removeprefix("https://").removeprefix("http://").rstrip("/")
        if not v or " " in v:
            raise ValueError("Invalid domain")
        return v


class DomainResponse(BaseModel):
    id: uuid.UUID
    fqdn: str
    is_active: bool
    scan_interval_hours: int
    last_scanned_at: Optional[datetime]
    created_at: datetime

    model_config = {"from_attributes": True}


# ──────────────────────────────────────────────
# ScanJob
# ──────────────────────────────────────────────

class ScanJobResponse(BaseModel):
    id: uuid.UUID
    domain_id: uuid.UUID
    status: ScanStatus
    current_stage: str = ""
    error_message: str
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanStatusResponse(BaseModel):
    active: bool
    job_id: Optional[uuid.UUID] = None
    status: Optional[ScanStatus] = None
    current_stage: str = ""
    findings_count: int = 0
    fqdn: str = ""
    started_at: Optional[datetime] = None
    error_message: str = ""


# ──────────────────────────────────────────────
# Finding
# ──────────────────────────────────────────────

class FindingResponse(BaseModel):
    id: uuid.UUID
    scan_job_id: uuid.UUID
    finding_type: str
    target: str
    port: Optional[int]
    service: str
    severity: Severity
    title: str
    description: str
    cve_id: str
    risk_score: float
    first_seen_at: datetime
    last_seen_at: datetime
    is_resolved: bool

    model_config = {"from_attributes": True}


class FindingUpdate(BaseModel):
    is_resolved: Optional[bool] = None
