import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, DateTime, Enum, Float, ForeignKey,
    Integer, String, Text, UniqueConstraint, Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


def utcnow():
    return datetime.now(timezone.utc)


class PlanTier(str, enum.Enum):
    free = "free"
    starter = "starter"
    pro = "pro"


class ScanStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class Severity(str, enum.Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True, native_uuid=False), primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    stripe_customer_id: Mapped[str] = mapped_column(String(255), default="")
    stripe_subscription_id: Mapped[str] = mapped_column(String(255), default="")
    plan: Mapped[PlanTier] = mapped_column(Enum(PlanTier), default=PlanTier.free, nullable=False)
    plan_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    workspaces: Mapped[list["Workspace"]] = relationship(back_populates="owner", cascade="all, delete-orphan")


class Workspace(Base):
    __tablename__ = "workspaces"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True, native_uuid=False), primary_key=True, default=uuid.uuid4
    )
    owner_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True, native_uuid=False), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    owner: Mapped["User"] = relationship(back_populates="workspaces")
    domains: Mapped[list["Domain"]] = relationship(back_populates="workspace", cascade="all, delete-orphan")


class Domain(Base):
    __tablename__ = "domains"
    __table_args__ = (UniqueConstraint("workspace_id", "fqdn"),)

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True, native_uuid=False), primary_key=True, default=uuid.uuid4
    )
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True, native_uuid=False), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False
    )
    fqdn: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    scan_interval_hours: Mapped[int] = mapped_column(Integer, default=24)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    workspace: Mapped["Workspace"] = relationship(back_populates="domains")
    scan_jobs: Mapped[list["ScanJob"]] = relationship(back_populates="domain", cascade="all, delete-orphan")


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True, native_uuid=False), primary_key=True, default=uuid.uuid4
    )
    domain_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True, native_uuid=False), ForeignKey("domains.id", ondelete="CASCADE"), nullable=False
    )
    celery_task_id: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.pending, nullable=False)
    current_stage: Mapped[str] = mapped_column(String(64), default="")
    error_message: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    domain: Mapped["Domain"] = relationship(back_populates="scan_jobs")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan_job", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True, native_uuid=False), primary_key=True, default=uuid.uuid4
    )
    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True, native_uuid=False), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False
    )
    finding_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    service: Mapped[str] = mapped_column(String(128), default="")
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.info, nullable=False)
    title: Mapped[str] = mapped_column(String(512), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    cve_id: Mapped[str] = mapped_column(String(32), default="")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    raw_output: Mapped[str] = mapped_column(Text, default="")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    is_resolved: Mapped[bool] = mapped_column(Boolean, default=False)

    scan_job: Mapped["ScanJob"] = relationship(back_populates="findings")
