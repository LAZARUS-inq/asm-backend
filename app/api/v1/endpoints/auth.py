import secrets
import uuid
from datetime import datetime, timezone, timedelta

import resend
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import Column, String, DateTime
from sqlalchemy.orm import Session

from app.api.v1.deps import get_current_user
from app.core.config import settings
from app.core.security import (
    create_access_token,
    decode_token_allow_expired,
    token_past_refresh_grace,
)
from app.db.session import Base, get_db
from app.models.models import User
from app.schemas.schemas import (
    MagicLinkRequest,
    MagicLinkVerify,
    TokenResponse,
    UserResponse,
)

_bearer = HTTPBearer(auto_error=False)

router = APIRouter(prefix="/auth", tags=["auth"])

resend.api_key = settings.resend_api_key


# ──────────────────────────────────────────────
# Magic link token storage (simple DB table)
# ──────────────────────────────────────────────

class MagicToken(Base):
    __tablename__ = "magic_tokens"
    token = Column(String(64), primary_key=True)
    email = Column(String(255), nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)


def utcnow():
    return datetime.now(timezone.utc)


# ──────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────

@router.post("/magic-link")
def send_magic_link(
    email: str | None = None,
    body: MagicLinkRequest | None = None,
    plan: str = "starter",
    db: Session = Depends(get_db),
):
    """Send magic link to email. Creates user if not exists."""
    raw = (body.email if body else None) or email
    if not raw:
        raise HTTPException(status_code=400, detail="email is required")
    email = raw.lower().strip()

    # Create user if not exists
    user = db.query(User).filter(User.email == email).first()
    if not user:
        user = User(email=email, hashed_password="magic_link_user")
        db.add(user)
        db.commit()
        db.refresh(user)

    # Create magic token
    token = secrets.token_urlsafe(32)
    expires_at = utcnow() + timedelta(minutes=30)

    # Remove old tokens for this email
    db.query(MagicToken).filter(MagicToken.email == email).delete()

    magic = MagicToken(token=token, email=email, expires_at=expires_at)
    db.add(magic)
    db.commit()

    # Build magic link URL
    magic_url = f"{settings.frontend_url}/verify?token={token}&plan={plan}"

    # Send email via Resend
    try:
        resend.Emails.send({
            "from": f"ASM Security <noreply@{settings.resend_domain}>",
            "to": [email],
            "subject": "Your ASM login link",
            "html": f"""
            <div style="font-family: -apple-system, sans-serif; max-width: 480px; margin: 0 auto; padding: 40px 20px;">
                <div style="margin-bottom: 32px;">
                    <div style="width: 40px; height: 40px; background: linear-gradient(135deg, #6366F1, #EF4444); border-radius: 10px; display: flex; align-items: center; justify-content: center; margin-bottom: 16px;">
                        <span style="color: white; font-size: 20px;">🛡</span>
                    </div>
                    <h1 style="font-size: 22px; font-weight: 700; color: #111; margin: 0 0 8px;">Sign in to ASM</h1>
                    <p style="font-size: 15px; color: #666; margin: 0;">Click the button below to sign in. This link expires in 30 minutes.</p>
                </div>
                <a href="{magic_url}" style="display: inline-block; background: #6366F1; color: white; text-decoration: none; padding: 14px 28px; border-radius: 10px; font-size: 15px; font-weight: 600; margin-bottom: 24px;">
                    Sign in to ASM →
                </a>
                <p style="font-size: 13px; color: #999; margin: 0;">If you didn't request this, you can safely ignore this email.</p>
                <p style="font-size: 12px; color: #ccc; margin-top: 8px;">Link: {magic_url}</p>
            </div>
            """,
        })
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to send email: {str(e)}")

    return {"status": "sent", "message": "Check your email for the login link"}


@router.post("/verify-magic-link", response_model=TokenResponse)
def verify_magic_link(
    token: str | None = None,
    body: MagicLinkVerify | None = None,
    db: Session = Depends(get_db),
):
    """Verify magic link token and return JWT."""
    raw = (body.token if body else None) or token
    if not raw:
        raise HTTPException(status_code=400, detail="token is required")
    token = raw.strip()
    magic = db.query(MagicToken).filter(MagicToken.token == token).first()

    if not magic:
        raise HTTPException(status_code=400, detail="Invalid or expired link")

    if magic.expires_at < utcnow():
        db.delete(magic)
        db.commit()
        raise HTTPException(status_code=400, detail="Link expired. Please request a new one.")

    user = db.query(User).filter(User.email == magic.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Delete used token
    db.delete(magic)
    db.commit()

    access_token = create_access_token({"sub": str(user.id)})
    return TokenResponse(access_token=access_token)


@router.post("/refresh", response_model=TokenResponse)
def refresh_access_token(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
):
    """Issue a new JWT while the previous one is still within the refresh grace window."""
    if not creds or creds.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Missing bearer token")

    payload = decode_token_allow_expired(creds.credentials)
    if token_past_refresh_grace(payload):
        raise HTTPException(
            status_code=401,
            detail="Session expired. Please request a new login link.",
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return TokenResponse(access_token=create_access_token({"sub": str(user.id)}))


@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user