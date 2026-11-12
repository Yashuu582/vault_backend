from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import require_oversight
from ..models import AuditLog, User
from ..schemas import AuditLogOut, Page

router = APIRouter(prefix="/api/audit-logs", tags=["audit"])


@router.get("", response_model=Page[AuditLogOut])
def list_audit_logs(
    _: User = Depends(require_oversight),
    db: Session = Depends(get_db),
    action: str | None = Query(default=None, max_length=64),
    actor: str | None = Query(default=None, max_length=254, description="Actor email contains"),
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
):
    q = select(AuditLog)
    if action:
        q = q.where(AuditLog.action.like(f"{action}%"))
    if actor:
        q = q.where(func.lower(AuditLog.actor_email).like(f"%{actor.lower()}%"))
    if date_from:
        q = q.where(AuditLog.created_at >= date_from)
    if date_to:
        q = q.where(AuditLog.created_at <= date_to)
    total = db.scalar(select(func.count()).select_from(q.subquery()))
    items = db.scalars(q.order_by(AuditLog.id.desc()).offset((page - 1) * page_size).limit(page_size)).all()
    return Page(items=[AuditLogOut.model_validate(i) for i in items], total=total, page=page, page_size=page_size)


@router.get("/actions", response_model=list[str])
def list_actions(_: User = Depends(require_oversight), db: Session = Depends(get_db)):
    return db.scalars(select(AuditLog.action).distinct().order_by(AuditLog.action)).all()
