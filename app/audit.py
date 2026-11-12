from fastapi import Request
from sqlalchemy.orm import Session

from .models import AuditLog, User
from .rate_limit import client_ip


def record(
    db: Session,
    action: str,
    *,
    actor: User | None = None,
    request: Request | None = None,
    entity_type: str | None = None,
    entity_id: object | None = None,
    details: dict | None = None,
    actor_email: str | None = None,
) -> None:
    """Add an audit entry to the current transaction (committed with the action itself)."""
    db.add(
        AuditLog(
            actor_id=actor.id if actor else None,
            actor_email=actor.email if actor else actor_email,
            action=action,
            entity_type=entity_type,
            entity_id=str(entity_id) if entity_id is not None else None,
            details=details,
            ip=client_ip(request) if request else None,
            user_agent=(request.headers.get("user-agent", "")[:255] or None) if request else None,
        )
    )
