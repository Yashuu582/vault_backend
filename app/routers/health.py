import os

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

from ..db import engine
from ..rate_limit import limiter

router = APIRouter(tags=["health"])

# Render sets RENDER_GIT_COMMIT to the deployed commit SHA. The CI/CD pipeline compares it with
# the commit it just deployed, to know the new version is really live. Other hosts: APP_COMMIT.
DEPLOYED_COMMIT = os.environ.get("RENDER_GIT_COMMIT") or os.environ.get("APP_COMMIT") or None


@router.get("/health")
def health():
    """Liveness: the process is up and serving requests."""
    return {"status": "ok", "commit": DEPLOYED_COMMIT}


@router.get("/ready")
def ready():
    """Readiness: dependencies (database, Redis if configured) are reachable."""
    checks: dict[str, str] = {}
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:
        checks["database"] = "unavailable"

    redis_ok = limiter.ping()
    checks["redis"] = "not_configured" if redis_ok is None else ("ok" if redis_ok else "unavailable")
    checks["rate_limiter"] = limiter.backend

    is_ready = checks["database"] == "ok" and checks["redis"] != "unavailable"
    return JSONResponse(status_code=200 if is_ready else 503,
                        content={"status": "ready" if is_ready else "not_ready", "checks": checks})
