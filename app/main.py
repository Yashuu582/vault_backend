import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import get_settings
from .rate_limit import client_ip, limiter
from .routers import accounts, admin, audit_logs, auth, health, transactions

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("balancevault")
settings = get_settings()

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@asynccontextmanager
async def lifespan(_: FastAPI):
    limiter.init(settings.redis_host if settings.redis_port else None,
                 settings.redis_port or 6379, settings.redis_password, settings.redis_db)
    yield


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.environment != "production" else None,
    redoc_url=None,
)


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    path = request.url.path

    if path.startswith("/api/"):
        # CSRF defence in depth (cookies are also SameSite=Strict): reject cross-site writes.
        origin = request.headers.get("origin")
        if request.method in UNSAFE_METHODS and origin and origin not in settings.allowed_origins:
            return JSONResponse(status_code=403, content={"detail": "Origin not allowed"})

        allowed, retry_after = limiter.hit(f"api:ip:{client_ip(request)}", settings.api_rate_limit,
                                           settings.api_rate_window)
        if not allowed:
            return JSONResponse(status_code=429, content={"detail": "Too many requests. Please slow down."},
                                headers={"Retry-After": str(retry_after)})

    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    if path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)


@app.exception_handler(Exception)
async def unhandled_exception(request: Request, exc: Exception):
    log.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


app.include_router(health.router)
app.include_router(auth.router)
app.include_router(accounts.router)
app.include_router(admin.router)
app.include_router(audit_logs.router)
app.include_router(transactions.router)
