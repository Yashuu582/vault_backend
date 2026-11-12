from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL, make_url

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=BASE_DIR / ".env", extra="ignore")

    app_name: str = "BalanceVault API"
    environment: str = "development"

    # ---- PostgreSQL: normally you only set DB_PORT, DB_USER and DB_PASSWORD ----
    db_host: str = "localhost"
    db_port: int = 5432
    db_name: str = "balancevault"
    db_user: str | None = None
    db_password: str | None = None
    # Optional separate role for Alembic migrations (schema owner). Defaults to DB_USER/DB_PASSWORD.
    migration_db_user: str | None = None
    migration_db_password: str | None = None
    # "require" for hosted databases that only accept encrypted connections (Neon, etc.).
    db_sslmode: str | None = None
    # Optional full connection string, e.g. the one Neon gives you
    # (postgresql://user:pass@host/db?sslmode=require). Takes precedence over the DB_* parts.
    database_url: str | None = None

    # ---- Redis: set REDIS_PORT to enable it; leave empty for in-memory rate limiting ----
    redis_host: str = "localhost"
    redis_port: int | None = None
    redis_password: str | None = None
    redis_db: int = 0

    cors_origins: str = "http://localhost:5173"

    jwt_secret: str = Field(min_length=32)
    jwt_algorithm: str = "HS256"
    access_token_ttl_minutes: int = 15
    refresh_token_ttl_days: int = 7
    cookie_secure: bool = False
    # "strict"/"lax" work when frontend and API share a site (localhost:5173 + localhost:8000 do).
    # Use "none" (requires COOKIE_SECURE=true / HTTPS) only if they are on different domains.
    cookie_samesite: Literal["strict", "lax", "none"] = "strict"

    # Forgot password: the reset link points at the frontend's /reset-password page.
    frontend_url: str = "http://localhost:5173"
    password_reset_ttl_minutes: int = 30
    # Optional SMTP for sending reset emails. If SMTP_HOST is empty, the link is written to the
    # backend log instead (development only).
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from: str = "BalanceVault <no-reply@example.com>"
    smtp_starttls: bool = True

    # Rate limits: requests per window (seconds)
    forgot_password_rate_limit: int = 3
    forgot_password_rate_window: int = 3600
    login_rate_limit: int = 5
    login_rate_window: int = 60
    register_rate_limit: int = 10
    register_rate_window: int = 3600
    api_rate_limit: int = 300
    api_rate_window: int = 60

    @field_validator("redis_port", "redis_password", "database_url", "db_user", "db_password",
                     "migration_db_user", "migration_db_password", "db_sslmode", "smtp_host", "smtp_user",
                     "smtp_password", mode="before")
    @classmethod
    def empty_is_none(cls, v):
        return None if isinstance(v, str) and v.strip() == "" else v

    @model_validator(mode="after")
    def check_database_config(self):
        if not self.database_url and not (self.db_user and self.db_password):
            raise ValueError("Database not configured: set DB_USER and DB_PASSWORD (and DB_PORT) in Backend/.env")
        if self.cookie_samesite == "none" and not self.cookie_secure:
            raise ValueError("COOKIE_SAMESITE=none requires COOKIE_SECURE=true")
        return self

    def _pg_url(self, user: str, password: str) -> URL:
        # URL.create escapes special characters, so passwords may contain anything.
        return URL.create(
            "postgresql+psycopg",
            username=user,
            password=password,
            host=self.db_host,
            port=self.db_port,
            database=self.db_name,
            query={"sslmode": self.db_sslmode} if self.db_sslmode else {},
        )

    def _from_database_url(self) -> URL:
        url = make_url(self.database_url)
        # Hosted providers hand out plain "postgresql://" / "postgres://" URLs, which SQLAlchemy
        # would map to psycopg2. This app ships psycopg (v3), so pin that driver.
        if url.drivername in ("postgresql", "postgres"):
            url = url.set(drivername="postgresql+psycopg")
        if self.db_sslmode and url.get_backend_name() == "postgresql" and "sslmode" not in url.query:
            url = url.update_query_dict({"sslmode": self.db_sslmode})
        return url

    @property
    def sqlalchemy_url(self) -> URL:
        if self.database_url:
            return self._from_database_url()
        return self._pg_url(self.db_user, self.db_password)

    @property
    def alembic_url(self) -> URL:
        if self.database_url:
            return self._from_database_url()
        return self._pg_url(self.migration_db_user or self.db_user,
                            self.migration_db_password or self.db_password)

    @property
    def allowed_origins(self) -> list[str]:
        return [o.strip().rstrip("/") for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
