-- BalanceVault database + role bootstrap. Run ONCE as a PostgreSQL superuser:
--
--   psql -U postgres -h localhost -v migrator_pw=<strong-password> -v app_pw=<strong-password> -f sql/db_roles.sql
--
-- Roles (separation of duties):
--   bv_migrator  owns the database and schema; used only by Alembic migrations (DDL).
--   bv_app       used by the running API; DML only, and INSERT/SELECT-only on audit_logs.
--   bv_readonly  NOLOGIN group role for reporting / auditors; grant it to individual login roles.

CREATE ROLE bv_migrator LOGIN PASSWORD :'migrator_pw';
CREATE ROLE bv_app LOGIN PASSWORD :'app_pw';
CREATE ROLE bv_readonly NOLOGIN;

CREATE DATABASE balancevault OWNER bv_migrator;

\connect balancevault

ALTER SCHEMA public OWNER TO bv_migrator;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO bv_app, bv_readonly;
REVOKE CREATE ON SCHEMA public FROM bv_app, bv_readonly;

-- Tables created later by bv_migrator get sensible defaults automatically.
-- (Migration 0001 additionally revokes UPDATE/DELETE/TRUNCATE on audit_logs from bv_app.)
ALTER DEFAULT PRIVILEGES FOR ROLE bv_migrator IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO bv_app;
ALTER DEFAULT PRIVILEGES FOR ROLE bv_migrator IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO bv_app;
ALTER DEFAULT PRIVILEGES FOR ROLE bv_migrator IN SCHEMA public
    GRANT SELECT ON TABLES TO bv_readonly;
