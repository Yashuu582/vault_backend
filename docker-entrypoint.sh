#!/bin/sh
set -e

echo "Applying database migrations..."
alembic upgrade head

if [ -n "$BV_ADMIN_PASSWORD" ]; then
  # Idempotent: does nothing if the admin already exists. Password is read from BV_ADMIN_PASSWORD.
  python -m scripts.create_admin \
    --email "${BV_ADMIN_EMAIL:-admin@example.com}" \
    --username "${BV_ADMIN_USERNAME:-admin}" \
    --name "${BV_ADMIN_NAME:-Vault Admin}"
fi

exec "$@"
