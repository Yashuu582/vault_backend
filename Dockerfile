# BalanceVault backend (FastAPI). Build and run from the Backend folder:
#
#   docker build -t balancevault-backend .
#   docker run -d -p 8000:8000 --env-file .env -e DB_HOST=host.docker.internal \
#       -e REDIS_HOST=host.docker.internal --name balancevault-backend balancevault-backend
#
# Inside a container "localhost" is the container itself, so point DB_HOST / REDIS_HOST at
# host.docker.internal to reach PostgreSQL and Redis running on your machine.
# On start the container applies Alembic migrations, then serves the API on $PORT
# (8000 by default; hosts such as Render set PORT themselves).

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN useradd --create-home --uid 10001 appuser

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
# Normalise line endings in case the repo was checked out on Windows.
RUN sed -i 's/\r$//' docker-entrypoint.sh && chmod +x docker-entrypoint.sh

USER appuser
ENV PORT=8000
EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=5 \
  CMD python -c "import os,urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/ready' % os.environ.get('PORT','8000'), timeout=2).status == 200 else 1)"

ENTRYPOINT ["./docker-entrypoint.sh"]
# Shell form so $PORT is expanded at start-up; exec keeps uvicorn as PID 1 for clean shutdowns.
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
