# Grantly backend

FastAPI and SQLAlchemy backend for Grantly.

## Local development

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Local development defaults to SQLite. API documentation is available at `http://127.0.0.1:8000/docs`.

## Checks

```powershell
.\.venv\Scripts\python -m pytest tests -q
```

## PostgreSQL migration

```powershell
$env:DATABASE_URL='postgresql+psycopg://USER:PASSWORD@HOST/DATABASE?sslmode=require'
.\.venv\Scripts\python -m alembic -c alembic.ini upgrade head
```

## Render

Create a Docker web service from this repository. Set `main` as the production branch, `/api/v1/health` as the health check path, and Auto-Deploy to `After CI Checks Pass`.

Required environment variables:

```text
DATABASE_URL=<Neon SQLAlchemy connection string>
JWT_SECRET=<stable random secret of at least 32 bytes>
ENVIRONMENT=production
FRONTEND_URL=<Vercel production URL>
```

The container applies the Alembic migration before starting Uvicorn.

