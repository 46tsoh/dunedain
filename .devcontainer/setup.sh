#!/usr/bin/env bash
set -e

echo "==> Installing Python dependencies..."
cd /workspace/backend
pip install --user --no-cache-dir -r requirements.txt
pip install --user --no-cache-dir pytest pytest-asyncio

echo "==> Running database migrations..."
cd /workspace/backend
alembic upgrade head

echo "==> Installing frontend dependencies..."
cd /workspace/frontend
npm install

echo ""
echo "Dunedain dev environment ready."
echo ""
echo "  Backend:  cd backend && uvicorn app.main:app --reload --host 0.0.0.0 --port 1337"
echo "  Worker:   cd backend && celery -A app.celery_app worker --loglevel=info -Q scans"
echo "  Frontend: cd frontend && npm run dev"
echo ""
