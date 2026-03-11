"""Registries router — CRUD + connection test + manual sync + repo/tag browsing."""

from __future__ import annotations

from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Registry
from ..repositories.repos import RegistryRepository
from ..schemas import RegistryCreate, RegistryRead, RegistryTestResult, RegistryUpdate
from ..services import registry as registry_svc
from ..tasks.registry_sync import sync_registry

router = APIRouter(prefix="/registries", tags=["registries"])


def _get_repo(db: Session = Depends(get_db)) -> RegistryRepository:
    return RegistryRepository(db)


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

@router.get("/", response_model=list[RegistryRead])
def list_registries(repo: RegistryRepository = Depends(_get_repo)):
    return repo.list_all()


@router.post("/", response_model=RegistryRead, status_code=201)
def create_registry(
    payload: RegistryCreate,
    repo: RegistryRepository = Depends(_get_repo),
):
    reg = Registry(
        id=str(uuid4()),
        name=payload.name,
        url=payload.url.rstrip("/"),
        type=payload.type,
        auth_method=payload.auth_method,
        username=payload.username or None,
        password=payload.password or None,
        auto_sync=payload.auto_sync,
    )
    return repo.save(reg)


@router.get("/{registry_id}", response_model=RegistryRead)
def get_registry(registry_id: str, repo: RegistryRepository = Depends(_get_repo)):
    reg = repo.get(registry_id)
    if not reg:
        raise HTTPException(status_code=404, detail="Registry not found")
    return reg


@router.patch("/{registry_id}", response_model=RegistryRead)
def update_registry(
    registry_id: str,
    payload: RegistryUpdate,
    repo: RegistryRepository = Depends(_get_repo),
):
    reg = repo.get(registry_id)
    if not reg:
        raise HTTPException(status_code=404, detail="Registry not found")
    if payload.name is not None:
        reg.name = payload.name
    if payload.url is not None:
        reg.url = payload.url.rstrip("/")
    if payload.auth_method is not None:
        reg.auth_method = payload.auth_method
    if payload.username is not None:
        reg.username = payload.username or None
    if payload.password is not None:
        reg.password = payload.password or None
    if payload.auto_sync is not None:
        reg.auto_sync = payload.auto_sync
    repo.db.commit()
    repo.db.refresh(reg)
    return reg


@router.delete("/{registry_id}", status_code=204)
def delete_registry(registry_id: str, repo: RegistryRepository = Depends(_get_repo)):
    reg = repo.get(registry_id)
    if not reg:
        raise HTTPException(status_code=404, detail="Registry not found")
    repo.delete(reg)


# ---------------------------------------------------------------------------
# Connection test
# ---------------------------------------------------------------------------

@router.post("/{registry_id}/test", response_model=RegistryTestResult)
def test_registry_connection(
    registry_id: str,
    repo: RegistryRepository = Depends(_get_repo),
):
    reg = repo.get(registry_id)
    if not reg:
        raise HTTPException(status_code=404, detail="Registry not found")
    success, message, repositories = registry_svc.test_connection(reg.url, reg.auth_method, username=reg.username, password=reg.password)
    return RegistryTestResult(success=success, message=message, repositories=repositories)


# ---------------------------------------------------------------------------
# Manual sync (dispatches Celery task immediately)
# ---------------------------------------------------------------------------

@router.post("/{registry_id}/sync", status_code=202)
def trigger_sync(
    registry_id: str,
    repo: RegistryRepository = Depends(_get_repo),
):
    reg = repo.get(registry_id)
    if not reg:
        raise HTTPException(status_code=404, detail="Registry not found")
    sync_registry.delay(registry_id)
    return {"queued": True, "registry_id": registry_id}


# ---------------------------------------------------------------------------
# Repository + tag browsing (live — bypasses cache)
# ---------------------------------------------------------------------------

@router.get("/{registry_id}/repositories/search", response_model=list[str])
def search_repositories(
    registry_id: str,
    q: str = Query(default="", min_length=1),
    repo: RegistryRepository = Depends(_get_repo),
):
    reg = repo.get(registry_id)
    if not reg:
        raise HTTPException(status_code=404, detail="Registry not found")
    try:
        return registry_svc.search_repositories(reg.url, reg.auth_method, q, username=reg.username, password=reg.password)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@router.get("/{registry_id}/repositories", response_model=list[str])
def list_repositories(
    registry_id: str,
    repo: RegistryRepository = Depends(_get_repo),
):
    reg = repo.get(registry_id)
    if not reg:
        raise HTTPException(status_code=404, detail="Registry not found")
    try:
        return registry_svc.list_repositories(reg.url, reg.auth_method, username=reg.username, password=reg.password)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@router.get("/{registry_id}/repositories/{repository:path}/tags", response_model=list[str])
def list_tags(
    registry_id: str,
    repository: str,
    repo: RegistryRepository = Depends(_get_repo),
):
    reg = repo.get(registry_id)
    if not reg:
        raise HTTPException(status_code=404, detail="Registry not found")
    try:
        return registry_svc.list_tags(reg.url, reg.auth_method, repository, username=reg.username, password=reg.password)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))
