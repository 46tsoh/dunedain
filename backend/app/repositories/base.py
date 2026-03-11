from __future__ import annotations

from typing import Any, Generic, Type, TypeVar

from sqlalchemy.orm import Session

from ..database import Base

ModelT = TypeVar("ModelT", bound=Base)


class BaseRepository(Generic[ModelT]):
    """Generic CRUD repository.

    Subclass and set ``model`` to the SQLAlchemy ORM model class.
    All DB interaction is funnelled through these methods so swapping the
    underlying ORM/database only requires changes here, not in routers.
    """

    model: Type[ModelT]

    def __init__(self, db: Session) -> None:
        self.db = db

    # ── Read ──────────────────────────────────────────────────────────────

    def get(self, pk: Any) -> ModelT | None:
        return self.db.get(self.model, pk)

    def get_or_404(self, pk: Any, detail: str = "Not found") -> ModelT:
        from fastapi import HTTPException
        obj = self.get(pk)
        if obj is None:
            raise HTTPException(status_code=404, detail=detail)
        return obj

    def list(
        self,
        *,
        skip: int = 0,
        limit: int = 100,
        order_by=None,
        filters: list | None = None,
    ) -> list[ModelT]:
        q = self.db.query(self.model)
        if filters:
            for f in filters:
                q = q.filter(f)
        if order_by is not None:
            q = q.order_by(order_by)
        return q.offset(skip).limit(limit).all()

    def count(self, filters: list | None = None) -> int:
        from sqlalchemy import func
        q = self.db.query(func.count(self.model.id))
        if filters:
            for f in filters:
                q = q.filter(f)
        return q.scalar() or 0

    # ── Write ─────────────────────────────────────────────────────────────

    def add(self, obj: ModelT) -> ModelT:
        self.db.add(obj)
        return obj

    def add_all(self, objs: list[ModelT]) -> None:
        self.db.add_all(objs)

    def commit(self) -> None:
        self.db.commit()

    def refresh(self, obj: ModelT) -> ModelT:
        self.db.refresh(obj)
        return obj

    def flush(self) -> None:
        self.db.flush()

    def delete(self, obj: ModelT) -> None:
        self.db.delete(obj)
        self.db.commit()

    def save(self, obj: ModelT) -> ModelT:
        """Add, commit, and refresh in one call."""
        self.db.add(obj)
        self.db.commit()
        self.db.refresh(obj)
        return obj
