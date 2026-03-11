# Database Portability

Current engine: **SQLite** (default). Target engine for production/Kubernetes: **PostgreSQL**.

The application is close to being database-agnostic but has a small number of known gaps that
must be resolved before switching engines.

---

## What is already in good shape

| Area | Detail |
|---|---|
| `DATABASE_URL` is env-driven | Change the connection string in the environment — nothing else in `database.py` needs to change |
| All queries go through SQLAlchemy ORM | No raw SQL, no `text()` calls, no dialect-specific tricks anywhere in the codebase |
| Repository pattern is in place | All DB access is centralized in `app/repositories/` — not scattered across routers |
| Column types are portable | `String`, `Boolean`, `Float`, `Text`, `Integer`, `JSON`, `DateTime` are standard across SQLite and Postgres |

---

## Known blockers

### 1. `connect_args={"check_same_thread": False}` — SQLite-only (`database.py:10`)

This argument is passed unconditionally to `create_engine`. PostgreSQL does not accept it and
will raise an error on startup.

**Fix — 2-line change in `database.py`:**

```python
connect_args = {"check_same_thread": False} if SQLALCHEMY_DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args=connect_args,
    ...
)
```

---

### 2. Named `Enum` types in `models.py` — Postgres creates them as real DB types

Every `Enum` column has a `name=` kwarg (e.g. `scan_type_enum`, `severity_enum`). SQLite silently
ignores these names. PostgreSQL treats them as first-class types and issues
`CREATE TYPE scan_type_enum AS ENUM (...)` on `Base.metadata.create_all()`.

This causes two problems:

- **Re-deploy breaks** — if the type already exists, `create_all()` raises a `DuplicateObject` error
- **Schema changes break** — adding or renaming an enum value requires `ALTER TYPE`, which
  `create_all()` will never issue

Options:

| Option | Trade-off |
|---|---|
| Add `create_type=False` to each `Enum` and manage types externally via Alembic | Correct long-term approach; more setup |
| Replace `Enum` columns with `String` + application-level validation | Simpler; loses DB-level constraint enforcement |

---

### 3. No migration system (Alembic)

The app currently uses `Base.metadata.create_all()` in `main.py` for schema initialisation.
This is fine for SQLite (it is additive and tolerant of drift) but insufficient for Postgres:

- Any column addition, rename, or type change requires an explicit `ALTER TABLE`
- `create_all()` will silently skip tables that already exist, so schema drift accumulates
- There is no rollback path

**Fix:** Introduce [Alembic](https://alembic.sqlalchemy.org/).

```
pip install alembic
alembic init alembic
# point alembic/env.py at app.database.engine and app.models.Base
alembic revision --autogenerate -m "initial"
alembic upgrade head
```

Replace the `Base.metadata.create_all()` call in `main.py` with `alembic upgrade head` run as
an init container (in Docker Compose or Kubernetes) before the backend starts.

---

### 4. Test suite hardcodes SQLite (`tests/test_api.py:9-10`)

```python
TEST_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
```

CI cannot run against Postgres without parameterising this. The fix is to read
`TEST_DATABASE_URL` from the environment, falling back to SQLite for local runs.

---

## Kubernetes context

Switching to Postgres is a prerequisite for running multiple backend replicas in Kubernetes.
SQLite uses a single file on a PVC — concurrent writes from two pods will corrupt data.

The rest of the stack (Celery, Redis, the FastAPI app, the repository layer) is already
Kubernetes-native in design. See `docs/kubernetes.md` for the broader K8s architecture notes.

---

## Work required (in order)

1. Fix `connect_args` conditional in `database.py` — ~2 minutes
2. Decide: named Enums with `create_type=False` vs. `String` columns
3. Introduce Alembic, generate initial migration, replace `create_all()` with migration runner
4. Parameterise `TEST_DATABASE_URL` in the test suite
5. Add `psycopg2-binary` (or `asyncpg` for async) to `requirements.txt`
6. Update `docker-compose.yml` to add a `postgres` service and set `DATABASE_URL` accordingly
7. Test end-to-end with Postgres locally before touching any K8s manifests
