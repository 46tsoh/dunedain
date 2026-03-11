"""Registry service — ACR connectivity via User-Assigned Managed Identity (UAMI),
and generic Docker Registry v2 with username/password (Basic auth token exchange).

Auth flows:
  managed_identity (ACR):
    1. GET IMDS endpoint to obtain an AAD access token for management.azure.com
    2. POST to ACR's OAuth2 exchange endpoint to get an ACR *refresh token*
    3. POST to ACR's token endpoint to get an ACR *access token* scoped for the registry
    4. Use the ACR access token as a Bearer token for ACR HTTP API calls

  username_password (Docker Hub / GHCR / generic OCI):
    1. POST to the registry's token service with Basic auth to get a Bearer token
    2. Use the Bearer token for API calls
    Docker Hub token service: https://auth.docker.io/token
    GHCR token service:       https://ghcr.io/token
    Generic: falls back to HTTP Basic auth directly

  none:
    Anonymous — no auth headers sent.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# IMDS endpoint available inside Azure VMs/containers
_IMDS_TOKEN_URL = (
    "http://169.254.169.254/metadata/identity/oauth2/token"
    "?api-version=2018-02-01"
    "&resource=https://management.azure.com/"
)

_IMDS_TIMEOUT = 5  # short — if not on Azure this will just fail fast




# ---------------------------------------------------------------------------
# Internal helpers — UAMI / ACR
# ---------------------------------------------------------------------------

def _get_aad_token() -> str:
    """Fetch an AAD access token from the Azure IMDS endpoint."""
    with httpx.Client(timeout=_IMDS_TIMEOUT) as client:
        resp = client.get(_IMDS_TOKEN_URL, headers={"Metadata": "true"})
    resp.raise_for_status()
    data = resp.json()
    token = data.get("access_token")
    if not token:
        raise RuntimeError(f"IMDS returned no access_token: {data}")
    return token


def _get_acr_token(registry_url: str) -> str:
    """Exchange an AAD token for an ACR catalog-scoped access token."""
    aad_token = _get_aad_token()

    exchange_url = f"https://{registry_url}/oauth2/exchange"
    with httpx.Client(timeout=30) as client:
        resp = client.post(
            exchange_url,
            data={
                "grant_type": "access_token",
                "service": registry_url,
                "access_token": aad_token,
            },
        )
    resp.raise_for_status()
    refresh_token = resp.json().get("refresh_token")
    if not refresh_token:
        raise RuntimeError(f"ACR exchange returned no refresh_token: {resp.text}")

    token_url = f"https://{registry_url}/oauth2/token"
    with httpx.Client(timeout=30) as client:
        resp = client.post(
            token_url,
            data={
                "grant_type": "refresh_token",
                "service": registry_url,
                "scope": "registry:catalog:*",
                "refresh_token": refresh_token,
            },
        )
    resp.raise_for_status()
    access_token = resp.json().get("access_token")
    if not access_token:
        raise RuntimeError(f"ACR token endpoint returned no access_token: {resp.text}")
    return access_token


def _get_acr_token_for_repo(registry_url: str, repository: str) -> str:
    """Get an ACR access token scoped for a specific repository (tag listing)."""
    aad_token = _get_aad_token()

    exchange_url = f"https://{registry_url}/oauth2/exchange"
    with httpx.Client(timeout=30) as client:
        resp = client.post(
            exchange_url,
            data={
                "grant_type": "access_token",
                "service": registry_url,
                "access_token": aad_token,
            },
        )
    resp.raise_for_status()
    refresh_token = resp.json().get("refresh_token")
    if not refresh_token:
        raise RuntimeError(f"ACR exchange returned no refresh_token: {resp.text}")

    token_url = f"https://{registry_url}/oauth2/token"
    with httpx.Client(timeout=30) as client:
        resp = client.post(
            token_url,
            data={
                "grant_type": "refresh_token",
                "service": registry_url,
                "scope": f"repository:{repository}:pull",
                "refresh_token": refresh_token,
            },
        )
    resp.raise_for_status()
    access_token = resp.json().get("access_token")
    if not access_token:
        raise RuntimeError(f"ACR token endpoint returned no access_token: {resp.text}")
    return access_token


_DOCKER_HUB_HOSTS = {"registry-1.docker.io", "index.docker.io", "registry.hub.docker.com"}


def _is_docker_hub(registry_url: str) -> bool:
    return registry_url in _DOCKER_HUB_HOSTS


def _docker_hub_list_repositories(username: str, password: str) -> list[str]:
    """List repositories for a Docker Hub user via the Hub REST API.

    Uses hub.docker.com/v2/users/login to get a JWT, then paginates
    hub.docker.com/v2/repositories/{username}/.

    Returns fully-qualified names like 'username/reponame'.
    """
    # Step 1: obtain a Hub JWT
    with httpx.Client(timeout=30) as client:
        resp = client.post(
            "https://hub.docker.com/v2/users/login",
            json={"username": username, "password": password},
        )
    resp.raise_for_status()
    jwt = resp.json().get("token")
    if not jwt:
        raise RuntimeError(f"Docker Hub login returned no token: {resp.text[:200]}")

    # Step 2: paginate repos
    repos: list[str] = []
    url: str | None = f"https://hub.docker.com/v2/repositories/{username}/?page_size=100"
    headers = {"Authorization": f"JWT {jwt}"}

    with httpx.Client(timeout=30) as client:
        while url:
            resp = client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            for item in data.get("results", []):
                ns = item.get("namespace", username)
                name = item.get("name", "")
                if name:
                    repos.append(f"{ns}/{name}")
            url = data.get("next")

    return repos


# ---------------------------------------------------------------------------
# Internal helpers — username/password token exchange (Docker Hub / GHCR / OCI)
# ---------------------------------------------------------------------------

def _parse_www_authenticate(header: str) -> dict[str, str]:
    """Parse a Bearer WWW-Authenticate header into a dict of its parameters.

    Example input:
        Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="registry:catalog:*"
    Returns:
        {"realm": "https://auth.docker.io/token", "service": "registry.docker.io", "scope": "..."}
    """
    result: dict[str, str] = {}
    # Strip the "Bearer " prefix
    value = header.strip()
    if value.lower().startswith("bearer "):
        value = value[7:]
    import re
    for match in re.finditer(r'(\w+)="([^"]*)"', value):
        result[match.group(1)] = match.group(2)
    return result


def _discover_token_challenge(registry_url: str) -> dict[str, str]:
    """Hit /v2/ anonymously and extract the WWW-Authenticate Bearer challenge params.

    Returns a dict with at least 'realm' and 'service' keys, or empty dict if
    the registry doesn't issue a 401 challenge (e.g. it's fully open).
    """
    with httpx.Client(timeout=10) as client:
        try:
            resp = client.get(f"https://{registry_url}/v2/")
        except Exception:
            return {}
    if resp.status_code == 401:
        www_auth = resp.headers.get("www-authenticate", "")
        if www_auth:
            return _parse_www_authenticate(www_auth)
    return {}


def _get_bearer_token(
    registry_url: str,
    username: str,
    password: str,
    scope: str,
) -> str | None:
    """Obtain a Bearer token via the Docker Registry v2 token service protocol.

    Discovers the correct token endpoint and service name by probing /v2/ and
    reading the WWW-Authenticate challenge — works for Docker Hub, GHCR, and
    any OCI-compliant registry without hardcoded URLs.

    Returns the token string, or None if no token service is found.
    """
    challenge = _discover_token_challenge(registry_url)
    realm = challenge.get("realm")
    if not realm:
        return None

    service = challenge.get("service", registry_url)
    params = {"service": service, "scope": scope}

    with httpx.Client(timeout=30) as client:
        resp = client.get(realm, params=params, auth=(username, password))

    if resp.status_code in (404, 405):
        return None

    resp.raise_for_status()
    data = resp.json()
    return data.get("token") or data.get("access_token")


def _is_acr(registry_url: str) -> bool:
    return registry_url.lower().endswith(".azurecr.io")


def _get_acr_token_from_refresh(
    registry_url: str,
    refresh_token: str,
    scope: str,
) -> str:
    """Exchange an ACR refresh token for a scoped ACR access token.

    Used when the user provides an ACR refresh token (from ``az acr login
    --expose-token``) as the password.  The refresh token cannot be used
    directly as Basic auth — it must be POSTed to the ACR OAuth2 token
    endpoint with ``grant_type=refresh_token``.
    """
    token_url = f"https://{registry_url}/oauth2/token"
    with httpx.Client(timeout=30) as client:
        resp = client.post(
            token_url,
            data={
                "grant_type": "refresh_token",
                "service": registry_url,
                "scope": scope,
                "refresh_token": refresh_token,
            },
        )
    resp.raise_for_status()
    access_token = resp.json().get("access_token")
    if not access_token:
        raise RuntimeError(f"ACR token endpoint returned no access_token: {resp.text}")
    return access_token


def _build_auth_headers(
    registry_url: str,
    auth_method: str,
    repository: str | None = None,
    username: str | None = None,
    password: str | None = None,
) -> dict[str, str]:
    """Return HTTP headers for authenticating against a registry."""
    if auth_method == "managed_identity":
        try:
            if repository:
                token = _get_acr_token_for_repo(registry_url, repository)
            else:
                token = _get_acr_token(registry_url)
            return {"Authorization": f"Bearer {token}"}
        except Exception as exc:
            logger.warning("UAMI token fetch failed, falling back to anonymous: %s", exc)

    elif auth_method == "username_password" and username and password:
        scope = f"repository:{repository}:pull" if repository else "registry:catalog:*"

        # ACR refresh tokens (from `az acr login --expose-token`) must be
        # exchanged via POST grant_type=refresh_token, not Basic auth GET.
        if _is_acr(registry_url) and username == "00000000-0000-0000-0000-000000000000":
            try:
                token = _get_acr_token_from_refresh(registry_url, password, scope)
                return {"Authorization": f"Bearer {token}"}
            except Exception as exc:
                logger.warning("ACR refresh token exchange failed: %s", exc)
                return {}

        try:
            token = _get_bearer_token(registry_url, username, password, scope)
            if token:
                return {"Authorization": f"Bearer {token}"}
        except Exception as exc:
            logger.warning("Bearer token fetch failed, falling back to Basic auth: %s", exc)
        # Fall back to HTTP Basic auth
        import base64
        creds = base64.b64encode(f"{username}:{password}".encode()).decode()
        return {"Authorization": f"Basic {creds}"}

    return {}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def list_repositories(
    registry_url: str,
    auth_method: str,
    username: str | None = None,
    password: str | None = None,
) -> list[str]:
    """Return all repository names in the registry (paginated)."""
    # Docker Hub blocks /v2/_catalog for all non-admin users.
    # Use the Hub REST API instead.
    if auth_method == "username_password" and username and password and _is_docker_hub(registry_url):
        return _docker_hub_list_repositories(username, password)

    headers = _build_auth_headers(registry_url, auth_method, username=username, password=password)
    repos: list[str] = []
    url: str | None = f"https://{registry_url}/v2/_catalog"

    with httpx.Client(timeout=30) as client:
        while url:
            resp = client.get(url, headers=headers)
            resp.raise_for_status()
            data: dict[str, Any] = resp.json()
            repos.extend(data.get("repositories") or [])

            link = resp.headers.get("link", "")
            url = _parse_link_next(link, registry_url) if link else None

    return repos


def list_tags(
    registry_url: str,
    auth_method: str,
    repository: str,
    username: str | None = None,
    password: str | None = None,
) -> list[str]:
    """Return all tags for a repository (paginated)."""
    headers = _build_auth_headers(registry_url, auth_method, repository=repository, username=username, password=password)
    tags: list[str] = []
    url: str | None = f"https://{registry_url}/v2/{repository}/tags/list"

    with httpx.Client(timeout=30) as client:
        while url:
            resp = client.get(url, headers=headers)
            resp.raise_for_status()
            data: dict[str, Any] = resp.json()
            tags.extend(data.get("tags") or [])

            link = resp.headers.get("link", "")
            url = _parse_link_next(link, registry_url) if link else None

    return tags


def search_repositories(
    registry_url: str,
    auth_method: str,
    query: str,
    username: str | None = None,
    password: str | None = None,
) -> list[str]:
    """Search for repositories by name.

    For Docker Hub: uses the public Hub search API (no auth required).
    For other registries: filters the cached catalog (or live catalog) by query string.
    Returns up to 25 results.
    """
    query = query.strip()
    if not query:
        return []

    if _is_docker_hub(registry_url):
        # Docker Hub public search — no auth needed
        with httpx.Client(timeout=15) as client:
            resp = client.get(
                "https://hub.docker.com/v2/search/repositories/",
                params={"query": query, "page_size": 25},
            )
        resp.raise_for_status()
        results = resp.json().get("results", [])
        return [r["repo_name"] for r in results if r.get("repo_name")]

    # Generic: filter catalog by query string
    try:
        all_repos = list_repositories(registry_url, auth_method, username=username, password=password)
    except Exception:
        all_repos = []
    q_lower = query.lower()
    return [r for r in all_repos if q_lower in r.lower()][:25]


def test_connection(
    registry_url: str,
    auth_method: str,
    username: str | None = None,
    password: str | None = None,
) -> tuple[bool, str, list[str] | None]:
    """Try to connect to the registry and verify credentials."""
    try:
        # For Docker Hub with credentials, verify via the login endpoint instead
        # of catalog (which is blocked for normal users)
        if auth_method == "username_password" and username and password and _is_docker_hub(registry_url):
            with httpx.Client(timeout=15) as client:
                resp = client.post(
                    "https://hub.docker.com/v2/users/login",
                    json={"username": username, "password": password},
                )
            if resp.status_code == 200:
                return True, f"Connected to Docker Hub as '{username}'. Use the search box to find repositories.", None
            else:
                detail = resp.json().get("detail", resp.text[:100])
                return False, f"Docker Hub login failed: {detail}", None

        repos = list_repositories(registry_url, auth_method, username=username, password=password)
        return True, f"Connected successfully. Found {len(repos)} repositor{'y' if len(repos) == 1 else 'ies'}.", repos
    except httpx.HTTPStatusError as exc:
        return False, f"HTTP {exc.response.status_code}: {exc.response.text[:200]}", None
    except httpx.TimeoutException:
        return False, "Connection timed out.", None
    except Exception as exc:
        return False, str(exc), None


def fetch_full_cache(
    registry_url: str,
    auth_method: str,
    username: str | None = None,
    password: str | None = None,
) -> dict[str, list[str]]:
    """Fetch the full {repo: [tags]} mapping for a registry (used by Celery sync)."""
    repos = list_repositories(registry_url, auth_method, username=username, password=password)
    cache: dict[str, list[str]] = {}
    for repo in repos:
        try:
            cache[repo] = list_tags(registry_url, auth_method, repo, username=username, password=password)
        except Exception as exc:
            logger.warning("Failed to list tags for %s/%s: %s", registry_url, repo, exc)
            cache[repo] = []
    return cache


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_link_next(link_header: str, registry_url: str) -> str | None:
    """Parse a `Link: <url>; rel="next"` header and return the absolute URL."""
    for part in link_header.split(","):
        part = part.strip()
        if 'rel="next"' in part or "rel=next" in part:
            url_part = part.split(";")[0].strip().strip("<>")
            if url_part.startswith("/"):
                return f"https://{registry_url}{url_part}"
            if url_part.startswith("http"):
                return url_part
    return None
