from __future__ import annotations

from fastapi import APIRouter, HTTPException
import httpx

router = APIRouter(prefix="/vulns", tags=["vulns"])

_OSV_BASE = "https://api.osv.dev/v1"
_HTTP_TIMEOUT = 15.0


@router.get("/{vuln_id}", summary="Get full vulnerability details from OSV.dev")
async def get_vulnerability(vuln_id: str):
    """Fetch the full vulnerability record from OSV.dev for a given advisory ID.

    Accepts any OSV identifier: ``CVE-*``, ``GHSA-*``, ``PYSEC-*``,
    ``RUSTSEC-*``, etc.  The response is the raw OSV object including the full
    description, affected package version ranges, CVSS vectors, CWE IDs, and
    all references — suitable for powering a CVE "deep dive" view in the UI.
    """
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
        try:
            resp = await client.get(f"{_OSV_BASE}/vulns/{vuln_id}")
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=503, detail=f"Unable to reach OSV.dev: {exc}")

        if resp.status_code == 404:
            raise HTTPException(
                status_code=404,
                detail=f"Vulnerability '{vuln_id}' not found in OSV",
            )
        resp.raise_for_status()
        return resp.json()
