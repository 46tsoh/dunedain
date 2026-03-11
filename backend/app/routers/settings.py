from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AppSetting
from ..repositories import SettingRepository
from ..schemas import SettingRead, SettingUpdate

router = APIRouter(prefix="/settings", tags=["settings"])

# Keys that are valid to get/set, with their defaults and descriptions.
_KNOWN_SETTINGS: dict[str, tuple[str, str]] = {
    "scanner_backend": (
        "auto",
        "Preferred scanner engine. One of: auto, trivy, grype, syft_grype, osv_scanner. "
        "'auto' tries Trivy first, then Grype, then OSV-only.",
    ),
    "comparison_backend": (
        "none",
        "Side-by-side comparison engine. When set, every container scan also "
        "enqueues a second scan using this engine. One of: none, auto, trivy, grype, syft_grype, osv_scanner.",
    ),
    "windows_scanner_mode": (
        "pe_version",
        "Windows container scanning approach. "
        "'pe_version' infers the OS build from PE DLL productVersion fields (fast, no full layer download). "
        "'layer_extraction' downloads all image layers, extracts the filesystem, and parses the Windows "
        "SOFTWARE registry hive for ground-truth OS build + cumulative update revision. More accurate but "
        "slower and requires regipy.",
    ),
    "windows_scanner_backend": (
        "grype",
        "CVE-matching engine used for Windows container scans. "
        "'grype' feeds a Syft SBOM into Grype (default). "
        "'trivy' runs Trivy with --platform windows/amd64 (pe_version) or trivy fs (layer_extraction).",
    ),
}


@router.get("", response_model=list[SettingRead])
def list_settings(db: Session = Depends(get_db)):
    repo = SettingRepository(db)
    repo.ensure_defaults(_KNOWN_SETTINGS)
    return repo.list()


@router.get("/{key}", response_model=SettingRead)
def get_setting(key: str, db: Session = Depends(get_db)):
    repo = SettingRepository(db)
    repo.ensure_defaults(_KNOWN_SETTINGS)
    return repo.get_or_404(key, detail=f"Setting '{key}' not found")


@router.put("/{key}", response_model=SettingRead)
def update_setting(key: str, body: SettingUpdate, db: Session = Depends(get_db)):
    if key not in _KNOWN_SETTINGS:
        raise HTTPException(status_code=400, detail=f"Unknown setting '{key}'")

    repo = SettingRepository(db)
    repo.ensure_defaults(_KNOWN_SETTINGS)
    return repo.set_value(key, body.value)
