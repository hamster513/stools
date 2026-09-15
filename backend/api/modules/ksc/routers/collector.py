"""Раздача PowerShell-сборщика."""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse

from api.db.models import AppUser
from api.deps import get_current_user

router = APIRouter(tags=["ksc"])

SCRIPT = Path(__file__).resolve().parent.parent / "collector" / "STools-KSC-Collector.ps1"


@router.get("/collector.ps1")
def download_collector(_user: AppUser = Depends(get_current_user)) -> FileResponse:
    return FileResponse(
        SCRIPT,
        media_type="text/plain; charset=utf-8",
        filename="STools-KSC-Collector.ps1",
        headers={"Cache-Control": "no-cache"},
    )
