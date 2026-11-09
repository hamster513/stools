from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

from .monitoring_contracts import ClassificationResult, SourceConfigV2

PROTOCOL_VERSION = 1


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


Source = SourceConfigV2


class Publication(BaseModel):
    external_id: str = Field(min_length=1, max_length=1024)
    title: str = Field(max_length=2000)
    url: str = Field(max_length=2048)
    text: str = Field(default="", max_length=262144)
    published_at: str | None = None
    updated_at: str | None = None
    language: str = ""
    identifiers: list[str] = Field(default_factory=list, max_length=500)
    links: list[str] = Field(default_factory=list, max_length=100)
    exploitation_confirmed: bool = False
    evidence_kind: str = "publication"
    full_text: bool = False
    truncated: bool = False
    retracted: bool = False
    date_basis: Literal["published", "inferred", "unknown"] = "unknown"
    source_published_at: str | None = None
    source_updated_at: str | None = None
    content_hash: str = Field(default="", max_length=64)
    classification: ClassificationResult | None = None


class SourceUpdate(Source):
    version: int

PublicationV2 = Publication
