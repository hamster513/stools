from datetime import datetime, timezone
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, field_validator

PROTOCOL_VERSION = 1


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class Source(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    publisher_id: str = Field(min_length=1, max_length=100)
    adapter: Literal["rss", "kev", "msrc", "cncert", "telegram", "github"] = "rss"
    url: str = Field(max_length=1024)
    language: str = Field(default="en", max_length=16)
    region: str = Field(default="", max_length=40)
    enabled: bool = False
    interval_minutes: int = Field(default=60, ge=15, le=10080)
    llm_allowed: bool = False
    version: int = Field(default=1, ge=1)

    @field_validator("url")
    @classmethod
    def check_url(cls, value: str) -> str:
        parts = urlsplit(value)
        if parts.scheme not in ("https", "http") or not parts.hostname or parts.username or parts.password:
            raise ValueError("public HTTP(S) URL required, without credentials")
        return value


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


class SourceUpdate(Source):
    version: int
