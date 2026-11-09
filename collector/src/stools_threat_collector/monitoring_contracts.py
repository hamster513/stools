"""Versioned monitoring wire models. Mirrored in STools; verified by contract fixtures."""
from datetime import datetime
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import model_validator, AfterValidator, BaseModel, ConfigDict, Field, field_validator


def http_url(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme not in ('http', 'https') or not parts.hostname or parts.username or parts.password:
        raise ValueError('HTTP(S) URL without credentials required')
    if any(c in value for c in ('\r', '\n', '\x00')):
        raise ValueError('invalid URL')
    return value


HttpUrl = Annotated[str, Field(max_length=2048), AfterValidator(http_url)]
CveId = Annotated[str, Field(pattern=r'^CVE-\d{4}-\d{4,}$', max_length=32)]


class IdentifierRole(BaseModel):
    identifier: str = Field(max_length=120)
    role: Literal['primary', 'actionable', 'mentioned']
    evidence_text: str = Field(default='', max_length=2000)
    evidence_location: str = Field(default='', max_length=100)


class ClassificationResult(BaseModel):
    category: Literal['relevant', 'early_signal', 'background', 'uncertain']
    reasons: list[str] = Field(default_factory=list, max_length=30)
    identifier_roles: list[IdentifierRole] = Field(default_factory=list, max_length=500)
    rule_version: int = Field(default=1, ge=1)


class ProviderStatus(BaseModel):
    status: Literal['ok', 'not_found', 'error', 'rate_limited', 'not_configured']
    fetched_at: datetime
    expires_at: datetime | None = None
    url: HttpUrl | None = None
    error: str = Field(default='', max_length=300)


class CveEnrichment(BaseModel):
    model_config = ConfigDict(extra='forbid')
    cve_id: CveId
    cvss: float | None = Field(default=None, ge=0, le=10)
    cvss_vector: str = Field(default='', max_length=256)
    epss: float | None = Field(default=None, ge=0, le=1)
    epss_percentile: float | None = Field(default=None, ge=0, le=1)
    known_exploited: bool | None = None
    description: str = Field(default='', max_length=16000)
    affected_products: list[str] = Field(default_factory=list, max_length=200)
    cpe_matches: list[dict[str, Any]] = Field(default_factory=list, max_length=2000)
    provenance: dict[str, str] = Field(default_factory=dict)
    providers: dict[str, ProviderStatus] = Field(default_factory=dict)
    references: list[HttpUrl] = Field(default_factory=list, max_length=100)
    fetched_at: datetime
    expires_at: datetime | None = None
    published_at: datetime | None = None


class PocEvidence(BaseModel):
    path: str = Field(max_length=1000)
    url: HttpUrl
    sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    quote: str = Field(default='', max_length=2000)


class PocCandidate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    cve_id: CveId
    repository_id: int = Field(gt=0)
    repository_name: str = Field(default='', max_length=300)
    url: HttpUrl
    commit_sha: str = Field(default='', pattern=r'^([a-f0-9]{40}|[a-f0-9]{64})?$')
    fork_parent: int | None = Field(default=None, gt=0)
    family_id: str = Field(default='', max_length=100)
    state: Literal['candidate', 'likely'] = 'candidate'
    signals: list[str] = Field(default_factory=list, max_length=30)
    evidence: list[PocEvidence] = Field(default_factory=list, max_length=50)
    reason: str = Field(default='', max_length=2000)
    validation_version: int = Field(default=1, ge=1)
    checked_at: datetime | None = None
    incomplete: bool = False
    error: str = Field(default='', max_length=300)


class CollectionWindow(BaseModel):
    date_from: datetime | None = None
    date_to: datetime | None = None
    force: bool = False


    @model_validator(mode="after")
    def validate_window(self):
        if any(v and v.tzinfo is None for v in (self.date_from, self.date_to)):
            raise ValueError("window timestamps must include timezone")
        if self.date_from and self.date_to and self.date_from >= self.date_to:
            raise ValueError("window start must precede end")
        return self


class CollectionBatch(BaseModel):
    documents: list[dict[str, Any]] = Field(default_factory=list)
    checkpoint: dict[str, Any] = Field(default_factory=dict)
    continuation: dict[str, Any] | None = None
    counters: dict[str, int] = Field(default_factory=dict)
    coverage: dict[str, Any] = Field(default_factory=dict)


class SourceRun(BaseModel):
    id: str
    source_id: str
    state: Literal['queued', 'running', 'succeeded', 'partial', 'failed', 'cancelled']
    created_at: str
    finished_at: str | None = None
    error: str | None = None
    stage: str = 'queued'
    counters: dict[str, int] = Field(default_factory=dict)
    coverage: dict[str, Any] = Field(default_factory=dict)
    continuation: dict[str, Any] | None = None
    next_attempt: str | None = None


class SourceConfigV2(BaseModel):
    @model_validator(mode='before')
    @classmethod
    def normalize_telegram(cls, values):
        if isinstance(values, dict) and values.get('adapter') == 'telegram':
            import re
            value = values.get('url') or values.get('telegram_channel', '')
            if value.startswith(('http://','https://')):
                parts = urlsplit(value)
                if parts.hostname != 't.me' or parts.query or parts.fragment:
                    raise ValueError('public Telegram channel required')
                value = parts.path.removeprefix('/s/').strip('/')
            value = value.lstrip('@')
            if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{3,31}',value):
                raise ValueError('public Telegram channel required')
            values = {**values,'url':'https://t.me/'+value.lower(),'telegram_channel':value.lower()}
        return values

    @model_validator(mode='after')
    def retired_must_be_disabled(self):
        if self.retired and self.enabled:
            raise ValueError('retired source cannot be enabled')
        return self

    name: str = Field(min_length=1, max_length=200)
    publisher_id: str = Field(min_length=1, max_length=100)
    adapter: Literal["rss", "kev", "msrc", "cncert", "telegram", "github", "nvd", "html", "nvidia"] = "rss"
    url: str = Field(max_length=1024)
    language: str = Field(default="en", max_length=16)
    region: str = Field(default="", max_length=40)
    enabled: bool = False
    interval_minutes: int = Field(default=60, ge=15, le=10080)
    llm_allowed: bool = False
    version: int = Field(default=1, ge=1)

    catalog_key: str = Field(default="", max_length=100)
    content_scope: Literal["security_news", "vendor_advisory", "vulnerability_database", "general_it", "poc_repository"] = "security_news"
    fallback_urls: list[HttpUrl] = Field(default_factory=list, max_length=10)
    importance: int = Field(default=3, ge=1, le=5)
    retired: bool = False
    replacement_key: str = Field(default="", max_length=100)
    proxy_profile: str = Field(default="inherit", max_length=100)
    telegram_mode: Literal["web", "mtproto"] = "web"
    telegram_channel: str = Field(default="", max_length=64)
    user_agent: str = Field(default="", max_length=256, pattern=r"^[^\r\n]*$")

    @field_validator("url")
    @classmethod
    def check_url(cls, value: str) -> str:
        parts = urlsplit(value)
        if parts.scheme not in ("https", "http") or not parts.hostname or parts.username or parts.password:
            raise ValueError("public HTTP(S) URL required, without credentials")
        return value
