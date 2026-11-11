from typing import Literal

from pydantic import BaseModel, Field

from api.modules.toolbox.services.lookup_types import Evidence, Fact, Group


class SearchRequest(BaseModel):
    query: str = Field(min_length=1, max_length=255)
    kind: Literal["auto", "ip", "host", "domain", "cve", "user", "group"] = "auto"
    entity_id: str | None = Field(
        default=None,
        pattern=r"^(?:(host|user|group):[1-9][0-9]{0,18}|kscgroup:[1-9][0-9]{0,18}:[0-9]{1,19})$",
    )


class Entity(BaseModel):
    id: str
    kind: Literal["host", "user", "group"]
    title: str
    domain: str = ""
    href: str
    facts: list[Fact] = Field(default_factory=list)


class Row(Evidence):
    target: Entity | None = None


class Section(BaseModel):
    id: str
    title: str
    note: str = ""
    items: list[Row] = Field(default_factory=list)
    has_more: bool = False


class Dossier(BaseModel):
    entity: Entity
    sections: list[Section]
    notes: list[str] = Field(default_factory=list)


class SearchResult(BaseModel):
    query: str
    matches: list[Entity] = Field(default_factory=list)
    dossier: Dossier | None = None
    groups: list[Group] = Field(default_factory=list)
    has_more: bool = False
    notes: list[str] = Field(default_factory=list)
