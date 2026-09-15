"""Веса формулы риска и их значения по умолчанию.

Значения — из формулы, документированной в интерфейсе первой итерации
(спека §4): она самосогласована с приведённым там контрольным примером.
Веса первой итерации из базы до расчёта не доезжали (ключи не совпадали),
поэтому именно документированные, а не «фактически работавшие», и есть
то, что аналитики считали правилом.
"""
from __future__ import annotations

from pydantic import BaseModel, Field

#: Ранги Metasploit по шкале фреймворка: число → имя.
MSF_RANKS: dict[int, str] = {
    0: "manual",
    100: "low",
    200: "average",
    300: "normal",
    400: "good",
    500: "great",
    600: "excellent",
}

CRITICALITIES = ("Critical", "High", "Medium", "Low", "None")
EXPLOIT_TYPES = ("remote", "webapps", "local", "hardware", "dos")


class ImpactWeights(BaseModel):
    criticality: dict[str, float] = Field(
        default_factory=lambda: {
            "Critical": 0.33,
            "High": 0.25,
            "Medium": 0.20,
            "Low": 0.10,
            "None": 0.20,
        }
    )
    confidential: dict[str, float] = Field(default_factory=lambda: {"yes": 0.33, "no": 0.20})
    internet: dict[str, float] = Field(default_factory=lambda: {"yes": 0.33, "no": 0.20})


class CvssV3Weights(BaseModel):
    av: dict[str, float] = Field(
        default_factory=lambda: {
            "NETWORK": 1.20,
            "ADJACENT_NETWORK": 1.10,
            "LOCAL": 0.95,
            "PHYSICAL": 0.85,
        }
    )
    pr: dict[str, float] = Field(default_factory=lambda: {"NONE": 1.20, "LOW": 1.00, "HIGH": 0.85})
    ui: dict[str, float] = Field(default_factory=lambda: {"NONE": 1.15, "REQUIRED": 0.90})


class CvssV2Weights(BaseModel):
    av: dict[str, float] = Field(
        default_factory=lambda: {"NETWORK": 1.20, "ADJACENT_NETWORK": 1.10, "LOCAL": 0.95}
    )
    ac: dict[str, float] = Field(default_factory=lambda: {"LOW": 1.10, "MEDIUM": 1.00, "HIGH": 0.90})
    au: dict[str, float] = Field(
        default_factory=lambda: {"NONE": 1.15, "SINGLE": 1.00, "MULTIPLE": 0.90}
    )


class Weights(BaseModel):
    impact: ImpactWeights = Field(default_factory=ImpactWeights)
    cvss_v3: CvssV3Weights = Field(default_factory=CvssV3Weights)
    cvss_v2: CvssV2Weights = Field(default_factory=CvssV2Weights)
    exploitdb: dict[str, float] = Field(
        default_factory=lambda: {
            "remote": 1.30,
            "webapps": 1.20,
            "local": 1.05,
            "hardware": 1.00,
            "dos": 0.85,
        }
    )
    msf: dict[str, float] = Field(
        default_factory=lambda: {
            "excellent": 1.30,
            "great": 1.25,
            "good": 1.25,
            "normal": 1.20,
            "average": 1.10,
            "low": 0.80,
            "manual": 1.00,
            "unknown": 0.80,
        }
    )


DEFAULT_WEIGHTS = Weights()

#: Порог, выше которого пара считается требующей действия.
DEFAULT_THRESHOLD = 70

#: Что подставляется, когда EPSS для CVE нет: середина шкалы, а не ноль —
#: ноль означал бы «точно не эксплуатируют», чего никто не утверждал.
EPSS_FALLBACK = 0.5
