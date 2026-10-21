"""Веса формулы риска и их значения по умолчанию (спека 2026-10-21 §9).

Risk = round(100 × L × S × V): вероятность эксплуатации × тяжесть × ценность
хоста. Все три члена — от 0 до 1, поэтому веса здесь — вероятности, доли и
надбавки, а не множители вокруг единицы, как в первой итерации: там EPSS
множителем обнулял почти всё, а подстановки поднимали неизвестное выше
известного (критика — в спеке §9).

Пороги уровней тоже здесь: уровень вычисляется из балла при чтении, поэтому
их можно двигать без пересчёта пар.
"""
from __future__ import annotations

from typing import Self

from pydantic import BaseModel, Field, model_validator

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


class ReachWeights(BaseModel):
    """Достижимость по вектору атаки CVE и доступу хоста из интернета."""

    network_internet: float = Field(default=1.0, ge=0.0, le=1.0)
    network_internal: float = Field(default=0.8, ge=0.0, le=1.0)
    adjacent: float = Field(default=0.6, ge=0.0, le=1.0)
    #: LOCAL и PHYSICAL: нужен доступ к самой машине.
    local: float = Field(default=0.4, ge=0.0, le=1.0)


class ValueWeights(BaseModel):
    """Ценность хоста: база по критичности плюс надбавки зоны, потолок 1.0."""

    criticality: dict[str, float] = Field(
        default_factory=lambda: {
            "Critical": 1.0,
            "High": 0.8,
            "Medium": 0.6,
            "Low": 0.4,
            # Не задана — середина шкалы, а не минимум: «не знаем» не значит «неважный».
            "None": 0.6,
        }
    )
    conf_bonus: float = Field(default=0.1, ge=0.0, le=1.0)
    inet_bonus: float = Field(default=0.1, ge=0.0, le=1.0)


class Levels(BaseModel):
    """Нижние границы уровней по баллу; ниже `medium` — низкий."""

    medium: int = Field(default=15, ge=1, le=100)
    high: int = Field(default=35, ge=1, le=100)
    critical: int = Field(default=60, ge=1, le=100)

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if not 0 < self.medium < self.high < self.critical <= 100:
            raise ValueError("пороги уровней: нужно 0 < средний < высокий < критический ≤ 100")
        return self


class Weights(BaseModel):
    #: EPSS для CVE, которых нет в EPSS: «не измерено» — малая априорная вероятность,
    #: а не середина шкалы (иначе неизвестные CVE оказывались выше 90 % известных).
    prior_epss: float = Field(default=0.01, ge=0.0, le=1.0)
    #: CVSS ÷ 10 для CVE без балла в NVD.
    cvss_missing: float = Field(default=0.5, ge=0.0, le=1.0)
    #: Достижимость, когда у CVE нет вектора атаки.
    reach_unknown: float = Field(default=0.8, ge=0.0, le=1.0)
    #: Вероятность эксплуатации по типу лучшего эксплойта ExploitDB.
    p_exdb: dict[str, float] = Field(
        default_factory=lambda: {
            "remote": 0.30,
            "webapps": 0.25,
            "local": 0.15,
            "hardware": 0.10,
            "dos": 0.05,
        }
    )
    #: Вероятность эксплуатации по лучшему рангу модуля Metasploit.
    p_msf: dict[str, float] = Field(
        default_factory=lambda: {
            "excellent": 0.50,
            "great": 0.45,
            "good": 0.40,
            "normal": 0.30,
            "average": 0.20,
            "low": 0.10,
            "manual": 0.05,
        }
    )
    reach: ReachWeights = Field(default_factory=ReachWeights)
    value: ValueWeights = Field(default_factory=ValueWeights)
    levels: Levels = Field(default_factory=Levels)


DEFAULT_WEIGHTS = Weights()

#: Порог, выше которого пара считается требующей действия.
DEFAULT_THRESHOLD = 70
