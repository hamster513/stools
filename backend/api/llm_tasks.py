"""Live AI tasks and their data boundaries; independent of provider credentials."""
from typing import Literal, TypedDict

from pydantic import BaseModel, Field, model_validator

Provider = Literal['ollama', 'openrouter', 'deepseek']
DataClass = Literal['public', 'redacted', 'internal']
TaskId = Literal['attack_embeddings', 'attack_markup', 'attack_translation', 'threat_analysis', 'vulnerability_assistant', 'rule_rewrite']

class TaskInfo(TypedDict):
    title: str
    kind: Literal['embedding', 'completion']
    data_class: DataClass
    description: str
    providers: list[Provider]


TASKS: dict[TaskId, TaskInfo] = {
    'rule_rewrite': {
        'title': 'Исправление правил SIEM', 'kind': 'completion', 'data_class': 'internal',
        'description': 'Предлагает полный исправленный код правила, пояснения и сравнение. Полный исходник обрабатывается только локальной Ollama; выберите модель для работы с кодом.',
        'providers': ['ollama'],
    },
    'attack_embeddings': {
        'title': 'Поиск кандидатов ATT&CK', 'kind': 'embedding', 'data_class': 'redacted',
        'description': 'Преобразует техники и очищенные описания правил в векторы. Для локальной обработки подойдёт bge-m3.',
        'providers': ['ollama', 'openrouter'],
    },
    'attack_markup': {
        'title': 'Разметка правил SIEM', 'kind': 'completion', 'data_class': 'redacted',
        'description': 'Выбирает техники ATT&CK из найденных кандидатов. Внешняя модель получает выжимку после очистки и проверки на утечки.',
        'providers': ['ollama', 'openrouter', 'deepseek'],
    },
    'attack_translation': {
        'title': 'Перевод ATT&CK', 'kind': 'completion', 'data_class': 'public',
        'description': 'Переводит названия и описания техник из публичной базы ATT&CK.',
        'providers': ['ollama', 'openrouter', 'deepseek'],
    },
    'vulnerability_assistant': {
        'title': 'Перевод и объяснение CVE и новостей', 'kind': 'completion', 'data_class': 'public',
        'description': 'По запросу аналитика переводит описание CVE или публикацию и объясняет опасность простым языком. Использует разрешённые тексты без сведений о наших хостах и образах.',
        'providers': ['ollama', 'openrouter', 'deepseek'],
    },
    'threat_analysis': {
        'title': 'Анализ публикаций об угрозах', 'kind': 'completion', 'data_class': 'public',
        'description': 'Выделяет продукт, версии и признаки эксплуатации из разрешённых публикаций. Сопоставление с нашими активами выполняется локально.',
        'providers': ['ollama', 'openrouter', 'deepseek'],
    },
}


class TaskAssignment(BaseModel):
    provider: Provider = 'ollama'
    model: str = Field(default='', max_length=256)
    enabled: bool = True
    timeout: int = Field(default=180, ge=5, le=1800)
    think: bool = False
    local_only: bool = False

    @model_validator(mode='after')
    def enforce_local(self) -> "TaskAssignment":
        if self.local_only and self.provider != 'ollama':
            raise ValueError('Для задачи «Только локально» выберите Ollama')
        return self
