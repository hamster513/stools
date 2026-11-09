"""Direct DeepSeek Platform: authenticated model catalogue and JSON completions."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from .provider import ModelError, OllamaSettings

BASE_URL = "https://api.deepseek.com"


def request(path: str, *, key: str, body: dict | None = None, timeout: int = 30) -> dict:
    req = urllib.request.Request(
        BASE_URL + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            data = json.load(response)
    except urllib.error.HTTPError as exc:
        messages = {
            400: "DeepSeek отклонил параметры запроса: проверьте выбранную модель",
            401: "API-ключ DeepSeek недействителен",
            402: "Недостаточно средств на балансе DeepSeek Platform",
            403: "DeepSeek запретил запрос",
            422: "DeepSeek не поддерживает параметры запроса для выбранной модели",
            429: "Превышен лимит запросов DeepSeek. Повторите позже",
            503: "DeepSeek перегружен. Повторите позже",
        }
        raise ModelError(messages.get(exc.code, f"DeepSeek вернул HTTP {exc.code}")) from None
    except (OSError, ValueError) as exc:
        raise ModelError(f"Не удалось получить ответ DeepSeek ({type(exc).__name__})") from None
    if not isinstance(data, dict) or data.get("error"):
        raise ModelError("DeepSeek вернул ошибку вместо результата")
    return data


def models(key: str) -> dict[str, list[str]]:
    result = request("/models", key=key)
    try:
        rows = result["data"]
        if not isinstance(rows, list):
            raise ValueError()
        names = set()
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not row["id"].strip():
                raise ValueError()
            if "text" in row.get("output_modalities", ["text"]):
                names.add(row["id"])
    except (KeyError, TypeError, ValueError):
        raise ModelError("DeepSeek вернул некорректный каталог моделей") from None
    return {"models": sorted(names), "embedding_models": []}


def complete(settings: OllamaSettings, prompt: str, schema: dict[str, Any]) -> str:
    instruction = "Return only valid JSON matching this schema, without Markdown: " + json.dumps(schema, ensure_ascii=False)
    body = {
        "model": settings.model,
        "messages": [{"role": "user", "content": instruction + "\n\n" + prompt}],
        "stream": False,
        "response_format": {"type": "json_object"},
        "thinking": {"type": "enabled" if settings.think else "disabled"},
    }
    if not settings.think:
        body["temperature"] = 0
    result = request("/chat/completions", key=settings.api_key.get_secret_value(), timeout=settings.timeout, body=body)
    try:
        choice = result["choices"][0]
        if not isinstance(choice, dict):
            raise ValueError()
        if choice.get("finish_reason") == "length":
            raise ModelError("DeepSeek обрезал ответ по лимиту длины")
        content = choice["message"]["content"]
        if not isinstance(content, str) or not content.strip():
            raise ValueError()
        json.loads(content)
    except (KeyError, IndexError, TypeError, ValueError):
        raise ModelError("DeepSeek не вернул корректный JSON-ответ") from None
    return content
