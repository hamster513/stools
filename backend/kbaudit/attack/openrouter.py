"""OpenRouter transport for structured completions and embedding vectors."""
from __future__ import annotations

import json
import math
import time
from functools import lru_cache
import urllib.error
import urllib.request
from typing import Any

from .provider import ModelError, OllamaSettings

BASE_URL = "https://openrouter.ai/api/v1"


def request(path: str, *, key: str = "", body: dict | None = None, timeout: int = 30) -> dict:
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(BASE_URL + path, data=json.dumps(body).encode() if body is not None else None, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            data = json.load(response)
    except urllib.error.HTTPError as exc:
        messages = {401: "API-ключ OpenRouter недействителен", 402: "Недостаточно средств OpenRouter",
                    403: "OpenRouter запретил запрос", 429: "Превышен лимит запросов OpenRouter"}
        raise ModelError(messages.get(exc.code, f"OpenRouter вернул HTTP {exc.code}")) from None
    except (OSError, ValueError) as exc:
        raise ModelError(f"Не удалось получить ответ OpenRouter ({type(exc).__name__})") from None
    if not isinstance(data, dict) or data.get("error"):
        raise ModelError("OpenRouter вернул ошибку вместо результата")
    return data


def models() -> dict[str, list[str]]:
    generation = request("/models")
    embeddings = request("/embeddings/models")
    try:
        names = sorted({m["id"] for m in generation["data"]
                        if "text" in m.get("architecture", {}).get("output_modalities", ["text"])})
        embed_names = sorted({m["id"] for m in embeddings["data"]})
        if not all(isinstance(n, str) for n in names + embed_names):
            raise ValueError()
    except (KeyError, TypeError, ValueError):
        raise ModelError("OpenRouter вернул некорректный каталог моделей") from None
    return {"models": names, "embedding_models": embed_names}


@lru_cache(maxsize=2)
def _model_parameters(bucket: int) -> dict[str, list[str]]:
    """Короткий кэш возможностей, чтобы не загружать каталог для каждого правила."""
    try:
        return {m["id"]: m.get("supported_parameters", []) for m in request("/models")["data"]}
    except (KeyError, TypeError):
        raise ModelError("OpenRouter вернул некорректный каталог моделей") from None


def complete(settings: OllamaSettings, prompt: str, schema: dict[str, Any]) -> str:
    catalog = _model_parameters(int(time.monotonic() // 300))
    if settings.model not in catalog:
        raise ModelError("Выбранная модель отсутствует в каталоге OpenRouter")
    parameters = catalog[settings.model]
    instruction = "Return only valid JSON matching this schema, without Markdown: " + json.dumps(schema, ensure_ascii=False)
    body = {
        "model": settings.model,
        "messages": [{"role": "user", "content": instruction + "\n\n" + prompt}],
        "stream": False,
        "provider": {"require_parameters": True},
    }
    if "structured_outputs" in parameters:
        body["response_format"] = {"type": "json_schema", "json_schema": {"name": "result", "strict": False, "schema": schema}}
    elif "response_format" in parameters:
        body["response_format"] = {"type": "json_object"}
    if "temperature" in parameters:
        body["temperature"] = 0
    if settings.think and "reasoning" in parameters:
        body["reasoning"] = {"enabled": True}
    result = request("/chat/completions", key=settings.api_key.get_secret_value(), timeout=settings.timeout, body=body)
    try:
        content = result["choices"][0]["message"]["content"]
        if not isinstance(content, str) or not content.strip():
            raise ValueError()
    except (KeyError, IndexError, TypeError, ValueError):
        raise ModelError("OpenRouter не вернул текст ответа") from None
    try:
        json.loads(content)
    except ValueError:
        raise ModelError("Модель вернула ответ, который не является JSON") from None
    return content


def embed(settings: OllamaSettings, texts: list[str]) -> list[list[float]]:
    result = request("/embeddings", key=settings.api_key.get_secret_value(), timeout=settings.timeout,
                     body={"model": settings.embed_model, "input": texts, "encoding_format": "float"})
    try:
        rows = sorted(result["data"], key=lambda row: row["index"])
        if [row["index"] for row in rows] != list(range(len(texts))):
            raise ValueError()
        vectors = [[float(x) for x in row["embedding"]] for row in rows]
        if not vectors or not vectors[0] or any(len(v) != len(vectors[0]) or not all(math.isfinite(x) for x in v) for v in vectors):
            raise ValueError()
        return vectors
    except (KeyError, TypeError, ValueError):
        raise ModelError("OpenRouter вернул некорректные эмбеддинги") from None
