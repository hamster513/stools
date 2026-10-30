/**
 * Тонкая обёртка над fetch. Все запросы идут с cookie сессии и разбирают
 * ошибку контракта {"detail": "текст"} в понятное исключение.
 */

export class ApiRequestError extends Error {
  status: number

  constructor(status: number, detail: string) {
    super(detail)
    this.status = status
  }
}

/** Текст ошибки запроса для подписи у кнопки: ответ API как есть, иначе запасной; без ошибки — null. */
export function errorText(error: unknown, fallback: string): string | null {
  return error instanceof ApiRequestError ? error.message : error ? fallback : null
}

/**
 * Ошибка проверки схемы (422) приходит списком `[{loc, msg, …}]`, а не строкой:
 * показываем тексты `msg`. Наши валидаторы пишут их по-русски, pydantic
 * предваряет такой текст «Value error, » — префикс убирается. Объект вместо
 * строки — его `msg` или `detail`, иначе JSON, но не «[object Object]».
 */
export function formatDetail(detail: unknown): string {
  if (Array.isArray(detail)) return detail.map(formatDetail).join('; ')
  if (!detail || typeof detail !== 'object') return String(detail)
  if ('msg' in detail) return String(detail.msg).replace(/^Value error, /, '')
  if ('detail' in detail) return String(detail.detail)
  return JSON.stringify(detail)
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    credentials: 'include',
    headers: {
      ...(init?.body && !(init.body instanceof FormData)
        ? { 'Content-Type': 'application/json' }
        : {}),
      ...init?.headers,
    },
  })

  if (res.status === 204) {
    return undefined as T
  }

  const isJson = res.headers.get('content-type')?.includes('application/json')
  const payload = isJson ? await res.json() : undefined

  if (!res.ok) {
    const detail =
      payload && typeof payload === 'object' && 'detail' in payload
        ? formatDetail((payload as { detail: unknown }).detail)
        : `Запрос завершился ошибкой ${res.status}`
    // Отказ по правам объясняем словами: «нужна роль: аналитик» само по
    // себе не говорит, что действие отклонено, а не пошло не так.
    throw new ApiRequestError(
      res.status,
      res.status === 403 ? `недостаточно прав: ${detail}` : detail,
    )
  }

  return payload as T
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) }),
  postForm: <T>(path: string, form: FormData) => request<T>(path, { method: 'POST', body: form }),
  put: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: 'PUT', body: body === undefined ? undefined : JSON.stringify(body) }),
  patch: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: 'PATCH', body: body === undefined ? undefined : JSON.stringify(body) }),
  del: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
}

/**
 * Значение параметра запроса. Список уходит повторением ключа (`os=Windows%2010&os=Debian`), а не через запятую:
 * свободные значения (ОС, группа, зона) сами содержат запятые и рвались бы на части.
 */
export type QueryValue = string | number | boolean | string[] | number[] | undefined

export function buildQuery(params: Record<string, QueryValue>): string {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === '') continue
    // Пустой список — фильтр не задан, а не «ничего не подходит»; пустая строка внутри списка — законное значение.
    if (Array.isArray(value)) {
      for (const v of value) search.append(key, String(v))
      continue
    }
    search.set(key, String(value))
  }
  const qs = search.toString()
  return qs ? `?${qs}` : ''
}
