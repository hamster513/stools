/**
 * Черновик ханта в карточке: то, что человек правит, до сохранения. Выключатели ханта и его запросов
 * принадлежат серверу (у них свои ручки) — в черновике они нужны только несохранённому ханту и новым запросам.
 * Правка (PUT) сервером принимается целиком и ставит `enabled` из тела, поэтому в тело всегда кладём текущие значения.
 */
import type { HuntIn, HuntView, QueryIn } from './api/types'

export interface QueryDraft {
  /** Ключ строки в списке: у сохранённого запроса `pk-<id>`, у нового `new-<n>`. */
  key: string
  /** Номер запроса в базе (`QueryView.id`); у ещё не сохранённого — null. */
  pk: number | null
  query_id: string
  query: string
  fields: string
  fields_label: string
  /** Пустая строка — предел по умолчанию из настроек. */
  limit: string
  enabled: boolean
}

export interface HuntDraft {
  code: string
  name: string
  description: string
  technique_id: string
  enabled: boolean
  queries: QueryDraft[]
}

let counter = 0

export function emptyQuery(taken: QueryDraft[]): QueryDraft {
  const used = new Set(taken.map((q) => q.query_id))
  let n = taken.length + 1
  while (used.has(`Q${n}`)) n += 1
  counter += 1
  return { key: `new-${counter}`, pk: null, query_id: `Q${n}`, query: '', fields: '', fields_label: '', limit: '', enabled: true }
}

/** Новый хант включён, как и по умолчанию на сервере: гипотеза идёт в ближайшую ночь; снять галочку можно до создания. */
export function emptyHunt(): HuntDraft {
  return { code: '', name: '', description: '', technique_id: '', enabled: true, queries: [emptyQuery([])] }
}

export function fromHunt(h: HuntView): HuntDraft {
  return {
    code: h.code,
    name: h.name,
    description: h.description,
    technique_id: h.technique_id ?? '',
    enabled: h.enabled,
    queries: h.queries.map((q) => ({
      key: `pk-${q.id}`,
      pk: q.id,
      query_id: q.query_id,
      query: q.query,
      fields: q.fields,
      fields_label: q.fields_label,
      limit: q.limit === null ? '' : String(q.limit),
      enabled: q.enabled,
    })),
  }
}

/** Тело для POST и PUT: выключатели сохранённого берём у сервера (`server`), а не из черновика, который их не ведёт. */
export function toHuntIn(draft: HuntDraft, server: HuntView | undefined): HuntIn {
  const queries: QueryIn[] = draft.queries.map((q) => {
    const stored = q.pk === null ? undefined : server?.queries.find((s) => s.id === q.pk)
    const limit = q.limit.trim()
    return {
      query_id: q.query_id.trim(),
      query: q.query,
      fields: q.fields,
      fields_label: q.fields_label,
      limit: limit === '' ? null : Number(limit),
      enabled: stored ? stored.enabled : q.enabled,
    }
  })
  return {
    code: draft.code.trim(),
    name: draft.name.trim(),
    description: draft.description,
    technique_id: draft.technique_id.trim().toUpperCase() || null,
    enabled: server ? server.enabled : draft.enabled,
    queries,
  }
}

/** Отпечаток правимого: выключатели сохранённых хантов и запросов в него не входят — их меняют отдельные ручки. */
export function draftSignature(d: HuntDraft, saved: boolean): string {
  return JSON.stringify([
    d.code, d.name, d.description, d.technique_id, saved ? null : d.enabled,
    d.queries.map((q) => [q.pk, q.query_id, q.query, q.fields, q.fields_label, q.limit, q.pk === null ? q.enabled : null]),
  ])
}
