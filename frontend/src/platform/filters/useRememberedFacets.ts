import { useRef } from 'react'

/** Значение фасета: `label` — подпись, если она не равна значению; `count` — сколько строк под ним сейчас. */
export interface FacetValue {
  value: string
  label?: string
  count: number
}

/**
 * Фасет помнит значения, которые уже показывал. Счётчики сервер считает по
 * отфильтрованному набору: стоит выбрать «высокий», и «критичный» уходит из
 * ответа — а с ним и возможность выбрать второе значение. Поэтому панель
 * держит объединение всех значений, виденных за жизнь страницы: текущее число
 * или 0. Порядок — как в последнем ответе, затем ушедшие в ноль (в порядке,
 * в котором их увидели впервые). Пока ответа нет (`undefined` — идёт запрос),
 * отдаётся прошлый результат, чтобы счётчики не мигали нулями.
 *
 *   ответ 1: { zone: [a:5, b:3] }   → { zone: [a:5, b:3] }
 *   ответ 2: { zone: [a:5] }        → { zone: [a:5, b:0] }
 *   ответ 3: { zone: [c:1, a:2] }   → { zone: [c:1, a:2, b:0] }
 *   undefined                       → прошлый результат
 *
 * Пока ни одного ответа не было, ключей фасетов в результате нет — страница
 * читает их как `facets.zone ?? []`.
 */
export function useRememberedFacets<F extends Record<string, FacetValue[]>>(facets: F | undefined): F {
  const seen = useRef(new Map<string, Map<string, string | undefined>>())
  const last = useRef<F>({} as F)
  if (!facets) return last.current
  const out: Record<string, FacetValue[]> = {}
  for (const [key, values] of Object.entries(facets)) {
    let known = seen.current.get(key)
    if (!known) seen.current.set(key, (known = new Map()))
    for (const v of values) known.set(v.value, v.label ?? known.get(v.value))
    const present = new Set(values.map((v) => v.value))
    const gone = [...known].filter(([value]) => !present.has(value)).map(([value, label]) => ({ value, label, count: 0 }))
    out[key] = [...values, ...gone]
  }
  // Фасет, которого в этом ответе нет вовсе, — тоже в ноль, а не пропадает.
  for (const [key, known] of seen.current) {
    if (!(key in out)) out[key] = [...known].map(([value, label]) => ({ value, label, count: 0 }))
  }
  last.current = out as F
  return last.current
}

/** Счётчики фасета `{значение: число}` → список для useRememberedFacets: по убыванию числа или (`sorted=false`) как прислал сервер. */
export function facetValues(counts: Partial<Record<string, number>> | undefined, sorted = true): FacetValue[] {
  const entries = Object.entries(counts ?? {}).map(([value, count]) => ({ value, count: count ?? 0 }))
  return sorted ? entries.sort((a, b) => b.count - a.count) : entries
}
