import type { Entity, Row } from './api.ts'
const normalize = (value: string) => value.toLocaleLowerCase('ru-RU').replaceAll('ё', 'е').trim()
export function matchesEntity(entity: Entity, query: string): boolean {
  return normalize([entity.title, entity.id, entity.domain, ...entity.facts.flatMap(f => [f.label, f.value])].join(' ')).includes(normalize(query))
}
export function matchesRow(row: Row, query: string): boolean {
  return normalize([row.title, row.reason, row.source, ...row.facts.flatMap(f => [f.label, f.value])].join(' ')).includes(normalize(query)) || !!row.target && matchesEntity(row.target, query)
}
