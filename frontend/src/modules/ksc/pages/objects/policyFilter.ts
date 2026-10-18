/** Выбранная в фасете политика: номер уходит в запрос, имя — в чип. */
export interface PickedPolicy {
  id: number
  name: string
}

/** Переключить политику в мультивыборе; пустой выбор — фильтр снят. */
export function togglePolicy(list: PickedPolicy[] | undefined, p: PickedPolicy): PickedPolicy[] | undefined {
  const next = list?.some((x) => x.id === p.id) ? list.filter((x) => x.id !== p.id) : [...(list ?? []), p]
  return next.length ? next : undefined
}
