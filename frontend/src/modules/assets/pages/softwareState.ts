export type InventoryStatus = 'complete' | 'error' | 'not_collected'

/** A failed or missing collection must never look like a successfully empty inventory. */
export function inventoryEmptyText(statuses: InventoryStatus[], searching: boolean): string {
  if (statuses.length === 0 || statuses.every((status) => status === 'not_collected')) return 'Инвентарь ПО KSC ещё не собран.'
  if (!statuses.includes('complete')) return 'Инвентарь ПО KSC не удалось получить.'
  if (statuses.some((status) => status !== 'complete')) return 'Данные неполные: часть инвентарей KSC недоступна.'
  return searching ? 'По запросу ПО не найдено.' : 'Последний собранный инвентарь KSC не содержит ПО.'
}
