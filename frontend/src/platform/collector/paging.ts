/** Следующая страница бесконечного списка: смещение, пока загружено меньше total. */
export function nextPageOffset(last: { total: number }, pages: { items: unknown[] }[]): number | undefined {
  const loaded = pages.reduce((sum, p) => sum + p.items.length, 0)
  return loaded < last.total ? loaded : undefined
}
