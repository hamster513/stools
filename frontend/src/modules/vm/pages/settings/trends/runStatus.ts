export const runStates: Record<string, string> = { queued: 'В очереди', running: 'Выполняется', succeeded: 'Успешно', partial: 'Частично', failed: 'Ошибка', cancelled: 'Отменён' }
export function runTone(state?: string, error?: unknown) {
  if (error || state === 'failed') return 'text-kind-1'
  if (state === 'succeeded') return 'text-kind-accepted'
  if (state === 'partial') return 'text-kind-3'
  return 'text-text-secondary'
}
