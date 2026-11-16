import { useEffect, useState } from 'react'
import { Link } from '@/lib/router'
import { QUEUE_ACCEPTED } from './client'
import { STATUS } from './types'

export function QueueNotice() {
  const [notice, setNotice] = useState<{ id: number; status: string } | null>(null)
  useEffect(() => {
    const receive = (event: Event) => setNotice((event as CustomEvent).detail)
    window.addEventListener(QUEUE_ACCEPTED, receive)
    return () => window.removeEventListener(QUEUE_ACCEPTED, receive)
  }, [])
  if (!notice) return null
  return <aside role="status" className="fixed bottom-4 right-4 z-50 max-w-[min(24rem,calc(100vw-5rem))] rounded border border-border bg-surface p-4 text-sm shadow-lg">
    <button type="button" aria-label="Закрыть уведомление об очереди" className="float-right ml-4 px-2" onClick={() => setNotice(null)}>×</button>
    <p>Запуск #{notice.id}: {STATUS[notice.status] ?? notice.status}.</p>
    <p className="mt-1 text-text-secondary">Можно перейти к другим задачам или закрыть страницу.</p>
    <Link className="mt-2 inline-block text-primary hover:underline" to="/settings/schedules">Открыть очередь</Link>
  </aside>
}
