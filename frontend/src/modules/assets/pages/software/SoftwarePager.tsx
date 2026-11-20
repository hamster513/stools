import { Button } from '@/components/ui/Button'

export const PAGE_SIZE = 50

interface PagerProps {
  label: string
  offset: number
  total: number
  busy: boolean
  onChange: (offset: number) => void
  pageSize?: number
}

export function SoftwarePager({ label, offset, total, busy, onChange, pageSize = PAGE_SIZE }: PagerProps) {
  const lastPage = Math.max(0, Math.floor((total - 1) / pageSize) * pageSize)
  const previous = Math.min(lastPage, Math.max(0, offset - pageSize))
  return <nav aria-label={label} className="flex flex-wrap items-center justify-between gap-2 py-2 text-xs text-text-secondary">
    <span>{offset < total ? `${offset + 1}–${Math.min(offset + pageSize, total)} из ${total}` : `Всего записей: ${total}`}</span>
    {(total > pageSize || offset > 0) && <div className="flex gap-2">
      <Button disabled={busy || offset === 0} onClick={() => onChange(previous)}>Назад</Button>
      <Button disabled={busy || offset >= lastPage} onClick={() => onChange(offset + pageSize)}>Далее</Button>
    </div>}
  </nav>
}
