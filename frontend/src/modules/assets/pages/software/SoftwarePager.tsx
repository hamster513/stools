import { Button } from '@/components/ui/Button'
export const PAGE_SIZE = 50
export function SoftwarePager({ label, offset, total, busy, onChange }: { label: string; offset: number; total: number; busy: boolean; onChange: (offset: number) => void }) {
  return <nav aria-label={label} className="flex flex-wrap items-center justify-between gap-2 py-2 text-xs text-text-secondary">
    <span>{total ? `${offset + 1}–${Math.min(offset + PAGE_SIZE, total)} из ${total}` : '0 записей'}</span>
    {total > PAGE_SIZE && <div className="flex gap-2"><Button disabled={busy || offset === 0} onClick={() => onChange(Math.max(0, offset - PAGE_SIZE))}>Назад</Button><Button disabled={busy || offset + PAGE_SIZE >= total} onClick={() => onChange(offset + PAGE_SIZE)}>Далее</Button></div>}
  </nav>
}
