import { useEffect, useState } from 'react'
import { AlertTriangle } from 'lucide-react'
import { FIELD } from '@/components/ui/Field'
import { cn } from '@/lib/cn'
import { CopyButton } from '../components/CopyButton'
import { formatLocal, formatUtc, fromDateInput, localZone, parseTimestamp, relative, UNIT_LABELS, weekday } from '../lib/unixtime'

const SEG = 'rounded px-3 py-1.5 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'

/** Текущее время, обновляется раз в секунду. */
function useNow(): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(id)
  }, [])
  return now
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <tr className="border-b border-grid">
      <th scope="row" className="w-48 py-2 pr-4 text-left align-top text-xs font-medium text-text-secondary">{label}</th>
      <td className="py-2 align-top text-sm">{children}</td>
    </tr>
  )
}

/** Значение для поля datetime-local по местному времени: «2025-10-29T13:40:00». */
function localInputValue(ms: number): string {
  const d = new Date(ms)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

/** Unix time: текущая метка, метка → дата (единица угадывается по числу цифр), дата → метка. Считается в браузере. */
export function UnixTimePage() {
  const now = useNow()
  const [stamp, setStamp] = useState(() => String(Math.floor(Date.now() / 1000)))
  const [date, setDate] = useState(() => localInputValue(Date.now()))
  const [utc, setUtc] = useState(false)
  const parsed = stamp.trim() ? parseTimestamp(stamp) : null
  const fromDate = fromDateInput(date, utc)
  const nowSec = String(Math.floor(now / 1000))

  return (
    <div className="h-full overflow-y-auto p-6">
      <p className="mb-4 max-w-2xl text-xs text-text-secondary">
        Unix time — число секунд с 1 января 1970 года 00:00 UTC. В логах встречаются и миллисекунды, и микро-, и наносекунды: единица угадывается по числу цифр. Местное время — по часовому поясу браузера ({localZone(now)}).
      </p>

      <section className="mb-6 flex flex-wrap items-center gap-4 rounded border border-grid bg-surface px-4 py-3">
        <span className="text-xs text-text-secondary">Сейчас</span>
        <span className="font-mono text-xl tabular-nums text-text">{nowSec}</span>
        <span className="font-mono text-xs tabular-nums text-text-secondary">{formatUtc(Math.floor(now / 1000) * 1000)}</span>
        <CopyButton text={nowSec} />
      </section>

      <div className="grid gap-8 xl:grid-cols-2">
        <section>
          <h2 className="mb-2 text-sm font-semibold text-text">Метка → дата</h2>
          <label className="block max-w-md">
            <span className="mb-1 block text-xs font-medium text-text">Unix time</span>
            <input className={cn(FIELD, 'font-mono')} value={stamp} onChange={(e) => setStamp(e.target.value)} spellCheck={false} autoComplete="off" inputMode="numeric" placeholder="1761734400" />
          </label>
          {parsed && !parsed.ok && <div role="alert" className="mt-3 flex max-w-md items-start gap-2 rounded border border-kind-1/40 bg-kind-1/5 px-3 py-2.5 text-sm text-text"><AlertTriangle size={16} className="mt-0.5 shrink-0 text-kind-1" aria-hidden />{parsed.error}</div>}
          {parsed?.ok && (
            <table className="mt-3 w-full">
              <tbody>
                <Row label="Единица">{UNIT_LABELS[parsed.unit]} <span className="text-xs text-text-secondary">— по числу цифр</span></Row>
                <Row label="UTC"><span className="font-mono">{formatUtc(parsed.ms)}</span> <span className="text-xs text-text-secondary">{weekday(parsed.ms, true)}</span></Row>
                <Row label="Местное время"><span className="font-mono">{formatLocal(parsed.ms)}</span> <span className="text-xs text-text-secondary">{weekday(parsed.ms, false)}</span></Row>
                <Row label="ISO 8601"><span className="font-mono">{new Date(parsed.ms).toISOString()}</span></Row>
                <Row label="Относительно">{relative(parsed.ms, now)}</Row>
                <Row label="Секунды / миллисекунды"><span className="font-mono tabular-nums">{Math.floor(parsed.ms / 1000)} / {parsed.ms}</span></Row>
              </tbody>
            </table>
          )}
        </section>

        <section>
          <h2 className="mb-2 text-sm font-semibold text-text">Дата → метка</h2>
          <div className="flex flex-wrap items-end gap-3">
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-text">Дата и время</span>
              <input type="datetime-local" step={1} className={cn(FIELD, 'w-auto font-mono')} value={date} onChange={(e) => setDate(e.target.value)} />
            </label>
            <div role="radiogroup" aria-label="Часовой пояс" className="flex gap-1 rounded border border-border p-0.5">
              {([false, true] as const).map((u) => (
                <button key={String(u)} type="button" role="radio" aria-checked={utc === u} onClick={() => setUtc(u)}
                  className={cn(SEG, utc === u ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text')}>
                  {u ? 'UTC' : 'Местное'}
                </button>
              ))}
            </div>
          </div>
          {fromDate !== null && (
            <table className="mt-3 w-full">
              <tbody>
                <Row label="Секунды"><span className="mr-2 font-mono tabular-nums">{Math.floor(fromDate / 1000)}</span><CopyButton compact text={String(Math.floor(fromDate / 1000))} label="Скопировать секунды" /></Row>
                <Row label="Миллисекунды"><span className="mr-2 font-mono tabular-nums">{fromDate}</span><CopyButton compact text={String(fromDate)} label="Скопировать миллисекунды" /></Row>
                <Row label={utc ? 'Местное время' : 'UTC'}><span className="font-mono">{utc ? formatLocal(fromDate) : formatUtc(fromDate)}</span></Row>
              </tbody>
            </table>
          )}
        </section>
      </div>
    </div>
  )
}
