import { useMemo, useState } from 'react'
import { AlertTriangle } from 'lucide-react'
import { FIELD } from '@/components/ui/Field'
import { cn } from '@/lib/cn'
import { CopyButton } from '../components/CopyButton'
import { compactValues, CRON_ALIASES, CRON_FIELDS, describeCron, nextRuns, parseCron } from '../lib/cron'
import { relative } from '../lib/unixtime'

const RUNS = 5
const ALLOWED = ['0–59', '0–23', '1–31', '1–12 или JAN–DEC', '0–7 или SUN–SAT; 0 и 7 — воскресенье']

const EXAMPLES = ['*/5 * * * *', '0 * * * *', '30 2 * * *', '0 9-18 * * 1-5', '0 0 1 * *', '0 3 * * 0', '15 4 1,15 * *', '@reboot']

const SYNTAX: [string, string][] = [
  ['*', 'любое значение'],
  [',', 'список значений: 1,15'],
  ['-', 'диапазон: 1-5 — с 1 по 5 включительно'],
  ['/', 'шаг: */15 — каждое 15-е от начала, 0-30/10 — 0, 10, 20, 30'],
  ['JAN–DEC, SUN–SAT', 'имена месяцев и дней недели, регистр не важен'],
]

/** Номер поля под кареткой: пробелы разделяют поля; у специальной строки `@…` полей нет. */
function fieldAt(text: string, caret: number): number | null {
  if (text.trimStart().startsWith('@')) return null
  const tokens = text.slice(0, caret).trimStart().split(/\s+/)
  return Math.min(tokens.length - 1, 4)
}

function when(d: Date): string {
  return d.toLocaleString('ru-RU', { weekday: 'short', day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' })
}

/** Cron: строка crontab по-русски, значения каждого поля и ближайшие запуски. Считается в браузере. */
export function CronPage() {
  const [input, setInput] = useState('5 4 * * *')
  const [caret, setCaret] = useState<number | null>(null)
  const r = useMemo(() => parseCron(input), [input])
  const runs = useMemo(() => (r.ok && r.cron.kind === 'schedule' ? nextRuns(r.cron, new Date(), RUNS) : []), [r])
  const active = caret === null ? null : fieldAt(input, caret)
  const errorField = r.ok ? null : (r.field ?? null)
  const schedule = r.ok && r.cron.kind === 'schedule' ? r.cron : null
  const tokens = schedule ? schedule.expanded.split(' ') : input.trim().split(/\s+/)
  const now = Date.now()

  const track = (e: React.SyntheticEvent<HTMLInputElement>) => setCaret(e.currentTarget.selectionStart)

  return (
    <div className="h-full overflow-y-auto p-6">
      <p className="mb-4 max-w-2xl text-xs text-text-secondary">
        Строка расписания crontab Linux — пять полей через пробел или специальная строка вида <span className="font-mono">@daily</span>. Ниже — что она значит, какие значения берёт каждое поле и когда сработает. Всё считается в браузере.
      </p>

      <div className="max-w-3xl">
        <div className="flex items-center gap-3">
          <input className={cn(FIELD, 'py-2.5 text-center font-mono text-2xl tracking-wider')} value={input} spellCheck={false} autoComplete="off" aria-label="Строка cron"
            onChange={(e) => { setInput(e.target.value); track(e) }} onSelect={track} onKeyUp={track} onClick={track} onBlur={() => setCaret(null)} />
          <CopyButton compact text={input.trim()} label="Скопировать строку" />
        </div>

        {r.ok ? (
          <div className="mt-4 text-center">
            <div className="text-xl text-text">«{describeCron(r.cron)}»</div>
            {schedule?.alias && <div className="mt-1 text-xs text-text-secondary">{schedule.alias} — то же, что <span className="font-mono text-text">{schedule.expanded}</span></div>}
          </div>
        ) : (
          <div role="alert" className="mt-4 flex items-start gap-2 rounded border border-kind-1/40 bg-kind-1/5 px-3 py-2.5 text-sm text-text"><AlertTriangle size={16} className="mt-0.5 shrink-0 text-kind-1" aria-hidden />{r.error}</div>
        )}

        {(schedule || !r.ok) && (
          <div className="mt-5 grid grid-cols-5 gap-2">
            {CRON_FIELDS.map((f, i) => (
              <div key={f.label} className={cn('rounded border px-2 py-2 text-center',
                errorField === i ? 'border-kind-1/60 bg-kind-1/5' : active === i ? 'border-primary bg-row-selected' : 'border-grid bg-surface')}>
                <div className="text-xs font-medium text-text">{f.label}</div>
                <div className="my-1 truncate font-mono text-base text-text" title={tokens[i]}>{tokens[i] ?? '—'}</div>
                <div className="text-[11px] leading-snug text-text-secondary">{ALLOWED[i]}</div>
                {schedule && <div className="mt-1.5 border-t border-grid pt-1.5 text-[11px] leading-snug text-text"><span className="text-text-secondary">значения: </span>{compactValues(schedule, i)}</div>}
              </div>
            ))}
          </div>
        )}

        {schedule && (
          <section className="mt-6">
            <h2 className="mb-2 text-sm font-semibold text-text">Ближайшие запуски</h2>
            {runs.length === 0
              ? <p className="text-sm text-text">Не сработает никогда: такой даты не бывает (например, 30 февраля).</p>
              : (
                <ol className="space-y-1">
                  {runs.map((d) => (
                    <li key={d.getTime()} className="flex gap-4 text-sm">
                      <span className="w-56 font-mono tabular-nums text-text">{when(d)}</span>
                      <span className="text-xs leading-5 text-text-secondary">{relative(d.getTime(), now)}</span>
                    </li>
                  ))}
                </ol>
              )}
            <p className="mt-2 text-xs text-text-secondary">По часовому поясу браузера. Cron на сервере считает время в поясе сервера — проверьте, совпадают ли они.</p>
          </section>
        )}

        <section className="mt-6">
          <h2 className="mb-2 text-sm font-semibold text-text">Примеры</h2>
          <div className="grid gap-1 sm:grid-cols-2">
            {EXAMPLES.map((ex) => {
              const p = parseCron(ex)
              return (
                <button key={ex} type="button" onClick={() => setInput(ex)}
                  className="flex items-baseline gap-3 rounded px-2 py-1 text-left hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring">
                  <span className="w-32 shrink-0 font-mono text-sm text-text">{ex}</span>
                  <span className="text-xs text-text-secondary">{p.ok ? describeCron(p.cron) : ''}</span>
                </button>
              )
            })}
          </div>
        </section>

        <section className="mt-6">
          <h2 className="mb-2 text-sm font-semibold text-text">Синтаксис</h2>
          <table className="w-full text-sm">
            <tbody>
              {SYNTAX.map(([sym, text]) => (
                <tr key={sym} className="border-b border-grid">
                  <th scope="row" className="w-44 py-1.5 pr-4 text-right align-top font-mono font-normal text-text">{sym}</th>
                  <td className="py-1.5 text-text-secondary">{text}</td>
                </tr>
              ))}
              {Object.entries(CRON_ALIASES).map(([alias, expanded]) => (
                <tr key={alias} className="border-b border-grid">
                  <th scope="row" className="w-44 py-1.5 pr-4 text-right align-top font-mono font-normal text-text">{alias}</th>
                  <td className="py-1.5 text-text-secondary">= <span className="font-mono">{expanded}</span> (нестандартное, но есть в cronie и Vixie cron)</td>
                </tr>
              ))}
              <tr className="border-b border-grid">
                <th scope="row" className="w-44 py-1.5 pr-4 text-right align-top font-mono font-normal text-text">@reboot</th>
                <td className="py-1.5 text-text-secondary">один раз при загрузке системы (нестандартное)</td>
              </tr>
            </tbody>
          </table>
          <p className="mt-2 text-xs text-text-secondary">
            Если заданы и день месяца, и день недели и ни одно из полей не начинается со «*», задание срабатывает в любой из этих дней: <span className="font-mono">0 0 13 * 5</span> — 13-го числа <em>или</em> в пятницу. Секунды, а также «L», «W», «#» и «?» из Quartz в crontab Linux не поддерживаются.
          </p>
        </section>
      </div>
    </div>
  )
}
