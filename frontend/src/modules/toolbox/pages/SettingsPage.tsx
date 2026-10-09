import { useRef, useState } from 'react'
import { AlertTriangle, Check, Lock, Plus, X } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FIELD } from '@/components/ui/Field'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { Section } from '@/platform/collector/ui'
import { useSaveToolboxSettings, useToolboxSettings } from '../api/queries'
import type { ToolboxSettings } from '../api/types'

/** Строка списка с собственным ключом: по индексу поля путались бы при удалении строки из середины. */
interface Row { k: number; a: string; b: string }

const RETENTION_MAX = 3650

/** Настройки: слова, подсети, срок хранения файлов. Только администратору — остальным пояснение. */
export function SettingsPage() {
  const { admin } = useCan()
  const settings = useToolboxSettings(admin)
  if (!admin) {
    return <div className="p-6"><EmptyState icon={Lock} title="Только для администратора" description="Слова, подсети и срок хранения файлов меняет администратор." /></div>
  }
  if (settings.isLoading) return <FullPageSpinner />
  if (settings.isError || !settings.data) return <div className="p-6"><ErrorState message={settings.error?.message ?? 'Не удалось загрузить настройки'} onRetry={() => settings.refetch()} /></div>
  // Форма берёт данные один раз: фоновое обновление запроса не должно затирать правки.
  return <SettingsForm initial={settings.data} />
}

function SettingsForm({ initial }: { initial: ToolboxSettings }) {
  const save = useSaveToolboxSettings()
  const seq = useRef(0)
  const mk = (a = '', b = ''): Row => ({ k: seq.current++, a, b })
  const fromWords = (s: ToolboxSettings) => s.words.map((w) => mk(w.word, w.alias))
  const fromSubnets = (s: ToolboxSettings) => s.subnets.map((n) => mk(n.cidr, n.to))
  const [words, setWords] = useState<Row[]>(() => fromWords(initial))
  const [subnets, setSubnets] = useState<Row[]>(() => fromSubnets(initial))
  const [days, setDays] = useState(String(initial.retention_days))
  const [saved, setSaved] = useState(false)

  const daysNum = Number(days)
  const daysOk = days.trim() !== '' && Number.isInteger(daysNum) && daysNum >= 0 && daysNum <= RETENTION_MAX

  // Псевдоним без слова сервер отвергает английским текстом без номера строки — ловим здесь.
  const noWord = words.flatMap((r, i) => (r.a.trim() === '' && r.b.trim() !== '' ? [i] : []))

  function edit(set: typeof setWords, k: number, field: 'a' | 'b', value: string) {
    setSaved(false)
    set((rows) => rows.map((r) => (r.k === k ? { ...r, [field]: value } : r)))
  }
  function remove(set: typeof setWords, k: number) {
    setSaved(false)
    set((rows) => rows.filter((r) => r.k !== k))
  }
  function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!daysOk || noWord.length > 0 || save.isPending) return
    // Совсем пустые строки (добавили и не заполнили) отбрасываются; остальное проверяет сервер.
    const used = (r: Row) => r.a.trim() !== '' || r.b.trim() !== ''
    setSaved(false)
    save.mutate(
      {
        words: words.filter(used).map((r) => ({ word: r.a.trim(), alias: r.b.trim() })),
        subnets: subnets.filter(used).map((r) => ({ cidr: r.a.trim(), to: r.b.trim() })),
        retention_days: daysNum,
      },
      {
        // Форма показывает то, что сервер сохранил (он мог нормализовать значения), а не то, что отправили.
        onSuccess: (r) => {
          setWords(fromWords(r))
          setSubnets(fromSubnets(r))
          setDays(String(r.retention_days))
          setSaved(true)
        },
      },
    )
  }

  return (
    <form onSubmit={submit} className="h-full overflow-y-auto p-6">
      <h1 className="mb-4 text-base font-semibold text-text">Настройки</h1>
      <div className="max-w-3xl space-y-4">
        <Section title="Слова" about="Свои слова: названия проектов, площадок, систем. Слово ищется как часть слова, без учёта регистра — короткое слово заменится и внутри других слов. Псевдоним можно не задавать — тогда он будет вида word-NNNN.">
          <PairList rows={words} left="слово" right="word-NNNN" label="Слово" rightLabel="Псевдоним" onEdit={(k, f, v) => edit(setWords, k, f, v)} onRemove={(k) => remove(setWords, k)} onAdd={() => { setSaved(false); setWords((r) => [...r, mk()]) }} addLabel="Добавить слово" invalid={noWord} />
          {noWord.map((i) => <p key={i} role="alert" className="mt-2 text-xs text-kind-1">Слово не задано в строке {i + 1}</p>)}
        </Section>

        <Section title="Подсети" about="Дополнительные подсети к сетям модуля «Активы»: адреса первой подсети заменяются адресами второй, которую вы задаёте явно. Длины префиксов в паре должны совпадать.">
          <PairList rows={subnets} left="10.20.0.0/16" right="172.30.0.0/16" label="Подсеть" rightLabel="Заменить на" onEdit={(k, f, v) => edit(setSubnets, k, f, v)} onRemove={(k) => remove(setSubnets, k)} onAdd={() => { setSaved(false); setSubnets((r) => [...r, mk()]) }} addLabel="Добавить подсеть" mono />
        </Section>

        <Section title="Хранение файлов" about="Файлы задания (исходный, результат, отчёт) удаляются при ежесуточной очистке: через указанное число дней после завершения задания; 0 — при ближайшей очистке. Строка задания, находки и таблица соответствий остаются.">
          <label className="block max-w-[200px]">
            <span className="mb-1 block text-xs font-medium text-text">Срок хранения, дней</span>
            <input type="number" min={0} max={RETENTION_MAX} step={1} className={cn(FIELD, 'font-mono', !daysOk && 'border-kind-1')} value={days} onChange={(e) => { setDays(e.target.value); setSaved(false) }} aria-invalid={!daysOk} />
            <span className={cn('mt-1 block text-xs', daysOk ? 'text-text-secondary' : 'text-kind-1')}>{daysOk ? '0 — при ближайшей очистке' : `Целое число от 0 до ${RETENTION_MAX}`}</span>
          </label>
        </Section>

        {save.error && <div role="alert" className="flex items-start gap-2 rounded border border-kind-1/40 bg-kind-1/5 px-3 py-2.5 text-sm text-text"><AlertTriangle size={16} className="mt-0.5 shrink-0 text-kind-1" aria-hidden />{save.error.message}</div>}

        <div className="flex items-center gap-3">
          <Button type="submit" variant="primary" disabled={!daysOk || noWord.length > 0} loading={save.isPending}>Сохранить</Button>
          {saved && <span className="flex items-center gap-1 text-xs text-kind-accepted" role="status"><Check size={13} aria-hidden />Сохранено</span>}
        </div>
      </div>
    </form>
  )
}

function PairList({ rows, left, right, label, rightLabel, onEdit, onRemove, onAdd, addLabel, mono, invalid = [] }: {
  rows: Row[]
  left: string
  right: string
  label: string
  rightLabel: string
  onEdit: (k: number, field: 'a' | 'b', value: string) => void
  onRemove: (k: number) => void
  onAdd: () => void
  addLabel: string
  mono?: boolean
  /** Номера строк (с нуля), у которых левое поле не заполнено. */
  invalid?: number[]
}) {
  const field = cn(FIELD, 'py-1 text-xs', mono && 'font-mono')
  return (
    <div className="space-y-2">
      {rows.length === 0 && <p className="text-xs text-text-secondary">Список пуст.</p>}
      {rows.map((r, i) => (
        <div key={r.k} className="flex items-center gap-2">
          <input className={cn(field, invalid.includes(i) && 'border-kind-1')} aria-invalid={invalid.includes(i)} value={r.a} onChange={(e) => onEdit(r.k, 'a', e.target.value)} placeholder={left} aria-label={`${label} ${i + 1}`} spellCheck={false} />
          <span className="text-text-secondary" aria-hidden>→</span>
          <input className={field} value={r.b} onChange={(e) => onEdit(r.k, 'b', e.target.value)} placeholder={right} aria-label={`${rightLabel} ${i + 1}`} spellCheck={false} />
          <button type="button" onClick={() => onRemove(r.k)} aria-label={`Убрать строку ${i + 1}`} title="Убрать" className="rounded p-1 text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"><X size={14} aria-hidden /></button>
        </div>
      ))}
      <Button type="button" onClick={onAdd}><Plus size={14} aria-hidden />{addLabel}</Button>
    </div>
  )
}
