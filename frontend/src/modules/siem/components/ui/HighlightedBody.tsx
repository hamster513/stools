import { useMemo } from 'react'
import { tint } from '@/lib/tint'
import type { FindingKind, FindingStatus, RuleBodySpan } from '@/modules/siem/api/types'
import { FINDING_KIND_LABELS } from '@/modules/siem/api/types'
import { STATUS_TITLES } from '@/platform/findings/types'
import { cn } from '@/lib/cn'

/**
 * Код с подсвеченными находками — тело правила целиком или его фрагмент.
 *
 * Цвет отрезка — цвет класса замечания, тот же, что у значка в списке:
 * человек, увидевший «дублирует список» красным наверху, находит красное
 * в коде без сопоставления легенды.
 *
 * Принятое замечание гасится, а не исчезает: решение принято, но код
 * остался прежним, и это разные вещи.
 */
const KIND_COLOR: Record<number, string> = {
  1: 'var(--color-kind-1)',
  2: 'var(--color-kind-2)',
  3: 'var(--color-kind-3)',
  4: 'var(--color-kind-4)',
  5: 'var(--color-kind-5)',
}

/**
 * Одно подсвеченное значение.
 *
 * Неучитываемое замечание (принят риск, ложное срабатывание — настройка
 * платформы `counted`) показывается иначе не для красоты: приглушённая
 * подсветка сама по себе не читается — человек видит бледное пятно и
 * гадает, замечание это или нет. Поэтому у него зелёная пунктирная
 * черта и галочка: решение видно, а не угадывается.
 */
/**
 * Ссылка на табличный список, который правило читает впустую. Цвета те
 * же, что у состояний списка: отсутствующий — красный, пустой —
 * оранжевый. Волнистая черта отличает её от замечаний: это не значение
 * из находки, а имя списка.
 */
const TONE_COLOR = {
  missing: 'var(--color-kind-1)',
  empty: 'var(--color-risk-high)',
} as const

function TableMark({ tone, note, text }: { tone: keyof typeof TONE_COLOR; note?: string; text: string }) {
  const color = TONE_COLOR[tone]
  return (
    <mark
      className="rounded-[2px] px-0.5"
      style={{
        backgroundColor: tint(color, 14),
        color,
        textDecoration: `underline wavy ${color}`,
        textUnderlineOffset: '3px',
      }}
      title={note}
    >
      {text}
    </mark>
  )
}

function Mark({ span, text }: { span: RuleBodySpan; text: string }) {
  if (span.tone) return <TableMark tone={span.tone} note={span.note} text={text} />
  const accepted = !span.counted
  const color = accepted
    ? 'var(--color-kind-accepted)'
    : (KIND_COLOR[span.kind] ?? 'var(--color-kind-5)')
  const label = FINDING_KIND_LABELS[String(span.kind) as FindingKind]
  return (
    <mark
      className="rounded-[2px] px-0.5"
      style={{
        backgroundColor: tint(color, accepted ? 8 : 18),
        color,
        boxShadow: accepted ? 'none' : `inset 0 -1px 0 ${color}`,
        borderBottom: accepted ? `1px dashed ${color}` : undefined,
      }}
      title={accepted ? `${label} — ${STATUS_TITLES[span.status]}, не учитывается` : label}
    >
      {text}
      {accepted && (
        <span className="ml-0.5 align-baseline text-[10px]" aria-hidden>
          ✓
        </span>
      )}
    </mark>
  )
}

export function HighlightedBody({
  body,
  spans,
  className,
}: {
  body: string
  spans: RuleBodySpan[]
  className?: string
}) {
  const parts = useMemo(() => {
    if (spans.length === 0) return [{ text: body, span: null as RuleBodySpan | null }]
    const out: { text: string; span: RuleBodySpan | null }[] = []
    let cursor = 0
    for (const span of spans) {
      // Отрезки приходят по порядку и без пересечений; на всякий случай
      // пропускаем те, что не укладываются в тело.
      if (span.start < cursor || span.end > body.length) continue
      if (span.start > cursor) out.push({ text: body.slice(cursor, span.start), span: null })
      out.push({ text: body.slice(span.start, span.end), span })
      cursor = span.end
    }
    if (cursor < body.length) out.push({ text: body.slice(cursor), span: null })
    return out
  }, [body, spans])

  return (
    <pre
      className={cn(
        'overflow-x-auto rounded border border-grid bg-app-bg px-2.5 py-2 font-mono text-xs whitespace-pre-wrap text-text',
        className,
      )}
    >
      {parts.map((part, i) =>
        part.span ? (
          <Mark key={i} span={part.span} text={part.text} />
        ) : (
          <span key={i}>{part.text}</span>
        ),
      )}
    </pre>
  )
}


/**
 * Отрезки для одного значения внутри фрагмента.
 *
 * На экране находки значение уже известно клиенту — оно пришло по явному
 * запросу вместе с фрагментом, — поэтому позиции считаются здесь, а не
 * на сервере. Правило поиска то же, что и там: только закавыченные
 * вхождения, иначе подсветится имя поля.
 */
export function spansForValue(
  excerpt: string,
  value: string,
  kind: number,
  status: FindingStatus,
  counted: boolean,
): RuleBodySpan[] {
  if (!excerpt || value.length < 2) return []
  const needle = `"${value}"`
  const out: RuleBodySpan[] = []
  let from = 0
  for (;;) {
    const at = excerpt.indexOf(needle, from)
    if (at < 0) break
    out.push({ start: at + 1, end: at + 1 + value.length, kind, status, counted })
    from = at + 1
  }
  return out
}
