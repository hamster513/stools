import type { AdCellCheck } from '@/modules/assets/api/types'
import { Link } from '@/lib/router'

const num = (n: number) => n.toLocaleString('ru-RU')

/** «1 компьютер», «3 компьютера», «12 компьютеров». */
function plural(n: number, forms: [string, string, string]): string {
  const mod10 = n % 10
  const mod100 = n % 100
  const form = mod10 === 1 && mod100 !== 11 ? forms[0] : mod10 >= 2 && mod10 <= 4 && (mod100 < 10 || mod100 >= 20) ? forms[1] : forms[2]
  return `${num(n)} ${form}`
}

function when(iso: string): string {
  return new Date(iso).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' }).replace(', ', ' ')
}

/**
 * Строка-сверка под чипами, когда список открыт из ячейки сводки AD: снапшот, домен и сколько участников ячейки
 * нашлось в «Активах» (без учёта прочих фильтров — число строк списка показывается отдельно). Участники другого
 * вида (компьютеры на странице пользователей и наоборот) — ссылкой на ту же ячейку на соседней странице.
 * Состав разошёлся с числом на странице сводки (сводка без сохранённых настроек) — это говорится явно.
 * Номер снапшота в тексте не показывается — только в адресе ссылки.
 */
export function AdCellNote({ check, snapshot, cell, page }: { check: AdCellCheck; snapshot: number; cell: string; page: 'users' | 'assets' }) {
  const otherHref = `${page === 'users' ? '/assets/list' : '/assets/users'}?${new URLSearchParams({ ad_snapshot: String(snapshot), ad_cell: cell })}`
  const trusts = check.not_managed > 0 ? ` (из них ${num(check.not_managed)} — учётки доверий, в Активы не заводятся)` : ''
  return (
    <div className="basis-full text-xs text-text-secondary">
      Снапшот от {when(check.collected_at)}, домен <span className="font-mono text-text">{check.domain}</span>.{' '}
      {check.in_summary === 0
        ? <>{page === 'users' ? 'Пользователей' : 'Компьютеров'} в этой ячейке нет.</>
        : check.found === check.in_summary
        ? <>В сводке <span className="tabular-nums text-text">{num(check.in_summary)}</span>{trusts}, все найдены.</>
        : <>В сводке <span className="tabular-nums text-text">{num(check.in_summary)}</span>{trusts}, найдено в Активах <span className="tabular-nums text-text">{num(check.found)}</span>.</>}
      {check.other > 0 && (
        <>
          {' '}Ещё {page === 'users' ? plural(check.other, ['компьютер', 'компьютера', 'компьютеров']) : plural(check.other, ['пользователь', 'пользователя', 'пользователей'])} —{' '}
          <Link to={otherHref} className="text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring">{page === 'users' ? 'открыть в Активах' : 'открыть'}</Link>.
        </>
      )}
      {check.summary_n !== null && check.in_summary + check.other !== check.summary_n && (
        <>
          {' '}На странице сводки было <span className="tabular-nums text-text">{num(check.summary_n)}</span>; состав посчитан по текущим настройкам модуля AD — пересчитайте снапшот, чтобы числа совпали.
        </>
      )}
    </div>
  )
}
