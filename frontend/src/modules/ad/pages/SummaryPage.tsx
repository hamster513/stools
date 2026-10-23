import { useState, type ReactNode } from 'react'
import { ArrowRight, RefreshCw, ServerCog } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useDcLinks, useOverview, useSummary } from '@/modules/ad/api/queries'
import type { DcLink, Summary, SummaryBucket, SummaryClusters, SummaryCounts } from '@/modules/ad/api/types'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { Link } from '@/lib/router'
import { cn } from '@/lib/cn'
import { Section } from '@/platform/collector/ui'
import { ColGroup, ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'

const ACTION_LINK = 'inline-flex items-center gap-1.5 rounded bg-primary px-3 py-1.5 text-xs font-medium text-primary-text hover:bg-primary/90'
const GPO_PAGE = 50

const ACCOUNT_COLUMNS: ColumnDef<'label' | 'users' | 'computers'>[] = [
  { key: 'label', label: 'Показатель', width: 220, flex: true },
  { key: 'users', label: 'Пользователи', width: 120, align: 'right' },
  { key: 'computers', label: 'Компьютеры', width: 120, align: 'right' },
]
const DC_COLUMNS: ColumnDef<'name' | 'dns' | 'os' | 'build' | 'rodc' | 'logon' | 'pwd' | 'owner' | 'ips' | 'subnet' | 'vm' | 'av'>[] = [
  { key: 'name', label: 'Имя', width: 140 },
  { key: 'dns', label: 'DNS', width: 200, flex: true },
  { key: 'os', label: 'ОС', width: 200 },
  { key: 'build', label: 'Сборка', width: 80 },
  { key: 'rodc', label: 'RODC', width: 64 },
  { key: 'logon', label: 'Вход, дн.', width: 88, align: 'right' },
  { key: 'pwd', label: 'Пароль, дн.', width: 96, align: 'right' },
  { key: 'owner', label: 'Владелец', width: 180 },
  { key: 'ips', label: 'IP', width: 128 },
  { key: 'subnet', label: 'Подсеть AD', width: 104 },
  { key: 'vm', label: 'Уязвимости (VM)', width: 176 },
  { key: 'av', label: 'Антивирус', width: 88 },
]
const CLUSTER_COLUMNS: ColumnDef<'name' | 'enabled' | 'roles' | 'disabled'>[] = [
  { key: 'name', label: 'Кластер', width: 180 },
  { key: 'enabled', label: 'Включён', width: 88 },
  { key: 'roles', label: 'Роли', width: 320, flex: true },
  { key: 'disabled', label: 'Выключенных ролей', width: 144, align: 'right' },
]
const NODE_COLUMNS: ColumnDef<'name' | 'dns' | 'os'>[] = [
  { key: 'name', label: 'Имя', width: 160 },
  { key: 'dns', label: 'DNS', width: 220, flex: true },
  { key: 'os', label: 'ОС', width: 220 },
]
const GROUP_COLUMNS: ColumnDef<'name' | 'members' | 'enabled' | 'inactive' | 'never' | 'delegable' | 'protected'>[] = [
  { key: 'name', label: 'Группа', width: 220, flex: true },
  { key: 'members', label: 'Участников', width: 104, align: 'right' },
  { key: 'enabled', label: 'Включено', width: 96, align: 'right' },
  { key: 'inactive', label: 'Неактивных', width: 104, align: 'right' },
  { key: 'never', label: 'Пароль не истекает', width: 144, align: 'right' },
  { key: 'delegable', label: 'Делегируемых', width: 120, align: 'right' },
  { key: 'protected', label: 'В Protected Users', width: 136, align: 'right' },
]
const OS_COLUMNS: ColumnDef<'name' | 'build' | 'total' | 'enabled' | 'active'>[] = [
  { key: 'name', label: 'ОС', width: 260, flex: true },
  { key: 'build', label: 'Сборка', width: 96 },
  { key: 'total', label: 'Всего', width: 88, align: 'right' },
  { key: 'enabled', label: 'Включено', width: 96, align: 'right' },
  { key: 'active', label: 'Активно', width: 88, align: 'right' },
]
const TRUST_COLUMNS: ColumnDef<'partner' | 'flat' | 'direction' | 'type' | 'forest' | 'changed'>[] = [
  { key: 'partner', label: 'Партнёр', width: 220, flex: true },
  { key: 'flat', label: 'NetBIOS', width: 120 },
  { key: 'direction', label: 'Направление', width: 128 },
  { key: 'type', label: 'Тип', width: 140 },
  { key: 'forest', label: 'В своём лесу', width: 104 },
  { key: 'changed', label: 'Изменено', width: 104 },
]
const POLICY_COLUMNS: ColumnDef<'name' | 'min' | 'lockout' | 'complexity' | 'reversible' | 'precedence'>[] = [
  { key: 'name', label: 'Имя', width: 220, flex: true },
  { key: 'min', label: 'Мин. длина', width: 96, align: 'right' },
  { key: 'lockout', label: 'Порог блокировки', width: 136, align: 'right' },
  { key: 'complexity', label: 'Сложность', width: 96 },
  { key: 'reversible', label: 'Обратимое', width: 96 },
  { key: 'precedence', label: 'Приоритет', width: 96, align: 'right' },
]
const GPO_COLUMNS: ColumnDef<'name' | 'links' | 'machine' | 'user'>[] = [
  { key: 'name', label: 'Имя', width: 240 },
  { key: 'links', label: 'Привязки', width: 320, flex: true },
  { key: 'machine', label: 'Комп. часть выкл.', width: 128 },
  { key: 'user', label: 'Польз. часть выкл.', width: 136 },
]
const SUBNET_COLUMNS: ColumnDef<'name' | 'site'>[] = [
  { key: 'name', label: 'Подсеть', width: 180 },
  { key: 'site', label: 'Сайт', width: 220, flex: true },
]

const ACCOUNT_ROWS: { key: keyof SummaryCounts; label: string }[] = [
  { key: 'total', label: 'Всего' },
  { key: 'enabled', label: 'Включено' },
  { key: 'disabled', label: 'Выключено' },
  { key: 'active', label: 'Активно' },
  { key: 'inactive', label: 'Неактивно' },
  { key: 'pwd_never_expires', label: 'Пароль не истекает' },
  { key: 'pwd_not_required', label: 'Пароль не требуется' },
  { key: 'no_preauth', label: 'Без предварительной аутентификации Kerberos' },
  { key: 'sid_history', label: 'С SID History' },
  { key: 'delegation', label: 'С делегированием' },
  { key: 'laps', label: 'С LAPS' },
]

const BUCKET_LABELS: Record<number, string> = { 30: '≤ 30 дн.', 90: '≤ 90 дн.', 180: '≤ 180 дн.', 365: '≤ 1 года', 730: '≤ 2 лет', 1095: '≤ 3 лет' }
const TRUST_DIRECTION: Record<number, string> = { 0: 'отключено', 1: 'входящее', 2: 'исходящее', 3: 'двустороннее' }
const TRUST_TYPE: Record<number, string> = { 1: 'Windows NT', 2: 'Active Directory', 3: 'Kerberos (MIT)', 4: 'DCE' }

function bucketLabel(b: SummaryBucket): string {
  return b.le === null ? '> 3 лет' : (BUCKET_LABELS[b.le] ?? `≤ ${b.le} дн.`)
}

function when(iso: string): string {
  return new Date(iso).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' })
}

function day(iso: string | null): string {
  return iso ? new Date(iso).toLocaleDateString('ru-RU') : '—'
}

function num(n: number | null): string {
  return n === null ? '—' : n.toLocaleString('ru-RU')
}

/** Список «Активов» с составом ячейки сводки (идентификатор — как в `core/summary_cells.py`). */
function cellHref(page: 'users' | 'assets', snapshotId: number, cell: string): string {
  return `/assets/${page === 'users' ? 'users' : 'list'}?ad_snapshot=${snapshotId}&ad_cell=${encodeURIComponent(cell)}`
}

const CELL_TITLE = 'Открыть список в Активах'
const CELL_LINK = 'rounded-sm hover:text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'

/** Число ячейки: ненулевое — ссылка на её состав в «Активах», ноль, «—» и ячейка без адреса — текстом. */
function cellNum(n: number | null, href: string | null): ReactNode {
  if (!n || !href) return num(n)
  return <Link to={href} className={CELL_LINK} title={CELL_TITLE}>{num(n)}</Link>
}

function yesNo(v: boolean | null): string {
  return v === null ? '—' : v ? 'да' : 'нет'
}

function code(map: Record<number, string>, v: number | null): string {
  return v === null ? '—' : (map[v] ?? String(v))
}

/** Таблица сводки с перетаскиваемыми колонками; ячейки строки — в порядке `columns`. */
function Table<C extends string>({ storageKey, columns, rows }: { storageKey: string; columns: readonly ColumnDef<C>[]; rows: { key: string; cells: Record<C, ReactNode> }[] }) {
  const cols = useColumnWidths(storageKey, columns)
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs" style={cols.tableStyle}>
        <ColGroup cols={cols} />
        <thead className="text-[11px] tracking-wide text-text-secondary uppercase"><tr><ResizableHeader cols={cols} className="py-1.5 pr-3" /></tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.key} className="border-t border-grid align-top">
              {columns.map((c) => (
                <td key={c.key} className={cn('py-1.5 pr-3 break-words', c.align === 'right' ? 'text-right font-mono tabular-nums text-text' : 'text-text-secondary')}>{r.cells[c.key]}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/** Горизонтальные полосы по корзинам; длина — от самой большой корзины. Ненулевая полоса — ссылка на её состав. */
function Histogram({ title, buckets, href }: { title: string; buckets: SummaryBucket[]; href: (b: SummaryBucket) => string }) {
  const total = buckets.reduce((s, b) => s + b.n, 0)
  const max = Math.max(1, ...buckets.map((b) => b.n))
  return (
    <div>
      <h3 className="mb-2 text-xs font-semibold text-text">{title}</h3>
      {total === 0 ? (
        <p className="text-xs text-text-secondary">учётных записей нет</p>
      ) : (
        <div className="flex flex-col gap-1.5">
          {buckets.map((b) => {
            const info = `${bucketLabel(b)}: ${b.n.toLocaleString('ru-RU')} (${Math.round((b.n / total) * 100)}%)`
            const bar = (
              <>
                <span className="w-20 shrink-0 text-text-secondary group-hover:underline">{bucketLabel(b)}</span>
                <div className="h-3 min-w-0 flex-1 rounded-sm bg-row-hover">
                  <div className="h-full rounded-sm bg-primary" style={{ width: `${(b.n / max) * 100}%` }} />
                </div>
                <span className="w-14 shrink-0 text-right font-mono tabular-nums text-text group-hover:underline">{b.n.toLocaleString('ru-RU')}</span>
              </>
            )
            return b.n > 0 ? (
              <Link key={String(b.le)} to={href(b)} className="group flex items-center gap-2 rounded-sm text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" title={`${info}. ${CELL_TITLE}`}>{bar}</Link>
            ) : (
              <div key={String(b.le)} className="flex items-center gap-2 text-xs" title={info}>{bar}</div>
            )
          })}
        </div>
      )}
    </div>
  )
}

function Distributions({ s, snapshotId }: { s: Summary; snapshotId: number }) {
  const [admins, setAdmins] = useState(false)
  const pick = admins ? 'admins' : 'all'
  return (
    <Section title="Возраст паролей и давность входа" about="Включённые пользователи по корзинам дней с последней смены пароля и с последнего входа; «админы» — включённые администраторы (RID из настроек и встроенный администратор). В «> 3 лет» попадают и те, у кого дата неизвестна: не входил, пароль не задавался.">
      <div className="mb-4 flex items-center gap-2" role="group" aria-label="Чьи учётные записи">
        {([[false, 'все'], [true, 'админы']] as const).map(([value, label]) => (
          <button
            key={label}
            type="button"
            aria-pressed={admins === value}
            onClick={() => setAdmins(value)}
            className={cn(
              'rounded border px-3 py-1 text-xs font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring',
              admins === value ? 'border-primary bg-primary text-primary-text' : 'border-border text-text hover:bg-row-hover',
            )}
          >
            {label}
          </button>
        ))}
      </div>
      <div className="grid gap-6 md:grid-cols-2">
        <Histogram title="Возраст паролей" buckets={s.password_age[pick]} href={(b) => cellHref('users', snapshotId, `password_age:${pick}:${b.le ?? 'over'}`)} />
        <Histogram title="Давность входа" buckets={s.last_logon[pick]} href={(b) => cellHref('users', snapshotId, `last_logon:${pick}:${b.le ?? 'over'}`)} />
      </div>
    </Section>
  )
}

function Gpos({ gpos }: { gpos: Summary['gpos'] }) {
  const [all, setAll] = useState(false)
  const shown = all ? gpos : gpos.slice(0, GPO_PAGE)
  return (
    <Section title="GPO" about={`Объекты групповой политики домена (${gpos.length}) и контейнеры, к которым они привязаны; в привязках и отключённые ссылки.`}>
      <Table
        storageKey="ad-summary-gpos"
        columns={GPO_COLUMNS}
        rows={shown.map((g) => ({
          key: g.dn,
          cells: {
            name: <span className="text-text">{g.name}</span>,
            links: g.links === null ? 'привязка неизвестна' : g.links.length === 0 ? 'не привязана' : (
              <ul className="flex flex-col gap-0.5">
                {g.links.map((l, i) => (
                  <li key={`${l.dn}|${i}`}>
                    <span className="break-all">{l.dn}</span>
                    {l.enforced && <span className="ml-1.5 whitespace-nowrap text-risk-high">принудительно</span>}
                    {l.disabled && <span className="ml-1.5 whitespace-nowrap text-text-secondary">отключена</span>}
                  </li>
                ))}
              </ul>
            ),
            machine: g.machine_disabled ? 'да' : '',
            user: g.user_disabled ? 'да' : '',
          },
        }))}
      />
      {gpos.length > GPO_PAGE && (
        <div className="mt-3"><Button variant="ghost" onClick={() => setAll((v) => !v)}>{all ? `показать первые ${GPO_PAGE}` : `показать все (${gpos.length})`}</Button></div>
      )}
    </Section>
  )
}

function roleNames(roles: { name: string; enabled: boolean }[]): ReactNode {
  if (roles.length === 0) return '—'
  return roles.map((r, i) => (
    <span key={r.name}>{i > 0 && ', '}<span className="text-text">{r.name}</span>{!r.enabled && <span className="text-risk-high"> (выкл.)</span>}</span>
  ))
}

function Clusters({ c }: { c: SummaryClusters }) {
  return (
    <Section title="Кластеры Windows" about="Кластеры отказоустойчивости по SPN компьютеров: учётка кластера, роли (виртуальные имена) и узлы. Роль относится к кластеру, учётка которого её создала (ms-DS-CreatorSID); выключенная роль, вероятно, брошена.">
      <div className="flex flex-col gap-3">
        {c.clusters.length > 0 && (
          <Table
            storageKey="ad-summary-clusters"
            columns={CLUSTER_COLUMNS}
            rows={c.clusters.map((k) => ({
              key: k.dn,
              cells: { name: <span className="text-text">{k.name}</span>, enabled: k.enabled ? 'да' : <span className="text-risk-high">нет</span>, roles: roleNames(k.roles), disabled: num(k.roles_disabled) },
            }))}
          />
        )}
        {c.orphan_roles.length > 0 && <p className="text-xs text-text-secondary">Роли без кластера: {roleNames(c.orphan_roles)}</p>}
        {c.nodes.length > 0 && (
          <div>
            <h3 className="mb-1 text-xs font-semibold text-text">Узлы</h3>
            <p className="mb-2 text-xs text-text-secondary">узлы к кластеру из AD не привязываются</p>
            <Table
              storageKey="ad-summary-cluster-nodes"
              columns={NODE_COLUMNS}
              rows={c.nodes.map((n) => ({ key: n.name, cells: { name: <span className="text-text">{n.name}</span>, dns: <span className="break-all">{n.dns || '—'}</span>, os: n.os || '—' } }))}
            />
          </div>
        )}
      </div>
    </Section>
  )
}

/** Ячейки связок контроллера; пока связки грузятся или не пришли — «—». */
function dcLinkCells(l: DcLink | undefined) {
  return {
    ips: l?.ips.length ? <span className="font-mono">{l.ips.join(', ')}</span> : '—',
    subnet: l?.in_ad_subnet == null ? '—' : l.in_ad_subnet ? 'да' : <span className="text-risk-high">нет подсети</span>,
    vm: l?.vm ? `${l.vm.critical} критичных, ${l.vm.exploitable} с эксплойтом` : '—',
    av: l?.ksc_agent == null ? '—' : l.ksc_agent ? 'есть' : <span className="text-risk-high">нет</span>,
  }
}

function SummaryView({ s, domainId, snapshotId }: { s: Summary; domainId: number; snapshotId: number }) {
  const { users, computers } = s.accounts
  const links = useDcLinks(domainId)
  const clusters = s.clusters
  return (
    <div className="flex flex-col gap-4">
      {users.total + computers.total > 0 && (
        <Section title="Учётные записи" about="Активные — включённые и входившие за срок неактивности из настроек модуля, неактивные — остальные включённые. Флаги (пароль, preauth, SID History, делегирование, LAPS) считаются среди включённых; штатная неограниченная делегация контроллеров не входит.">
          <Table
            storageKey="ad-summary-accounts"
            columns={ACCOUNT_COLUMNS}
            rows={ACCOUNT_ROWS.map((r) => ({
              key: r.key,
              cells: {
                label: r.label,
                users: r.key === 'laps' ? '—' : cellNum(users[r.key], cellHref('users', snapshotId, `accounts:users:${r.key}`)),
                computers: cellNum(computers[r.key], cellHref('assets', snapshotId, `accounts:computers:${r.key}`)),
              },
            }))}
          />
        </Section>
      )}

      {s.password_age.all.some((b) => b.n > 0) || s.last_logon.all.some((b) => b.n > 0) ? <Distributions s={s} snapshotId={snapshotId} /> : null}

      {s.dcs.length > 0 && (
        <Section title="Контроллеры домена" about="Дни — с последнего входа и с последней смены пароля учётной записи контроллера на момент сбора. Владелец — владелец объекта в AD; «—» — дескриптор не прочитан. IP, уязвимости и антивирус — из Assets, VM и KSC сейчас, по имени хоста; имя ведёт в карточку актива, если хост есть в Assets; «нет подсети» — ни один адрес не входит в подсети сайтов AD; «—» — данных нет.">
          <Table
            storageKey="ad-summary-dcs"
            columns={DC_COLUMNS}
            rows={s.dcs.map((d) => {
              const l = links.data?.find((x) => x.name === d.name)
              return {
                key: d.dn,
                cells: {
                  name: l?.asset_id != null
                    ? <Link to={`/assets/list?asset=${l.asset_id}`} className="rounded-sm text-text hover:text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" title="Карточка актива в реестре Assets">{d.name}</Link>
                    : <span className="text-text">{d.name}</span>,
                  dns: <span className="break-all">{d.dns || '—'}</span>,
                  os: d.os || '—',
                  build: d.build || '—',
                  rodc: d.rodc ? 'да' : '',
                  logon: num(d.last_logon_days),
                  pwd: num(d.pwd_age_days),
                  owner: d.owner || '—',
                  ...dcLinkCells(l),
                },
              }
            })}
          />
        </Section>
      )}

      {clusters && clusters.clusters.length + clusters.orphan_roles.length + clusters.nodes.length > 0 && <Clusters c={clusters} />}

      {s.groups.length > 0 && (
        <Section title="Привилегированные группы" about="Участников — все рекурсивные участники (пользователи и компьютеры), остальные столбцы — по включённым пользователям-участникам. Делегируемые — без флага «учётная запись важна и не может быть делегирована». Название ведёт в находки по группе.">
          <Table
            storageKey="ad-summary-groups"
            columns={GROUP_COLUMNS}
            rows={s.groups.map((g) => {
              // Группа без SID ячейки не имеет — числа текстом.
              const n = (field: string, v: number) => cellNum(v, g.sid ? cellHref('users', snapshotId, `groups:${field}:${g.sid}`) : null)
              return {
                key: g.sid || g.name,
                cells: {
                  name: <Link to={`/ad/domains/${domainId}/findings?q=${encodeURIComponent(g.name)}`} className="text-text hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring">{g.name}</Link>,
                  members: n('members', g.members),
                  enabled: n('enabled', g.enabled),
                  inactive: n('inactive', g.inactive),
                  never: n('pwd_never_expires', g.pwd_never_expires),
                  delegable: n('delegable', g.delegable),
                  protected: n('protected_users', g.protected_users),
                },
              }
            })}
          />
        </Section>
      )}

      {s.os.length > 0 && (
        <Section title="Операционные системы" about="Компьютеры домена по ОС и сборке, по убыванию числа; активные — входили за срок неактивности компьютеров из настроек.">
          <Table
            storageKey="ad-summary-os"
            columns={OS_COLUMNS}
            rows={s.os.map((o) => ({
              key: `${o.name}|${o.build}`,
              cells: {
                name: <span className="text-text">{o.name || 'не указана'}</span>,
                build: o.build || '—',
                // Ячейка — сборка и имя как в JSON сводки, пустые строки тоже.
                total: cellNum(o.total, cellHref('assets', snapshotId, `os:total:${o.build}:${o.name}`)),
                enabled: cellNum(o.enabled, cellHref('assets', snapshotId, `os:enabled:${o.build}:${o.name}`)),
                active: cellNum(o.active, cellHref('assets', snapshotId, `os:active:${o.build}:${o.name}`)),
              },
            }))}
          />
        </Section>
      )}

      {s.trusts.length > 0 && (
        <Section title="Доверия" about="Доверительные отношения домена. Входящее — партнёр доверяет нам, исходящее — мы доверяем партнёру.">
          <Table
            storageKey="ad-summary-trusts"
            columns={TRUST_COLUMNS}
            rows={s.trusts.map((t, i) => ({
              key: `${t.partner}|${i}`,
              cells: {
                partner: <span className="break-all text-text">{t.partner}</span>,
                flat: t.flat_name || '—',
                direction: code(TRUST_DIRECTION, t.direction),
                type: code(TRUST_TYPE, t.type),
                forest: t.within_forest ? 'да' : 'нет',
                changed: day(t.changed),
              },
            }))}
          />
        </Section>
      )}

      {s.password_policies.length > 0 && (
        <Section title="Политики паролей" about="Политика домена и детальные политики (PSO) по приоритету: у PSO меньшее число — выше приоритет. Порог блокировки 0 — учётная запись не блокируется.">
          <Table
            storageKey="ad-summary-policies"
            columns={POLICY_COLUMNS}
            rows={s.password_policies.map((p, i) => ({
              key: `${p.name}|${i}`,
              cells: {
                name: <span className="text-text">{p.name}</span>,
                min: num(p.min_length),
                lockout: num(p.lockout_threshold),
                complexity: <span className={cn(p.complexity === false && 'text-risk-high')}>{yesNo(p.complexity)}</span>,
                reversible: <span className={cn(p.reversible === true && 'text-risk-high')}>{yesNo(p.reversible)}</span>,
                precedence: num(p.precedence),
              },
            }))}
          />
        </Section>
      )}

      {s.gpos.length > 0 && <Gpos gpos={s.gpos} />}

      {s.subnets.length > 0 && (
        <Section title="Подсети AD" about="Подсети из конфигурации сайтов и сайт, к которому каждая привязана.">
          <Table
            storageKey="ad-summary-subnets"
            columns={SUBNET_COLUMNS}
            rows={s.subnets.map((n) => ({ key: n.name, cells: { name: <span className="font-mono text-text">{n.name}</span>, site: n.site || '—' } }))}
          />
        </Section>
      )}
    </div>
  )
}

/** Сводка домена по последнему снапшоту: таблицы учётных записей, контроллеров, групп, ОС, доверий, политик, GPO и подсетей. */
export function SummaryPage({ domainId }: { domainId: number }) {
  const overview = useOverview(domainId)
  const snap = overview.data?.snapshot ?? null
  const summary = useSummary(snap?.id)

  if (overview.isLoading) return <FullPageSpinner />
  if (overview.isError || !overview.data) {
    const msg = overview.error instanceof ApiRequestError ? overview.error.message : 'Не удалось загрузить обзор'
    return <div className="p-6"><ErrorState message={msg} onRetry={() => overview.refetch()} /></div>
  }
  if (!snap) {
    return (
      <div className="p-6">
        <EmptyState icon={ServerCog} title="Снапшотов ещё нет" description="Загрузите выгрузку скрипта или запустите сбор по LDAP в настройках модуля." action={<Link to="/ad/settings" className={ACTION_LINK}>Настройки и данные <ArrowRight size={13} aria-hidden /></Link>} />
      </div>
    )
  }
  if (summary.isLoading) return <FullPageSpinner />
  if (summary.error?.status === 409) {
    return (
      <div className="p-6">
        <EmptyState icon={RefreshCw} title="Сводка появится после пересчёта снапшота" description={`Снапшот #${snap.id} посчитан до появления сводки. Пересчитайте его на странице снапшотов.`} action={<Link to={`/ad/domains/${domainId}/snapshots`} className={ACTION_LINK}>Снапшоты <ArrowRight size={13} aria-hidden /></Link>} />
      </div>
    )
  }
  if (summary.isError || !summary.data) {
    const msg = summary.error instanceof ApiRequestError ? summary.error.message : 'Не удалось загрузить сводку'
    return <div className="p-6"><ErrorState message={msg} onRetry={() => summary.refetch()} /></div>
  }

  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-4">
        <h1 className="text-base font-semibold text-text">Сводка — {overview.data.domain.dns_root || overview.data.domain.netbios}</h1>
        <p className="max-w-2xl text-xs text-text-secondary">Снапшот #{snap.id} от {when(snap.collected_at)}. Числа — на момент сбора выгрузки.</p>
      </div>
      <SummaryView s={summary.data} domainId={domainId} snapshotId={snap.id} />
    </div>
  )
}
