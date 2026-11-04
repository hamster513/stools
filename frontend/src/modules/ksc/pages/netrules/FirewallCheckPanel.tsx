import { useId, useState, type ReactNode } from 'react'
import { X } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { cn } from '@/lib/cn'
import { Link } from '@/lib/router'
import { ErrorState } from '@/components/ui/ErrorState'
import { useHostProfiles } from '../../api/queries'
import { useFirewallCheck, type FirewallBranch, type FirewallRule, type FirewallSide, type FirewallStep, type FirewallVerdict } from '../../api/firewall'
import { HostPicker } from './HostPicker'
import { buildCheck, MATCH_LABELS, outcomeTitle, STEP_LABELS, VERDICTS, type CheckForm } from './checkModel'

const FIELD = 'rounded border border-border bg-app-bg px-2 py-1.5 text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'
const BUTTON = 'rounded px-2 py-1.5 text-xs hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'

export function FirewallCheckPanel({ id, snapshotId, serverId, initialHost, onOpenRule, onClose }: { id: string; snapshotId: number; serverId: number; initialHost?: string; onOpenRule: (id: number) => void; onClose: () => void }) {
  const formId = useId()
  const [form, setForm] = useState<CheckForm>({ source: initialHost ?? '', destinationKind: 'address', address: '', host: '', protocol: 'tcp', port: '443', icmpType: '' })
  const [attempted, setAttempted] = useState(false)
  const mutation = useFirewallCheck(snapshotId)
  const built = buildCheck(form)
  const sameInput = !!built.input && JSON.stringify(built.input) === JSON.stringify(mutation.variables)
  const result = sameInput && !mutation.isPending ? mutation.data : undefined
  const error = sameInput && mutation.isError ? mutation.error.message : attempted ? built.error : undefined
  const update = (patch: Partial<CheckForm>) => { setForm(current => ({ ...current, ...patch })); setAttempted(false) }
  return <section id={id} aria-label="Проверка связи" className="border-b border-grid bg-surface p-4 text-xs text-text">
    <div className="mb-3 flex items-start justify-between gap-3">
      <div><h2 className="text-sm font-semibold">Проверка связи по правилам firewall</h2><p className="mt-1 text-text-secondary">Снапшот #{snapshotId}. Расчёт по политикам, тегам и правилам, без отправки пакетов. Сеть, маршрутизация и состояние службы не проверяются.</p></div>
      <button type="button" aria-label="Закрыть проверку связи" className={BUTTON} onClick={onClose}><X size={16} /></button>
    </div>
    <form onSubmit={e => { e.preventDefault(); setAttempted(true); if (built.input) mutation.mutate(built.input) }}>
      <div className="flex flex-wrap items-end gap-3">
        <div><div className="mb-1 text-text-secondary">Исходный хост</div><HostPicker snapshotId={snapshotId} value={form.source || undefined} onChange={source => update({ source: source ?? '' })} labelPrefix="Источник" emptyLabel="Выберите хост" /></div>
        <div><label className="mb-1 block text-text-secondary" htmlFor={`${formId}-destination`}>Назначение</label><select id={`${formId}-destination`} className={FIELD} value={form.destinationKind} onChange={e => update({ destinationKind: e.target.value as CheckForm['destinationKind'] })}><option value="address">IP-адрес</option><option value="host">Хост снапшота</option></select></div>
        {form.destinationKind === 'address' ? <div className="min-w-48 flex-1"><label className="mb-1 block text-text-secondary" htmlFor={`${formId}-address`}>IP назначения</label><input id={`${formId}-address`} className={cn(FIELD, 'w-full')} placeholder="IPv4 или IPv6" autoComplete="off" value={form.address} onChange={e => update({ address: e.target.value })} /></div> : <div><div className="mb-1 text-text-secondary">Хост назначения</div><HostPicker snapshotId={snapshotId} value={form.host || undefined} onChange={host => update({ host: host ?? '' })} labelPrefix="Назначение" emptyLabel="Выберите хост" /></div>}
        <div><label className="mb-1 block text-text-secondary" htmlFor={`${formId}-protocol`}>Протокол</label><select id={`${formId}-protocol`} className={FIELD} value={form.protocol} onChange={e => update({ protocol: e.target.value as CheckForm['protocol'] })}><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option><option value="icmpv6">ICMPv6</option><option value="any">Не указан</option></select></div>
        {(form.protocol === 'tcp' || form.protocol === 'udp') && <div><label className="mb-1 block text-text-secondary" htmlFor={`${formId}-port`}>Порт назначения</label><input id={`${formId}-port`} className={cn(FIELD, 'w-32')} inputMode="numeric" placeholder="Не указан" value={form.port} onChange={e => update({ port: e.target.value })} /></div>}
        {(form.protocol === 'icmp' || form.protocol === 'icmpv6') && <div><label className="mb-1 block text-text-secondary" htmlFor={`${formId}-icmp`}>Тип ICMP</label><input id={`${formId}-icmp`} className={cn(FIELD, 'w-28')} inputMode="numeric" placeholder="Не указан" value={form.icmpType} onChange={e => update({ icmpType: e.target.value })} /></div>}
        <button type="submit" disabled={mutation.isPending} className={cn(BUTTON, 'border border-primary text-primary disabled:opacity-50')}>{mutation.isPending ? 'Проверяем…' : 'Рассчитать'}</button>
      </div>
      <p className="mt-2 text-text-secondary">Если назначение однозначно найдено в снапшоте, проверяются исходящие правила источника и входящие правила назначения. Пустой порт или неизвестное условие могут дать неопределённый результат.</p>
      {error && <p role="alert" className="mt-3 text-risk-medium">{error}</p>}
      {mutation.isPending && <p role="status" className="mt-3 text-text-secondary">Проверяются политики, профили и порядок правил…</p>}
      {mutation.variables && !sameInput && <p role="status" className="mt-3 text-text-secondary">Параметры изменены — запустите расчёт снова.</p>}
    </form>
    {result && <div className="mt-4 space-y-3" aria-label="Результат проверки связи" aria-live="polite">
      <div className="rounded border border-grid bg-app-bg p-3">
        <h3 className="text-sm font-semibold">{outcomeTitle(result)}</h3>
        <p className="mt-1 text-text-secondary">{result.destination ? 'Проверены обе стороны связи по снапшоту.' : 'Проверена только сторона источника. Входящие правила назначения не проверены.'}</p>
        <Notes items={result.notes} /><Notes items={result.depends_on.map(p => `Результат зависит от: ${p}`)} />
        {!result.destination && result.destination_hosts.length > 1 && <p className="mt-2 text-text-secondary">С этим IP найдены: {result.destination_hosts.map(h => h.name || h.host_id).join(', ')}. Выберите конкретный хост назначения.</p>}
      </div>
      <SideResult key={`source:${result.source.host.host_id}`} side={result.source} snapshotId={snapshotId} serverId={serverId} onOpenRule={onOpenRule} />
      {result.destination && <SideResult key={`destination:${result.destination.host.host_id}`} side={result.destination} snapshotId={snapshotId} serverId={serverId} onOpenRule={onOpenRule} />}
    </div>}
  </section>
}

function Notes({ items }: { items: string[] }) {
  return items.length > 0 && <ul className="mt-2 space-y-1 text-text-secondary">{items.map((note, i) => <li key={i}>{note}</li>)}</ul>
}
function Verdict({ value }: { value: FirewallVerdict }) {
  return <span className={cn('font-semibold', value === 'allow' ? 'text-kind-accepted' : value === 'deny' ? 'text-kind-1' : 'text-risk-medium')}>{VERDICTS[value]}</span>
}
function Expandable({ title, children, initialOpen = false }: { title: ReactNode; children: ReactNode; initialOpen?: boolean }) {
  const [open, setOpen] = useState(initialOpen)
  return <details open={open} onToggle={e => setOpen(e.currentTarget.open)} className="rounded border border-grid">
    <summary className="cursor-pointer px-3 py-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring">{title}</summary>
    {open && <div className="border-t border-grid p-3">{children}</div>}
  </details>
}
function SideResult({ side, snapshotId, serverId, onOpenRule }: { side: FirewallSide; snapshotId: number; serverId: number; onOpenRule: (id: number) => void }) {
  return <section aria-label={side.direction === 'out' ? 'Проверка источника' : 'Проверка назначения'} className="space-y-2 rounded border border-grid p-3">
    <h4 className="font-semibold">{side.direction === 'out' ? 'Источник · исходящий трафик' : 'Назначение · входящий трафик'} — {side.host.name || side.host.host_id} <span className="font-normal text-text-secondary">{side.host.ip}</span></h4>
    <Verdict value={side.verdict} />
    {side.mode === 'notify_only' && <p className="text-risk-medium">Режим только уведомлений: блокировка не выполняется.</p>}
    {side.effective_sources.length > 0 && <p className="text-text-secondary">Источники правил в рассмотренных вариантах: {side.effective_sources.join('; ')}.</p>}
    <Notes items={side.notes} /><Notes items={side.depends_on.map(p => `Зависит от: ${p}`)} />
    <Expandable title="Теги, политики и активация профилей"><HostContext snapshotId={snapshotId} hostId={side.host.host_id} serverId={serverId} /></Expandable>
    {side.branches.map((branch, index) => <Expandable key={index} initialOpen={side.branches.length === 1} title={<span>Вариант {index + 1} · <Verdict value={branch.verdict} />{branch.assumptions.length > 0 && <span className="ml-2 text-text-secondary">{branch.assumptions.join('; ')}</span>}</span>}>
      <BranchResult branch={branch} onOpenRule={onOpenRule} />
    </Expandable>)}
  </section>
}
function RuleLink({ rule, onOpenRule }: { rule: FirewallRule; onOpenRule: (id: number) => void }) {
  return <button type="button" className="rounded text-left text-primary hover:underline focus-visible:ring-2 focus-visible:ring-focus-ring" onClick={() => onOpenRule(rule.row_id)}>№{rule.position} {rule.name || 'Без названия'} <span className="text-text-secondary">· {rule.profile ? `профиль «${rule.profile}»` : 'политика'} · {rule.action}</span></button>
}
function BranchResult({ branch, onOpenRule }: { branch: FirewallBranch; onOpenRule: (id: number) => void }) {
  return <div className="space-y-3">
    {branch.note && <p className="text-text-secondary">{branch.note}</p>}
    {branch.decided_by ? <div>Решающее правило: <RuleLink rule={branch.decided_by} onOpenRule={onOpenRule} /></div> : <p className="text-text-secondary">Единого решающего правила нет.</p>}
    {branch.steps.length > 0 && <Expandable title={`Прохождение правил · ${branch.steps.length}`}><Trace steps={branch.steps} onOpenRule={onOpenRule} /></Expandable>}
    {branch.reply_steps.length > 0 && <Expandable title={`Ответный пакет · ${branch.reply_steps.length}`}><Trace steps={branch.reply_steps} onOpenRule={onOpenRule} /></Expandable>}
    {branch.app_candidates.length > 0 && <Expandable title={`Подходящие правила программ · ${branch.app_candidates.length}`}><ul className="space-y-2">{branch.app_candidates.map((rule, i) => <li key={i}><RuleLink rule={rule} onOpenRule={onOpenRule} /></li>)}</ul></Expandable>}
    {branch.trust_groups.length > 0 && <ul className="space-y-1 text-text-secondary">{branch.trust_groups.map((g, i) => <li key={i}>Группа доверия «{g.name}»: {g.allow === null ? 'решение не определено' : g.allow ? 'разрешает' : 'запрещает'}</li>)}</ul>}
  </div>
}
function Trace({ steps, onOpenRule }: { steps: FirewallStep[]; onOpenRule: (id: number) => void }) {
  return <ol className="max-h-96 space-y-3 overflow-y-auto">
    {steps.map((step, index) => <li key={index} className="border-b border-grid pb-2 last:border-0">
      <div className="flex flex-wrap items-start justify-between gap-2"><RuleLink rule={step.rule} onOpenRule={onOpenRule} /><span className={step.status === 'hit' ? 'font-semibold text-text' : 'text-text-secondary'}>{STEP_LABELS[step.status]}</span></div>
      {step.criteria.length > 0 && <ul className="mt-1 space-y-1 text-text-secondary">{step.criteria.map((criterion, i) => <li key={i}>{MATCH_LABELS[criterion.result]}: {criterion.text}</li>)}</ul>}
      {step.almost && <p className="mt-1 text-risk-medium">Ближайшее несовпадение: {step.almost.text}</p>}
      {step.assumption && <p className="mt-1 text-risk-medium">Допущение: {step.assumption}</p>}
    </li>)}
  </ol>
}
function HostContext({ snapshotId, hostId, serverId }: { snapshotId: number; hostId: string; serverId: number }) {
  const query = useHostProfiles(snapshotId, hostId)
  if (query.isLoading) return <p role="status" className="text-text-secondary">Загрузка тегов и профилей…</p>
  if (query.isError || !query.data) return <ErrorState message={query.error instanceof ApiRequestError ? query.error.message : 'Не удалось загрузить условия применения'} onRetry={() => query.refetch()} />
  const data = query.data
  return <div className="space-y-3">
    <p>Теги хоста: {data.tags === null ? 'не собраны — активация может быть неопределённой' : data.tags.length ? data.tags.join(', ') : 'собраны, тегов нет'}.</p>
    {!data.profiles_collected && <p className="text-risk-medium">Профили политик не собраны.</p>}
    <p className="text-text-secondary">Активация по тегам и применение списка firewall — разные условия. Участие правил также зависит от замка и режима наложения; использованные источники указаны выше.</p>
    {data.policies.filter(p => p.product === 'KES').map(policy => <div key={policy.id}>
      <p className="font-semibold"><Link to={`/ksc/servers/${serverId}/policies/${policy.id}`} className="text-primary hover:underline">{policy.name}</Link> · {policy.active ? 'активная' : 'неактивная'} · {policy.own ? 'собственная' : 'унаследованная'}</p>
      {!policy.profiles_collected ? <p className="text-text-secondary">Профили этой политики не собраны.</p> : policy.profiles.length === 0 ? <p className="text-text-secondary">Профилей нет.</p> : <ul className="mt-2 max-h-80 space-y-2 overflow-y-auto">
        {policy.profiles.map((profile, i) => <li key={i} className="border-l-2 border-grid pl-3">
          <p>{profile.name} · приоритет {profile.priority} · {profile.active === null ? 'активация не определена' : profile.active ? 'активен' : 'неактивен'}</p>
          <p className="text-text-secondary">{profile.reason}</p>
          {profile.matched_tags.length > 0 && <p className="text-text-secondary">Совпавшие теги: {profile.matched_tags.join(', ')}</p>}
          {profile.condition.length > 0 && <p className="text-text-secondary">Условие: {profile.condition.map(group => `(${group.map(c => c.text).join(' И ')})`).join(' ИЛИ ')}</p>}
        </li>)}
      </ul>}
    </div>)}
  </div>
}
