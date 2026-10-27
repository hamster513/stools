import { useEffect, useState } from 'react'
import { Calculator, CheckCircle2, Plus, Save, Tag, X } from 'lucide-react'
import {
  useProfile,
  usePreviewProfile,
  useSnapshotSummary,
  useUpdateProfile,
} from '@/modules/siem/api/queries'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { ErrorState } from '@/components/ui/ErrorState'
import { Button } from '@/components/ui/Button'
import { ApiRequestError } from '@/api/client'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { FieldRolesSection } from './profile/FieldRolesSection'
import { TableRow } from './profile/TableRow'

export function ProfilePage({ snapshotId }: { snapshotId: number }) {
  const profile = useProfile(snapshotId)
  const summary = useSnapshotSummary(snapshotId)
  const update = useUpdateProfile()
  const preview = usePreviewProfile()
  // Профиль — настройка модуля: читают все, а сохранение и прикидку
  // «что изменится» сервер даёт только администратору SIEM.
  const { admin } = useCan()

  const [scoping, setScoping] = useState<Set<string>>(new Set())
  const [accounts, setAccounts] = useState<string[]>([])
  const [newAccount, setNewAccount] = useState('')
  const [roles, setRoles] = useState<{ environmental: string[]; technical: string[] }>({
    environmental: [],
    technical: [],
  })
  const [dirty, setDirty] = useState(false)

  useEffect(() => {
    if (!profile.data) return
    setScoping(new Set(profile.data.tables.scoping))
    setAccounts(profile.data.builtin_accounts)
    setRoles({
      environmental: profile.data.field_roles.environmental,
      technical: profile.data.field_roles.technical,
    })
  }, [profile.data])

  if (profile.isLoading || summary.isLoading) return <FullPageSpinner />
  if (profile.isError || !profile.data) {
    const msg = profile.error instanceof ApiRequestError ? profile.error.message : 'Не удалось загрузить профиль инсталляции'
    return (
      <div className="p-6">
        <ErrorState message={msg} onRetry={() => profile.refetch()} />
      </div>
    )
  }

  const p = profile.data
  // Ранжирование списков приходит со сводкой снапшота, а не с профилем:
  // профиль хранит решения человека, ранжирование считается по данным.
  const sortedTables = [...(summary.data?.table_ranking ?? [])].sort(
    (a, b) => b.risk - a.risk,
  )

  //: Скольких правил касается текущий выбор. Отметка — не пометка на
  //: списке, а утверждение обо всех читающих его правилах, и масштаб
  //: этого утверждения должен быть виден до сохранения.
  const scopedPreview = sortedTables.length
    ? sortedTables
        .filter((t) => scoping.has(t.name))
        .reduce((sum, t) => sum + t.dependant_count, 0)
    : null

  function toggleScoping(name: string) {
    setDirty(true)
    setScoping((prev) => {
      const next = new Set(prev)
      if (next.has(name)) next.delete(name)
      else next.add(name)
      return next
    })
  }

  //: Что даст этот профиль до сохранения. Одно поле на эталонной выгрузке
  //: добавляет до семидесяти замечаний, и узнавать об этом постфактум,
  //: разыскивая источник сотни новых находок, — плохой порядок.
  function checkEffect() {
    preview.mutate({
      snapshot_id: snapshotId,
      tables: { scoping: Array.from(scoping), watched: p.tables.watched },
      builtin_accounts: accounts,
      field_roles: roles,
      name_scheme: p.name_scheme ?? undefined,
    })
  }

  function save() {
    update.mutate(
      {
        snapshot_id: snapshotId,
        tables: { scoping: Array.from(scoping), watched: p.tables.watched },
        builtin_accounts: accounts,
        field_roles: roles,
        name_scheme: p.name_scheme ?? undefined,
      },
      { onSuccess: () => setDirty(false) },
    )
  }

  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-5 flex items-start justify-between">
        <div>
          <h1 className="text-base font-semibold text-text">Профиль инсталляции</h1>
          <p className="max-w-2xl text-xs text-text-secondary">
            Единственное, что инструмент не может вывести сам: в теле правила чтение табличного списка и
            ограничение им области действия выглядят одинаково. Отметьте ниже, какие списки на самом деле
            сужают область действия правил.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {summary.data && (
            <span
              className={cn(
                'inline-flex items-center gap-1.5 rounded border px-2 py-1 text-xs',
                summary.data.profile_confirmed
                  ? 'border-kind-accepted/40 bg-kind-accepted/10 text-kind-accepted'
                  : 'border-kind-3/40 bg-kind-3/10 text-kind-3',
              )}
            >
              <CheckCircle2 size={12} aria-hidden />
              {summary.data.profile_confirmed ? 'Профиль подтверждён' : 'Профиль не подтверждён'}
            </span>
          )}
          {admin && (
            <>
              <Button onClick={checkEffect} loading={preview.isPending}>
                <Calculator size={13} aria-hidden /> Что изменится
              </Button>
              <Button variant="primary" loading={update.isPending} disabled={!dirty} onClick={save}>
                <Save size={13} aria-hidden /> Сохранить
              </Button>
            </>
          )}
        </div>
      </div>

      {preview.data && summary.data && (
        <div className="mb-4 flex flex-wrap items-center gap-4 rounded border border-primary/40 bg-primary/5 px-3 py-2 text-xs">
          <span className="text-text-secondary">Если сохранить этот профиль:</span>
          <span className="text-text">
            замечаний{' '}
            <span className="font-mono">{summary.data.finding_count}</span> →{' '}
            <span
              className={cn(
                'font-mono',
                preview.data.finding_count > summary.data.finding_count
                  ? 'text-kind-2'
                  : preview.data.finding_count < summary.data.finding_count
                    ? 'text-kind-accepted'
                    : 'text-text',
              )}
            >
              {preview.data.finding_count}
            </span>
          </span>
          <span className="text-text">
            ограничено списком{' '}
            <span className="font-mono">{summary.data.scoped_count}</span> →{' '}
            <span className="font-mono text-text">{preview.data.scoped_count}</span>
          </span>
          <span className="text-text-secondary">групп {preview.data.group_count}</span>
        </div>
      )}

      {p.name_scheme && (
        <section className="mb-4 rounded border border-grid bg-surface p-4">
          <div className="mb-2 flex items-center gap-1.5 text-xs font-semibold tracking-wide text-text-secondary uppercase">
            <Tag size={12} aria-hidden /> Предложенная схема именования
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <code className="rounded border border-grid bg-app-bg px-2 py-1 font-mono text-xs text-text">
              {p.name_scheme.segments.map((s) => `{${s}}`).join(p.name_scheme.separator)}
            </code>
            <span className="font-mono text-xs tabular-nums text-text-secondary">
              покрытие {p.name_scheme.coverage} из {p.name_scheme.total}, групп {p.name_scheme.group_count}
            </span>
          </div>
          {/* По позициям, а не примерами целиком: схема — утверждение о том,
              что стоит на каждом месте имени, и проверять её удобно там же. */}
          <table className="mt-2 text-xs">
            <tbody>
              {p.name_scheme.stats.map((s) => (
                <tr key={s.position}>
                  <td className="pr-3 py-0.5 font-mono tabular-nums text-text-secondary">{s.position + 1}</td>
                  <td className="pr-3 py-0.5 text-text">{s.role ?? 'описание'}</td>
                  <td className="pr-3 py-0.5 font-mono text-text-secondary">{s.examples.join(', ')}</td>
                  <td className="py-0.5 font-mono tabular-nums text-text-secondary">
                    {s.distinct} разных, в {s.coverage} именах
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      <section className="mb-4 rounded border border-grid bg-surface p-4">
        <div className="mb-1 text-xs font-semibold tracking-wide text-text-secondary uppercase">
          Встроенные учётные записи
        </div>
        {/* Раньше здесь был безымянный список без объяснения. Смысл в том,
            что эти имена одинаковы в любой инсталляции, поэтому зашитые
            в правило они замечанием не являются — в отличие от имени
            служебной учётки конкретной организации. */}
        <p className="mb-3 max-w-3xl text-xs text-text-secondary">
          Эти имена одинаковы в любой инсталляции Windows, поэтому зашитые прямо в правило они
          замечанием не считаются и в находки не попадают. Имя служебной учётной записи вашей
          организации — совсем другое дело: оно уникально, и его место в табличном списке.
          Добавьте сюда те, что у вас тоже встроенные.
        </p>
        {(p.builtin_accounts_default?.length ?? 0) > 0 && (
          <div className="mb-3">
            <div className="mb-1 text-[11px] text-text-secondary">
              Учтены всегда, настройки не требуют:
            </div>
            <div className="flex flex-wrap gap-1.5">
              {p.builtin_accounts_default?.map((a) => (
                <span
                  key={a}
                  className="rounded border border-grid/60 px-2 py-0.5 font-mono text-[11px] text-text-secondary"
                >
                  {a}
                </span>
              ))}
              <span className="px-1 py-0.5 text-[11px] text-text-secondary">
                а также NT AUTHORITY\\* и учётные записи компьютеров (имя оканчивается на $)
              </span>
            </div>
          </div>
        )}

        <div className="mb-1 text-[11px] text-text-secondary">Добавлено для этой инсталляции:</div>
        <div className="mb-2 flex flex-wrap gap-1.5">
          {accounts.map((a) => (
            <span
              key={a}
              className="inline-flex items-center gap-1.5 rounded border border-grid bg-app-bg px-2 py-1 font-mono text-xs text-text-secondary"
            >
              {a}
              {admin && (
                <button
                  type="button"
                  onClick={() => {
                    setDirty(true)
                    setAccounts((prev) => prev.filter((x) => x !== a))
                  }}
                  className="rounded text-text-secondary hover:text-kind-1 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
                  aria-label={`Убрать ${a}`}
                >
                  <X size={11} aria-hidden />
                </button>
              )}
            </span>
          ))}
          {accounts.length === 0 && (
            <span className="text-xs text-text-secondary">не задано ни одной</span>
          )}
        </div>
        {admin && (
        <form
          className="flex items-center gap-2"
          onSubmit={(e) => {
            e.preventDefault()
            const value = newAccount.trim()
            if (!value || accounts.includes(value)) return
            setDirty(true)
            setAccounts((prev) => [...prev, value])
            setNewAccount('')
          }}
        >
          <input
            value={newAccount}
            onChange={(e) => setNewAccount(e.target.value)}
            placeholder="Например, СЛУЖБА ЛОКАЛЬНОГО СЕРВЕРА"
            className="w-72 rounded border border-border bg-app-bg px-2.5 py-1 text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
          />
          <Button type="submit" disabled={!newAccount.trim()}>
            <Plus size={13} aria-hidden />
            Добавить
          </Button>
        </form>
        )}
      </section>

      <FieldRolesSection
        snapshotId={snapshotId}
        profile={p}
        environmental={roles.environmental}
        technical={roles.technical}
        onChange={(next) => {
          setDirty(true)
          setRoles(next)
        }}
      />

      <section className="rounded border border-grid bg-surface p-4">
        <div className="mb-1 text-xs font-semibold tracking-wide text-text-secondary uppercase">
          Табличные списки по риску ({sortedTables.length})
        </div>
        {/* Что делает галочка — раньше нигде не было сказано, и человек
            отмечал наугад. Следствие у неё вполне ощутимое. */}
        <p className="mb-2 max-w-3xl text-xs text-text-secondary">
          Отметка означает: правила, читающие этот список, работают <span className="text-text">
          не шире его содержимого</span>. Пустой такой список — тихая точка отказа: правило
          формально работает, но не сработает никогда. Отмеченные списки меняют «Ограничено
          списком» в инвентаре правил и добавляют покрытию ATT&CK состояние «закрыто частично».
        </p>
        <p className="mb-3 max-w-3xl text-xs text-text-secondary">
          Раскройте список, чтобы увидеть, что в нём лежит и какие правила его читают: по имени
          перечень критичных узлов и справочник соответствий неотличимы.
          {scopedPreview !== null && (
            <span className="ml-1 text-text">
              Сейчас отмечено {scoping.size}; это затрагивает {scopedPreview} правил.
            </span>
          )}
        </p>
        <div className="flex flex-col divide-y divide-grid">
          {sortedTables.map((t) => (
            <TableRow
              key={t.name}
              snapshotId={snapshotId}
              entry={t}
              scoping={scoping.has(t.name)}
              onToggle={() => toggleScoping(t.name)}
            />
          ))}
        </div>
      </section>
    </div>
  )
}
