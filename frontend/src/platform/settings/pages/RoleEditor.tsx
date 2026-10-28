import { useState } from 'react'
import { ArrowLeft, CheckCircle2, Copy, Trash2, UserCog } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { Field, FIELD } from '@/components/ui/Field'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { Link, matchPath, useRouter, useSearchParams } from '@/lib/router'
import {
  AREAS,
  LEVEL_TITLES,
  PLATFORM_LEVEL_TITLES,
  type Access,
  type Area,
  type Level,
} from '@/platform/access/types'
import { MODULES } from '@/platform/modules'
import { useCreateRole, useDeleteRole, useRoles, useUpdateRole, type RoleRow } from '@/platform/settings/api/access'

const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1)

const MODULE_LEVELS: Level[] = ['deny', 'read', 'write', 'admin']
const PLATFORM_LEVELS: Level[] = ['deny', 'read', 'admin']

/** Строки матрицы: модули в порядке рейки (только те, что есть среди областей прав), затем платформа. */
const ROWS: Array<{ area: Area; title: string; levels: Level[] }> = [
  ...MODULES.filter((m) => AREAS.some((a) => a === m.id)).map((m) => ({
    area: m.id as Area,
    title: m.title,
    levels: MODULE_LEVELS,
  })),
  { area: 'platform', title: 'Платформа', levels: PLATFORM_LEVELS },
]

const EMPTY_LEVELS = Object.fromEntries(AREAS.map((a) => [a, 'deny'])) as Access

function levelTitle(area: Area, level: Level): string {
  return cap(area === 'platform' ? PLATFORM_LEVEL_TITLES[level as keyof typeof PLATFORM_LEVEL_TITLES] : LEVEL_TITLES[level])
}

/**
 * Один уровень на область. Нативные radio под видом сегментной кнопки:
 * стрелки, Tab и озвучка работают без своего кода.
 */
function LevelRadios({
  area,
  title,
  levels,
  value,
  onChange,
  disabled,
}: {
  area: Area
  title: string
  levels: Level[]
  value: Level
  onChange: (level: Level) => void
  disabled: boolean
}) {
  return (
    <div role="radiogroup" aria-label={title} className="inline-flex overflow-hidden rounded border border-border">
      {levels.map((level) => (
        <label
          key={level}
          className={cn(
            'cursor-pointer border-l border-border px-3 py-1 text-xs text-text first:border-l-0 hover:bg-row-hover',
            'has-checked:bg-primary has-checked:text-primary-text has-checked:hover:bg-primary',
            'has-focus-visible:ring-2 has-focus-visible:ring-focus-ring has-focus-visible:ring-inset',
            'has-disabled:cursor-not-allowed has-disabled:opacity-60 has-disabled:hover:bg-transparent',
          )}
        >
          <input
            type="radio"
            className="sr-only"
            name={`level-${area}`}
            checked={value === level}
            disabled={disabled}
            onChange={() => onChange(level)}
          />
          {levelTitle(area, level)}
        </label>
      ))}
    </div>
  )
}

/**
 * Карточка роли: `/settings/access/roles/{id}` и `/settings/access/roles/new`.
 * Предзаполнение для «Скопировать как новую» передаётся параметром адреса
 * `?copy=<id роли>`: роутер состояния истории не несёт, а адрес переживает
 * перезагрузку страницы.
 */
export function RoleEditor() {
  const { path } = useRouter()
  const params = useSearchParams()
  const roles = useRoles()

  const rawId = matchPath('/settings/access/roles/:id', path)?.id
  const isNew = rawId === 'new'
  const copyOf = params.get('copy')

  if (roles.isLoading) return <FullPageSpinner />
  if (roles.isError || !roles.data) {
    return (
      <div className="p-6">
        <ErrorState message={roles.error?.message ?? 'Не удалось загрузить роли'} onRetry={() => roles.refetch()} />
      </div>
    )
  }

  const role = isNew ? undefined : roles.data.find((r) => String(r.id) === rawId)
  if (!isNew && !role) {
    return (
      <div className="p-6">
        <EmptyState
          icon={UserCog}
          title="Роль не найдена"
          description="Возможно, её уже удалили."
          action={<Link to="/settings/access/roles" className="text-sm text-primary hover:underline">К списку ролей</Link>}
        />
      </div>
    )
  }
  const template = isNew && copyOf ? roles.data.find((r) => String(r.id) === copyOf) : undefined

  // Ключ: переход между ролями и «Скопировать как новую» заново собирают форму из нужной записи.
  return <RoleForm key={role ? `role-${role.id}` : `new-${template?.id ?? ''}`} role={role} template={template} />
}

function RoleForm({ role, template }: { role?: RoleRow; template?: RoleRow }) {
  const can = useCan()
  const { navigate } = useRouter()
  const create = useCreateRole()
  const update = useUpdateRole()
  const remove = useDeleteRole()

  const [name, setName] = useState(role ? role.name : template ? `${template.name} (копия)` : '')
  const [description, setDescription] = useState((role ?? template)?.description ?? '')
  const [levels, setLevels] = useState<Access>((role ?? template)?.levels ?? EMPTY_LEVELS)

  const editable = can.platform.admin
  // «Администратор» нельзя менять совсем; у остальных встроенных меняется матрица, но не имя.
  const adminRole = !!role?.builtin && role.name === 'Администратор'
  const matrixLocked = !editable || adminRole
  const nameLocked = !editable || !!role?.builtin
  const save = role ? update : create
  const failure = [save.error, remove.error].find((e) => e != null)

  function change(apply: () => void) {
    save.reset()
    apply()
  }

  function submit() {
    const body = { name: name.trim(), description: description.trim(), levels }
    if (role) update.mutate({ id: role.id, body })
    else create.mutate(body, { onSuccess: (created) => navigate(`/settings/access/roles/${created.id}`, { replace: true }) })
  }

  function removeRole() {
    if (!role) return
    if (!window.confirm(`Удалить роль «${role.name}»?`)) return
    remove.mutate(role.id, { onSuccess: () => navigate('/settings/access/roles') })
  }

  const deleteWhy = !role
    ? null
    : role.builtin
      ? 'Встроенную роль нельзя удалить'
      : role.groups > 0
        ? 'Роль назначена группам — сначала назначьте им другую'
        : null

  return (
    <div className="h-full overflow-y-auto p-6">
      <Link to="/settings/access/roles" className="mb-3 inline-flex items-center gap-1 text-xs text-text-secondary hover:text-text">
        <ArrowLeft size={13} aria-hidden />
        Роли
      </Link>
      <h1 className="mb-5 text-base font-semibold text-text">{role ? role.name : 'Новая роль'}</h1>

      <div className="grid max-w-3xl gap-3 sm:grid-cols-2">
        <Field
          label="Название"
          hint={role?.builtin ? 'имя встроенной роли не меняется' : undefined}
        >
          <input
            className={FIELD}
            value={name}
            disabled={nameLocked}
            onChange={(e) => change(() => setName(e.target.value))}
          />
        </Field>
        <Field label="Описание">
          <input
            className={FIELD}
            value={description}
            disabled={!editable || adminRole}
            onChange={(e) => change(() => setDescription(e.target.value))}
          />
        </Field>
      </div>

      <section className="mt-6 max-w-3xl">
        <h2 className="mb-1 text-sm font-semibold text-text">Права</h2>
        {adminRole && (
          <p className="mb-2 text-xs text-text-secondary">встроенная роль, всегда полные права</p>
        )}
        <table className="w-full text-xs">
          <thead className="sr-only">
            <tr>
              <th>Область</th>
              <th>Уровень</th>
            </tr>
          </thead>
          <tbody>
            {ROWS.map((row) => (
              <tr key={row.area} className="border-b border-grid">
                <th scope="row" className="w-56 py-2 pr-3 text-left font-normal text-text">
                  {row.title}
                </th>
                <td className="py-2">
                  <LevelRadios
                    area={row.area}
                    title={row.title}
                    levels={row.levels}
                    value={levels[row.area] ?? 'deny'}
                    disabled={matrixLocked}
                    onChange={(level) => change(() => setLevels((v) => ({ ...v, [row.area]: level })))}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      {editable && (
        <div className="mt-5 flex flex-wrap items-center gap-3">
          {!adminRole && (
            <Button
              variant="primary"
              onClick={submit}
              loading={save.isPending}
              disabled={name.trim() === ''}
            >
              Сохранить
            </Button>
          )}
          {role && (
            <Button onClick={() => navigate(`/settings/access/roles/new?copy=${role.id}`)}>
              <Copy size={14} aria-hidden />
              Скопировать как новую
            </Button>
          )}
          {role && (
            <Button
              variant="danger"
              onClick={removeRole}
              loading={remove.isPending}
              disabled={deleteWhy !== null}
              title={deleteWhy ?? undefined}
            >
              <Trash2 size={14} aria-hidden />
              Удалить
            </Button>
          )}
          {role && update.isSuccess && (
            <span className="inline-flex items-center gap-1.5 text-xs text-kind-accepted">
              <CheckCircle2 size={14} aria-hidden />
              сохранено
            </span>
          )}
        </div>
      )}
      {failure && <p className="mt-3 text-xs text-kind-1">{failure.message}</p>}
    </div>
  )
}
