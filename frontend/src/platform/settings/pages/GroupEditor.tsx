import { useState } from 'react'
import { ArrowLeft, CheckCircle2, Trash2, UsersRound, X } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { Field, FIELD } from '@/components/ui/Field'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { Link, matchPath, useRouter } from '@/lib/router'
import {
  useCreateGroup,
  useDeleteGroup,
  useGroup,
  useGroupMembers,
  useRoles,
  useSetGroupMembers,
  useUpdateGroup,
  type GroupRow,
  type RoleRow,
} from '@/platform/settings/api/access'
import { useUsers } from '@/platform/settings/api/queries'

function person(login: string, displayName: string | null): string {
  return displayName ? `${displayName} (${login})` : login
}

/** Карточка группы: `/settings/access/groups/{id}` и `/settings/access/groups/new`. */
export function GroupEditor() {
  const { path } = useRouter()
  const rawId = matchPath('/settings/access/groups/:id', path)?.id
  const isNew = rawId === 'new'
  const group = useGroup(isNew ? null : Number(rawId))
  const roles = useRoles()

  if (group.isLoading || roles.isLoading) return <FullPageSpinner />
  const failed = group.isError ? group : roles.isError ? roles : null
  if (failed || !roles.data) {
    return (
      <div className="p-6">
        <ErrorState
          message={failed?.error?.message ?? 'Не удалось загрузить группы'}
          onRetry={() => {
            void group.refetch()
            void roles.refetch()
          }}
        />
      </div>
    )
  }
  if (!isNew && !group.data) {
    return (
      <div className="p-6">
        <EmptyState
          icon={UsersRound}
          title="Группа не найдена"
          description="Возможно, её уже удалили."
          action={<Link to="/settings/access/groups" className="text-sm text-primary hover:underline">К списку групп</Link>}
        />
      </div>
    )
  }
  return <GroupForm key={group.data?.id ?? 'new'} group={group.data} roles={roles.data} />
}

function GroupForm({ group, roles }: { group?: GroupRow; roles: RoleRow[] }) {
  const can = useCan()
  const { navigate } = useRouter()
  const create = useCreateGroup()
  const update = useUpdateGroup()
  const remove = useDeleteGroup()

  const [name, setName] = useState(group?.name ?? '')
  const [source, setSource] = useState<'local' | 'oidc'>(group?.source ?? 'local')
  const [externalName, setExternalName] = useState(group?.external_name ?? '')
  const [roleId, setRoleId] = useState(group ? String(group.role_id) : '')

  const editable = can.platform.admin
  const save = group ? update : create
  const failure = [save.error, remove.error].find((e) => e != null)
  const complete = name.trim() !== '' && roleId !== '' && (source === 'local' || externalName.trim() !== '')

  function change(apply: () => void) {
    save.reset()
    apply()
  }

  function submit() {
    const external_name = source === 'oidc' ? externalName.trim() : null
    const common = { name: name.trim(), external_name, role_id: Number(roleId) }
    if (group) update.mutate({ id: group.id, body: common })
    else {
      create.mutate(
        { ...common, source },
        { onSuccess: (created) => navigate(`/settings/access/groups/${created.id}`, { replace: true }) },
      )
    }
  }

  function removeGroup() {
    if (!group) return
    if (!window.confirm(`Удалить группу «${group.name}»? Её участники потеряют права, которые давала эта роль.`)) return
    remove.mutate(group.id, { onSuccess: () => navigate('/settings/access/groups') })
  }

  return (
    <div className="h-full overflow-y-auto p-6">
      <Link to="/settings/access/groups" className="mb-3 inline-flex items-center gap-1 text-xs text-text-secondary hover:text-text">
        <ArrowLeft size={13} aria-hidden />
        Группы
      </Link>
      <h1 className="mb-5 text-base font-semibold text-text">{group ? group.name : 'Новая группа'}</h1>

      <div className="grid max-w-3xl gap-3 sm:grid-cols-2">
        <Field label="Название">
          <input
            className={FIELD}
            value={name}
            disabled={!editable}
            onChange={(e) => change(() => setName(e.target.value))}
          />
        </Field>
        <Field label="Роль">
          <select
            className={FIELD}
            value={roleId}
            disabled={!editable}
            onChange={(e) => change(() => setRoleId(e.target.value))}
          >
            {!group && <option value="">выберите роль</option>}
            {roles.map((r) => (
              <option key={r.id} value={r.id}>
                {r.name}
              </option>
            ))}
          </select>
        </Field>

        {/* Источник выбирают при создании; у готовой группы он не меняется. */}
        {group ? (
          <div>
            <span className="mb-1 block text-xs font-medium text-text">Источник</span>
            <p className="py-1.5 text-sm text-text">{group.source === 'oidc' ? 'OIDC' : 'локальная'}</p>
          </div>
        ) : (
          <fieldset>
            <legend className="mb-1 block text-xs font-medium text-text">Источник</legend>
            <div className="flex gap-4 py-1.5">
              {(
                [
                  ['local', 'Локальная'],
                  ['oidc', 'OIDC'],
                ] as const
              ).map(([value, label]) => (
                <label key={value} className="flex items-center gap-1.5 text-sm text-text">
                  <input
                    type="radio"
                    name="group-source"
                    checked={source === value}
                    disabled={!editable}
                    onChange={() => change(() => setSource(value))}
                  />
                  {label}
                </label>
              ))}
            </div>
          </fieldset>
        )}
        {source === 'oidc' && (
          <Field label="Имя в OIDC" hint="Так группа называется в ответе провайдера">
            <input
              className={FIELD}
              value={externalName}
              disabled={!editable}
              spellCheck={false}
              onChange={(e) => change(() => setExternalName(e.target.value))}
            />
          </Field>
        )}
      </div>

      {editable && (
        <div className="mt-5 flex flex-wrap items-center gap-3">
          <Button variant="primary" onClick={submit} loading={save.isPending} disabled={!complete}>
            {group ? 'Сохранить' : 'Создать'}
          </Button>
          {group && (
            <Button variant="danger" onClick={removeGroup} loading={remove.isPending}>
              <Trash2 size={14} aria-hidden />
              Удалить
            </Button>
          )}
          {group && update.isSuccess && (
            <span className="inline-flex items-center gap-1.5 text-xs text-kind-accepted">
              <CheckCircle2 size={14} aria-hidden />
              сохранено
            </span>
          )}
        </div>
      )}
      {failure && <p className="mt-3 text-xs text-kind-1">{failure.message}</p>}

      {group ? (
        <Members group={group} editable={editable} />
      ) : (
        source === 'local' && (
          <p className="mt-6 text-xs text-text-secondary">Участников можно добавить после создания группы.</p>
        )
      )}
    </div>
  )
}

/**
 * Состав группы. У local каждая правка сразу уходит на сервер полным
 * списком; у oidc список только для чтения: его заново собирает вход.
 */
function Members({ group, editable }: { group: GroupRow; editable: boolean }) {
  const members = useGroupMembers(group.id)
  const users = useUsers()
  const setMembers = useSetGroupMembers(group.id)
  const manual = group.source === 'local' && editable

  if (members.isLoading) return <p className="mt-6 text-xs text-text-secondary">Загрузка участников…</p>
  if (members.isError || !members.data) {
    return (
      <div className="mt-6 max-w-3xl">
        <ErrorState message={members.error?.message ?? 'Не удалось загрузить участников'} onRetry={() => members.refetch()} />
      </div>
    )
  }

  const ids = members.data.map((m) => m.user_id)
  const candidates = (users.data ?? []).filter((u) => !ids.includes(u.id))

  return (
    <section className="mt-6 max-w-3xl" aria-labelledby="group-members">
      <h2 id="group-members" className="mb-1 text-sm font-semibold text-text">
        Участники <span className="font-normal text-text-secondary">{members.data.length}</span>
      </h2>
      {group.source === 'oidc' && (
        <p className="mb-2 text-xs text-text-secondary">обновляется при входе</p>
      )}
      {members.data.length === 0 ? (
        <p className="py-2 text-xs text-text-secondary">В группе никого нет.</p>
      ) : (
        <ul className="mb-3 divide-y divide-grid border-y border-grid text-xs">
          {members.data.map((m) => (
            <li key={m.user_id} className="flex items-center justify-between gap-3 py-1.5">
              <span className="text-text">{person(m.login, m.display_name)}</span>
              {manual && (
                <Button
                  variant="ghost"
                  disabled={setMembers.isPending}
                  onClick={() => setMembers.mutate(ids.filter((id) => id !== m.user_id))}
                >
                  <X size={14} aria-hidden />
                  убрать
                </Button>
              )}
            </li>
          ))}
        </ul>
      )}
      {manual && (
        <div className="max-w-sm">
          <Field label="Добавить участника">
            <select
              className={FIELD}
              value=""
              disabled={candidates.length === 0 || setMembers.isPending}
              onChange={(e) => {
                if (e.target.value !== '') setMembers.mutate([...ids, Number(e.target.value)])
              }}
            >
              <option value="">{candidates.length === 0 ? 'все учётки уже в группе' : 'выберите пользователя'}</option>
              {candidates.map((u) => (
                <option key={u.id} value={u.id}>
                  {person(u.login, u.display_name)}
                </option>
              ))}
            </select>
          </Field>
        </div>
      )}
      {setMembers.isError && <p className="mt-2 text-xs text-kind-1">{setMembers.error.message}</p>}
    </section>
  )
}
