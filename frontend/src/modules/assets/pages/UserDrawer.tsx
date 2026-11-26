import { SiemLogons } from './SiemLogons'
import { useEffect, useRef, useState } from 'react'
import { User, X } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { usePatchUser, useUser } from '@/modules/assets/api/queries'
import {
  SOURCE_LABELS,
  USER_CODE_LABELS,
  USER_STATE_LABELS,
  userState,
  type UserCode,
  type UserDetail,
  type UserDevice,
  type UserGroup,
  type UserObservation,
} from '@/modules/assets/api/types'
import { Button } from '@/components/ui/Button'
import { FIELD } from '@/components/ui/Field'
import { Spinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { Link } from '@/lib/router'
import { ColGroup, ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'
import { SectionTitle } from './AssetDrawer'

/** Сеанс отключённой и привилегированной учётки — тоном риска, остальное — «внимание». */
const CODE_TEXT: Record<UserCode, string> = {
  disabled_session: 'text-risk-high',
  not_in_ad: 'text-risk-medium',
  privileged_on_workstation: 'text-risk-high',
  owner_without_session: 'text-kind-1',
}

function day(iso: string | null): string {
  return iso ? new Date(iso).toLocaleDateString('ru-RU') : '—'
}

function title(u: { id: number; sam: string; display_name: string; upn: string }): string {
  return u.sam || u.display_name || u.upn || `пользователь #${u.id}`
}

/** Связь с устройством: сеанс на хосте без сбора пользователей считается прошлым (API: users_collected); пропавшая — в прошедшем времени. */
function linkLabel(d: UserDevice): string {
  if (d.gone_at) return d.kind === 'owner' ? 'был владельцем' : d.kind === 'local_group' ? 'был в локальной группе' : d.active ? 'был в системе' : 'заходил раньше'
  if (d.kind === 'owner') return 'владелец'
  if (d.kind === 'local_group') return 'локальная группа'
  return d.active && d.users_collected ? 'в системе на момент сбора' : 'заходил раньше'
}

/** Самое свежее наблюдение AD (`live` — только живое); наблюдений у учётки может быть несколько (домены, пересопоставление). */
function latestAd(u: UserDetail, live: boolean): UserObservation | undefined {
  return u.observations
    .filter((o) => o.source === 'ad' && (!live || !o.gone_at))
    .reduce<UserObservation | undefined>((best, o) => (!best || (o.seen_at ?? '') > (best.seen_at ?? '') ? o : best), undefined)
}

const TAG_MAX = 100

/** Почему строка приглушена или чем оговорена; null — оговорок нет. */
function linkReason(d: UserDevice): string | null {
  if (d.gone_at) return `связь пропала ${day(d.gone_at)}`
  if (d.stale) return 'устарела: пользователи на хосте не собираются, в расхождениях не участвует'
  if (!d.users_collected) return 'пользователи на хосте не собираются'
  return null
}

function Identity({ u }: { u: UserDetail }) {
  const state = userState(u.enabled)
  const adGone = latestAd(u, true) ? undefined : latestAd(u, false)
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
      <dt className="text-text-secondary">Учётка</dt><dd className="font-mono break-all text-text">{u.sam || '—'}</dd>
      <dt className="text-text-secondary">Имя</dt><dd className="text-text">{u.display_name || '—'}</dd>
      <dt className="text-text-secondary">UPN</dt><dd className="font-mono break-all text-text">{u.upn || '—'}</dd>
      <dt className="text-text-secondary">Домен</dt>
      <dd className="text-text">{u.local ? <span>локальная учётка хоста <span className="text-text-secondary">— не склеивается с учётками других хостов</span></span> : <span className="font-mono">{u.domain || '—'}</span>}</dd>
      <dt className="text-text-secondary">SID</dt><dd className="font-mono break-all text-text">{u.sid || '—'}</dd>
      <dt className="text-text-secondary">В AD</dt>
      <dd className={cn(state === 'disabled' ? 'text-risk-medium' : state === 'unknown' ? 'text-text-secondary' : 'text-text')}>
        {USER_STATE_LABELS[state]}
        {state === 'unknown' && <span className="text-text-secondary"> — {adGone ? `AD больше не видит учётку, последний раз ${day(adGone.seen_at)}` : 'AD учётку не видел'}</span>}
      </dd>
      <dt className="text-text-secondary">Привилегированная</dt>
      <dd className={u.privileged ? 'text-risk-high' : 'text-text'}>
        {u.privileged ? 'да' : 'нет'}
        {u.privileged && <span className="text-text-secondary"> — член привилегированных групп по настройкам AD или встроенный администратор</span>}
      </dd>
      <dt className="text-text-secondary">Источники</dt>
      <dd className="text-text">
        {u.sources.length === 0 && '—'}
        {u.sources.map((s, i) => (
          <span key={s.source} className={cn(!s.fresh && 'text-text-secondary')}>
            {i > 0 && ', '}{SOURCE_LABELS[s.source]} {s.live ? `видел ${day(s.seen_at)}${s.fresh ? '' : ' — давно'}` : `больше не видит, последний раз ${day(s.seen_at)}`}
          </span>
        ))}
      </dd>
      <dt className="text-text-secondary">Виден</dt><dd className="text-text">впервые {day(u.first_seen)}, последний раз {day(u.last_seen)}</dd>
    </dl>
  )
}

/** Флаги учётки из живого наблюдения AD (поля выгрузки на момент сбора). */
function AdFlags({ u, onOpenUser }: { u: UserDetail; onOpenUser: (id: number) => void }) {
  const ad = latestAd(u, true)
  if (!ad) return null
  const d = ad.data
  return (
    <>
      <SectionTitle>По AD</SectionTitle>
      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
        <dt className="text-text-secondary">Почта</dt><dd className="break-all text-text">{u.mail || '—'}</dd>
        <dt className="text-text-secondary">Руководитель</dt>
        <dd className="break-words text-text">{u.manager ? <>
          {u.manager.user_id !== null ? <button type="button" className="text-primary underline" onClick={() => { if (u.manager?.user_id != null) onOpenUser(u.manager.user_id) }}>{u.manager.name}</button> : u.manager.name}
          {u.manager.name !== u.manager.dn && <div className="mt-0.5 break-all font-mono text-text-secondary">{u.manager.dn}</div>}
        </> : '—'}</dd>
        <dt className="text-text-secondary">Пароль не истекает</dt><dd className={d.pwd_never_expires ? 'text-risk-medium' : 'text-text'}>{d.pwd_never_expires ? 'да' : 'нет'}</dd>
        <dt className="text-text-secondary">Последний вход</dt><dd className="text-text">{typeof d.last_logon === 'string' ? day(d.last_logon) : 'нет (lastLogonTimestamp пуст)'}</dd>
        <dt className="text-text-secondary">adminCount</dt><dd className="font-mono text-text">{d.admin_count != null ? String(d.admin_count) : '—'}</dd>
        <dt className="text-text-secondary">DN</dt><dd className="font-mono break-all text-text-secondary">{typeof d.dn === 'string' && d.dn ? d.dn : '—'}</dd>
        <dt className="text-text-secondary">Выгрузка</dt><dd className="text-text">{day(ad.seen_at)}</dd>
      </dl>
    </>
  )
}

function GroupList({ groups }: { groups: UserGroup[] }) {
  return (
    <ul className="flex flex-col gap-0.5">
      {groups.map((g) => (
        <li key={g.sid || g.name} className="flex items-baseline justify-between gap-3">
          {/* Ссылка — только на группу с записью в разделе «Группы»; без неё (встроенная чужого домена и т. п.) — текстом. */}
          {g.group_id !== null ? (
            <Link to={`/assets/groups?id=${g.group_id}`} className="min-w-0 break-all text-text hover:text-primary hover:underline">{g.name || g.sid}</Link>
          ) : (
            <span className="min-w-0 break-all text-text">{g.name || g.sid}</span>
          )}
          {g.sid && g.name && <span className="shrink-0 font-mono text-[10px] text-text-secondary">{g.sid}</span>}
        </li>
      ))}
    </ul>
  )
}

function Groups({ u }: { u: UserDetail }) {
  const direct = u.groups.filter((g) => g.direct)
  const nested = u.groups.filter((g) => !g.direct)
  const adLive = latestAd(u, true) !== undefined
  const adSeen = u.observations.some((o) => o.source === 'ad')
  return (
    <>
      <SectionTitle>Группы AD</SectionTitle>
      {u.groups.length === 0 && <p className="text-text-secondary">{adLive ? 'групп нет' : adSeen ? 'AD больше не видит учётку — группы не известны' : 'AD учётку не видел — групп нет'}</p>}
      {direct.length > 0 && (
        <>
          <div className="mt-1 mb-1 text-text-secondary">Прямые, с основной группой ({direct.length})</div>
          <GroupList groups={direct} />
        </>
      )}
      {nested.length > 0 && (
        <>
          <div className="mt-2 mb-1 text-text-secondary">Через вложенные группы ({nested.length})</div>
          <GroupList groups={nested} />
        </>
      )}
      {u.group_notes.length > 0 && (
        <div className="mt-2 rounded border border-grid px-3 py-2 text-text-secondary">
          <div className="mb-0.5 text-kind-1">Оговорка выгрузки AD</div>
          {u.group_notes.map((n) => <p key={n}>{n}</p>)}
        </div>
      )}
    </>
  )
}

// Сумма ширин по умолчанию — 560 px: влезает в содержимое панели без прокрутки (как таблица источников актива).
const DEVICE_COLUMNS: ColumnDef[] = [
  { key: 'name', label: 'Хост', width: 128, flex: true },
  { key: 'ip', label: 'IP', width: 96 },
  { key: 'os', label: 'ОС', width: 112 },
  { key: 'kind', label: 'Связь', width: 136 },
  { key: 'seen', label: 'Видел', width: 88 },
]

function Devices({ u }: { u: UserDetail }) {
  const cols = useColumnWidths('assets-user-devices-columns', DEVICE_COLUMNS)
  return (
    <>
      <SectionTitle>Устройства ({u.devices.length})</SectionTitle>
      {u.devices.length === 0 ? (
        <p className="text-text-secondary">ни сеансов, ни владения по KSC</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-[11px]" style={cols.tableStyle}>
            <ColGroup cols={cols} />
            <thead className="text-text-secondary">
              <tr><ResizableHeader cols={cols} className="px-1.5 py-1" /></tr>
            </thead>
            <tbody>
              {u.devices.map((d, i) => {
                const reason = linkReason(d)
                return (
                  <tr key={`${d.asset_id}:${d.kind}:${i}`} className={cn('border-t border-grid align-top', (d.gone_at || d.stale) && 'opacity-50')}>
                    <td className="truncate px-1.5 py-1" title={d.name}>
                      <Link to={`/assets/list?asset=${d.asset_id}`} className="text-text hover:text-primary hover:underline">{d.name || `актив #${d.asset_id}`}</Link>
                    </td>
                    <td className="truncate px-1.5 py-1 font-mono text-text-secondary" title={d.ip}>{d.ip || '—'}</td>
                    <td className="px-1.5 py-1 break-words text-text-secondary">{d.os || '—'}</td>
                    <td className="px-1.5 py-1 break-words">
                      <div className={d.kind === 'session' && d.active && d.users_collected ? 'text-text' : 'text-text-secondary'}>{linkLabel(d)}</div>
                      {reason && <div className="text-text-secondary">{reason}</div>}
                    </td>
                    <td className="px-1.5 py-1 break-words text-text-secondary">{day(d.seen_at)}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </>
  )
}

function Discrepancies({ u }: { u: UserDetail }) {
  return (
    <>
      <SectionTitle>Расхождения ({u.discrepancies.length})</SectionTitle>
      <ul className="flex flex-col gap-1">
        {u.discrepancies.map((d, i) => (
          <li key={`${d.code}:${d.host_asset_id ?? ''}:${i}`} className="flex items-start gap-2 px-1 py-0.5">
            <span className={cn('shrink-0', CODE_TEXT[d.code])}>{USER_CODE_LABELS[d.code]}</span>
            {d.host_asset_id !== null ? (
              <Link to={`/assets/list?asset=${d.host_asset_id}`} className="min-w-0 flex-1 text-text-secondary hover:text-primary hover:underline">{d.text}</Link>
            ) : (
              <span className="min-w-0 flex-1 text-text-secondary">{d.text}</span>
            )}
          </li>
        ))}
      </ul>
    </>
  )
}

function ManualFields({ u, write }: { u: UserDetail; write: boolean }) {
  const patch = usePatchUser(u.id)
  // Начальные значения — из карточки; после сохранения форма пересоздаётся по updated_at (key у вызова).
  const [tags, setTags] = useState(u.tags.join(', '))
  const [note, setNote] = useState(u.note)
  if (!write) {
    return (
      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
        <dt className="text-text-secondary">Теги</dt><dd className="text-text">{u.tags.length ? u.tags.join(', ') : '—'}</dd>
        <dt className="text-text-secondary">Заметка</dt><dd className="whitespace-pre-line text-text">{u.note || '—'}</dd>
      </dl>
    )
  }
  const tagList = tags.split(',').map((t) => t.trim()).filter(Boolean)
  // API принимает теги не длиннее 100 символов: длинный не отрезается молча, а показывается.
  const tooLong = tagList.filter((t) => t.length > TAG_MAX)
  const dirty = tags !== u.tags.join(', ') || note !== u.note
  // Форма — из нормализованного ответа (обрезанные пробелы, без повторов): после сохранения без изменений «Сохранить» гаснет.
  const save = () => patch.mutate({ tags: tagList, note }, { onSuccess: (r) => { setTags(r.tags.join(', ')); setNote(r.note) } })
  return (
    <div className="flex flex-col gap-2">
      <label className="block">
        <span className="mb-1 block text-text-secondary">Теги через запятую</span>
        <input value={tags} onChange={(e) => setTags(e.target.value)} className={cn(FIELD, 'text-xs')} />
      </label>
      <label className="block">
        <span className="mb-1 block text-text-secondary">Заметка</span>
        <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={2} className={cn(FIELD, 'text-xs')} />
      </label>
      <div className="flex items-center gap-2">
        <Button variant="primary" disabled={!dirty || tooLong.length > 0} loading={patch.isPending} onClick={save}>Сохранить</Button>
        {tooLong.length > 0 && <span className="text-kind-1">тег длиннее {TAG_MAX} символов: {tooLong.map((t) => `${t.slice(0, 24)}…`).join(', ')}</span>}
        {patch.error && <span className="text-kind-1">{patch.error.message}</span>}
      </div>
    </div>
  )
}

/** Карточка пользователя справа: кто по AD, флаги, расхождения, устройства со ссылками на активы, группы AD, ручные поля. */
export function UserDrawer({ userId, onClose, onOpenUser }: { userId: number | null; onClose: () => void; onOpenUser: (id: number) => void }) {
  const open = userId !== null
  const { write } = useCan()
  const detail = useUser(userId)
  const closeRef = useRef<HTMLButtonElement>(null)
  useEffect(() => { if (open) closeRef.current?.focus() }, [open, userId])
  const u = detail.data

  return (
    <>
      <div className={cn('fixed inset-0 z-30 bg-black/50 transition-opacity duration-200', open ? 'opacity-100' : 'pointer-events-none opacity-0')} onClick={onClose} aria-hidden />
      <aside role="dialog" aria-label="Пользователь" aria-hidden={!open} className={cn('fixed top-0 right-0 z-40 flex h-full w-[600px] flex-col border-l border-grid bg-surface transition-transform duration-200', open ? 'translate-x-0' : 'translate-x-full')}>
        {open && (
          <>
            <div className="flex items-center justify-between border-b border-grid px-4 py-3">
              <div className="flex min-w-0 items-center gap-2">
                <User size={16} className="shrink-0 text-text-secondary" aria-hidden />
                <span className="truncate text-sm text-text">{u ? title(u) : `пользователь #${userId}`}</span>
                {u?.display_name && u.sam && <span className="truncate text-xs text-text-secondary">{u.display_name}</span>}
              </div>
              <button ref={closeRef} type="button" onClick={onClose} className="rounded p-1 text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" aria-label="Свернуть (Esc)"><X size={16} aria-hidden /></button>
            </div>
            <div className="flex-1 overflow-y-auto px-4 py-3 text-xs">
              {detail.isLoading && <div className="flex justify-center py-8"><Spinner /></div>}
              {detail.error && <p className="text-kind-1">{detail.error instanceof ApiRequestError ? detail.error.message : 'Не удалось загрузить пользователя'}</p>}
              {u && (
                <>
                  {u.merged_into !== null && (
                    <p className="mb-3 rounded border border-grid px-3 py-2 text-text-secondary">
                      Пользователь объединён с <button type="button" className="text-text underline hover:text-primary" onClick={() => { if (u.merged_into !== null) onOpenUser(u.merged_into) }}>пользователем #{u.merged_into}</button>.
                    </p>
                  )}
                  <Identity u={u} />
                  {u.discrepancies.length > 0 && <Discrepancies u={u} />}
                  <Devices u={u} />
                  <SiemLogons key={u.id} userId={u.id} />
                  <Groups u={u} />
                  <AdFlags u={u} onOpenUser={onOpenUser} />
                  <SectionTitle>Ручные поля</SectionTitle>
                  <ManualFields key={`${u.id}:${u.updated_at}`} u={u} write={write && u.merged_into === null} />
                </>
              )}
            </div>
          </>
        )}
      </aside>
    </>
  )
}
