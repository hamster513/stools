import {
  useCollect, useConnections, useDeleteConnection, useDeleteConnectionSchedule, useSaveConnection, useSaveConnectionSchedule, useTestConnection,
} from '@/modules/ksc/api/queries'
import type { Connection, ConnectionIn } from '@/modules/ksc/api/types'
import { CollectorConnectionsSection } from '@/platform/collector/ConnectionsSection'
import { Field, FIELD } from '@/platform/collector/ui'

const EMPTY: ConnectionIn = { title: '', host: '', port: 13299, username: '', password: '', verify_tls: true, internal: true, domain: '', skip_policy_contents: false }

const SCHEDULE = {
  useSave: useSaveConnectionSchedule,
  useDelete: useDeleteConnectionSchedule,
  note: 'Запуск откладывается, пока идёт другая задача модуля; без пароля расписание выключается.',
}

export function ConnectionsSection() {
  const list = useConnections()
  const test = useTestConnection()
  const collect = useCollect()
  const remove = useDeleteConnection()
  return (
    <CollectorConnectionsSection<Connection, ConnectionIn>
      storageKey="ksc-connections-columns"
      list={list}
      test={test}
      collect={collect}
      remove={remove}
      useSaveConnection={useSaveConnection}
      schedule={SCHEDULE}
      empty={EMPTY}
      toForm={(c) => ({ ...c, password: '' })}
      title="Подключения к KSC (онлайн-режим)"
      about="Модуль читает KSC сам по Open API (HTTPS, порт 13299). Нужен сетевой доступ от сервера STools к KSC и учётная запись с правом чтения. Пароль хранится в базе и наружу не показывается."
      hostHeader="Сервер"
      linked={(c) => !!c.server_id && <span className="ml-1 text-[10px] text-text-secondary">· сервер связан</span>}
      address={(c) => <>{c.host}:{c.port}</>}
      account={(c) => (c.internal ? c.username : `${c.domain}\\${c.username}`)}
      fields={(f, patch, initial) => (
        <>
          <Field label="Название" hint="Как показывать в списке"><input className={FIELD} value={f.title} onChange={(e) => patch({ title: e.target.value })} /></Field>
          <Field label="Сервер KSC" hint="Имя или адрес; Open API 13299"><input className={FIELD} value={f.host} onChange={(e) => patch({ host: e.target.value })} spellCheck={false} /></Field>
          <Field label="Порт"><input className={FIELD} type="number" value={f.port} onChange={(e) => patch({ port: Number(e.target.value) })} /></Field>
          <Field label="Учётная запись"><input className={FIELD} value={f.username} onChange={(e) => patch({ username: e.target.value })} spellCheck={false} autoComplete="off" /></Field>
          <Field label="Пароль" hint={initial.id ? 'пусто — оставить прежний' : undefined}><input className={FIELD} type="password" value={f.password} onChange={(e) => patch({ password: e.target.value })} autoComplete="new-password" /></Field>
          {!f.internal && <Field label="Домен"><input className={FIELD} value={f.domain} onChange={(e) => patch({ domain: e.target.value })} spellCheck={false} /></Field>}
          <div className="flex flex-col gap-2 pt-1">
            <label className="flex items-center gap-2 text-xs text-text"><input type="checkbox" className="accent-primary" checked={f.internal} onChange={(e) => patch({ internal: e.target.checked })} /> Внутренняя учётная запись KSC</label>
            <label className="flex items-center gap-2 text-xs text-text"><input type="checkbox" className="accent-primary" checked={f.verify_tls} onChange={(e) => patch({ verify_tls: e.target.checked })} /> Проверять сертификат</label>
            {!f.verify_tls && <span className="text-[11px] text-risk-medium">Сертификат сервера проверяться не будет: подключение уязвимо к подмене. Выключайте только для внутреннего CA, которому контейнер не доверяет.</span>}
            <label className="flex items-center gap-2 text-xs text-text"><input type="checkbox" className="accent-primary" checked={!f.skip_policy_contents} onChange={(e) => patch({ skip_policy_contents: !e.target.checked })} /> Собирать содержимое политик</label>
            {f.skip_policy_contents && <span className="text-[11px] text-text-secondary">Содержимое политик (замки, настройки) собираться не будет — файл выгрузки заметно меньше.</span>}
          </div>
        </>
      )}
    />
  )
}
