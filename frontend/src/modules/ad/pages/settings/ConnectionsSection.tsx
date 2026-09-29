import { useCollect, useConnections, useDeleteConnection, useSaveConnection, useTestConnection } from '@/modules/ad/api/queries'
import type { Connection, ConnectionIn } from '@/modules/ad/api/types'
import { CollectorConnectionsSection } from '@/platform/collector/ConnectionsSection'
import { Field, FIELD } from '@/platform/collector/ui'

const EMPTY: ConnectionIn = { title: '', host: '', port: 636, use_ssl: true, verify_tls: true, username: '', password: '', base_dn: '', collect_sysvol: true, page_size: 500, pause_ms: 500 }

// Пустое числовое поле — NaN, а не 0: уходит как null, и API отвечает русским текстом о допустимых границах,
// вместо того чтобы молча сохранить ноль.
const numberOrEmpty = (value: string) => (value === '' ? NaN : Number(value))
const shown = (value: number) => (Number.isNaN(value) ? '' : value)

export function ConnectionsSection() {
  const list = useConnections()
  const test = useTestConnection()
  const collect = useCollect()
  const remove = useDeleteConnection()
  return (
    <CollectorConnectionsSection<Connection, ConnectionIn>
      list={list}
      test={test}
      collect={collect}
      remove={remove}
      useSaveConnection={useSaveConnection}
      empty={EMPTY}
      toForm={(c) => ({ ...c, password: '' })}
      title="Подключения к доменам (онлайн-режим)"
      about="Модуль читает домен сам: объекты и дескрипторы по LDAP/LDAPS, GptTmpl.inf по SMB. Нужен сетевой доступ от сервера STools к контроллеру (389/636 и 445) и учётная запись с правами чтения. Пароль хранится в базе и наружу не показывается."
      hostHeader="Контроллер"
      linked={(c) => !!c.domain_id && <span className="ml-1 text-[10px] text-text-secondary">· домен связан</span>}
      address={(c) => <>{c.use_ssl ? 'ldaps' : 'ldap'}://{c.host}:{c.port}{c.collect_sysvol ? ' + SMB' : ''}</>}
      account={(c) => c.username}
      fields={(f, patch, initial) => (
        <>
          <Field label="Название" hint="Как показывать в списке"><input className={FIELD} value={f.title} onChange={(e) => patch({ title: e.target.value })} /></Field>
          <Field label="Контроллер домена" hint="Имя или адрес; LDAPS 636 по умолчанию"><input className={FIELD} value={f.host} onChange={(e) => patch({ host: e.target.value })} spellCheck={false} /></Field>
          <Field label="Порт"><input className={FIELD} type="number" value={f.port} onChange={(e) => patch({ port: Number(e.target.value) })} /></Field>
          <Field label="Учётная запись" hint={'Формат имя@домен, например svc_stools@corp.example.ru, или ДОМЕН\\имя, например CORP\\svc_stools (обратный слеш один). Для имя@домен включите LDAPS (порт 636): пароль передаётся внутри TLS.'}><input className={FIELD} value={f.username} onChange={(e) => patch({ username: e.target.value })} spellCheck={false} autoComplete="off" /></Field>
          <Field label="Пароль" hint={initial.id ? 'пусто — оставить прежний' : undefined}><input className={FIELD} type="password" value={f.password} onChange={(e) => patch({ password: e.target.value })} autoComplete="new-password" /></Field>
          <Field label="Base DN" hint="Пусто — defaultNamingContext из rootDSE"><input className={FIELD} value={f.base_dn} onChange={(e) => patch({ base_dn: e.target.value })} spellCheck={false} /></Field>
          <Field label="Объектов в странице LDAP" hint="От 50 до 1000. Щадит контроллер: меньше страница и больше пауза — дольше сбор"><input className={FIELD} type="number" min={50} max={1000} value={shown(f.page_size)} onChange={(e) => patch({ page_size: numberOrEmpty(e.target.value) })} /></Field>
          <Field label="Пауза между запросами к контроллеру, мс" hint="От 0 до 10000. Щадит контроллер: меньше страница и больше пауза — дольше сбор"><input className={FIELD} type="number" min={0} max={10000} step={100} value={shown(f.pause_ms)} onChange={(e) => patch({ pause_ms: numberOrEmpty(e.target.value) })} /></Field>
          <div className="flex flex-col gap-2 pt-1">
            <label className="flex items-center gap-2 text-xs text-text"><input type="checkbox" className="accent-primary" checked={f.use_ssl} onChange={(e) => patch({ use_ssl: e.target.checked })} /> LDAPS</label>
            <label className="flex items-center gap-2 text-xs text-text"><input type="checkbox" className="accent-primary" checked={f.verify_tls} onChange={(e) => patch({ verify_tls: e.target.checked })} /> Проверять сертификат</label>
            {!f.verify_tls && <span className="text-[11px] text-risk-medium">Сертификат контроллера проверяться не будет: подключение уязвимо к подмене. Выключайте только для внутреннего CA, которому контейнер не доверяет.</span>}
            <label className="flex items-center gap-2 text-xs text-text"><input type="checkbox" className="accent-primary" checked={f.collect_sysvol} onChange={(e) => patch({ collect_sysvol: e.target.checked })} /> Читать SYSVOL по SMB (User Rights Assignment)</label>
          </div>
        </>
      )}
    />
  )
}
