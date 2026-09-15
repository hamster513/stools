import { useState } from 'react'
import { CheckCircle2, PlugZap, Plus, ServerCog, Trash2, XCircle } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useCollect, useConnections, useDeleteConnection, useSaveConnection, useTestConnection } from '@/modules/ad/api/queries'
import type { Connection, ConnectionIn } from '@/modules/ad/api/types'
import { Button } from '@/components/ui/Button'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { Field, FIELD, Section } from './ui'

const EMPTY: ConnectionIn = { title: '', host: '', port: 636, use_ssl: true, verify_tls: true, username: '', password: '', base_dn: '', collect_sysvol: true }

function Form({ initial, onDone, onCancel }: { initial: ConnectionIn & { id?: number }; onDone: () => void; onCancel: () => void }) {
  const save = useSaveConnection()
  const [f, setF] = useState<ConnectionIn>({ ...EMPTY, ...initial, password: '' })
  const patch = (p: Partial<ConnectionIn>) => setF((v) => ({ ...v, ...p }))
  return (
    <div className="rounded border border-grid bg-app-bg p-3">
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Название" hint="Как показывать в списке"><input className={FIELD} value={f.title} onChange={(e) => patch({ title: e.target.value })} /></Field>
        <Field label="Контроллер домена" hint="Имя или адрес; LDAPS 636 по умолчанию"><input className={FIELD} value={f.host} onChange={(e) => patch({ host: e.target.value })} spellCheck={false} /></Field>
        <Field label="Порт"><input className={FIELD} type="number" value={f.port} onChange={(e) => patch({ port: Number(e.target.value) })} /></Field>
        <Field label="Учётная запись" hint="DOMAIN\\user — NTLM, иначе simple bind (например, DN или user@domain)"><input className={FIELD} value={f.username} onChange={(e) => patch({ username: e.target.value })} spellCheck={false} autoComplete="off" /></Field>
        <Field label="Пароль" hint={initial.id ? 'пусто — оставить прежний' : undefined}><input className={FIELD} type="password" value={f.password} onChange={(e) => patch({ password: e.target.value })} autoComplete="new-password" /></Field>
        <Field label="Base DN" hint="Пусто — defaultNamingContext из rootDSE"><input className={FIELD} value={f.base_dn} onChange={(e) => patch({ base_dn: e.target.value })} spellCheck={false} /></Field>
        <div className="flex flex-col gap-2 pt-1">
          <label className="flex items-center gap-2 text-xs text-text"><input type="checkbox" className="accent-primary" checked={f.use_ssl} onChange={(e) => patch({ use_ssl: e.target.checked })} /> LDAPS</label>
          <label className="flex items-center gap-2 text-xs text-text"><input type="checkbox" className="accent-primary" checked={f.verify_tls} onChange={(e) => patch({ verify_tls: e.target.checked })} /> Проверять сертификат</label>
          {!f.verify_tls && <span className="text-[11px] text-risk-medium">Сертификат контроллера проверяться не будет: подключение уязвимо к подмене. Выключайте только для внутреннего CA, которому контейнер не доверяет.</span>}
          <label className="flex items-center gap-2 text-xs text-text"><input type="checkbox" className="accent-primary" checked={f.collect_sysvol} onChange={(e) => patch({ collect_sysvol: e.target.checked })} /> Читать SYSVOL по SMB (User Rights Assignment)</label>
        </div>
      </div>
      <div className="mt-3 flex items-center gap-2">
        <Button variant="primary" loading={save.isPending} disabled={!f.host} onClick={() => save.mutate({ id: initial.id, body: f }, { onSuccess: onDone })}>Сохранить</Button>
        <Button onClick={onCancel}>Отмена</Button>
        {save.error && <span className="text-xs text-kind-1">{save.error instanceof ApiRequestError ? save.error.message : 'Не удалось сохранить'}</span>}
      </div>
    </div>
  )
}

export function ConnectionsSection() {
  // Подключения аудитор видит списком — контроллер и учётная запись нужны,
  // чтобы понимать, откуда снапшот; править, проверять и собирать не может.
  const { write } = useCan()
  const list = useConnections()
  const test = useTestConnection()
  const collect = useCollect()
  const remove = useDeleteConnection()
  const [editing, setEditing] = useState<(ConnectionIn & { id?: number }) | null>(null)
  const [testResult, setTestResult] = useState<{ id: number; ok: boolean; message: string } | null>(null)

  return (
    <Section title="Подключения к доменам (онлайн-режим)" about="Модуль читает домен сам: объекты и дескрипторы по LDAP/LDAPS, GptTmpl.inf по SMB. Нужен сетевой доступ от сервера STools к контроллеру (389/636 и 445) и учётная запись с правами чтения. Пароль хранится в базе и наружу не показывается.">
      {(list.data ?? []).length > 0 && (
        <table className="mb-3 w-full text-xs">
          <thead className="text-[11px] font-semibold tracking-wide text-text-secondary uppercase"><tr><th className="py-1.5 pr-3 text-left">Подключение</th><th className="py-1.5 pr-3 text-left">Контроллер</th><th className="py-1.5 pr-3 text-left">Учётная запись</th><th className="py-1.5 text-right"></th></tr></thead>
          <tbody>
            {(list.data ?? []).map((c: Connection) => (
              <tr key={c.id} className="border-t border-grid align-top">
                <td className="py-2 pr-3 text-text">{c.title || `#${c.id}`}{c.domain_id && <span className="ml-1 text-[10px] text-text-secondary">· домен связан</span>}</td>
                <td className="py-2 pr-3 font-mono text-text-secondary">{c.use_ssl ? 'ldaps' : 'ldap'}://{c.host}:{c.port}{c.collect_sysvol ? ' + SMB' : ''}</td>
                <td className="py-2 pr-3 font-mono text-text-secondary">{c.username}{c.password_set ? '' : ' (нет пароля)'}</td>
                <td className="py-2 text-right whitespace-nowrap">
                  {write && (
                    <>
                      <Button variant="ghost" onClick={() => test.mutate(c.id, { onSuccess: (r) => setTestResult({ id: c.id, ...r }) })} loading={test.isPending}><PlugZap size={13} aria-hidden /> проверить</Button>
                      <Button variant="ghost" onClick={() => collect.mutate(c.id)} loading={collect.isPending} disabled={!c.password_set}><ServerCog size={13} aria-hidden /> собрать</Button>
                      <Button variant="ghost" onClick={() => setEditing({ ...c, password: '' })}>изменить</Button>
                      <Button variant="ghost" onClick={() => remove.mutate(c.id)} aria-label="Удалить подключение"><Trash2 size={13} aria-hidden /></Button>
                      {testResult?.id === c.id && <div className={cn('mt-1 inline-flex items-center gap-1 text-[11px]', testResult.ok ? 'text-kind-accepted' : 'text-kind-1')}>{testResult.ok ? <CheckCircle2 size={12} aria-hidden /> : <XCircle size={12} aria-hidden />} {testResult.message}</div>}
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {write && (editing ? <Form initial={editing} onDone={() => setEditing(null)} onCancel={() => setEditing(null)} /> : <Button onClick={() => setEditing({ ...EMPTY })}><Plus size={13} aria-hidden /> Добавить подключение</Button>)}
      {collect.data && <p className="mt-2 text-xs text-text-secondary">сбор запущен, задача #{collect.data.job_id} — прогресс на экране «Задачи»</p>}
      {collect.error && <p className="mt-2 text-xs text-kind-1">{collect.error instanceof ApiRequestError ? collect.error.message : 'Сбор не запущен'}</p>}
    </Section>
  )
}
