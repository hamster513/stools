import { useState, type ReactNode } from 'react'
import type { UseMutationResult, UseQueryResult } from '@tanstack/react-query'
import { CheckCircle2, PlugZap, Plus, ServerCog, Trash2, XCircle } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { Section } from './ui'

/** Поля подключения, которые показывает общий список. */
interface ConnectionBase {
  id: number
  title: string
  host: string
  port: number
  username: string
  password_set: boolean
}

type Editing<CI> = CI & { id?: number }
type Patch<CI> = (p: Partial<CI>) => void
type SaveConnection<CI> = () => UseMutationResult<unknown, ApiRequestError, { id?: number; body: CI }>

function Form<CI extends { host: string; password: string }>({ empty, initial, useSaveConnection, fields, onDone, onCancel }: {
  empty: CI
  initial: Editing<CI>
  useSaveConnection: SaveConnection<CI>
  fields: (f: CI, patch: Patch<CI>, initial: Editing<CI>) => ReactNode
  onDone: () => void
  onCancel: () => void
}) {
  const save = useSaveConnection()
  const [f, setF] = useState<CI>({ ...empty, ...initial, password: '' })
  const patch = (p: Partial<CI>) => setF((v) => ({ ...v, ...p }))
  return (
    <div className="rounded border border-grid bg-app-bg p-3">
      <div className="grid gap-3 sm:grid-cols-2">
        {fields(f, patch, initial)}
      </div>
      <div className="mt-3 flex items-center gap-2">
        <Button variant="primary" loading={save.isPending} disabled={!f.host} onClick={() => save.mutate({ id: initial.id, body: f }, { onSuccess: onDone })}>Сохранить</Button>
        <Button onClick={onCancel}>Отмена</Button>
        {save.error && <span className="text-xs text-kind-1">{save.error instanceof ApiRequestError ? save.error.message : 'Не удалось сохранить'}</span>}
      </div>
    </div>
  )
}

/**
 * Подключения онлайн-режима: список, проверка, сбор, правка. Модуль задаёт
 * тексты, ячейки адреса и учётной записи и поля формы.
 * useSaveConnection — хук модуля: форма держит своё состояние сохранения.
 */
export function CollectorConnectionsSection<C extends ConnectionBase, CI extends { host: string; password: string }>({ list, test, collect, remove, useSaveConnection, empty, toForm, fields, title, about, hostHeader, linked, address, account }: {
  list: UseQueryResult<C[], ApiRequestError>
  test: UseMutationResult<{ ok: boolean; message: string }, ApiRequestError, number>
  collect: UseMutationResult<{ job_id: number }, ApiRequestError, number>
  remove: UseMutationResult<void, ApiRequestError, number>
  useSaveConnection: SaveConnection<CI>
  empty: CI
  toForm: (c: C) => Editing<CI>
  fields: (f: CI, patch: Patch<CI>, initial: Editing<CI>) => ReactNode
  title: string
  about: string
  hostHeader: string
  linked: (c: C) => ReactNode
  address: (c: C) => ReactNode
  account: (c: C) => ReactNode
}) {
  // Подключения аудитор видит списком — адрес и учётная запись нужны,
  // чтобы понимать, откуда снапшот; править, проверять и собирать не может.
  const { write } = useCan()
  const [editing, setEditing] = useState<Editing<CI> | null>(null)
  const [testResult, setTestResult] = useState<{ id: number; ok: boolean; message: string } | null>(null)

  return (
    <Section title={title} about={about}>
      {(list.data ?? []).length > 0 && (
        <table className="mb-3 w-full text-xs">
          <thead className="text-[11px] font-semibold tracking-wide text-text-secondary uppercase"><tr><th className="py-1.5 pr-3 text-left">Подключение</th><th className="py-1.5 pr-3 text-left">{hostHeader}</th><th className="py-1.5 pr-3 text-left">Учётная запись</th><th className="py-1.5 text-right"></th></tr></thead>
          <tbody>
            {(list.data ?? []).map((c: C) => (
              <tr key={c.id} className="border-t border-grid align-top">
                <td className="py-2 pr-3 text-text">{c.title || `#${c.id}`}{linked(c)}</td>
                <td className="py-2 pr-3 font-mono text-text-secondary">{address(c)}</td>
                <td className="py-2 pr-3 font-mono text-text-secondary">{account(c)}{c.password_set ? '' : ' (нет пароля)'}</td>
                <td className="py-2 text-right">
                  {write && (
                    <>
                      <div className="whitespace-nowrap">
                        <Button variant="ghost" onClick={() => test.mutate(c.id, { onSuccess: (r) => setTestResult({ id: c.id, ...r }) })} loading={test.isPending}><PlugZap size={13} aria-hidden /> проверить</Button>
                        <Button variant="ghost" onClick={() => collect.mutate(c.id)} loading={collect.isPending} disabled={!c.password_set}><ServerCog size={13} aria-hidden /> собрать</Button>
                        <Button variant="ghost" onClick={() => setEditing(toForm(c))}>изменить</Button>
                        <Button variant="ghost" onClick={() => remove.mutate(c.id)} aria-label="Удалить подключение"><Trash2 size={13} aria-hidden /></Button>
                      </div>
                      {/* Результат проверки — отдельной строкой под кнопками: длинный DN
                          домена или текст ошибки переносится, а не вылезает за блок. */}
                      {testResult?.id === c.id && <div className={cn('mt-1 flex items-start justify-end gap-1 text-[11px] break-words', testResult.ok ? 'text-kind-accepted' : 'text-kind-1')}>{testResult.ok ? <CheckCircle2 size={12} className="mt-0.5 shrink-0" aria-hidden /> : <XCircle size={12} className="mt-0.5 shrink-0" aria-hidden />}<span className="min-w-0 text-left">{testResult.message}</span></div>}
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {write && (editing ? <Form empty={empty} initial={editing} useSaveConnection={useSaveConnection} fields={fields} onDone={() => setEditing(null)} onCancel={() => setEditing(null)} /> : <Button onClick={() => setEditing({ ...empty })}><Plus size={13} aria-hidden /> Добавить подключение</Button>)}
      {collect.data && <p className="mt-2 text-xs text-text-secondary">сбор запущен, задача #{collect.data.job_id} — прогресс на экране «Задачи»</p>}
      {collect.error && <p className="mt-2 text-xs text-kind-1">{collect.error instanceof ApiRequestError ? collect.error.message : 'Сбор не запущен'}</p>}
    </Section>
  )
}
