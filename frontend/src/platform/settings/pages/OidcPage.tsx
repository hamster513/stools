import { useEffect, useRef, useState } from 'react'
import { CheckCircle2, Copy, PlugZap, Save, Trash2, XCircle } from 'lucide-react'
import type { Role } from '@/api/auth'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { Field, FIELD } from '@/components/ui/Field'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { cn } from '@/lib/cn'
import { useOidcSettings, useSaveOidc, useTestOidc } from '@/platform/settings/api/queries'
import { ROLE_TITLES, type OidcSettings, type OidcSettingsInput } from '@/platform/settings/api/types'

const ROLES: Role[] = ['admin', 'analyst', 'auditor']

/** Что уходит на сервер: маска секрета и собранный им же адрес возврата
 *  ему не нужны. */
function payload(form: OidcSettings): OidcSettingsInput {
  return {
    enabled: form.enabled,
    display_name: form.display_name,
    public_url: form.public_url,
    issuer_url: form.issuer_url,
    client_id: form.client_id,
    client_secret: form.client_secret,
    scopes: form.scopes,
    groups_claim: form.groups_claim,
    login_claim: form.login_claim,
    name_claim: form.name_claim,
    group_roles: form.group_roles,
  }
}

/**
 * Вход через провайдера OpenID Connect — Avanpost FAM или любой другой.
 *
 * Роль за учёткой не хранится: её задаёт таблица «группа → роль», по
 * которой роль пересчитывается на каждом входе. Поэтому таблица здесь
 * не второстепенная настройка, а главное: без единой строки вход
 * включить нельзя — иначе вошедшему нечего было бы разрешить.
 */
export function OidcPage() {
  const oidc = useOidcSettings()
  const save = useSaveOidc()
  const test = useTestOidc()

  const [form, setForm] = useState<OidcSettings | null>(null)
  const [dirty, setDirty] = useState(false)
  const [saved, setSaved] = useState(false)
  const [group, setGroup] = useState('')
  const [role, setRole] = useState<Role>('analyst')
  const [copied, setCopied] = useState(false)
  const redirect = useRef<HTMLInputElement>(null)

  // Секрет в форму не переносится: сервер отдаёт вместо него маску, а
  // пустое поле означает «оставить прежний».
  useEffect(() => {
    if (oidc.data) setForm({ ...oidc.data, client_secret: '' })
  }, [oidc.data])

  if (oidc.isError) {
    return (
      <div className="p-6">
        <ErrorState
          message={oidc.error?.message ?? 'Не удалось загрузить настройки входа'}
          onRetry={() => oidc.refetch()}
        />
      </div>
    )
  }
  if (!form) return <FullPageSpinner />

  function edit(update: (prev: OidcSettings) => OidcSettings) {
    setDirty(true)
    setSaved(false)
    // Правка адреса STools меняет и адрес возврата: отметка «скопирован»
    // после этого относилась бы к чужой строке.
    setCopied(false)
    setForm((prev) => (prev ? update(prev) : prev))
  }

  function patch(change: Partial<OidcSettings>) {
    edit((prev) => ({ ...prev, ...change }))
  }

  function addMapping() {
    const name = group.trim()
    if (name === '') return
    edit((prev) => ({ ...prev, group_roles: [...prev.group_roles, { group: name, role }] }))
    setGroup('')
  }

  function submit() {
    if (!form) return
    save.mutate(payload(form), {
      onSuccess: () => {
        setDirty(false)
        setSaved(true)
        // Перечитывание делает сама мутация: адрес возврата собирает
        // сервер из public_url, а признак заданного секрета мог измениться
        // только что — показывать дальше отправленное было бы враньём.
      },
    })
  }

  async function copyRedirect() {
    if (!form) return
    try {
      await navigator.clipboard.writeText(form.redirect_uri)
      setCopied(true)
    } catch {
      // Буфер бывает закрыт (нет https, отказ в разрешении) — тогда хотя бы
      // выделяем адрес, чтобы его скопировали руками.
      redirect.current?.select()
    }
  }

  const result = test.data

  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-5 flex items-start justify-between gap-4">
        <div>
          <h1 className="text-base font-semibold text-text">Вход по OIDC</h1>
          <p className="max-w-2xl text-xs text-text-secondary">
            Вход через Avanpost FAM или другого провайдера OpenID Connect. Вход по паролю при этом
            остаётся: он нужен, пока провайдер настраивается, и на случай, когда он недоступен.
          </p>
        </div>
      </div>

      <div className="grid max-w-2xl gap-5">
        <section className="rounded border border-grid bg-surface p-4">
          <div className="grid gap-3">
            <label className="flex items-center gap-2 text-xs text-text">
              <input
                type="checkbox"
                checked={form.enabled}
                onChange={(e) => patch({ enabled: e.target.checked })}
              />
              <span>Вход через провайдера включён</span>
            </label>
            <p className="text-xs text-text-secondary">
              Включить не выйдет, пока не заполнены адрес STools, адрес провайдера, идентификатор
              и секрет клиента и хотя бы одно соответствие групп ролям.
            </p>

            <Field label="Название провайдера" hint="Так подписана кнопка на странице входа">
              <input
                className={FIELD}
                value={form.display_name}
                onChange={(e) => patch({ display_name: e.target.value })}
              />
            </Field>

            <Field
              label="Адрес STools"
              hint="Внешний адрес, по которому сюда заходят. Из него собран адрес возврата."
            >
              <input
                className={FIELD}
                value={form.public_url}
                onChange={(e) => patch({ public_url: e.target.value })}
                placeholder="https://stools.example.ru"
                spellCheck={false}
              />
            </Field>

            <Field label="Адрес возврата" hint="Его нужно зарегистрировать в провайдере">
              <div className="flex items-center gap-2">
                <input
                  ref={redirect}
                  className={cn(FIELD, 'font-mono text-xs')}
                  value={form.redirect_uri}
                  readOnly
                  spellCheck={false}
                  aria-label="Адрес возврата"
                />
                <Button onClick={copyRedirect} disabled={form.redirect_uri === ''}>
                  <Copy size={14} aria-hidden />
                  Скопировать
                </Button>
                {copied && <span className="text-xs whitespace-nowrap text-kind-accepted">скопирован</span>}
              </div>
            </Field>

            <Field label="Адрес провайдера" hint="Издатель (issuer): по нему читается его описание">
              <input
                className={FIELD}
                value={form.issuer_url}
                onChange={(e) => patch({ issuer_url: e.target.value })}
                placeholder="https://fam.example.ru"
                spellCheck={false}
              />
            </Field>

            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Идентификатор клиента">
                <input
                  className={FIELD}
                  value={form.client_id}
                  onChange={(e) => patch({ client_id: e.target.value })}
                  spellCheck={false}
                />
              </Field>
              <Field label="Секрет клиента" hint="Пусто — оставить прежний">
                <input
                  className={FIELD}
                  type="password"
                  autoComplete="off"
                  value={form.client_secret}
                  onChange={(e) => patch({ client_secret: e.target.value })}
                  placeholder={form.has_secret ? 'задан' : 'не задан'}
                />
              </Field>
            </div>

            <div className="mt-1 flex flex-wrap items-center gap-3 border-t border-grid pt-3">
              <Button
                onClick={() => test.mutate({ issuer_url: form.issuer_url.trim() })}
                loading={test.isPending}
                disabled={form.issuer_url.trim() === ''}
              >
                <PlugZap size={14} aria-hidden />
                Проверить
              </Button>
              <Button variant="primary" onClick={submit} loading={save.isPending} disabled={!dirty}>
                <Save size={14} aria-hidden />
                Сохранить
              </Button>
              {saved && !dirty && (
                <span className="inline-flex items-center gap-1.5 text-xs text-kind-accepted">
                  <CheckCircle2 size={14} aria-hidden />
                  сохранено
                </span>
              )}
              {save.isError && <span className="text-xs text-kind-1">{save.error.message}</span>}
              {test.isError && <span className="text-xs text-kind-1">{test.error.message}</span>}
              {result && (
                <span
                  className={cn(
                    'inline-flex items-center gap-1.5 text-xs',
                    result.ok ? 'text-kind-accepted' : 'text-kind-1',
                  )}
                >
                  {result.ok ? <CheckCircle2 size={14} aria-hidden /> : <XCircle size={14} aria-hidden />}
                  {result.ok
                    ? `${result.issuer}, подписных ключей: ${result.keys}`
                    : result.error}
                </span>
              )}
            </div>
            {result?.ok && result.endpoints && (
              <dl className="grid grid-cols-[7rem_1fr] gap-x-3 gap-y-1 font-mono text-xs text-text-secondary">
                <dt>авторизация</dt>
                <dd className="break-all">{result.endpoints.authorization}</dd>
                <dt>токены</dt>
                <dd className="break-all">{result.endpoints.token}</dd>
                <dt>ключи</dt>
                <dd className="break-all">{result.endpoints.jwks}</dd>
                <dt>профиль</dt>
                <dd className="break-all">{result.endpoints.userinfo ?? '—'}</dd>
              </dl>
            )}
            <p className="text-xs text-text-secondary">
              Проверка идёт по адресу из поля выше, а не по сохранённому, и без секрета: читается
              описание провайдера и его подписные ключи.
            </p>
          </div>
        </section>

        <section className="rounded border border-grid bg-surface p-4">
          <h2 className="mb-1 text-sm font-semibold text-text">Группы и роли</h2>
          <p className="mb-4 text-xs text-text-secondary">
            Роль не хранится за учёткой — она пересчитывается из групп провайдера на каждом входе.
            Если групп несколько, побеждает старшая роль. Не попавший ни в одно соответствие войти
            не сможет.
          </p>

          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-grid text-left text-[11px] tracking-wide text-text-secondary uppercase">
                <th className="py-1.5 pr-3 font-medium">Группа в провайдере</th>
                <th className="py-1.5 pr-3 font-medium">Роль в STools</th>
                <th className="py-2" />
              </tr>
            </thead>
            <tbody>
              {form.group_roles.map((mapping, index) => (
                <tr key={index} className="border-b border-grid">
                  <td className="py-1.5 pr-3">
                    <input
                      className={FIELD}
                      value={mapping.group}
                      spellCheck={false}
                      aria-label={`Группа ${index + 1}`}
                      onChange={(e) =>
                        edit((prev) => ({
                          ...prev,
                          group_roles: prev.group_roles.map((g, i) =>
                            i === index ? { ...g, group: e.target.value } : g,
                          ),
                        }))
                      }
                    />
                  </td>
                  <td className="py-1.5 pr-3">
                    <select
                      className={FIELD}
                      value={mapping.role}
                      aria-label={`Роль для группы ${mapping.group}`}
                      onChange={(e) =>
                        edit((prev) => ({
                          ...prev,
                          group_roles: prev.group_roles.map((g, i) =>
                            i === index ? { ...g, role: e.target.value as Role } : g,
                          ),
                        }))
                      }
                    >
                      {ROLES.map((r) => (
                        <option key={r} value={r}>
                          {ROLE_TITLES[r]}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td className="py-1.5 text-right">
                    <Button
                      variant="ghost"
                      onClick={() =>
                        edit((prev) => ({
                          ...prev,
                          group_roles: prev.group_roles.filter((_, i) => i !== index),
                        }))
                      }
                    >
                      <Trash2 size={14} aria-hidden />
                      удалить
                    </Button>
                  </td>
                </tr>
              ))}
              <tr>
                <td className="py-1.5 pr-3">
                  <input
                    className={FIELD}
                    value={group}
                    onChange={(e) => setGroup(e.target.value)}
                    placeholder="stools-analysts"
                    spellCheck={false}
                    aria-label="Новая группа"
                  />
                </td>
                <td className="py-1.5 pr-3">
                  <select
                    className={FIELD}
                    value={role}
                    aria-label="Роль для новой группы"
                    onChange={(e) => setRole(e.target.value as Role)}
                  >
                    {ROLES.map((r) => (
                      <option key={r} value={r}>
                        {ROLE_TITLES[r]}
                      </option>
                    ))}
                  </select>
                </td>
                <td className="py-1.5 text-right">
                  <Button onClick={addMapping} disabled={group.trim() === ''}>
                    Добавить
                  </Button>
                </td>
              </tr>
            </tbody>
          </table>
        </section>

        <section className="rounded border border-grid bg-surface p-4">
          <h2 className="mb-1 text-sm font-semibold text-text">Claim'ы и scope</h2>
          <p className="mb-4 text-xs text-text-secondary">
            Что запрашивать у провайдера и из каких полей ответа брать группы, логин и имя.
            Значения по умолчанию подходят для FAM.
          </p>

          <div className="grid gap-3">
            <Field label="Scope" hint="Через пробел. Минимум openid, плюс тот, что отдаёт группы.">
              <input
                className={FIELD}
                value={form.scopes}
                onChange={(e) => patch({ scopes: e.target.value })}
                spellCheck={false}
              />
            </Field>
            <div className="grid gap-3 sm:grid-cols-3">
              <Field label="Claim с группами">
                <input
                  className={FIELD}
                  value={form.groups_claim}
                  onChange={(e) => patch({ groups_claim: e.target.value })}
                  spellCheck={false}
                />
              </Field>
              <Field label="Claim с логином">
                <input
                  className={FIELD}
                  value={form.login_claim}
                  onChange={(e) => patch({ login_claim: e.target.value })}
                  spellCheck={false}
                />
              </Field>
              <Field label="Claim с именем">
                <input
                  className={FIELD}
                  value={form.name_claim}
                  onChange={(e) => patch({ name_claim: e.target.value })}
                  spellCheck={false}
                />
              </Field>
            </div>
          </div>
        </section>
      </div>
    </div>
  )
}
