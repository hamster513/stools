import { useEffect, useRef, useState } from 'react'
import { CheckCircle2, Copy, PlugZap, Save, XCircle } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { Field, FIELD } from '@/components/ui/Field'
import { Spinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { Link } from '@/lib/router'
import { useGroups } from '@/platform/settings/api/access'
import { useOidcSettings, useSaveOidc, useTestOidc } from '@/platform/settings/api/queries'
import type { OidcSettings, OidcSettingsInput } from '@/platform/settings/api/types'

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
  }
}

/**
 * Блок «Вход по OIDC» вкладки «Вход» (якорь `#oidc`): вход через
 * провайдера OpenID Connect — Avanpost FAM или любой другой. Прокрутку и
 * отступы задаёт вкладка.
 *
 * Права вошедшего задают группы с источником OIDC: их заводят на странице
 * «Группы», здесь остаётся только подключение к провайдеру. Без единой
 * такой группы вход включить нельзя — иначе вошедшему нечего было бы
 * разрешить; отказ приходит от сервера и показывается как есть.
 */
export function OidcPage() {
  const oidc = useOidcSettings()
  const save = useSaveOidc()
  const test = useTestOidc()
  const groups = useGroups()
  // Читать раздел может и тот, кому платформа открыта на чтение; менять и проверять — её администратор.
  const admin = useCan().platform.admin

  const [form, setForm] = useState<OidcSettings | null>(null)
  const [dirty, setDirty] = useState(false)
  const [saved, setSaved] = useState(false)
  const [copied, setCopied] = useState(false)
  const redirect = useRef<HTMLInputElement>(null)

  // Секрет в форму не переносится: сервер отдаёт вместо него маску, а
  // пустое поле означает «оставить прежний».
  useEffect(() => {
    if (oidc.data) setForm({ ...oidc.data, client_secret: '' })
  }, [oidc.data])

  if (oidc.isError) {
    return (
      <ErrorState
        message={oidc.error?.message ?? 'Не удалось загрузить настройки входа'}
        onRetry={() => oidc.refetch()}
      />
    )
  }
  if (!form) return <Spinner className="mx-auto my-8" />

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
    <section id="oidc" className="scroll-mt-6">
      <div className="mb-5 flex items-start justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-text">Вход по OIDC</h2>
          <p className="max-w-2xl text-xs text-text-secondary">
            Вход через Avanpost FAM или другого провайдера OpenID Connect. Вход по паролю при этом
            остаётся: он нужен, пока провайдер настраивается, и на случай, когда он недоступен.
          </p>
        </div>
        {!admin && <span className="text-xs text-text-secondary">только чтение</span>}
      </div>

      {/* Без права менять форма целиком закрыта: поля, кнопки проверки и сохранения. */}
      <fieldset disabled={!admin} className="grid min-w-0 max-w-2xl gap-5">
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
              и секрет клиента и не заведена хотя бы одна группа из OIDC.
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

        <p className="text-xs text-text-secondary">
          Группы из OIDC настраиваются в разделе{' '}
          <Link to="/settings/access/groups" className="text-primary hover:underline">
            Группы
          </Link>{' '}
          — сейчас их {groups.data ? groups.data.filter((g) => g.source === 'oidc').length : '…'}
        </p>

        <section className="rounded border border-grid bg-surface p-4">
          <h3 className="mb-1 text-sm font-semibold text-text">Claim'ы и scope</h3>
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
      </fieldset>
    </section>
  )
}
