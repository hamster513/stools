import { useState } from 'react'
import { Mail, Save } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { Field, FIELD } from '@/components/ui/Field'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { useMail, useSaveMail, useTestMail, type MailInput, type MailSettings } from '../api/mail'

export function MailPage() {
  const query = useMail()
  if (query.isError) return <div className="p-6"><ErrorState message={query.error.message} onRetry={() => query.refetch()} /></div>
  if (!query.data) return <FullPageSpinner />
  return <MailEditor initial={query.data} />
}

function input(settings: MailSettings): MailInput {
  return {
    enabled: settings.enabled, host: settings.host, port: settings.port, security: settings.security,
    from_address: settings.from_address, from_name: settings.from_name,
    auth_enabled: settings.auth_enabled, username: settings.username, timeout: settings.timeout,
  }
}

function MailEditor({ initial }: { initial: MailSettings }) {
  const [form, setForm] = useState<MailInput>(() => input(initial))
  const [hasPassword, setHasPassword] = useState(initial.has_password)
  const [recipient, setRecipient] = useState('')
  const [dirty, setDirty] = useState(false)
  const [saved, setSaved] = useState(false)
  const save = useSaveMail()
  const test = useTestMail()
  const pending = save.isPending || test.isPending
  function patch(change: Partial<MailInput>) {
    setForm((prev) => ({ ...prev, ...change }))
    setDirty(true)
    setSaved(false)
    save.reset()
    test.reset()
  }
  function submit() {
    save.mutate(form, { onSuccess: () => {
      if (form.password !== undefined && form.password !== null) setHasPassword(!!form.password)
      setForm((prev) => ({ ...prev, password: undefined }))
      setDirty(false)
      setSaved(true)
    } })
  }
  return <div className="h-full overflow-y-auto p-6">
    <h1 className="text-base font-semibold text-text">Почта</h1>
    <p className="mt-1 max-w-3xl text-sm text-text-secondary">
      Общий SMTP-сервер для оповещений STools. События и получателей будем настраивать в каждом модуле отдельно.
      Сохранение сервера само по себе не включает оповещения модулей.
    </p>
    <form className="mt-5 max-w-3xl" onSubmit={(e) => { e.preventDefault(); submit() }}>
      <fieldset disabled={pending} className="space-y-5">
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={form.enabled} onChange={(e) => patch({ enabled: e.target.checked })} />
          Разрешить отправку оповещений по почте
        </label>
        <p className="text-xs text-text-secondary">Общий выключатель для всех модулей. Тестовое письмо можно отправить и при выключенных оповещениях.</p>
        <section aria-labelledby="mail-server" className="space-y-4 rounded border border-grid bg-surface p-4">
          <h2 id="mail-server" className="text-sm font-medium">SMTP-сервер</h2>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Сервер" hint="Имя или IP без smtp:// и без порта.">
              <input className={FIELD} value={form.host} required={form.enabled} maxLength={255} placeholder="smtp.example.org"
                autoComplete="off" spellCheck={false} onChange={(e) => patch({ host: e.target.value })} />
            </Field>
            <Field label="Порт" hint="Обычно 587 для STARTTLS, 465 для TLS, 25 для внутреннего relay.">
              <input className={FIELD} type="number" min={1} max={65535} required value={form.port || ''}
                onChange={(e) => patch({ port: Number(e.target.value) })} />
            </Field>
            <Field label="Защита соединения" hint="Сертификат сервера проверяется при STARTTLS и TLS.">
              <select className={FIELD} value={form.security} onChange={(e) => {
                const security = e.target.value as MailInput['security']
                patch({ security, port: security === 'tls' ? 465 : security === 'starttls' ? 587 : 25 })
              }}>
                <option value="starttls">STARTTLS</option><option value="tls">TLS с начала соединения</option>
                <option value="none">Без шифрования (внутренний relay)</option>
              </select>
            </Field>
            <Field label="Таймаут, секунд" hint="Время ожидания ответа SMTP-сервера, от 1 до 60 секунд.">
              <input className={FIELD} type="number" min={1} max={60} required value={form.timeout || ''}
                onChange={(e) => patch({ timeout: Number(e.target.value) })} />
            </Field>
          </div>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={form.auth_enabled} onChange={(e) => patch({ auth_enabled: e.target.checked })} />
            Авторизация на сервере
          </label>
          {form.auth_enabled && <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Пользователь SMTP">
              <input className={FIELD} value={form.username} required maxLength={255} autoComplete="off"
                onChange={(e) => patch({ username: e.target.value })} />
            </Field>
            <Field label="Пароль" hint={hasPassword ? 'Пароль сохранён. Пустое поле оставляет его без изменений.' : 'Пароль ещё не сохранён.'}>
              <input className={FIELD} type="password" autoComplete="new-password" value={form.password ?? ''}
                onChange={(e) => patch({ password: e.target.value || undefined })} />
            </Field>
          </div>}
          {hasPassword && <Button disabled={form.password === ''} onClick={() => patch({ password: '', auth_enabled: false })}>Удалить сохранённый пароль</Button>}
          {form.password === '' && <p role="status" className="text-xs text-text-secondary">Пароль будет удалён после сохранения. Авторизация выключена.</p>}
          <p className="text-xs text-text-secondary">При смене сервера, порта, защиты или пользователя введите пароль заново либо удалите сохранённый.</p>
        </section>
        <section aria-labelledby="mail-sender" className="space-y-4 rounded border border-grid bg-surface p-4">
          <h2 id="mail-sender" className="text-sm font-medium">Отправитель</h2>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Email отправителя" hint="Адрес должен быть разрешён вашим SMTP-сервером.">
              <input className={FIELD} type="email" required={form.enabled} maxLength={254} value={form.from_address}
                placeholder="stools@example.org" onChange={(e) => patch({ from_address: e.target.value })} />
            </Field>
            <Field label="Имя отправителя">
              <input className={FIELD} maxLength={200} value={form.from_name} onChange={(e) => patch({ from_name: e.target.value })} />
            </Field>
          </div>
        </section>
        <div className="flex items-center gap-3">
          <Button type="submit" variant="primary" disabled={!dirty || pending} loading={save.isPending}><Save size={14} />Сохранить</Button>
          {saved && !dirty && <span role="status" className="text-sm text-kind-accepted">Сохранено</span>}
        </div>
      </fieldset>
      {save.isError && <p role="alert" className="mt-3 text-sm text-kind-1">{save.error.message}</p>}
    </form>
    <form className="mt-6 max-w-3xl rounded border border-grid bg-surface p-4" onSubmit={(e) => {
      e.preventDefault(); test.mutate({ settings: form, recipient })
    }}>
      <fieldset disabled={pending} className="space-y-3">
        <h2 className="text-sm font-medium">Тестовое письмо</h2>
        <p className="text-xs text-text-secondary">Проверка использует текущие поля формы, включая несохранённые изменения. Настройки при проверке не сохраняются.</p>
        <Field label="Получатель тестового письма">
          <input className={FIELD} type="email" required maxLength={254} value={recipient} placeholder="you@example.org"
            onChange={(e) => { setRecipient(e.target.value); test.reset() }} />
        </Field>
        <Button type="submit" loading={test.isPending} disabled={pending || !recipient.trim()}><Mail size={14} />Отправить тестовое письмо</Button>
      </fieldset>
      {test.isError && <p role="alert" className="mt-3 text-sm text-kind-1">{test.error.message}</p>}
      {test.data?.accepted && <p role="status" className="mt-3 text-sm text-kind-accepted">SMTP-сервер принял тестовое письмо. Проверьте входящие и папку «Спам»; принятие сервером не гарантирует доставку в ящик.</p>}
    </form>
  </div>
}
