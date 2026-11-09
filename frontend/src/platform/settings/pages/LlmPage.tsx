import { useEffect, useId, useState } from 'react'
import { Save } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { Field, FIELD } from '@/components/ui/Field'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { useLlm, useSaveLlm } from '@/platform/settings/api/queries'
import type { LlmSettings, LlmTaskId } from '@/platform/settings/api/types'
import { LlmTaskCard } from './LlmTaskCard'
import { PROVIDER_NAMES } from './llmProviders'

export function LlmPage() {
  const llm = useLlm()
  if (llm.isError) return <div className="p-6"><ErrorState message={llm.error.message} onRetry={() => llm.refetch()} /></div>
  if (!llm.data) return <FullPageSpinner />
  return <LlmEditor initial={llm.data} />
}

function LlmEditor({ initial }: { initial: LlmSettings }) {
  const save = useSaveLlm()
  const [form, setForm] = useState(initial)
  const [dirty, setDirty] = useState(false)
  const [saved, setSaved] = useState(false)
  const [revisions, setRevisions] = useState({ openrouter: 0, deepseek: 0 })
  const catalogId = useId()
  const address = form.base_url.trim().replace(/\/+$/, '')
  const [catalogAddress, setCatalogAddress] = useState(address)
  useEffect(() => {
    const timer = setTimeout(() => setCatalogAddress(address), 400)
    return () => clearTimeout(timer)
  }, [address])
  function patch(change: Partial<LlmSettings>) {
    setForm((prev) => ({ ...prev, ...change }))
    setDirty(true)
    setSaved(false)
  }
  function updateKey(provider: 'openrouter' | 'deepseek', value: string | undefined) {
    patch({ key_updates: { ...form.key_updates, [provider]: value } })
    setRevisions((prev) => ({ ...prev, [provider]: prev[provider] + 1 }))
  }
  function submit() {
    save.mutate(form, { onSuccess: () => {
      const keys = { ...form.api_keys }
      for (const [provider, value] of Object.entries(form.key_updates ?? {})) {
        if (value !== undefined) keys[provider] = !!value.trim()
      }
      setForm({ ...form, api_keys: keys, api_key: undefined, key_updates: undefined })
      setRevisions((prev) => ({ openrouter: prev.openrouter + 1, deepseek: prev.deepseek + 1 }))
      setDirty(false)
      setSaved(true)
    } })
  }

  return <div className="h-full overflow-y-auto p-6">
    <div className="mb-5 flex items-start justify-between gap-4">
      <div>
        <h1 className="text-base font-semibold text-text">Модели ИИ по задачам</h1>
        <p className="mt-1 max-w-3xl text-xs text-text-secondary">
          Публичные и обезличенные данные можно обрабатывать внешними моделями. Внутренние данные — только локально.
          При недоступности выбранной модели задача сообщает об ошибке; автоматической смены провайдера нет.
        </p>
      </div>
      <div className="flex items-center gap-2">
        {saved && !dirty && <span role="status" className="text-xs text-kind-accepted">Сохранено</span>}
        <Button variant="primary" loading={save.isPending} disabled={!dirty} onClick={submit}><Save size={14} />Сохранить</Button>
      </div>
    </div>
    {save.isError && <p role="alert" className="mb-4 text-xs text-kind-1">{save.error.message}</p>}
    <fieldset disabled={save.isPending} className="max-w-6xl space-y-5">
      <section aria-labelledby="llm-connections">
        <h2 id="llm-connections" className="mb-3 text-sm font-medium">Подключения к провайдерам</h2>
        <div className="grid gap-3 lg:grid-cols-3">
          <div className="rounded border border-grid bg-surface p-4">
            <Field label="Адрес Ollama" hint="Сервер для локальной генерации и эмбеддингов. Например http://ollama:11434.">
              <input className={FIELD} value={form.base_url} spellCheck={false} placeholder="http://хост:11434"
                onChange={(e) => patch({ base_url: e.target.value })} />
            </Field>
          </div>
          {(['openrouter', 'deepseek'] as const).map((provider) => {
            const removed = form.key_updates?.[provider] === ''
            const hasKey = !!form.api_keys?.[provider] && !removed
            return <div key={provider} className="rounded border border-grid bg-surface p-4">
              <Field label={`API-ключ ${PROVIDER_NAMES[provider]}`} hint={removed ? 'Ключ будет удалён при сохранении.' : hasKey
                ? 'Ключ сохранён. Пустое поле использует сохранённый ключ.' : 'Введите ключ, затем обновите модели в нужной задаче.'}>
                <input className={FIELD} type="password" autoComplete="new-password" value={form.key_updates?.[provider] ?? ''}
                  placeholder={hasKey ? 'Сохранённый ключ' : 'API-ключ'} onChange={(e) => updateKey(provider, e.target.value || undefined)} />
              </Field>
              {form.api_keys?.[provider] && <Button variant="ghost" onClick={() => updateKey(provider, removed ? undefined : '')}>
                {removed ? 'Отменить удаление' : 'Удалить ключ при сохранении'}
              </Button>}
            </div>
          })}
        </div>
      </section>
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={form.enabled} onChange={(e) => patch({ enabled: e.target.checked })} />
        Обращения к моделям разрешены
      </label>
      {!form.enabled && <p className="text-xs text-text-secondary">Автоматическая обработка моделями выключена. Настройки сохранены; ручная проверка подключения доступна.</p>}
      <div className="grid items-start gap-4 xl:grid-cols-2">
        {(Object.keys(form.task_catalog ?? {}) as LlmTaskId[]).map((id) => {
          const config = form.tasks?.[id]
          const info = form.task_catalog?.[id]
          if (!config || !info) return null
          const provider = config.provider
          return <LlmTaskCard key={id} id={id} info={info} config={config} address={address} catalogAddress={catalogAddress}
            apiKey={provider === 'ollama' ? undefined : form.key_updates?.[provider]}
            hasSavedKey={!!form.api_keys?.[provider]}
            credentialVersion={`${catalogId}-${provider}-${provider === 'ollama' ? 0 : revisions[provider]}`}
            onChange={(next) => patch({ tasks: { ...form.tasks!, [id]: next } })} />
        })}
      </div>
      <p className="text-xs text-text-secondary">
        Проверка использует выбранную модель и введённые параметры до сохранения. Для эмбеддингов проверяется получение вектора.
        Внешние тестовые запросы тарифицируются провайдером; у бесплатных моделей действуют лимиты.
      </p>
    </fieldset>
  </div>
}
