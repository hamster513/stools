import { useEffect } from 'react'
import { Button } from '@/components/ui/Button'
import { Field, FIELD } from '@/components/ui/Field'
import { useLlmModels, useTestLlm } from '@/platform/settings/api/queries'
import type { LlmProvider, LlmTaskAssignment, LlmTaskId, LlmTaskInfo } from '@/platform/settings/api/types'

import { PROVIDER_NAMES } from './llmProviders'

export function LlmTaskCard({ id, info, config, address, catalogAddress, apiKey, hasSavedKey, credentialVersion, onChange }: {
  id: LlmTaskId
  info: LlmTaskInfo
  config: LlmTaskAssignment
  address: string
  catalogAddress: string
  apiKey?: string
  hasSavedKey: boolean
  credentialVersion: string
  onChange: (config: LlmTaskAssignment) => void
}) {
  const test = useTestLlm()
  const remote = config.provider !== 'ollama'
  const hasKey = apiKey === undefined ? hasSavedKey : !!apiKey.trim()
  const matching = remote || address === catalogAddress
  const models = useLlmModels(catalogAddress, config.provider, {
    apiKey, credentialVersion,
    enabled: config.provider === 'ollama' ? !!catalogAddress
      : config.provider === 'openrouter' || (hasSavedKey && apiKey === undefined),
  })
  const names = matching ? (info.kind === 'embedding' && remote ? models.data?.embedding_models : models.data?.models) ?? [] : []
  const resetTest = test.reset
  useEffect(() => { resetTest() }, [config, address, credentialVersion, resetTest])
  function patch(change: Partial<LlmTaskAssignment>) { onChange({ ...config, ...change }) }
  const alias = !remote && !config.model.includes(':') && names.includes(config.model + ':latest')

  return <section aria-labelledby={`${id}-title`} className="rounded border border-grid bg-surface p-4">
    <div className="mb-3 flex items-start justify-between gap-3">
      <div>
        <h2 id={`${id}-title`} className="text-sm font-medium text-text">{info.title}</h2>
        <p className="mt-1 text-xs text-text-secondary">{info.description}</p>
      </div>
      <label className="flex shrink-0 items-center gap-2 text-xs">
        <input type="checkbox" checked={config.enabled} onChange={(e) => patch({ enabled: e.target.checked })} />
        Включена
      </label>
    </div>
    <p className="mb-3 text-xs text-text-secondary">
      Данные: {info.data_class === 'public' ? 'публичные' : info.data_class === 'redacted' ? 'публичные и обезличенные' : 'внутренние, только локально'}.
    </p>
    <div className="grid gap-3 sm:grid-cols-2">
      <Field label="Провайдер">
        <select className={FIELD} value={config.provider}
          onChange={(e) => patch({ provider: e.target.value as LlmProvider, model: '' })}>
          {info.providers.filter((p) => !config.local_only || p === 'ollama').map((p) =>
            <option key={p} value={p}>{PROVIDER_NAMES[p]}</option>)}
        </select>
      </Field>
      <Field label={info.kind === 'embedding' ? 'Модель эмбеддингов' : 'Модель'}>
        <select className={FIELD} value={config.model} onChange={(e) => patch({ model: e.target.value })}
          disabled={!matching || models.isFetching || !names.length}>
          {!config.model && <option value="">Выберите модель</option>}
          {config.model && !names.includes(config.model) && <option value={config.model}>
            {config.model}{alias ? ' (:latest)' : models.isSuccess && matching ? ' — отсутствует в каталоге' : ' — сохранённая'}
          </option>}
          {names.map((name) => <option key={name} value={name}>{name}</option>)}
        </select>
      </Field>
      <Field label="Таймаут, с">
        <input className={FIELD} type="number" min={5} max={1800} value={config.timeout}
          onChange={(e) => patch({ timeout: Number(e.target.value) })} />
      </Field>
      <div className="flex flex-col justify-center gap-2 text-xs">
        <label className="flex items-center gap-2">
          <input type="checkbox" checked={config.local_only} onChange={(e) => patch(e.target.checked
            ? { local_only: true, provider: 'ollama', model: remote ? '' : config.model } : { local_only: false })} />
          Только локально
        </label>
        {info.kind === 'completion' && <label className="flex items-center gap-2">
          <input type="checkbox" checked={config.think} onChange={(e) => patch({ think: e.target.checked })} />
          Режим рассуждения
        </label>}
      </div>
    </div>
    <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
      <Button variant="ghost" loading={models.isFetching}
        disabled={!matching || (config.provider === 'ollama' ? !address : config.provider === 'deepseek' && !hasKey)}
        onClick={() => { void models.refetch() }}>Обновить модели</Button>
      <Button loading={test.isPending} disabled={!config.model.trim() || (remote ? !hasKey : !address)}
        onClick={() => test.mutate({ task: id, assignment: config, base_url: address, api_key: apiKey })}>
        Проверить подключение
      </Button>
      {test.data && <span role="status" className={test.data.ok ? 'text-kind-accepted' : 'text-kind-1'}>
        {test.data.ok ? `${info.kind === 'embedding' ? 'Эмбеддинг получен' : 'Модель ответила'} за ${test.data.latency_ms} мс` : test.data.error}
      </span>}
      {test.isError && <span role="alert" className="text-kind-1">{test.error.message}</span>}
    </div>
    {remote && !hasKey && <p className="mt-2 text-xs text-text-secondary">Добавьте API-ключ провайдера в блоке подключений.</p>}
    {matching && models.isError && <p role="alert" className="mt-2 text-xs text-kind-1">{models.error.message}</p>}
    {matching && models.isSuccess && !names.length && <p className="mt-2 text-xs text-text-secondary">В каталоге нет моделей для этой задачи.</p>}
  </section>
}
