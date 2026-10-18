import { useEffect, useState } from 'react'
import { RotateCcw, Save } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useSaveVmSettings } from '@/modules/vm/api/queries'
import type { SettingsView } from '@/modules/vm/api/types'
import { Button } from '@/components/ui/Button'
import { useCan } from '@/lib/can'
import { Section } from '@/platform/collector/ui'
import { NUM } from './ui'

/** Порог экспозиции для матрицы ATT&CK — отдельно от весов формулы.
 *
 *  Отдельно потому, что это разные решения: веса меняют риск и требуют
 *  пересчёта всех пар, порог матрицы не меняет ни одного числа. Сохранять
 *  его кнопкой «Сохранить и пересчитать» значило бы обещать работу,
 *  которой нет.
 */
export function AttackThresholdSection({ settings }: { settings: SettingsView }) {
  // Порог аудитору виден: по нему собирается матрица, которую он читает.
  const { write } = useCan()
  const save = useSaveVmSettings()
  const [value, setValue] = useState(settings.attack_min_risk)
  const [dirty, setDirty] = useState(false)
  useEffect(() => {
    setValue(settings.attack_min_risk)
    setDirty(false)
  }, [settings.attack_min_risk])

  function submit() {
    // Тело PUT собирается целиком: поля, которых в нём нет, бэкенд
    // возвращает в умолчания. Подключение и веса идут такими, какими
    // они загружены, — секреты форма не видит и присылает пустыми,
    // пустое их не затирает.
    save.mutate(
      {
        connection: {
          host: settings.connection.host,
          api_token: '',
          verify_tls: settings.connection.verify_tls,
          os_exclude: settings.connection.os_exclude,
          pdql_extra: settings.connection.pdql_extra,
          limit: settings.connection.limit,
        },
        weights: settings.weights,
        threshold: settings.threshold,
        attack_min_risk: value,
      },
      { onSuccess: () => setDirty(false) },
    )
  }

  return (
    <Section
      title="Матрица ATT&CK"
      about="Пары хост–CVE с риском не ниже порога считаются экспозицией в матрице ATT&CK. Порог отдельный от порога «требует действия»: очередь работ и способ атаки — разные вопросы, и опустить его до нуля значит объявить экспозицией всё подряд."
    >
      <div className="flex items-center gap-3">
        <label htmlFor="attack-threshold" className="text-xs text-text">Порог риска для матрицы</label>
        <input
          id="attack-threshold"
          className={NUM}
          type="number"
          min={0}
          max={100}
          value={value}
          onChange={(e) => {
            setDirty(true)
            setValue(Number(e.target.value))
          }}
          aria-label="Порог риска для матрицы ATT&CK"
          disabled={!write}
        />
        <span className="text-[11px] text-text-secondary">40 — граница High</span>
      </div>
      {write && (
        <div className="mt-4 flex items-center gap-2 border-t border-grid pt-3">
          <Button variant="primary" onClick={submit} loading={save.isPending} disabled={!dirty}>
            <Save size={13} aria-hidden /> Сохранить
          </Button>
          <Button
            onClick={() => {
              setDirty(true)
              setValue(settings.defaults.attack_min_risk)
            }}
          >
            <RotateCcw size={13} aria-hidden /> По умолчанию
          </Button>
          {save.error && (
            <span className="text-xs text-kind-1">
              {save.error instanceof ApiRequestError ? save.error.message : 'Не удалось сохранить'}
            </span>
          )}
          <span className="text-xs text-text-secondary">
            Пересчёт риска не нужен: слой матрицы пересобирается сам, когда видит новый порог.
          </span>
        </div>
      )}
    </Section>
  )
}
