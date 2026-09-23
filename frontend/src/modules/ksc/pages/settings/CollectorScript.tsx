import { Download } from 'lucide-react'
import { Section } from './ui'

/** Офлайн-режим: скрипт для машины внутри сети с доступом к серверу KSC. */
export function CollectorScript() {
  return (
    <Section
      title="Скрипт для машины внутри сети"
      about="Офлайн-режим: скрипт запускается на любой Windows-машине с доступом к серверу KSC по порту 13299 (PowerShell 5.1+), от учётной записи KSC с правом чтения. Ничего не меняет: вызывает Open API и пишет один файл .json.gz."
    >
      <ol className="mb-3 list-decimal space-y-1 pl-5 text-xs text-text-secondary">
        <li>Скачайте скрипт и перенесите на машину с доступом к серверу KSC.</li>
        <li>
          Запустите в PowerShell: <code className="rounded border border-grid bg-app-bg px-1.5 py-0.5 font-mono text-[11px] text-text">.\STools-KSC-Collector.ps1 -Server ksc01.corp.local -User audit</code>
          {' '}(параметры: <span className="font-mono">-Port</span>, <span className="font-mono">-OutputPath</span>, <span className="font-mono">-SkipTlsCheck</span>, <span className="font-mono">-SkipProducts</span>; пароль спросит сам). Все параметры, пароль и секрет второго фактора можно держать в файле: шаблон создаёт <span className="font-mono">-InitConfig</span>, запуск по нему — <span className="font-mono">-ConfigPath</span>, удалить файл после сбора — <span className="font-mono">-DeleteConfigAfterRun</span>.
        </li>
        <li>Загрузите полученный файл в блоке ниже. Один и тот же файл можно загружать повторно — будет второй снапшот.</li>
      </ol>
      <a href="/api/ksc/collector.ps1" className="inline-flex items-center gap-1.5 rounded border border-border px-3 py-1.5 text-sm text-text hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring">
        <Download size={14} aria-hidden /> Скачать STools-KSC-Collector.ps1
      </a>
    </Section>
  )
}
