import { Download } from 'lucide-react'
import { Section } from '@/platform/collector/ui'

/** Офлайн-режим: скрипт для доменной машины. */
export function CollectorScript() {
  return (
    <Section
      title="Скрипт для доменной машины"
      about="Офлайн-режим: скрипт запускается на машине в домене с модулем ActiveDirectory (RSAT) от учётной записи с правами чтения, ничего не анализирует и не меняет — только читает объекты, дескрипторы, GptTmpl.inf из SYSVOL и шаблоны сертификатов, и пишет один файл .json.gz."
    >
      <ol className="mb-3 list-decimal space-y-1 pl-5 text-xs text-text-secondary">
        <li>Скачайте скрипт и перенесите на машину в домене.</li>
        <li>
          Запустите в PowerShell: <code className="rounded border border-grid bg-app-bg px-1.5 py-0.5 font-mono text-[11px] text-text">.\STools-AD-Collector.ps1</code>
          {' '}— откроется меню: выгрузка AD целиком или без ACL компьютеров и SYSVOL, данные центра сертификации (настройки и права ЦС, реестр контроллеров, веб-выдача) по отдельности или всё сразу.
          Без вопросов: <span className="font-mono">-Mode AD</span> или <span className="font-mono">-Mode CA -Sections ca,dc,web</span> (ещё <span className="font-mono">-Server</span>, <span className="font-mono">-OutputPath</span>, <span className="font-mono">-Yes</span>).
        </li>
        <li>Загрузите полученные файлы в блоке ниже: выгрузка AD станет снапшотом (повторная загрузка — второй снапшот), файл данных ЦС привяжется к домену и пересчитает последний снапшот.</li>
      </ol>
      <a href="/api/ad/collector.ps1" className="inline-flex items-center gap-1.5 rounded border border-border px-3 py-1.5 text-sm text-text hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring">
        <Download size={14} aria-hidden /> Скачать STools-AD-Collector.ps1
      </a>
    </Section>
  )
}
