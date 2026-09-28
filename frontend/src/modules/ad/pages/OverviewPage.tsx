import { useOverview } from '@/modules/ad/api/queries'
import { CollectorOverviewPage } from '@/platform/collector/OverviewPage'

export function OverviewPage({ domainId }: { domainId: number }) {
  const overview = useOverview(domainId)
  return (
    <CollectorOverviewPage
      overview={overview}
      settingsPath="/ad/settings"
      emptyDescription="Загрузите выгрузку скрипта или запустите сбор по LDAP в настройках модуля."
      findingsPath={`/ad/domains/${domainId}/findings`}
      title={(o) => o.domain.dns_root || o.domain.netbios}
      source={(snap) => (snap.source === 'ldap' ? 'сбор по LDAP' : 'выгрузка скрипта')}
      count={(snap) => `объектов ${snap.objects.toLocaleString('ru-RU')}`}
      firstNote=" Это первый снапшот домена."
    />
  )
}
