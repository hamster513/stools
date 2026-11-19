import { when, type Catalog } from './types'

export function SnapshotInfo({ snapshot }: { snapshot: Catalog['mp_vm'] }) {
  return <div className="shrink-0 border-b border-grid px-4 py-2 text-[11px] text-text-secondary">
    {snapshot?.error ? <span role="alert" className="text-kind-1">{snapshot.error}. {snapshot.collected_at ? `Показан снимок от ${when(snapshot.collected_at)}.` : 'Успешного снимка пока нет.'}</span>
      : snapshot?.collected_at ? `Снимок MP VM: ${when(snapshot.collected_at)} · Статусы на момент сбора.` : 'Снимок Docker ещё не получен. Он собирается при синхронизации MaxPatrol VM.'}
  </div>
}
