import { BundleUpdate } from './BundleUpdate'

/**
 * База ATT&CK — общее достояние платформы: на идентификаторы её техник
 * ссылаются и разметка правил SIEM, и техники VM с AD. Поэтому обновляет
 * её администратор здесь, а не каждый модуль у себя.
 */
export function AttackPage() {
  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-5">
        <h1 className="text-base font-semibold text-text">База ATT&CK</h1>
        <p className="max-w-2xl text-xs text-text-secondary">
          Матрица одна на все модули: её обновление видят и покрытие правилами, и экспозиция.
          Файл разбирается на месте и никуда не отправляется.
        </p>
      </div>
      <div className="max-w-5xl">
        <BundleUpdate />
      </div>
    </div>
  )
}
