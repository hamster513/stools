import { useState } from 'react'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { Spinner } from '@/components/ui/Spinner'
import { Link } from '@/lib/router'
import { useCveImages, type CveDetail } from '../../api/cve'

export function CveImages({ data }: { data: CveDetail }) {
  const [offset, setOffset] = useState(0)
  const result = useCveImages(data.id, offset), page = offset === 0 ? data.images : result.data
  if (!data.images.total) return null
  return <section className="space-y-3 rounded border border-grid bg-surface p-4"><h2 className="text-sm font-semibold">Образы с уязвимостью · {data.images.total}</h2><p className="text-xs text-text-secondary">Находки Trivy связаны по исходным идентификаторам и официальным алиасам. Один образ считается один раз.</p>{offset > 0 && result.isPending && <Spinner />}{result.error && <ErrorState message={result.error.message} onRetry={() => result.refetch()} />}<div className="divide-y divide-grid">{page?.items.map(image => <div className="space-y-1 py-2 text-xs" key={image.id}><Link className="break-all font-mono font-semibold text-primary hover:underline" to={`/vm/images/${image.id}`}>{image.repository}</Link><p className="break-all text-text-secondary">{image.digest}</p><p className="break-words">Пакеты: {image.packages.join(', ')}</p><p className="break-words font-mono">{image.identifiers.join(' · ')}</p><p>Риск образа: {image.risk === null ? 'Нет расчёта' : `${image.risk} / 100`}</p></div>)}</div>{data.images.total > 50 && <div className="flex items-center gap-3 text-xs"><Button disabled={!offset} onClick={() => setOffset(Math.max(0, offset-50))}>Назад</Button><span>Страница {offset/50+1}</span><Button disabled={offset+50 >= data.images.total} onClick={() => setOffset(offset+50)}>Далее</Button></div>}</section>
}
