import { useRef, useState } from 'react'
import { Button } from '@/components/ui/Button'
import { FIELD } from '@/components/ui/Field'
import { errorText } from '@/api/client'
import { CopyButton } from '../components/CopyButton'
import { inspectCertificates, type CertificateEncoding, type CertificateResult } from '../api/certificates'

const MAX_BYTES = 1024 * 1024
const AREA = `${FIELD} min-h-40 resize-y font-mono text-xs`
const VALIDITY = { valid: 'Действует', expired: 'Истёк', not_yet_valid: 'Ещё не действует' }
const HOSTNAME = { not_checked: 'Не проверено — имя не задано', match: 'Совпадает с SAN', mismatch: 'Не совпадает с SAN' }

function Value({ label, value }: { label: string; value: string }) {
  return <div className="grid gap-1 border-b border-border py-2 sm:grid-cols-[150px_1fr_auto]">
    <span className="text-text-secondary">{label}</span>
    <span className="min-w-0 whitespace-pre-wrap break-all font-mono">{value || '—'}</span>
    <CopyButton compact text={value} label={`Скопировать ${label}`} />
  </div>
}

/** Explicit submit; data stays in component memory and the local application server. */
export function CertificatesPage() {
  const [data, setData] = useState('')
  const [encoding, setEncoding] = useState<CertificateEncoding>('pem')
  const [hostname, setHostname] = useState('')
  const [roots, setRoots] = useState('')
  const [result, setResult] = useState<CertificateResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const revision = useRef(0)

  function invalidate() {
    revision.current += 1
    setResult(null)
    setError(null)
    setBusy(false)
  }

  async function upload(file: File | undefined, trust: boolean) {
    if (!file) return
    invalidate()
    const current = revision.current
    if (trust) setRoots('')
    else setData('')
    if (file.size > MAX_BYTES) { setError('Файл превышает 1 МиБ.'); return }
    try {
      const bytes = new Uint8Array(await file.arrayBuffer())
      if (revision.current !== current) return
      const text = new TextDecoder().decode(bytes)
      if (trust || text.includes('-----BEGIN ')) {
        if (trust) setRoots(text)
        else { setData(text); setEncoding('pem') }
      } else {
        let binary = ''
        for (const byte of bytes) binary += String.fromCharCode(byte)
        setData(btoa(binary))
        setEncoding('der_base64')
      }
    } catch { if (revision.current === current) setError('Не удалось прочитать файл.') }
  }

  async function analyze() {
    invalidate()
    const current = revision.current
    if (!data.trim()) { setError('Добавьте сертификат.'); return }
    if ((encoding === 'pem' && new TextEncoder().encode(data).length > MAX_BYTES)
      || (encoding === 'der_base64' && data.length > Math.ceil(MAX_BYTES / 3) * 4)
      || new TextEncoder().encode(roots).length > MAX_BYTES) {
      setError('Сертификаты и корни доверия ограничены 1 МиБ каждый.'); return
    }
    setBusy(true)
    try {
      const value = await inspectCertificates(data, encoding, hostname, roots)
      if (revision.current === current) setResult(value)
    } catch (cause) {
      if (revision.current === current) setError(errorText(cause, 'Не удалось проверить сертификат.'))
    } finally { if (revision.current === current) setBusy(false) }
  }

  return <div className="h-full overflow-y-auto p-6">
    <p className="mb-4 max-w-3xl text-xs text-text-secondary">
      Проверка на локальном сервере STools по кнопке «Анализировать». Сертификаты не сохраняются и не отправляются во внешние сервисы.
      Сетевые подключения, загрузка промежуточных сертификатов и проверка отзыва не выполняются. Приватные ключи не принимаются.
    </p>
    <div className="grid gap-4 lg:grid-cols-2">
      <div className="space-y-3">
        <label className="block text-xs text-text">Сертификат / цепочка (первый — серверный, затем промежуточные)
          <textarea className={`${AREA} mt-1`} aria-label="Сертификат / цепочка (первый — серверный, затем промежуточные)" value={data} spellCheck={false} placeholder="-----BEGIN CERTIFICATE-----"
            onChange={(event) => { invalidate(); setData(event.target.value) }} />
        </label>
        <div className="flex flex-wrap gap-3">
          <label className="text-xs text-text">Формат
            <select className={`${FIELD} ml-2 w-auto`} value={encoding} onChange={(event) => { invalidate(); setEncoding(event.target.value as CertificateEncoding) }}>
              <option value="pem">PEM</option><option value="der_base64">DER в Base64</option>
            </select>
          </label>
          <label className="text-xs text-text">Файл PEM / DER, до 1 МиБ
            <input className="mt-1 block text-xs" type="file" accept=".pem,.crt,.cer,.der" onChange={(event) => { void upload(event.target.files?.[0], false); event.target.value = '' }} />
          </label>
        </div>
        <label className="block text-xs text-text">DNS-имя или IP-адрес (необязательно)
          <input className={`${FIELD} mt-1`} value={hostname} maxLength={253} placeholder="server.example.org" onChange={(event) => { invalidate(); setHostname(event.target.value) }} />
        </label>
      </div>
      <div className="space-y-3">
        <label className="block text-xs text-text">Явные корни доверия PEM (необязательно)
          <textarea className={`${AREA} mt-1`} aria-label="Явные корни доверия PEM (необязательно)" value={roots} spellCheck={false} placeholder="Без корней доверие не проверяется"
            onChange={(event) => { invalidate(); setRoots(event.target.value) }} />
        </label>
        <label className="block text-xs text-text">Файл корней PEM, до 1 МиБ
          <input className="mt-1 block text-xs" type="file" accept=".pem,.crt,.cer" onChange={(event) => { void upload(event.target.files?.[0], true); event.target.value = '' }} />
        </label>
        <p className="text-xs text-text-secondary">До 16 сертификатов в каждом PEM-поле. Для проверки TLS-цепочки нужны имя и отдельные корни доверия. Системное хранилище не используется; сертификат из основной цепочки сам по себе не становится доверенным.</p>
      </div>
    </div>
    <div className="my-4 flex gap-3">
      <Button onClick={() => void analyze()} disabled={busy || !data.trim()}>{busy ? 'Проверка…' : 'Анализировать'}</Button>
      <Button variant="secondary" onClick={() => { invalidate(); setData(''); setRoots(''); setHostname(''); setEncoding('pem') }}>Очистить</Button>
    </div>
    {error && <p role="alert" className="mb-4 rounded border border-kind-1/40 p-3 text-sm text-kind-1">{error}</p>}
    {!result && !error && !busy && <p className="text-xs text-text-secondary">Добавьте сертификат и нажмите «Анализировать». Результат сбрасывается при изменении ввода.</p>}
    {result && <div className="space-y-4 text-xs text-text">
      <div role="status" className="space-y-2 rounded border border-border p-3">
        <p>Разбор: выполнен ({result.certificates.length}).</p>
        <p>Имя: {HOSTNAME[result.hostname.status]}{result.hostname.value && ` — ${result.hostname.value}`}.</p>
        <p>Доверие: {result.trust.message}{result.trust.chain_length && ` Сертификатов в проверенной цепочке: ${result.trust.chain_length}.`}</p>
        <p className="text-text-secondary">Успешный разбор и совпадение имени отдельно не подтверждают доверие. Проверка выполняется на текущее время UTC; отзыв через CRL/OCSP не проверяется.</p>
      </div>
      {result.certificates.map((cert, index) => <section key={`${index}-${cert.sha256}`} className="rounded border border-border p-4">
        <h2 className="mb-2 font-semibold">Сертификат {index + 1}{index === 0 ? ' — серверный' : ''}: {VALIDITY[cert.validity.status]}</h2>
        <Value label="Subject" value={cert.subject} /><Value label="Issuer" value={cert.issuer} />
        <Value label="SAN" value={cert.san.map((name) => `${name.type}: ${name.value}`).join('\n')} />
        <Value label="Действует с (UTC)" value={cert.validity.not_before} /><Value label="Действует до (UTC)" value={cert.validity.not_after} />
        <Value label="Серийный № (hex)" value={cert.serial} /><Value label="Публичный ключ" value={cert.key_algorithm} />
        <Value label="Подпись" value={cert.signature_algorithm} /><Value label="SHA-256" value={cert.sha256} /><Value label="SHA-1" value={cert.sha1} />
      </section>)}
    </div>}
  </div>
}
