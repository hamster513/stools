import { api } from '@/api/client'

export type CertificateEncoding = 'pem' | 'der_base64'
export interface CertificateInfo {
  subject: string
  issuer: string
  serial: string
  san: { type: string; value: string }[]
  validity: { not_before: string; not_after: string; status: 'valid' | 'expired' | 'not_yet_valid' }
  key_algorithm: string
  signature_algorithm: string
  sha256: string
  sha1: string
}
export interface CertificateResult {
  parse_status: 'parsed'
  certificates: CertificateInfo[]
  hostname: { status: 'not_checked' | 'match' | 'mismatch'; value: string }
  trust: { status: 'not_checked' | 'hostname_required' | 'trusted' | 'failed'; message: string; chain_length?: number }
}
export function inspectCertificates(data: string, encoding: CertificateEncoding, hostname: string, trust_roots: string) {
  return api.post<CertificateResult>('/api/toolbox/certificates/inspect', { data, encoding, hostname, trust_roots })
}
