export function safeUrl(value: string) {
  try { const url = new URL(value); return ['http:', 'https:'].includes(url.protocol) ? url.href : undefined } catch { return undefined }
}

export function publicationUrl(value: string, id: string) {
  const safe = safeUrl(value)
  if (!safe) return undefined
  const url = new URL(safe)
  if (/^CVE-\d{4}-\d{4,}$/i.test(id) && ['cisa.gov', 'www.cisa.gov'].includes(url.hostname) && url.pathname.replace(/\/$/, '') === '/known-exploited-vulnerabilities-catalog') {
    url.searchParams.set('field_cve', id)
  }
  return url.href
}
