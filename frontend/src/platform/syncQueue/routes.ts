/** Only persisted-source updates use the queue; uploads and hunting keep their own workflows. */
export function synchronizationPost(path: string, body?: unknown) {
  let module = '', kind = '', target_id = 0
  let response: 'job' | 'result' = 'job'
  let options = (body ?? {}) as Record<string, unknown>
  const connection = /^\/api\/(ad|ksc)\/connections\/([0-9]+)\/collect$/.exec(path)
  const asset = /^\/api\/assets\/(dns|racktables)\/([0-9]+)\/run$/.exec(path)
  const ref = /^\/api\/vm\/refs\/([a-z_]+)\/download$/.exec(path)
  if (connection) {
    module = connection[1]; kind = 'collect'; target_id = Number(connection[2])
  } else if (asset) {
    module = 'assets'; kind = asset[1] === 'dns' ? 'dns' : 'rt'; target_id = Number(asset[2])
  } else if (ref) {
    module = 'vm'; kind = 'ref_' + ref[1]
  } else {
    const fixed: Record<string, [string, string]> = {
      '/api/assets/sync': ['assets', 'sync'],
      '/api/vm/import/vm': ['vm', 'import_vm'],
      '/api/vm/harbor/sync': ['vm', 'harbor'],
      '/api/vm/trends/sync': ['vm', 'trends_pull'],
      '/api/vm/trends/sync/full': ['vm', 'trends_pull'],
      '/api/siem/mp/collect': ['siem', 'kb_collect'],
      '/api/siem/logons/run': ['siem', 'logons'],
      '/api/settings/attack/download': ['attack', 'download'],
      '/api/settings/storage/measure': ['platform', 'storage'],
      '/api/settings/storage/retention/run': ['platform', 'storage_cleanup'],
    }
    const match = fixed[path]
    if (!match) return null
    ;[module, kind] = match
    if (module === 'platform') response = 'result'
    if (path.endsWith('/sync/full')) options = { reset: true }
  }
  return { task: { module, kind, target_id, options }, response }
}
