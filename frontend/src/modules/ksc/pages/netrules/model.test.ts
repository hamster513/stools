import assert from 'node:assert/strict'
import test from 'node:test'
import type { NetRuleSection, NetRuleScope, NetRuleAddress } from '../../api/types.ts'

let model: typeof import('./model.ts') | undefined
try { model = await import('./model.ts') } catch (error) {
  if ((error as NodeJS.ErrnoException).code !== 'ERR_MODULE_NOT_FOUND') throw error
}
function api() { assert.ok(model, 'Логика секций firewall ещё не реализована'); return model }
const section = (profile = '', rules = 5): NetRuleSection => ({ layer: 'packet', policy_id: 1, policy_name: 'Политика', profile, priority: null, rules, shadowed: 2, hosts: 10, hosts_kind: 'policy', locked: true, overridden: false, overridden_by: '', overridden_reason: '' })
const scope = (patch: Partial<NetRuleScope> = {}): NetRuleScope => ({ networks: null, remote: [], local: [], icmp_type: null, direction: null, protocol: null, local_ports: [], remote_ports: [], unread: [], ...patch })

test('фильтр сохраняет пустую секцию и исходное число правил', () => {
  const rows = api().mergeSections([section(), section('VPN', 3)], [{ ...section(), rules: 1, shadowed: 0 }])
  assert.deepEqual(rows.map(s => [s.profile, s.rules, s.total, s.shadowed]), [['', 1, 5, 0], ['VPN', 0, 3, 0]])
})
test('секция политики и секция профиля с тем же именем не смешиваются', () => {
  const a = section('1:office'); const b = { ...section('office'), policy_id: 11 }
  assert.notEqual(api().sectionKey(a), api().sectionKey(b))
  assert.equal(api().mergeSections([a, b], [b])[0].rules, 0)
})
test('неактивность политики, отсутствие замка и замена профилем различаются', () => {
  assert.match(api().inactiveLabel('inactive'), /политика.*не действует/i)
  assert.match(api().inactiveLabel('unlocked'), /без замка/i)
  assert.match(api().inactiveLabel('replaced', 'VPN'), /VPN/)
  assert.equal(api().inactiveLabel(''), '')
})
test('известные пустые адресные критерии означают любые адреса', () => {
  assert.deepEqual(api().scopeTokens(scope(), '').map(t => t.text), ['любые адреса'])
})
test('непрочитанная зона не превращается в любые адреса', () => {
  const tokens = api().scopeTokens(scope({ unread: ['networks'] }), '')
  assert.ok(tokens.some(t => t.kind === 'warning'))
  assert.ok(tokens.every(t => !t.text.includes('любые')))
})
test('имя узла сохраняет разрешённые IP, а локальная сеть подписана отдельно', () => {
  const tokens = api().scopeTokens(scope({ remote: [{ host: 'app.example.test', ip: '', mask: null, ips: [{ host: '', ip: '192.0.2.10', mask: null, ips: [], hidden: '' }], hidden: '' }], local: [{ host: '', ip: '198.51.100.0', mask: 24, ips: [], hidden: '' }] }), '')
  assert.ok(tokens.some(t => t.text.includes('app.example.test') && t.title?.includes('192.0.2.10')))
  assert.ok(tokens.some(t => t.text.includes('лок.') && t.text.includes('198.51.100.0/24')))
})
test('скрытый адрес остаётся скрытым, старые записи используют исходный текст', () => {
  assert.match(api().scopeTokens(scope({ remote: [{ host: '', ip: '', mask: null, ips: [], hidden: 'secret' }] }), '')[0].text, /скрыт/)
  assert.equal(api().scopeTokens(null, 'Старая запись')[0].text, 'Старая запись')
})
test('порты: любое значение, диапазон и непрочитанный критерий различаются', () => {
  assert.equal(api().portsText(scope(), 'local_ports', ''), 'любые')
  assert.equal(api().portsText(scope({ remote_ports: [[443, 443], [8000, 8080]] }), 'remote_ports', ''), '443, 8000–8080')
  assert.match(api().portsText(scope({ unread: ['local_ports'] }), 'local_ports', ''), /не прочитаны/)
})
test('общий маркер ports из API не превращается в разрешение любых портов', () => {
  const unread = scope({ unread: ['ports'], remote_ports: [[443, 443]] })
  assert.equal(api().portsText(unread, 'local_ports', ''), 'не прочитаны')
  assert.equal(api().portsText(unread, 'remote_ports', ''), '443 (прочитано не полностью)')
})
test('URL сохраняет повторные фильтры, false и чужую вкладку', () => {
  const filters = api().readFilters('?host_id=host%201&action=allow&action=deny&enabled=false&policy_id=7&policy_id=bad')
  assert.deepEqual(filters.action, ['allow', 'deny'])
  assert.deepEqual(filters.policy_id, [7]); assert.equal(filters.enabled, false)
  const search = api().writeFilters('?tab=netrules&unused=keep', filters)
  assert.equal(new URLSearchParams(search).get('tab'), 'netrules')
  assert.equal(new URLSearchParams(search).get('host_id'), 'host 1')
  assert.deepEqual(api().readFilters(search), filters)
})
test('маркер пустого значения из ссылки согласован с пустым значением фасета', () => {
  assert.deepEqual(api().readFilters('?action=-&direction=-').action, [''])
  assert.deepEqual(api().readFilters('?action=-&direction=-').direction, [''])
})
test('состояние секций по умолчанию закрыто; повреждённое хранилище игнорируется', () => {
  assert.deepEqual(api().readOpenSections(null), [])
  assert.deepEqual(api().readOpenSections('{broken'), [])
  assert.deepEqual(api().readOpenSections('["a",2,true,"b"]'), ['a', 'b'])
})

test('одинаковые списки объединяются внутри политики и слоя, без замка — отдельно', () => {
  const s = (profile: string, patch = {}) => ({ ...section(profile), total: 5, content_key: 'same', ...patch })
  const groups = api().groupPolicies([s(''), s('A'), s('B'), s('Unlocked', { locked: false }), s('Other', { policy_id: 2 }), s('Application', { layer: 'app' })])
  assert.equal(groups.length, 2)
  assert.equal(groups[0].layers.length, 2)
  assert.equal(groups[0].layers[0].base?.profile, '')
  assert.deepEqual(groups[0].layers[0].groups[0].members.map(s => s.profile), ['A', 'B'])
  assert.deepEqual(groups[0].layers[0].unlocked[0].members.map(s => s.profile), ['Unlocked'])
})
test('фильтр не меняет объединение списков и не теряет нулевые совпадения', () => {
  const base = [{ ...section('A'), content_key: 'same' }, { ...section('B'), content_key: 'same' }]
  const sections = api().mergeSections(base, [])
  const groups = api().groupPolicies(sections)
  assert.equal(groups[0].layers[0].groups[0].members.length, 2)
  assert.equal(groups[0].layers[0].groups[0].members[0].rules, 0)
})


const addr = (patch: Partial<NetRuleAddress> = {}): NetRuleAddress => ({ host: '', ip: '', mask: null, hidden: '', ips: [], ...patch })
test('вложенные IP без имени раскрываются в отдельные адресные плашки', () => {
  const tokens = api().scopeTokens(scope({ remote: [addr({ ips: [addr({ ip: '192.0.2.10' }), addr({ ip: '2001:db8::', mask: 64 })] })] }), '')
  assert.deepEqual(tokens.map(t => t.text), ['192.0.2.10', '2001:db8::/64'])
  assert.ok(tokens.every(t => t.kind !== 'warning'))
})
test('вложенные локальные IP сохраняют сторону, скрытые и непрочитанные значения', () => {
  const tokens = api().scopeTokens(scope({ local: [addr({ ips: [addr({ ip: '198.51.100.0', mask: 24 }), addr({ hidden: 'secret' }), addr({ hidden: 'unparsed' }), addr()] })] }), '')
  assert.deepEqual(tokens.map(t => t.text), ['лок. 198.51.100.0/24', 'лок. адрес скрыт', 'лок. адрес не прочитан', 'лок. адрес не определён'])
})
test('вложенные IP именованного или скрытого узла не раскрываются отдельными плашками', () => {
  const ips = [addr({ ip: '192.0.2.10' })]
  const host = api().scopeTokens(scope({ remote: [addr({ host: 'app.example.test', ips })] }), '')
  assert.equal(host.length, 1)
  assert.equal(host[0].text, 'app.example.test')
  assert.equal(host[0].title, '192.0.2.10')
  const hidden = api().scopeTokens(scope({ remote: [addr({ hidden: 'secret', ips })] }), '')
  assert.deepEqual(hidden.map(t => t.text), ['адрес скрыт'])
})
