import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parseDocument, parseCsv, compareDocuments, selectRows, MAX_INPUT_BYTES } from './structured.ts'

test('CSV understands BOM, quoted separators, escaped quotes, CRLF and embedded newlines', () => {
  assert.deepEqual(parseCsv('\ufeffname;note\r\n"a;b";"line 1\r\nline ""2"""\r\n', ';'), [['name', 'note'], ['a;b', 'line 1\r\nline "2"']])
  assert.deepEqual(parseCsv('a,b\n1,\n', ','), [['a', 'b'], ['1', '']])
})
test('CSV errors report physical lines and reject inconsistent columns and headers', () => {
  assert.throws(() => parseCsv('a,b\n1,"oops', ','), /строка 2/i)
  assert.throws(() => parseCsv('a,b\n1,"x"oops', ','), /строка 2/i)
  assert.throws(() => parseDocument('a,b\n1', 'csv'), /строка 2/i)
  assert.throws(() => parseDocument('a,a\n1,2', 'csv'), /заголов/i)
})
test('JSON supports array, object, scalar and prototype-like property names', () => {
  assert.deepEqual(parseDocument('42', 'json').rows, [{ value: 42 }])
  const doc = parseDocument('[{"a":1,"__proto__":"safe"},null,"ok"]', 'json')
  assert.deepEqual(doc.fields, ['a', '__proto__', 'value'])
  assert.equal(doc.rows[0].__proto__, 'safe')
  assert.deepEqual(parseDocument('{"a":1}', 'json').rows, [{ a: 1 }])
})
test('JSONL skips empty lines and identifies the invalid physical line', () => {
  assert.equal(parseDocument('\n{"a":1}\n\n42', 'jsonl').rows.length, 2)
  assert.throws(() => parseDocument('{}\n\n{bad}', 'jsonl'), /строка 3/i)
})
test('selection filters visible fields without changing the full rows', () => {
  const doc = parseDocument('[{"a":"hello","b":"hidden"},{"a":"world","b":"hello"}]', 'json')
  assert.deepEqual(selectRows(doc.rows, ['a'], 'HELLO'), [{ a: 'hello' }])
  assert.equal(doc.rows.length, 2)
})
test('JSON semantic compare ignores key order but preserves arrays and reports values', () => {
  const a = parseDocument('{"x":1,"obj":{"a":2,"b":3},"arr":[1,2]}', 'json')
  const same = parseDocument('{"arr":[1,2],"obj":{"b":3,"a":2},"x":1}', 'json')
  assert.equal(compareDocuments(a, same).total, 0)
  const b = parseDocument('{"x":2,"obj":{"b":3,"c":4},"arr":[2,1]}', 'json')
  const diff = compareDocuments(a, b)
  assert.equal(diff.total, 5)
  assert.deepEqual(diff.changes.map(x => x.kind).sort(), ['added', 'changed', 'changed', 'changed', 'removed'])
})
test('line comparison reports inserted and removed suffixes and caps rendered entries', () => {
  const a = parseDocument('v\n1\n2', 'csv')
  const b = parseDocument('v\n1\n2\n3', 'csv')
  assert.equal(compareDocuments(a, b).changes[0].kind, 'added')
  assert.equal(compareDocuments(b, a).changes[0].kind, 'removed')
  const left = parseDocument(JSON.stringify(Array.from({ length: 500 }, (_, i) => i)), 'json')
  const right = parseDocument(JSON.stringify(Array.from({ length: 500 }, (_, i) => i + 1)), 'json')
  assert.equal(compareDocuments(left, right, 10).changes.length, 10)
  assert.equal(compareDocuments(left, right, 10).total, 500)
})
test('limits and unsafe XML declarations are rejected before parser access', () => {
  assert.throws(() => parseDocument('я'.repeat(MAX_INPUT_BYTES), 'json'), /1 МиБ/)
  assert.throws(() => parseDocument('['.repeat(150) + '0' + ']'.repeat(150), 'json'), /вложенн/i)
  assert.throws(() => parseDocument('<!DOCTYPE a [<!ENTITY e SYSTEM "file:///etc/passwd">]><a>&e;</a>', 'xml'), /DTD|ENTITY/)
  assert.throws(() => parseDocument('', 'json'), /пуст/i)
})

test('JSON Pointer paths escape slashes and tildes and use the empty path for the root', () => {
  const root = compareDocuments(parseDocument('1', 'json'), parseDocument('2', 'json'))
  assert.equal(root.changes[0].path, '')
  const nested = compareDocuments(parseDocument('{"a/b~c":1}', 'json'), parseDocument('{"a/b~c":2}', 'json'))
  assert.equal(nested.changes[0].path, '/a~1b~0c')
})

test('diff locations are bounded even with long adversarial property names', () => {
  const key = 'x'.repeat(20_000)
  const left = parseDocument(JSON.stringify({ [key]: { a: 1 } }), 'json')
  const right = parseDocument(JSON.stringify({ [key]: { a: 2 } }), 'json')
  assert.ok(compareDocuments(left, right).changes[0].path.length <= 1024)
})

test('JSON and JSONL reject unsafe, nonfinite and lossy numeric values before formatting or comparison', () => {
  for (const number of ['9007199254740993', '-9007199254740992', '1e400', '1e-400', '1.0000000000000001', '0.1234567890123456789', '-0', '-0.0']) {
    for (const format of ['json', 'jsonl'] as const) {
      assert.throws(() => parseDocument(`{"nested":[{"id":${number}}]}`, format), /числ|точност/i, `${format}: ${number}`)
    }
  }
  assert.throws(() => parseDocument('{}\n\n{"id":9007199254740993}', 'jsonl'), /строка 3.*числ|строка 3.*точност/i)
})
test('JSON accepts exact decimal spellings, safe boundaries and numeric-looking string content', () => {
  const parsed = parseDocument('[9007199254740991,-9007199254740991,1.0,1e0,0.1,1.2300,0e99999,"9007199254740993",{"text":"\\"id\\":1e400"}]', 'json')
  assert.deepEqual(parsed.value, [9007199254740991, -9007199254740991, 1, 1, 0.1, 1.23, 0, '9007199254740993', { text: '"id":1e400' }])
  assert.equal(compareDocuments(parseDocument('1.0', 'json'), parseDocument('1e0', 'json')).total, 0)
})
test('CSV formatting preserves final empty single-field records on round trip', () => {
  for (const source of ['h\n""', 'h\n""\n""', 'h\r\n""\r\n', 'h\nvalue\n""']) {
    for (const delimiter of [',', ';', '\t', '|']) {
      const parsed = parseDocument(source, 'csv', delimiter)
      assert.deepEqual(parseDocument(parsed.text, 'csv', delimiter).rows, parsed.rows)
    }
  }
})
