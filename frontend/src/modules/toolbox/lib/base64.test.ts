import { test } from 'node:test'
import assert from 'node:assert/strict'
import { decodeBase64, encodeBase64, hexDump } from './base64.ts'

function dec(input: string) {
  const r = decodeBase64(input)
  if (!r.ok) throw new Error(`${input}: ${r.error}`)
  return r
}

test('кодирование: UTF-8, обычный и URL-safe алфавит', () => {
  assert.equal(encodeBase64('hello', false), 'aGVsbG8=')
  assert.equal(encodeBase64('Привет', false), '0J/RgNC40LLQtdGC')
  assert.equal(encodeBase64('Привет', true), '0J_RgNC40LLQtdGC')
  assert.equal(encodeBase64('a', true), 'YQ')
  assert.equal(encodeBase64('', false), '')
})

test('кодирование большого текста не падает на размере стека', () => {
  const big = 'x'.repeat(300_000)
  assert.equal(dec(encodeBase64(big, false)).text, big)
})

test('декодирование: пробелы и переносы, оба алфавита, без «=»', () => {
  assert.equal(dec('aGVs\nbG8=').text, 'hello')
  assert.equal(dec('  aGVsbG8  ').text, 'hello')
  assert.equal(dec('0J_RgNC40LLQtdGC').text, 'Привет')
  assert.equal(dec('YQ').text, 'a')
  assert.equal(dec('').text, '')
})

test('декодирование не-текста: байты есть, текста нет', () => {
  const r = dec('/w==')
  assert.equal(r.text, null)
  assert.deepEqual([...r.bytes], [255])
})

test('ошибки: чужой символ с позицией, обрубленная группа, «=» в середине', () => {
  const bad = decodeBase64('aGV*bG8=')
  assert.ok(!bad.ok && /«\*».*4/.test(bad.error), JSON.stringify(bad))
  assert.equal(decodeBase64('aGVsb').ok, false)
  assert.equal(decodeBase64('aG=VsbG8').ok, false)
})

test('hex-дамп: по 16 байт в строке, с обрезкой', () => {
  assert.equal(hexDump(new Uint8Array([0, 15, 255]), 100), '00 0f ff')
  const long = hexDump(new Uint8Array(40), 32)
  assert.equal(long.split('\n').length, 3)
  assert.match(long, /ещё 8 байт/)
})
