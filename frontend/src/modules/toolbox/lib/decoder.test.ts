import { test } from 'node:test'
import assert from 'node:assert/strict'
import { gzipSync, deflateSync } from 'node:zlib'
import { decodeStep, decodeText, DECODER_LIMIT } from './decoder.ts'
const bytes = (s: string) => new TextEncoder().encode(s)
const run = async (s: string, op: Parameters<typeof decodeStep>[1]) => decodeText(await decodeStep(bytes(s), op))
test('chain preserves bytes: Base64 UTF16LE command', async () => {
  const raw = await decodeStep(bytes('VwByAGkAdABlAC0ASABvAHMAdAAgACIAaABpACIA'), 'base64')
  assert.equal(decodeText(await decodeStep(raw, 'utf16le')), 'Write-Host "hi"')
  assert.equal(await run('powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIAaABpACIA','powershell'), 'Write-Host "hi"')
})
test('URL, hex and JSON escaped strings are data only', async () => {
  assert.equal(await run('%3Cscript%3Ex%3C%2Fscript%3E','url'), '<script>x</script>')
  assert.equal(await run('68 69','hex'), 'hi')
  assert.equal(await run('"line\\n\\u0041"','json'), 'line\nA')
  assert.equal(await run('YQ==','base64'), 'a')
})
test('JWT decode makes no signature authenticity claim', async () => {
  const h=Buffer.from('{"alg":"none"}').toString('base64url'), p=Buffer.from('{"sub":"test"}').toString('base64url')
  const result=JSON.parse((await run(`${h}.${p}.`, 'jwt'))!)
  assert.deepEqual(result.payload, { sub:'test' })
  assert.match(result.signature, /не проверена/i)
})
test('gzip and deflate stay bounded and preserve text', async () => {
  assert.equal(decodeText(await decodeStep(new Uint8Array(gzipSync('hello')), 'gzip')), 'hello')
  assert.equal(decodeText(await decodeStep(new Uint8Array(deflateSync('hello')), 'deflate')), 'hello')
  await assert.rejects(decodeStep(new Uint8Array(gzipSync('x'.repeat(DECODER_LIMIT+1))), 'gzip'), /лимит/i)
})
test('bad encodings fail clearly, no replacement bytes', async () => {
  for (const [s,op] of [['%', 'url'],['a', 'hex'],['!', 'base64'],['foo', 'jwt']] as const) await assert.rejects(decodeStep(bytes(s),op))
  await assert.rejects(decodeStep(new Uint8Array([1]), 'utf16le'))
  await assert.rejects(decodeStep(new Uint8Array([255]), 'utf8'))
  assert.equal(decodeText(new Uint8Array([255])), null)
})
