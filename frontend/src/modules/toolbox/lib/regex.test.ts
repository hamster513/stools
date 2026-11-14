import { test } from 'node:test'
import assert from 'node:assert/strict'
import { runRegex, MAX_INPUT_BYTES, MAX_MATCHES, MAX_OUTPUT_LENGTH, type RegexRequest } from './regex.ts'

const request = (extra: Partial<RegexRequest> = {}): RegexRequest => ({ pattern: '(?<word>a)(b)?', flags: 'g', input: 'a ab', replacement: '$<word>:$2', positive: '', negative: '', ...extra })

test('captures, optional and named groups, UTF-16 match offsets, native replacement', () => {
  const result = runRegex(request())
  assert.deepEqual(result.matches.map(m => [m.start, m.end, m.text, m.groups, m.named]), [
    [0, 1, 'a', ['a', undefined], { word: 'a' }], [2, 4, 'ab', ['a', 'b'], { word: 'a' }],
  ])
  assert.equal(result.replacement, 'a: a:b')
  assert.equal(result.truncated, false)
})

test('flags preserve first-only, global, case, multiline, dotAll, sticky semantics', () => {
  assert.equal(runRegex(request({ pattern: 'a', flags: '', input: 'aaa', replacement: 'x' })).replacement, 'xaa')
  assert.equal(runRegex(request({ pattern: 'a', flags: 'g', input: 'aaa', replacement: 'x' })).replacement, 'xxx')
  assert.equal(runRegex(request({ pattern: '^a.$', flags: 'gim', input: 'Ab\naC' })).matches.length, 2)
  assert.equal(runRegex(request({ pattern: 'a.b', flags: 's', input: 'a\nb' })).matches.length, 1)
  assert.equal(runRegex(request({ pattern: 'a', flags: 'gy', input: 'aa a' })).matches.length, 2)
})

test('zero-length matches terminate and advance Unicode code points only with u/v', () => {
  assert.deepEqual(runRegex(request({ pattern: '', flags: 'gu', input: '😀' })).matches.map(m => m.start), [0, 2])
  assert.deepEqual(runRegex(request({ pattern: '', flags: 'g', input: '😀' })).matches.map(m => m.start), [0, 1, 2])
  assert.equal(runRegex(request({ pattern: '', input: '' })).matches.length, 1)
})

test('replacement strings agree with native JavaScript substitutions', () => {
  for (const pattern of ['(?<word>a)(b)?', '(a)(b)?', 'x']) {
    for (const replacement of ['$$ $& $` $\' $1 $2 $3 $12 $01 $00 $99', '$<word>:$<missing>:$<unterminated', '$']) {
      const args = request({ pattern, replacement })
      assert.equal(runRegex(args).replacement, args.input.replace(new RegExp(pattern, args.flags), replacement))
    }
  }
})

test('sample checks reset state and distinguish expected matches from unexpected matches', () => {
  const result = runRegex(request({ pattern: '^a$', flags: 'g', positive: 'a\na\nb', negative: 'b\na\n' }))
  assert.deepEqual(result.samples.map(s => s.pass), [true, true, false, true, false])
})

test('invalid pattern/flags and bounded inputs are rejected explicitly', () => {
  for (const extra of [{ pattern: '[' }, { flags: 'gg' }, { flags: 'z' }, { flags: 'uv' }, { pattern: 'a'.repeat(2001) }, { input: 'я'.repeat(MAX_INPUT_BYTES / 2 + 1) }, { positive: 'a\n'.repeat(201) }]) {
    assert.throws(() => runRegex(request(extra)))
  }
})

test('matches are bounded with explicit truncation and no misleading partial replacement', () => {
  const result = runRegex(request({ pattern: 'a', input: 'a'.repeat(MAX_MATCHES + 1) }))
  assert.equal(result.matches.length, MAX_MATCHES)
  assert.equal(result.truncated, true)
  assert.equal(result.replacement, null)
  assert.match(result.replacementError ?? '', /200/)
})

test('replacement output amplification is capped without losing match results', () => {
  const result = runRegex(request({ pattern: 'a', input: 'a'.repeat(100), replacement: 'x'.repeat(5000) }))
  assert.equal(result.matches.length, 100)
  assert.equal(result.replacement, null)
  assert.match(result.replacementError ?? '', new RegExp(String(MAX_OUTPUT_LENGTH)))
})

test('named replacement lookup ignores inherited object properties', () => {
  const args = request({ replacement: '$<constructor>:$<__proto__>:$<toString>' })
  assert.equal(runRegex(args).replacement, args.input.replace(new RegExp(args.pattern, args.flags), args.replacement))
})

test('without named captures, dollar tokens inside literal named placeholders still expand', () => {
  for (const replacement of ['$<x$&>', '$<x$$>', '$<x$1>', '$<x$\'>', '$<x$`>']) {
    const args = request({ pattern: '(a)(b)?', replacement })
    assert.equal(runRegex(args).replacement, args.input.replace(new RegExp(args.pattern, args.flags), replacement))
  }
})
