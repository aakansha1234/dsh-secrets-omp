import { describe, expect, it } from 'bun:test'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createAssistantMessage, createUserMessage, ToolCallId, type GenerateOptions } from '@deepseek-ai/dsh-llm'
import { Config } from '../src/index.ts'
import { loadKey } from '../src/key.ts'
import { mapStrings, Obfuscator, Vault } from '../src/obfuscator.ts'
import { BUILTIN_PATTERNS, envEntries, parseEntries, Sources } from '../src/sources.ts'
import { freezeJson, redactRequest, rememberMessages } from '../src/transform.ts'

const KEY = 'k'.repeat(43)

describe('reversible capabilities', () => {
  it('hides overlapping literals longest-first and restores exact original bytes', () => {
    const value = 'Secret-AbC123456789'
    const vault = new Vault(KEY)
    const engine = new Obfuscator(vault, [{ type: 'plain', content: value }, { type: 'plain', content: value.slice(0, 8) }])
    const input = `${value} / ${value.slice(0, 8)}`
    const hidden = engine.obfuscate(input)
    expect(hidden).not.toContain(value.slice(0, 8))
    expect(vault.reveal(hidden)).toBe(input)
    expect(engine.obfuscate(hidden)).toBe(hidden)
    expect(new Obfuscator(new Vault('p'.repeat(43)), [{ type: 'plain', content: value }]).obfuscate(input)).not.toBe(hidden)
  })

  it('uses independent bases for values differing only by case; unknown capabilities stay inert', () => {
    const vault = new Vault(KEY)
    const engine = new Obfuscator(vault, [{ type: 'plain', content: 'password123' }, { type: 'plain', content: 'PASSWORD123' }])
    const lower = engine.obfuscate('password123')
    const upper = engine.obfuscate('PASSWORD123')
    expect(lower.split(':')[0]).not.toBe(upper.split(':')[0])
    expect(vault.reveal(lower.replace(':L', ':U'))).not.toBe('PASSWORD123')
    expect(vault.reveal('$$UNKNOWN_000000000000:M$$')).toBe('$$UNKNOWN_000000000000:M$$')
  })

  it('ignores short reversible values but supports short one-way replacements', () => {
    const engine = new Obfuscator(new Vault(KEY), [
      { type: 'plain', content: 'seven77' },
      { type: 'plain', content: 'eight888' },
      { type: 'plain', content: 'pin', mode: 'replace', replacement: '***' },
    ])
    const hidden = engine.obfuscate('seven77 eight888 pin')
    expect(hidden).toStartWith('seven77 ')
    expect(hidden).not.toContain('eight888')
    expect(hidden).toEndWith(' ***')
  })

  it('handles regex literals, Unicode zero-width matches, and regex values returned outside their original context', () => {
    const vault = new Vault(KEY)
    const engine = new Obfuscator(vault, [{ type: 'regex', content: '/(?<=Bearer )token\\/[a-z0-9]+/i' }, { type: 'regex', content: '/(?:)/u' }])
    const value = 'ToKeN/abcdef123456'
    const hidden = engine.obfuscate(`😀 Bearer ${value}`)
    expect(hidden).not.toContain(value)
    expect(vault.reveal(hidden)).toBe(`😀 Bearer ${value}`)
    expect(new Obfuscator(vault, []).obfuscate(value)).not.toContain(value)
  }, 1000)

  it('rebuilds dynamic capabilities with the same key from raw history after a process restart', () => {
    const value = `ghp_${'r'.repeat(36)}`
    const previous = new Obfuscator(new Vault(KEY), BUILTIN_PATTERNS).obfuscate(value)
    const restartedVault = new Vault(KEY)
    const restarted = new Obfuscator(restartedVault, BUILTIN_PATTERNS)
    rememberMessages(restarted, [createUserMessage({ source: { kind: 'user' }, content: [{ type: 'text', text: `Original tool output: ${value}` }] })])
    expect(restartedVault.reveal(previous)).toBe(value)
    expect(restarted.obfuscate(previous)).toBe(previous)
  })

  it('cannot expose another secret through a friendly label, including later regex discoveries', () => {
    const engine = new Obfuscator(new Vault(KEY), [
      { type: 'plain', content: 'first-secret-12345', friendlyName: 'later-token-12345' },
      { type: 'regex', content: '(?<=credential=)later_token-[0-9]+' },
    ])
    const first = engine.obfuscate('first-secret-12345')
    expect(first).toContain('LATERTOKEN12345_')
    const options: GenerateOptions = { provider: 'test', model: 'test', messages: [
      createUserMessage({ source: { kind: 'user' }, content: [{ type: 'text', text: first }] }),
      createUserMessage({ source: { kind: 'user' }, content: [{ type: 'text', text: 'credential=later_token-12345' }] }),
    ] }
    const hidden = JSON.stringify(redactRequest(engine, options))
    expect(hidden).not.toContain('LATERTOKEN12345')
    expect(hidden).not.toContain('later_token-12345')
  })

  it('hides unsafe labels and the key itself without granting access to the key', () => {
    const value = 'secret-label1234'
    const vault = new Vault(KEY)
    const engine = new Obfuscator(vault, [{ type: 'plain', content: value, friendlyName: value }])
    expect(engine.obfuscate(value)).not.toContain('SECRETLABEL1234')
    const hiddenKey = engine.obfuscate(KEY)
    expect(hiddenKey).not.toContain(KEY)
    expect(vault.reveal(hiddenKey)).not.toBe(KEY)
  })

  it('makes default replacements one-way, distinct and length-preserving, with stable catch-all fallback markers', () => {
    const vault = new Vault(KEY)
    const engine = new Obfuscator(vault, [{ type: 'plain', content: '🔒password123', mode: 'replace' }])
    const hidden = engine.obfuscate('🔒password123')
    expect(Array.from(hidden).length).toBe(Array.from('🔒password123').length)
    expect(hidden).not.toBe('🔒password123')
    expect(vault.reveal(hidden)).toBe(hidden)
    const catchAll = new Obfuscator(vault, [{ type: 'regex', content: '[\\s\\S]{8}', mode: 'replace' }])
    const marker = catchAll.obfuscate('12345678')
    expect(marker).not.toContain('12345678')
    expect(catchAll.obfuscate(marker)).toBe(marker)
    expect(vault.reveal(marker)).toBe(marker)
  })

  it('does not make a one-way substring reversible through a larger credential match', () => {
    const value = `ghp_${'a'.repeat(36)}`
    const vault = new Vault(KEY)
    const engine = new Obfuscator(vault, [{ type: 'plain', content: 'a'.repeat(8), mode: 'replace', replacement: '***' }, ...BUILTIN_PATTERNS])
    const hidden = engine.obfuscate(value)
    expect(hidden).not.toContain('a'.repeat(8))
    expect(vault.reveal(hidden)).not.toBe(value)
  })

  it('re-scrubs a secret reconstructed by replacement and rejects replacements exposing their original', () => {
    const engine = new Obfuscator(new Vault(KEY), [
      { type: 'plain', content: 'TRIGGER', mode: 'replace', replacement: '' },
      { type: 'plain', content: 'SECRET1234' },
    ])
    expect(engine.obfuscate('SECRETTRIGGER1234')).not.toContain('SECRET1234')
    const invalid = new Obfuscator(new Vault(KEY), [{ type: 'plain', content: 'raw-secret123', mode: 'replace', replacement: 'raw-secret123' }])
    expect(() => invalid.obfuscate('raw-secret123')).toThrow('refusing')
  })

  it.each(['lookbehind', 'lookahead'] as const)('keeps %s context across redacted and preexisting capabilities', direction => {
    const vault = new Vault(KEY)
    const engine = new Obfuscator(vault, [
      { type: 'plain', content: 'ContextABCDEFGH' },
      { type: 'regex', content: direction === 'lookbehind' ? '(?<=ContextABCDEFGH)SecretUV123' : 'SecretUV123(?=ContextABCDEFGH)' },
    ])
    const adjacent = (context: string) => direction === 'lookbehind' ? `${context}SecretUV123` : `SecretUV123${context}`
    for (const input of [adjacent('ContextABCDEFGH'), adjacent(engine.obfuscate('ContextABCDEFGH'))]) {
      const hidden = engine.obfuscate(input)
      expect(hidden).not.toContain('SecretUV123')
      expect(hidden).not.toContain('ContextABCDEFGH')
      expect(vault.reveal(hidden)).toBe(adjacent('ContextABCDEFGH'))
      expect(engine.obfuscate(hidden)).toBe(hidden)
    }
  })

  it('redacts a regex spanning an existing capability and a short raw suffix', () => {
    const vault = new Vault(KEY)
    const engine = new Obfuscator(vault, [
      { type: 'plain', content: 'ContextABCDEFGH' },
      { type: 'regex', content: 'ContextABCDEFGHxyz' },
    ])
    const hidden = engine.obfuscate(`${engine.obfuscate('ContextABCDEFGH')}xyz`)
    expect(hidden).not.toContain('xyz')
    expect(vault.reveal(hidden)).toBe('ContextABCDEFGHxyz')
    expect(engine.obfuscate(hidden)).toBe(hidden)
  })

  it('redacts regex secrets introduced across custom replacement boundaries', () => {
    const vault = new Vault(KEY)
    const engine = new Obfuscator(vault, [
      { type: 'plain', content: 'SyntheticSeed', mode: 'replace', replacement: 'Synthetic' },
      { type: 'regex', content: 'SyntheticRebuilt[0-9]+' },
    ])
    const hidden = engine.obfuscate('SyntheticSeedRebuilt123')
    expect(hidden).not.toContain('SyntheticRebuilt123')
    expect(vault.reveal(hidden)).toBe('SyntheticRebuilt123')
    expect(engine.obfuscate(hidden)).toBe(hidden)
  })

  it('makes one-way regex coverage override superstring capabilities and revoke earlier capabilities', () => {
    const vault = new Vault(KEY)
    const value = 'prefix-SyntheticPin123-suffix'
    const earlier = new Obfuscator(vault, [{ type: 'plain', content: value }]).obfuscate(value)
    const engine = new Obfuscator(vault, [
      { type: 'plain', content: value },
      { type: 'regex', content: 'SyntheticPin[0-9]+', mode: 'replace', replacement: 'PIN_MASK' },
    ])
    const hidden = engine.obfuscate(earlier)
    expect(hidden).not.toContain('SyntheticPin123')
    expect(hidden).toContain('PIN_MASK')
    expect(vault.reveal(hidden)).not.toContain('SyntheticPin123')
    expect(vault.reveal(earlier)).not.toContain('SyntheticPin123')
    expect(engine.obfuscate(hidden)).toBe(hidden)
    const withoutSource = new Obfuscator(vault, [])
    expect(withoutSource.obfuscate(value)).toContain('PIN_MASK')
    expect(vault.reveal(withoutSource.obfuscate(value))).not.toContain('SyntheticPin123')
  })

  it('removes labels colliding with short regex discoveries without hiding short standalone values', () => {
    const engine = new Obfuscator(new Vault(KEY), [
      { type: 'plain', content: 'PubliclyNamedSecret-1234', friendlyName: 'pin123' },
      { type: 'regex', content: '(?<=credential=)pin[0-9]+' },
    ])
    engine.prepare(['PubliclyNamedSecret-1234', 'credential=pin123'])
    expect(engine.obfuscate('PubliclyNamedSecret-1234')).not.toContain('PIN123')
    expect(engine.obfuscate('credential=pin123')).toBe('credential=pin123')
  })

  it('preserves rendered-token regex context without turning placeholder hashes into secrets', () => {
    const vault = new Vault(KEY)
    const base = new Obfuscator(vault, [{ type: 'plain', content: 'ContextABCDEFGH' }])
    const context = base.obfuscate('ContextABCDEFGH')
    const engine = new Obfuscator(vault, [
      { type: 'plain', content: 'ContextABCDEFGH' },
      { type: 'regex', content: 'SecretUV123(?=\\$\\$)' },
    ])
    const hidden = engine.obfuscate(`SecretUV123${context}`)
    expect(hidden).not.toContain('SecretUV123')
    expect(vault.reveal(hidden)).toBe('SecretUV123ContextABCDEFGH')
    expect(engine.obfuscate(hidden)).toBe(hidden)
  })

  it('redacts registered raw literals containing another valid capability without changing their actual value', () => {
    const vault = new Vault(KEY)
    const context = new Obfuscator(vault, [{ type: 'plain', content: 'ContextABCDEFGH' }]).obfuscate('ContextABCDEFGH')
    const value = `OuterPrefix-${context}-LongSuffix`
    const engine = new Obfuscator(vault, [{ type: 'plain', content: value }])
    const hidden = engine.obfuscate(value)
    expect(hidden).not.toContain(value)
    expect(vault.reveal(hidden)).toBe(value)
    expect(engine.obfuscate(hidden)).toBe(hidden)
  })

  it('keeps valid aliases inert when their label discloses a known secret', () => {
    const vault = new Vault(KEY)
    const engine = new Obfuscator(vault, [
      { type: 'plain', content: 'ContextABCDEFGH' },
      { type: 'plain', content: 'AliasSecret123' },
    ])
    const token = engine.obfuscate('ContextABCDEFGH')
    const unsafe = token.replace(/^\$\$/, () => '$$ALIASSECRET123_')
    expect(vault.reveal(unsafe)).toBe(unsafe)
    expect(vault.reveal(token)).toBe('ContextABCDEFGH')
  })

  it.each(BUILTIN_PATTERNS.map((entry, index) => [entry.friendlyName!, [
    `ghp_${'a'.repeat(36)}`, 'AKIA1234567890123456', `AIza${'a'.repeat(30)}`, `xoxb-${'a'.repeat(15)}`,
    `npm_${'a'.repeat(30)}`, `sk_live_${'a'.repeat(20)}`, `whsec_${'a'.repeat(20)}`, `hf_${'a'.repeat(30)}`,
    `SG.${'a'.repeat(22)}.${'a'.repeat(43)}`, `eyJ${'a'.repeat(10)}.eyJ${'b'.repeat(10)}.${'c'.repeat(10)}`,
    `Bearer ${'a'.repeat(24)}`, '-----BEGIN PRIVATE KEY-----\nsynthetic-private-key\n-----END PRIVATE KEY-----',
  ][index]!] as const))('round-trips built-in %s credentials', (_name, input) => {
    const vault = new Vault(KEY)
    const engine = new Obfuscator(vault, BUILTIN_PATTERNS)
    const hidden = engine.obfuscate(input)
    expect(hidden).not.toContain(input)
    expect(vault.reveal(hidden)).toBe(input)
  })
})

describe('source policy and provider copies', () => {
  it('collects encoded and decoded URL passwords regardless of env name without treating ordinary values as secrets', () => {
    const entries = envEntries({ API_KEY: 'credential1234', DUPLICATE_TOKEN: 'credential1234', SMALL_PASS: 'short',
      DATABASE_URL: 'postgres://user:pass%21word123@db/service', ORDINARY: 'not-sensitive123' })
    expect(entries.map(entry => entry.content).sort()).toEqual(['credential1234', 'pass!word123', 'pass%21word123'].sort())
  })

  it('keeps valid secrets with invalid optional labels and skips malformed entries without printing their values', () => {
    const warnings: string[] = []
    const entries = parseEntries([
      { type: 'plain', content: 'valid-secret123', friendlyName: 42 },
      { type: 'regex', content: 'bad-secret123[', flags: 'i' },
      { type: 'invalid', content: 'bad-secret456' },
    ], 'fixture', message => warnings.push(message))
    expect(entries).toEqual([{ type: 'plain', content: 'valid-secret123' }])
    expect(warnings.join('\n')).not.toContain('bad-secret')
  })

  it('selects project rules by session cwd, applies project overrides, and sees edited files', () => {
    const directory = mkdtempSync(join(tmpdir(), 'dsh-secrets-sources-'))
    try {
      const first = join(directory, 'first')
      const second = join(directory, 'second')
      mkdirSync(join(first, '.dsh'), { recursive: true })
      mkdirSync(join(second, '.dsh'), { recursive: true })
      writeFileSync(join(directory, 'secrets.yml'), '- type: regex\n  content: "custom-[a-z0-9]+"\n  mode: replace\n  replacement: GLOBAL\n')
      writeFileSync(join(first, '.dsh/secrets.yml'), '- type: regex\n  content: "custom-[a-z0-9]+"\n  mode: replace\n  replacement: PROJECT\n')
      const sources = new Sources({ vault: new Vault(KEY), home: directory, files: ['$DSH_HOME/secrets.yml', '.dsh/secrets.yml'],
        entries: [], env: undefined, builtin: false, warn: () => { throw new Error('unexpected source warning') } })
      expect(sources.for(first).obfuscate('custom-credential123')).toBe('PROJECT')
      expect(sources.for(second).obfuscate('custom-credential123')).toBe('GLOBAL')
      writeFileSync(join(first, '.dsh/secrets.yml'), '- type: regex\n  content: "custom-[a-z0-9]+"\n  mode: replace\n  replacement: UPDATED\n')
      expect(sources.for(first).obfuscate('custom-credential123')).toBe('UPDATED')
    } finally { rmSync(directory, { recursive: true, force: true }) }
  })

  it('hides a custom key read from a session .env before provider dispatch without a configured rule', () => {
    const directory = mkdtempSync(join(tmpdir(), 'dsh-secrets-dotenv-'))
    const secret = 'Custom-Synthetic-EnvValue-123456'
    try {
      writeFileSync(join(directory, '.env'), `API_KEY="${secret}"\n`)
      const vault = new Vault(KEY)
      const sources = new Sources({ vault, home: directory, files: [], entries: [], env: undefined, builtin: false,
        warn: () => { throw new Error('unexpected source warning') } })
      const input = freezeJson({ provider: 'test', model: 'test',
        messages: [createUserMessage({ source: { kind: 'user' }, content: [{ type: 'text', text: `API_KEY="${secret}"\n` }] })] })
      const output = redactRequest(sources.for(directory), input)
      expect(JSON.stringify(output.messages)).not.toContain(secret)
      expect(vault.reveal(JSON.stringify(output.messages))).toBe(JSON.stringify(input.messages))
      expect(JSON.stringify(input.messages)).toContain(secret)
    } finally { rmSync(directory, { recursive: true, force: true }) }
  })

  it('defaults dotenv discovery on independently of process environment collection and isolates session directories', () => {
    const directory = mkdtempSync(join(tmpdir(), 'dsh-secrets-dotenv-cwd-'))
    const firstValue = 'first-synthetic-ordinary-value123'
    const secondValue = 'second-synthetic-ordinary-value456'
    const ignored = ['home-synthetic-value123', 'envrc-synthetic-value123', 'nested-synthetic-value123']
    try {
      const first = join(directory, 'first')
      const second = join(directory, 'second')
      mkdirSync(join(first, '.env.directory'), { recursive: true })
      mkdirSync(second)
      writeFileSync(join(directory, '.env'), `ORDINARY=${ignored[0]}\n`)
      writeFileSync(join(first, '.env'), `ORDINARY=${firstValue}\n`)
      writeFileSync(join(second, '.env.production'), `ORDINARY=${secondValue}\n`)
      writeFileSync(join(first, '.envrc'), `ORDINARY=${ignored[1]}\n`)
      writeFileSync(join(first, '.env.directory', '.env'), `ORDINARY=${ignored[2]}\n`)
      const config = Config({ env: false, builtin: false, files: [] })
      const vault = new Vault(KEY)
      const sources = new Sources({ vault, home: directory, files: config.files, entries: config.secrets,
        env: undefined, envFiles: config.envFiles, builtin: config.builtin,
        warn: () => { throw new Error('unexpected source warning') } })
      const firstEngine = sources.for(first)
      expect(firstEngine.obfuscate(firstValue)).not.toContain(firstValue)
      expect(firstEngine.obfuscate(secondValue)).toBe(secondValue)
      for (const value of ignored) expect(firstEngine.obfuscate(value)).toBe(value)
      const secondEngine = sources.for(second)
      expect(secondEngine.obfuscate(secondValue)).not.toContain(secondValue)
      for (const value of ignored) expect(secondEngine.obfuscate(value)).toBe(value)
      // Shared capabilities protect already discovered values even outside their originating cwd.
      expect(vault.reveal(secondEngine.obfuscate(firstValue))).toBe(firstValue)
      expect(firstEngine.obfuscate(secondValue)).not.toContain(secondValue)
    } finally { rmSync(directory, { recursive: true, force: true }) }
  })

  it('sees new and edited dotenv files and protects removed values through the shared vault', () => {
    const directory = mkdtempSync(join(tmpdir(), 'dsh-secrets-dotenv-change-'))
    const firstValue = 'initial-synthetic-value123'
    const editedValue = 'edited-synthetic-value-with-a-different-length456'
    const addedValue = 'new-local-synthetic-value789'
    try {
      const vault = new Vault(KEY)
      const sources = new Sources({ vault, home: directory, files: [], entries: [], env: undefined, builtin: false,
        warn: () => { throw new Error('unexpected source warning') } })
      const empty = sources.for(directory)
      expect(empty.obfuscate(firstValue)).toBe(firstValue)
      const path = join(directory, '.env')
      writeFileSync(path, `ORDINARY=${firstValue}\n`)
      const created = sources.for(directory)
      const originalToken = created.obfuscate(firstValue)
      expect(originalToken).not.toContain(firstValue)
      writeFileSync(path, `ORDINARY=${editedValue}\n`)
      const edited = sources.for(directory)
      expect(edited.obfuscate(firstValue)).toBe(originalToken)
      expect(edited.obfuscate(editedValue)).not.toContain(editedValue)
      rmSync(path)
      const removed = sources.for(directory)
      for (const value of [firstValue, editedValue]) {
        const hidden = removed.obfuscate(value)
        expect(hidden).not.toContain(value)
        expect(vault.reveal(hidden)).toBe(value)
      }
      writeFileSync(join(directory, '.env.local'), `ORDINARY=${addedValue}\n`)
      const added = sources.for(directory)
      expect(added.obfuscate(addedValue)).not.toContain(addedValue)
      expect(vault.reveal(added.obfuscate(addedValue))).toBe(addedValue)
    } finally { rmSync(directory, { recursive: true, force: true }) }
  })

  it('protects all eligible dotenv values, quotes, exports, multiline and escaped spellings without expansion', () => {
    const directory = mkdtempSync(join(tmpdir(), 'dsh-secrets-dotenv-syntax-'))
    const values = ['ordinary-synthetic-value123', 'exported-synthetic-value234', 'quoted#synthetic-value345',
      'multiline-synthetic\nsecond-synthetic-line456', 'escaped-synthetic\\nsecond-synthetic-line567',
      'escaped-synthetic\nsecond-synthetic-line567', 'overwritten-synthetic-value678', 'latest-synthetic-value789',
      '${ORDINARY}', '$(echo synthetic-value890)']
    const text = `# synthetic comment remains visible
ORDINARY = ${values[0]} # trailing synthetic comment
export EXPORTED = '${values[1]}'
QUOTED_HASH="${values[2]}"
MULTILINE="${values[3]}"
ESCAPED="${values[4]}"
DUPLICATE=${values[6]}
DUPLICATE=${values[7]}
REFERENCE="${values[8]}"
COMMAND='${values[9]}'
SHORT=seven77
EMPTY=
`
    try {
      writeFileSync(join(directory, '.env.test'), text)
      const vault = new Vault(KEY)
      const sources = new Sources({ vault, home: directory, files: [], entries: [], env: undefined, builtin: false,
        warn: () => { throw new Error('unexpected source warning') } })
      const engine = sources.for(directory)
      const hiddenFile = engine.obfuscate(text)
      for (const value of values) {
        const hidden = engine.obfuscate(value)
        expect(hidden).not.toContain(value)
        expect(vault.reveal(hidden)).toBe(value)
        expect(hiddenFile).not.toContain(value)
      }
      expect(hiddenFile).toContain('# synthetic comment remains visible')
      expect(hiddenFile).toContain('# trailing synthetic comment')
      expect(hiddenFile).toContain('SHORT=seven77')
      expect(vault.reveal(hiddenFile)).toBe(text)
    } finally { rmSync(directory, { recursive: true, force: true }) }
  })

  it('hides passwords extracted from dotenv connection URLs in encoded and decoded forms', () => {
    const directory = mkdtempSync(join(tmpdir(), 'dsh-secrets-dotenv-url-'))
    const decoded = 'Custom-Database@Password-123456'
    const encoded = encodeURIComponent(decoded)
    const url = `postgres://synthetic:${encoded}@fixture.invalid/database`
    try {
      writeFileSync(join(directory, '.env'), `DATA_ENDPOINT="${url}"\n`)
      const vault = new Vault(KEY)
      const sources = new Sources({ vault, home: directory, files: [], entries: [], env: undefined, builtin: false,
        warn: () => { throw new Error('unexpected source warning') } })
      const engine = sources.for(directory)
      for (const value of [url, encoded, decoded]) {
        const hidden = engine.obfuscate(value)
        expect(hidden).not.toContain(value)
        expect(vault.reveal(hidden)).toBe(value)
      }
    } finally { rmSync(directory, { recursive: true, force: true }) }
  })

  it('lets explicit YAML and inline replacements and labels override dotenv discovery', () => {
    const directory = mkdtempSync(join(tmpdir(), 'dsh-secrets-dotenv-precedence-'))
    const fileValue = 'file-policy-synthetic-value123'
    const inlineValue = 'inline-policy-synthetic-value456'
    const labelValue = 'label-policy-synthetic-value789'
    try {
      writeFileSync(join(directory, '.env'), `FIRST=${fileValue}\nSECOND=${inlineValue}\nTHIRD=${labelValue}\n`)
      writeFileSync(join(directory, 'secrets.yml'), `- type: plain
  content: ${fileValue}
  mode: replace
  replacement: FILE_POLICY
- type: plain
  content: ${inlineValue}
  mode: replace
  replacement: FILE_POLICY
- type: plain
  content: ${labelValue}
  friendlyName: FileLabel
`)
      const vault = new Vault(KEY)
      const sources = new Sources({ vault, home: directory, files: ['secrets.yml'], env: undefined, builtin: false,
        entries: [{ type: 'plain', content: inlineValue, mode: 'replace', replacement: 'INLINE_POLICY' },
          { type: 'plain', content: labelValue, friendlyName: 'InlineLabel' }],
        warn: () => { throw new Error('unexpected source warning') } })
      const engine = sources.for(directory)
      expect(engine.obfuscate(fileValue)).toBe('FILE_POLICY')
      expect(engine.obfuscate(inlineValue)).toBe('INLINE_POLICY')
      expect(vault.reveal(engine.obfuscate(fileValue))).toBe('FILE_POLICY')
      expect(vault.reveal(engine.obfuscate(inlineValue))).toBe('INLINE_POLICY')
      expect(engine.obfuscate(labelValue)).toContain('INLINELABEL_')
      expect(vault.reveal(engine.obfuscate(labelValue))).toBe(labelValue)
    } finally { rmSync(directory, { recursive: true, force: true }) }
  })

  it('can disable automatic dotenv files without disabling process environment or explicit rules', () => {
    const directory = mkdtempSync(join(tmpdir(), 'dsh-secrets-dotenv-disabled-'))
    const automatic = 'automatic-synthetic-value123'
    const environment = 'environment-synthetic-value456'
    const configured = 'configured-synthetic-value789'
    try {
      // Invalid syntax would refuse dispatch if discovery were attempted.
      writeFileSync(join(directory, '.env'), `not a dotenv assignment ${automatic}\n`)
      const config = Config({ envFiles: false })
      const sources = new Sources({ vault: new Vault(KEY), home: directory, files: [],
        entries: [{ type: 'plain', content: configured }], env: { API_KEY: environment },
        envFiles: config.envFiles, builtin: false, warn: () => { throw new Error('unexpected source warning') } })
      const engine = sources.for(directory)
      expect(engine.obfuscate(automatic)).toBe(automatic)
      expect(engine.obfuscate(environment)).not.toContain(environment)
      expect(engine.obfuscate(configured)).not.toContain(configured)
    } finally { rmSync(directory, { recursive: true, force: true }) }
  })

  it('keeps YAML and dotenv caches distinct and never lets builtin patterns or the vault key override source safety', () => {
    const directory = mkdtempSync(join(tmpdir(), 'dsh-secrets-dotenv-formats-'))
    const pattern = BUILTIN_PATTERNS[0]!.content
    const warnings: string[] = []
    try {
      writeFileSync(join(directory, '.env'), `PATTERN='${pattern}'\nPLACEHOLDER_KEY=${KEY}\n`)
      const vault = new Vault(KEY)
      const sources = new Sources({ vault, home: directory, files: ['.env'], entries: [], env: undefined, builtin: true,
        warn: message => warnings.push(message) })
      const engine = sources.for(directory)
      const hiddenPattern = engine.obfuscate(pattern)
      expect(hiddenPattern).not.toContain(pattern)
      expect(vault.reveal(hiddenPattern)).toBe(pattern)
      const hiddenKey = engine.obfuscate(KEY)
      expect(hiddenKey).not.toContain(KEY)
      expect(vault.reveal(hiddenKey)).not.toBe(KEY)
      expect(warnings).toHaveLength(1)
      expect(warnings[0]).not.toContain(pattern)
      expect(warnings[0]).not.toContain(KEY)
    } finally { rmSync(directory, { recursive: true, force: true }) }
  })

  it('refuses malformed automatic dotenv sources without forwarding their contents or parser causes', () => {
    const directory = mkdtempSync(join(tmpdir(), 'dsh-secrets-dotenv-invalid-'))
    const value = 'malformed-synthetic-value123'
    const warnings: string[] = []
    try {
      const path = join(directory, '.env')
      const sources = new Sources({ vault: new Vault(KEY), home: directory, files: [], entries: [], env: undefined, builtin: false,
        warn: message => warnings.push(message) })
      writeFileSync(path, `ORDINARY=${value}\n`)
      expect(sources.for(directory).obfuscate(value)).not.toContain(value)
      for (const text of [`invalid declaration ${value}\n`, `ORDINARY="${value}\n`, `ORDINARY="valid-synthetic-value456" ${value}\n`]) {
        writeFileSync(path, text)
        let failure: unknown
        try { sources.for(directory) } catch (error) { failure = error }
        expect(failure).toBeInstanceOf(Error)
        if (!(failure instanceof Error)) throw new Error('expected a sanitized source refusal')
        expect(failure.message).not.toContain(value)
        expect(failure.cause).toBeUndefined()
      }
      expect(warnings).toEqual([])
      writeFileSync(path, `ORDINARY=repaired-synthetic-value789\n`)
      expect(sources.for(directory).obfuscate('repaired-synthetic-value789')).not.toContain('repaired-synthetic-value789')
    } finally { rmSync(directory, { recursive: true, force: true }) }
  })

  it('refuses matching dotenv symlinks on initial discovery and after a previously regular file changes', () => {
    const directory = mkdtempSync(join(tmpdir(), 'dsh-secrets-dotenv-symlink-'))
    const value = 'linked-synthetic-value123'
    const warnings: string[] = []
    try {
      const target = join(directory, 'synthetic-target')
      const path = join(directory, '.env')
      writeFileSync(target, `ORDINARY=${value}\n`)
      symlinkSync(target, path)
      const sources = new Sources({ vault: new Vault(KEY), home: directory, files: [], entries: [], env: undefined, builtin: false,
        warn: message => warnings.push(message) })
      expect(() => sources.for(directory)).toThrow(Error)
      rmSync(path)
      writeFileSync(path, `ORDINARY=${value}\n`)
      expect(sources.for(directory).obfuscate(value)).not.toContain(value)
      rmSync(path)
      symlinkSync(target, path)
      let failure: unknown
      try { sources.for(directory) } catch (error) { failure = error }
      expect(failure).toBeInstanceOf(Error)
      if (!(failure instanceof Error)) throw new Error('expected a sanitized source refusal')
      expect(failure.message).not.toContain(value)
      expect(failure.cause).toBeUndefined()
      expect(warnings).toEqual([])
    } finally { rmSync(directory, { recursive: true, force: true }) }
  })

  it('preserves frozen canonical data and structural identities while removing stale signed replay on changed assistant content', () => {
    const value = 'Secret-123456789'
    const engine = new Obfuscator(new Vault(KEY), [{ type: 'plain', content: value }])
    const callId = ToolCallId(value)
    const message = createAssistantMessage({ source: { provider: 'test', model: 'test', replayState: { signature: 'signed-original' } }, content: [
      { type: 'reasoning', text: value }, { type: 'tool-call', id: callId, name: value, arguments: JSON.stringify({ [value]: value }) },
    ] })
    const input = freezeJson({ provider: 'test', model: 'test', messages: [message], system: value,
      tools: [{ name: value, description: value, parameters: { enum: [value] } }] }) satisfies GenerateOptions
    const original = JSON.stringify(input)
    const output = redactRequest(engine, input)
    expect(JSON.stringify(input)).toBe(original)
    expect(output.messages[0]?.content[0]).toEqual({ type: 'reasoning', text: engine.obfuscate(value) })
    const call = output.messages[0]?.content[1]
    if (call?.type !== 'tool-call') throw new Error('missing replayed call')
    expect(call.id).toBe(callId)
    expect(call.name).toBe(value)
    expect(JSON.parse(call.arguments)).toEqual({ [value]: engine.obfuscate(value) })
    const assistant = output.messages[0]
    if (assistant?.role !== 'assistant') throw new Error('missing assistant')
    expect(assistant.source.replayState).toBeUndefined()
    expect(output.system).toStartWith(value)
    expect(output.tools).toBe(input.tools)
    expect(Object.isFrozen(output)).toBe(true)
  })

  it('preserves cancellation and borrowed tool definitions while freezing only the redacted copy', () => {
    const value = 'Cancellation-Secret-123456'
    const engine = new Obfuscator(new Vault(KEY), [{ type: 'plain', content: value }])
    const controller = new AbortController()
    const lifetime = new AbortController()
    const signal = AbortSignal.any([controller.signal, lifetime.signal])
    const tools = [{ name: 'example', description: 'mutable catalog', parameters: { type: 'object' } }]
    const message = createUserMessage({ source: { kind: 'user' }, content: [{ type: 'text', text: value }] })
    const input = Object.freeze({ provider: 'test', model: 'test', messages: [message], tools, signal }) satisfies GenerateOptions
    const output = redactRequest(engine, input)
    expect(output.messages[0]?.content[0]).toEqual({ type: 'text', text: engine.obfuscate(value) })
    expect(Object.isFrozen(output.messages[0]?.content)).toBe(true)
    expect(Object.isExtensible(output.signal)).toBe(true)
    const downstream = AbortSignal.any([output.signal!, new AbortController().signal])
    controller.abort('consumer-cancelled')
    expect(downstream.aborted).toBe(true)
    expect(downstream.reason).toBe('consumer-cancelled')
    tools[0]!.description = 'updated catalog'
    expect(output.tools?.[0]?.description).toBe('updated catalog')
  })

  it('restores string values without mutating object keys or enabling __proto__ assignment', () => {
    const value = 'password123456'
    const vault = new Vault(KEY)
    const hidden = new Obfuscator(vault, [{ type: 'plain', content: value }]).obfuscate(value)
    const metadata = { administrator: true }
    const input: Record<string, unknown> = Object.fromEntries([['nested', [hidden]], [hidden, hidden], ['__proto__', metadata]])
    const result = mapStrings(input, text => vault.reveal(text))
    expect(input).toEqual(Object.fromEntries([['nested', [hidden]], [hidden, hidden], ['__proto__', metadata]]))
    expect(result).toEqual(Object.fromEntries([['nested', [value]], [hidden, value], ['__proto__', metadata]]))
    expect(Object.getPrototypeOf(result)).toBe(Object.prototype)
    expect(Object.getOwnPropertyDescriptor(result, '__proto__')?.value).toBe(metadata)
  })

  it('persists a complete owner-only key and fails closed on corruption without replacing it', () => {
    const directory = mkdtempSync(join(tmpdir(), 'dsh-secrets-key-'))
    try {
      const path = join(directory, 'private', 'secret-placeholder.key')
      const key = loadKey(path)
      expect(loadKey(path)).toBe(key)
      expect(statSync(path).mode & 0o777).toBe(0o600)
      writeFileSync(path, 'corrupted')
      expect(() => loadKey(path)).toThrow('refusing')
      expect(readFileSync(path, 'utf8')).toBe('corrupted')
    } finally { rmSync(directory, { recursive: true, force: true }) }
  })
})
