import { createHmac } from 'node:crypto'

export interface SecretEntry {
  type: 'plain' | 'regex'
  content: string
  mode?: 'obfuscate' | 'replace'
  replacement?: string
  flags?: string
  friendlyName?: string
}

export const MIN_SECRET_LENGTH = 8
const PLACEHOLDER = /\$\$(?:([A-Z0-9]{1,32})_)?([A-Z0-9]{12})(?::([ULCM]))?\$\$/g
const HASH_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
const REPLACEMENT_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'

function digest(key: string, value: string): string {
  let bits = createHmac('sha256', key).update(value).digest().readBigUInt64BE(0)
  let result = ''
  for (let i = 0; i < 12; i++) {
    result += HASH_CHARS[Number(bits % 36n)]
    bits /= 36n
  }
  return result
}

function caseHint(value: string): string | undefined {
  const letters = value.replace(/[^A-Za-z]/g, '')
  if (!letters) return undefined
  if (letters === letters.toUpperCase()) return 'U'
  if (letters === letters.toLowerCase()) return 'L'
  return letters === letters[0]!.toUpperCase() + letters.slice(1).toLowerCase() ? 'C' : 'M'
}

interface Minted {
  value: string
  base: string
  hint: string | undefined
  name: string | undefined
}

/** Shared across sessions: anything restored to a tool must be hidden wherever it returns. */
export class Vault {
  private readonly byValue = new Map<string, Minted>()
  private readonly byBase = new Map<string, Minted>()
  private readonly collisionValues = new Set<string>()
  private readonly deniedValues = new Map<string, Rule>()
  readonly values = new Set<string>()
  readonly oneWayTokens = new Set<string>()
  revision = 0

  constructor(readonly key: string) {
    this.register(key)
  }

  register(value: string): void {
    if (this.values.has(value)) return
    this.values.add(value)
    const normalized = value.replace(/[^A-Za-z0-9]/g, '').toUpperCase()
    if (normalized) this.collisionValues.add(normalized)
    this.revision++
  }

  labelIsSafe(label: string): boolean {
    for (const value of this.collisionValues) {
      if (label.includes(value) || (label.length === 32 && value.startsWith(label))) return false
    }
    return true
  }

  deny(value: string, rule: Rule): void {
    this.register(value)
    if (this.deniedValues.get(value) !== rule) {
      this.deniedValues.set(value, rule)
      this.revision++
    }
  }

  replacements(): IterableIterator<[string, Rule]> {
    return this.deniedValues.entries()
  }

  isReversible(value: string): boolean {
    for (const denied of this.deniedValues.keys()) if (value.includes(denied)) return false
    return true
  }

  minted(): IterableIterator<Minted> {
    return this.byValue.values()
  }

  token(value: string, name?: string): string {
    if (!this.isReversible(value)) throw new Error('A one-way secret cannot become a reversible capability; refusing the model request')
    let record = this.byValue.get(value)
    if (record === undefined) {
      this.register(value)
      let base: string
      let salt = 0
      do {
        base = digest(this.key, salt === 0 ? value : `${value}\0${salt}`)
        salt++
      } while (this.byBase.has(base) || this.values.has(this.format(base, caseHint(value), undefined)))
      record = { value, base, hint: caseHint(value), name }
      this.byValue.set(value, record)
      this.byBase.set(base, record)
      this.revision++
    }
    return this.format(record.base, record.hint, name)
  }

  format(base: string, hint: string | undefined, name: string | undefined): string {
    return `$$${name === undefined ? '' : `${name}_`}${base}${hint === undefined ? '' : `:${hint}`}$$`
  }

  lookup(base: string, hint: string | undefined): Minted | undefined {
    const record = this.byBase.get(base)
    return record !== undefined && (hint === undefined || hint === record.hint) ? record : undefined
  }

  reveal(text: string): string {
    if (!text.includes('$$')) return text
    return text.replace(PLACEHOLDER, (token, name: string | undefined, base: string, hint: string | undefined) => {
      const record = this.lookup(base, hint)
      return record !== undefined && (name === undefined || this.labelIsSafe(name)) && this.isReversible(record.value) ? record.value : token
    })
  }

  /** A one-way keyed stand-in; never register it in the restoration map. */
  replacement(value: string, pattern?: RegExp): string {
    const length = Array.from(value).length
    for (let salt = 0; salt < 32; salt++) {
      let result = ''
      for (let block = 0; result.length < length; block++) {
        const bytes = createHmac('sha256', this.key).update(`replace\0${salt}\0${block}\0${value}`).digest()
        for (const byte of bytes) {
          if (result.length === length) break
          result += REPLACEMENT_CHARS[byte % REPLACEMENT_CHARS.length]
        }
      }
      if (result !== value && !this.values.has(result) && (pattern === undefined || !matches(pattern, result))) return result
    }
    const marker = `$$${digest(this.key, `one-way\0${value}`)}$$`
    if (marker === value || this.values.has(marker)) throw new Error('Cannot generate a distinct secret replacement')
    this.oneWayTokens.add(marker)
    return marker
  }
}

export function compilePattern(content: string, flags = ''): RegExp {
  const literal = /^\/((?:[^\\/]|\\.)*)\/([dgimsuvy]*)$/.exec(content)
  return new RegExp(literal?.[1] ?? content, [...new Set([...flags, ...literal?.[2] ?? '', 'g'])].join(''))
}

interface Rule {
  mode: 'obfuscate' | 'replace'
  replacement: string | undefined
  name: string | undefined
  pattern?: RegExp
}
interface Run { text: string; locked: boolean; offset?: number }
interface ExistingToken { end: number; token: string }
interface TokenRange { start: number; end: number; expandedStart: number; expandedEnd: number; opaque: boolean }

function matches(pattern: RegExp, text: string): boolean {
  pattern.lastIndex = 0
  const found = pattern.test(text)
  pattern.lastIndex = 0
  return found
}

function* scan(pattern: RegExp, text: string): Generator<RegExpExecArray> {
  let cursor = 0
  try {
    while (cursor <= text.length) {
      pattern.lastIndex = cursor
      const match = pattern.exec(text)
      if (match === null) break
      cursor = pattern.lastIndex
      if (match[0].length !== 0) yield match
      else {
        const first = text.charCodeAt(cursor)
        const second = text.charCodeAt(cursor + 1)
        cursor += (pattern.unicode || pattern.unicodeSets) && first >= 0xd800 && first <= 0xdbff && second >= 0xdc00 && second <= 0xdfff ? 2 : 1
      }
    }
  } finally {
    pattern.lastIndex = 0
  }
}

/** Literal values first (longest first), then configured regexes, then credential detectors. */
export class Obfuscator {
  private readonly literals = new Map<string, Rule>()
  private readonly regexes: Rule[] = []
  private readonly discovered = new Map<string, Rule>()
  private matcher: { revision: number; pattern: RegExp; replacementPattern: RegExp; rules: Map<string, Rule> } | undefined

  constructor(readonly vault: Vault, entries: readonly SecretEntry[], warn: (message: string) => void = () => {}) {
    const effective = new Map<string, SecretEntry>()
    for (const entry of entries) {
      effective.delete(entry.content)
      effective.set(entry.content, entry)
    }
    for (const entry of effective.values()) {
      if (!entry.content || (entry.type === 'plain' && (entry.mode ?? 'obfuscate') === 'obfuscate' && entry.content.length < MIN_SECRET_LENGTH)) continue
      const rule: Rule = { mode: entry.mode ?? 'obfuscate', replacement: entry.replacement, name: entry.friendlyName }
      if (entry.type === 'plain') {
        vault.register(entry.content)
        this.literals.set(entry.content, rule)
        if (rule.mode === 'replace') vault.deny(entry.content, rule)
      } else {
        try {
          rule.pattern = compilePattern(entry.content, entry.flags)
          this.regexes.push(rule)
        } catch {
          warn('Invalid secret regex skipped (pattern omitted to avoid disclosing secrets)')
        }
      }
    }
    // Never make the HMAC key available as a reversible capability.
    this.literals.set(vault.key, { mode: 'replace', replacement: '[REDACTED_PLACEHOLDER_KEY]', name: undefined })
    for (const [value, rule] of this.literals) {
      if (rule.mode === 'obfuscate' && vault.isReversible(value)) vault.token(value, this.safeName(rule.name))
    }
  }

  /** Pre-scan the entire request so a label cannot disclose a regex value found in a later message. */
  prepare(texts: Iterable<string>): void {
    for (const text of texts) {
      const context = this.expandTokens(text)
      const expanded = context.runs.map(run => run.text).join('')
      const discover = (value: string, rule: Rule, length = value.length) => {
        // Short matches constrain public labels without becoming capabilities.
        this.vault.register(value)
        if (rule.mode === 'replace') this.vault.deny(value, rule)
        if (rule.mode === 'replace' || length >= MIN_SECRET_LENGTH) {
          if ((rule.mode === 'replace' || this.discovered.get(value)?.mode !== 'replace') && this.discovered.get(value) !== rule) {
            this.discovered.set(value, rule)
            this.matcher = undefined
          }
        }
      }
      const expandedIndex = (index: number) => {
        let delta = 0
        for (const range of context.ranges) {
          if (range.end > index) break
          delta += range.expandedEnd - range.expandedStart - (range.end - range.start)
        }
        return index + delta
      }
      for (const rule of this.regexes) {
        for (const match of scan(rule.pattern!, expanded)) {
          if (context.ranges.some(range => range.opaque && match.index >= range.expandedStart && match.index + match[0].length <= range.expandedEnd)) continue
          discover(match[0], rule)
        }
        if (expanded === text) continue
        // Regexes can depend on literal placeholder syntax as well as original bytes.
        for (const match of scan(rule.pattern!, text)) {
          let start = match.index
          let end = start + match[0].length
          if (context.ranges.some(range => start >= range.start && end <= range.end)) continue
          for (const range of context.ranges) {
            if (start < range.end && end > range.start) {
              start = Math.min(start, range.start)
              end = Math.max(end, range.end)
            }
          }
          discover(expanded.slice(expandedIndex(start), expandedIndex(end)), rule, match[0].length)
        }
      }
    }
  }

  private safeName(name: string | undefined): string | undefined {
    if (name === undefined) return undefined
    const label = name.replace(/[^A-Za-z0-9]/g, '').toUpperCase().slice(0, 32)
    if (!label || !this.vault.labelIsSafe(label)) return undefined
    if (this.regexes.some(rule => matches(rule.pattern!, name) || matches(rule.pattern!, label))) return undefined
    return label
  }

  private output(value: string, rule: Rule): string | undefined {
    if (rule.mode === 'obfuscate') {
      if (value.length < MIN_SECRET_LENGTH) return undefined
      return this.vault.token(value, this.safeName(rule.name))
    }
    const output = rule.replacement ?? this.vault.replacement(value, rule.pattern)
    if (output.includes(value)) throw new Error('A secret replacement contains its original value; refusing the model request')
    return output
  }

  private literalMatcher(): { pattern: RegExp; replacementPattern: RegExp; rules: Map<string, Rule> } {
    if (this.matcher?.revision === this.vault.revision) return this.matcher
    const rules = new Map<string, Rule>()
    for (const record of this.vault.minted()) rules.set(record.value, { mode: 'obfuscate', replacement: undefined, name: record.name })
    for (const [value, rule] of this.discovered) rules.set(value, rule)
    for (const [value, rule] of this.literals) rules.set(value, rule)
    for (const [value, rule] of this.discovered) if (rule.mode === 'replace') rules.set(value, rule)
    for (const [value, rule] of this.vault.replacements()) rules.set(value, rule)
    const needles = [...rules.keys()].sort((a, b) => b.length - a.length)
    const pattern = new RegExp(needles.map(value => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'), 'g')
    const replacements = needles.filter(value => rules.get(value)!.mode === 'replace')
    const replacementPattern = new RegExp(replacements.map(value => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'), 'g')
    this.matcher = { revision: this.vault.revision, pattern, replacementPattern, rules }
    return this.matcher
  }

  /** Expand known capabilities for regex context; preserve their spelling on exact re-sealing. */
  private expandTokens(text: string): { runs: Run[]; tokens: Map<number, ExistingToken>; ranges: TokenRange[] } {
    if (!text.includes('$$')) return { runs: text ? [{ text, locked: false, offset: 0 }] : [], tokens: new Map(), ranges: [] }
    const runs: Run[] = []
    const tokens = new Map<number, ExistingToken>()
    const ranges: TokenRange[] = []
    // A registered raw literal may itself contain a valid capability's spelling.
    const rawRanges = [...scan(this.literalMatcher().pattern, text)].map(match => ({ start: match.index, end: match.index + match[0].length }))
    let last = 0
    let offset = 0
    let unlocked = ''
    const append = (value: string) => { unlocked += value; offset += value.length }
    for (const match of text.matchAll(PLACEHOLDER)) {
      if (rawRanges.some(range => match.index >= range.start && match.index + match[0].length <= range.end)) continue
      const record = this.vault.lookup(match[2]!, match[3])
      const oneWay = this.vault.oneWayTokens.has(match[0])
      if (record === undefined && !oneWay) continue
      append(text.slice(last, match.index))
      const expandedStart = offset
      if (record !== undefined) {
        const token = this.vault.format(record.base, record.hint, this.safeName(match[1]))
        tokens.set(offset, { end: offset + record.value.length, token })
        append(record.value)
      } else {
        if (unlocked) runs.push({ text: unlocked, locked: false, offset: offset - unlocked.length })
        runs.push({ text: match[0], locked: true })
        unlocked = ''
        offset += match[0].length
      }
      ranges.push({ start: match.index, end: match.index + match[0].length, expandedStart, expandedEnd: offset, opaque: record === undefined })
      last = match.index + match[0].length
    }
    append(text.slice(last))
    if (unlocked) runs.push({ text: unlocked, locked: false, offset: offset - unlocked.length })
    return { runs, tokens, ranges }
  }

  obfuscate(text: string): string {
    if (!text) return text
    let result = text
    // Learn regex values before literal replacement erases lookaround context.
    // Re-scan replacement output too; round-trip alone is not proof of secrecy.
    for (let pass = 0; pass < 8; pass++) {
      this.prepare([result])
      const expanded = this.expandTokens(result)
      let runs = expanded.runs
      const matcher = this.literalMatcher()
      runs = this.replaceRuns(runs, matcher.replacementPattern, value => this.output(value, matcher.rules.get(value)!))
      runs = this.replaceRuns(runs, matcher.pattern, (value, offset) => {
        const rule = matcher.rules.get(value)!
        const token = offset === undefined ? undefined : expanded.tokens.get(offset)
        if (rule.mode === 'obfuscate' && this.vault.isReversible(value) && offset !== undefined && token?.end === offset + value.length) return token.token
        return this.output(value, rule)
      })
      const next = runs.map(run => run.text).join('')
      if (next === result) return next
      result = next
    }
    throw new Error('Secret replacements form a cycle; refusing the model request')
  }

  private replaceRuns(runs: readonly Run[], pattern: RegExp, output: (value: string, offset?: number) => string | undefined): Run[] {
    const result: Run[] = []
    for (const run of runs) {
      if (run.locked) { result.push(run); continue }
      let last = 0
      for (const match of scan(pattern, run.text)) {
        const offset = run.offset === undefined ? undefined : run.offset + match.index
        const replacement = output(match[0], offset)
        if (replacement === undefined) continue
        if (match.index > last) result.push({ text: run.text.slice(last, match.index), locked: false, ...(run.offset === undefined ? {} : { offset: run.offset + last }) })
        result.push({ text: replacement, locked: true })
        last = match.index + match[0].length
      }
      if (last === 0) result.push(run)
      else if (last < run.text.length) result.push({ text: run.text.slice(last), locked: false, ...(run.offset === undefined ? {} : { offset: run.offset + last }) })
    }
    return result
  }
}

/** Only values are walked: object keys are parameter identifiers, not conversation prose. */
export function mapStrings<T>(value: T, transform: (text: string) => string): T {
  if (typeof value === 'string') return transform(value) as T
  if (Array.isArray(value)) {
    let output: unknown[] | undefined
    value.forEach((item: unknown, index: number) => {
      const next = mapStrings(item, transform)
      if (next !== item) { output ??= value.slice(); output![index] = next }
    })
    return (output ?? value) as T
  }
  if (value !== null && typeof value === 'object') {
    let output: Record<string, unknown> | undefined
    const entries = Object.entries(value)
    for (const [key, item] of entries) {
      const next = mapStrings(item, transform)
      if (next === item) continue
      output ??= Object.fromEntries(entries)
      Object.defineProperty(output, key, { value: next, enumerable: true, writable: true, configurable: true })
    }
    return (output ?? value) as T
  }
  return value
}
