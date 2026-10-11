import z from '@deepseek-ai/schemastery'
import { lstatSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { homedir } from 'node:os'
import { isAbsolute, join, resolve } from 'node:path'
import { parseEnv } from 'node:util'
import { parse } from 'yaml'
import { compilePattern, MIN_SECRET_LENGTH, Obfuscator, type SecretEntry, type Vault } from './obfuscator.ts'

export const SecretSchema: z<SecretEntry> = z.object({
  type: z.union(['plain', 'regex'] as const).required(),
  content: z.string().required(),
  mode: z.union(['obfuscate', 'replace'] as const),
  replacement: z.string(),
  flags: z.string(),
  friendlyName: z.string(),
})

const left = '(?<![A-Za-z0-9_-])'
const right = '(?![A-Za-z0-9_-])'
/** Credential patterns from oh-my-pi's secrets/patterns.ts; no irreversible entropy gate. */
export const BUILTIN_PATTERNS: readonly SecretEntry[] = ([
  ['Credential', String.raw`(?<![a-zA-Z0-9_*-])(gh[opusr]_[a-zA-Z0-9_*]{36,}|github_pat_[a-zA-Z0-9_*]{36,}|glpat-[a-zA-Z0-9_*-]{20,}|sk-proj-[a-zA-Z0-9_*-]{36,}|sk-ant-[a-zA-Z0-9_*-]{36,}|sk-[a-zA-Z0-9_*-]{48,})(?![a-zA-Z0-9_*-])`, 'i'],
  ['AWSAccessKey', `${left}(?:AKIA|ASIA)[A-Z0-9]{16}${right}`],
  ['GoogleAPIKey', `${left}AIza[A-Za-z0-9_-]{30,}${right}`],
  ['SlackToken', `${left}xox[abprs]-[A-Za-z0-9-]{10,}${right}`],
  ['NpmToken', `${left}npm_[A-Za-z0-9]{30,}${right}`],
  ['StripeKey', `${left}(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}${right}`],
  ['StripeWebhookSecret', `${left}whsec_[A-Za-z0-9]{20,}${right}`],
  ['HuggingFaceToken', `${left}hf_[A-Za-z0-9]{30,}${right}`],
  ['SendGridKey', `${left}SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}${right}`],
  ['JWT', `${left}eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}${right}`],
  ['BearerToken', String.raw`(?<=\bBearer )[A-Za-z0-9._~+/=-]{20,}(?![A-Za-z0-9_-])`, 'i'],
  ['PrivateKey', String.raw`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`],
] satisfies [string, string, string?][]).map(([friendlyName, content, flags]) => ({
  type: 'regex', content, friendlyName, ...flags === undefined ? {} : { flags },
}))

function addUrlPasswords(value: string, add: (value: string) => void): void {
  const password = /^[a-z][a-z0-9+.-]*:\/\/[^/:@?#\s]*:([^/?#\s]+)@/i.exec(value)?.[1]
  if (password === undefined) return
  add(password)
  try { add(decodeURIComponent(password)) } catch { /* Raw password remains protected. */ }
}

/** Includes connection-URL passwords even when the variable name is not secret-shaped. */
export function envEntries(env: Readonly<Record<string, string | undefined>>): SecretEntry[] {
  const values = new Set<string>()
  const add = (value: string): void => {
    if (value.length >= MIN_SECRET_LENGTH) values.add(value)
  }
  for (const [name, value] of Object.entries(env)) {
    if (value === undefined) continue
    if (/(?:KEY|SECRET|TOKEN|PASSWORD|PASS|AUTH|CREDENTIAL|PRIVATE|OAUTH)(?:_|$)/i.test(name)) add(value)
    addUrlPasswords(value, add)
  }
  return [...values].map(content => ({ type: 'plain', content }))
}

/** Frame declarations so duplicate assignments and the raw spelling of escaped values remain protected. */
function dotenvEntries(text: string): SecretEntry[] {
  const values = new Set<string>()
  const add = (value: string): void => {
    if (value.length >= MIN_SECRET_LENGTH) values.add(value)
  }
  if (text.startsWith('\uFEFF')) text = text.slice(1)
  let offset = 0
  while (offset < text.length) {
    let end = text.indexOf('\n', offset)
    if (end === -1) end = text.length
    const line = text.slice(offset, end)
    if (/^[ \t\r]*(?:#.*)?$/.test(line)) {
      offset = end + 1
      continue
    }
    const assignment = /^[ \t\r]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*/.exec(line)
    if (assignment === null || line.includes('\0')) throw new Error('Invalid dotenv syntax')
    const start = offset + assignment[0].length
    const quote = text[start]
    let raw: string
    if (quote === '"' || quote === "'" || quote === '`') {
      const closing = text.indexOf(quote, start + 1)
      if (closing === -1) throw new Error('Invalid dotenv syntax')
      end = text.indexOf('\n', closing + 1)
      if (end === -1) end = text.length
      if (!/^[ \t\r]*(?:#.*)?$/.test(text.slice(closing + 1, end))) throw new Error('Invalid dotenv syntax')
      raw = text.slice(start + 1, closing)
    } else {
      const comment = text.indexOf('#', start)
      raw = text.slice(start, comment !== -1 && comment < end ? comment : end).trim()
    }
    const parsed = parseEnv(text.slice(offset, end))
    const name = assignment[1]!
    if (!Object.hasOwn(parsed, name)) throw new Error('Invalid dotenv syntax')
    add(raw)
    add(parsed[name]!)
    addUrlPasswords(raw, add)
    if (parsed[name] !== raw) addUrlPasswords(parsed[name]!, add)
    offset = end + 1
  }
  return [...values].map(content => ({ type: 'plain', content }))
}

/** Invalid metadata never disables an otherwise valid secret; warnings contain no YAML snippets. */
export function parseEntries(raw: unknown, location: string, warn: (message: string) => void): SecretEntry[] {
  if (!Array.isArray(raw)) {
    warn(`${location}: expected a YAML array of secret entries`)
    return []
  }
  const result: SecretEntry[] = []
  for (const [index, item] of raw.entries()) {
    if (item === null || typeof item !== 'object' || Array.isArray(item)) {
      warn(`${location}[${index}]: expected a secret entry mapping`)
      continue
    }
    const { friendlyName, ...fields } = item
    let entry: SecretEntry
    try {
      entry = SecretSchema(fields)
      if (!entry.content) throw new Error('empty content')
      if (entry.type === 'regex') compilePattern(entry.content, entry.flags)
    } catch {
      warn(`${location}[${index}]: invalid secret entry or regex; entry skipped`)
      continue
    }
    if (typeof friendlyName === 'string' && /[A-Za-z0-9]/.test(friendlyName)) entry.friendlyName = friendlyName
    else if (friendlyName !== undefined) warn(`${location}[${index}]: invalid friendlyName ignored`)
    result.push(entry)
  }
  return result
}

export function expandPath(path: string, home: string): string {
  if (path === '~' || path.startsWith('~/')) return join(homedir(), path.slice(1))
  if (path === '$DSH_HOME' || path.startsWith('$DSH_HOME/')) return join(home, path.slice('$DSH_HOME'.length))
  return path
}

interface FileState { version: string; entries: readonly SecretEntry[] }
interface DirectoryState { version: string; paths: readonly string[] }
export interface SourceOptions {
  vault: Vault
  home: string
  files: readonly string[]
  entries: readonly SecretEntry[]
  env: Readonly<Record<string, string | undefined>> | undefined
  envFiles?: boolean
  builtin: boolean
  warn: (message: string) => void
}

export class Sources {
  private readonly environment: readonly SecretEntry[]
  private readonly files = new Map<string, FileState>()
  private readonly directories = new Map<string, DirectoryState>()
  private readonly contexts = new Map<string, { version: string; engine: Obfuscator }>()

  constructor(private readonly options: SourceOptions) {
    this.environment = options.env === undefined ? [] : envEntries(options.env)
  }

  /** Session cwd, not the host cwd, selects the project file; global files remain shared. */
  for(cwd: string): Obfuscator {
    const directory = resolve(cwd)
    const discovered = this.options.envFiles === false ? [] : this.envPaths(directory).map(path => this.readEnv(path))
    const states = this.options.files.map(file => {
      const expanded = expandPath(file, this.options.home)
      return this.readYaml(isAbsolute(expanded) ? expanded : resolve(directory, expanded))
    })
    const version = [...discovered, ...states].map(state => state.version).join('\n')
    const existing = this.contexts.get(directory)
    if (existing?.version === version) return existing.engine
    const effective = new Map<string, SecretEntry>()
    const add = (entries: readonly SecretEntry[]): void => {
      for (const entry of entries) {
        effective.delete(entry.content)
        effective.set(entry.content, entry)
      }
    }
    add(this.environment)
    for (const state of discovered) add(state.entries)
    for (const state of states) add(state.entries)
    add(this.options.entries)
    const builtin = this.options.builtin ? BUILTIN_PATTERNS.filter(entry => !effective.has(entry.content)) : []
    const engine = new Obfuscator(this.options.vault, [...effective.values(), ...builtin], this.options.warn)
    this.contexts.set(directory, { version, engine })
    return engine
  }

  private readYaml(path: string): FileState {
    let version: string
    try {
      const stat = statSync(path)
      version = `yaml:${path}:${stat.dev}:${stat.ino}:${stat.mtimeMs}:${stat.ctimeMs}:${stat.size}`
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') this.options.warn(`${path}: unable to inspect secrets file`)
      return { version: `yaml:${path}:missing`, entries: [] }
    }
    const identity = `yaml:${path}`
    const existing = this.files.get(identity)
    if (existing?.version === version) return existing
    let text: string
    try { text = readFileSync(path, 'utf8') } catch {
      this.options.warn(`${path}: unable to read secrets file`)
      return { version: `${version}:unreadable`, entries: [] }
    }
    let entries: readonly SecretEntry[] = []
    try { entries = parseEntries(parse(text), path, this.options.warn) } catch {
      this.options.warn(`${path}: unable to parse secrets YAML (contents omitted)`)
    }
    const state = { version, entries }
    this.files.set(identity, state)
    return state
  }

  private envPaths(directory: string): readonly string[] {
    let version: string
    try {
      const stat = statSync(directory)
      version = `${stat.dev}:${stat.ino}:${stat.mtimeMs}:${stat.ctimeMs}:${stat.size}`
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return []
      throw new Error('Unable to inspect the session directory for dotenv sources; refusing the model request (contents omitted)')
    }
    const existing = this.directories.get(directory)
    if (existing?.version === version) return existing.paths
    let paths: string[]
    try {
      paths = readdirSync(directory, { withFileTypes: true })
        .filter(entry => {
          if (entry.name !== '.env' && !entry.name.startsWith('.env.')) return false
          if (entry.isDirectory()) return false
          if (!entry.isFile()) throw new Error('Unsupported automatic dotenv source')
          return true
        })
        .map(entry => join(directory, entry.name))
        .sort()
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return []
      throw new Error('Unable to discover session dotenv sources; refusing the model request (contents omitted)')
    }
    this.directories.set(directory, { version, paths })
    return paths
  }

  private readEnv(path: string): FileState {
    const identity = `dotenv:${path}`
    let version: string
    try {
      const stat = lstatSync(path)
      if (stat.isDirectory()) return { version: `${identity}:not-file`, entries: [] }
      if (!stat.isFile()) throw new Error('Unsupported automatic dotenv source')
      version = `${identity}:${stat.dev}:${stat.ino}:${stat.mtimeMs}:${stat.ctimeMs}:${stat.size}`
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { version: `${identity}:missing`, entries: [] }
      throw new Error('Unable to inspect an automatic dotenv source; refusing the model request (contents omitted)')
    }
    const existing = this.files.get(identity)
    if (existing?.version === version) return existing
    let text: string
    try { text = readFileSync(path, 'utf8') } catch {
      throw new Error('Unable to read an automatic dotenv source; refusing the model request (contents omitted)')
    }
    let entries: readonly SecretEntry[]
    try { entries = dotenvEntries(text) } catch {
      throw new Error('Unable to parse an automatic dotenv source; refusing the model request (contents omitted)')
    }
    const state = { version, entries }
    this.files.set(identity, state)
    return state
  }
}
