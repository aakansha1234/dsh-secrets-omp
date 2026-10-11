/**
 * Execution after rebuilding the plugin: bun tests/web-audit/runner.ts
 * Narrow diagnostic execution: bun tests/web-audit/runner.ts --case environment-secret-name
 * Optional prerequisites: nativeLauncher/nativePeers in startWebAudit(options).
 * runWebAudit() returns status/count-only JSON. startWebAudit() supports browser
 * proof through bootstrapUrl (private: never print it) and explicit close().
 * Browser lane: await startWebAudit(); await audit.prepareBrowserCase(name);
 * open audit.bootstrapUrl privately, create a minimal session with returned cwd,
 * submit a prompt, then await audit.browserEvidence(sessionId), which proves
 * successful raw tool stdout/canonical history as well as wire privacy.
 * currentEvidence() is wire-only; both report only name/classification/count/status.
 * Always await audit.close() in finally; run() owns case selection and restarts.
 * No registry access, profile SDK copies, caller HOME/rules, or real auth.
 */
import { mkdtemp, mkdir, cp, readFile, writeFile, symlink, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { randomUUID } from 'node:crypto'
import { auditCases, probes, type AuditCase, type Classification } from './cases.ts'

const resources = '/Applications/DeepSeek Harness.app/Contents/Resources'
const repo = resolve(import.meta.dir, '../..')
const tokenPattern = /\$\$(?:[A-Z0-9]{1,32}_)?[A-Z0-9]{12}(?::[ULCM])?\$\$/g
export interface AuditRow { name: string; classification: Classification; outboundRequestCount: number; status: string }
interface RpcValue {
  sessionId?: string
  unchanged?: boolean
  borrowedSignal?: boolean
  denied?: boolean
  notExecuted?: boolean
  historyContainsOld?: boolean
  historyContainsNew?: boolean
  sourceRefused?: boolean
  guard?: number
  classification?: number
  execution?: number
  bashSuccessCount?: number
  bashFailureCount?: number
  bashStdoutHasExpected?: boolean
  canonicalToolHasExpected?: boolean
  toolFailure?: string
}
type ModelBlock = { type: 'text'; text: string } | { type: 'tool_use'; id: string; name: string; input: object }
function record(value: unknown): value is Record<string, unknown> { return typeof value === 'object' && value !== null && !Array.isArray(value) }
export interface AuditOptions { nativeLauncher?: string; nativePeers?: string; timeoutMs?: number; caseName?: string }
class AuditFailure extends Error {}
function textResponse(blocks: ModelBlock[], index: number, stopReason = 'end_turn') {
  const events: object[] = [{ type: 'message_start', message: { id: `audit_${index}`, model: 'deepseek-flash', usage: { input_tokens: 12, output_tokens: 1 } } }]
  blocks.forEach((block, i) => {
    events.push({ type: 'content_block_start', index: i, content_block: block.type === 'tool_use' ? { ...block, input: {} } : { type: 'text', text: '' } })
    events.push({ type: 'content_block_delta', index: i, delta: block.type === 'tool_use' ? { type: 'input_json_delta', partial_json: JSON.stringify(block.input) } : { type: 'text_delta', text: block.text } })
    events.push({ type: 'content_block_stop', index: i })
  })
  events.push({ type: 'message_delta', delta: { stop_reason: stopReason }, usage: { output_tokens: 5 } }, { type: 'message_stop' })
  return new Response(events.map(event => `data: ${JSON.stringify(event)}\n\n`).join(''), { headers: { 'content-type': 'text/event-stream' } })
}
export async function startWebAudit(options: AuditOptions = {}) {
  const root = await mkdtemp(join(tmpdir(), 'dsh-native-web-wire-'))
  const home = join(root, 'home')
  const dshHome = join(home, '.dsh')
  const profile = join(dshHome, 'profiles', 'web')
  const workspace = join(root, 'workspaces')
  const fixture = join(profile, 'node_modules', 'dsh-web-wire-audit-fixture')
  const plugin = join(profile, 'node_modules', 'dsh-secrets-omp')
  const editCwd = join(workspace, 'tool-edit-old-new-values')
  const matrix = auditCases()
  let current: AuditCase | undefined
  let bodies: string[] = []
  let stage = 0
  let lastToken: string | undefined
  const server = Bun.serve({ hostname: '127.0.0.1', port: 0, async fetch(request) {
    if (request.method !== 'POST' || new URL(request.url).pathname !== '/anthropic/v1/messages') return new Response('not found', { status: 404 })
    // Never read request auth or cookies. Only synthetic model bodies remain in memory.
    const body = await request.text()
    bodies.push(body)
    stage++
    const tokens = body.match(tokenPattern) ?? []
    if (tokens.length) lastToken = tokens[0]
    if (current?.command && stage === 1) return textResponse([{ type: 'tool_use', id: 'audit_read', name: 'bash', input: { command: current.command.replace(/^node /, `${JSON.stringify(process.execPath)} `), description: 'Read the isolated synthetic audit fixture', workdir: join(workspace, current.name) } }], stage, 'tool_use')
    if (current?.mode === 'edit') {
      if (stage === 1) return textResponse([{ type: 'tool_use', id: 'audit_read', name: 'bash', input: { command: 'cat .env', description: 'Read the isolated synthetic dotenv fixture', workdir: editCwd } }], stage, 'tool_use')
      if (stage === 2 && lastToken) return textResponse([{ type: 'tool_use', id: 'audit_edit', name: 'audit_edit', input: { old_text: lastToken, new_text: `${lastToken}x` } }], stage, 'tool_use')
    }
    return textResponse([{ type: 'text', text: 'Synthetic audit continuation complete.' }], stage)
  } })
  let child: Bun.Subprocess<'ignore', 'pipe', 'pipe'> | undefined
  let cookie = ''
  let baseUrl = ''
  let bootstrapUrl = ''
  let closed = false
  let stderrBuffer = ''
  function safeDiagnostic(message: string) {
    message = message.replace(/\x1b\[[0-9;]*m/g, '').replace(/^.*(?:authorization|cookie|api.key|bootstrap|token=).*$/gim, '[private transport diagnostic omitted]')
    message = message.replace(/https?:\/\/[^\s"'<>]+/g, '[endpoint omitted]').replace(tokenPattern, '[placeholder omitted]').replaceAll(root, '[fixture]')
    for (const value of [...Object.values(probes), ...matrix.flatMap(item => item.hidden ?? [])]) message = message.replaceAll(value, '[synthetic value omitted]')
    return message.replace(/\s+/g, ' ').slice(0, 700)
  }
  function failureStatus(prefix: string, error: unknown) {
    const message = error instanceof Error ? error.message : 'unknown fixture failure'
    const selected = stderrBuffer.split('\n').filter(line => /error|failed|unavailable|refus|waiting|startup/i.test(line)).slice(-3).join(' | ')
    return `${prefix}:${safeDiagnostic(message)}${selected ? `; native:${safeDiagnostic(selected)}` : ''}`
  }
  const timeoutMs = options.timeoutMs ?? 45000
  async function closeHost() {
    if (!child) return
    const running = child
    child = undefined
    running.kill('SIGTERM')
    const timer = setTimeout(() => running.kill('SIGKILL'), 5000)
    try { await running.exited } finally { clearTimeout(timer) }
  }
  async function close() {
    if (closed) return
    closed = true
    try { await closeHost() } finally { server.stop(true); await rm(root, { recursive: true, force: true }) }
  }
  async function boot() {
    // HOME, shell roots, provider credentials, proxy settings, launch rule paths
    // and startup dotenv all live in the owned empty tree, not the caller's env.
    const env = {
      HOME: home, PATH: `${dirname(process.execPath)}:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin`,
      TMPDIR: join(root, 'tmp'), DSH_HOME: dshHome, LANG: 'en_US.UTF-8', TERM: 'dumb',
      DSH_TELEMETRY_DISABLED: '1', DSH_PERMISSION_MODE: 'danger-full-access',
      DSH_AGENTS_HOME: join(root, 'agents'), DSH_BUNDLED_SKILL_DIR: join(root, 'skills'),
      SYNTHETIC_TOKEN: probes.env, SYNTHETIC_PUBLIC_VALUE: probes.public,
      MONKEY: 'SyntheticOddEnvName-Ll123456', SYNTHETIC_AUTHORIZATION: 'SyntheticNonSuffixEnv-Mm123456',
      SYNTHETIC_DATA_ENDPOINT: `postgres://user:${probes.encodedPassword}@host/db`,
      DSH_AUDIT_MESSAGES_URL: `http://127.0.0.1:${server.port}/anthropic`,
      DSH_AUDIT_FILE_VALUE: probes.file, DSH_AUDIT_UPDATED_VALUE: probes.updated,
      DSH_AUDIT_EDIT_CWD: editCwd,
    }
    child = Bun.spawn([options.nativeLauncher ?? join(resources, 'runtime/cli/bin/dsh'), 'web', '--no-open', '--host', '127.0.0.1', '--port', '0'], { cwd: root, env, stdin: 'ignore', stdout: 'pipe', stderr: 'pipe' })
    const running = child
    // Keep bounded fixture-only diagnostics; sanitization drops auth/cookie/URL
    // lines before any diagnostic becomes part of the status-only report.
    void (async () => {
      const reader = running.stderr.getReader()
      const decoder = new TextDecoder()
      while (true) {
        const { value, done } = await reader.read()
        if (done) break
        stderrBuffer = (stderrBuffer + decoder.decode(value, { stream: true })).slice(-16384)
      }
    })().catch(() => { stderrBuffer += '\nnative diagnostic reader failed' })
    let resolveReady!: (value: string) => void
    let rejectReady!: (error: Error) => void
    const ready = new Promise<string>((yes, no) => { resolveReady = yes; rejectReady = no })
    void (async () => {
      const reader = running.stdout.getReader()
      const decoder = new TextDecoder()
      let buffer = ''
      while (true) {
        const { value, done } = await reader.read()
        if (done) break
        buffer = (buffer + decoder.decode(value, { stream: true })).slice(-16384)
        const match = buffer.match(/http:\/\/127\.0\.0\.1:\d+\/\?token=[A-Za-z0-9_-]+/)
        if (match) resolveReady(match[0])
      }
    })().catch(() => rejectReady(new Error('native-host-output-failed')))
    void running.exited.then(code => rejectReady(new Error(`native-host-exited-${code}`)))
    const timer = setTimeout(() => rejectReady(new Error('native-host-ready-timeout')), timeoutMs)
    try { bootstrapUrl = await ready } finally { clearTimeout(timer) }
    baseUrl = new URL(bootstrapUrl).origin
    const login = await fetch(bootstrapUrl, { redirect: 'manual' })
    if (login.status !== 303) throw new Error('native-host-login-failed')
    cookie = login.headers.get('set-cookie')?.split(';')[0] ?? ''
    if (!cookie) throw new Error('native-host-cookie-missing')
  }
  async function rpc(method: string, request: object) {
    const response = await fetch(`${baseUrl}/api/${method}`, { method: 'POST', headers: { 'content-type': 'application/json', cookie }, body: JSON.stringify({ type: 'client-request', rpcId: randomUUID(), method, payload: { args: { request } } }), signal: AbortSignal.timeout(timeoutMs) })
    if (!response.ok) throw new AuditFailure(`${method}:http-${response.status}:${safeDiagnostic(await response.text())}`)
    const envelope: unknown = await response.json()
    if (!record(envelope) || !record(envelope.result)) throw new AuditFailure(`${method}:invalid-rpc-envelope`)
    if (envelope.result.ok !== true) {
      const error = record(envelope.result.error) ? envelope.result.error : {}
      throw new AuditFailure(`${method}:${typeof error.code === 'string' ? error.code : 'unknown-rpc-error'}:${safeDiagnostic(typeof error.message === 'string' ? error.message : 'missing error message')}`)
    }
    const value = envelope.result.value
    if (!record(value)) throw new Error('native-host-rpc-value-invalid')
    for (const field of ['sessionId', 'toolFailure']) if (field in value && typeof value[field] !== 'string') throw new Error('native-host-rpc-field-invalid')
    for (const field of ['unchanged', 'borrowedSignal', 'denied', 'notExecuted', 'historyContainsOld', 'historyContainsNew', 'sourceRefused', 'bashStdoutHasExpected', 'canonicalToolHasExpected']) if (field in value && typeof value[field] !== 'boolean') throw new Error('native-host-rpc-field-invalid')
    for (const field of ['guard', 'classification', 'execution', 'bashSuccessCount', 'bashFailureCount']) if (field in value && typeof value[field] !== 'number') throw new Error('native-host-rpc-field-invalid')
    // Every consumed field is validated above; unrelated native response fields stay unused.
    return value as RpcValue
  }
  async function createSession(name: string, cwd: string) {
    const created = await rpc('session/create', { sessionId: `wire-${name}`, cwd, agentPreset: 'minimal' })
    if (typeof created.sessionId !== 'string') throw new Error('native-host-session-id-missing')
    await rpc('session/selectModel', { sessionId: created.sessionId, provider: 'deepseek-official', model: 'deepseek-flash' })
    return created.sessionId
  }
  async function prompt(sessionId: string, text: string, historyValue?: string, expectedToolValues: readonly string[] = []) {
    await rpc('session/prompt', { requestId: randomUUID(), sessionId, mode: 'queue', content: [{ type: 'text', text }] })
    return rpc('wireAudit/idle', { sessionId, expectedToolValues, ...historyValue === undefined ? {} : { historyValue } })
  }
  try {
    if (options.caseName !== undefined && !matrix.some(item => item.name === options.caseName) && !['history-restart-source-changed', 'history-restart-source-deleted'].includes(options.caseName)) throw new AuditFailure('unknown-audit-case')
    await mkdir(join(root, 'tmp'), { recursive: true })
    await mkdir(fixture, { recursive: true })
    await mkdir(plugin, { recursive: true })
    await mkdir(workspace, { recursive: true })
    await cp(join(repo, 'lib'), join(plugin, 'lib'), { recursive: true })
    await cp(join(repo, 'cordis.patch.yml'), join(plugin, 'cordis.patch.yml'))
    const pluginManifest = JSON.parse(await readFile(join(repo, 'package.json'), 'utf8'))
    delete pluginManifest.devDependencies
    await writeFile(join(plugin, 'package.json'), JSON.stringify(pluginManifest))
    // Non-SDK yaml dependency is reused locally; Host owns every SDK peer.
    await mkdir(join(plugin, 'node_modules'), { recursive: true })
    await symlink(join(repo, 'node_modules/yaml'), join(plugin, 'node_modules/yaml'))
    const nativePeers = options.nativePeers ?? join(resources, 'app.asar/dsh/node_modules')
    await writeFile(join(fixture, 'index.js'), (await readFile(join(import.meta.dir, 'fixture.js'), 'utf8')).replaceAll('__NATIVE_PEERS__', nativePeers))
    await writeFile(join(fixture, 'package.json'), JSON.stringify({ name: 'dsh-web-wire-audit-fixture', version: '0.0.0', type: 'module', main: 'index.js', dsh: { bundle: { patch: './cordis.patch.yml' } } }))
    const disabled = ['hmr', 'llm-deepseek', 'llm-deepseek-account', 'llm-pi-ai', 'session-title-llm', 'session-log-deepseek', 'web-search-deepseek', 'desktop-product-telemetry', 'product-analytics']
    const fixturePatch = [
      ...disabled.map(id => ({ id, disabled: true })),
      { id: 'ui-plugin-manager', config: { registryProbeEnabled: false } },
      { id: 'preset-minimal', config: { id: 'minimal', order: 3, plugins: [{ id: 'audit-bash', name: '@deepseek-ai/dsh-tool-bash' }] } },
      { insert: [{ id: 'wire-audit-fixture', name: 'dsh-web-wire-audit-fixture' }] },
      { id: 'dsh-secrets-omp', config: { secrets: matrix.flatMap(item => item.inline ?? []) } },
    ]
    await writeFile(join(fixture, 'cordis.patch.yml'), JSON.stringify(fixturePatch))
    await writeFile(join(profile, 'package.json'), JSON.stringify({ name: 'dsh-profile-web', private: true, type: 'module', dependencies: { 'dsh-secrets-omp': `file:${plugin}`, 'dsh-web-wire-audit-fixture': `file:${fixture}` }, dsh: { profile: { bundles: ['@deepseek-ai/dsh-base', '@deepseek-ai/dsh-web-app', 'dsh-secrets-omp', 'dsh-web-wire-audit-fixture'] } } }))
    await writeFile(join(profile, 'cordis.yml'), '[]\n')
    await writeFile(join(profile, 'cordis.patch.yml'), '[]\n')
    await boot()
  } catch (error) {
    await close()
    throw new AuditFailure(failureStatus('setup-failed', error))
  }
  async function prepareBrowserCase(name = 'tool-edit-old-new-values') {
    const item = matrix.find(candidate => candidate.name === name)
    if (!item) throw new Error('unknown-audit-case')
    current = item; bodies = []; stage = 0; lastToken = undefined; stderrBuffer = ''
    const cwd = join(workspace, item.name)
    await mkdir(cwd, { recursive: true })
    for (const [relative, contents] of Object.entries(item.files ?? {})) {
      const path = join(cwd, relative)
      await mkdir(dirname(path), { recursive: true })
      // Only runtime-created synthetic source files inside the owned temp root.
      await writeFile(path, contents)
    }
    if (item.rules) { await mkdir(join(cwd, '.dsh'), { recursive: true }); await writeFile(join(cwd, '.dsh/secrets.yml'), JSON.stringify(item.rules)) }
    if (item.globalRules) await writeFile(join(dshHome, 'secrets.yml'), JSON.stringify(item.globalRules))
    return { name: item.name, cwd }
  }
  function currentEvidence(): AuditRow {
    if (!current) throw new Error('audit-case-not-selected')
    const strings: string[] = []
    const visit = (value: unknown) => {
      if (typeof value === 'string') {
        strings.push(value)
        // Tool arguments are a JSON string inside the real HTTP body.
        if (value.startsWith('{') || value.startsWith('[')) {
          try { visit(JSON.parse(value)) } catch { }
        }
      } else if (Array.isArray(value)) value.forEach(visit)
      else if (record(value)) Object.values(value).forEach(visit)
    }
    for (const body of bodies) visit(JSON.parse(body))
    let status = bodies.length ? 'pass' : 'no-wire-evidence'
    if (current.hidden?.some(value => strings.some(text => text.includes(value)))) status = 'outbound-leak'
    if (current.visible?.some(value => !strings.some(text => text.includes(value)))) status = 'expected-visible-value-missing'
    return { name: current.name, classification: current.classification, outboundRequestCount: bodies.length, status }
  }
  async function browserEvidence(sessionId: string): Promise<AuditRow> {
    if (!current) throw new Error('audit-case-not-selected')
    const item = current
    const result = await rpc('wireAudit/idle', { sessionId, expectedToolValues: item.mode === 'edit' ? [probes.file] : item.command ? item.hidden ?? [] : [] })
    const wire = currentEvidence()
    if (['token-context', 'rendered-token-context', 'raw-literal-token', 'oneway-removal'].includes(item.mode ?? '') && bodies.length !== 2) return { ...wire, status: 'dynamic-probe-not-exercised' }
    if (item.command || item.mode === 'edit') {
      if (!result.bashSuccessCount || result.bashFailureCount || !result.bashStdoutHasExpected || !result.canonicalToolHasExpected) return { ...wire, status: failureStatus('tool-output-not-proven', new Error(result.toolFailure || 'successful synthetic stdout/canonical history missing')) }
      if (item.command && bodies.length !== 2) return { ...wire, status: 'tool-continuation-missing' }
    }
    if (item.mode === 'edit') {
      if (bodies.length !== 3 || !result.historyContainsOld || !result.historyContainsNew || !result.execution || !result.guard || !result.classification || !(await readFile(join(editCwd, '.env'), 'utf8')).includes(probes.updated)) return { ...wire, status: 'consumer-restoration-failed' }
      if (new Set(bodies.at(-1)?.match(tokenPattern) ?? []).size < 2) return { ...wire, status: 'updated-placeholder-missing' }
    }
    return wire
  }
  async function run(): Promise<AuditRow[]> {
    const report: AuditRow[] = []
    for (const item of matrix.filter(candidate => options.caseName === undefined || candidate.name === options.caseName)) {
      const { cwd } = await prepareBrowserCase(item.name)
      let status = 'pass'
      try {
        const sessionId = await createSession(item.name, cwd)
        let result: RpcValue
        if (['direct', 'prepared', 'compaction', 'blocks', 'static'].includes(item.mode ?? '')) {
          result = await rpc('wireAudit/probe', { sessionId, mode: item.mode, text: item.text })
          if (!result.unchanged || !result.borrowedSignal) status = 'consumer-restoration-failed'
        } else result = await prompt(sessionId, item.text, undefined, item.mode === 'edit' ? [probes.file] : item.command ? item.hidden ?? [] : [])
        if (['token-context', 'rendered-token-context', 'raw-literal-token'].includes(item.mode ?? '')) {
          if (!lastToken) throw new Error('audit-context-token-missing')
          const knownToken = lastToken
          let text = item.mode === 'rendered-token-context' ? `${item.hidden?.[1] ?? ''}${knownToken}` : `${knownToken}${item.hidden?.[1] ?? ''}`
          if (item.mode === 'raw-literal-token') {
            text = `OuterPrefix-${knownToken}-LongSuffix`
            await mkdir(join(cwd, '.dsh'), { recursive: true })
            await writeFile(join(cwd, '.dsh/secrets.yml'), JSON.stringify([{ type: 'plain', content: text }]))
          }
          result = await rpc('wireAudit/probe', { sessionId, mode: 'direct', text })
          if (!result.unchanged || !result.borrowedSignal) status = 'consumer-restoration-failed'
          if (bodies.length !== 2 && status === 'pass') status = 'dynamic-probe-not-exercised'
        }
        if (item.mode === 'oneway-removal') {
          const baselineCount = bodies.length
          if (baselineCount !== 1 || !bodies[0]?.includes('ONEWAY_REMOVAL_MASK') || bodies[0]?.includes(item.text)) throw new Error('oneway-removal-baseline-not-proven')
          await rm(join(cwd, '.dsh/secrets.yml'))
          const afterRemoval = await createSession(`${item.name}-after-removal`, cwd)
          result = await prompt(afterRemoval, item.text)
          if (bodies.length !== 2) status = 'dynamic-probe-not-exercised'
          else if (!bodies[1]?.includes('ONEWAY_REMOVAL_MASK')) status = 'oneway-policy-not-retained'
        }
        if (item.command || item.mode === 'edit') {
          if (!result.bashSuccessCount || result.bashFailureCount || !result.bashStdoutHasExpected || !result.canonicalToolHasExpected) status = failureStatus('tool-output-not-proven', new Error(result.toolFailure || 'successful Bash stdout and canonical tool history did not contain the expected synthetic values'))
        }
        if (item.mode === 'guard' && lastToken) {
          const guard = await rpc('wireAudit/guard', { sessionId, token: lastToken })
          if (!guard.denied || !guard.unchanged || !guard.notExecuted || !guard.guard || !guard.classification) status = 'consumer-restoration-failed'
        } else if (item.mode === 'guard') status = 'placeholder-missing'
        if (item.mode === 'edit') {
          if (status === 'pass' && (bodies.length !== 3 || !result.historyContainsOld || !result.historyContainsNew || !result.execution || !result.guard || !result.classification || !(await readFile(join(cwd, '.env'), 'utf8')).includes(probes.updated))) status = 'consumer-restoration-failed'
          if (status === 'pass' && new Set(bodies.at(-1)?.match(tokenPattern) ?? []).size < 2) status = 'updated-placeholder-missing'
        }
        if (item.malformed) status = bodies.length === 0 && (result.sourceRefused || stderrBuffer.includes('Unable to parse an automatic dotenv source; refusing the model request')) ? 'refused' : 'source-refusal-not-observed'
      } catch (error) { status = failureStatus('request-failed', error) }
      const wire = currentEvidence()
      if (bodies.length && wire.status !== 'pass') status = wire.status
      if (!bodies.length && !item.malformed && status === 'pass') status = 'no-wire-evidence'
      if (item.command && bodies.length !== 2 && status === 'pass') status = 'tool-continuation-missing'
      report.push({ name: item.name, classification: item.classification, outboundRequestCount: bodies.length, status })
    }
    // Persisted arbitrary source values deliberately have no secret-pattern shape.
    for (const change of ['changed', 'deleted'] as const) {
      const item: AuditCase = { name: `history-restart-source-${change}`, classification: 'shared-limit', text: 'Read the synthetic source.', command: 'cat .env' }
      if (options.caseName !== undefined && options.caseName !== item.name) continue
      const oldValue = `SyntheticHistory${change}-Nn123456`
      const newValue = `SyntheticHistory${change}-Oo123456`
      const cwd = join(workspace, item.name)
      await mkdir(cwd, { recursive: true }); await writeFile(join(cwd, '.env'), `DATA=${oldValue}\n`)
      current = item; bodies = []; stage = 0
      let status = 'pass'; let count = 0
      try {
        const sessionId = await createSession(item.name, cwd)
        const first = await prompt(sessionId, item.text, oldValue, [oldValue])
        count += bodies.length
        if (!first.bashSuccessCount || first.bashFailureCount || !first.bashStdoutHasExpected || !first.canonicalToolHasExpected) status = failureStatus('tool-output-not-proven', new Error(first.toolFailure || 'history source read did not produce successful synthetic stdout'))
        else if (!first.historyContainsOld || bodies.some(body => body.includes(oldValue))) status = 'history-baseline-failed'
        await closeHost()
        if (change === 'changed') await writeFile(join(cwd, '.env'), `DATA=${newValue}\n`)
        else await rm(join(cwd, '.env'))
        await boot()
        current = { ...item }; delete current.command
        bodies = []; stage = 0
        await prompt(sessionId, 'Continue the retained synthetic history.')
        count += bodies.length
        if (status === 'pass') {
          if (!bodies.length) status = 'no-wire-evidence'
          else if (bodies.some(body => body.includes(oldValue))) status = 'limit-observed'
          else status = 'limit-not-observed'
        }
      } catch (error) { status = failureStatus('request-failed', error) }
      report.push({ name: item.name, classification: item.classification, outboundRequestCount: count, status })
    }
    return report
  }
  return { run, close, rpc, prepareBrowserCase, currentEvidence, browserEvidence, get bootstrapUrl() { return bootstrapUrl }, get baseUrl() { return baseUrl }, workspace }
}
export async function runWebAudit(options: AuditOptions = {}) {
  const audit = await startWebAudit(options)
  try { return await audit.run() } finally { await audit.close() }
}
if (import.meta.main) {
  try {
    const index = process.argv.indexOf('--case')
    const caseName = index === -1 ? undefined : process.argv[index + 1]
    if (index !== -1 && !caseName) throw new AuditFailure('setup-failed:--case requires a case name')
    const report = await runWebAudit(caseName === undefined ? {} : { caseName })
    console.log(JSON.stringify(report, null, 2))
    if (report.some(row => ['protected', 'refusal', 'gap-probe'].includes(row.classification) && !['pass', 'refused'].includes(row.status))) process.exitCode = 1
  } catch (error) { console.log(JSON.stringify([{ name: 'native-web-setup', classification: 'protected', outboundRequestCount: 0, status: error instanceof AuditFailure ? error.message : 'setup-failed:unclassified-fixture-error' }])); process.exitCode = 1 }
}
