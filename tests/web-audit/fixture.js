// Testing-only plugin. __NATIVE_PEERS__ is replaced with the installed Host's ASAR module root.
import { DeepSeekAdapter, resolveAdapterOptions } from '__NATIVE_PEERS__/@deepseek-ai/dsh-llm-deepseek/lib/index.js'
import { createUserMessage, createDeveloperMessage, createAssistantMessage, createToolResultMessage, createSystemMessage, ToolCallId } from '__NATIVE_PEERS__/@deepseek-ai/dsh-llm/lib/index.js'
import { Remote, TypertRemoteService } from '__NATIVE_PEERS__/@deepseek-ai/dsh-typert-protocol/lib/index.js'
import { readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
export const name = 'dsh-web-wire-audit-fixture'
export const inject = ['llm', 'tools', 'agents', 'sessions', 'typert']
const model = 'deepseek-flash'
function freeze(value) {
  if (value === null || typeof value !== 'object' || value instanceof AbortSignal) return value
  for (const child of Object.values(value)) freeze(child)
  return Object.freeze(value)
}
// Use the public standard-decorator initializer API without requiring a TS transpiler in the Host.
function markRemote(instance, method) {
  Remote(method)(instance[method], { kind: 'method', name: method, private: false, static: false,
    addInitializer(initializer) { initializer.call(instance) } })
}
export function apply(ctx) {
  const counters = { guard: 0, classification: 0, execution: 0 }
  const bashOutcomes = new Map()
  ctx.on('tools/result', (exec, result) => {
    if (exec.name !== 'bash' || !exec.agent) return
    const value = result.value
    const success = !result.isError && value?.kind === 'foreground' && value.exitCode === 0 && !value.timedOut && !value.aborted && value.signal === null
    const outcomes = bashOutcomes.get(exec.agent.session.id) ?? []
    outcomes.push({ callId: exec.callId, success, stdout: typeof value?.stdout?.text === 'string' ? value.stdout.text : '' })
    bashOutcomes.set(exec.agent.session.id, outcomes)
  }, { global: true })
  ctx.llm.registerAdapter(['deepseek-official'], new DeepSeekAdapter({
    options: () => resolveAdapterOptions({ baseURL: process.env.DSH_AUDIT_MESSAGES_URL, thinking: 'disabled' }),
    discoverModels: async provider => [{ provider, id: model, name: 'Synthetic Native Web Wire Fixture', inputModalities: ['text'] }],
    resolveAuth: async () => ({ headers: { 'x-api-key': 'synthetic-audit-auth-only' } }),
    resolveUserId: () => 'synthetic-wire-audit-user',
    prepareExtensions: async () => ({ fields: {}, accept: async () => {} }),
  }))
  ctx.tools.guard(exec => {
    if (exec.name !== 'audit_edit') return
    if (exec.arguments.old_text !== process.env.DSH_AUDIT_FILE_VALUE) throw new Error('audit guard restoration failed')
    counters.guard++
    if (exec.arguments.new_text === 'DENIED') return 'audit-denied-restored-argument'
  })
  ctx.tools.register({
    name: 'audit_edit', description: 'Testing-only exact-match edit in the isolated fixture.',
    parameters: { type: 'object', properties: { old_text: { type: 'string' }, new_text: { type: 'string' } }, required: ['old_text', 'new_text'] },
    output: { schema: { type: 'string' }, render(_args, value) { return [{ type: 'text', text: String(value) }] } },
    isConcurrencySafe(args) {
      if (args.old_text !== process.env.DSH_AUDIT_FILE_VALUE) throw new Error('audit classification restoration failed')
      counters.classification++
      return false
    },
    async execute(args) {
      if (args.old_text !== process.env.DSH_AUDIT_FILE_VALUE || args.new_text !== process.env.DSH_AUDIT_UPDATED_VALUE) throw new Error('audit execution restoration failed')
      const path = join(process.env.DSH_AUDIT_EDIT_CWD, '.env')
      const before = await readFile(path, 'utf8')
      if (!before.includes(args.old_text)) throw new Error('audit exact match failed')
      await writeFile(path, before.replace(args.old_text, args.new_text))
      counters.execution++
      return `Replaced ${args.old_text} with ${args.new_text}`
    },
  })
  class AuditRemote extends TypertRemoteService {
    constructor(owner) {
      super(owner, 'wireAudit')
      for (const method of ['idle', 'probe', 'guard']) markRemote(this, method)
    }
    async idle(request) {
      const agent = ctx.agents.get(request.sessionId)
      if (!agent) throw new Error('audit session missing')
      await agent.whenIdle()
      const events = agent.session.snapshotEvents()
      const history = JSON.stringify(events)
      const outcomes = bashOutcomes.get(agent.session.id) ?? []
      const successful = outcomes.filter(outcome => outcome.success)
      const expected = request.expectedToolValues ?? []
      const canonical = events.filter(event => event.type === 'tool/result' && !event.data.message.isError && successful.some(outcome => outcome.callId === event.data.message.toolCallId))
      const canonicalTexts = canonical.flatMap(event => event.data.message.content.filter(block => block.type === 'text').map(block => block.text))
      const failed = events.filter(event => event.type === 'tool/result' && outcomes.some(outcome => !outcome.success && outcome.callId === event.data.message.toolCallId))
      const toolFailure = failed.flatMap(event => event.data.message.content.filter(block => block.type === 'text').map(block => block.text)).join(' | ').slice(0, 2000)
      return { ...counters, eventCount: events.length,
        historyContainsOld: history.includes(request.historyValue ?? process.env.DSH_AUDIT_FILE_VALUE),
        historyContainsNew: history.includes(process.env.DSH_AUDIT_UPDATED_VALUE),
        bashSuccessCount: successful.length, bashFailureCount: outcomes.length - successful.length,
        bashStdoutHasExpected: expected.every(value => successful.some(outcome => outcome.stdout.includes(value))),
        canonicalToolHasExpected: expected.every(value => canonicalTexts.some(text => text.includes(value))),
        toolFailure,
        sourceRefused: /Unable to (?:inspect|discover|read|parse).*dotenv.*refusing the model request/.test(history) }
    }
    async probe(request) {
      const agent = ctx.agents.get(request.sessionId)
      if (!agent) throw new Error('audit session missing')
      const cancellation = new AbortController()
      const signal = cancellation.signal
      let messages = [createUserMessage({ source: { kind: 'user' }, content: [{ type: 'text', text: request.text }] })]
      if (request.mode === 'blocks') {
        const callId = ToolCallId('audit-block-call')
        messages = [
          createDeveloperMessage({ source: { kind: 'plugin', name }, content: [{ type: 'text', text: request.text }] }),
          createUserMessage({ source: { kind: 'user' }, content: [{ type: 'text', text: request.text }] }),
          createAssistantMessage({ source: { provider: 'deepseek-official', model }, content: [
            { type: 'text', text: request.text }, { type: 'reasoning', text: request.text },
            { type: 'tool-call', id: callId, name: 'audit_edit', arguments: JSON.stringify({ old_text: request.text, new_text: request.text }) },
          ] }),
          createToolResultMessage({ callId, content: [{ type: 'text', text: request.text }], isError: false }),
        ]
      }
      if (request.mode === 'static') messages.unshift(createSystemMessage(request.text))
      const prepared = request.mode === 'prepared' ? await ctx.llm.prepareCall({ provider: 'deepseek-official', model }) : undefined
      const options = freeze({ provider: 'deepseek-official', model, ...prepared?.config, sessionId: agent.session.id, signal, messages,
        ...(request.mode === 'compaction' ? { purpose: 'compaction' } : {}),
        ...(request.mode === 'static' ? { tools: [{ name: 'static_probe', description: request.text, parameters: { type: 'object', properties: { data: { type: 'string', description: request.text } } } }] } : {}),
      })
      const before = JSON.stringify(options)
      for await (const _chunk of prepared ? prepared.stream(options) : ctx.llm.stream(options)) { }
      const downstream = AbortSignal.any([signal, new AbortController().signal])
      cancellation.abort('synthetic-audit-cancel')
      return { unchanged: JSON.stringify(options) === before, borrowedSignal: downstream.aborted && downstream.reason === 'synthetic-audit-cancel' }
    }
    async guard(request) {
      const call = freeze({ callId: ToolCallId('audit-denied'), name: 'audit_edit', arguments: { old_text: request.token, new_text: 'DENIED' } })
      const original = JSON.stringify(call)
      const input = { ...call, signal: new AbortController().signal }
      const executionBefore = counters.execution
      ctx.tools.executionMode(input)
      const result = await ctx.tools.execute(input)
      return { denied: result.isError === true && JSON.stringify(result.content).includes('audit-denied-restored-argument'),
        unchanged: JSON.stringify(call) === original, notExecuted: executionBefore === counters.execution, ...counters }
    }
  }
  new AuditRemote(ctx)
}
