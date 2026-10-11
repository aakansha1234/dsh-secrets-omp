import assert from 'node:assert/strict'
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import AgentRegistry from '@deepseek-ai/dsh-agent'
import AgentLoop from '@deepseek-ai/dsh-agent-loop'
import SessionStore, { SessionId } from '@deepseek-ai/dsh-session'
import SessionProjections from '@deepseek-ai/dsh-session-projection'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import ToolRuntime from '@deepseek-ai/dsh-tools'
import LlmRuntime, { createUserMessage, ToolCallId, type GenerateOptions } from '@deepseek-ai/dsh-llm'
import { DeepSeekAdapter, resolveAdapterOptions } from '@deepseek-ai/dsh-llm-deepseek'
import type { AnonymousUserId } from '@deepseek-ai/dsh-anonymous-user-id'
import z from '@deepseek-ai/schemastery'
import * as Secrets from '../src/index.ts'
import { freezeJson } from '../src/transform.ts'

interface EditInput { old_text: string; new_text: string }

const secret = 'Synthetic-FileSecret-Abc12345'
const updatedSecret = `${secret}x`
const model = 'deepseek-v4-flash'
export async function runHarnessScenario(): Promise<void> {
  const home = await mkdtemp(join(tmpdir(), 'dsh-secrets-smoke-'))
  const project = join(home, 'project')
  const file = join(project, '.env')
  await mkdir(project, { recursive: true })
  await writeFile(file, `CUSTOM_CREDENTIAL=${secret}\n`)
  let requests = 0
  let executions = 0
  let reads = 0
  let classifications = 0
  let restoredGuards = 0
  let token: string | undefined
  const ctx = new Context()
  const server = Bun.serve({
    hostname: '127.0.0.1', port: 0,
    async fetch(request) {
      assert.equal(new URL(request.url).pathname, '/anthropic/v1/messages')
      const body = await request.text()
      assert(!body.includes(secret), 'Raw credential reached real DeepSeek HTTP transport')
      assert(!body.includes(updatedSecret), 'Updated credential reached real DeepSeek HTTP transport')
      requests++
      const events: object[] = [
        { type: 'message_start', message: { id: `msg_${requests}`, model, usage: { input_tokens: 12, output_tokens: 1 } } },
      ]
      if (requests === 1) {
        assert(!body.includes('CUSTOM_CREDENTIAL='), 'Initial instruction unexpectedly contains file contents')
        events.push(
          { type: 'content_block_start', index: 0, content_block: { type: 'tool_use', id: 'call_read', name: 'read_fixture', input: {} } },
          { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: '{}' } },
          { type: 'content_block_stop', index: 0 },
          { type: 'message_delta', delta: { stop_reason: 'tool_use' }, usage: { output_tokens: 5 } },
        )
      } else if (requests === 2) {
        assert.equal(reads, 1, 'Provider continuation preceded the actual cat execution')
        token = body.match(/\$\$(?:[A-Z0-9]{1,32}_)?[A-Z0-9]{12}(?::[ULCM])?\$\$/)?.[0]
        assert(token, 'Automatic .env credential did not become a reversible placeholder')
        assert(body.includes(`CUSTOM_CREDENTIAL=${token}`), 'cat output did not reach the provider with a placeholder-only value')
        events.push(
          { type: 'content_block_start', index: 0, content_block: { type: 'tool_use', id: 'call_edit', name: 'edit_fixture', input: {} } },
          { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: JSON.stringify({ old_text: token, new_text: `${token}x` }) } },
          { type: 'content_block_stop', index: 0 },
          { type: 'message_delta', delta: { stop_reason: 'tool_use' }, usage: { output_tokens: 5 } },
        )
      } else {
        if (requests === 3) {
          assert.equal(executions, 1, 'Final provider continuation preceded the actual edit')
          assert(token && body.includes(token), 'Old credential disappeared rather than being redacted')
          const placeholders = body.match(/\$\$(?:[A-Z0-9]{1,32}_)?[A-Z0-9]{12}(?::[ULCM])?\$\$/g) ?? []
          assert(new Set(placeholders).size >= 2, 'Modified .env credential did not acquire its own placeholder')
          assert(placeholders.some(updated => updated !== token && body.includes(`Replaced ${token} with ${updated}`)),
            'Edited file output did not redact the updated credential as a distinct placeholder')
        }
        events.push(
          { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } },
          { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'Done.' } },
          { type: 'content_block_stop', index: 0 },
          { type: 'message_delta', delta: { stop_reason: 'end_turn' }, usage: { output_tokens: 5 } },
        )
      }
      events.push({ type: 'message_stop' })
      return new Response(events.map(event => `data: ${JSON.stringify(event)}\n\n`).join(''), { headers: { 'content-type': 'text/event-stream' } })
    },
  })

  try {
    await ctx.plugin(SessionStore)
    await ctx.plugin(AgentRegistry)
    await ctx.plugin(SessionProjections)
    await ctx.plugin(SystemPrompt)
    await ctx.plugin(ToolRuntime)
    await ctx.plugin(LlmRuntime)
    await ctx.plugin(Secrets, Secrets.Config({ dshHome: home, env: false }))
    const userId = 'smoke-user' as AnonymousUserId // Branded, locally chosen fixture identity.
    ctx.llm.registerAdapter(['deepseek-official'], new DeepSeekAdapter({
      options: () => resolveAdapterOptions({ baseURL: `http://127.0.0.1:${server.port}/anthropic`, thinking: 'disabled' }),
      resolveAuth: async () => ({ headers: { 'x-api-key': 'synthetic-transport-key' } }),
      resolveUserId: () => userId,
      prepareExtensions: async () => ({ fields: {}, accept: async () => {} }),
    }))
    const EditArguments = z.object({ old_text: z.string().required(), new_text: z.string().required() })
    function parseEditArguments(input: unknown): EditInput {
      // resolve validates the whole object but its dynamic API omits generic output types.
      const validated = z.resolve(input, EditArguments, {})[0] as unknown as EditInput
      return validated
    }
    ctx.tools.register({
      name: 'read_fixture', description: 'Run cat .env in the session project.',
      parameters: { type: 'object', properties: {}, additionalProperties: false },
      output: { schema: { type: 'string' }, render(_args, value) {
        assert.equal(typeof value, 'string')
        return [{ type: 'text', text: String(value) }]
      } },
      isConcurrencySafe() { return true },
      async execute() {
        const child = Bun.spawn(['cat', '.env'], { cwd: project, stdout: 'pipe', stderr: 'pipe' })
        const contents = await new Response(child.stdout).text()
        assert.equal(await child.exited, 0, 'cat .env failed')
        assert.equal(contents, `CUSTOM_CREDENTIAL=${secret}\n`)
        reads++
        return contents
      },
    })
    ctx.tools.guard(exec => {
      if (exec.name !== 'edit_fixture') return undefined
      const parsed = parseEditArguments(exec.arguments)
      assert.equal(parsed.old_text, secret, 'Guard did not receive original credential bytes')
      if (parsed.new_text !== 'DENIED') {
        assert.equal(parsed.new_text, updatedSecret, 'Guard did not receive restored updated credential')
        restoredGuards++
      }
      return undefined
    })
    ctx.tools.register({
      name: 'edit_fixture', description: 'Replace an exact string in the fixture file.',
      parameters: { type: 'object', properties: { old_text: { type: 'string' }, new_text: { type: 'string' } }, required: ['old_text', 'new_text'], additionalProperties: false },
      output: { schema: { type: 'string' }, render(_args, value) {
        assert.equal(typeof value, 'string')
        return [{ type: 'text', text: String(value) }]
      } },
      isConcurrencySafe(args) {
        const parsed = parseEditArguments(args)
        assert.equal(parsed.old_text, secret, 'Classification did not receive original credential bytes')
        if (parsed.new_text !== 'DENIED') {
          assert.equal(parsed.new_text, updatedSecret, 'Classification did not receive restored updated credential')
          classifications++
        }
        return false
      },
      async execute(args) {
        const parsed = parseEditArguments(args)
        assert.equal(parsed.old_text, secret, 'Execution did not receive original credential bytes')
        assert.equal(parsed.new_text, updatedSecret, 'Execution did not receive restored updated credential')
        const contents = await readFile(file, 'utf8')
        assert(contents.includes(parsed.old_text), 'Placeholder was not restored before exact-match file edit')
        await writeFile(file, contents.replace(parsed.old_text, parsed.new_text))
        executions++
        return `Replaced ${parsed.old_text} with ${parsed.new_text}`
      },
    })
    await ctx.plugin(AgentLoop)
    const agent = await ctx.agentLoop.create(SessionId('secrets-smoke'), { provider: 'deepseek-official', model }, { cwd: project })
    agent.followup(createUserMessage({ source: { kind: 'user' }, content: [{ type: 'text', text: 'Run cat .env, then append x to its credential using edit_fixture.' }] }))
    await agent.whenIdle()
    assert.equal(await readFile(file, 'utf8'), `CUSTOM_CREDENTIAL=${updatedSecret}\n`)
    assert.equal(reads, 1)
    assert.equal(executions, 1)
    assert(classifications > 0, 'Edit bypassed restored concurrency classification')
    assert.equal(restoredGuards, 1)
    assert.equal(requests, 3)
    const history = JSON.stringify(agent.session.snapshotEvents())
    assert(history.includes(`CUSTOM_CREDENTIAL=${secret}\\n`), 'Raw cat output was not retained in canonical history')
    assert(history.includes(updatedSecret), 'Raw updated credential was not retained in canonical history')
    assert(token)

    const requestCancellation = new AbortController()
    const direct: GenerateOptions = freezeJson({ provider: 'deepseek-official', model, sessionId: agent.session.id,
      signal: requestCancellation.signal,
      messages: [createUserMessage({ source: { kind: 'user' }, content: [{ type: 'text', text: secret }] })] })
    const original = JSON.stringify(direct)
    for await (const _chunk of ctx.llm.stream(direct)) { /* Exercise direct stream. */ }
    const prepared = await ctx.llm.prepareCall({ provider: 'deepseek-official', model })
    for await (const _chunk of prepared.stream(freezeJson({ ...direct, ...prepared.config }))) { /* Exercise frozen prepared dispatch. */ }
    for await (const _chunk of ctx.llm.stream(freezeJson({ ...direct, purpose: 'compaction' }))) { /* Exercise side request. */ }
    assert.equal(JSON.stringify(direct), original)
    assert.equal(requests, 6)
    const downstream = AbortSignal.any([requestCancellation.signal, new AbortController().signal])
    requestCancellation.abort('after-provider-smoke')
    assert.equal(downstream.reason, 'after-provider-smoke')

    let guardSawRealValue = false
    ctx.tools.guard(exec => {
      if (parseEditArguments(exec.arguments).old_text === secret) {
        guardSawRealValue = true
        return 'guard-denied-restored-value'
      }
      return undefined
    })
    const call = freezeJson({ callId: ToolCallId('guard-check'), name: 'edit_fixture', arguments: { old_text: token, new_text: 'DENIED' } })
    const input = { ...call, signal: new AbortController().signal }
    assert.equal(ctx.tools.executionMode(input).kind, 'exclusive')
    const result = await ctx.tools.execute(input)
    assert(guardSawRealValue, 'Security guard evaluated placeholders rather than real arguments')
    assert(result.isError && JSON.stringify(result.content).includes('guard-denied-restored-value'))
    assert.equal(executions, 1)
    assert.equal(call.arguments.old_text, token)
    assert.equal(await readFile(file, 'utf8'), `CUSTOM_CREDENTIAL=${updatedSecret}\n`)
    console.log('PASS: real AgentLoop + DeepSeekAdapter HTTP; 6 provider requests hide old and updated .env credentials')
    console.log('PASS: actual cat .env output -> placeholder edit -> actual .env update -> redacted provider continuation')
    console.log('PASS: frozen direct/prepared/compaction requests; raw local history preserved')
    console.log('PASS: security guard and concurrency classification see restored arguments; denied edit does not run')
  } finally {
    await ctx.fiber.dispose()
    server.stop(true)
    await rm(home, { recursive: true, force: true })
  }
}
