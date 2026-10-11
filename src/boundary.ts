import { symbols, type Context } from '@deepseek-ai/cordis'
import type { GenerateOptions, LlmAdapter } from '@deepseek-ai/dsh-llm'
import type { Session } from '@deepseek-ai/dsh-session'
import type {} from '@deepseek-ai/dsh-agent'
import type { ToolExecutionInput, ToolExecutionMode } from '@deepseek-ai/dsh-tools'
import { mapStrings, type Vault } from './obfuscator.ts'
import type { Sources } from './sources.ts'
import { freezeJson, redactRequest, rememberMessages } from './transform.ts'

interface ProviderBoundary {
  forAdapter(options: GenerateOptions, adapter: LlmAdapter): GenerateOptions
}
interface ToolBoundary {
  createExecution(input: ToolExecutionInput): unknown
  executionMode(input: ToolExecutionInput): ToolExecutionMode
}

/** Cordis exposes service proxies; patch their underlying instance, not one scoped facade. */
function originalService(service: object): object {
  let current = service
  while (true) {
    const original: unknown = Reflect.get(current, symbols.original)
    if (original === null || typeof original !== 'object' || original === current) return current
    current = original
  }
}

/** Private seams are required by rc.2: public waterfalls cannot replace frozen request/input objects. */
function replaceMethod<T extends (...args: never[]) => unknown>(
  target: object,
  property: string,
  wrap: (original: T) => T,
): { current: T; dispose: () => void } {
  const method: unknown = Reflect.get(target, property)
  if (typeof method !== 'function') throw new Error(`dsh-secrets-omp requires Harness 0.2.0-rc.2 ${property}; refusing an unprotected cutover`)
  const descriptor = Object.getOwnPropertyDescriptor(target, property)
  // The seam is checked above; the pinned Harness defines its exact callable signature.
  const original = method as T
  const current = wrap(original)
  Object.defineProperty(target, property, { value: current, configurable: true, writable: true })
  return {
    current,
    dispose() {
      if (Reflect.get(target, property) !== current) return
      if (descriptor === undefined) Reflect.deleteProperty(target, property)
      else Object.defineProperty(target, property, descriptor)
    },
  }
}

export function installBoundaries(ctx: Context, sources: Sources, vault: Vault): void {
  const protectedRuntimes = new WeakMap<object, ProviderBoundary['forAdapter']>()
  const protectedTools = new WeakMap<object, { create: ToolBoundary['createExecution']; mode: ToolBoundary['executionMode'] }>()
  const seededSessions = new WeakSet<object>()
  const engineForSession = (session: Session) => {
    const engine = sources.for(session.header.cwd ?? process.cwd())
    const identity = originalService(session)
    if (!seededSessions.has(identity)) {
      for (const event of session.snapshotEvents()) {
        const message = session.deriveEventMessage(event)
        if (message !== null) rememberMessages(engine, [message])
      }
      seededSessions.add(identity)
    }
    return engine
  }
  ctx.on('llm/stream', function (_options, next) {
    const runtime = originalService(this)
    const boundary = protectedRuntimes.get(runtime)
    if (boundary === undefined || Reflect.get(runtime, 'forAdapter') !== boundary) {
      throw new Error('dsh-secrets-omp provider boundary is unavailable; refusing the model request')
    }
    const tools = ctx.get('tools')
    if (tools !== undefined) {
      const identity = originalService(tools)
      const protectedMethods = protectedTools.get(identity)
      if (protectedMethods === undefined
        || Reflect.get(identity, 'createExecution') !== protectedMethods.create
        || Reflect.get(identity, 'executionMode') !== protectedMethods.mode) {
        throw new Error('dsh-secrets-omp tool restoration boundary is unavailable; refusing the model request')
      }
    }
    return next()
  }, { prepend: true })

  ctx.inject(['llm'], child => {
    child.effect(() => {
      const runtime = originalService(child.llm)
      let active = true
      const patch = replaceMethod<ProviderBoundary['forAdapter']>(runtime, 'forAdapter', original => function (this: ProviderBoundary, options, adapter) {
        const projected = Reflect.apply(original, this, [options, adapter]) as GenerateOptions
        if (!active) return projected
        let engine
        if (projected.sessionId !== undefined) {
          const session = child.get('sessions')?.get(projected.sessionId) ?? child.get('agents')?.get(projected.sessionId)?.session
          if (session === undefined) throw new Error('dsh-secrets-omp cannot resolve the request session; refusing to omit project secrets')
          engine = engineForSession(session)
        } else engine = sources.for(process.cwd())
        return redactRequest(engine, projected)
      })
      protectedRuntimes.set(runtime, patch.current)
      return () => {
        active = false
        protectedRuntimes.delete(runtime)
        patch.dispose()
      }
    })
  })

  ctx.inject(['tools'], child => {
    child.effect(() => {
      const runtime = originalService(child.tools)
      let active = true
      const restore = (input: ToolExecutionInput): ToolExecutionInput => {
        if (!active) return input
        if (input.agent !== undefined) engineForSession(input.agent.session)
        const argumentsValue = mapStrings(input.arguments, text => vault.reveal(text))
        return argumentsValue === input.arguments ? input : { ...input, arguments: freezeJson(argumentsValue, input.arguments) }
      }
      const patches: { dispose: () => void }[] = []
      try {
        // Restore before snapshot/validation/approval/guards, never after security decisions.
        // Both direct execution and the parallel agent scheduler converge on this seam.
        const creation = replaceMethod<ToolBoundary['createExecution']>(runtime, 'createExecution', original => function (this: ToolBoundary, input) {
          return Reflect.apply(original, this, [restore(input)])
        })
        patches.push(creation)
        // Scheduling must classify the same real arguments the tool will receive.
        const scheduling = replaceMethod<ToolBoundary['executionMode']>(runtime, 'executionMode', original => function (this: ToolBoundary, input) {
          return Reflect.apply(original, this, [restore(input)]) as ToolExecutionMode
        })
        patches.push(scheduling)
        protectedTools.set(runtime, { create: creation.current, mode: scheduling.current })
      } catch (error) {
        for (const patch of patches.reverse()) patch.dispose()
        throw error
      }
      return () => {
        active = false
        protectedTools.delete(runtime)
        for (const patch of patches.reverse()) patch.dispose()
      }
    })
  })
}
