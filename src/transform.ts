import type { ContentBlock, GenerateOptions, RequestMessage } from '@deepseek-ai/dsh-llm'
import { mapStrings, type Obfuscator } from './obfuscator.ts'

export const REDACTED_VALUES_PROMPT = [
  '# Redacted values',
  'Some values in conversation messages and tool output are replaced for security by opaque placeholders such as `$$HASH$$`, `$$HASH:CASE$$`, or `$$NAME_HASH:CASE$$`. They stand for sensitive values, not errors. Never decode, alter, or guess them.',
  'Copy a placeholder exactly into a tool argument when you need the hidden value, including in commands, request headers, and file edits. The harness restores the original bytes before tool validation and execution, then hides them again in the next model request. One-way replacements are not restored.',
].join('\n')

function mapArray<T>(items: readonly T[], transform: (item: T) => T): readonly T[] {
  let output: T[] | undefined
  items.forEach((item, index) => {
    const next = transform(item)
    if (next !== item) { output ??= items.slice(); output[index] = next }
  })
  return output ?? items
}

function mapBlock(block: ContentBlock, transform: (text: string) => string): ContentBlock {
  if (block.type === 'text' || block.type === 'reasoning') {
    const text = transform(block.text)
    return text === block.text ? block : { ...block, text }
  }
  if (block.type === 'tool-call') {
    let parsed: unknown
    try {
      parsed = JSON.parse(block.arguments)
    } catch {
      const argumentsText = transform(block.arguments)
      return argumentsText === block.arguments ? block : { ...block, arguments: argumentsText }
    }
    const mapped = mapStrings(parsed, transform)
    return mapped === parsed ? block : { ...block, arguments: JSON.stringify(mapped) }
  }
  // Binary attachments, tool identities, definitions, and unknown block types are not prose.
  return block
}

function mapMessage(message: RequestMessage, transform: (text: string) => string): RequestMessage {
  // As in omp, static system prompts and tool schemas are outside conversation redaction.
  if (message.role === 'system') return message
  const content = mapArray(message.content, block => mapBlock(block, transform))
  if (!('source' in message) || message.source === undefined) return content === message.content ? message : { ...message, content }
  let source = message.source
  if ('form' in source && source.form === 'notice') {
    const summary = transform(source.summary)
    if (summary !== source.summary) source = { ...source, summary }
  } else if ('form' in source && source.form === 'snapshot') {
    const sections = mapArray(source.sections, section => {
      const text = transform(section.text)
      return text === section.text ? section : { ...section, text }
    })
    if (sections !== source.sections) source = { ...source, sections }
  }
  if (message.role === 'assistant') {
    // Signed native replay is bound to the old bytes. Use neutral history when any block changes.
    if (content !== message.content && message.source.replayState !== undefined) {
      const { replayState: _replayState, ...unsigned } = message.source
      return { ...message, content, source: unsigned }
    }
    return content === message.content ? message : { ...message, content }
  }
  if (message.role === 'tool') return content === message.content ? message : { ...message, content }
  return content === message.content && source === message.source ? message : { ...message, content, source }
}

/** Freeze owned JSON containers, never borrowed data or runtime capabilities. */
export function freezeJson<T>(value: T, original?: unknown): T {
  if (value === original || value === null || typeof value !== 'object' || Object.isFrozen(value)) return value
  const prototype: unknown = Object.getPrototypeOf(value)
  if (!Array.isArray(value) && prototype !== Object.prototype && prototype !== null) return value
  const borrowed = original !== null && typeof original === 'object' ? original : undefined
  for (const key of Object.keys(value)) {
    freezeJson(Reflect.get(value, key), borrowed === undefined ? undefined : Reflect.get(borrowed, key))
  }
  return Object.freeze(value)
}

/** Pre-collect request-wide collision values before emitting any model-visible label. */
export function prepareMessages(engine: Obfuscator, messages: readonly RequestMessage[]): void {
  const collect = (text: string): string => { engine.prepare([text]); return text }
  for (const message of messages) mapMessage(message, collect)
}

/** Rebuild only capabilities that survive the current replacement rules. */
export function rememberMessages(engine: Obfuscator, messages: readonly RequestMessage[]): void {
  prepareMessages(engine, messages)
  const remember = (text: string): string => { engine.obfuscate(text); return text }
  for (const message of messages) mapMessage(message, remember)
}

/** Redact a final dispatch copy; canonical messages, call config, and local logs are never mutated. */
export function redactRequest(engine: Obfuscator, options: GenerateOptions): GenerateOptions {
  prepareMessages(engine, options.messages)
  const messages = mapArray(options.messages, message => mapMessage(message, text => engine.obfuscate(text)))
  let output = messages === options.messages ? options : { ...options, messages: messages as RequestMessage[] }
  // One-shot callers and preassembled prompts must receive guidance too.
  if (output.system !== undefined) {
    if (!output.system.includes(REDACTED_VALUES_PROMPT)) output = { ...output, system: `${output.system}\n\n${REDACTED_VALUES_PROMPT}` }
  } else {
    const index = output.messages.findIndex(message => message.role === 'system')
    if (index === -1) output = { ...output, system: REDACTED_VALUES_PROMPT }
    else {
      const system = output.messages[index]!
      if (!system.content.some(block => block.type === 'text' && block.text.includes(REDACTED_VALUES_PROMPT))) {
        const copy = output.messages.slice()
        copy[index] = { ...system, content: [...system.content, { type: 'text', text: REDACTED_VALUES_PROMPT }] }
        output = { ...output, messages: copy }
      }
    }
  }
  return Object.isFrozen(options) ? freezeJson(output, options) : output
}
