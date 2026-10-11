import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { homedir } from 'node:os'
import { join, resolve } from 'node:path'
import { installBoundaries } from './boundary.ts'
import { loadKey } from './key.ts'
import { Vault, type SecretEntry } from './obfuscator.ts'
import { expandPath, SecretSchema, Sources } from './sources.ts'

export { Obfuscator, Vault } from './obfuscator.ts'
export type { SecretEntry } from './obfuscator.ts'
export { BUILTIN_PATTERNS } from './sources.ts'
export const name = 'dsh-secrets-omp'

export interface Config {
  enabled: boolean
  env: boolean
  envFiles: boolean
  builtin: boolean
  secrets: SecretEntry[]
  files: string[]
  dshHome: string
}

export const Config: z<Partial<Config>, Config> = z.object({
  enabled: z.boolean().default(true).description('Obfuscate provider-bound conversation text and restore tool arguments.'),
  env: z.boolean().default(true).description('Collect secret-named environment values and connection-URL passwords.'),
  envFiles: z.boolean().default(true).description('Collect values of at least eight characters from session .env and .env.* files.'),
  builtin: z.boolean().default(true).description('Detect common credential shapes in conversation text and tool output.'),
  secrets: z.array(SecretSchema).default([]).description('Inline entries in oh-my-pi secrets.yml format; override file entries by content.'),
  files: z.array(z.string()).default(['$DSH_HOME/secrets.yml', '.dsh/secrets.yml'])
    .description('Ordered secrets.yml files. ~/ and $DSH_HOME expand; relative paths use the request session directory.'),
  dshHome: z.string().default('').description('Home for global secrets and the private key; empty uses $DSH_HOME or ~/.dsh.'),
})

export function apply(ctx: Context, config: Config): void {
  if (!config.enabled) return
  const home = resolve(expandPath(config.dshHome || process.env.DSH_HOME || join(homedir(), '.dsh'), ''))
  const vault = new Vault(loadKey(join(home, 'dsh-secrets-omp', 'secret-placeholder.key')))
  const logger = ctx.logger(name)
  const warnings = new Set<string>()
  const warn = (message: string): void => {
    if (warnings.has(message)) return
    warnings.add(message)
    logger.warn(message)
  }
  const sources = new Sources({
    vault, home, files: config.files, entries: config.secrets,
    env: config.env ? process.env : undefined, envFiles: config.envFiles, builtin: config.builtin, warn,
  })
  installBoundaries(ctx, sources, vault)
}
