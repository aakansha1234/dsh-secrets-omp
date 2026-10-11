import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, utimesSync, writeFileSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { SOURCE_CASES, SOURCE_EVIDENCE } from './cases.mjs'

export { SOURCE_CASES, SOURCE_EVIDENCE }
const KEY = 'SyntheticKeyForSourceParityOnly1234567890abcd'.slice(0, 43)
const DEFAULT_OMP = join(homedir(), '.bun/install/global/node_modules/@oh-my-pi/pi-coding-agent')
const matchExpected = (actual, expected) => Object.entries(expected).every(([key, value]) => actual[key] === value)

/**
 * All source/key IO below is confined to newly created synthetic temporary trees.
 * Upstream defaults to the current user's Bun global installation; override with ompRoot or --omp-root=PATH.
 */
export async function runSourceParity({ ompRoot = DEFAULT_OMP, filter = '', bunExecutable } = {}) {
  if (!globalThis.Bun) throw new Error('Run this runtime-only audit with Bun, not Node.')
  const path = process.env.PATH ?? '/usr/bin:/bin'
  const bun = bunExecutable === undefined ? Bun.which('bun', { PATH: path }) : resolve(bunExecutable)
  if (!bun) throw new Error('A real Bun executable must be available on PATH or supplied as bunExecutable/--bun.')
  const node = Bun.which('node', { PATH: path })
  const root = mkdtempSync(join(tmpdir(), 'dsh-synthetic-source-parity-'))
  const baseEnv = {
    PATH: path, HOME: join(root, 'home'), TMPDIR: root,
    XDG_CONFIG_HOME: join(root, 'config'), XDG_STATE_HOME: join(root, 'state'),
    XDG_CACHE_HOME: join(root, 'cache'), PI_CODING_AGENT_DIR: join(root, 'agent'),
    DSH_HOME: join(root, 'dsh'), NODE_ENV: 'test', NO_COLOR: '1',
  }
  for (const directory of Object.values(baseEnv).filter(value => value.startsWith(root))) mkdirSync(directory, { recursive: true })
  // Never enumerate or collect the caller's actual environment values.
  const setEnv = values => {
    for (const name of Object.keys(process.env)) delete process.env[name]
    Object.assign(process.env, baseEnv, values)
  }
  setEnv({})
  const results = []
  try {
    const omp = await import(pathToFileURL(join(resolve(ompRoot), 'src/secrets/index.ts')).href)
    const plugin = await import(new URL('../../src/sources.ts', import.meta.url).href)
    const { Vault, Obfuscator } = await import(new URL('../../src/obfuscator.ts', import.meta.url).href)
    const { loadKey } = await import(new URL('../../src/key.ts', import.meta.url).href)
    const { apply } = await import(new URL('../../src/index.ts', import.meta.url).href)
    let tick = 0
    const put = (file, content) => {
      mkdirSync(dirname(file), { recursive: true })
      writeFileSync(file, content)
      // Force distinguishable file/directory versions without sleeps or relying on clock granularity.
      const stamp = new Date(Date.now() + ++tick * 2000)
      utimesSync(file, stamp, stamp)
      utimesSync(dirname(file), stamp, stamp)
    }
    const observe = (engine, input, side) => {
      const output = engine.obfuscate(input)
      const restored = side === 'plugin' ? engine.vault.reveal(output) : engine.deobfuscate(output)
      const hidden = !output.includes(input)
      return { hidden, reversible: hidden && restored === input, output, idempotent: engine.obfuscate(output) === output }
    }
    const makeSources = (home, options = {}) => new plugin.Sources({
      vault: options.vault ?? new Vault(KEY), home,
      files: options.files ?? [join(home, 'secrets.yml'), '.dsh/secrets.yml'],
      entries: options.entries ?? [], env: Object.hasOwn(options, 'env') ? options.env : {}, envFiles: options.envFiles ?? false,
      builtin: options.builtin ?? false, warn: options.warn ?? (() => {}),
    })
    const loadOmp = async (cwd, home, builtin = false) => new omp.SecretObfuscator([
      ...omp.collectEnvSecrets(), ...await omp.loadSecrets(cwd, home),
      ...builtin ? omp.builtinCredentialSecretEntries() : [],
    ], KEY)
    const freshHidden = async (side, cwd, home, input, env = {}, envFiles = false) => {
      const file = join(root, `fresh-source-process-${++tick}.mjs`)
      const sourceUrl = new URL('../../src/sources.ts', import.meta.url).href
      const obfuscatorUrl = new URL('../../src/obfuscator.ts', import.meta.url).href
      const upstreamUrl = pathToFileURL(join(resolve(ompRoot), 'src/secrets/index.ts')).href
      const script = side === 'plugin'
        ? `const { Sources } = await import(${JSON.stringify(sourceUrl)}); const { Vault } = await import(${JSON.stringify(obfuscatorUrl)}); const engine = new Sources({ vault: new Vault(${JSON.stringify(KEY)}), home: ${JSON.stringify(home)}, files: [${JSON.stringify(join(home, 'secrets.yml'))}, '.dsh/secrets.yml'], entries: [], env: process.env, envFiles: ${envFiles}, builtin: false, warn: () => {} }).for(${JSON.stringify(cwd)});`
        : `const { collectEnvSecrets, loadSecrets, SecretObfuscator } = await import(${JSON.stringify(upstreamUrl)}); const engine = new SecretObfuscator([...collectEnvSecrets(), ...await loadSecrets(${JSON.stringify(cwd)}, ${JSON.stringify(home)})], ${JSON.stringify(KEY)});`
      const environment = JSON.stringify({ ...baseEnv, ...env })
      put(file, `for (const name of Object.keys(process.env)) delete process.env[name]; Object.assign(process.env, ${environment});\n${script}\nconsole.log(JSON.stringify({ hidden: !engine.obfuscate(${JSON.stringify(input)}).includes(${JSON.stringify(input)}) }));\n`)
      const proc = Bun.spawn([bun, 'run', '--no-env-file', file], { cwd, env: { ...baseEnv, ...env }, stdout: 'pipe', stderr: 'pipe' })
      const output = await new Response(proc.stdout).text()
      const errors = await new Response(proc.stderr).text()
      if (await proc.exited !== 0) throw new Error(`Fresh synthetic source process failed: ${errors}`)
      return JSON.parse(output).hidden
    }
    for (const descriptor of SOURCE_CASES.filter(item => !filter || item.id.includes(filter))) {
      const work = join(root, descriptor.id)
      const cwd = join(work, 'project')
      const home = join(work, 'global')
      mkdirSync(cwd, { recursive: true })
      mkdirSync(home, { recursive: true })
      setEnv(descriptor.args.env ?? {})
      try {
        const { kind, args } = descriptor
        let actual
        if (descriptor.id === 'disable-plugin') {
          // An absent context proves disabled installation never touches services or source/key IO.
          const disabledHome = join(work, 'disabled-plugin')
          apply(undefined, { enabled: false, dshHome: disabledHome })
          actual = { plugin: { keyCreated: existsSync(disabledHome) } }
        } else if (kind === 'env') {
          const p = new Obfuscator(new Vault(KEY), plugin.envEntries(args.env))
          const o = new omp.SecretObfuscator(omp.collectEnvSecrets(), KEY)
          actual = { plugin: observe(p, args.input, 'plugin'), omp: observe(o, args.input, 'omp') }
        } else if (kind === 'yaml' || kind === 'dotenv' || kind === 'flags') {
          if (args.global !== undefined) put(join(home, 'secrets.yml'), JSON.stringify(args.global))
          if (args.project !== undefined || args.projectText !== undefined) {
            const text = args.projectText ?? JSON.stringify(args.project)
            put(join(cwd, '.dsh/secrets.yml'), text)
            put(join(cwd, '.omp/secrets.yml'), text)
          }
          if (args.projectDirectory) {
            mkdirSync(join(cwd, '.dsh/secrets.yml'), { recursive: true })
            mkdirSync(join(cwd, '.omp/secrets.yml'), { recursive: true })
          }
          if (args.text !== undefined) {
            if (args.symlink) {
              put(join(work, 'synthetic-env-target'), args.text)
              symlinkSync(join(work, 'synthetic-env-target'), join(cwd, '.env'))
            } else put(join(cwd, args.path ?? '.env'), args.text)
          }
          if (args.directory) mkdirSync(join(cwd, '.env'))
          const warnings = []
          const sources = makeSources(home, {
            env: args.envEnabled === false ? undefined : args.env ?? {},
            envFiles: kind === 'dotenv' || (kind === 'flags' && args.envFiles !== false),
            builtin: args.builtin ?? false, entries: args.inline ?? [], warn: message => warnings.push(message),
          })
          let p
          try { p = observe(sources.for(cwd), args.input, 'plugin') } catch (error) {
            p = { refused: true, error: String(error), errorOmitsInput: !String(error).includes(args.input) }
          }
          const o = observe(await loadOmp(cwd, home, args.builtin ?? false), args.input, 'omp')
          actual = { plugin: { ...p, warnings, warningsOmitInput: !warnings.some(message => message.includes(args.input)) }, omp: o }
        } else if (kind === 'timing') {
          const old = 'OldLifecycleSecret-12345'
          const fresh = 'NewLifecycleSecret-12345'
          const yaml = (directory, entries) => {
            put(join(directory, '.dsh/secrets.yml'), JSON.stringify(entries))
            put(join(directory, '.omp/secrets.yml'), JSON.stringify(entries))
          }
          const entry = value => ({ type: 'plain', content: value })
          if (descriptor.id === 'env-snapshot') {
            const environment = { API_KEY: old }
            setEnv(environment)
            const sources = makeSources(home, { env: environment })
            const p = sources.for(cwd)
            const o = await loadOmp(cwd, home)
            environment.API_KEY = fresh
            setEnv(environment)
            actual = {
              plugin: { originalHidden: observe(p, old, 'plugin').hidden, changedHidden: observe(sources.for(cwd), fresh, 'plugin').hidden, restartedHidden: await freshHidden('plugin', cwd, home, fresh, environment) },
              omp: { originalHidden: observe(o, old, 'omp').hidden, changedHidden: observe(o, fresh, 'omp').hidden, restartedHidden: await freshHidden('omp', cwd, home, fresh, environment) },
            }
          } else if (descriptor.id === 'yaml-edit' || descriptor.id === 'yaml-remove') {
            yaml(cwd, [entry(old)])
            const sources = makeSources(home)
            const p = sources.for(cwd)
            const o = await loadOmp(cwd, home)
            const pToken = p.obfuscate(old)
            const oToken = o.obfuscate(old)
            if (descriptor.id === 'yaml-edit') {
              yaml(cwd, [entry(fresh)])
              const stalePluginNewHidden = observe(p, fresh, 'plugin').hidden
              const staleOmpNewHidden = observe(o, fresh, 'omp').hidden
              const nextP = sources.for(cwd)
              const nextO = await loadOmp(cwd, home)
              actual = {
                plugin: { oldHidden: observe(nextP, old, 'plugin').hidden, newHidden: observe(nextP, fresh, 'plugin').hidden, staleNewHidden: stalePluginNewHidden },
                omp: { oldHidden: observe(nextO, old, 'omp').hidden, newHidden: observe(nextO, fresh, 'omp').hidden, staleNewHidden: staleOmpNewHidden },
              }
            } else {
              rmSync(join(cwd, '.dsh/secrets.yml'))
              rmSync(join(cwd, '.omp/secrets.yml'))
              actual = {
                plugin: { liveHidden: observe(sources.for(cwd), old, 'plugin').hidden, restartedHidden: await freshHidden('plugin', cwd, home, old), oldTokenRestores: p.vault.reveal(pToken) === old },
                omp: { liveHidden: observe(o, old, 'omp').hidden, restartedHidden: await freshHidden('omp', cwd, home, old), oldTokenRestores: o.deobfuscate(oToken) === old },
              }
            }
          } else if (descriptor.id === 'dotenv-add') {
            const sources = makeSources(home, { envFiles: true })
            const beforeHidden = observe(sources.for(cwd), fresh, 'plugin').hidden
            const ompBeforeHidden = observe(await loadOmp(cwd, home), fresh, 'omp').hidden
            put(join(cwd, '.env.local'), `NORMAL=${fresh}\n`)
            actual = {
              plugin: { beforeHidden, afterHidden: observe(sources.for(cwd), fresh, 'plugin').hidden },
              omp: { beforeHidden: ompBeforeHidden, afterHidden: observe(await loadOmp(cwd, home), fresh, 'omp').hidden },
            }
          } else if (descriptor.id === 'source-removal-replace') {
            yaml(cwd, [{ type: 'plain', content: old, mode: 'replace', replacement: '[MASK]' }])
            const sources = makeSources(home)
            sources.for(cwd).obfuscate(old)
            const originalOmp = await loadOmp(cwd, home)
            yaml(cwd, [])
            actual = {
              plugin: { liveHidden: observe(sources.for(cwd), old, 'plugin').hidden, restartedHidden: await freshHidden('plugin', cwd, home, old) },
              omp: { liveHidden: observe(originalOmp, old, 'omp').hidden, restartedHidden: await freshHidden('omp', cwd, home, old) },
            }
          } else if (descriptor.id === 'dotenv-edit-remove') {
            put(join(cwd, '.env'), `NORMAL=${old}\n`)
            const sources = makeSources(home, { envFiles: true })
            sources.for(cwd).obfuscate(old)
            put(join(cwd, '.env'), `NORMAL=${fresh}\n`)
            const editedHidden = observe(sources.for(cwd), fresh, 'plugin').hidden
            rmSync(join(cwd, '.env'))
            const stamp = new Date(Date.now() + ++tick * 2000)
            utimesSync(cwd, stamp, stamp)
            actual = {
              plugin: { editedHidden, removedStillHidden: observe(sources.for(cwd), fresh, 'plugin').hidden, restartedHidden: await freshHidden('plugin', cwd, home, fresh, {}, true) },
              omp: { editedHidden: observe(await loadOmp(cwd, home), fresh, 'omp').hidden, removedStillHidden: observe(await loadOmp(cwd, home), fresh, 'omp').hidden, restartedHidden: await freshHidden('omp', cwd, home, fresh) },
            }
          } else if (descriptor.id === 'project-isolation') {
            const b = join(work, 'project-b')
            const c = join(work, 'project-never-loaded')
            mkdirSync(b)
            mkdirSync(c)
            yaml(cwd, [entry(old)])
            yaml(b, [entry(fresh)])
            yaml(c, [entry('NeverLoadedSecret-12345')])
            const sources = makeSources(home)
            const pa = sources.for(cwd)
            const pb = sources.for(b)
            const oa = await loadOmp(cwd, home)
            const ob = await loadOmp(b, home)
            actual = {
              plugin: { aHidden: observe(pa, old, 'plugin').hidden, bHidden: observe(pb, fresh, 'plugin').hidden, siblingKnownHidden: observe(pb, old, 'plugin').hidden, siblingNeverLoadedHidden: observe(pb, 'NeverLoadedSecret-12345', 'plugin').hidden },
              omp: { aHidden: observe(oa, old, 'omp').hidden, bHidden: observe(ob, fresh, 'omp').hidden, siblingKnownHidden: observe(ob, old, 'omp').hidden, siblingNeverLoadedHidden: observe(ob, 'NeverLoadedSecret-12345', 'omp').hidden },
            }
          } else {
            yaml(cwd, [{ type: 'regex', content: 'LifecycleMatch-[0-9]+' }])
            const sources = makeSources(home)
            const p = sources.for(cwd)
            const o = await loadOmp(cwd, home)
            p.obfuscate('LifecycleMatch-111111')
            o.obfuscate('LifecycleMatch-111111')
            yaml(cwd, [])
            const nextP = sources.for(cwd)
            const nextO = await loadOmp(cwd, home)
            actual = {
              plugin: { newMatchHidden: observe(nextP, 'LifecycleMatch-222222', 'plugin').hidden, oldMatchHidden: observe(nextP, 'LifecycleMatch-111111', 'plugin').hidden },
              // An existing upstream session retains its regex; a fresh session forgets both dynamic values.
              omp: { newMatchHidden: observe(nextO, 'LifecycleMatch-222222', 'omp').hidden, oldMatchHidden: observe(o, 'LifecycleMatch-111111', 'omp').hidden },
            }
          }
        } else if (kind === 'key') {
          actual = {}
          for (const side of ['plugin', 'omp']) {
            if (descriptor.expected[side] === null) continue
            const keyDir = join(work, side)
            const file = join(keyDir, 'secret-placeholder.key')
            mkdirSync(keyDir)
            const load = () => side === 'plugin' ? loadKey(file) : omp.getSecretPlaceholderKey(keyDir)
            const valid = value => /^[A-Za-z0-9_-]{43}$/.test(value)
            if (descriptor.id === 'key-create-persist') {
              const first = await load()
              actual[side] = { valid: valid(first), stable: await load() === first, privateMode: (statSync(file).mode & 0o777) === 0o600 }
            } else if (descriptor.id === 'key-whitespace') {
              put(file, `\n ${KEY} \n`)
              actual[side] = { same: await load() === KEY }
            } else if (descriptor.id === 'key-invalid' || descriptor.id === 'key-empty') {
              const content = descriptor.id === 'key-empty' ? '' : 'Synthetic-invalid-key'
              put(file, content)
              let refused = false
              try { await load() } catch { refused = true }
              actual[side] = { refused, unchanged: readFileSync(file, 'utf8') === content }
            } else if (descriptor.id === 'key-unreadable-directory') {
              mkdirSync(file)
              let refused = false
              try { await load() } catch { refused = true }
              actual[side] = { refused }
            } else if (descriptor.id === 'key-cache-tamper') {
              await load()
              put(file, 'Synthetic-corrupted-key')
              let refused = false
              try { await load() } catch { refused = true }
              actual[side] = { refused }
            } else if (descriptor.id === 'key-sync-invalid') {
              put(file, 'Synthetic-invalid-key')
              let refused = false
              let value
              try { value = side === 'plugin' ? loadKey(file) : omp.getSecretPlaceholderKeySync(keyDir) } catch { refused = true }
              actual[side] = { valid: value === undefined ? false : valid(value), unchanged: readFileSync(file, 'utf8') === 'Synthetic-invalid-key', refused }
            } else if (descriptor.id === 'key-replace-only') {
              const project = join(keyDir, 'project')
              put(join(project, '.omp/secrets.yml'), JSON.stringify([{ type: 'plain', content: 'ReplaceOnlySecret-12345', mode: 'replace', replacement: '[MASK]' }]))
              const engine = await omp.buildSecretObfuscator(project, keyDir, keyDir)
              actual[side] = { keyCreated: existsSync(file), ...observe(engine, 'ReplaceOnlySecret-12345', side) }
            } else if (descriptor.id === 'key-builtin-lazy') {
              const engine = await omp.buildSecretObfuscator(cwd, keyDir, keyDir)
              const beforeMatch = existsSync(file)
              const observation = observe(engine, `ghp_${'b'.repeat(36)}`, side)
              actual[side] = { beforeMatch, afterMatch: existsSync(file), ...observation }
            } else {
              put(file, KEY)
              const engine = side === 'plugin' ? new Obfuscator(new Vault(loadKey(file)), []) : await omp.buildSecretObfuscator(cwd, keyDir, keyDir)
              actual[side] = observe(engine, KEY, side)
            }
          }
        } else {
          put(join(cwd, '.env'), 'SYNTHETIC_STARTUP_KEY=StartupValue-12345\n')
          const child = join(work, 'startup-probe.mjs')
          const isNode = descriptor.id === 'startup-node-dotenv'
          const upstreamUrl = pathToFileURL(join(resolve(ompRoot), 'src/secrets/index.ts')).href
          const collector = isNode ? '' : `const { collectEnvSecrets } = await import(${JSON.stringify(upstreamUrl)}); const collected = collectEnvSecrets().some(entry => entry.content === 'StartupValue-12345'); const loaded = process.env.SYNTHETIC_STARTUP_KEY === 'StartupValue-12345';`
          put(child, `${collector}\nconsole.log(JSON.stringify({ loaded: process.env.SYNTHETIC_STARTUP_KEY === 'StartupValue-12345', runtime: ${isNode ? "'node'" : "'bun'"}, version: ${isNode ? 'process.versions.node' : 'Bun.version'}, ${isNode ? '' : 'collected, collectionMatchesRuntime: collected === loaded'} }));\n`)
          if (isNode && !node) throw new Error('A real Node executable is required for the native startup comparison.')
          const command = isNode ? [node, child] : [bun, 'run', ...(descriptor.id === 'startup-bun-no-env-file' ? ['--no-env-file'] : []), child]
          const proc = Bun.spawn(command, { cwd, env: baseEnv, stdout: 'pipe', stderr: 'pipe' })
          const text = await new Response(proc.stdout).text()
          const error = await new Response(proc.stderr).text()
          if (await proc.exited !== 0) throw new Error(`Synthetic startup process failed: ${error}`)
          actual = { [isNode ? 'plugin' : 'omp']: JSON.parse(text) }
        }
        const mismatches = Object.entries(descriptor.expected).filter(([side, expected]) => expected !== null && !matchExpected(actual[side] ?? {}, expected)).map(([side]) => side)
        results.push({ ...descriptor, actual, pass: mismatches.length === 0, mismatches })
      } catch (error) {
        results.push({ ...descriptor, pass: false, error: String(error) })
      } finally {
        setEnv({})
      }
    }
    return { cases: results, total: results.length, failed: results.filter(item => !item.pass).length, sourceEvidence: SOURCE_EVIDENCE }
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
}

/** Compact CLI output contains case status and boolean runtime observations, never fixture secrets. */
export function compactSourceParityReport(report) {
  return {
    total: report.total, failed: report.failed,
    cases: report.cases.map(({ id, kind, classification, pass, mismatches, error }) => ({
      id, kind, classification, status: error ? 'ERROR' : pass ? 'PASS' : 'FAIL',
      ...(mismatches?.length ? { mismatches } : {}),
    })),
    runtimeObservations: report.cases.filter(item => item.kind === 'runtime').map(({ id, actual }) => ({ id, actual })),
    sourceEvidence: report.sourceEvidence,
  }
}

if (import.meta.main) {
  const ompRoot = process.argv.find(value => value.startsWith('--omp-root='))?.slice('--omp-root='.length)
  const filter = process.argv.find(value => value.startsWith('--case='))?.slice('--case='.length) ?? ''
  const bunExecutable = process.argv.find(value => value.startsWith('--bun='))?.slice('--bun='.length)
  const report = await runSourceParity({ ...(ompRoot ? { ompRoot } : {}), ...(bunExecutable ? { bunExecutable } : {}), filter })
  console.log(JSON.stringify(process.argv.includes('--detail') ? report : compactSourceParityReport(report), null, 2))
  if (report.failed) process.exitCode = 1
}
