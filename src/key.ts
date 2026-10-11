import { randomBytes } from 'node:crypto'
import { linkSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'

/** Publish a complete 0600 key atomically; concurrent starts never read a half-written key. */
export function loadKey(path: string): string {
  const read = (): string => {
    const key = readFileSync(path, 'utf8').trim()
    if (!/^[A-Za-z0-9_-]{43}$/.test(key)) throw new Error(`Invalid secret placeholder key at ${path}; refusing to replace it`)
    return key
  }
  try {
    return read()
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
  }
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
  const key = randomBytes(32).toString('base64url')
  const temporary = `${path}.${randomBytes(12).toString('hex')}.tmp`
  writeFileSync(temporary, key, { flag: 'wx', mode: 0o600 })
  try {
    try {
      linkSync(temporary, path)
      return key
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
      return read()
    }
  } finally {
    unlinkSync(temporary)
  }
}
