import { it } from 'bun:test'
import { runHarnessScenario } from './harness.ts'

it('discovers a file-only .env credential through actual cat, hides old and edited values on the real provider wire, and restores arguments before guards', runHarnessScenario)
