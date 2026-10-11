import { expect, test } from 'bun:test'
import { runWebAudit } from './runner.ts'

// Explicit native integration lane: DSH_WEB_AUDIT=1 bun test tests/web-audit/runner.spec.ts
// The isolated child receives an allowlisted synthetic environment regardless
// of this opt-in flag or any credentials in the test process environment.
const nativeTest = process.env.DSH_WEB_AUDIT === '1' ? test : test.skip
nativeTest('actual Native Web provider transport hides protected values and restores tool consumers', async () => {
  const report = await runWebAudit()
  for (const row of report) {
    if (row.classification === 'refusal') {
      expect({ name: row.name, status: row.status, requests: row.outboundRequestCount }).toEqual({ name: row.name, status: 'refused', requests: 0 })
    } else if (row.classification === 'protected' || row.classification === 'gap-probe') {
      expect({ name: row.name, status: row.status }).toEqual({ name: row.name, status: 'pass' })
      expect(row.outboundRequestCount).toBeGreaterThan(0)
    } else {
      expect({ name: row.name, status: row.status }).toEqual({ name: row.name, status: row.name.startsWith('history-restart-') ? 'limit-observed' : 'pass' })
      expect(row.outboundRequestCount).toBeGreaterThan(0)
    }
  }
}, 240000)
