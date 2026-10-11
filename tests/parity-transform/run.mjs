#!/usr/bin/env bun
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { transformCases, adjacentTokenCases, boundaryMatrix } from './cases.mjs';
import { loadImplementations, probeTransform, probeBoundaries, classify } from './probe.mjs';

export const allTransformCases = [...transformCases, ...adjacentTokenCases];
const TIMEOUT_MS = 10000;

// Each engine/case gets its own process: an empty Unicode regex in a reference
// implementation cannot hang the remaining matrix or conceal the other result.
// No production source loader, actual .env, profile, or persisted key is invoked.
export function runIsolated(ompRoot, args) {
  const child = spawnSync(process.execPath, [fileURLToPath(import.meta.url), '--worker', ...args], {
    cwd: resolve(fileURLToPath(new URL('../..', import.meta.url))),
    env: { PATH: process.env.PATH ?? '', TMPDIR: tmpdir(), OMP_SECRETS_DIR: ompRoot },
    encoding: 'utf8', timeout: TIMEOUT_MS, maxBuffer: 4 * 1024 * 1024,
  });
  if (child.error || child.status !== 0) return {
    checks: { executionCompleted: false },
    error: child.error?.code === 'ETIMEDOUT' ? `Timed out after ${TIMEOUT_MS} ms` : child.error?.message ?? child.stderr.trim() ?? `Exit ${child.status}`,
    infrastructureFailure: child.error?.code !== 'ETIMEDOUT', timedOut: child.error?.code === 'ETIMEDOUT',
  };
  try { return JSON.parse(child.stdout); }
  catch { return { checks: { executionCompleted: false }, error: 'Worker did not emit valid JSON', infrastructureFailure: true, stdout: child.stdout, stderr: child.stderr }; }
}

export function compareRecordedReference(spec, pluginResult, recordedOMP) {
  if ((recordedOMP.caseRevision ?? 1) !== (spec.revision ?? 1)) return classify(spec, pluginResult, {
    checks: {}, referenceError: true, invalidatedReference: true,
    error: `Recorded upstream case revision ${recordedOMP.caseRevision ?? 1} does not match current revision ${spec.revision ?? 1}; run this case without --reference-results for fresh native evidence.`,
  });
  const ompResult = recordedOMP.timedOut || /timed out|ETIMEDOUT/i.test(recordedOMP.error ?? '')
    ? { ...recordedOMP, referenceError: true, reused: true }
    : { ...recordedOMP, reused: true };
  return classify(spec, pluginResult, ompResult);
}

export function runParity({ ompRoot, selectedCase, strict = false, pluginOnly = false, referenceRecords = [] }) {
  const selected = selectedCase === undefined ? allTransformCases : allTransformCases.filter(spec => spec.id === selectedCase);
  if (selectedCase !== undefined && selected.length === 0 && selectedCase !== 'boundaries') throw new Error(`Unknown synthetic case: ${selectedCase}`);
  if (pluginOnly && selectedCase === 'boundaries') throw new Error('--plugin-only covers transform cases; boundaries require the separate installed-reference probe.');
  const upstream = new Map(referenceRecords.map(record => [record.id ?? record.name ?? record.case, record.omp]));
  const records = selected.map(spec => {
    const pluginResult = runIsolated(ompRoot, ['--case', spec.id, '--engine', 'plugin']);
    const recorded = upstream.get(spec.id);
    if (recorded !== undefined) return compareRecordedReference(spec, pluginResult, recorded);
    if (pluginOnly || spec.id === 'regex-zero-width-unicode') return classify(spec, pluginResult, {
      checks: {}, referenceError: true, skipped: true,
      error: spec.id === 'regex-zero-width-unicode'
        ? 'Reference Unicode empty-regex execution is skipped because of nontermination risk. Supply recorded upstream evidence with --reference-results.'
        : 'Plugin-only run: no recorded upstream result supplied; reference not executed.',
    });
    return classify(spec, pluginResult, runIsolated(ompRoot, ['--case', spec.id, '--engine', 'omp']));
  });
  if (!pluginOnly && (selectedCase === undefined || selectedCase === 'boundaries')) {
    const boundaryResults = runIsolated(ompRoot, ['--boundaries']);
    if (!Array.isArray(boundaryResults)) records.push({ id: 'boundaries', status: 'failed-contract', result: boundaryResults });
    else for (const result of boundaryResults) {
      const spec = boundaryMatrix.find(item => item.id === result.id);
      const record = classify(spec, result.plugin, result.omp);
      if (result.nativeShape !== undefined) record.nativeShape = result.nativeShape;
      if (result.jsonOnlyScope !== undefined) record.jsonOnlyScope = result.jsonOnlyScope;
      if (result.observations !== undefined) record.observations = result.observations;
      records.push(record);
    }
  }
  const counts = {};
  for (const record of records) counts[record.status] = (counts[record.status] ?? 0) + 1;
  const failures = records.filter(record => record.status === 'failed-contract' || record.classification === 'observed-consumer-gap');
  return {
    scope: 'Synthetic direct installed-OMP and plugin transform behavior, not actual Web transport or universal SDK parity.',
    interpretation: 'Privacy/reveal/order compare booleans only; output strings are evidence, not exact-token expectations. gap-probe is a hypothesis until execution; observed-consumer-gap requires a native passing/plugin failing privacy check. Intentional differences are reported rather than made parity failures.',
    sourceRoot: ompRoot,
    environment: 'Workers receive only PATH, TMPDIR and explicit OMP_SECRETS_DIR. No real source/key/env loaders are imported.',
    counts, records,
    boundaryMode: pluginOnly ? 'Not executed in plugin-only mode; run boundaries separately or use exported probeBoundaries with installed reference.' : selectedCase === undefined || selectedCase === 'boundaries' ? 'Executed direct boundary probe.' : 'Not selected.',
    exitCode: strict && failures.length ? 1 : 0,
    actualBoundaryCoverageRequired: boundaryMatrix.filter(spec => spec.id === 'tool-before-security-decisions'),
  };
}

if (import.meta.main) {
  const args = process.argv.slice(2);
  const argument = flag => { const index = args.indexOf(flag); return index < 0 ? undefined : args[index + 1]; };
  const ompRoot = argument('--omp-root') ?? process.env.OMP_SECRETS_DIR ?? join(homedir(), '.bun/install/global/node_modules/@oh-my-pi/pi-coding-agent');
  if (args.includes('--matrix')) {
    console.log(JSON.stringify({ transform: allTransformCases, boundaries: boundaryMatrix }, null, 2));
  } else if (args.includes('--worker')) {
    try {
      const implementations = await loadImplementations(ompRoot, { pluginOnly: argument('--engine') === 'plugin' });
      if (args.includes('--boundaries')) console.log(JSON.stringify(probeBoundaries(implementations)));
      else {
        const spec = allTransformCases.find(item => item.id === argument('--case'));
        const implementation = implementations[argument('--engine')];
        if (!spec || !implementation) throw new Error('Worker requires known --case and --engine');
        console.log(JSON.stringify(probeTransform(implementation, spec)));
      }
    } catch (error) {
      console.error(String(error?.stack ?? error));
      process.exitCode = 1;
    }
  } else {
    try {
      const referencePath = argument('--reference-results');
      const referenceData = referencePath === undefined ? [] : JSON.parse(readFileSync(referencePath, 'utf8'));
      const referenceRecords = Array.isArray(referenceData) ? referenceData : referenceData.records;
      if (!Array.isArray(referenceRecords)) throw new Error('--reference-results requires a synthetic report array or { records: [...] }');
      const report = runParity({ ompRoot, selectedCase: argument('--case'), strict: args.includes('--strict'), pluginOnly: args.includes('--plugin-only'), referenceRecords });
      console.log(JSON.stringify(report, null, 2));
      process.exitCode = report.exitCode;
    } catch (error) {
      console.error(String(error?.stack ?? error));
      process.exitCode = 1;
    }
  }
}
