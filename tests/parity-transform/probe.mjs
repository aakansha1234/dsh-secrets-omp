import { pathToFileURL } from 'node:url';
import { join } from 'node:path';
import { SYNTHETIC_KEY, SECRET, PLAIN, REGEX } from './cases.mjs';

export async function loadImplementations(ompRoot, { pluginOnly = false } = {}) {
  const [plugin, transform, omp, messages, scan, sdk] = await Promise.all([
    import('../../src/obfuscator.ts'), import('../../src/transform.ts'),
    pluginOnly ? {} : import(pathToFileURL(join(ompRoot, 'src/secrets/obfuscator.ts')).href),
    pluginOnly ? {} : import(pathToFileURL(join(ompRoot, 'src/secrets/message-transform.ts')).href),
    pluginOnly ? {} : import(pathToFileURL(join(ompRoot, 'src/secrets/placeholder-scan.ts')).href),
    import('@deepseek-ai/dsh-llm'),
  ]);
  return {
    plugin: {
      name: 'plugin',
      create(entries) { const vault = new plugin.Vault(SYNTHETIC_KEY); const engine = new plugin.Obfuscator(vault, entries); return { engine, hide: text => engine.obfuscate(text), reveal: text => vault.reveal(text) }; },
      map: plugin.mapStrings, transform, sdk,
      batch(engine, texts) {
        const options = { provider: 'synthetic', model: 'synthetic', messages: texts.map(text => ({ role: 'user', content: [{ type: 'text', text }] })) };
        return transform.redactRequest(engine, options).messages.map(message => message.content[0].text);
      },
    },
    omp: {
      name: 'omp',
      create(entries) { const engine = new omp.SecretObfuscator(entries, SYNTHETIC_KEY); return { engine, hide: text => engine.obfuscate(text), reveal: text => engine.deobfuscate(text) }; },
      map: scan.mapJsonStrings, deepMap: scan.deepWalkStrings, messages,
      batch(engine, texts) { return messages.obfuscateMessages(engine, texts.map(content => ({ role: 'user', content, timestamp: 0 }))).map(message => message.content); },
    },
  };
}

function checks(contract, input, output, restored, again) {
  const result = {};
  for (const value of contract.hidden ?? []) result[`hidden:${value}`] = !output.includes(value);
  for (const value of contract.visible ?? []) result[`visible:${value}`] = output.includes(value);
  for (const value of contract.oneWay ?? []) result[`oneWay:${value}`] = !restored.includes(value);
  if (contract.roundTrip) result.roundTrip = restored === input;
  if (contract.idempotent) result.idempotent = again === output;
  return result;
}

export function probeTransform(implementation, spec) {
  const instance = implementation.create(spec.entries);
  const { hide, reveal, engine } = instance;
  let input = spec.input;
  try {
    let output;
    const extra = {};
    if (spec.scenario === 'friendly-batch' || spec.scenario === 'friendly-short') {
      const token = hide(input);
      const later = spec.scenario === 'friendly-short' ? 'credential=pin123' : 'credential=later_token-12345';
      output = implementation.batch(engine, [token, later]).join('\n');
      input += `\n${later}`;
      extra.priorToken = token;
    } else if (spec.scenario === 'forged-prefix') {
      output = hide(input);
      const forged = output.replace(/^\$\$(?:[A-Z0-9]+_)?/, () => '$$SYNTHETICOTHER123_');
      extra.forged = forged;
      extra.forgedRestored = reveal(forged);
      extra.checks = {
        forgedAliasWellFormed: /^\$\$SYNTHETICOTHER123_[A-Z0-9]+(?::[ULCM])?\$\$$/.test(forged),
        forgedSecretPrefixInert: extra.forgedRestored === forged,
      };
    } else if (spec.scenario === 'preexisting-lookbehind') {
      input = hide('ABCDEFGH') + 'SECRETUV';
      output = hide(input);
      extra.checks = { hidesAdjacentRegexValue: !output.includes('SECRETUV'), restoresOriginalBytes: reveal(output) === 'ABCDEFGHSECRETUV' };
    } else if (spec.scenario === 'preexisting-lookahead') {
      input = 'SECRETUV' + hide('ABCDEFGH');
      output = hide(input);
      extra.checks = { hidesAdjacentRegexValue: !output.includes('SECRETUV'), restoresOriginalBytes: reveal(output) === 'SECRETUVABCDEFGH' };
    } else {
      output = hide(input);
      if (spec.scenario === 'known-token') output = hide(output);
      if (spec.scenario === 'case-hints') {
        const lower = hide(SECRET.toLowerCase());
        extra.checks = { caseHintDoesNotGrantSibling: reveal(lower.replace(':L', ':U')) !== SECRET.toUpperCase() };
      }
    }
    const restored = reveal(output);
    const again = hide(output);
    const assertions = { ...checks(spec.contracts?.[implementation.name] ?? spec.contract, input, output, restored, again), ...extra.checks };
    delete extra.checks;
    return { caseRevision: spec.revision ?? 1, output, restored, again, checks: assertions, semantic: { restoresInput: restored === input, changesInput: output !== input, idempotent: again === output }, refused: false, ...extra };
  } catch (error) {
    const message = String(error?.message ?? error);
    const refusal = /A secret replacement contains its original value|Secret replacements form a cycle/.test(message);
    return { caseRevision: spec.revision ?? 1, refused: refusal, error: message, checks: refusal && spec.classification === 'intentional-difference' ? { privacyPreservingRefusal: true } : { executionCompleted: false } };
  }
}

export function probeBoundaries(implementations) {
  const { plugin, omp } = implementations;
  const p = plugin.create([PLAIN(SECRET)]);
  const o = omp.create([PLAIN(SECRET)]);
  const records = [];
  const add = (id, pluginChecks, ompChecks, details = {}) => records.push({ id, plugin: { checks: pluginChecks }, omp: { checks: ompChecks }, ...details });
  const sdk = plugin.sdk;
  const pMessages = [
    sdk.createUserMessage({ source: { kind: 'user' }, content: [{ type: 'text', text: SECRET }] }),
    sdk.createDeveloperMessage({ source: { kind: 'user' }, content: [{ type: 'text', text: SECRET }] }),
    sdk.createAssistantMessage({ source: { provider: 'synthetic', model: 'synthetic' }, content: [{ type: 'text', text: SECRET }] }),
    sdk.createToolResultMessage({ callId: 'synthetic-call', content: [{ type: 'text', text: SECRET }], isError: false }),
    sdk.createSystemMessage(SECRET),
  ];
  const oMessages = ['user', 'developer', 'assistant', 'toolResult'].map(role => ({ role, attribution: 'user', timestamp: 0, content: [{ type: 'text', text: SECRET }] }));
  const projected = plugin.transform.redactRequest(p.engine, { provider: 'synthetic', model: 'synthetic', messages: pMessages });
  const oProjected = omp.messages.obfuscateMessages(o.engine, oMessages);
  add('roles-text', {
    allConversationRolesHidden: projected.messages.slice(0, 4).every(message => !message.content[0].text.includes(SECRET)),
    staticSystemVisible: projected.messages[4].content[0].text === SECRET,
    canonicalMessagesRemainLiteral: pMessages.every(message => message.content[0].text === SECRET),
  }, { allConversationRolesHidden: oProjected.every(message => !message.content[0].text.includes(SECRET)), canonicalMessagesRemainLiteral: oMessages.every(message => message.content[0].text === SECRET) });

  const replay = { response: { signature: 'synthetic-signature' }, blocks: [{ opaque: SECRET }] };
  const changed = sdk.createAssistantMessage({ source: { provider: 'synthetic', model: 'synthetic', replayState: replay }, content: [{ type: 'reasoning', text: SECRET }] });
  const unchanged = sdk.createAssistantMessage({ source: { provider: 'synthetic', model: 'synthetic', replayState: replay }, content: [{ type: 'reasoning', text: 'public reasoning' }] });
  const pReasoning = plugin.transform.redactRequest(p.engine, { provider: 'synthetic', model: 'synthetic', messages: [changed, unchanged] });
  const oReasoning = omp.messages.obfuscateMessages(o.engine, [{ role: 'assistant', timestamp: 0, content: [{ type: 'thinking', thinking: SECRET, thinkingSignature: 'synthetic-signature' }, { type: 'thinking', thinking: 'public reasoning', thinkingSignature: 'keep-signature' }] }]);
  add('reasoning-replay', { hidden: !pReasoning.messages[0].content[0].text.includes(SECRET), changedReplayOmitted: pReasoning.messages[0].source.replayState === undefined, unchangedReplayRetained: pReasoning.messages[1].source.replayState === unchanged.source.replayState }, { hidden: !oReasoning[0].content[0].thinking.includes(SECRET), changedReplayOmitted: oReasoning[0].content[0].thinkingSignature === undefined, unchangedReplayRetained: oReasoning[0].content[1].thinkingSignature === 'keep-signature' });

  const args = { [SECRET]: SECRET, nested: ['public', { value: SECRET }], number: 7, boolean: true, null: null };
  const call = sdk.createAssistantMessage({ source: { provider: 'synthetic', model: 'synthetic' }, content: [{ type: 'tool-call', id: 'synthetic-call', name: SECRET, arguments: JSON.stringify(args) }] });
  const pCall = plugin.transform.redactRequest(p.engine, { provider: 'synthetic', model: 'synthetic', messages: [call] }).messages[0].content[0];
  const pArgs = JSON.parse(pCall.arguments);
  const oArgs = omp.messages.obfuscateToolArguments(o.engine, args);
  add('tool-json-values-and-keys', { nestedValuesHidden: pArgs[SECRET] !== SECRET && pArgs.nested[1].value !== SECRET, keysUnchanged: Object.hasOwn(pArgs, SECRET), identityUnchanged: pCall.name === SECRET && pCall.id === 'synthetic-call', roundTrip: JSON.stringify(plugin.map(pArgs, p.reveal)) === JSON.stringify(args) }, { nestedValuesHidden: oArgs[SECRET] !== SECRET && oArgs.nested[1].value !== SECRET, keysUnchanged: Object.hasOwn(oArgs, SECRET), roundTrip: JSON.stringify(omp.messages.deobfuscateToolArguments(o.engine, oArgs)) === JSON.stringify(args) });
  const malformed = { ...call, content: [{ ...call.content[0], arguments: `{"value":"${SECRET}` }] };
  const pMalformed = plugin.transform.redactRequest(p.engine, { provider: 'synthetic', model: 'synthetic', messages: [malformed] }).messages[0].content[0];
  add('malformed-tool-json', { malformedTextHidden: !pMalformed.arguments.includes(SECRET) }, {}, { nativeShape: 'OMP tool arguments are structured objects; no malformed JSON string equivalent.' });

  const tools = [{ name: 'synthetic', description: SECRET, parameters: { type: 'object', properties: { value: { const: SECRET } } } }];
  const pStatic = plugin.transform.redactRequest(p.engine, { provider: 'synthetic', model: 'synthetic', messages: [], system: SECRET, tools });
  const oStatic = omp.messages.obfuscateProviderContext(o.engine, { messages: [], systemPrompt: SECRET, tools });
  add('static-system-schema', { systemVisible: pStatic.system.startsWith(SECRET), toolSchemaVisible: pStatic.tools === tools }, { systemVisible: oStatic.systemPrompt === SECRET, toolSchemaVisible: oStatic.tools === tools });

  const unknown = { type: 'synthetic-unknown', text: SECRET, payload: { value: SECRET } };
  const image = { type: 'image', image: SECRET, mimeType: 'image/png' };
  const pUnknown = plugin.transform.redactRequest(p.engine, { provider: 'synthetic', model: 'synthetic', messages: [{ role: 'user', content: [unknown, image] }] });
  const oUnknown = omp.messages.obfuscateMessages(o.engine, [{ role: 'user', timestamp: 0, content: [unknown, { type: 'image', data: SECRET, mimeType: 'image/png' }] }]);
  add('unknown-and-binary-blocks', { unknownUnchanged: pUnknown.messages[0].content[0] === unknown, binaryUnchanged: pUnknown.messages[0].content[1] === image }, { unknownUnchanged: oUnknown[0].content[0] === unknown, binaryUnchanged: oUnknown[0].content[1].data === SECRET });

  const sourceMessages = [
    { role: 'user', source: { kind: 'synthetic', form: 'notice', summary: SECRET }, content: [{ type: 'text', text: 'public' }] },
    { role: 'developer', source: { kind: 'synthetic', form: 'snapshot', sections: [{ name: SECRET, text: SECRET }] }, content: [{ type: 'text', text: 'public' }] },
  ];
  const pSources = plugin.transform.redactRequest(p.engine, { provider: 'synthetic', model: 'synthetic', messages: sourceMessages });
  add('source-notice-snapshot', { summaryHidden: pSources.messages[0].source.summary !== SECRET, sectionTextHidden: pSources.messages[1].source.sections[0].text !== SECRET, sectionNameUntouched: pSources.messages[1].source.sections[0].name === SECRET }, {}, { nativeShape: 'dsh-specific producer source metadata; OMP has no same source envelope.' });

  class SyntheticContainer { constructor() { this.value = SECRET; } }
  const object = new SyntheticContainer();
  const nullProto = Object.assign(Object.create(null), { value: SECRET });
  const protoKey = JSON.parse(`{"__proto__":"${SECRET}","nested":{"value":"${SECRET}"}}`);
  const pm = plugin.map([object, nullProto, protoKey], p.hide);
  const om = omp.map([object, nullProto, protoKey], o.hide);
  const od = omp.deepMap(object, o.hide);
  add('recursive-prototypes', { nullPrototypeValueHidden: pm[1].value !== SECRET, ownProtoKeyPreserved: Object.hasOwn(pm[2], '__proto__'), ownProtoValueHidden: pm[2].__proto__ !== SECRET, nestedValueHidden: pm[2].nested.value !== SECRET }, { nullPrototypeValueHidden: om[1].value !== SECRET, ownProtoKeyPreserved: Object.hasOwn(om[2], '__proto__'), ownProtoValueHidden: om[2].__proto__ !== SECRET, nestedValueHidden: om[2].nested.value !== SECRET }, {
    jsonOnlyScope: 'Class objects are outside JSON tool arguments; own __proto__ is valid JSON and must not disappear.',
    observations: { plugin: { classValueHidden: pm[0].value !== SECRET, classPrototypeRetained: Object.getPrototypeOf(pm[0]) === SyntheticContainer.prototype }, omp: { classValueHidden: om[0].value !== SECRET, classPrototypeRetained: Object.getPrototypeOf(om[0]) === SyntheticContainer.prototype, objectHelperClassSkipped: od === object } },
  });

  const controller = new AbortController();
  const frozen = Object.freeze({ provider: 'synthetic', model: 'synthetic', signal: controller.signal, messages: Object.freeze([pMessages[0]]) });
  const dispatch = plugin.transform.redactRequest(p.engine, frozen);
  controller.abort('synthetic-abort');
  add('borrowed-signal-frozen-request', { hidden: dispatch.messages[0].content[0].text !== SECRET, canonicalNotMutated: frozen.messages[0].content[0].text === SECRET, signalBorrowed: dispatch.signal === controller.signal, signalNotFrozen: !Object.isFrozen(controller.signal), abortFunctional: dispatch.signal.aborted && dispatch.signal.reason === 'synthetic-abort', dispatchFrozen: Object.isFrozen(dispatch) }, {}, { nativeShape: 'OMP provider Context has no dsh GenerateOptions.signal freezing contract.' });

  const staticTokenP = p.hide(SECRET), staticTokenO = o.hide(SECRET);
  const inbound = omp.messages.deobfuscateAgentMessages(o.engine, [
    { role: 'user', content: staticTokenO, timestamp: 0 },
    { role: 'developer', attribution: 'user', content: staticTokenO, timestamp: 0 },
    { role: 'toolResult', content: [{ type: 'text', text: staticTokenO }], timestamp: 0 },
    { role: 'assistant', content: [{ type: 'text', text: staticTokenO }, { type: 'thinking', thinking: staticTokenO, thinkingSignature: 'keep' }, { type: 'toolCall', name: 'synthetic', id: 'synthetic-call', arguments: { value: staticTokenO }, intent: staticTokenO, rawBlock: staticTokenO }], timestamp: 0 },
    { role: 'branchSummary', summary: staticTokenO },
    { role: 'compactionSummary', summary: staticTokenO, shortSummary: staticTokenO, blocks: [{ type: 'text', text: staticTokenO }] },
  ]);
  add('inbound-display-role-policy', {}, {
    operatorUserTokenUntouched: inbound[0].content === staticTokenO,
    operatorDeveloperTokenUntouched: inbound[1].content === staticTokenO,
    toolResultTokenUntouched: inbound[2].content[0].text === staticTokenO,
    assistantTextRestored: inbound[3].content[0].text === SECRET,
    hiddenThinkingTokenUntouched: inbound[3].content[1].thinking === staticTokenO && inbound[3].content[1].thinkingSignature === 'keep',
    assistantToolArgumentRestored: inbound[3].content[2].arguments.value === SECRET,
    assistantIntentAndRawBlockRestored: inbound[3].content[2].intent === SECRET && inbound[3].content[2].rawBlock === SECRET,
    modelSummaryRestored: inbound[4].summary === SECRET && inbound[5].summary === SECRET && inbound[5].shortSummary === SECRET && inbound[5].blocks[0].text === SECRET,
  }, { nativeShape: 'OMP-only local display transformer. Plugin direct exports cover outbound dispatch/tool capabilities; actual dsh local display needs the Web fixture, not an invented equivalent.' });
  const restartedP = plugin.create([PLAIN(SECRET)]), restartedO = omp.create([PLAIN(SECRET)]);
  add('restart-retained-custom', { retainedSourceRestores: restartedP.reveal(staticTokenP) === SECRET }, { retainedSourceRestores: restartedO.reveal(staticTokenO) === SECRET });
  const dynamic = 'SyntheticDynamic-12345678';
  const entries = [REGEX('(?<=credential=)SyntheticDynamic-[0-9]+')];
  const beforeP = plugin.create(entries), beforeO = omp.create(entries);
  const dynamicP = beforeP.hide(`credential=${dynamic}`).slice('credential='.length);
  const dynamicO = beforeO.hide(`credential=${dynamic}`).slice('credential='.length);
  const afterP = plugin.create(entries), afterO = omp.create(entries);
  const rawHistory = [{ role: 'user', content: [{ type: 'text', text: `credential=${dynamic}` }] }];
  plugin.transform.rememberMessages(afterP.engine, rawHistory);
  const nativeBeforeDiscovery = afterO.reveal(dynamicO);
  afterO.hide(`credential=${dynamic}`);
  add('restart-dynamic-raw-history', { seededHistoryRestores: afterP.reveal(dynamicP) === dynamic, contextFreeRehide: afterP.hide(dynamic) !== dynamic }, { constructorRestoresBeforeDiscovery: nativeBeforeDiscovery === dynamic, explicitRawDiscoveryRestores: afterO.reveal(dynamicO) === dynamic, contextFreeRehide: afterO.hide(dynamic) !== dynamic });
  const removedP = plugin.create([]), removedO = omp.create([]);
  const opaqueP = plugin.create(entries), opaqueO = omp.create(entries);
  plugin.transform.rememberMessages(opaqueP.engine, [{ role: 'assistant', source: { kind: 'model', provider: 'synthetic', model: 'synthetic' }, content: [{ type: 'text', text: dynamicP }] }]);
  omp.messages.deobfuscateAgentMessages(opaqueO.engine, [{ role: 'assistant', timestamp: 0, content: [{ type: 'text', text: dynamicO }] }]);
  add('restart-removed-custom-and-placeholder-only', { removedSourceInert: removedP.reveal(staticTokenP) === staticTokenP, opaqueHistoryInert: opaqueP.reveal(dynamicP) === dynamicP }, { removedSourceInert: removedO.reveal(staticTokenO) === staticTokenO, opaqueHistoryInert: opaqueO.reveal(dynamicO) === dynamicO });
  const staticDeveloper = omp.messages.obfuscateMessages(o.engine, [{ role: 'developer', attribution: 'system', timestamp: 0, content: SECRET }]);
  add('developer-static-attribution', { dshDeveloperHidden: projected.messages[1].content[0].text !== SECRET }, { ompStaticDeveloperVisible: staticDeveloper[0].content === SECRET });
  return records;
}

export function classify(spec, plugin, omp) {
  if (spec.contracts?.omp !== undefined && typeof omp.output === 'string') {
    // Evaluate recorded output against the current engine-specific contract.
    omp = { ...omp, checks: checks(spec.contracts.omp, spec.input, omp.output, omp.restored, omp.again) };
  }
  const pChecks = plugin.checks ?? {}, oChecks = omp.checks ?? {};
  const pFailed = Object.entries(pChecks).filter(([, pass]) => !pass).map(([name]) => name);
  const oFailed = Object.entries(oChecks).filter(([, pass]) => !pass).map(([name]) => name);
  const common = Object.keys(pChecks).filter(key => Object.hasOwn(oChecks, key));
  const differences = common.filter(key => pChecks[key] !== oChecks[key]);
  for (const key of Object.keys(plugin.semantic ?? {})) {
    if (Object.hasOwn(omp.semantic ?? {}, key) && plugin.semantic[key] !== omp.semantic[key]) differences.push(`semantic:${key}`);
  }
  if (plugin.refused !== omp.refused && 'refused' in plugin && 'refused' in omp) differences.push('refusal-policy');
  const privacyGap = differences.some(key => /^(hidden:|oneWay:|hidesAdjacentRegexValue|forgedSecretPrefixInert)/.test(key) && pChecks[key] === false && oChecks[key] === true);
  const failed = pFailed.length || oFailed.length;
  const executionFailed = pChecks.executionCompleted === false || oChecks.executionCompleted === false;
  const status = executionFailed ? 'failed-contract' : differences.length || (failed && spec.classification === 'intentional-difference') ? 'difference' : failed ? 'failed-contract' : 'pass';
  const classification = omp.referenceError ? 'reference-error' : privacyGap && spec.classification !== 'intentional-difference' ? 'observed-consumer-gap' : spec.classification;
  const unasserted = Object.keys(pChecks).length === 0 && Object.keys(oChecks).length === 0;
  const reportedStatus = omp.referenceError ? pChecks.executionCompleted === false || pFailed.length > 0 ? 'failed-contract' : 'reference-error' : status === 'pass' && unasserted ? 'observation' : status;
  return { id: spec.id, caseRevision: spec.revision ?? 1, classification, purpose: spec.purpose, refs: spec.refs, status: reportedStatus, differences, failed: { plugin: pFailed, omp: oFailed }, plugin, omp };
}
