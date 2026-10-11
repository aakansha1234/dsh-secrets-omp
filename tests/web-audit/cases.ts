export type Classification = 'protected' | 'intentional-difference' | 'shared-limit' | 'gap-probe' | 'refusal'
export interface AuditCase {
  name: string
  classification: Classification
  text: string
  hidden?: string[]
  visible?: string[]
  files?: Record<string, string>
  rules?: object[]
  inline?: object[]
  globalRules?: object[]
  mode?: 'session' | 'direct' | 'prepared' | 'compaction' | 'blocks' | 'static' | 'edit' | 'guard' | 'token-context' | 'rendered-token-context' | 'raw-literal-token' | 'oneway-removal'
  command?: string
  malformed?: boolean
}
export const probes = {
  env: 'SyntheticEnvCredential-Aa123456', public: 'SyntheticPublicSetting-Bb123456',
  password: 'SyntheticUrlPassword-Cc123456!', encodedPassword: 'SyntheticUrlPassword-Cc123456%21',
  file: 'SyntheticFileCredential-Dd123456', updated: 'SyntheticFileCredential-Dd123456x',
  plain: 'SyntheticPlainCredential-Ff123456', regex: 'AuditRegex-Gg123456',
}
const literal = (content: string, extras: Record<string, string> = {}) => ({ type: 'plain', content, ...extras })
export function auditCases(): AuditCase[] {
  const p = probes
  const cases: AuditCase[] = [
    { name: 'environment-secret-name', classification: 'protected', text: p.env, hidden: [p.env] },
    { name: 'environment-public-name', classification: 'intentional-difference', text: p.public, visible: [p.public] },
    { name: 'environment-name-suffix-matching', classification: 'intentional-difference', text: 'SyntheticOddEnvName-Ll123456 SyntheticNonSuffixEnv-Mm123456', hidden: ['SyntheticOddEnvName-Ll123456'], visible: ['SyntheticNonSuffixEnv-Mm123456'] },
    { name: 'environment-url-password-raw-decoded', classification: 'protected', text: `${p.password} ${p.encodedPassword}`, hidden: [p.password, p.encodedPassword] },
    { name: 'dotenv-arbitrary-name', classification: 'protected', text: p.file, files: { '.env': `CUSTOM_DATA=${p.file}\n` }, hidden: [p.file] },
    { name: 'dotenv-actual-cat-output', classification: 'protected', text: 'Run the actual synthetic source read.', command: 'cat .env', files: { '.env': `CUSTOM_DATA=${p.file}\n` }, hidden: [p.file] },
    { name: 'dotenv-local-export-single-quote', classification: 'protected', text: p.file, files: { '.env.local': `export CUSTOM_DATA='${p.file}' # ignored comment\n` }, hidden: [p.file] },
    { name: 'dotenv-backtick-and-comments', classification: 'protected', text: `${p.file} visible-comment`, files: { '.env.production': `DATA=\`${p.file}\` # visible-comment\n` }, hidden: [p.file], visible: ['visible-comment'] },
    { name: 'dotenv-escaped-and-multiline', classification: 'protected', text: `${p.file}\\nsecond-line\n${p.file}\nsecond-line`, files: { '.env': `DOUBLE="${p.file}\\nsecond-line"\nMULTI='${p.file}\nsecond-line'\n` }, hidden: [`${p.file}\\nsecond-line`, `${p.file}\nsecond-line`] },
    { name: 'dotenv-duplicate-values', classification: 'protected', text: `${p.file} ${p.updated}`, files: { '.env': `DATA=${p.file}\nDATA=${p.updated}\n` }, hidden: [p.file, p.updated] },
    { name: 'dotenv-short-value', classification: 'shared-limit', text: 'tiny123', files: { '.env': 'DATA=tiny123\n' }, visible: ['tiny123'] },
    { name: 'dotenv-eight-character-boundary', classification: 'protected', text: 'Eight123', files: { '.env': 'DATA=Eight123\n' }, hidden: ['Eight123'] },
    { name: 'dotenv-nested-directory', classification: 'shared-limit', text: p.file, files: { 'nested/.env': `DATA=${p.file}\n` }, visible: [p.file] },
    { name: 'dotenv-comment-not-source', classification: 'shared-limit', text: p.file, files: { '.env': `# DATA=${p.file}\nPUBLIC=short\n` }, visible: [p.file] },
    { name: 'dotenv-url-extracted-password', classification: 'gap-probe', text: 'Read URL password components only.', files: { '.env': 'DATA_ENDPOINT=postgres://user:SyntheticDotenvUrl-Hh123456%21@host/db\n' }, mode: 'session', command: "node -e 'const fs=require(\"fs\");const u=new URL(fs.readFileSync(\".env\",\"utf8\").trim().split(\"=\").slice(1).join(\"=\"));console.log(u.password);console.log(decodeURIComponent(u.password))'", hidden: ['SyntheticDotenvUrl-Hh123456%21', 'SyntheticDotenvUrl-Hh123456!'] },
    { name: 'dotenv-url-full-raw-parsed', classification: 'protected', text: 'Print raw and parsed synthetic connection values.', files: { '.env': 'DATA_ENDPOINT="postgres://user:SyntheticDotenvFull-Pp123456%21@host/db"\n' }, command: `node -e 'const fs=require("fs");const text=fs.readFileSync(".env","utf8");console.log(text);const value=text.trim().split("=").slice(1).join("=").slice(1,-1);console.log(value);console.log(decodeURIComponent(value))'`, hidden: ['SyntheticDotenvFull-Pp123456%21', 'SyntheticDotenvFull-Pp123456!'] },
    { name: 'yaml-file-inline-override', classification: 'protected', text: p.plain, rules: [literal(p.plain, { mode: 'replace', replacement: 'FILE_MASK' })], inline: [literal(p.plain, { mode: 'replace', replacement: 'INLINE_MASK' })], hidden: [p.plain], visible: ['INLINE_MASK'] },
    { name: 'yaml-global-rule', classification: 'protected', text: 'SyntheticGlobalYaml-Kk123456', globalRules: [literal('SyntheticGlobalYaml-Kk123456')], hidden: ['SyntheticGlobalYaml-Kk123456'] },
    { name: 'literal-friendly-label', classification: 'protected', text: 'SyntheticLabelCredential-Ii123456', inline: [literal('SyntheticLabelCredential-Ii123456', { friendlyName: 'Audit friendly label' })], hidden: ['SyntheticLabelCredential-Ii123456'], visible: ['AUDITFRIENDLYLABEL_'] },
    { name: 'short-regex-value-label-collision', classification: 'gap-probe', text: 'SyntheticShortLabel-Pp123456 #QXZ', inline: [literal('SyntheticShortLabel-Pp123456', { friendlyName: 'QXZ' }), { type: 'regex', content: '(?<=#)QXZ' }], hidden: ['SyntheticShortLabel-Pp123456', 'QXZ_'], visible: ['#QXZ'] },
    { name: 'literal-case-variants', classification: 'shared-limit', text: 'SYNTHETICCASE-JJ123456 syntheticcase-jj123456 SyntheticCase-Jj123456', inline: [literal('SyntheticCase-Jj123456')], hidden: ['SyntheticCase-Jj123456'], visible: ['SYNTHETICCASE-JJ123456', 'syntheticcase-jj123456'] },
    { name: 'regex-flags-and-replacement', classification: 'protected', text: p.regex.toLowerCase(), inline: [{ type: 'regex', content: 'AuditRegex-[A-Za-z0-9]+', flags: 'i', mode: 'replace', replacement: 'REGEX_MASK' }], hidden: [p.regex.toLowerCase()], visible: ['REGEX_MASK'] },
    { name: 'regex-lookbehind-redacted-literal', classification: 'gap-probe', text: 'AuditCtxABCDEFGHSECRETUV', inline: [literal('AuditCtxABCDEFGH'), { type: 'regex', content: '(?<=AuditCtxABCDEFGH)SECRETUV' }], hidden: ['AuditCtxABCDEFGH', 'SECRETUV'] },
    { name: 'regex-lookahead-redacted-literal', classification: 'gap-probe', text: 'SECRETAHEADAuditAheadABCDEFGH', inline: [literal('AuditAheadABCDEFGH'), { type: 'regex', content: 'SECRETAHEAD(?=AuditAheadABCDEFGH)' }], hidden: ['AuditAheadABCDEFGH', 'SECRETAHEAD'] },
    { name: 'regex-lookbehind-existing-token', classification: 'gap-probe', mode: 'token-context', text: 'AuditExistingABCDEFGH', inline: [literal('AuditExistingABCDEFGH'), { type: 'regex', content: '(?<=AuditExistingABCDEFGH)SECRETEXISTINGUV' }], hidden: ['AuditExistingABCDEFGH', 'SECRETEXISTINGUV'] },
    { name: 'whole-regex-spans-existing-token', classification: 'gap-probe', mode: 'token-context', text: 'AuditWholeABCDEFGH', inline: [literal('AuditWholeABCDEFGH'), { type: 'regex', content: 'AuditWholeABCDEFGHSpanPayload-Rr123456' }], hidden: ['AuditWholeABCDEFGH', 'SpanPayload-Rr123456'] },
    { name: 'regex-rendered-token-syntax-context', classification: 'gap-probe', mode: 'rendered-token-context', text: 'AuditRenderedABCDEFGH', inline: [literal('AuditRenderedABCDEFGH'), { type: 'regex', content: 'RenderedPayload-Vv123456(?=\\$\\$)' }], hidden: ['AuditRenderedABCDEFGH', 'RenderedPayload-Vv123456'] },
    { name: 'registered-raw-literal-containing-token', classification: 'gap-probe', mode: 'raw-literal-token', text: 'AuditOuterABCDEFGH', inline: [literal('AuditOuterABCDEFGH')], hidden: ['AuditOuterABCDEFGH', 'OuterPrefix-', '-LongSuffix'] },
    { name: 'one-way-rule-inside-reversible-literal', classification: 'gap-probe', text: 'prefix-SyntheticPin123-suffix', inline: [literal('prefix-SyntheticPin123-suffix'), { type: 'regex', content: 'SyntheticPin[0-9]+', mode: 'replace', replacement: 'PIN_MASK' }], hidden: ['SyntheticPin123'], visible: ['PIN_MASK'] },
    { name: 'replacement-introduced-regex-secret', classification: 'gap-probe', text: 'REPLACE_TRIGGER', inline: [literal('REPLACE_TRIGGER', { mode: 'replace', replacement: 'CredentialSynthetic-123456' }), { type: 'regex', content: 'CredentialSynthetic-[0-9]+' }], hidden: ['CredentialSynthetic-123456'] },
    { name: 'oneway-source-removal-live-host', classification: 'protected', mode: 'oneway-removal', text: 'SyntheticOneWayRemoved-Ww123456', rules: [literal('SyntheticOneWayRemoved-Ww123456', { mode: 'replace', replacement: 'ONEWAY_REMOVAL_MASK' })], hidden: ['SyntheticOneWayRemoved-Ww123456'], visible: ['ONEWAY_REMOVAL_MASK'] },
    ...(['direct', 'prepared', 'compaction', 'blocks'] as const).map(mode => ({ name: `request-${mode}-frozen`, classification: 'protected' as const, mode, text: p.file, files: { '.env': `DATA=${p.file}\n` }, hidden: [p.file] })),
    { name: 'borrowed-cancellation-signal', classification: 'protected', mode: 'direct', text: p.file, files: { '.env': `DATA=${p.file}\n` }, hidden: [p.file] },
    { name: 'static-system-tool-schema', classification: 'shared-limit', mode: 'static', text: p.file, files: { '.env': `DATA=${p.file}\n` }, visible: [p.file] },
    { name: 'encoded-secret', classification: 'shared-limit', text: Buffer.from(p.file).toString('base64'), files: { '.env': `DATA=${p.file}\n` }, visible: [Buffer.from(p.file).toString('base64')] },
    { name: 'split-secret', classification: 'shared-limit', text: `${p.file.slice(0, 15)} ${p.file.slice(15)}`, files: { '.env': `DATA=${p.file}\n` }, visible: [p.file.slice(0, 15), p.file.slice(15)] },
    { name: 'unregistered-arbitrary-value', classification: 'shared-limit', text: p.file, visible: [p.file] },
    { name: 'tool-edit-old-new-values', classification: 'protected', mode: 'edit', text: 'Read then edit the fixture credential.', files: { '.env': `DATA=${p.file}\n` }, hidden: [p.file, p.updated] },
    { name: 'tool-guard-restored-arguments', classification: 'protected', mode: 'guard', text: p.file, files: { '.env': `DATA=${p.file}\n` }, hidden: [p.file] },
    { name: 'malformed-dotenv-refusal', classification: 'refusal', malformed: true, text: p.file, files: { '.env': `DATA="${p.file}\n` }, hidden: [p.file] },
    { name: 'malformed-yaml-source-skipped', classification: 'shared-limit', text: p.file, files: { '.dsh/secrets.yml': '[invalid: [' }, visible: [p.file] },
  ]
  const builtins: Record<string, string> = {
    GitHubOAuth: `gho_${'B'.repeat(36)}`, GitHubPAT: `ghp_${'C'.repeat(36)}`,
    GitHubUser: `ghu_${'D'.repeat(36)}`, GitHubServer: `ghs_${'E'.repeat(36)}`,
    GitHubRefresh: `ghr_${'F'.repeat(36)}`, GitHubFineGrained: `github_pat_${'G'.repeat(36)}`,
    GitLab: `glpat-${'H'.repeat(20)}`, OpenAILegacy: `sk-${'I'.repeat(48)}`,
    OpenAIProject: `sk-proj-${'J'.repeat(36)}`, Anthropic: `sk-ant-${'K'.repeat(36)}`,
    AWSAccessKey: `AKIA${'A'.repeat(16)}`,
    GoogleAPIKey: `AIza${'A'.repeat(30)}`, SlackToken: `xoxb-${'A'.repeat(20)}`,
    NpmToken: `npm_${'A'.repeat(30)}`, StripeKey: `sk_test_${'A'.repeat(20)}`,
    StripeWebhookSecret: `whsec_${'A'.repeat(20)}`, HuggingFaceToken: `hf_${'A'.repeat(30)}`,
    SendGridKey: `SG.${'A'.repeat(22)}.${'A'.repeat(43)}`,
    JWT: `eyJ${'A'.repeat(12)}.eyJ${'B'.repeat(12)}.${'C'.repeat(12)}`,
    BearerToken: `Bearer ${'A'.repeat(24)}`,
    PrivateKey: ['-----BEGIN ', 'PRIVATE KEY-----\n', 'U3ludGhldGljLW5vdC1hLWtleQ==\n', '-----END ', 'PRIVATE KEY-----'].join(''),
  }
  for (const [family, value] of Object.entries(builtins)) cases.push({ name: `builtin-${family}`, classification: 'protected', text: value, hidden: [family === 'BearerToken' ? value.slice(7) : value] })
  // The plugin's Vault survives sessions. Independent cases must not share
  // arbitrary literals, otherwise earlier discovery masks excluded sources.
  return cases.map((item, index) => {
    if (item.mode === 'edit' || item.mode === 'guard') return item
    const fileValue = `SyntheticFileCase${index}-Dd123456`
    const substitutions = [
      [p.updated, `${fileValue}x`], [p.file, fileValue],
      [p.plain, `SyntheticPlainCase${index}-Ff123456`],
      [Buffer.from(p.file).toString('base64'), Buffer.from(fileValue).toString('base64')],
    ] as const
    const rewrite = (text: string) => {
      for (const [before, after] of substitutions) text = text.replaceAll(before, after)
      return text
    }
    const rewriteRule = (entry: object) => Object.fromEntries(Object.entries(entry).map(([key, value]) => [key, typeof value === 'string' ? rewrite(value) : value]))
    const result: AuditCase = { ...item, text: rewrite(item.text) }
    if (item.hidden) result.hidden = item.hidden.map(rewrite)
    if (item.visible) result.visible = item.visible.map(rewrite)
    if (item.files) result.files = Object.fromEntries(Object.entries(item.files).map(([path, contents]) => [path, rewrite(contents)]))
    if (item.inline) result.inline = item.inline.map(rewriteRule)
    if (item.rules) result.rules = item.rules.map(rewriteRule)
    if (item.globalRules) result.globalRules = item.globalRules.map(rewriteRule)
    if (item.name === 'split-secret') {
      result.text = `${fileValue.slice(0, 15)} ${fileValue.slice(15)}`
      result.visible = [fileValue.slice(0, 15), fileValue.slice(15)]
    }
    return result
  })
}
