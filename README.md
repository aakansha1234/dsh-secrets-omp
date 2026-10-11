# dsh-secrets-omp

A secrets plugin for **DeepSeek Harness 0.2.0-rc.2**, based on [oh-my-pi](https://github.com/can1357/oh-my-pi).

Replaces secrets with placeholders before messages reach the model. When the model puts a placeholder in a tool argument, the plugin restores the original value before validation, approval checks, and execution. Tool output is redacted before the next model request.

Local history still contains the real values. This plugin hides secrets from the model; it doesn't encrypt files or sandbox tools.

## Install

### Build

Run from the repository root:

```sh
bun install
bun pm pack --destination release
printf '%s\n' "$PWD/release/dsh-secrets-omp-0.1.5.tgz"
```

Use the printed archive path in the installer. Environment variables, `.env` files, and built-in credential patterns are enabled by default.

### Desktop

1. Open **DeepSeek Harness → Plugins → Add plugin**.
2. Paste the archive's absolute local path into the package field.
3. Accept the trust prompt and install.
4. Enable `dsh-secrets-omp` if it isn't already enabled.
5. Check that it shows **Running**. Restart Desktop if prompted.

On macOS, you can also use Desktop's bundled CLI. Quit Desktop first:

```sh
"/Applications/DeepSeek Harness.app/Contents/Resources/runtime/cli/bin/dsh" \
  plugin --profile desktop add "$PWD/release/dsh-secrets-omp-0.1.5.tgz"
open -a "DeepSeek Harness"
```

### Web

Run these commands on the machine hosting Harness, where the archive is available:

```sh
npx @deepseek-ai/dsh plugin --profile web add "$PWD/release/dsh-secrets-omp-0.1.5.tgz"
npx @deepseek-ai/dsh web --no-open
```

Use `bunx` instead of `npx` if you prefer Bun.

### Uninstall

Use **Uninstall** in Plugins, or run this for Web:

```sh
npx @deepseek-ai/dsh@0.2.0-rc.2 plugin --profile web remove dsh-secrets-omp
```

For Desktop, use its bundled CLI with `plugin --profile desktop remove dsh-secrets-omp`. If you remove the package offline with `bun remove --cwd`, also remove it from the profile's `dsh.profile.bundles` list. Restart the affected Host after an offline change.

## Secret sources

Sources are read in this order:

1. Environment variables with `KEY`, `SECRET`, `TOKEN`, `PASSWORD`, `PASS`, `AUTH`, `CREDENTIAL`, `PRIVATE`, or `OAUTH` as a name component or suffix.
2. Passwords in connection URLs from the environment, even when the variable name isn't secret-related.
3. `.env` and `.env.*` files in the session's working directory. Values from every variable name are collected if they're at least eight characters long. Quoted and escaped values are collected in both raw and parsed form, as are duplicate assignments. URL passwords are collected separately.
4. `$DSH_HOME/secrets.yml` (usually `~/.dsh/secrets.yml`).
5. `.dsh/secrets.yml` in the session's working directory.
6. Rules in the plugin configuration.
7. Built-in credential patterns. A configured rule with the same pattern overrides the built-in rule.

For rules with the same `content`, the last entry wins. Duplicate values are collected once. Relative paths use the session's working directory, not the directory where Harness was started. URL passwords are collected in both percent-encoded and decoded form.

Dotenv files are checked for changes on each request. Values already found remain protected until the Host restarts, even if their source changes or disappears. Environment variables are read when the plugin starts; restart it after changing them.

Built-in patterns cover GitHub/GitLab, OpenAI/Anthropic, AWS access keys, Google API keys, Slack, npm, Stripe keys and webhook secrets, Hugging Face, SendGrid, JWTs, Bearer tokens, and PEM private keys. Detection uses known credential formats, not entropy.

Dotenv files are parsed, not executed or loaded into `process.env`. Shell commands and variable interpolation aren't supported. If a matching file can't be read or parsed, is a symlink, or isn't a regular file, the model request is blocked without logging its contents. Matching directories are ignored.

Only the session's working directory is scanned. Nested files, files elsewhere, short values, and secrets in comments need an explicit rule or a built-in pattern that matches them. Set `envFiles: false` to turn off dotenv discovery; YAML and inline rules still apply.

### `secrets.yml`

Use a list of rules, in the same format as oh-my-pi:

```yaml
- type: plain
  content: sample-api-credential-1234
  friendlyName: Service API

- type: plain
  content: short-password
  mode: replace
  replacement: '[password hidden]'

- type: regex
  content: 'custom_token_[A-Za-z0-9]{16,}'
  friendlyName: Custom Token
```

| Field | Meaning |
|---|---|
| `type` | Required: `plain` or `regex` |
| `content` | Required: nonempty literal value or regex source |
| `mode` | `obfuscate` (default, reversible) or `replace` (one-way) |
| `replacement` | Optional fixed text for replace mode |
| `flags` | Optional regex flags; `g` is always added |
| `friendlyName` | Optional label shown to the model; converted to uppercase letters/digits and limited to 32 characters |

Regex rules also accept `/pattern/i` syntax. Matching uses both the original text and text containing placeholders, so lookarounds still work. One-way rules run first; literal matches use the longest match first. A longer reversible value can't make a one-way secret restorable.

Reversible matches shorter than eight characters are ignored. Use `mode: replace` for short values. Short regex matches are still checked against friendly labels to keep those labels from exposing them.

Without a custom `replacement`, replace mode generates a stable, keyed string with the same number of Unicode characters. If the regex matches every generated candidate, a fixed one-way marker is used instead.

One-way values can't be restored, even through an older placeholder for a larger value containing them. This stays in effect until the Host restarts; deleting the rule doesn't undo it. Replacement text is checked again for secrets. If a replacement exposes its original value or creates a cycle, the request is blocked.

Missing YAML files are ignored. Bad YAML, invalid rules, and invalid regexes are skipped with a warning that doesn't include secret values or file contents. An invalid label doesn't disable the rest of a valid rule.

### Configuration

Override the bundle entry in your profile's `cordis.patch.yml`:

```yaml
- id: dsh-secrets-omp
  name: dsh-secrets-omp
  config:
    env: true
    envFiles: true
    builtin: true
    files:
      - $DSH_HOME/secrets.yml
      - .dsh/secrets.yml
    secrets:
      - type: plain
        content: sample-api-credential-1234
        friendlyName: Service API
```

| Option | Default |
|---|---|
| `enabled` | `true` |
| `env` | `true` |
| `envFiles` | `true` |
| `builtin` | `true` |
| `secrets` | `[]` |
| `files` | `[$DSH_HOME/secrets.yml, .dsh/secrets.yml]` |
| `dshHome` | `$DSH_HOME`, otherwise `~/.dsh` |

To use existing oh-my-pi rules, add `~/.omp/agent/secrets.yml` and `.omp/secrets.yml` to `files`, with the project file last. This plugin has its own placeholder key; it doesn't use oh-my-pi's key.

## How it works

- Redacts message text, reasoning, and string values in tool-call JSON. JSON keys, tool names, and call IDs are left alone.
- Handles streaming, prepared agent calls, session calls, and compaction/title requests through the same LLM runtime.
- Redacts a copy of the final provider request. Original messages, frozen requests, and cancellation signals aren't changed.
- Discards stale replay signatures when the signed assistant content changes.
- Restores a copy of tool arguments before they're saved to history and passed to validation, guards, scheduling, and execution. This also covers parallel tool calls.
- Rebuilds pattern-based placeholders from saved history when a session resumes, including events hidden by compaction. Literal values still need an available source.
- Tells the model to copy placeholders exactly.

Placeholders use HMAC-SHA256 with a per-install key stored at `$DSH_HOME/dsh-secrets-omp/secret-placeholder.key`. The file is created atomically with permissions `0600`. Each placeholder has 12 uppercase base-36 characters, with optional suffixes for casing. Values are hashed as-is, so different-case secrets have different placeholders. Friendly labels are removed if they would reveal a known secret, including one found in a later message.

Keep the key private and preserve it across restarts. The key itself is hidden one-way and can't be restored through a placeholder. A corrupt or unreadable key stops plugin activation; it isn't silently replaced.

A placeholder can't recover a missing original value. After a restart, old arbitrary secrets need to be available in the environment, dotenv files, or rules again. Raw history alone isn't enough, though values matching a known pattern can be rediscovered there. Keep an explicit rule for an old value or start a new session.

Rotate any credentials already sent to a model. The plugin can't undo those requests.

Harness doesn't have public hooks for rewriting these inputs, so the plugin wraps `LlmRuntime.forAdapter`, `ToolRuntime.createExecution`, and `ToolRuntime.executionMode`. Once active, it blocks model requests if those wrappers are missing or replaced. Only Harness 0.2.0-rc.2 is supported; check for activation errors after loading the plugin.

## Limits

- Static system prompts and tool definitions aren't redacted. Don't put credentials in them.
- Binary attachments, encrypted or opaque replay data, routing/auth metadata, tool names, IDs, and JSON keys aren't scanned as text.
- Local logs, files, subprocess environments, and other plugins can still contain real values.
- Encoded or transformed secrets, and values split across content blocks, may not match. Add rules for the formats you use.
- The model can use a secret without seeing it. A tool call can still send the restored value elsewhere, so approvals and sandboxing still matter.
- Turning the plugin off removes protection. Don't ignore activation errors.

## Development

```sh
bun install
bun run typecheck
bun test
bun pm pack --destination release
```

Tests use synthetic credentials and local HTTP/SSE servers, not cloud models. They cover matching and restoration, source changes, key handling, request ownership, and cancellation. The AgentLoop/DeepSeekAdapter test reads a fixture `.env`, edits a credential through a placeholder, and checks the outgoing HTTP requests and guard decisions.

### Web and oh-my-pi audits

The Web audit needs an installed Harness 0.2.0-rc.2 runtime. The oh-my-pi audits need a source tree with `src/secrets/index.ts` and its dependencies installed. Set `OMP_ROOT` to that package directory. The source audit also needs Node on `PATH`.

```sh
bun run build
bun tests/web-audit/runner.ts
DSH_WEB_AUDIT=1 bun test

OMP_ROOT=/path/to/oh-my-pi/packages/coding-agent
env -i PATH="$PATH" bun run --no-env-file tests/parity-sources/run.mjs --omp-root="$OMP_ROOT"
bun tests/parity-transform/run.mjs --omp-root "$OMP_ROOT" --strict
```

The Web runner uses the macOS Desktop installation shown above by default. For another rc.2 installation, pass `nativeLauncher` and `nativePeers` in code. It starts a temporary Host with its own home and profile, using the real DeepSeekAdapter against a local test server. It doesn't install packages or read your credentials, rules, key, or `.env`.

Web cases check file reads and edits, outgoing HTTP requests, placeholder restoration, and guards. A tool-output case must produce the expected stdout and saved history to pass. Cases for known limits check that those limits are still present; they don't claim the excluded values were hidden.

Reports separate matches, intentional differences, and reference errors. A reference timeout isn't a passing comparison. Run the checks against the versions you're using.

### Differences from oh-my-pi

- oh-my-pi reads `process.env`; this plugin also reads the session's dotenv files. Bun can load dotenv at startup, but standalone builds may not.
- This plugin shares learned values across Host sessions and refreshes file sources on each request. oh-my-pi builds its sources per session.
- Rule precedence, one-way overlap, and handling of invalid keys and replacements can differ. Don't assume identical behavior across upstream versions.
- Harness stores tool arguments as JSON strings and uses different message metadata. There's no matching hook for oh-my-pi's assistant-display restoration, so assistant replies can still show placeholders.

To run one case, use `--case NAME` for Web and transform audits, or `--case=substring` for source audits. The source runner's `--detail` option shows fixture data. The transform runner supports `--plugin-only` and `--reference-results`; recorded results must match the case revision.

## References

- [Secret obfuscation contract](https://github.com/can1357/oh-my-pi/blob/main/docs/secrets.md)
- [Provider-context and tool-argument transforms](https://github.com/can1357/oh-my-pi/blob/main/packages/coding-agent/src/secrets/message-transform.ts)
- [Keyed placeholders and collision checks](https://github.com/can1357/oh-my-pi/blob/main/packages/coding-agent/src/secrets/placeholder.ts)
- [Credential patterns](https://github.com/can1357/oh-my-pi/blob/main/packages/coding-agent/src/secrets/patterns.ts)
