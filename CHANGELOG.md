# Changelog

All notable changes to this project are documented here. This project follows [Semantic Versioning](https://semver.org/).

## 1.1.1

- README rewritten in plainer language. No code changes.

## 1.1.0

- New `keyblob` CLI. `keyblob scan` finds secrets in files git would commit; `--staged` checks only the next commit; `--json` for CI.
- `keyblob hook install` / `uninstall` adds a git pre-commit hook that blocks commits containing secrets. An existing non-keyblob hook is never overwritten.
- Detects known token formats by value (AWS, GitHub, GitLab, Google, OpenAI, Anthropic, Stripe, Slack, npm, JWT, PEM private keys, URL passwords), hardcoded values under sensitive names (same rules as `redact()`), and committed `.env` / private key files.
- Findings never print the full secret. `keyblob-ignore` on a line or a `.keyblobignore` file suppresses false alarms.
- New `keyblob/scan` entry point with `scanText()` and `scanFileName()`, with TypeScript types.

## 1.0.0

First public release.

- `redact(input, options?)` returns a redacted deep copy; `createRedactor(options)` builds a reusable one; `REDACTED` is the mask.
- Options: `keys` (extra sensitive words), `allow` (exact keys never masked), `maxDepth` (100), `maxNodes` (10,000), `maxArrayLength` (100).
- Key matching by whole words after splitting camelCase, `_`, `-`, digits; adjacent-word pairs (`X-API-KEY` → `apikey`); built-in list covers passwords, tokens, API/private/signing/encryption keys, cookies, sessions, payment fields, MFA codes, DSNs and connection strings.
- Keys that only describe a secret (`passwordPolicy`, `sessionTimeout`, `tokenType`) are kept.
- Passwords inside connection-string values (`postgres://user:pass@host`) are masked; other strings are not scanned.
- Never throws and never hangs: cycles, throwing getters, hostile Proxies, deep nesting and exponential graphs are bounded.
- Errors keep `name`, `message`, `stack`, `cause`; raw HTTP internals (`_header`, `rawHeaders`, `outputData`) are masked.
- TypeScript types included; works from CommonJS and ESM.
