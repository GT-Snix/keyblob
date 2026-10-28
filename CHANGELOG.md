# Changelog

All notable changes to this project are documented here. This project follows [Semantic Versioning](https://semver.org/).

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
