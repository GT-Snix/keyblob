# keyblob

Return a redacted deep copy of any object so it is safe to log. Zero dependencies, Node.js >= 18.

```js
const { redact } = require('keyblob');   // or: import { redact } from 'keyblob';

console.log(redact({ user: 'alice', password: 'hunter2', headers: { authorization: 'Bearer abc' } }));
// { user: 'alice', password: '[REDACTED]', headers: { authorization: '[REDACTED]' } }
```

Your original object is never modified. Only the copy you log is masked.

```sh
npm install keyblob
```

## Why

Logs are read by more people, copied to more tools and kept longer than your database. `console.log(req)` or `logger.error(err)` is how API keys, passwords and session cookies end up in them. Call `redact()` right before logging, on the data you choose to log, e.g. `redact({ method: req.method, url: req.url, headers: req.headers })`.

A raw Node `req` is not a good input: `req.headers` is a prototype getter and is dropped. The raw header fields (`rawHeaders`, `_header`, `outputData` and similar) are masked whole, so nothing leaks, but you lose the headers.

## How it decides

It looks at **key names**, not values. Keys are split into words on camelCase, `_`, `-`, spaces and digits, and a key is sensitive if one word, or two adjacent words joined, is on the list:

- **Passwords and secrets:** `password`, `pwd`, `pass`, `passphrase`, `secret`, `credential(s)`
- **Tokens and auth:** `token`, `jwt`, `bearer`, `authorization`, `auth` (as the whole key), `x-auth`, `signature`, `otp`, `pin`, MFA / verification / reset codes
- **Keys:** `apikey`, `privatekey`, `accesskey`, `encryptionkey`, `signingkey`, `hmackey`, `masterkey`, `sshkey`, `licensekey`, `sessionkey`, `clientkey`
- **Sessions and cookies:** `session(s)`, `sessionid`, `sid`, `cookie(s)`
- **Payment and identity:** `cardnumber`, `creditcard`, `cvv`, `cvc`, `iban`, `accountnumber`, `ssn`
- **Connection info:** `connectionstring`, `dsn`

So `accessToken`, `user_password`, `X-API-KEY`, `APIKey`, `password2` and `stripeSigningKey` are caught, while `tokens_used`, `keyboard`, `author`, `primaryKey` and `publicKey` are left alone.

A key whose **last word only describes a secret** is kept: `passwordPolicy`, `sessionTimeout`, `tokenType`, `token_count`, `privateKeyPath`, `cookieConsent`. The full list of those words is `count`, `limit`, `timeout`, `ttl`, `length`, `policy`, `strength`, `type`, `enabled`, `required`, `changed`, `at`, `name`, `path`, `consent`, `algorithm`.

One value check: a string that **starts with** `scheme://user:password@` has the password masked (`postgres://app:[REDACTED]@db:5432/prod`). That covers `DATABASE_URL`-style config. Other strings are never scanned.

## Options

The defaults will be wrong for some of your keys. Tune them:

```js
const { createRedactor } = require('keyblob');

const redact = createRedactor({
  keys: ['ssnLast4', 'employeeNumber'],   // more sensitive words, matched like the built-ins
  allow: ['session'],                      // exact keys never masked (still masks sessionId)
});

logger.info(redact(payload));
```

| Option | Default | Meaning |
|---|---|---|
| `keys` | `[]` | Extra sensitive words. Case-insensitive; match a word, a run of adjacent words, or the whole key. `'ssnLast4'` also masks `tenant_ssn_last4`. |
| `allow` | `[]` | Keys that are never masked. Exact whole-key match, ignoring case, `_` and `-`. Wins over everything else. |
| `maxDepth` | `100` | Deeper nesting becomes `'[MaxDepth]'`. |
| `maxArrayLength` | `100` | Items kept per array; the rest becomes one `'[Truncated: N more items]'` entry. Same default as `console.log`. |
| `maxNodes` | `10000` | Objects visited per call; the rest becomes `'[Truncated]'`. |

Limits accept a non-negative integer or `Infinity`. Invalid options throw a `TypeError` when the redactor is built, never while logging.

`redact(input, options)` also accepts options directly. Prefer `createRedactor` and reuse the result: it keeps a warm cache of key decisions, which is what makes repeated logging fast.

## What it handles

- Circular references become `'[Circular]'`. Shared (non-circular) references are copied normally.
- Arrays stay arrays; `Date`, `RegExp`, `Buffer`, typed arrays and `ArrayBuffer` pass through as-is.
- Class instances are walked by their own enumerable fields.
- Functions become `'[Function]'` (they can carry secret props).
- `Error` objects keep `name`, `message`, `stack`, `cause` and own props, so `err.config.headers.Authorization` is masked. HTTP client errors (axios etc.) carry `err.request`; its raw header text is masked.
- A getter that throws, or a hostile Proxy, becomes `'[Unreadable]'`. A sensitive key's getter is never called.
- Work is bounded by the three limits above, so cyclic, exponential or huge inputs return quickly. **It never throws.**
- An own `__proto__` key (e.g. from `JSON.parse`) is treated as a normal key.
- `null`, `undefined`, numbers and other primitives are returned unchanged.

## Known limits

Read these. They are deliberate or accepted.

- **Free-text strings are not scanned.** A secret inside a message (`"login failed for Bearer abc123"`, or inside `err.message`) is not caught. Only keys, plus the connection-string check above.
- **Key matching is a heuristic.** It will miss some secrets and mask some harmless fields. Unknown names (`myVendorRef`) and keys without word boundaries (`myapikeyvalue`) are missed. Bare `key` is not masked, because `primaryKey`, `cacheKey` and `sortKey` are everywhere; add yours with `keys`. Plurals not in the list are missed on purpose so `tokens_used` stays readable.
- **Map and Set contents are dropped** (they come out as `{}`). Nothing leaks, but the data is lost from the log.
- **Pass-through values are not copied**, and own extra keys on them (e.g. `date.password`) are not checked.
- **Symbol keys and non-enumerable properties are omitted** from the copy (except Error fields).
- **Big inputs are truncated** by the limits. A getter that loops forever inside your own code cannot be interrupted.
- **Node.js only.** It uses `node:util`. Bun and Deno's Node compatibility should work but are not tested; browsers and edge runtimes without Node APIs are not supported.
- This reduces accidental leaks. It is not a substitute for keeping secrets out of logs at the source.

## Why not pino's `redact` / fast-redact?

If you already use pino, use its built-in redaction: it is fast, path-based and has no false positives, because you list the exact paths (`req.headers.authorization`). keyblob is for when you want logger-independent, name-based redaction that works without listing every path, plus safe handling of messy input (cycles, getters, Errors, Proxies, `__proto__`). The trade-off is that name matching is a heuristic; `keys` and `allow` let you correct it.

## API

- `redact(input, options?)` returns the redacted copy, typed `unknown` because its shape differs from the input.
- `createRedactor(options?)` returns a reusable `(input) => unknown` function.
- `REDACTED` is the mask constant (`'[REDACTED]'`).

TypeScript types are included.

## License

MIT
