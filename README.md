# keyblob

Keep your secrets out of your logs, and out of git.

keyblob does two small jobs. `redact()` gives you a copy of any object with the passwords, tokens and keys masked, so you can log it without worrying. `keyblob scan` looks through your files before you commit and stops you if you're about to push an API key to GitHub.

No dependencies. Node 18 or newer.

```sh
npm install keyblob
```

## Logging safely with redact()

```js
const { redact } = require('keyblob');   // or: import { redact } from 'keyblob'

console.log(redact({
  user: 'alice',
  password: 'hunter2',
  headers: { authorization: 'Bearer abc' },
}));
// { user: 'alice', password: '[REDACTED]', headers: { authorization: '[REDACTED]' } }
```

Your original object is left alone. Only the copy you log is masked, so the rest of your app keeps working with the real values.

### Why bother

Logs get read by more people than your database does. They get shipped to other services, pasted into Slack, and kept for months. A stray `console.log(req)` or `logger.error(err)` is usually how a session cookie or an API key ends up somewhere it shouldn't. Wrap what you log in `redact()` and that mostly stops happening.

One tip: log the parts of a request you care about, like `redact({ method: req.method, url: req.url, headers: req.headers })`, rather than the raw Node `req` object. `req.headers` is a getter on the prototype, so it gets dropped if you pass `req` itself. The raw header fields are masked whole in that case, so nothing leaks, but you lose the headers.

### How it decides what to mask

It goes by the key name, not the value. Each key is split into words (on camelCase, `_`, `-`, spaces and digits), and if one word, or two neighbouring words joined together, is on the list, the value is masked. The list covers:

- passwords and secrets: `password`, `pwd`, `pass`, `passphrase`, `secret`, `credential`
- tokens and auth: `token`, `jwt`, `bearer`, `authorization`, `signature`, `otp`, `pin`, MFA and reset codes, and `auth` when it's the whole key
- keys: `apikey`, `privatekey`, `accesskey`, `signingkey`, `encryptionkey`, `sshkey` and a few more like them
- sessions and cookies: `session`, `sessionid`, `sid`, `cookie`
- payment and identity: `cardnumber`, `cvv`, `iban`, `accountnumber`, `ssn`
- connection info: `connectionstring`, `dsn`

So `accessToken`, `user_password`, `X-API-KEY` and `password2` get masked, while `tokens_used`, `keyboard`, `author` and `primaryKey` don't.

Keys that only describe a secret are kept, because they're useful when you're debugging: `passwordPolicy`, `sessionTimeout`, `tokenType`, `privateKeyPath`. That works when the last word is one of `count`, `limit`, `timeout`, `ttl`, `length`, `policy`, `strength`, `type`, `enabled`, `required`, `changed`, `at`, `name`, `path`, `consent` or `algorithm`.

There's one check on values. A string that starts with `scheme://user:password@` gets its password masked, so `postgres://app:[REDACTED]@db:5432/prod` still tells you which database you were talking to.

### Tuning it

The defaults won't fit every codebase. If you have your own sensitive fields, or a harmless one keeps getting masked, build your own redactor:

```js
const { createRedactor } = require('keyblob');

const redact = createRedactor({
  keys: ['ssnLast4', 'employeeNumber'],  // extra words to treat as sensitive
  allow: ['session'],                     // exact keys to never mask (sessionId is still masked)
});

logger.info(redact(payload));
```

| Option | Default | What it does |
|---|---|---|
| `keys` | `[]` | Extra sensitive words, matched the same way as the built-in ones. `'ssnLast4'` also catches `tenant_ssn_last4`. |
| `allow` | `[]` | Keys that are never masked. Exact match, ignoring case, `_` and `-`. Beats every other rule. |
| `maxDepth` | `100` | Anything nested deeper becomes `'[MaxDepth]'`. |
| `maxArrayLength` | `100` | Items kept per array. The rest turn into one `'[Truncated: N more items]'` entry, like `console.log` does. |
| `maxNodes` | `10000` | Objects visited per call. After that you get `'[Truncated]'`. |

The limits take a non-negative integer or `Infinity`. A bad option throws a `TypeError` when you create the redactor, never later while you're logging.

You can also pass options straight to `redact(input, options)`, but `createRedactor` is faster if you log a lot, because it remembers which keys it has already checked.

### Messy input

A logger shouldn't be the thing that crashes your app, so `redact()` never throws. Some details:

- Circular references come out as `'[Circular]'`. Objects that are shared but not circular are copied normally.
- `Date`, `RegExp`, `Buffer` and typed arrays are passed through as they are. Class instances are copied field by field.
- Functions become `'[Function]'`, since they can carry properties too.
- Errors keep their `name`, `message`, `stack` and `cause`, and their extra fields are masked like anything else. That covers things like `err.config.headers.Authorization` on axios errors.
- A getter that throws, or a hostile Proxy, becomes `'[Unreadable]'`. The getter on a sensitive key is never even called.
- Huge or deeply nested input is cut off by the limits above, so it always returns quickly.

## Keeping secrets out of git with keyblob scan

`redact()` covers your logs while the app is running. `keyblob scan` covers the other way secrets usually leak, which is being committed and pushed.

```sh
npm install --save-dev keyblob
npx keyblob hook install   # check what you're committing, every time you commit
npx keyblob scan           # check every file in the project, whenever you like
```

If you try to commit a key, the commit stops and you see where it is. The secret itself is never printed in full:

```
keyblob: found 1 possible secret

  index.js:10:23  google-oauth-client-secret  GOCS… (35 chars)
```

The fix is almost always the same. Move the value into a `.env` file, add `.env` to your `.gitignore`, and read it with `process.env.NAME` (Node can load the file for you with `node --env-file=.env app.js`).

If a real key has already been pushed, change it with whoever issued it. Deleting it in a new commit doesn't remove it from the git history, and bots scan public repos for keys within minutes.

### What it looks for

- Keys it recognises by their format, whatever your variable is called: AWS, GitHub, GitLab, Google (API keys and OAuth client secrets), OpenAI, Anthropic, Stripe live keys, Slack, npm tokens, JWTs, PEM private keys, and passwords inside `user:pass@host` URLs.
- Values typed straight into code under a sensitive name, like `clientSecret = "..."` or `"db_password": "..."`, using the same word rules as `redact()`. In `.env`, YAML, INI, TOML and `.npmrc` files it also checks unquoted `API_TOKEN=...` lines.
- Files that shouldn't be in a repo at all: `.env` and `.env.local` (but not `.env.example`), `id_rsa`, `*.key`, `*.p12`, `*.pfx`.

It skips obvious placeholders such as `your-key-here`, `${API_TOKEN}`, `<token>` and `****`, as well as `process.env` lookups and ordinary sentences.

### False alarms

Add a comment containing `keyblob-ignore` to the line, or list files and folders in a `.keyblobignore` file at the root of your project. It uses the same pattern style as `.gitignore`:

```
# fake keys used in tests
test/fixtures/
*.snap
```

Inside a git repo the scan also respects `.gitignore`, so a `.env` that's properly ignored won't be reported.

### Running it in CI

Anyone can skip a local hook with `git commit --no-verify`, so it's worth running the scan in CI as well:

```yaml
- run: npx keyblob scan
```

It exits with `1` when it finds something, `0` when the project is clean and `2` if the command was used wrong. Add `--json` if you want to process the results yourself. You can also call the scanner from code with `require('keyblob/scan')`, which gives you `scanText()` and `scanFileName()`.

### What it can't do

No tool can hide a secret from someone who runs your code. Anything your app sends to the browser, like frontend JavaScript or a mobile app bundle, can be read by the person using it, however you encode it. If the browser needs to talk to a paid API, have it go through your own server and keep the key there.

## Known limits

I'd rather you know these up front:

- `redact()` doesn't read free text. A secret inside a message, like `"login failed for Bearer abc123"` or inside `err.message`, isn't caught. Only key names and the connection-string check are.
- Name matching is a heuristic, in both `redact()` and `scan`. It will miss some secrets and occasionally mask something harmless. Unusual names like `myVendorRef`, or keys with no word breaks like `myapikeyvalue`, are missed. A bare `key` isn't masked, because `primaryKey`, `cacheKey` and `sortKey` are everywhere. Use `keys` to add your own.
- Map and Set contents come out as `{}`. Nothing leaks, but you lose that data from the log.
- Symbol keys and non-enumerable properties aren't copied, except for the Error fields listed above.
- It's built for Node. It should work under Bun and Deno's Node compatibility but isn't tested there, and it won't run in the browser.
- None of this replaces keeping secrets out of your code in the first place. It's a safety net.

## Should I use this or pino's redact?

If you already use pino, its built-in `redact` option is great. It's fast and exact, because you list the precise paths to mask (`req.headers.authorization`). keyblob is for when you'd rather not maintain that list, want something that works with any logger, or log messy objects like errors and class instances. The cost is that matching by name is a guess, which is why `keys` and `allow` exist.

## API

- `redact(input, options?)` returns the masked copy. It's typed `unknown` in TypeScript because the shape can differ from the input.
- `createRedactor(options?)` returns a reusable `(input) => unknown` function.
- `REDACTED` is the mask string, `'[REDACTED]'`.
- `require('keyblob/scan')` gives you `scanText(text, { filename })` and `scanFileName(filename)`.

TypeScript types are included for everything.

## License

MIT
