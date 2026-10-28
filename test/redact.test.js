'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const http = require('node:http');
const { redact, createRedactor, REDACTED } = require('../src/index.js');

// Generous ceiling: these tests catch a hang or exponential blow-up, not slowness,
// so a slow CI machine must not fail them. The bugs they guard took seconds to forever.
const HANG_MS = 10000;

describe('circular references', () => {
  test('does not throw on a self-referencing object', () => {
    const obj = { name: 'a' };
    obj.self = obj;
    assert.doesNotThrow(() => redact(obj));
  });
  test('replaces the cycle with "[Circular]" and keeps other fields', () => {
    const obj = { name: 'a', password: 'hunter2' };
    obj.self = obj;
    assert.deepEqual(redact(obj), { name: 'a', password: REDACTED, self: '[Circular]' });
  });
  test('handles indirect cycles (a -> b -> a)', () => {
    const a = { name: 'a' };
    const b = { name: 'b', parent: a };
    a.child = b;
    assert.deepEqual(redact(a), { name: 'a', child: { name: 'b', parent: '[Circular]' } });
  });
  test('a shared (non-circular) reference is not marked circular', () => {
    const shared = { v: 1 };
    assert.deepEqual(redact({ x: shared, y: shared }), { x: { v: 1 }, y: { v: 1 } });
  });
  test('a cycle through an array is caught', () => {
    const arr = [];
    arr.push({ list: arr });
    assert.deepEqual(redact(arr), [{ list: '[Circular]' }]);
  });
});

describe('Date', () => {
  test('preserves a Date with the same time', () => {
    const when = new Date('2026-01-02T03:04:05.000Z');
    const out = redact({ when });
    assert.ok(out.when instanceof Date);
    assert.equal(out.when.getTime(), when.getTime());
  });
  test('a Date under a sensitive key is still redacted', () => {
    assert.deepEqual(redact({ tokenExpiry: new Date(0) }), { tokenExpiry: REDACTED });
  });
  test('a Date from another realm is still preserved', () => {
    const d = vm.runInNewContext('new Date(0)');
    assert.equal(redact({ d }).d, d);
  });
});

describe('Buffer and typed arrays', () => {
  test('preserves a Buffer', () => {
    const buf = Buffer.from('abc');
    const out = redact({ buf });
    assert.ok(Buffer.isBuffer(out.buf));
    assert.ok(out.buf.equals(buf));
  });
  test('a Buffer under a sensitive key is redacted', () => {
    assert.deepEqual(redact({ secret: Buffer.from('shh') }), { secret: REDACTED });
  });
  test('preserves a typed array', () => {
    const t = new Uint8Array([1, 2, 3]);
    assert.equal(redact({ t }).t, t);
  });
});

describe('class instances and getters', () => {
  class User {
    constructor() { this.name = 'alice'; this.apiKey = 'k-123'; this.password = 'p'; }
    get token() { return 'tok-from-getter'; }
  }
  test('redacts sensitive own fields and keeps the rest', () => {
    const out = redact(new User());
    assert.equal(out.name, 'alice');
    assert.equal(out.apiKey, REDACTED);
    assert.equal(out.password, REDACTED);
  });
  test('a prototype getter secret never appears in the output', () => {
    assert.ok(!JSON.stringify(redact(new User())).includes('tok-from-getter'));
  });
  test('does not mutate the original instance', () => {
    const u = new User();
    redact(u);
    assert.equal(u.apiKey, 'k-123');
  });
  test('Map and Set do not crash', () => {
    assert.doesNotThrow(() => redact({ m: new Map([['password', 'x']]), s: new Set(['x']) }));
  });
  test('Map entries do not leak', () => {
    assert.ok(!JSON.stringify(redact({ m: new Map([['k', 'topsecretvalue']]) })).includes('topsecretvalue'));
  });
});

describe('sensitive check before read', () => {
  test('a sensitive key whose getter throws is redacted and the getter never runs', () => {
    let called = false;
    const obj = {};
    Object.defineProperty(obj, 'password', { enumerable: true, get() { called = true; throw new Error('x'); } });
    assert.deepEqual(redact(obj), { password: REDACTED });
    assert.equal(called, false);
  });
  test('a non-sensitive key whose getter throws gives "[Unreadable]"', () => {
    const obj = { name: 'x' };
    Object.defineProperty(obj, 'boom', { enumerable: true, get() { throw new Error('getter exploded'); } });
    const out = redact(obj);
    assert.equal(out.boom, '[Unreadable]');
    assert.ok(!JSON.stringify(out).includes('getter exploded'));
  });
});

describe('sensitive key matching', () => {
  for (const key of ['password', 'user_password', 'accessToken', 'access_token', 'X-API-KEY', 'APIKey', 'clientSecret', 'Authorization', 'sessionId', 'privateKey', 'Cookie']) {
    test(`redacts "${key}"`, () => {
      assert.deepEqual(redact({ [key]: 'value' }), { [key]: REDACTED });
    });
  }
  test('does not redact harmless keys', () => {
    const input = { username: 'a', tokens_used: 5, keyboard: 'k', author: 'x', primaryKey: 1 };
    assert.deepEqual(redact(input), input);
  });
  test('redacts keys in nested objects and arrays of objects, arrays stay arrays', () => {
    const out = redact({ users: [{ name: 'a', user_password: 'p' }] });
    assert.ok(Array.isArray(out.users));
    assert.deepEqual(out, { users: [{ name: 'a', user_password: REDACTED }] });
  });
  test('a top-level array stays an array', () => {
    assert.ok(Array.isArray(redact([{ token: 'x' }])));
  });
});

describe('non-object input', () => {
  test('null, undefined, string, number return unchanged', () => {
    assert.equal(redact(null), null);
    assert.equal(redact(undefined), undefined);
    assert.equal(redact('hello'), 'hello');
    assert.equal(redact(5), 5);
  });
});

describe('__proto__ safety', () => {
  test('an own "__proto__" key does not change the output prototype', () => {
    const out = redact(JSON.parse('{"__proto__":{"polluted":true},"a":1}'));
    assert.equal(Object.getPrototypeOf(out), Object.prototype);
    assert.equal(({}).polluted, undefined);
    assert.equal(out.polluted, undefined);
    assert.equal(out.a, 1);
  });
});

describe('Error objects', () => {
  test('keeps name, message and stack', () => {
    const out = redact({ err: new TypeError('bad thing') });
    assert.equal(out.err.name, 'TypeError');
    assert.equal(out.err.message, 'bad thing');
    assert.match(out.err.stack, /bad thing/);
  });
  test('redacts sensitive data on own props (axios-style)', () => {
    const e = new Error('Request failed');
    e.config = { headers: { Authorization: 'Bearer abc123' }, url: '/x' };
    const out = redact(e);
    assert.equal(out.config.headers.Authorization, REDACTED);
    assert.equal(out.config.url, '/x');
  });
  test('walks cause and survives a cyclic cause', () => {
    const inner = new Error('inner');
    inner.token = 't';
    const outer = new Error('outer', { cause: inner });
    assert.equal(redact(outer).cause.token, REDACTED);
    const loop = new Error('loop');
    loop.cause = loop;
    assert.equal(redact(loop).cause, '[Circular]');
  });
  test('an Error under a sensitive key is redacted', () => {
    assert.deepEqual(redact({ token: new Error('x') }), { token: REDACTED });
  });
});

describe('spoofing', () => {
  test('a fake Symbol.toStringTag does not bypass redaction', () => {
    const fake = { password: 'x', [Symbol.toStringTag]: 'Date' };
    assert.equal(redact(fake).password, REDACTED);
  });
});

describe('hostile and runaway input never crashes', () => {
  test('very deep nesting is capped, not a RangeError', () => {
    let o = { v: 1 };
    for (let i = 0; i < 3500; i++) o = { a: o };
    let out;
    assert.doesNotThrow(() => { out = redact(o); });
    assert.ok(JSON.stringify(out).includes('[MaxDepth]'));
  });
  test('revoked Proxy', () => {
    const { proxy, revoke } = Proxy.revocable({}, {});
    revoke();
    assert.doesNotThrow(() => redact({ p: proxy }));
    assert.equal(redact({ p: proxy }).p, '[Unreadable]');
  });
  test('Proxy with throwing ownKeys trap', () => {
    const p = new Proxy({}, { ownKeys() { throw new Error('no'); } });
    assert.equal(redact({ p }).p, '[Unreadable]');
  });
  test('infinite lazy getter is capped', () => {
    const make = () => ({ get next() { return make(); } });
    assert.doesNotThrow(() => redact(make()));
  });
  test('a 100k-char all-caps key is processed in linear time (no ReDoS)', () => {
    const key = 'A'.repeat(100000);
    const t = Date.now();
    redact({ [key]: 1 });
    assert.ok(Date.now() - t < HANG_MS, 'took too long');
  });
});

describe('extra sensitive keys', () => {
  for (const key of ['password2', 'db_password1', 'cookies', 'connect.sid', 'sid', 'pwd', 'passphrase', 'jwt', 'session', 'cardNumber']) {
    test(`redacts "${key}"`, () => {
      assert.deepEqual(redact({ [key]: 'v' }), { [key]: REDACTED });
    });
  }
  test('a session object is masked as a whole', () => {
    assert.deepEqual(redact({ session: { id: 'abc' } }), { session: REDACTED });
  });
  test('whole-word matching still spares passenger, bypass, author', () => {
    const input = { passenger: 1, bypass: 2, author: 3 };
    assert.deepEqual(redact(input), input);
  });
});

describe('functions', () => {
  test('a function with own secret props is not passed through', () => {
    const fn = () => {};
    fn.note = 'topsecretvalue';
    const out = redact({ fn });
    assert.equal(out.fn, '[Function]');
    assert.ok(!JSON.stringify(out).includes('topsecretvalue'));
  });
});

describe('bounded work', () => {
  test('exponential lazy getters are truncated, not an endless loop', () => {
    const make = () => ({ get a() { return make(); }, get b() { return make(); } });
    const t = Date.now();
    const out = redact(make());
    assert.ok(Date.now() - t < HANG_MS, 'took too long');
    assert.ok(JSON.stringify(out).includes('[Truncated]'));
  });
  test('a 22-level diamond graph returns quickly', () => {
    let n = { v: 1 };
    for (let i = 0; i < 22; i++) n = { l: n, r: n };
    const t = Date.now();
    redact(n);
    assert.ok(Date.now() - t < HANG_MS, 'took too long');
  });
  test('primitives do not use the object budget (array cap disabled)', () => {
    const arr = new Array(50000).fill(1);
    assert.equal(redact(arr, { maxArrayLength: Infinity }).length, 50000);
  });
});

describe('array __proto__ key', () => {
  test('an own "__proto__" key on an array does not change the output prototype', () => {
    const arr = [1];
    Object.defineProperty(arr, '__proto__', { value: { evil: 'x' }, enumerable: true, configurable: true, writable: true });
    const out = redact(arr);
    assert.equal(Object.getPrototypeOf(out), Array.prototype);
    assert.equal(out.evil, undefined);
  });
});

describe('HTTP request objects inside errors', () => {
  test('a real ClientRequest does not leak raw header text', () => {
    const req = http.request({ host: '127.0.0.1', port: 1, headers: { Authorization: 'Bearer S3CRET', Cookie: 'sid=S3CRET' } });
    req.on('error', () => {});
    req.end();
    const err = new Error('Request failed');
    err.request = req;
    const text = JSON.stringify(redact(err));
    req.destroy();
    assert.ok(!text.includes('S3CRET'), 'leaked: ' + text.match(/.{40}S3CRET.{20}/));
  });
  test('rawHeaders and _header are masked whole', () => {
    assert.deepEqual(redact({ rawHeaders: ['Authorization', 'x'], _header: 'Cookie: a' }), { rawHeaders: REDACTED, _header: REDACTED });
  });
});

describe('more sensitive words', () => {
  for (const key of ['sessions', 'x-auth', 'x-access-key', 'aws_access_key', 'pin', '1password_vault']) {
    test(`redacts "${key}"`, () => {
      assert.deepEqual(redact({ [key]: 'v' }), { [key]: REDACTED });
    });
  }
});

describe('options: keys and allow', () => {
  test('keys adds sensitive words, matched like the built-ins', () => {
    const out = redact({ ssnLast4: '1234', tenant_ssn_last4: '1', employeeNumber: 7, other: 1 }, { keys: ['ssnLast4', 'employee_number'] });
    assert.deepEqual(out, { ssnLast4: REDACTED, tenant_ssn_last4: REDACTED, employeeNumber: REDACTED, other: 1 });
  });
  test('allow is an exact whole-key match that wins over built-ins', () => {
    const out = redact({ session: 'kept', sessionId: 's', token: 't' }, { allow: ['session'] });
    assert.deepEqual(out, { session: 'kept', sessionId: REDACTED, token: REDACTED });
  });
  test('allow wins over keys', () => {
    assert.deepEqual(redact({ internalId: 1 }, { keys: ['internalId'], allow: ['internal_id'] }), { internalId: 1 });
  });
  test('custom keys are not exempted by metadata suffixes', () => {
    assert.deepEqual(redact({ vaultName: 'x' }, { keys: ['vaultName'] }), { vaultName: REDACTED });
  });
  test('createRedactor returns a reusable function', () => {
    const r = createRedactor({ keys: ['tenantSecretRef'] });
    assert.deepEqual(r({ tenantSecretRef: 'a', password: 'b', ok: 1 }), { tenantSecretRef: REDACTED, password: REDACTED, ok: 1 });
    assert.deepEqual(r({ ok: 2 }), { ok: 2 });
  });
  test('options are optional and redact() without them is unchanged', () => {
    assert.deepEqual(redact({ password: 'p' }, {}), { password: REDACTED });
  });
  test('invalid options throw a TypeError at setup, never silently', () => {
    assert.throws(() => createRedactor({ keys: 'password' }), TypeError);
    assert.throws(() => createRedactor({ allow: [1] }), TypeError);
    assert.throws(() => createRedactor({ maxDepth: -1 }), TypeError);
    assert.throws(() => createRedactor({ maxArrayLength: 1.5 }), TypeError);
    assert.throws(() => redact({}, 'keys'), TypeError);
  });
});

describe('limits', () => {
  test('arrays keep their first 100 items and say how many were dropped', () => {
    const out = redact({ rows: Array.from({ length: 15000 }, (_, i) => ({ id: i })) });
    assert.equal(out.rows.length, 101);
    assert.deepEqual(out.rows[99], { id: 99 });
    assert.equal(out.rows[100], '[Truncated: 14900 more items]');
  });
  test('object fields after a big array survive (per-array cap, not one shared budget)', () => {
    const out = redact({ data: Array.from({ length: 12000 }, (_, i) => ({ i })), status: { code: 500 } });
    assert.deepEqual(out.status, { code: 500 });
  });
  test('maxArrayLength, maxDepth and maxNodes are configurable', () => {
    assert.equal(redact([1, 2, 3], { maxArrayLength: 1 })[1], '[Truncated: 2 more items]');
    assert.deepEqual(redact({ a: { b: { c: 1 } } }, { maxDepth: 1 }), { a: { b: '[MaxDepth]' } });
    assert.deepEqual(redact({ a: {}, b: {} }, { maxNodes: 2 }), { a: {}, b: '[Truncated]' });
  });
  test('the cap does not skip a sensitive non-index key on an array', () => {
    const arr = new Array(500).fill(0);
    arr.token = 't';
    assert.equal(redact(arr).token, REDACTED);
  });
});

describe('credentials inside connection strings', () => {
  const cases = [
    ['postgres://user:hunter2@db:5432/app', `postgres://user:${REDACTED}@db:5432/app`],
    ['redis://:hunter2@cache:6379', `redis://:${REDACTED}@cache:6379`],
    ['mongodb+srv://u:p@ss@h1,h2/db', `mongodb+srv://u:${REDACTED}@h1,h2/db`],
    ['https://user@example.com/x', 'https://user@example.com/x'],
    ['https://example.com/@me', 'https://example.com/@me'],
    ['see postgres://u:p@h', 'see postgres://u:p@h'],
  ];
  for (const [input, expected] of cases) {
    test(`${input}`, () => {
      assert.deepEqual(redact({ databaseUrl: input }), { databaseUrl: expected });
    });
  }
  test('strings in arrays are checked too', () => {
    assert.deepEqual(redact(['amqp://a:b@q']), [`amqp://a:${REDACTED}@q`]);
  });
  test('a long hostile string is processed in linear time', () => {
    const s = 'x://' + 'a:'.repeat(100000) + '@';
    const t = Date.now();
    redact({ s });
    assert.ok(Date.now() - t < HANG_MS, 'took too long');
  });
});

describe('built-in words added for v1', () => {
  for (const key of ['encryptionKey', 'signingKey', 'hmac_key', 'masterKey', 'sshKey', 'licenseKey', 'sentryDsn', 'dsn',
    'signature', 'auth', 'mfaCode', 'verification_code', 'resetCode', 'creditCard', 'iban', 'accountNumber', 'connectionString', 'cvc']) {
    test(`redacts "${key}"`, () => {
      assert.deepEqual(redact({ [key]: 'v' }), { [key]: REDACTED });
    });
  }
  test('bare key, primaryKey, publicKey, authMethod stay readable', () => {
    const input = { key: 'k', primaryKey: 1, publicKey: 'pk', cacheKey: 'c', authMethod: 'oauth', code: 'ECONNRESET' };
    assert.deepEqual(redact(input), input);
  });
});

describe('metadata suffixes are not masked', () => {
  test('keys that describe a secret are kept', () => {
    const input = { sessionTimeout: 30, session_count: 2, tokenLimit: 5, token_count: 3, tokenType: 'Bearer', passwordPolicy: { min: 12 },
      passwordStrength: 'weak', passwordLastChanged: 'x', privateKeyPath: '/k', csrfTokenHeaderName: 'x-csrf', cookieConsent: true, signatureAlgorithm: 'RS256' };
    assert.deepEqual(redact(input), input);
  });
  test('keys that hold a secret are still masked', () => {
    const out = redact({ sessionId: 's', tokenExpiry: 'd', passwordHash: 'h', sessionStore: {}, apiKeyId: 'k', passwordConfirm: 'p' });
    assert.deepEqual(out, { sessionId: REDACTED, tokenExpiry: REDACTED, passwordHash: REDACTED, sessionStore: REDACTED, apiKeyId: REDACTED, passwordConfirm: REDACTED });
  });
});

describe('module formats', () => {
  test('ESM named imports work', async () => {
    const mod = await import('../src/index.js');
    assert.equal(typeof mod.redact, 'function');
    assert.equal(typeof mod.createRedactor, 'function');
    assert.equal(mod.REDACTED, REDACTED);
  });
});
