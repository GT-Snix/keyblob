'use strict';

// keyblob: return a redacted deep copy of any object so it is safe to log. Zero dependencies.
const { types } = require('node:util');

// Built-in sensitive words. A key matches if one of its words, or two adjacent
// words joined ("api"+"key"), is in this set.
const SENSITIVE = new Set([
  'password', 'passwords', 'passwd', 'pwd', 'pass', 'passphrase',
  'secret', 'secrets',
  'token',
  'apikey', 'apikeys',
  'authorization',
  'cookie', 'cookies',
  'jwt', 'otp', 'ssn', 'cvv', 'cvc', 'pin',
  'cardnumber', 'creditcard', 'iban', 'accountnumber',
  'credential', 'credentials',
  'privatekey', 'accesskey', 'encryptionkey', 'signingkey', 'hmackey', 'masterkey', 'sshkey',
  'licensekey', 'sessionkey', 'clientkey', 'authkey',
  'mfacode', 'verificationcode', 'resetcode', 'authcode',
  'connectionstring', 'dsn', 'signature',
  'bearer',
  'session', 'sessions', 'sessionid', 'sid',
  'xauth',
]);
// Keys that hold raw HTTP text or a flat name/value list. Whole-key match, because
// the secret is inside a string/array value that key-word matching cannot see.
const EXACT_SENSITIVE = new Set(['_header', 'rawheaders', '_rawheaders', 'rawtrailers', 'outputdata', 'auth']);
// A key whose LAST word is one of these describes a secret rather than holding one
// (passwordPolicy, sessionTimeout, tokenType), so built-in words do not mask it.
// Never applies to `keys` passed in options.
const METADATA_SUFFIX = new Set([
  'count', 'limit', 'timeout', 'ttl', 'length', 'policy', 'strength', 'type',
  'enabled', 'required', 'changed', 'at', 'name', 'path', 'consent', 'algorithm',
]);
const REDACTED = '[REDACTED]';
const DEFAULTS = { maxDepth: 100, maxNodes: 10000, maxArrayLength: 100 };
const CACHE_LIMIT = 10000; // per redactor; stops growing so hostile keys cannot fill memory

// "X-API-KEY" -> ['x','api','key'], "accessToken" -> ['access','token'], "APIKey" -> ['api','key']
function splitWords(key) {
  return key
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z])(?=[A-Z][a-z])/g, '$1 ')        // linear; the old ([A-Z]+)([A-Z][a-z]) was quadratic (ReDoS)
    .replace(/([a-zA-Z])([0-9])/g, '$1 $2')          // password2 -> password 2
    .replace(/([0-9])([a-zA-Z])/g, '$1 $2')          // 1password_vault -> 1 password_vault
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

// "X-API-KEY" -> "xapikey". Used for exact (whole-key) comparisons.
function normalize(key) {
  return key.toLowerCase().replace(/[^a-z0-9]/g, '');
}

// True if any run of 1..maxRun adjacent words, joined, is in the set.
function anyRun(words, set, maxRun) {
  for (let i = 0; i < words.length; i++) {
    let joined = '';
    for (let j = i; j < words.length && j < i + maxRun; j++) {
      joined += words[j];
      if (set.has(joined)) return true;
    }
  }
  return false;
}

function stringList(value, name) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || !value.every((v) => typeof v === 'string')) {
    throw new TypeError(`keyblob: options.${name} must be an array of strings`);
  }
  return value.map(normalize).filter(Boolean);
}

function limit(value, name) {
  if (value === undefined) return DEFAULTS[name];
  if (value !== Infinity && !(Number.isInteger(value) && value >= 0)) {
    throw new TypeError(`keyblob: options.${name} must be a non-negative integer or Infinity`);
  }
  return value;
}

// Returns a cached key -> boolean matcher for one set of options.
//   allow: exact keys that are never masked (wins over everything).
//   keys:  extra sensitive words, matched like the built-ins (word, adjacent words, or whole key).
function createMatcher(keys, allow) {
  const custom = new Set(keys);
  const allowed = new Set(allow);
  const cache = new Map();

  function decide(key) {
    const norm = normalize(key);
    if (allowed.has(norm)) return false;
    if (EXACT_SENSITIVE.has(key.toLowerCase()) || EXACT_SENSITIVE.has(norm)) return true;
    const words = splitWords(key);
    if (custom.size && (custom.has(norm) || anyRun(words, custom, 4))) return true;
    if (words.length > 1 && METADATA_SUFFIX.has(words[words.length - 1])) return false;
    return anyRun(words, SENSITIVE, 2);
  }

  return function isSensitiveKey(key) {
    let hit = cache.get(key);
    if (hit === undefined) {
      hit = decide(key);
      if (cache.size < CACHE_LIMIT && key.length <= 200) cache.set(key, hit);
    }
    return hit;
  };
}

// A connection string such as postgres://user:pass@host keeps everything except the
// password. Only strings that START with scheme:// are checked; free text is not scanned.
const URL_CREDENTIALS = /^([a-z][a-z0-9+.-]*:\/\/[^/\s:@]*:)[^/\s]*@/i;
function maskString(value) {
  if (value.indexOf('://') === -1 || value.indexOf('@') === -1) return value;
  return value.replace(URL_CREDENTIALS, `$1${REDACTED}@`);
}

// Value types returned as-is (by reference). util.types checks internal slots,
// so it cannot be spoofed with Symbol.toStringTag and also works across realms.
function isPassthroughValue(value) {
  return ArrayBuffer.isView(value)        // Buffer, typed arrays, DataView
    || types.isDate(value)
    || types.isRegExp(value)
    || types.isAnyArrayBuffer(value);
}

// Errors keep their useful fields. name/message/stack are not own-enumerable,
// so Object.keys alone would turn an Error into {}.
function keysOf(value) {
  const keys = Object.keys(value);
  if (!types.isNativeError(value)) return keys;
  const extra = ['name', 'message', 'stack'].filter((k) => !keys.includes(k));
  for (const k of ['cause', 'errors']) {
    if (!keys.includes(k) && Object.prototype.hasOwnProperty.call(value, k)) extra.push(k);
  }
  return [...extra, ...keys];
}

// defineProperty, not plain assignment, so an own "__proto__" key (e.g. from
// JSON.parse) becomes a normal key and never changes out's prototype.
function setKey(out, key, value) {
  Object.defineProperty(out, key, { value, enumerable: true, writable: true, configurable: true });
}

const INDEX = /^(?:0|[1-9][0-9]*)$/;

function walk(value, ctx, depth) {
  if (typeof value === 'string') return maskString(value);
  // Functions can carry own props (fn.apiKey) that console.log prints, so never pass them through.
  if (typeof value === 'function') return '[Function]';
  if (value === null || typeof value !== 'object') return value;
  if (depth > ctx.maxDepth) return '[MaxDepth]';
  let isArr;
  let keys;
  try {
    // Passthrough check, Array.isArray and key listing can all throw on hostile
    // Proxies (revoked, throwing traps). A logger must never crash.
    if (isPassthroughValue(value)) return value;  // everything else, class instances and Map/Set included, is walked
    isArr = Array.isArray(value);
    keys = keysOf(value);
  } catch {
    return '[Unreadable]';
  }
  if (ctx.path.has(value)) return '[Circular]';
  if (++ctx.nodes > ctx.maxNodes) return '[Truncated]';
  ctx.path.add(value);
  try {
    const out = isArr ? [] : {};
    let items = 0;
    let skipped = 0;
    // Own enumerable string keys only (plus Error fields). Symbol keys and
    // other non-enumerable props are dropped from the copy on purpose.
    for (const key of keys) {
      // Each array keeps its first maxArrayLength items, so one huge array cannot
      // use up the shared node budget and blank out the fields after it.
      if (isArr && INDEX.test(key) && ++items > ctx.maxArrayLength) { skipped++; continue; }
      let result;
      if (ctx.isSensitiveKey(key)) {
        result = REDACTED;                        // never read the value of a sensitive key
      } else {
        let child;
        try {
          child = value[key];                     // may invoke a throwing getter
          result = walk(child, ctx, depth + 1);
        } catch {
          result = '[Unreadable]';
        }
      }
      if (isArr && key !== '__proto__') out[key] = result;  // plain assignment is much faster; '__proto__' must go through setKey
      else setKey(out, key, result);
    }
    if (skipped) out.push(`[Truncated: ${skipped} more items]`);
    return out;
  } finally {
    ctx.path.delete(value);
  }
}

// Build a redact function for one set of options. Reuse it: its key cache stays warm.
function createRedactor(options = {}) {
  if (options === null || typeof options !== 'object') {
    throw new TypeError('keyblob: options must be an object');
  }
  const isSensitiveKey = createMatcher(stringList(options.keys, 'keys'), stringList(options.allow, 'allow'));
  const maxDepth = limit(options.maxDepth, 'maxDepth');
  const maxNodes = limit(options.maxNodes, 'maxNodes');
  const maxArrayLength = limit(options.maxArrayLength, 'maxArrayLength');
  return function redact(input) {
    return walk(input, { path: new WeakSet(), nodes: 0, isSensitiveKey, maxDepth, maxNodes, maxArrayLength }, 0);
  };
}

const defaultRedactor = createRedactor();
const compiled = new WeakMap();

function redact(input, options) {
  if (options === undefined) return defaultRedactor(input);
  if (options === null || typeof options !== 'object') {
    throw new TypeError('keyblob: options must be an object');
  }
  let fn = compiled.get(options);
  if (!fn) {
    fn = createRedactor(options);
    compiled.set(options, fn);
  }
  return fn(input);
}

module.exports = { redact, createRedactor, REDACTED };
