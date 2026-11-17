'use strict';

// keyblob/scan: find secrets in source text before they are committed. Zero dependencies.
// redact() protects logs at runtime; this protects the repository at commit time.
const { createRedactor, REDACTED } = require('./index.js');

// Known token formats. These are recognised by their VALUE, so they are caught
// whatever the variable is called. Order matters: when two rules hit the same
// text, the earlier (more specific) one wins. Quantifiers are bounded so a long
// line cannot cause catastrophic backtracking.
const TOKEN_RULES = [
  { id: 'private-key', re: /-----BEGIN (?:[A-Z0-9]+ ){0,3}PRIVATE KEY(?: BLOCK)?-----/g },
  { id: 'aws-access-key-id', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { id: 'github-token', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b/g },
  { id: 'gitlab-token', re: /\bglpat-[A-Za-z0-9_-]{20,100}/g },
  { id: 'google-api-key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: 'google-oauth-client-secret', re: /\bGOCSPX-[A-Za-z0-9_-]{24,40}/g },
  { id: 'anthropic-api-key', re: /\bsk-ant-[A-Za-z0-9_-]{32,255}/g },
  { id: 'openai-api-key', re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,255}/g },
  { id: 'stripe-secret-key', re: /\b[rs]k_live_[A-Za-z0-9]{20,255}/g },
  { id: 'slack-token', re: /\bxox[abposr]-[A-Za-z0-9-]{10,255}/g },
  { id: 'npm-token', re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { id: 'jwt', re: /\beyJ[A-Za-z0-9_-]{8,2000}\.eyJ[A-Za-z0-9_-]{8,4000}\.[A-Za-z0-9_-]{8,2000}/g },
  // scheme://user:password@host -- only the password is reported.
  { id: 'url-password', re: /\b[a-z][a-z0-9+.-]{0,30}:\/\/[^/\s:@'"`]{1,256}:([^/\s@'"`]{1,256})@/gi, group: 1, checkPlaceholder: true },
];

// name = "value" / name: 'value' / "name": "value" in any language.
// The name is judged with the same word rules as redact(), so the two never disagree.
const QUOTED_ASSIGN = /(["'`]?)([A-Za-z_$][\w$.-]{0,100})\1\s*(?::|=)\s*(["'`])([^"'`\r\n]{8,500})\3/g;
// name=value with no quotes, only in config files (.env, YAML, INI, TOML, .npmrc...).
const UNQUOTED_ASSIGN = /^\s*(?:export\s+)?([A-Za-z_][\w.-]{0,100})\s*[:=]\s*([^\s"'#`][^\s"'#`]{7,499})\s*(?:#.*)?$/;
const NPMRC_TOKEN = /:_auth(?:Token)?\s*=\s*([^\s]{8,500})/;
const CONFIG_FILE = /(?:^|[\\/])\.env(?:\.[^\\/]*)?$|\.(?:ya?ml|ini|properties|toml|cfg|conf)$|(?:^|[\\/])\.npmrc$/i;

// Files whose very presence in a commit is a leak.
const SECRET_FILES = [
  { id: 'env-file', re: /(?:^|[\\/])\.env(?:\.(?!(?:example|sample|template|dist|defaults)$)[^\\/]+)?$/i },
  { id: 'private-key-file', re: /(?:^|[\\/])id_(?:rsa|dsa|ecdsa|ed25519)$|\.(?:p12|pfx|jks|keystore|key)$/i },
];

const IGNORE_MARKER = 'keyblob-ignore';
const PLACEHOLDER = /your|example|sample|changeme|change_me|placeholder|dummy|redacted|xxxx|\*\*\*\*|process\.env|os\.environ|getenv|replace/i;

// True for values that are clearly not a real secret: placeholders, template
// variables, prose, identifiers. Missing a real secret is worse than a false
// alarm, so this only skips the obvious cases.
function isPlaceholder(value, isSensitiveName) {
  if (/\s/.test(value)) return true;                          // prose, not a key
  if (/^(.)\1*$/.test(value)) return true;                    // "********", "xxxxxxxx"
  if (/[<>]|\$\{|\{\{|%\(|^\$[A-Za-z_]/.test(value)) return true; // <token>, ${VAR}, {{ x }}, $VAR
  if (value === REDACTED) return true;
  if (PLACEHOLDER.test(value)) return true;
  if (/^[a-z]+(?:\.[a-z_]+)+$/i.test(value)) return true;     // "auth.password.label" (i18n keys)
  if (/^[a-z_-]+$/i.test(value) && isSensitiveName(value)) return true; // FIELD = "password"
  return false;
}

function looksLikeUrlOrPath(value) {
  return /^(?:[a-z][a-z0-9+.-]*:\/\/|\.{0,2}\/)/i.test(value);
}

function preview(secret) {
  return `${secret.slice(0, 4)}… (${secret.length} chars)`;
}

function overlaps(found, line, start, end) {
  return found.some((f) => f.line === line && start < f._end && end > f._start);
}

// Scan one file's text. Returns findings; never includes the full secret.
function scanText(text, options = {}) {
  if (typeof text !== 'string') throw new TypeError('keyblob: scanText expects a string');
  if (options === null || typeof options !== 'object') throw new TypeError('keyblob: options must be an object');
  const filename = typeof options.filename === 'string' ? options.filename : '';
  const redactKey = createRedactor({ keys: options.keys, allow: options.allow });
  const isSensitiveName = (name) => redactKey({ [name]: 0 })[name] === REDACTED;
  const isConfig = CONFIG_FILE.test(filename);
  const found = [];

  const add = (rule, lineNo, start, secret) => {
    const end = start + secret.length;
    if (overlaps(found, lineNo, start, end)) return;
    found.push({ file: filename, line: lineNo, column: start + 1, rule, preview: preview(secret), _start: start, _end: end });
  };

  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNo = i + 1;
    if (line.includes(IGNORE_MARKER)) continue;

    for (const rule of TOKEN_RULES) {
      rule.re.lastIndex = 0;
      let m;
      while ((m = rule.re.exec(line)) !== null) {
        const secret = rule.group ? m[rule.group] : m[0];
        const start = rule.group ? m.index + m[0].lastIndexOf(secret) : m.index;
        if (!rule.checkPlaceholder || !isPlaceholder(secret, isSensitiveName)) add(rule.id, lineNo, start, secret);
      }
    }

    QUOTED_ASSIGN.lastIndex = 0;
    let m;
    while ((m = QUOTED_ASSIGN.exec(line)) !== null) {
      const [whole, , name, , value] = m;
      if (!isSensitiveName(name) || looksLikeUrlOrPath(value) || isPlaceholder(value, isSensitiveName)) continue;
      add('hardcoded-secret', lineNo, m.index + whole.length - value.length - 1, value);
    }

    if (isConfig) {
      const npm = NPMRC_TOKEN.exec(line);
      if (npm && !isPlaceholder(npm[1], isSensitiveName)) add('npm-auth-token', lineNo, npm.index + npm[0].length - npm[1].length, npm[1]);
      const u = UNQUOTED_ASSIGN.exec(line);
      if (u && isSensitiveName(u[1]) && !looksLikeUrlOrPath(u[2]) && !isPlaceholder(u[2], isSensitiveName)) {
        add('hardcoded-secret', lineNo, line.indexOf(u[2], line.indexOf(u[1]) + u[1].length), u[2]);
      }
    }
  }
  return found.map(({ _start, _end, ...f }) => f);
}

// A finding for files that should never be committed at all (.env, private keys).
function scanFileName(filename) {
  if (typeof filename !== 'string') throw new TypeError('keyblob: scanFileName expects a string');
  const base = filename.split(/[\\/]/).pop();
  for (const rule of SECRET_FILES) {
    if (rule.re.test(filename)) return { file: filename, line: 0, column: 0, rule: rule.id, preview: `${base} should not be committed` };
  }
  return null;
}

module.exports = { scanText, scanFileName, IGNORE_MARKER };
