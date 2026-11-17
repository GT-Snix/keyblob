'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { scanText, scanFileName } = require('../src/scan.js');

// Fake secrets are assembled at runtime so this file never contains a literal
// token (GitHub push protection and other scanners would rightly flag it).
const FAKE = {
  google: 'GOC' + 'SPX-' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4',
  aws: 'AK' + 'IA' + 'ABCDEFGHIJKLMNOP',
  github: 'gh' + 'p_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8',
  anthropic: 'sk-' + 'ant-' + 'api03-' + 'x'.repeat(10) + 'Y7z8A9b0C1d2E3f4G5h6I7j8',
  openai: 'sk-' + 'proj-' + 'Q1w2E3r4T5y6U7i8O9p0A1s2D3f4G5h6',
  stripe: 'sk' + '_live_' + 'Z9y8X7w6V5u4T3s2R1q0P9o8',
  npm: 'np' + 'm_' + 'abcdefghijABCDEFGHIJ0123456789abcdef',
};

const rules = (text, opts) => scanText(text, opts).map((f) => f.rule);

describe('scanText: known token formats', () => {
  for (const [name, token] of Object.entries(FAKE)) {
    test(`finds a ${name} token whatever the variable is called`, () => {
      const found = scanText(`const thing = "${token}";`);
      assert.equal(found.length, 1, JSON.stringify(found));
      assert.notEqual(found[0].rule, 'hardcoded-secret');
    });
  }
  test('anthropic keys are not double-reported as openai keys', () => {
    assert.deepEqual(rules(`k = "${FAKE.anthropic}"`), ['anthropic-api-key']);
  });
  test('private key blocks', () => {
    assert.deepEqual(rules('-----BEGIN RSA ' + 'PRIVATE KEY-----'), ['private-key']);
    assert.deepEqual(rules('-----BEGIN PUBLIC KEY-----'), []);
  });
  test('passwords inside connection strings, but not placeholders', () => {
    assert.deepEqual(rules('url = "postgres://app:s3cretPw1@db:5432/prod"'), ['url-password']);
    assert.deepEqual(rules('url = "postgres://app:${DB_PASSWORD}@db/prod"'), []);
    assert.deepEqual(rules('see https://example.com/a@b'), []);
  });
});

describe('scanText: hardcoded values under sensitive names', () => {
  test('uses the same name rules as redact()', () => {
    assert.deepEqual(rules('const clientSecret = "k8s9d7f6g5h4";'), ['hardcoded-secret']);
    assert.deepEqual(rules('{ "db_password": "hunter2hunter2" }'), ['hardcoded-secret']);
    assert.deepEqual(rules("apiKey: 'a1b2c3d4e5f6'"), ['hardcoded-secret']);
    assert.deepEqual(rules('const passwordPolicy = "min-12-chars";'), []);
    assert.deepEqual(rules('const author = "somebody123";'), []);
  });
  test('skips placeholders, env lookups, prose and identifiers', () => {
    for (const line of [
      'password = "your-password-here"',
      'token = "${API_TOKEN}"',
      'secret = "<paste secret>"',
      'password = "********"',
      'password = "Please enter your password"',
      'const PASSWORD_FIELD = "password";',
      'passwordLabel = "auth.password.label"',
      'const secret = process.env.SECRET;',
      'tokenUrl = "https://oauth2.googleapis.com/token"',
      'apiKey = "short"',
    ]) assert.deepEqual(rules(line), [], line);
  });
  test('reports position and never the full secret', () => {
    const [f] = scanText('\n  const clientSecret = "k8s9d7f6g5h4";', { filename: 'a.js' });
    assert.equal(f.file, 'a.js');
    assert.equal(f.line, 2);
    assert.equal(f.column, 25);
    assert.equal(f.preview, 'k8s9… (12 chars)');
    assert.ok(!JSON.stringify(f).includes('k8s9d7f6g5h4'));
  });
  test('keyblob-ignore skips a line', () => {
    assert.deepEqual(rules(`k = "${FAKE.github}"; // keyblob-ignore`), []);
  });
  test('keys and allow options work like redact()', () => {
    assert.deepEqual(rules('vendorRef = "abc123xyz789"', { keys: ['vendorRef'] }), ['hardcoded-secret']);
    assert.deepEqual(rules('session = "abc123xyz789"', { allow: ['session'] }), []);
  });
});

describe('scanText: config files', () => {
  test('.env style unquoted values', () => {
    assert.deepEqual(rules('GOOGLE_CLIENT_SECRET=k8s9d7f6g5h4\nPORT=3000', { filename: '.env' }), ['hardcoded-secret']);
    assert.deepEqual(rules('export API_TOKEN=k8s9d7f6g5h4', { filename: 'prod.env' }), []); // only .env*, not *.env
    assert.deepEqual(rules('export API_TOKEN=k8s9d7f6g5h4', { filename: '.env.local' }), ['hardcoded-secret']);
  });
  test('YAML, with template placeholders skipped', () => {
    assert.deepEqual(rules('db:\n  password: hunter2hunter2', { filename: 'config.yml' }), ['hardcoded-secret']);
    assert.deepEqual(rules('token: ${{ secrets.TOKEN }}', { filename: 'ci.yml' }), []);
  });
  test('.npmrc auth tokens', () => {
    assert.deepEqual(rules('//registry.npmjs.org/:_authToken=abcdef123456', { filename: '.npmrc' }), ['npm-auth-token']);
    assert.deepEqual(rules('//registry.npmjs.org/:_authToken=${NPM_TOKEN}', { filename: '.npmrc' }), []);
  });
  test('unquoted values are not checked in source code', () => {
    assert.deepEqual(rules('password=hunter2hunter2', { filename: 'notes.js' }), []);
  });
});

describe('scanText: robustness', () => {
  test('rejects non-strings', () => {
    assert.throws(() => scanText(null), TypeError);
  });
  test('long hostile lines finish quickly', () => {
    const start = Date.now();
    scanText('a://' + 'b'.repeat(200000) + ':' + 'c'.repeat(200000));
    scanText('password = "' + 'x'.repeat(200000));
    scanText('eyJ' + 'a'.repeat(100000) + '.eyJ' + 'b'.repeat(100000));
    assert.ok(Date.now() - start < 5000);
  });
});

describe('scanFileName', () => {
  test('flags files that should never be committed', () => {
    for (const f of ['.env', 'app/.env', '.env.local', '.env.production', 'id_rsa', 'cert.p12', 'server.key']) {
      assert.ok(scanFileName(f), f);
    }
  });
  test('allows templates and public keys', () => {
    for (const f of ['.env.example', '.env.sample', '.env.template', 'id_rsa.pub', 'environment.js', 'keys.js']) {
      assert.equal(scanFileName(f), null, f);
    }
  });
});

describe('CLI', () => {
  const bin = path.join(__dirname, '..', 'bin', 'keyblob.js');
  const hasGit = spawnSync('git', ['--version']).status === 0;

  function repo() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'keyblob-'));
    const git = (...args) => spawnSync('git', args, { cwd: dir, encoding: 'utf8' });
    git('init', '-q');
    return { dir, git, run: (...args) => spawnSync(process.execPath, [bin, ...args], { cwd: dir, encoding: 'utf8' }) };
  }

  test('help and unknown commands', () => {
    assert.equal(spawnSync(process.execPath, [bin, 'help']).status, 0);
    assert.equal(spawnSync(process.execPath, [bin, 'nope']).status, 2);
  });

  test('scan --staged blocks a staged secret and passes once it is removed', { skip: !hasGit }, () => {
    const { dir, git, run } = repo();
    fs.writeFileSync(path.join(dir, 'index.js'), `const clientSecret = "${FAKE.google}";\n`);
    git('add', 'index.js');
    let r = run('scan', '--staged');
    assert.equal(r.status, 1);
    assert.match(r.stderr, /index\.js:1:\d+\s+google-oauth-client-secret/);
    assert.ok(!r.stderr.includes(FAKE.google), 'output must not contain the secret');

    fs.writeFileSync(path.join(dir, 'index.js'), 'const clientSecret = process.env.CLIENT_SECRET;\n');
    git('add', 'index.js');
    r = run('scan', '--staged');
    assert.equal(r.status, 0, r.stderr);
  });

  test('scan respects .gitignore but flags a committed .env', { skip: !hasGit }, () => {
    const { dir, git, run } = repo();
    fs.writeFileSync(path.join(dir, '.env'), 'API_TOKEN=k8s9d7f6g5h4\n');
    assert.equal(run('scan').status, 1);
    fs.writeFileSync(path.join(dir, '.gitignore'), '.env\n');
    assert.equal(run('scan').status, 0);
    git('add', '-f', '.env');
    const r = run('scan', '--staged', '--json');
    assert.equal(r.status, 1);
    assert.deepEqual(JSON.parse(r.stdout).findings.map((f) => f.rule), ['env-file', 'hardcoded-secret']);
  });

  test('.keyblobignore skips listed paths', { skip: !hasGit }, () => {
    const { dir, run } = repo();
    fs.mkdirSync(path.join(dir, 'test', 'fixtures'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'test', 'fixtures', 'a.js'), 'password = "hunter2hunter2"\n');
    fs.writeFileSync(path.join(dir, 'b.snap'), 'password = "hunter2hunter2"\n');
    fs.writeFileSync(path.join(dir, 'c.js'), 'password = "hunter2hunter2"\n');
    fs.writeFileSync(path.join(dir, '.keyblobignore'), '# fixtures\ntest/\n*.snap\n');
    const r = run('scan', '--json');
    assert.deepEqual(JSON.parse(r.stdout).findings.map((f) => f.file), ['c.js']);
  });

  test('hook install / uninstall, without clobbering a foreign hook', { skip: !hasGit }, () => {
    const { dir, git, run } = repo();
    const hook = path.join(dir, git('rev-parse', '--git-path', 'hooks/pre-commit').stdout.trim());
    assert.equal(run('hook', 'install').status, 0);
    assert.match(fs.readFileSync(hook, 'utf8'), /keyblob scan --staged/);
    assert.equal(run('hook', 'install').status, 0, 'reinstall is fine');
    assert.equal(run('hook', 'uninstall').status, 0);
    assert.equal(fs.existsSync(hook), false);

    fs.writeFileSync(hook, '#!/bin/sh\necho mine\n');
    assert.equal(run('hook', 'install').status, 2);
    assert.equal(fs.readFileSync(hook, 'utf8'), '#!/bin/sh\necho mine\n');
  });
});
