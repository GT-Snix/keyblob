#!/usr/bin/env node
'use strict';

// keyblob CLI: `keyblob scan` finds secrets before they leave your machine,
// `keyblob hook install` runs that scan on every git commit.
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { scanText, scanFileName } = require('../src/scan.js');

const MAX_FILE_BYTES = 1024 * 1024;
const SKIP_DIRS = new Set(['node_modules', '.git', '.hg', '.svn']);
const HOOK_MARKER = '# Installed by keyblob';

const HELP = `keyblob - keep secrets out of logs and out of git

Usage:
  keyblob scan [paths...]   Scan files for secrets (default: files git would commit,
                            or the current folder outside a git repo)
  keyblob scan --staged     Scan only what is staged for the next commit
  keyblob hook install      Run "keyblob scan --staged" before every git commit
  keyblob hook uninstall    Remove that hook

Options:
  --json                    Print findings as JSON

Exit codes: 0 clean, 1 secrets found, 2 usage or git error.
False alarm? Add  keyblob-ignore  in a comment on that line, or list the
file in .keyblobignore (gitignore-style globs, e.g. test/fixtures/).`;

function git(args) {
  const r = spawnSync('git', args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  if (r.error || r.status !== 0) return null;
  return r.stdout;
}

function isBinary(buf) {
  return buf.subarray(0, 8000).includes(0);
}

function walk(target, out) {
  let stat;
  try { stat = fs.lstatSync(target); } catch { return; }
  if (stat.isSymbolicLink()) return;
  if (stat.isDirectory()) {
    if (SKIP_DIRS.has(path.basename(target))) return;
    for (const name of fs.readdirSync(target)) walk(path.join(target, name), out);
  } else if (stat.isFile()) {
    out.push(target);
  }
}

// [{ name, read() -> Buffer|null }]
function collectFiles(paths, staged) {
  if (staged) {
    const list = git(['diff', '--cached', '--name-only', '-z', '--diff-filter=ACMR']);
    if (list === null) throw new UsageError('not a git repository, or git is not installed');
    return list.split('\0').filter(Boolean).map((name) => ({
      name,
      read: () => {
        const r = spawnSync('git', ['show', `:${name}`], { maxBuffer: 64 * 1024 * 1024 });
        return r.status === 0 ? r.stdout : null;
      },
    }));
  }
  // Inside a git repo, scan what git would commit (tracked + untracked, minus
  // .gitignore), so a correctly ignored .env is not reported. Elsewhere, walk.
  let names = [];
  const list = git(['ls-files', '-z', '--cached', '--others', '--exclude-standard', '--', ...paths]);
  if (list !== null) names = list.split('\0').filter(Boolean);
  else if (paths.length) for (const p of paths) walk(p, names);
  else walk('.', names);
  return names.map((name) => ({
    name,
    read: () => { try { return fs.readFileSync(name); } catch { return null; } },
  }));
}

class UsageError extends Error {}

// .keyblobignore: one glob per line, gitignore-style. `test/` ignores a folder,
// `*.snap` matches at any depth, `**` crosses folders, `#` starts a comment.
function loadIgnore() {
  let text;
  try { text = fs.readFileSync('.keyblobignore', 'utf8'); } catch { return () => false; }
  const res = text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#')).map((glob) => {
    const dir = glob.endsWith('/');
    let g = glob.replace(/^\/|\/$/g, '');
    const anchored = glob.startsWith('/') || g.includes('/');
    g = g.replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*\*\//g, '\u0000').replace(/\*\*/g, '\u0001')
      .replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]')
      .replace(/\u0000/g, '(?:.*/)?').replace(/\u0001/g, '.*');
    return new RegExp(`${anchored ? '^' : '(?:^|/)'}${g}${dir ? '/' : '(?:/|$)'}`);
  });
  return (name) => {
    const n = name.split(path.sep).join('/').replace(/^\.\//, '');
    return res.some((re) => re.test(n));
  };
}

function scan(args) {
  const staged = args.includes('--staged');
  const json = args.includes('--json');
  const unknown = args.find((a) => a.startsWith('-') && a !== '--staged' && a !== '--json');
  if (unknown) throw new UsageError(`unknown option ${unknown}`);
  const paths = args.filter((a) => !a.startsWith('-'));
  if (staged && paths.length) throw new UsageError('--staged does not take paths');

  const ignored = loadIgnore();
  const files = collectFiles(paths, staged).filter((f) => !ignored(f.name));
  const findings = [];
  for (const f of files) {
    const nameHit = scanFileName(f.name);
    if (nameHit) findings.push(nameHit);
    const buf = f.read();
    if (!buf || buf.length > MAX_FILE_BYTES || isBinary(buf)) continue;
    findings.push(...scanText(buf.toString('utf8'), { filename: f.name }));
  }

  if (json) {
    process.stdout.write(JSON.stringify({ files: files.length, findings }, null, 2) + '\n');
  } else if (!findings.length) {
    console.log(`keyblob: no secrets found in ${files.length} file${files.length === 1 ? '' : 's'}`);
  } else {
    const where = (f) => (f.line ? `${f.file}:${f.line}:${f.column}` : f.file);
    const width = Math.max(...findings.map((f) => where(f).length));
    console.error(`keyblob: found ${findings.length} possible secret${findings.length === 1 ? '' : 's'}\n`);
    for (const f of findings) console.error(`  ${where(f).padEnd(width)}  ${f.rule.padEnd(26)}  ${f.preview}`);
    console.error(`
Move secrets into environment variables (a .env file listed in .gitignore).
If a real secret was already pushed, rotate it: deleting it later does not
remove it from git history.
False alarm? Add  keyblob-ignore  in a comment on that line.`);
    if (staged) console.error('To commit anyway (not recommended): git commit --no-verify');
  }
  return findings.length ? 1 : 0;
}

function hookPath() {
  const p = git(['rev-parse', '--git-path', 'hooks/pre-commit']);
  if (p === null) throw new UsageError('not a git repository, or git is not installed');
  return path.resolve(p.trim());
}

const HOOK = `#!/bin/sh
${HOOK_MARKER} (keyblob hook install). Blocks commits that contain secrets.
# Remove with: npx keyblob hook uninstall
if [ -x ./node_modules/.bin/keyblob ]; then
  exec ./node_modules/.bin/keyblob scan --staged
elif command -v keyblob >/dev/null 2>&1; then
  exec keyblob scan --staged
fi
echo "keyblob pre-commit hook: keyblob is not installed. Run: npm install --save-dev keyblob" >&2
exit 1
`;

function hook(args) {
  const action = args[0];
  const file = hookPath();
  const existing = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : null;
  const ours = existing !== null && existing.includes(HOOK_MARKER);
  if (action === 'install') {
    if (existing !== null && !ours) {
      console.error(`keyblob: ${file} already exists and was not written by keyblob.
Add this line to it instead:  npx --no keyblob scan --staged || exit 1`);
      return 2;
    }
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, HOOK, { mode: 0o755 });
    fs.chmodSync(file, 0o755);
    console.log(`keyblob: pre-commit hook installed at ${file}`);
    return 0;
  }
  if (action === 'uninstall') {
    if (!ours) {
      console.error('keyblob: no keyblob pre-commit hook found');
      return 2;
    }
    fs.unlinkSync(file);
    console.log(`keyblob: removed ${file}`);
    return 0;
  }
  throw new UsageError('use: keyblob hook install | keyblob hook uninstall');
}

function main(argv) {
  const [cmd, ...rest] = argv;
  try {
    if (cmd === 'scan') return scan(rest);
    if (cmd === 'hook') return hook(rest);
    if (!cmd || cmd === 'help' || cmd === '--help' || cmd === '-h') {
      console.log(HELP);
      return cmd ? 0 : 2;
    }
    throw new UsageError(`unknown command ${cmd}`);
  } catch (err) {
    if (!(err instanceof UsageError)) throw err;
    console.error(`keyblob: ${err.message}\n\n${HELP}`);
    return 2;
  }
}

process.exitCode = main(process.argv.slice(2));
