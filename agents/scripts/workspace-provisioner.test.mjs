import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { provision, validateRequest } from './workspace-provisioner.mjs';
process.umask(0o077);
const uid = process.getuid();
const here = path.dirname(fileURLToPath(import.meta.url));
const actualGit = spawnSync('which', ['git'], { encoding: 'utf8' }).stdout.trim();
function run(file, args, options = {}) {
  const r = spawnSync(file, args, { encoding: 'utf8', ...options });
  assert.equal(r.status, 0, r.stderr); return r.stdout.trim();
}
function fixture(t) {
  const base = fs.mkdtempSync(path.join(process.env.TEST_TMPDIR || os.tmpdir(), 'workspace-fixture-'));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  const source = path.join(base, 'source'); fs.mkdirSync(source);
  run(actualGit, ['-C', source, 'init', '-b', 'main']);
  fs.writeFileSync(path.join(source, 'README'), 'fixture\n');
  run(actualGit, ['-C', source, 'add', '.']);
  run(actualGit, ['-C', source, '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.test', 'commit', '-m', 'fixture']);
  const sha = run(actualGit, ['-C', source, 'rev-parse', 'HEAD']);
  const request = { jobId: 'job-one', repository: 'test-org/project', baseRef: 'main', baseSha: sha };
  const attestation = { requesterId: 'developer-a', role: 'developer', enabled: true,
    ...request, status: 'active', expiresAt: '2099-01-01T00:00:00Z' };
  const answer = path.join(base, 'answer.json'); fs.writeFileSync(answer, JSON.stringify(attestation));
  const bin = fs.mkdtempSync(path.join(process.env.TEST_EXECUTABLE_TMPDIR || base, 'fixture-bin-'));
  t.after(() => fs.rmSync(bin, { recursive: true, force: true }));
  const verifier = path.join(bin, 'verify');
  fs.writeFileSync(verifier, `#!/usr/bin/env node\nprocess.stdout.write(require('fs').readFileSync(${JSON.stringify(answer)}));\n`, { mode: 0o700 });
  const runtimeRoot = path.join(base, 'runtime'); fs.mkdirSync(runtimeRoot);
  const workspaces = Object.fromEntries(['dispatcher-planner', 'developer-a', 'reviewer-a'].map(role => {
    const p = path.join(runtimeRoot, role); fs.mkdirSync(p); return [role, p];
  }));
  const stateDirectory = path.join(base, 'audit'), lockDirectory = path.join(base, 'locks');
  fs.mkdirSync(stateDirectory); fs.mkdirSync(lockDirectory);
  fs.writeFileSync(path.join(lockDirectory, 'provision.lock'), '', { mode: 0o600 });
  const config = { hostUid: 0, runtimeRoot, workspaces, stateDirectory, lockDirectory, verifier,
    allowedRepositories: ['test-org/project'], protectedPaths: [path.join(base, 'secrets')] };
  // Exercise real local Git without network or credential delivery. Only the
  // clone source is rewritten; stored origin remains the production-safe URL.
  fs.writeFileSync(path.join(bin, 'git'), `#!/usr/bin/env node
const cp=require('child_process'); const args=process.argv.slice(2);
if(args[0]==='clone') {
  const i=args.indexOf('https://github.com/test-org/project.git'); args[i]=${JSON.stringify(source)};
  let r=cp.spawnSync(${JSON.stringify(actualGit)},args,{stdio:'inherit'}); if(r.status)process.exit(r.status);
  r=cp.spawnSync(${JSON.stringify(actualGit)},['-C',args.at(-1),'remote','set-url','origin','https://github.com/test-org/project.git'],{stdio:'inherit'});process.exit(r.status);
}
const r=cp.spawnSync(${JSON.stringify(actualGit)},args,{stdio:'inherit'});process.exit(r.status??1);
`, { mode: 0o700 });
  const oldPath = process.env.PATH; process.env.PATH = `${bin}:${oldPath}`;
  t.after(() => { process.env.PATH = oldPath; });
  const invoke = () => provision(config, request, { hostUid: uid, agentUid: uid });
  const destinations = Object.values(workspaces).map(w => path.join(w, request.repository));
  return { base, source, request, attestation, answer, verifier, config, bin, invoke, destinations };
}
function rejects(fn, code) { assert.throws(fn, e => e.code === code, code); }
function snapshot(p) {
  if (!fs.existsSync(p)) return null;
  const result = {};
  function walk(dir) { for (const name of fs.readdirSync(dir)) {
    const file = path.join(dir, name), s = fs.lstatSync(file), relative = path.relative(p, file);
    if (s.isSymbolicLink()) result[relative] = ['link', fs.readlinkSync(file)];
    else if (s.isDirectory()) walk(file);
    else result[relative] = [s.mode, fs.readFileSync(file).toString('base64')];
  } } walk(p); return result;
}

test('strict request schema rejects identity, paths, traversal, option injection and malformed SHA', () => {
  const r = { jobId: 'job', repository: 'org/repo', baseRef: 'main', baseSha: 'a'.repeat(40) };
  assert.deepEqual(validateRequest(r), r);
  for (const bad of [{ ...r, agentId: 'owner' }, { ...r, destination: '/tmp/x' },
    { ...r, repository: '../repo' }, { ...r, baseRef: '--upload-pack=x' },
    { ...r, baseRef: 'a/../b' }, { ...r, baseRef: 'x.lock' }, { ...r, baseSha: 'abcd' }]) assert.throws(() => validateRequest(bad));
});

test('live authorization rejects before workspace, lock or audit writes', t => {
  const f = fixture(t);
  for (const change of [{ enabled: false }, { status: 'completed' }, { expiresAt: '2000-01-01T00:00:00Z' },
    { baseSha: 'b'.repeat(40) }, { repository: 'other/repo' }, { jobId: 'other' },
    { baseRef: 'other' }, { requesterId: '' }, { role: 'owner' }]) {
    fs.writeFileSync(f.answer, JSON.stringify({ ...f.attestation, ...change }));
    rejects(f.invoke, 'AUTHORIZATION');
    assert.deepEqual(fs.readdirSync(f.config.stateDirectory), []);
    assert.deepEqual(fs.readdirSync(f.config.lockDirectory), ['provision.lock']);
    for (const w of Object.values(f.config.workspaces)) assert.deepEqual(fs.readdirSync(w), []);
  }
  for (const answer of ['null', '{}', JSON.stringify({ ...f.attestation, agentId: 'owner' }), 'secret-canary:malformed']) {
    fs.writeFileSync(f.answer, answer); assert.throws(f.invoke);
    assert.deepEqual(fs.readdirSync(f.config.stateDirectory), []);
  }
  fs.rmSync(f.verifier); assert.throws(f.invoke);
});

test('creates three exact independent detached clones, persists receipts and repeats without checkout changes', t => {
  const f = fixture(t), result = f.invoke();
  assert.equal(result.result, 'success');
  assert.deepEqual(Object.values(result.roles), ['created', 'created', 'created']);
  const inodes = [];
  for (const d of f.destinations) {
    assert.equal(run(actualGit, ['-C', d, 'rev-parse', 'HEAD']), f.request.baseSha);
    assert.equal(spawnSync(actualGit, ['-C', d, 'symbolic-ref', '-q', 'HEAD']).status, 1);
    const object = path.join(d, '.git/objects', f.request.baseSha.slice(0, 2), f.request.baseSha.slice(2));
    inodes.push(fs.statSync(object).ino); assert.equal(fs.statSync(object).nlink, 1);
  }
  assert.equal(new Set(inodes).size, 3);
  const before = f.destinations.map(snapshot), again = f.invoke();
  assert.deepEqual(Object.values(again.roles), ['unchanged', 'unchanged', 'unchanged']);
  assert.deepEqual(f.destinations.map(snapshot), before);
  assert.equal(fs.readdirSync(f.config.stateDirectory).filter(n => n.endsWith('.result.json')).length, 2);
});

test('dirty tracked/index/untracked/ignored and wrong origin/SHA reject without checkout mutation', t => {
  const f = fixture(t); f.invoke(); const d = f.destinations[2];
  const check = code => { const before = f.destinations.map(snapshot); rejects(f.invoke, code); assert.deepEqual(f.destinations.map(snapshot), before); };
  fs.writeFileSync(path.join(d, 'README'), 'changed'); check('DIRTY');
  run(actualGit, ['-C', d, 'add', 'README']); check('DIRTY');
  run(actualGit, ['-C', d, 'reset', '--hard', f.request.baseSha]);
  fs.writeFileSync(path.join(d, 'new'), 'untracked'); check('DIRTY'); fs.rmSync(path.join(d, 'new'));
  fs.writeFileSync(path.join(d, '.git/info/exclude'), 'ignored\n');
  fs.writeFileSync(path.join(d, 'ignored'), 'ignored'); check('DIRTY'); fs.rmSync(path.join(d, 'ignored'));
  run(actualGit, ['-C', d, 'remote', 'set-url', 'origin', 'https://secret-canary@example.test/other']); check('ORIGIN');
  run(actualGit, ['-C', d, 'remote', 'set-url', 'origin', 'https://github.com/test-org/project.git']);
  fs.writeFileSync(path.join(d, 'README'), 'next'); run(actualGit, ['-C', d, 'add', 'README']);
  run(actualGit, ['-C', d, '-c', 'user.name=f', '-c', 'user.email=f@e.test', 'commit', '-m', 'next']); check('SHA');
});

test('canonical/symlink/protected/nested/untrusted roots fail before installation', t => {
  const f = fixture(t), original = f.config.workspaces['reviewer-a'];
  for (const p of ['/', '/etc/unsafe', `${original}/../escape`, f.config.workspaces['developer-a']]) {
    f.config.workspaces['reviewer-a'] = p; assert.throws(f.invoke);
  }
  f.config.workspaces['reviewer-a'] = original;
  fs.rmdirSync(original); fs.symlinkSync(path.join(f.base, 'absent'), original); rejects(f.invoke, 'SYMLINK');
  fs.unlinkSync(original); fs.mkdirSync(original); fs.chmodSync(original, 0o777); rejects(f.invoke, 'PATH_TRUST');
  fs.chmodSync(original, 0o755);
  fs.mkdirSync(path.join(original, 'test-org')); fs.symlinkSync('/does-not-exist', f.destinations[2]); rejects(f.invoke, 'SYMLINK');
  assert.equal(fs.existsSync(f.destinations[0]), false);
});

test('symlinked .git, includes, alternates and nonclone destinations fail closed', t => {
  const f = fixture(t); f.invoke(); const d = f.destinations[2], gitdir = path.join(d, '.git');
  fs.renameSync(gitdir, `${gitdir}.saved`); fs.symlinkSync(`${gitdir}.saved`, gitdir); assert.throws(f.invoke);
  fs.unlinkSync(gitdir); fs.renameSync(`${gitdir}.saved`, gitdir);
  fs.appendFileSync(path.join(gitdir, 'config'), '\n[include]\npath=/secret-canary\n'); rejects(f.invoke, 'CLONE_LAYOUT');
  fs.writeFileSync(path.join(gitdir, 'config'), '[core]\nbare=false\n[remote "origin"]\nurl=https://github.com/test-org/project.git\n');
  fs.writeFileSync(path.join(gitdir, 'objects/info/alternates'), '/secret-canary'); rejects(f.invoke, 'CLONE_LAYOUT');
  fs.rmSync(gitdir, { recursive: true }); rejects(f.invoke, 'CLONE_LAYOUT');
});

test('shared flock rejects concurrent provisioning and rejects symlink lock', t => {
  const f = fixture(t), lock = path.join(f.config.lockDirectory, 'provision.lock');
  const fd = fs.openSync(lock, 'w', 0o600);
  try { run('flock', ['-n', '3'], { stdio: ['ignore', 'pipe', 'pipe', fd] }); rejects(f.invoke, 'SUBPROCESS'); }
  finally { fs.closeSync(fd); }
  fs.unlinkSync(lock); fs.symlinkSync(path.join(f.base, 'outside-lock'), lock); rejects(f.invoke, 'SYMLINK');
  assert.equal(fs.existsSync(path.join(f.base, 'outside-lock')), false);
});

test('moved ref and upstream secret-canary failures do not install or disclose', t => {
  const f = fixture(t);
  fs.writeFileSync(path.join(f.source, 'next'), 'moved'); run(actualGit, ['-C', f.source, 'add', '.']);
  run(actualGit, ['-C', f.source, '-c', 'user.name=f', '-c', 'user.email=f@e.test', 'commit', '-m', 'moved']);
  rejects(f.invoke, 'SUBPROCESS');
  for (const d of f.destinations) assert.equal(fs.existsSync(d), false);
  fs.writeFileSync(path.join(f.bin, 'git'), '#!/bin/sh\necho secret-canary\necho secret-canary >&2\nexit 1\n', { mode: 0o700 });
  try { f.invoke(); assert.fail(); } catch (e) { assert.equal(e.message, 'SUBPROCESS'); }
  assert.equal(JSON.stringify(snapshot(f.config.stateDirectory)).includes('secret-canary'), false);
  for (const n of fs.readdirSync(f.config.stateDirectory)) assert.equal(fs.readFileSync(path.join(f.config.stateDirectory, n), 'utf8').includes('secret-canary'), false);
});

test('revocation during publication leaves documented partial result and clean retry recovers', t => {
  const f = fixture(t), counter = path.join(f.base, 'counter');
  fs.writeFileSync(f.verifier, `#!/usr/bin/env node
const fs=require('fs'), p=${JSON.stringify(counter)};const n=fs.existsSync(p)?Number(fs.readFileSync(p)):0;fs.writeFileSync(p,String(n+1));
const a=JSON.parse(fs.readFileSync(${JSON.stringify(f.answer)}));if(n>=4)a.status='completed';process.stdout.write(JSON.stringify(a));
`);
  rejects(f.invoke, 'AUTHORIZATION');
  assert.equal(fs.existsSync(f.destinations[0]), true); assert.equal(fs.existsSync(f.destinations[1]), false);
  const receipts = fs.readdirSync(f.config.stateDirectory).filter(n => n.endsWith('.result.json'));
  const failure = JSON.parse(fs.readFileSync(path.join(f.config.stateDirectory, receipts[0])));
  assert.equal(failure.result, 'failed'); assert.equal(failure.roles['dispatcher-planner'], 'created');
  fs.writeFileSync(f.verifier, `#!/usr/bin/env node\nprocess.stdout.write(require('fs').readFileSync(${JSON.stringify(f.answer)}));\n`);
  const first = snapshot(f.destinations[0]), result = f.invoke();
  assert.equal(result.roles['dispatcher-planner'], 'unchanged'); assert.deepEqual(snapshot(f.destinations[0]), first);
});

test('job ID cannot be rebound and audit failure never reports successful installation', t => {
  const f = fixture(t); f.invoke();
  f.request.baseRef = 'other'; fs.writeFileSync(f.answer, JSON.stringify({ ...f.attestation, baseRef: 'other' }));
  rejects(f.invoke, 'JOB_REUSE');
  f.request.baseRef = 'main'; fs.writeFileSync(f.answer, JSON.stringify(f.attestation));
  const before = f.destinations.map(snapshot);
  // A non-directory audit root is rejected even for an otherwise valid no-op.
  f.config.stateDirectory = path.join(f.base, 'not-a-directory'); fs.writeFileSync(f.config.stateDirectory, '');
  rejects(f.invoke, 'HOST_PREPARATION'); assert.deepEqual(f.destinations.map(snapshot), before);
});

test('production CLI refuses agent invocation without printing raw input', () => {
  if (uid === 0) return;
  const r = spawnSync(process.execPath, [path.join(here, 'workspace-provisioner.mjs'), '/secret-canary'],
    { encoding: 'utf8', input: 'secret-canary' });
  assert.equal(r.status, 1); assert.equal(r.stdout.trim(), '{"result":"rejected","error":"HOST_ONLY"}'); assert.equal(r.stderr, '');
});

// Git status can execute a repository-defined clean filter. It must run without
// host secrets even when the checkout is dirty and ultimately rejected.
test('existing clone filters receive no host authentication environment', t => {
  const f = fixture(t); f.invoke();
  const dest = f.destinations[0], output = path.join(f.base, 'filter-environment');
  const filter = path.join(f.bin, 'filter');
  fs.writeFileSync(filter, '#!/usr/bin/env node\n' +
    'const fs=require("fs");fs.writeFileSync(' + JSON.stringify(output) +
    ', process.env.HOST_AUTH_CANARY || "absent");process.stdout.write(fs.readFileSync(0));\n', { mode: 0o700 });
  run(actualGit, ['-C', dest, 'config', 'filter.fixture.clean', filter]);
  fs.writeFileSync(path.join(dest, '.git/info/attributes'), 'README filter=fixture\n');
  fs.writeFileSync(path.join(dest, 'README'), 'changed\n');
  fs.utimesSync(path.join(dest, 'README'), 1000000000, 1000000000);
  const previous = process.env.HOST_AUTH_CANARY;
  process.env.HOST_AUTH_CANARY = 'secret-canary';
  try { rejects(f.invoke, 'DIRTY'); }
  finally { if (previous === undefined) delete process.env.HOST_AUTH_CANARY; else process.env.HOST_AUTH_CANARY = previous; }
  assert.equal(fs.readFileSync(output, 'utf8'), 'absent');
});

test('result audit storage failure rejects after publication and retry verifies leftovers', t => {
  const f = fixture(t), open = fs.openSync;
  fs.openSync = function(file, ...args) {
    if (String(file).endsWith('.result.json')) throw new Error('secret-canary');
    return open.call(this, file, ...args);
  };
  try { rejects(f.invoke, 'AUDIT'); } finally { fs.openSync = open; }
  for (const d of f.destinations) assert.equal(fs.existsSync(d), true);
  assert.equal(fs.readdirSync(f.config.stateDirectory).some(n => n.endsWith('.result.json')), false);
  const before = f.destinations.map(snapshot);
  assert.deepEqual(Object.values(f.invoke().roles), ['unchanged', 'unchanged', 'unchanged']);
  assert.deepEqual(f.destinations.map(snapshot), before);
});

test('shared helper preserves manual fallback checkout without a pinned SHA', t => {
  const f = fixture(t), destination = path.join(f.base, 'manual-fallback');
  run('bash', ['-c', 'source "$1"; clone_independent_repository "$2" main "$3"',
    'fixture', path.join(here, 'repository-clone.sh'), f.source, destination]);
  assert.equal(fs.readFileSync(path.join(destination, 'README'), 'utf8'), 'fixture\n');
  assert.equal(run(actualGit, ['-C', destination, 'rev-parse', 'HEAD']), f.request.baseSha);
  assert.equal(run(actualGit, ['-C', destination, 'symbolic-ref', '--short', 'HEAD']), 'main');
});

for (const flag of ['assume-unchanged', 'skip-worktree']) {
  test(`rejects ${flag} hiding tracked modifications without changing index or worktrees`, t => {
    const f = fixture(t); f.invoke();
    const dest = f.destinations[2], index = path.join(dest, '.git/index');
    run(actualGit, ['-C', dest, 'update-index', `--${flag}`, '--', 'README']);
    fs.writeFileSync(path.join(dest, 'README'), 'hidden tracked modification\n');
    // Reproduce the bypass independently: status is empty while tracked content
    // differs from the approved commit. Disable optional index refresh writes.
    assert.equal(run(actualGit, ['-C', dest, 'status', '--porcelain=v1'],
      { env: { ...process.env, GIT_OPTIONAL_LOCKS: '0' } }), '');
    assert.notEqual(fs.readFileSync(path.join(dest, 'README'), 'utf8'),
      run(actualGit, ['-C', dest, 'show', 'HEAD:README']) + '\n');
    const before = f.destinations.map(snapshot), indexBytes = fs.readFileSync(index);
    const indexStat = fs.statSync(index, { bigint: true });
    const receipts = new Set(fs.readdirSync(f.config.stateDirectory));
    rejects(f.invoke, 'DIRTY');
    assert.deepEqual(fs.readFileSync(index), indexBytes);
    const afterStat = fs.statSync(index, { bigint: true });
    for (const key of ['ino', 'size', 'mtimeNs', 'ctimeNs']) assert.equal(afterStat[key], indexStat[key]);
    assert.deepEqual(f.destinations.map(snapshot), before);
    const results = fs.readdirSync(f.config.stateDirectory)
      .filter(n => n.endsWith('.result.json') && !receipts.has(n))
      .map(n => JSON.parse(fs.readFileSync(path.join(f.config.stateDirectory, n), 'utf8')));
    assert.equal(results.length, 1);
    assert.equal(results[0].result, 'failed');
    assert.equal(results[0].error, 'DIRTY');
  });
}
