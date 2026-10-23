#!/usr/bin/env node
// Host-only, owner-mediated adapter. No network listener, agent credentials, or
// caller-supplied identity. The host verifier is the live authorization boundary.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const roles = ['dispatcher-planner', 'developer-a', 'reviewer-a'];
const fields = ['jobId', 'repository', 'baseRef', 'baseSha'];
const fail = code => { throw new ProvisionError(code); };
export class ProvisionError extends Error {
  constructor(code) { super(code); this.code = code; }
}
function keys(value, names) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join() !== [...names].sort().join()) fail('SCHEMA');
}
export function validateRequest(r) {
  keys(r, fields);
  if (fields.some(k => typeof r[k] !== 'string')) fail('SCHEMA');
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(r.jobId) ||
      !/^[a-zA-Z0-9][a-zA-Z0-9_-]*\/[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(r.repository) ||
      r.repository.split('/').some(p => p.endsWith('.git') || p.includes('..')) ||
      !/^[a-f0-9]{40}$/.test(r.baseSha) ||
      !/^[a-zA-Z0-9][a-zA-Z0-9/_.-]{0,127}$/.test(r.baseRef) ||
      r.baseRef.includes('..') || r.baseRef.includes('//') ||
      r.baseRef.split('/').some(p => p.startsWith('.') || p.endsWith('.') || p.endsWith('.lock')) ||
      r.baseRef.endsWith('/')) fail('REQUEST');
  return r;
}
function overlaps(a, b) { return a === b || a.startsWith(`${b}/`) || b.startsWith(`${a}/`); }
function components(p) {
  if (typeof p !== 'string' || !path.isAbsolute(p) || path.normalize(p) !== p || p === '/') fail('PATH');
  const result = [];
  for (let part = p; part !== '/'; part = path.dirname(part)) result.unshift(part);
  return result;
}
// Ancestors are host-owned and cannot be replaced by UID 10001. A symlink is
// rejected even when it resolves to the same canonical string, or is dangling.
export function inspectPath(p, uid = 0, leafTrusted = true) {
  const list = components(p);
  for (const [i, part] of list.entries()) {
    let s;
    try { s = fs.lstatSync(part); } catch (e) { if (e.code === 'ENOENT') continue; throw e; }
    if (s.isSymbolicLink()) fail('SYMLINK');
    if (i !== list.length - 1 && !s.isDirectory()) fail('PATH');
    if (leafTrusted || i !== list.length - 1) {
      // /tmp is usable only by unprivileged fixture tests, never production.
      const fixtureTmp = uid !== 0 && part === '/tmp' && (s.uid === 0 || s.uid === uid) && (s.mode & 0o1000);
      if (!fixtureTmp && (s.uid !== uid || (s.mode & 0o022))) {
        // System ancestors owned by root are also trusted for a fixture host UID.
        if (!(uid !== 0 && s.uid === 0 && !(s.mode & 0o022))) fail('PATH_TRUST');
      }
    }
  }
}
function safeTree(p) {
  const s = fs.lstatSync(p);
  if (s.isSymbolicLink() || (s.isFile() && s.nlink !== 1) || (!s.isDirectory() && !s.isFile())) fail('CLONE_LAYOUT');
  if (s.isDirectory()) for (const name of fs.readdirSync(p)) safeTree(path.join(p, name));
}
function command(file, args, options = {}) {
  const result = spawnSync(file, args, { encoding: 'utf8', timeout: 120000,
    maxBuffer: 1024 * 1024, ...options });
  // Never forward upstream output, errors, paths or URLs to the agent or audit.
  if (result.error || result.status !== 0 || result.signal) fail('SUBPROCESS');
  return result.stdout.trim();
}
function gitEnv() {
  const env = { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_TERMINAL_PROMPT: '0', GIT_NO_REPLACE_OBJECTS: '1', GIT_OPTIONAL_LOCKS: '0' };
  // Disallow inherited command/config injection; host authentication may use its
  // existing SSH agent/askpass, but raw credentials never enter args or receipts.
  for (const k of Object.keys(env)) if (k.startsWith('GIT_CONFIG_') ||
      ['GIT_DIR', 'GIT_WORK_TREE', 'GIT_COMMON_DIR', 'GIT_INDEX_FILE',
       'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_TEMPLATE_DIR'].includes(k)) delete env[k];
  return { ...env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' };
}
// Existing checkouts are untrusted. Do not pass host authentication or arbitrary
// host environment to Git/config reads, which may run repository clean filters.
function inspectionEnv() {
  return { PATH: process.env.PATH, HOME: '/nonexistent', LANG: 'C',
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_TERMINAL_PROMPT: '0', GIT_NO_REPLACE_OBJECTS: '1', GIT_OPTIONAL_LOCKS: '0' };
}
function cloneIdentity(dest) {
  const uid = fs.statSync(dest).uid;
  if (process.getuid() === 0 && uid !== 0 && uid !== 10001) fail('CLONE_LAYOUT');
  return { uid, gid: uid };
}
function git(dest, args) {
  return command('git', ['-c', `safe.directory=${dest}`, '-c', 'core.fsmonitor=false',
    '-c', 'core.hooksPath=/dev/null', '-c', 'core.untrackedCache=false',
    '-c', 'submodule.recurse=false', '-C', dest, ...args], { env: inspectionEnv(), ...cloneIdentity(dest) });
}
function verifyClone(dest, url, sha, hostUid, staged = false) {
  inspectPath(dest, hostUid, false);
  if (!fs.existsSync(dest)) return false;
  // Only private host-created stages may be inspected as root. Existing clone
  // inspection must always drop to the agent UID before invoking Git.
  if (!staged && process.getuid() === 0 && fs.lstatSync(dest).uid !== 10001) fail('CLONE_LAYOUT');
  if (!fs.lstatSync(dest).isDirectory() || !fs.existsSync(path.join(dest, '.git')) ||
      !fs.lstatSync(path.join(dest, '.git')).isDirectory()) fail('CLONE_LAYOUT');
  safeTree(path.join(dest, '.git'));
  // Do not honor repository includes, worktree config, alternate object stores,
  // hooks or executable fsmonitor configuration from an agent-owned clone.
  // Existing clones are agent-owned. Never execute Git or parse their config as
  // privileged host, even if a writer races the read-only layout checks.
  const cfg = command(process.execPath, ['-e',
    "process.stdout.write(require('node:fs').readFileSync(process.argv[1], 'utf8'))",
    path.join(dest, '.git/config')], { env: inspectionEnv(), ...cloneIdentity(dest) });
  if (/^\s*\[\s*(include|includeIf|extensions)\b/im.test(cfg) ||
      fs.existsSync(path.join(dest, '.git/objects/info/alternates')) ||
      fs.existsSync(path.join(dest, '.git/shallow')) ||
      fs.existsSync(path.join(dest, '.git/config.worktree')) ||
      fs.existsSync(path.join(dest, '.git/commondir')) || /worktree\s*=/i.test(cfg)) fail('CLONE_LAYOUT');
  const origin = command('git', ['config', '--no-includes', '--file', path.join(dest, '.git/config'),
    '--get', 'remote.origin.url'], { env: inspectionEnv(), ...cloneIdentity(dest) });
  if (origin !== url) fail('ORIGIN');
  if (git(dest, ['rev-parse', 'HEAD^{commit}']) !== sha ||
      git(dest, ['rev-parse', '--is-bare-repository']) !== 'false') fail('SHA');
  if (/^160000 /m.test(git(dest, ['ls-files', '--stage']))) fail('CLONE_LAYOUT');
  if (git(dest, ['status', '--porcelain=v1', '--untracked-files=all', '--ignored', '--ignore-submodules=none'])) fail('DIRTY');
  return true;
}
function validateConfig(c, uid) {
  keys(c, ['hostUid', 'runtimeRoot', 'workspaces', 'stateDirectory', 'lockDirectory', 'verifier',
    'allowedRepositories', 'protectedPaths']);
  keys(c.workspaces, roles);
  if (!Number.isSafeInteger(c.hostUid) || c.hostUid < 0 || c.hostUid === 10001) fail('CONFIG');
  if (!Array.isArray(c.allowedRepositories) || c.allowedRepositories.length === 0 ||
      !Array.isArray(c.protectedPaths) || c.protectedPaths.length === 0) fail('CONFIG');
  for (const repo of c.allowedRepositories) validateRequest({ jobId: 'check', repository: repo,
    baseRef: 'main', baseSha: '0'.repeat(40) });
  const managed = [...Object.values(c.workspaces), c.stateDirectory, c.lockDirectory];
  const protectedPaths = [...c.protectedPaths, path.resolve(here, '../..'),
    '/etc', '/usr', '/bin', '/sbin', '/lib', '/lib64', '/dev', '/proc', '/sys', '/boot', '/run/secrets',
    ...['.ssh', '.aws', '.config', '.local/state'].map(p => path.join(process.env.HOME || '/root', p))];
  for (const p of [c.runtimeRoot, ...managed, c.verifier, ...c.protectedPaths]) components(p);
  for (const p of [c.runtimeRoot, ...managed]) {
    if (['/home', '/root', '/srv', '/var', '/opt', '/tmp', process.env.HOME].includes(p) ||
        protectedPaths.some(q => overlaps(p, q))) fail('PROTECTED');
    inspectPath(p, uid);
  }
  for (const p of Object.values(c.workspaces)) if (!p.startsWith(`${c.runtimeRoot}/`)) fail('PATH');
  for (const [i, p] of managed.entries()) for (const q of managed.slice(i + 1)) if (overlaps(p, q)) fail('OVERLAP');
  // Verifier, its parent chain and the config itself are never agent-writable.
  inspectPath(c.verifier, uid);
  if (!fs.statSync(c.verifier).isFile() || !(fs.statSync(c.verifier).mode & 0o100)) fail('VERIFIER');
}
function authorize(c, r) {
  if (!c.allowedRepositories.includes(r.repository)) fail('REPOSITORY');
  let a;
  try { a = JSON.parse(command(c.verifier, [], { input: JSON.stringify(r) + '\n', env: gitEnv() })); }
  catch { fail('AUTHORIZATION'); }
  keys(a, ['requesterId', 'role', 'enabled', 'jobId', 'repository', 'baseRef', 'baseSha', 'status', 'expiresAt']);
  if (typeof a.requesterId !== 'string' || typeof a.expiresAt !== 'string' || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(a.requesterId) ||
      !['control', 'developer', 'reviewer'].includes(a.role) || a.enabled !== true ||
      a.status !== 'active' || !Number.isFinite(Date.parse(a.expiresAt)) ||
      Date.parse(a.expiresAt) <= Date.now() || fields.some(k => a[k] !== r[k])) fail('AUTHORIZATION');
  return a;
}
function syncDirectory(p) { const fd = fs.openSync(p, 'r'); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); } }
function persist(file, value) {
  try {
    const fd = fs.openSync(file, 'wx', 0o600);
    try { fs.writeFileSync(fd, JSON.stringify(value) + '\n'); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    syncDirectory(path.dirname(file));
  } catch { fail('AUDIT'); }
}
function ownTree(p, uid) {
  const s = fs.lstatSync(p);
  // Never follow a repository symlink while assigning ownership.
  fs.lchownSync(p, uid, uid);
  if (s.isDirectory()) for (const n of fs.readdirSync(p)) ownTree(path.join(p, n), uid);
}

// Exported for isolated unprivileged fixtures. The CLI always uses UID 0/10001;
// there is deliberately no test-mode CLI flag or environment bypass.
export function provision(c, input, { hostUid = c.hostUid, agentUid = 10001 } = {}) {
  const r = validateRequest(input);
  validateConfig(c, hostUid);
  let a = authorize(c, r); // no mutation, including audit/lock creation, before auth
  const destinations = roles.map(role => path.join(c.workspaces[role], r.repository));
  const url = `https://github.com/${r.repository}.git`;
  const preflight = () => {
    validateConfig(c, hostUid);
    return destinations.map(dest => verifyClone(dest, url, r.baseSha, hostUid));
  };
  // Roots/state/lock are host-prepared, not recursively chowned or adopted here.
  for (const p of [...Object.values(c.workspaces), c.stateDirectory, c.lockDirectory]) {
    if (!fs.statSync(p).isDirectory()) fail('HOST_PREPARATION');
    if ([c.stateDirectory, c.lockDirectory].includes(p) && (fs.statSync(p).mode & 0o077)) fail('PATH_TRUST');
  }
  const lock = path.join(c.lockDirectory, 'provision.lock');
  inspectPath(lock, hostUid);
  if (!fs.existsSync(lock)) fail('HOST_PREPARATION');
  // Same flock inode/name as both existing provisioning scripts; no recursive
  // lock acquisition or stale mkdir lock.
  return withLock(lock, () => {
    a = authorize(c, r);
    const receiptId = randomUUID();
    const receipt = { receiptId, requesterId: a.requesterId, jobId: r.jobId,
      repository: r.repository, baseRef: r.baseRef, baseSha: r.baseSha,
      timestamp: new Date().toISOString(), result: 'started', roles: {} };
    const key = createHash('sha256').update(r.jobId).digest('hex');
    const binding = path.join(c.stateDirectory, `${key}.json`);
    inspectPath(binding, hostUid);
    const bound = { requesterId: a.requesterId, ...r };
    if (fs.existsSync(binding)) {
      if (fs.readFileSync(binding, 'utf8') !== JSON.stringify(bound) + '\n') fail('JOB_REUSE');
    } else persist(binding, bound);
    persist(path.join(c.stateDirectory, `${receiptId}.started.json`), receipt);
    const stages = [];
    try {
      const existing = preflight();
      for (const [i, dest] of destinations.entries()) {
        if (existing[i]) { receipt.roles[roles[i]] = 'unchanged'; continue; }
        const parent = path.dirname(dest);
        inspectPath(parent, hostUid);
        if (!fs.existsSync(parent)) fs.mkdirSync(parent, { mode: 0o755 });
        inspectPath(parent, hostUid);
        // Staging on the target filesystem permits atomic per-role rename.
        const container = fs.mkdtempSync(path.join(parent, '.provision-'));
        fs.chmodSync(container, 0o700);
        const stage = path.join(container, 'checkout');
        stages.push(container);
        command('bash', [path.join(here, 'repository-clone.sh'), url, r.baseRef, stage, r.baseSha], { env: gitEnv() });
        verifyClone(stage, url, r.baseSha, hostUid, true);
      }
      // Refresh authoritative job after network work; revocation/expiry fails closed.
      const refreshed = authorize(c, r);
      if (refreshed.requesterId !== a.requesterId || refreshed.role !== a.role) fail('AUTHORIZATION');
      preflight();
      let stageIndex = 0;
      for (const [i, dest] of destinations.entries()) {
        if (existing[i]) continue;
        inspectPath(dest, hostUid, false);
        if (fs.existsSync(dest)) fail('CONFLICT');
        const stage = path.join(stages[stageIndex++], 'checkout');
        const current = authorize(c, r);
        if (current.requesterId !== a.requesterId || current.role !== a.role) fail('AUTHORIZATION');
        ownTree(stage, agentUid);
        fs.renameSync(stage, dest);
        syncDirectory(path.dirname(dest));
        receipt.roles[roles[i]] = 'created';
      }
      receipt.result = 'success';
      persist(path.join(c.stateDirectory, `${receiptId}.result.json`), receipt);
      return receipt;
    } catch (e) {
      receipt.result = 'failed';
      receipt.error = e instanceof ProvisionError ? e.code : 'IO';
      persist(path.join(c.stateDirectory, `${receiptId}.result.json`), receipt);
      fail(receipt.error);
    } finally {
      for (const p of stages) fs.rmSync(p, { recursive: true, force: true });
    }
  });
}

// flock uses an inherited file description, shared with the host process.
function withLock(lock, work) {
  // flock on an inherited descriptor survives child exit while this process holds
  // the same open file description. No helper process or lock-held env switch.
  const fd = fs.openSync(lock, fs.constants.O_RDWR | fs.constants.O_NOFOLLOW, 0o600);
  try {
    const s = fs.fstatSync(fd);
    if (!s.isFile() || s.nlink !== 1 || (s.mode & 0o022)) fail('LOCK');
    command('flock', ['-n', '3'], { stdio: ['pipe', 'pipe', 'pipe', fd] });
    return work();
  } finally { fs.closeSync(fd); }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.getuid() !== 0 || process.argv.length !== 3) fail('HOST_ONLY');
    inspectPath(here);
    inspectPath(path.join(here, 'repository-clone.sh'));
    const configFile = process.argv[2];
    inspectPath(configFile);
    const s = fs.statSync(configFile);
    if (!s.isFile() || s.nlink !== 1 || (s.mode & 0o077)) fail('CONFIG');
    const input = fs.readFileSync(0, 'utf8');
    if (Buffer.byteLength(input) > 4096) fail('REQUEST');
    const c = JSON.parse(fs.readFileSync(configFile, 'utf8'));
    console.log(JSON.stringify(provision(c, JSON.parse(input))));
  } catch (e) {
    console.log(JSON.stringify({ result: 'rejected', error: e instanceof ProvisionError ? e.code : 'IO' }));
    process.exitCode = 1;
  }
}
