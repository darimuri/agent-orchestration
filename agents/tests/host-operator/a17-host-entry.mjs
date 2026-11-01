// Disposable P2 test entry only. No production bootstrap, policy or reporting authority.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const ROOT = '/home/dormael/.local/share/host-operator-a17-disposable';
export const UNIT = 'host-operator.service';
export const RUNTIME_DIGEST = 'fde6a4bf8d0562f7751d1a2d6cb9b417c4cfe107bbcb0aa3e9a24e125e348f48';
const install = ROOT + '/install';
const entry = install + '/agents/tests/host-operator/a17-host-entry.mjs';
const runtime = ROOT + '/runtime/node';
const manager = '/usr/bin/systemctl', runner = '/usr/bin/systemd-run';
const environment = Object.freeze({ XDG_RUNTIME_DIR: '/run/user/1000', DBUS_SESSION_BUS_ADDRESS: 'unix:path=/run/user/1000/bus', LANG: 'C.UTF-8', TZ: 'UTC' });
export const PROPERTIES = Object.freeze({ Type: 'exec', ExitType: 'main', Delegate: 'yes', DelegateSubgroup: 'supervisor', RemainAfterExit: 'no', Restart: 'no', KillMode: 'control-group', KillSignal: 'SIGTERM', FinalKillSignal: 'SIGKILL', SendSIGKILL: 'yes', TimeoutStopSec: '2s', UMask: '0077', NoNewPrivileges: 'yes', CapabilityBoundingSet: '', AmbientCapabilities: '', StandardOutput: 'null', StandardError: 'null', UnsetEnvironment: 'PATH HOME LOGNAME USER SHELL MANAGERPID NOTIFY_SOCKET WATCHDOG_PID WATCHDOG_USEC MEMORY_PRESSURE_WATCH MEMORY_PRESSURE_WRITE' });
const baseSha = '0ecde076bacecc853ec25eb764bb81d42b56f1ae';
const source = Object.freeze({ repository: 'darimuri/agent-orchestration', baseRef: 'main', baseSha, workspaceId: 'a17-disposable-fixture', sourceDigest: createHash('sha256').update('A17 disposable kernel fixture only').digest('hex') });
const deny = () => { throw Error('a17_host_denied'); };
const hash = b => createHash('sha256').update(b).digest('hex');
const fingerprint = s => [s.dev, s.ino, s.uid, s.gid, s.mode, s.nlink, s.size, s.mtimeNs, s.ctimeNs].join(':');
function exact(v, keys) { if (!v || Object.getPrototypeOf(v) !== Object.prototype || Object.keys(v).sort().join() !== [...keys].sort().join()) deny(); }
function directory(name, privateLeaf = false) {
  if (fs.realpathSync(name) !== name) deny();
  for (let p = name; ; p = path.dirname(p)) {
    const s = fs.lstatSync(p);
    if (!s.isDirectory() || ![0, 1000].includes(s.uid) || (s.mode & 0o7022) || (p === name && privateLeaf && (s.uid !== 1000 || (s.mode & 0o7777) !== 0o700))) deny();
    if (p === '/') break;
  }
}
function read(name, limit, privateFile = false) {
  directory(path.dirname(name));
  const before = fs.lstatSync(name, { bigint: true });
  if (!before.isFile() || ![0n, 1000n].includes(before.uid) || before.nlink !== 1n || (before.mode & 0o7022n) || before.size < 1n || before.size > BigInt(limit) || (privateFile && (before.uid !== 1000n || (before.mode & 0o7777n) !== 0o400n))) deny();
  const fd = fs.openSync(name, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    if (fingerprint(before) !== fingerprint(fs.fstatSync(fd, { bigint: true }))) deny();
    const bytes = Buffer.alloc(Number(before.size) + 1), n = fs.readSync(fd, bytes, 0, bytes.length, 0);
    if (n !== Number(before.size) || fingerprint(before) !== fingerprint(fs.fstatSync(fd, { bigint: true })) || fingerprint(before) !== fingerprint(fs.lstatSync(name, { bigint: true }))) deny();
    return bytes.subarray(0, n);
  } finally { fs.closeSync(fd); }
}
function pin(name, digest, limit) { if (!/^[a-f0-9]{64}$/.test(digest) || hash(read(name, limit)) !== digest) deny(); }
export function parseConfig(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length > 1048576) deny();
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) deny();
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const c = JSON.parse(text);
  // Canonical encoding also excludes duplicate keys/BOM and ambiguous spellings.
  if (JSON.stringify(c) + '\n' !== text) deny();
  exact(c, ['version', 'managerDigest', 'runnerDigest', 'helperDigest', 'workerDigest', 'files', 'baselineEvidenceDigest']);
  if (c.version !== 1) deny();
  for (const k of ['managerDigest', 'runnerDigest', 'helperDigest', 'workerDigest', 'baselineEvidenceDigest']) if (!/^[a-f0-9]{64}$/.test(c[k])) deny();
  if (!c.files || Object.getPrototypeOf(c.files) !== Object.prototype || Object.keys(c.files).length < 3 || Object.keys(c.files).length > 4096) deny();
  for (const [name, value] of Object.entries(c.files)) if (name.length > 4096 || !/^agents\/(?:[a-zA-Z0-9_-]+\/)*[a-zA-Z0-9_.-]+$/.test(name) || name.split('/').some(n => n === '.' || n === '..') || !/^[a-f0-9]{64}$/.test(value)) deny();
  for (const name of ['agents/tests/host-operator/a17-host-entry.mjs', 'agents/host-operator-auth/cgroup-revision-supervisor.mjs', 'agents/host-operator-auth/supervised-revision-worker.mjs']) if (!Object.hasOwn(c.files, name)) deny();
  return c;
}
export function launchPlan() {
  return { unit: UNIT, command: runner, argv: ['--user', '--unit=' + UNIT, '--service-type=exec', '--quiet',
    ...Object.entries(PROPERTIES).map(([k, v]) => '--property=' + k + '=' + v),
    '--property=Environment=XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus LANG=C.UTF-8 TZ=UTC',
    '--', runtime, entry, '--service'], environment: { ...environment } };
}
function command(file, args, absentQuery = false) {
  const r = spawnSync(file, args, { env: environment, encoding: 'utf8', timeout: 2000, maxBuffer: 16384, shell: false });
  if (r.error || !(absentQuery ? [0, 1] : [0]).includes(r.status) || r.signal || r.stderr) deny();
  return r.stdout;
}
export function parseProperties(text) {
  if (typeof text !== 'string' || text.length > 16384 || !text.endsWith('\n')) deny();
  const values = {};
  for (const line of text.slice(0, -1).split('\n')) { const i = line.indexOf('='); if (i < 1 || Object.hasOwn(values, line.slice(0, i))) deny(); values[line.slice(0, i)] = line.slice(i + 1); }
  return values;
}
function show(keys, absentQuery = false) { return parseProperties(command(manager, ['--user', 'show', UNIT, '--no-pager', ...keys.map(k => '--property=' + k)], absentQuery)); }
function absent(name) { try { fs.lstatSync(name); deny(); } catch (e) { if (e.code !== 'ENOENT') throw e; } }
function validate(service = false) {
  if (process.platform !== 'linux' || process.version !== 'v22.23.3' || [process.getuid(), process.geteuid(), process.getgid(), process.getegid()].some(n => n !== 1000) || process.execPath !== runtime || fs.realpathSync('/proc/self/exe') !== runtime || fileURLToPath(import.meta.url) !== entry || process.execArgv.length) deny();
  if (Object.keys(process.env).some(k => !['XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS', 'LANG', 'TZ', ...(service ? ['INVOCATION_ID', 'JOURNAL_STREAM', 'SYSTEMD_EXEC_PID'] : [])].includes(k)) || Object.entries(environment).some(([k, v]) => process.env[k] !== v)) deny();
  directory(ROOT, true); directory(install, true); directory(ROOT + '/control', true); directory(ROOT + '/source', true);
  const bytes = read(ROOT + '/config.json', 1048576, true), c = parseConfig(bytes);
  pin(runtime, RUNTIME_DIGEST, 268435456); pin(manager, c.managerDigest, 16777216); pin(runner, c.runnerDigest, 16777216); pin(ROOT + '/native/revision-supervisor', c.helperDigest, 16777216);
  // Inventory is complete for the disposable installation, not a list of exceptions.
  const found = [];
  function walk(dir, prefix = '') { for (const name of fs.readdirSync(dir).sort()) { const rel = prefix + name, full = path.join(dir, name), s = fs.lstatSync(full); if (s.isDirectory()) { directory(full); walk(full, rel + '/'); } else { if (!Object.hasOwn(c.files, rel)) deny(); pin(full, c.files[rel], 16777216); found.push(rel); } } }
  walk(install); if (found.length !== Object.keys(c.files).length || c.files['agents/host-operator-auth/supervised-revision-worker.mjs'] !== c.workerDigest) deny();
  if (read(ROOT + '/source/.git/HEAD', 41).toString() !== baseSha + '\n') deny();
  const inventory = JSON.parse(read(ROOT + '/control/artifacts.json', 1048576));
  exact(inventory, ['version', 'issuerDigest', 'files']);
  const authFiles = Object.fromEntries(Object.entries(c.files).filter(([k]) => k.startsWith('agents/host-operator-auth/')).map(([k, v]) => [k.slice('agents/host-operator-auth/'.length), v]));
  if (inventory.version !== 1 || inventory.issuerDigest !== authFiles['supervised-revision.mjs'] || !inventory.files || Object.keys(inventory.files).sort().join() !== Object.keys(authFiles).sort().join() || Object.entries(authFiles).some(([k, v]) => inventory.files[k] !== v)) deny();
  if (hash(read(ROOT + '/baseline.evidence', 1048576, true)) !== c.baselineEvidenceDigest) deny();
  if (service) { if (fs.readdirSync(ROOT + '/control').sort().join() !== 'artifacts.json,attempt.json') deny(); }
  else {
    const version = command(manager, ['--version']);
    if (!/^systemd (?:25[5-9]|2[6-9][0-9]|[3-9][0-9]{2})(?:[ .\n])/.test(version)) deny();
    const delegation = '/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service';
    if (Number(fs.statfsSync(delegation).type) !== 0x63677270) deny();
    fs.accessSync(delegation, fs.constants.R_OK | fs.constants.W_OK | fs.constants.X_OK);
    absent(ROOT + '/control/attempt.json'); absent(ROOT + '/control/result.json');
    if (fs.readdirSync(ROOT + '/control').join() !== 'artifacts.json') deny();
    validateUnitAbsence(show(['LoadState', 'ActiveState', 'UnitFileState', 'FragmentPath', 'ControlGroup'], true));
  }
  if (!read(ROOT + '/config.json', 1048576, true).equals(bytes)) deny();
  return c;
}
function exclusive(name, value) {
  const fd = fs.openSync(ROOT + '/control/' + name, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(value) + '\n'); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  const d = fs.openSync(ROOT + '/control', fs.constants.O_RDONLY | fs.constants.O_DIRECTORY); try { fs.fsyncSync(d); } finally { fs.closeSync(d); }
}
export function validateUnitAbsence(v) {
  exact(v, ['LoadState', 'ActiveState', 'UnitFileState', 'FragmentPath', 'ControlGroup']);
  if (v.LoadState !== 'not-found' || v.ActiveState !== 'inactive' || v.UnitFileState !== '' || v.FragmentPath !== '' || v.ControlGroup !== '') deny();
}
export function validateService(values, invocationId, pid, cgroup) {
  exact(values, ['InvocationID', 'ControlGroup', 'MainPID']);
  if (!/^[a-f0-9]{32}$/.test(invocationId ?? '') || values.InvocationID !== invocationId || values.MainPID !== String(pid) || !/^\/user.slice\/user-1000.slice\/user@1000.service\/(?:[A-Za-z0-9_.@-]+\/)*host-operator.service$/.test(values.ControlGroup) || cgroup !== '0::' + values.ControlGroup + '/supervisor\n') deny();
  return values.ControlGroup;
}
async function service() {
  const c = validate(true), invocationId = process.env.INVOCATION_ID;
  const attemptStat = fs.lstatSync(ROOT + '/control/attempt.json');
  if (attemptStat.uid !== 1000 || (attemptStat.mode & 0o7777) !== 0o600 || read(ROOT + '/control/attempt.json', 256).toString() !== JSON.stringify({ version: 1, status: 'UNKNOWN', unit: UNIT }) + '\n') deny();
  if (!/^[a-f0-9]{32}$/.test(invocationId ?? '')) deny();
  const v = show(['InvocationID', 'ControlGroup', 'MainPID']);
  validateService(v, invocationId, process.pid, fs.readFileSync('/proc/self/cgroup', 'utf8'));
  if (process.env.SYSTEMD_EXEC_PID && process.env.SYSTEMD_EXEC_PID !== String(process.pid)) deny();
  exclusive('started.json', { version: 1, status: 'UNKNOWN', invocationId });
  // Actual production factory only; there is no injection point for a kernel facade.
  const { createCgroupRevisionSupervisor } = await import(pathToFileURL(install + '/agents/host-operator-auth/cgroup-revision-supervisor.mjs'));
  const backend = createCgroupRevisionSupervisor({ uid: 1000, unitName: UNIT, invocationId, controlGroup: v.ControlGroup, cgroupMount: '/sys/fs/cgroup', controlDirectory: ROOT + '/control', sourceDirectory: ROOT + '/source', source, clockId: 'a17-disposable-clock', runtimePath: runtime, runtimeDigest: RUNTIME_DIGEST, workerPath: install + '/agents/host-operator-auth/supervised-revision-worker.mjs', workerDigest: c.workerDigest, helperPath: ROOT + '/native/revision-supervisor', helperDigest: c.helperDigest, managerPath: manager, managerDigest: c.managerDigest, managerEnvironment: { ...environment } });
  const startedAt = Date.now(), runId = 'a17-disposable-run', requestHash = hash('a17-test-request'), intentDigest = hash('a17-test-intent');
  const answer = await backend.run({ executable: runtime, entry: install + '/agents/host-operator-auth/supervised-revision-worker.mjs', input: JSON.stringify({ sourceDirectory: ROOT + '/source', uid: 1000, source, runId, requestHash, intentDigest, startedAt }), stdoutLimitBytes: 4096, stderrLimitBytes: 4096, inputLimitBytes: 8192, env: { LANG: 'C.UTF-8', TZ: 'UTC' }, runId, requestHash, intentDigest, workerArtifactDigest: c.workerDigest, clockId: 'a17-disposable-clock', startedAt, deadline: startedAt + 5000, settlementWaitMs: 10000 });
  // Raw output/proof is never copied into a journal, reporter or completion claim.
  const settled = answer?.status === 'settled';
  let observed = false;
  if (settled && answer.boundary.exitCode === 0 && answer.boundary.signal === null && answer.stderr === '') {
    try { const r = JSON.parse(answer.stdout); exact(r, ['status', 'repository', 'workspaceId', 'expectedSha', 'observedSha', 'observedAt', 'runId', 'requestHash', 'intentDigest']); observed = r.repository === source.repository && r.workspaceId === source.workspaceId && r.observedAt === startedAt && r.status === 'observed' && r.observedSha === baseSha && r.expectedSha === baseSha && r.runId === runId && r.requestHash === requestHash && r.intentDigest === intentDigest; } catch { /* UNKNOWN */ }
  }
  exclusive('result.json', { version: 1, status: settled && observed ? 'fixture_observed' : 'UNKNOWN', invocationId, cleanup: 'OWNER_INSPECTION_REQUIRED' });
  if (!settled) process.exitCode = 70;
  else if (!observed) process.exitCode = 1;
}
export async function main(args) {
  if (args.length !== 1) deny();
  if (args[0] === '--plan') return { status: 'NO_ACTION', plan: launchPlan(), cleanup: 'OWNER_INSPECTION_REQUIRED', hostAcceptance: 'NOT_READY' };
  if (args[0] === '--validate') { validate(); return { status: 'VALIDATED_NO_ACTION', hostAcceptance: 'NOT_READY' }; }
  if (args[0] === '--run-disposable') {
    const c = validate(); exclusive('attempt.json', { version: 1, status: 'UNKNOWN', unit: UNIT });
    const p = launchPlan();
    // Never retry a lost response. Never stop an unbound service or remove data.
    pin(runner, c.runnerDigest, 16777216);
    command(p.command, p.argv);
    return { status: 'DISPATCHED_NOT_VERIFIED', cleanup: 'OWNER_INSPECTION_REQUIRED', hostAcceptance: 'NOT_READY' };
  }
  if (args[0] === '--service') { await service(); return { status: 'TEST_ENTRY_EXIT', hostAcceptance: 'NOT_READY' }; }
  deny();
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { console.log(JSON.stringify(await main(process.argv.slice(2)))); }
  catch { console.error('{"status":"UNKNOWN","code":"a17_host_denied","cleanup":"OWNER_INSPECTION_REQUIRED","hostAcceptance":"NOT_READY"}'); process.exitCode = 70; }
}
