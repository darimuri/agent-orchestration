// Source-only tests. No mode, environment variable or fixture starts a live unit.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { main, launchPlan, parseConfig, parseProperties, validateService, validateUnitAbsence, ROOT, UNIT, PROPERTIES } from '../tests/host-operator/a17-host-entry.mjs';
const entry = fileURLToPath(new URL('../tests/host-operator/a17-host-entry.mjs', import.meta.url));
const driver = fileURLToPath(new URL('./test-host-operator-a17-host.sh', import.meta.url));
const config = () => ({ version: 1, managerDigest: '1'.repeat(64), runnerDigest: '2'.repeat(64), helperDigest: '3'.repeat(64), workerDigest: '4'.repeat(64), files: { 'agents/tests/host-operator/a17-host-entry.mjs': '5'.repeat(64), 'agents/host-operator-auth/cgroup-revision-supervisor.mjs': '6'.repeat(64), 'agents/host-operator-auth/supervised-revision-worker.mjs': '4'.repeat(64) }, baselineEvidenceDigest: '7'.repeat(64) });
const encode = c => Buffer.from(JSON.stringify(c) + '\n');
test('planning has no host admission or side effects and returns exact direct argv', async () => {
  const r = await main(['--plan']); assert.equal(r.status, 'NO_ACTION'); assert.equal(r.hostAcceptance, 'NOT_READY');
  const p = launchPlan(); assert.equal(p.unit, UNIT); assert.equal(p.command, '/usr/bin/systemd-run');
  assert.deepEqual(p.argv.slice(-4), ['--', ROOT + '/runtime/node', ROOT + '/install/agents/tests/host-operator/a17-host-entry.mjs', '--service']);
  for (const [k, v] of Object.entries(PROPERTIES)) assert(p.argv.includes('--property=' + k + '=' + v));
  assert.equal(PROPERTIES.Restart, 'no'); assert.equal(PROPERTIES.DelegateSubgroup, 'supervisor');
  assert.equal(PROPERTIES.KillMode, 'control-group');
  assert(!p.argv.some(a => /enable|restart|PIDFile|socket|bash/.test(a)));
  assert.deepEqual(Object.keys(p.environment).sort(), ['DBUS_SESSION_BUS_ADDRESS', 'LANG', 'TZ', 'XDG_RUNTIME_DIR']);
  p.argv.push('bad'); assert(!launchPlan().argv.includes('bad'));
});
test('canonical bounded immutable config accepts only the fixed inventory schema', () => {
  assert.deepEqual(parseConfig(encode(config())), config());
  for (const key of Object.keys(config())) { const c = config(); delete c[key]; assert.throws(() => parseConfig(encode(c))); }
  for (const key of ['command', 'argv', 'env', 'mount', 'unitName', 'path', 'kernel', 'verified']) { const c = config(); c[key] = 'canary'; assert.throws(() => parseConfig(encode(c))); }
  for (const name of ['../outside', '/etc/passwd', 'agents/../outside', 'agents/a/../../x', 'agents/a\nfile', 'agents/a//file']) { const c = config(); c.files[name] = 'a'.repeat(64); assert.throws(() => parseConfig(encode(c))); }
  for (const key of ['managerDigest', 'runnerDigest', 'helperDigest', 'workerDigest', 'baselineEvidenceDigest']) { const c = config(); c[key] = 'bad'; assert.throws(() => parseConfig(encode(c))); }
  assert.throws(() => parseConfig(Buffer.from('{"version":1,"version":2}\n')));
  assert.throws(() => parseConfig(Buffer.from([255]))); assert.throws(() => parseConfig(Buffer.alloc(1048577)));
  assert.throws(() => parseConfig(Buffer.from(JSON.stringify(config(), null, 2))));
});
test('actual invocation binding rejects sibling units, manager mismatch and unsealed placement', () => {
  const group = '/user.slice/user-1000.slice/user@1000.service/app.slice/host-operator.service';
  const id = 'a'.repeat(32), values = { InvocationID: id, ControlGroup: group, MainPID: '1234' };
  assert.equal(validateService(values, id, 1234, '0::' + group + '/supervisor\n'), group);
  for (const [k, v] of [['InvocationID', 'b'.repeat(32)], ['MainPID', '1'], ['ControlGroup', group + '-other'], ['ControlGroup', '/other/host-operator.service']]) assert.throws(() => validateService({ ...values, [k]: v }, id, 1234, '0::' + group + '/supervisor\n'));
  for (const cgroup of ['0::' + group + '\n', '0::' + group + '/worker\n', '0::/\n', '']) assert.throws(() => validateService(values, id, 1234, cgroup));
  assert.throws(() => validateService({ ...values, extra: true }, id, 1234, '0::' + group + '/supervisor\n'));
});
test('manager property parser refuses duplicates, malformed and unterminated data', () => {
  assert.deepEqual(parseProperties('MainPID=42\nControlGroup=/fixed\n'), { MainPID: '42', ControlGroup: '/fixed' });
  for (const s of ['', 'MainPID=42', 'MainPID=1\nMainPID=2\n', '=x\n', 'bad\n']) assert.throws(() => parseProperties(s));
});
test('unknown arguments cannot select requests or execution', async () => {
  for (const args of [[], ['--plan', '--run-disposable'], ['--start'], ['status.revision'], ['--command=touch'], ['--env=A=1']]) await assert.rejects(main(args));
});
test('ordinary source invocation fails closed even with activation environment flags', () => {
  for (const arg of ['--validate', '--service', '--run-disposable']) {
    // Wrong fixed process.execPath/source location denies before manager or file writes.
    const r = spawnSync(process.execPath, [entry, arg], { encoding: 'utf8', env: { LANG: 'C.UTF-8', TZ: 'UTC', HOST_OPERATOR_ACTIVATE: '1', HOST_OPERATOR_TEST_LIVE: '1' }, timeout: 5000 });
    assert.equal(r.status, 70); assert.equal(r.stdout, ''); assert.deepEqual(JSON.parse(r.stderr), { status: 'UNKNOWN', code: 'a17_host_denied', cleanup: 'OWNER_INSPECTION_REQUIRED', hostAcceptance: 'NOT_READY' });
  }
});
test('shell syntax and negative fixtures never launch a unit', () => {
  const syntax = spawnSync('/bin/bash', ['-n', driver]); assert.equal(syntax.status, 0);
  for (const args of [[], ['--service'], ['--plan', 'extra'], ['--command', 'true'], ['--env=LIVE=1']]) {
    const r = spawnSync('/bin/bash', [driver, ...args], { encoding: 'utf8', env: { LANG: 'C.UTF-8', TZ: 'UTC', HOST_OPERATOR_ACTIVATE: '1' } });
    assert.equal(r.status, 2); assert.equal(r.stdout, ''); assert.equal(JSON.parse(r.stderr).status, 'NO_ACTION');
  }
  const r = spawnSync('/bin/bash', [driver, '--plan'], { encoding: 'utf8', env: { LANG: 'C.UTF-8', TZ: 'UTC', NODE_OPTIONS: '--definitely-invalid-option', HOST_OPERATOR_ACTIVATE: '1' } });
  assert.equal(r.status, 0, r.stderr); assert.equal(JSON.parse(r.stdout).status, 'NO_ACTION');
});
test('entry imports real backend only after validation and has no runtime fixture facade', () => {
  const s = fs.readFileSync(entry, 'utf8');
  assert(!/node:vm|SyntheticModule|runSyntheticSupervisor|kernelFacade/.test(s));
  assert(s.indexOf('const c = validate(true)') < s.indexOf('await import(pathToFileURL'));
  assert(!/unlinkSync|rmSync|rmdirSync|sudo|docker|reset-failed/.test(s));
  assert(s.includes("exclusive('started.json'")); assert(s.includes("exclusive('attempt.json'"));
});

test('any loaded, installed, failed, inactive retained unit or cgroup collision denies', () => {
  const empty = { LoadState: 'not-found', ActiveState: 'inactive', UnitFileState: '', FragmentPath: '', ControlGroup: '' };
  assert.doesNotThrow(() => validateUnitAbsence(empty));
  for (const [key, value] of [['LoadState', 'loaded'], ['LoadState', 'masked'], ['ActiveState', 'failed'], ['ActiveState', 'active'], ['UnitFileState', 'enabled'], ['UnitFileState', 'static'], ['FragmentPath', '/fixed/unit'], ['ControlGroup', '/existing']]) assert.throws(() => validateUnitAbsence({ ...empty, [key]: value }));
  assert.throws(() => validateUnitAbsence({ ...empty, MainPID: '0' }));
});
