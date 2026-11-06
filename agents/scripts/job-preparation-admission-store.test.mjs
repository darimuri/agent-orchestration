// All UID/root/authority fixtures below are SIMULATED. No Polkit, root service,
// system bus, live ledger or managed workspace is accessed or accepted here.
import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { fork } from 'node:child_process';
import { createAdmissionStore } from '../job-preparation/admission-store.mjs';
import { canonical, digest, DEVELOPER_CAPABILITIES, canonicalIntent } from '../job-preparation/intent.mjs';

const epoch = Date.parse('2026-11-06T20:00:00.000Z'), id = '1'.repeat(32);
const config = () => ({ version: 1, ownerId: 'owner', developerAgentId: 'developer-a', repository: 'example/project', baseRef: 'main', baseSha: 'a'.repeat(40), policyVersion: 'p1', capabilityProfileVersion: 'developer-v1', capabilityProfileDigest: digest({ version: 'developer-v1', role: 'developer', capabilities: DEVELOPER_CAPABILITIES }), slotNamespace: 'managed-v1', approvalLifetimeMs: 10000, jobLifetimeMs: 20000, authorityTimeoutMs: 50 });
const proposal = (change = {}) => JSON.stringify({ version: 1, requestId: id, jobId: 'age7-prejob', repository: 'example/project', baseRef: 'main', baseSha: 'a'.repeat(40), approvalExpiresAt: new Date(epoch + 10000).toISOString(), jobExpiresAt: new Date(epoch + 20000).toISOString(), taskId: 'task7', assignmentId: 'assignment7', channelId: '00000000-0000-0000-0000-000000000000', threadId: 'b'.repeat(64), ...change });
const authority = binding => ({ ...binding, authorityId: 'fixture-only-authority', authorizedAt: epoch, validUntil: epoch + 9999, stillValid: () => true });
const actualUid = process.getuid();
function simulateCustody() {
  // Patch platform metadata only, exercising real filesystem I/O as UID10001.
  // Production constructor has no uid/fs/mock option and always requires root.
  for (const key of ['lstatSync', 'fstatSync']) {
    const original = fs[key]; mock.method(fs, key, (...args) => {
      const s = original(...args), big = typeof s.uid === 'bigint';
      const copy = Object.assign(Object.create(Object.getPrototypeOf(s)), s);
      if (Number(s.uid) === actualUid || Number(s.uid) === 0) copy.uid = big ? 0n : 0;
      if (s.isDirectory() && key === 'lstatSync' && ['/', '/tmp', '/workspace', '/workspace/.scratch'].includes(args[0])) copy.mode = big ? s.mode & ~0o7022n : s.mode & ~0o7022;
      return copy;
    });
  }
  mock.method(process, 'getuid', () => 0);
}
function fixture(t, change = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'prejob-fixture-')); fs.chmodSync(directory, 0o700); simulateCustody();
  t.after(() => { mock.restoreAll(); fs.rmSync(directory, { recursive: true, force: true }); });
  let time = epoch, calls = 0;
  const options = { directory, policy: config(), clock: () => time, decisionAuthority: b => { calls++; return authority(b); }, ...change };
  return { directory, options, store: createAdmissionStore(options), setTime: n => { time = n; }, calls: () => calls };
}
const count = directory => fs.readdirSync(directory).length;
const phase = result => result.phase;
function child(directory, action, extra = {}) {
  const cp = fork(fileURLToPath(import.meta.url), ['--fixture-worker', directory, action, JSON.stringify(extra)], { stdio: ['ignore', 'ignore', 'pipe', 'ipc'], env: { PATH: process.env.PATH } });
  let stderr = ''; cp.stderr.on('data', b => { stderr += b; });
  const ready = new Promise((resolve, reject) => { cp.once('message', resolve); cp.once('error', reject); });
  const result = new Promise((resolve, reject) => { cp.on('message', m => { if (m.result) resolve(m.result); }); cp.on('exit', (code, signal) => { if (signal) resolve({ signal }); else if (code) reject(Error(stderr || `worker:${code}`)); }); cp.once('error', reject); });
  return { cp, ready, result };
}

if (process.argv[2] === '--fixture-worker') {
  simulateCustody();
  const directory = process.argv[3], action = process.argv[4], extra = JSON.parse(process.argv[5]);
  const options = { directory, policy: config(), clock: () => extra.expire ? epoch + 10000 : epoch, decisionAuthority: authority };
  const store = createAdmissionStore(options);
  if (extra.crash) {
    const original = fs[extra.crash], target = extra.target ?? 1; let calls = 0;
    mock.method(fs, extra.crash, (...args) => { const result = original(...args); if (++calls === target) process.kill(process.pid, 'SIGKILL'); return result; });
  }
  process.send({ ready: true }); await new Promise(resolve => process.once('message', resolve));
  const result = action === 'submit' ? store.submit(proposal(extra.proposal)) : action === 'reserve' ? store.reserve(id) : await store.decide(id, action);
  process.send({ result: { ...result, token: result.token ? 'instance-local' : undefined } }); process.disconnect();
} else {
  test('production custody has no public UID override; constructor creates nothing', t => {
    const d = fs.mkdtempSync(path.join(os.tmpdir(), 'prejob-untrusted-')); t.after(() => fs.rmSync(d, { recursive: true, force: true }));
    assert.throws(() => createAdmissionStore({ directory: d, policy: config(), clock: () => epoch, decisionAuthority: authority }));
    assert.throws(() => createAdmissionStore({ directory: d, uid: actualUid, policy: config(), clock: () => epoch, decisionAuthority: authority })); assert.equal(count(d), 0);
  });

  test('submit/inspect are inert; decision is authenticated; reservation token is one-shot and instance-local', async t => {
    const f = fixture(t); assert.equal(phase(f.store.inspect(id)), 'absent'); assert.equal(count(f.directory), 0);
    const pending = f.store.submit(proposal()); assert.equal(pending.phase, 'pending'); assert.equal(f.calls(), 0); assert.equal(count(f.directory), 2);
    assert.deepEqual(f.store.submit(proposal()), pending); assert.equal(phase(f.store.submit(proposal({ taskId: 'different' }))), 'conflict');
    const snapshot = fs.readdirSync(f.directory).map(n => [n, fs.readFileSync(path.join(f.directory, n), 'utf8')]);
    assert.equal(phase(f.store.inspect(id)), 'pending'); assert.deepEqual(snapshot, fs.readdirSync(f.directory).map(n => [n, fs.readFileSync(path.join(f.directory, n), 'utf8')]));
    const approved = await f.store.decide(id, 'approve'); assert.equal(approved.phase, 'approved'); assert.equal(f.calls(), 1);
    assert.deepEqual(await f.store.decide(id, 'approve'), approved); assert.equal(f.calls(), 1); assert.equal(phase(await f.store.decide(id, 'reject')), 'conflict');
    const reserved = f.store.reserve(id); assert.equal(reserved.phase, 'reserved'); assert(reserved.token); assert.equal(Object.getPrototypeOf(reserved.token), null); assert.equal(Object.keys(reserved.token).length, 0);
    assert.equal(f.store.reserve(id).token, undefined); assert.equal(f.store.inspect(id).token, undefined);
    const restarted = createAdmissionStore(f.options); assert.equal(restarted.inspect(id).phase, 'reserved'); assert.equal(restarted.reserve(id).token, undefined); assert.equal(count(f.directory), 6);
    assert.equal(JSON.stringify(reserved).includes(f.directory), false);
  });

  test('reject/expiry are terminal, inspect never expires, deadlines never renew', async t => {
    const f = fixture(t); f.store.submit(proposal()); const reject = await f.store.decide(id, 'reject'); assert.equal(reject.phase, 'rejected'); assert.equal(f.store.reserve(id).token, undefined); assert.equal(phase(await f.store.decide(id, 'approve')), 'conflict');
    const second = '2'.repeat(32); f.store.submit(proposal({ requestId: second })); f.setTime(epoch + 10000);
    assert.equal(phase(f.store.inspect(second)), 'pending'); assert.equal(phase(await f.store.decide(second, 'approve')), 'expired'); assert.equal(f.calls(), 1);
    assert.equal(f.store.reserve(second).token, undefined); assert.equal(phase(f.store.submit(proposal({ requestId: second }))), 'expired'); assert.equal(phase(await f.store.decide(second, 'reject')), 'expired');
  });

  // Exercise the actual store, using the same explicitly simulated root metadata.
  // Ordinary denial must leave both the live instance and a fresh one usable.
  function unrelatedProgress(f, now = epoch) {
    for (const [store, rid] of [[f.store, '2'.repeat(32)], [createAdmissionStore(f.options), '3'.repeat(32)]]) {
      const result = store.submit(proposal({ requestId: rid, approvalExpiresAt: new Date(now + 10000).toISOString(), jobExpiresAt: new Date(now + 20000).toISOString() }));
      assert.equal(result.phase, 'pending'); assert(!fs.existsSync(path.join(f.directory, 'admission.lock')));
    }
  }

  for (const [name, change] of [
    ['expired approval', { approvalExpiresAt: new Date(epoch).toISOString() }],
    ['expired job', { approvalExpiresAt: new Date(epoch - 1).toISOString(), jobExpiresAt: new Date(epoch).toISOString() }],
    ['overlong approval', { approvalExpiresAt: new Date(epoch + 10001).toISOString() }],
    ['overlong job', { jobExpiresAt: new Date(epoch + 20001).toISOString() }],
  ]) test('R2: new ' + name + ' denies without acquiring a lock; unrelated IDs progress', t => {
    const f = fixture(t), original = fs.openSync; let lockAttempts = 0;
    mock.method(fs, 'openSync', (...args) => { if (args[0] === path.join(f.directory, 'admission.lock') && (args[1] & fs.constants.O_CREAT)) lockAttempts++; return original(...args); });
    assert.equal(f.store.submit(proposal(change)).phase, 'denied'); assert.equal(lockAttempts, 0); assert.equal(count(f.directory), 0); assert.equal(f.calls(), 0);
    unrelatedProgress(f); assert.equal(f.store.inspect(id).phase, 'absent');
  });

  test('R2: malformed new proposal has no lock or store effect', t => {
    const f = fixture(t), original = fs.openSync; let lockAttempts = 0;
    mock.method(fs, 'openSync', (...args) => { if (args[0] === path.join(f.directory, 'admission.lock')) lockAttempts++; return original(...args); });
    assert.throws(() => f.store.submit(proposal({ approvalExpiresAt: 'invalid' })), /admission_denied/);
    assert.equal(lockAttempts, 0); assert.equal(count(f.directory), 0); unrelatedProgress(f);
  });

  for (const now of [epoch + 10000, epoch + 20000]) test('R2: approved then expired reserve preserves immutable approval and releases its owned lock at ' + now, async t => {
    const f = fixture(t); f.store.submit(proposal()); const approved = await f.store.decide(id, 'approve'); assert.equal(approved.phase, 'approved');
    const files = fs.readdirSync(f.directory).map(name => [name, fs.readFileSync(path.join(f.directory, name), 'utf8')]);
    f.setTime(now); const result = f.store.reserve(id); assert.deepEqual(result, approved); assert.equal(result.token, undefined);
    assert.deepEqual(fs.readdirSync(f.directory).map(name => [name, fs.readFileSync(path.join(f.directory, name), 'utf8')]), files);
    assert.equal(f.calls(), 1); assert.deepEqual(f.store.inspect(id), approved); assert.deepEqual(createAdmissionStore(f.options).inspect(id), approved);
    unrelatedProgress(f, now); assert.deepEqual(f.store.inspect(id), approved);
  });

  test('R2: expiry between submit precheck and lock acquisition takes normal verified release', t => {
    const f = fixture(t), open = fs.openSync, unlink = fs.unlinkSync, lock = path.join(f.directory, 'admission.lock'); let acquired = 0, released = 0;
    mock.method(fs, 'openSync', (...args) => { if (args[0] === lock && (args[1] & fs.constants.O_CREAT)) { acquired++; f.setTime(epoch + 10000); } return open(...args); });
    mock.method(fs, 'unlinkSync', (...args) => { if (args[0] === lock) released++; return unlink(...args); });
    assert.equal(f.store.submit(proposal()).phase, 'denied'); assert.equal(acquired, 1); assert.equal(released, 1); assert.equal(count(f.directory), 0); assert.equal(f.calls(), 0);
    unrelatedProgress(f, epoch + 10000);
  });

  test('R2: expiry immediately before first intent record is ordinary denial', t => {
    let calls = 0; const f = fixture(t, { clock: () => ++calls >= 3 ? epoch + 10000 : epoch });
    assert.equal(f.store.submit(proposal()).phase, 'denied'); assert.equal(count(f.directory), 0); assert.equal(f.calls(), 0); unrelatedProgress(f, epoch + 10000);
  });

  test('R2: reserve expiry immediately before first candidate returns historical approval, no token', async t => {
    let reserving = false, calls = 0; const f = fixture(t, { clock: () => reserving && ++calls >= 2 ? epoch + 10000 : epoch });
    f.store.submit(proposal()); const approved = await f.store.decide(id, 'approve'); reserving = true;
    assert.deepEqual(f.store.reserve(id), approved); assert.equal(count(f.directory), 4); assert(!fs.existsSync(path.join(f.directory, 'admission.lock')));
    unrelatedProgress(f, epoch + 10000);
  });

  for (const action of ['submit', 'reserve']) test('R2: ' + action + ' expiry after a candidate preserves genuine partial evidence', async t => {
    let enabled = false, calls = 0; const threshold = action === 'submit' ? 4 : 3;
    const f = fixture(t, { clock: () => enabled && ++calls >= threshold ? epoch + 10000 : epoch });
    if (action === 'reserve') { f.store.submit(proposal()); await f.store.decide(id, 'approve'); }
    enabled = true;
    const result = action === 'submit' ? f.store.submit(proposal()) : f.store.reserve(id), kind = action === 'submit' ? 'intent' : 'reservation';
    assert.equal(result.phase, 'outcome_unknown'); assert.equal(result.token, undefined); assert(fs.existsSync(path.join(f.directory, id + '.' + kind + '.candidate')));
    assert(!fs.existsSync(path.join(f.directory, id + '.' + kind + '.json'))); assert(fs.existsSync(path.join(f.directory, 'admission.lock')));
    const before = fs.readdirSync(f.directory); assert.equal(createAdmissionStore(f.options).inspect(id).phase, 'outcome_unknown');
    assert.equal(f.store.submit(proposal({ requestId: '2'.repeat(32), approvalExpiresAt: new Date(epoch + 20000).toISOString(), jobExpiresAt: new Date(epoch + 30000).toISOString() })).phase, 'outcome_unknown');
    assert.deepEqual(fs.readdirSync(f.directory), before);
  });

  test('R2: release fsync failure during normal expired reserve remains uncertain after restart', async t => {
    const f = fixture(t); f.store.submit(proposal()); await f.store.decide(id, 'approve'); f.setTime(epoch + 10000);
    const original = fs.fsyncSync; let calls = 0; mock.method(fs, 'fsyncSync', (...args) => { if (++calls === 3) throw Error('release sync fault'); return original(...args); });
    assert.equal(f.store.reserve(id).phase, 'outcome_unknown'); assert(fs.existsSync(path.join(f.directory, 'admission.uncertain'))); assert(!fs.existsSync(path.join(f.directory, id + '.reservation.candidate')));
    assert.equal(createAdmissionStore(f.options).inspect(id).phase, 'outcome_unknown');
  });

  test('R2: unowned lock stays unknown even for an invalid lifetime', t => {
    const f = fixture(t), lock = path.join(f.directory, 'admission.lock'); fs.writeFileSync(lock, 'unowned evidence', { mode: 0o600 });
    assert.equal(f.store.submit(proposal({ approvalExpiresAt: new Date(epoch).toISOString() })).phase, 'outcome_unknown');
    assert.equal(fs.readFileSync(lock, 'utf8'), 'unowned evidence'); assert.equal(count(f.directory), 1);
    assert.equal(createAdmissionStore(f.options).submit(proposal({ requestId: '2'.repeat(32) })).phase, 'outcome_unknown');
    assert.equal(fs.readFileSync(lock, 'utf8'), 'unowned evidence');
  });

  test('R2: substituted lock during normal expired reserve is preserved, never released', async t => {
    let sabotage = false, time = epoch, directory; const f = fixture(t, { clock: () => {
      if (sabotage) { sabotage = false; const lock = path.join(directory, 'admission.lock'); fs.unlinkSync(lock); fs.writeFileSync(lock, 'unowned substitution', { mode: 0o600 }); }
      return time;
    } }); directory = f.directory;
    f.store.submit(proposal()); await f.store.decide(id, 'approve'); time = epoch + 10000; sabotage = true;
    assert.equal(f.store.reserve(id).phase, 'outcome_unknown'); assert.equal(fs.readFileSync(path.join(directory, 'admission.lock'), 'utf8'), 'unowned substitution'); assert.equal(count(directory), 5);
    assert.equal(createAdmissionStore(f.options).inspect(id).phase, 'outcome_unknown');
  });

  test('authority failure/cancellation/timeout cannot publish a decision and holds no lock', async t => {
    const f = fixture(t); f.store.submit(proposal());
    for (const fn of [() => { throw Error('private'); }, () => Promise.reject(Error('cancelled')), () => new Promise(() => {})]) {
      const s = createAdmissionStore({ ...f.options, decisionAuthority: fn }); assert.equal(phase(await s.decide(id, 'approve')), 'denied'); assert.equal(phase(f.store.inspect(id)), 'pending'); assert.equal(count(f.directory), 2);
    }
    let release; const slow = createAdmissionStore({ ...f.options, decisionAuthority: b => new Promise(resolve => { release = () => resolve(authority(b)); }) });
    const attempt = slow.decide(id, 'approve'); await new Promise(resolve => setImmediate(resolve)); assert(!fs.existsSync(path.join(f.directory, 'admission.lock')));
    f.setTime(epoch + 10000); release(); assert.equal(phase(await attempt), 'expired'); assert.equal(f.store.reserve(id).token, undefined);
  });

  for (const field of ['ownerId', 'requestId', 'intentDigest', 'policyDigest', 'decision', 'authorityId', 'authorizedAt', 'validUntil', 'stillValid']) test(`forged authority ${field} denies before reservation`, async t => {
    const bad = field === 'stillValid' ? () => false : field === 'authorityId' ? '' : field === 'authorizedAt' ? epoch - 1 : field === 'validUntil' ? epoch : 'wrong';
    const f = fixture(t, { decisionAuthority: b => ({ ...authority(b), [field]: bad }) }); f.store.submit(proposal()); const result = await f.store.decide(id, 'approve'); assert.equal(result.phase, 'outcome_unknown'); assert.equal(f.store.reserve(id).token, undefined); assert(!fs.existsSync(path.join(f.directory, `${id}.decision.json`)));
  });

  test('boolean/subject/serializable approval is not a trusted grant', async t => {
    const f = fixture(t, { decisionAuthority: () => ({ authorized: true, subject: { uid: 10001 }, receipt: 'forged' }) }); f.store.submit(proposal()); assert.equal(phase(await f.store.decide(id, 'approve')), 'outcome_unknown'); assert.equal(f.store.reserve(id).token, undefined);
    assert.throws(() => createAdmissionStore({ ...f.options, decisionAuthority: null })); await assert.rejects(f.store.decide(id, 'expire'));
  });

  test('clock regression and provider/config drift fail closed', async t => {
    const f = fixture(t); f.store.submit(proposal()); f.setTime(epoch - 1); assert.equal(phase(f.store.inspect(id)), 'outcome_unknown');
    f.setTime(epoch); const s = createAdmissionStore(f.options); f.options.policy.ownerId = 'other'; assert.equal(phase(s.reserve(id)), 'outcome_unknown');
  });

  test('authority callback changing persisted intent cannot race final CAS', async t => {
    const f = fixture(t, { decisionAuthority: b => ({ ...authority(b), stillValid() { fs.writeFileSync(path.join(f.directory, `${id}.intent.json`), '{}'); return true; } }) }); f.store.submit(proposal());
    assert.equal(phase(await f.store.decide(id, 'approve')), 'outcome_unknown'); assert(!fs.existsSync(path.join(f.directory, `${id}.decision.json`)));
  });

  for (const mutation of ['symlink', 'hardlink', 'mode', 'nonregular', 'partial', 'unknown', 'ancestor', 'custody']) test(`preserves ${mutation} evidence without repair`, t => {
    const f = fixture(t); f.store.submit(proposal()); const target = path.join(f.directory, `${id}.intent.json`);
    if (mutation === 'symlink') { fs.unlinkSync(target); fs.symlinkSync(`${id}.intent.candidate`, target); }
    if (mutation === 'hardlink') fs.linkSync(target, path.join(f.directory, 'unowned'));
    if (mutation === 'mode') fs.chmodSync(target, 0o640);
    if (mutation === 'nonregular') { fs.unlinkSync(target); fs.mkdirSync(target); }
    if (mutation === 'partial') fs.writeFileSync(target, '{');
    if (mutation === 'unknown') fs.writeFileSync(path.join(f.directory, 'unowned'), 'evidence');
    if (mutation === 'ancestor') { const original = fs.lstatSync; mock.method(fs, 'lstatSync', (...args) => { const s = original(...args); return args[0] === '/tmp' ? Object.assign(Object.create(Object.getPrototypeOf(s)), s, { ino: s.ino + 1 }) : s; }); }
    if (mutation === 'custody') { const original = fs.lstatSync; mock.method(fs, 'lstatSync', (...args) => { const s = original(...args); return args[0] === f.directory ? Object.assign(Object.create(Object.getPrototypeOf(s)), s, { uid: 10001 }) : s; }); }
    const before = fs.readdirSync(f.directory); assert.equal(phase(f.store.inspect(id)), 'outcome_unknown'); assert.equal(f.store.reserve(id).token, undefined); assert(before.every(n => fs.existsSync(path.join(f.directory, n))));
  });

  test('preexisting and substituted locks are never removed', async t => {
    const f = fixture(t); const lock = path.join(f.directory, 'admission.lock'); fs.writeFileSync(lock, 'unowned', { mode: 0o600 });
    assert.equal(phase(f.store.submit(proposal())), 'outcome_unknown'); assert.equal(fs.readFileSync(lock, 'utf8'), 'unowned');
    // Test operator, not the store, removes its own fixture lock.
    fs.unlinkSync(lock); f.store.submit(proposal());
    const original = fs.unlinkSync; let replaced = false;
    const stat = fs.lstatSync; mock.method(fs, 'lstatSync', (...args) => {
      if (args[0] === lock && !replaced && fs.existsSync(path.join(f.directory, `${id}.decision.json`))) { replaced = true; original(lock); fs.writeFileSync(lock, 'substituted', { mode: 0o600 }); }
      return stat(...args);
    });
    assert.equal(phase(await f.store.decide(id, 'approve')), 'outcome_unknown'); assert.equal(fs.readFileSync(lock, 'utf8'), 'substituted');
  });

  test('bounded short writes complete, zero writes and ENOSPC preserve unknown evidence', t => {
    const f = fixture(t); const original = fs.writeSync; mock.method(fs, 'writeSync', (fd, b, offset, length, position) => original(fd, b, offset, Math.min(length, 7), position));
    assert.equal(phase(f.store.submit(proposal())), 'pending'); mock.restoreAll(); simulateCustody();
    const s = createAdmissionStore(f.options); mock.method(fs, 'writeSync', () => 0); assert.equal(phase(s.submit(proposal({ requestId: '2'.repeat(32) }))), 'outcome_unknown'); assert(fs.existsSync(path.join(f.directory, 'admission.lock')));
  });

  for (const operation of ['writeSync', 'fsyncSync', 'readSync', 'unlinkSync', 'openSync']) test(`injected ${operation} failure preserves evidence and poisons new authority`, t => {
    const f = fixture(t); const original = fs[operation]; let calls = 0;
    mock.method(fs, operation, (...args) => { if (++calls === (operation === 'openSync' ? 3 : 1)) { const e = Error('fixture fault'); e.code = operation === 'writeSync' ? 'ENOSPC' : 'EIO'; throw e; } return original(...args); });
    assert.equal(phase(f.store.submit(proposal())), 'outcome_unknown'); assert.equal(f.store.reserve(id).token, undefined); assert(fs.existsSync(path.join(f.directory, 'admission.lock')));
  });

  test('candidate/final parent sync and readback failures cannot be adopted after restart', t => {
    const f = fixture(t), original = fs.fsyncSync; let calls = 0;
    mock.method(fs, 'fsyncSync', (...args) => { if (++calls === 6) throw Error('parent sync failure'); return original(...args); });
    assert.equal(phase(f.store.submit(proposal())), 'outcome_unknown'); assert(fs.existsSync(path.join(f.directory, `${id}.intent.json`)));
    assert.equal(phase(createAdmissionStore(f.options).inspect(id)), 'outcome_unknown');
  });

  test('multiprocess matching/changed submit races have one immutable winner', async t => {
    const f = fixture(t); const workers = [child(f.directory, 'submit'), child(f.directory, 'submit'), child(f.directory, 'submit', { proposal: { taskId: 'changed' } })];
    await Promise.all(workers.map(w => w.ready)); workers.forEach(w => w.cp.send('go')); const results = await Promise.all(workers.map(w => w.result));
    assert(results.some(r => r.phase === 'pending')); assert(results.every(r => ['pending', 'conflict', 'outcome_unknown'].includes(r.phase)));
    assert.equal(phase(f.store.inspect(id)), 'pending'); assert.equal(count(f.directory), 2);
    assert.equal(phase(f.store.submit(proposal({ requestId: '2'.repeat(32) }))), 'pending');
  });

  test('multiprocess approve/reject/expire CAS and reservation races have one winner', async t => {
    const f = fixture(t); f.store.submit(proposal()); const workers = [child(f.directory, 'approve'), child(f.directory, 'reject'), child(f.directory, 'approve', { expire: true })];
    await Promise.all(workers.map(w => w.ready)); workers.forEach(w => w.cp.send('go')); await Promise.all(workers.map(w => w.result));
    const state = f.store.inspect(id); assert(['approved', 'rejected', 'expired'].includes(state.phase)); assert.equal(count(f.directory), 4);
    if (state.phase === 'approved') {
      const reservers = [child(f.directory, 'reserve'), child(f.directory, 'reserve'), child(f.directory, 'reserve')]; await Promise.all(reservers.map(w => w.ready)); reservers.forEach(w => w.cp.send('go'));
      const results = await Promise.all(reservers.map(w => w.result)); assert.equal(results.filter(r => r.token).length, 1); assert.equal(count(f.directory), 6);
    }
  });

  test('approved reservation is one-winner across processes (unconditional coverage)', async t => {
    const f = fixture(t); f.store.submit(proposal()); assert.equal(phase(await f.store.decide(id, 'approve')), 'approved');
    const workers = [child(f.directory, 'reserve'), child(f.directory, 'reserve')]; await Promise.all(workers.map(w => w.ready)); workers.forEach(w => w.cp.send('go'));
    assert.equal((await Promise.all(workers.map(w => w.result))).filter(r => r.token).length, 1); assert.equal(f.store.reserve(id).token, undefined);
  });

  for (const [action, operation, target] of [['submit', 'writeSync', 1], ['submit', 'writeSync', 2], ['submit', 'fsyncSync', 3], ['submit', 'fsyncSync', 6], ['approve', 'fsyncSync', 3], ['approve', 'fsyncSync', 6], ['reserve', 'fsyncSync', 3], ['reserve', 'fsyncSync', 6], ['approve', 'unlinkSync', 1]]) test(`SIGKILL ${action} at ${operation}#${target} preserves crash evidence`, async t => {
    const f = fixture(t); if (action !== 'submit') f.store.submit(proposal()); if (action === 'reserve') await f.store.decide(id, 'approve');
    const w = child(f.directory, action, { crash: operation, target }); await w.ready; w.cp.send('go'); assert.equal((await w.result).signal, 'SIGKILL');
    const s = createAdmissionStore(f.options), state = s.inspect(id);
    if (operation === 'unlinkSync') { assert.equal(state.phase, 'approved'); assert.equal(s.inspect(id).decisionReceiptId, state.decisionReceiptId); }
    else { assert.equal(state.phase, 'outcome_unknown'); assert.equal(s.reserve(id).token, undefined); assert(fs.existsSync(path.join(f.directory, 'admission.lock'))); }
  });

  test('4096-intent capacity: contended IDs do not strand the last unrelated slot', async t => {
    const f = fixture(t);
    // Seed only well-formed immutable fixtures, not through a production bypass.
    for (let i = 2; i <= 4095; i++) {
      const rid = i.toString(16).padStart(32, '0'), intent = canonicalIntent(proposal({ requestId: rid }), f.options.policy);
      const body = { version: 1, kind: 'intent', requestId: rid, intentDigest: digest(intent), receiptId: rid, payload: intent };
      const bytes = canonical({ ...body, checksum: digest(body) });
      for (const ext of ['candidate', 'json']) fs.writeFileSync(path.join(f.directory, rid + '.intent.' + ext), bytes, { mode: 0o600 });
    }
    const workers = [child(f.directory, 'submit'), child(f.directory, 'submit'), child(f.directory, 'submit', { proposal: { taskId: 'changed' } })];
    await Promise.all(workers.map(w => w.ready)); workers.forEach(w => w.cp.send('go')); await Promise.all(workers.map(w => w.result));
    assert.equal(f.store.inspect(id).phase, 'pending'); assert.equal(count(f.directory), 4095 * 2);
    const lastSlots = ['f'.repeat(32), 'e'.repeat(32)].map(rid => child(f.directory, 'submit', { proposal: { requestId: rid } }));
    await Promise.all(lastSlots.map(w => w.ready)); lastSlots.forEach(w => w.cp.send('go')); const lastResults = await Promise.all(lastSlots.map(w => w.result));
    assert.equal(lastResults.filter(r => r.phase === 'pending').length, 1); const fresh = lastResults.find(r => r.phase === 'pending').intent.requestId;
    assert.equal(f.store.submit(proposal({ requestId: 'd'.repeat(32) })).phase, 'capacity');
    assert.equal(f.store.submit(proposal({ requestId: fresh })).phase, 'pending'); assert.equal(count(f.directory), 4096 * 2);
    const rid = 'c'.repeat(32), intent = canonicalIntent(proposal({ requestId: rid }), f.options.policy), body = { version: 1, kind: 'intent', requestId: rid, intentDigest: digest(intent), receiptId: rid, payload: intent };
    for (const ext of ['candidate', 'json']) fs.writeFileSync(path.join(f.directory, rid + '.intent.' + ext), canonical({ ...body, checksum: digest(body) }), { mode: 0o600 });
    assert.equal(f.store.inspect(id).phase, 'outcome_unknown'); assert.equal(count(f.directory), 4097 * 2);
  });

  for (const action of ['submit', 'approve', 'reserve']) for (const target of [2, 3, 4, 5, 6, 7]) test(action + ' fsync boundary ' + target + ' preserves uncertain publication', async t => {
    const f = fixture(t); if (action !== 'submit') f.store.submit(proposal()); if (action === 'reserve') await f.store.decide(id, 'approve');
    const original = fs.fsyncSync; let n = 0; mock.method(fs, 'fsyncSync', (...args) => { if (++n === target) throw Error('fixture fsync boundary'); return original(...args); });
    const result = action === 'submit' ? f.store.submit(proposal()) : action === 'reserve' ? f.store.reserve(id) : await f.store.decide(id, action);
    assert.equal(result.phase, 'outcome_unknown'); assert(fs.existsSync(path.join(f.directory, target === 7 ? 'admission.uncertain' : 'admission.lock'))); assert.equal(createAdmissionStore(f.options).inspect(id).phase, 'outcome_unknown');
  });

  test('deadline/authority continuity are checked again after candidate fsync before final CAS', async t => {
    const f = fixture(t); f.store.submit(proposal()); let valid = true;
    const s = createAdmissionStore({ ...f.options, decisionAuthority: b => ({ ...authority(b), stillValid: () => valid }) });
    const original = fs.fsyncSync; let n = 0; mock.method(fs, 'fsyncSync', (...args) => { const r = original(...args); if (++n === 4) valid = false; return r; });
    assert.equal((await s.decide(id, 'approve')).phase, 'outcome_unknown'); assert(fs.existsSync(path.join(f.directory, id + '.decision.candidate'))); assert(!fs.existsSync(path.join(f.directory, id + '.decision.json')));
  });

  for (const mutation of ['clock', 'decisionAuthority', 'policy', 'directory']) test('fixed option replacement ' + mutation + ' invalidates the instance', t => {
    const f = fixture(t); f.store.submit(proposal());
    f.options[mutation] = mutation === 'policy' ? { ...f.options.policy, policyVersion: 'other' } : mutation === 'directory' ? f.directory + '-other' : () => epoch;
    assert.equal(f.store.reserve(id).phase, 'outcome_unknown'); assert.equal(count(f.directory), 2);
  });

  for (const action of ['submit', 'approve', 'reserve']) test(action + ' final CAS/readback faults retain partial evidence', async t => {
    const f = fixture(t); if (action !== 'submit') f.store.submit(proposal()); if (action === 'reserve') await f.store.decide(id, 'approve');
    const kind = action === 'submit' ? 'intent' : action === 'reserve' ? 'reservation' : 'decision', target = path.join(f.directory, id + '.' + kind + '.json');
    const original = fs.openSync; mock.method(fs, 'openSync', (...args) => {
      if (args[0] === target && (args[1] & fs.constants.O_CREAT)) { fs.writeFileSync(target, 'unowned CAS evidence', { mode: 0o600 }); }
      return original(...args);
    });
    const result = action === 'submit' ? f.store.submit(proposal()) : action === 'reserve' ? f.store.reserve(id) : await f.store.decide(id, 'approve');
    assert.equal(result.phase, 'outcome_unknown'); assert.equal(fs.readFileSync(target, 'utf8'), 'unowned CAS evidence'); assert.equal(createAdmissionStore(f.options).inspect(id).phase, 'outcome_unknown');
  });

  test('wrong-checksum journal is preserved, never repaired', t => {
    const f = fixture(t); f.store.submit(proposal()); const p = path.join(f.directory, id + '.intent.json'), r = JSON.parse(fs.readFileSync(p)); r.checksum = '0'.repeat(64); fs.writeFileSync(p, canonical(r));
    assert.equal(f.store.inspect(id).phase, 'outcome_unknown'); assert.equal(fs.readFileSync(p, 'utf8'), canonical(r));
  });

  test('byte-identical replacement at final readback fails inode validation', t => {
    const f = fixture(t), target = path.join(f.directory, id + '.intent.json'), original = fs.fsyncSync; let n = 0;
    mock.method(fs, 'fsyncSync', (...args) => {
      const result = original(...args);
      if (++n === 6) { const temp = path.join(f.directory, 'fixture-replacement'); fs.writeFileSync(temp, fs.readFileSync(target), { mode: 0o600 }); fs.renameSync(temp, target); }
      return result;
    });
    assert.equal(f.store.submit(proposal()).phase, 'outcome_unknown'); assert(fs.existsSync(path.join(f.directory, 'admission.lock'))); assert.equal(createAdmissionStore(f.options).inspect(id).phase, 'outcome_unknown');
  });

  test('malformed JSON/config errors are fixed and disclose no private input', t => {
    const f = fixture(t); assert.throws(() => f.store.submit(proposal().replace('task7', 'private\\q-canary')), e => e.code === 'admission_denied' && !e.message.includes('canary'));
    assert.throws(() => createAdmissionStore({ ...f.options, directory: f.directory + '/private-canary-missing' }), e => e.code === 'admission_denied' && !e.message.includes('canary')); assert.equal(count(f.directory), 0);
  });

  test('source import graph has no effects or downstream receipt synthesizer', () => {
    for (const name of ['intent', 'admission-store']) {
      const source = fs.readFileSync(new URL(`../job-preparation/${name}.mjs`, import.meta.url), 'utf8');
      const imports = [...source.matchAll(/from ['"]([^'"]+)['"]/g)].map(m => m[1]); assert(imports.every(p => ['node:crypto', 'node:util', 'node:fs', 'node:path', './intent.mjs'].includes(p)));
      assert(!/child_process|fetch\(|https?:|GatewayReceipt|loadApprovedPrepared|mkdirSync|chownSync|renameSync|setuid/.test(source));
    }
  });
}
