import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { HostOperatorJournal } from './host-operator-journal.mjs';
import { digest, request, descriptor, ProtocolError } from './host-operator-protocol.mjs';

const now = 1800000000000;
const ownerPubkey = 'a'.repeat(64);
const source = { repository: 'test-org/project', baseRef: 'main', baseSha: 'b'.repeat(40),
  workspaceId: 'host-fixture', sourceDigest: 'c'.repeat(64) };
const original = { version: 1, requestId: 'request-one', taskId: 'task-one', jobId: 'job-one',
  repository: source.repository, baseRef: source.baseRef, baseSha: source.baseSha,
  operationId: 'status.revision', channelId: '00000000-0000-0000-0000-000000000001',
  threadId: 'd'.repeat(64), authorizationEventId: 'e'.repeat(64) };
function attestation(r, clock = now) {
  return { requesterId: 'owner', role: 'owner', kind: 'owner_event',
    eventId: r.authorizationEventId, signerPubkey: ownerPubkey, ownerPubkey,
    mentionPubkey: ownerPubkey, requestHash: digest(r), descriptorDigest: digest(descriptor(r, source)), verifiedAt: clock, expiresAt: clock + 3600000,
    enabled: true, status: 'active', ...Object.fromEntries(['taskId', 'jobId', 'repository',
      'baseRef', 'baseSha', 'operationId', 'channelId', 'threadId'].map(k => [k, r[k]])) };
}
function fixture(t, operationId = 'status.revision') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'host-operator-fixture-')); fs.chmodSync(root, 0o700);
  const directory = path.join(root, 'journal'); fs.mkdirSync(directory, { mode: 0o700 });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const r = { ...original, operationId }, authoritative = new Map();
  let clock = now, auth = q => attestation(q, clock), serial = 0;
  const options = { directory, source, ownerPubkey, clock: () => clock,
    authorize: q => auth(q), verifyReceipt: evidence => {
      if (!authoritative.has(evidence.ref)) throw new Error('SECRET_CANARY: no authoritative receipt');
      return authoritative.get(evidence.ref);
    } };
  const make = () => new HostOperatorJournal(options);
  function evidence(plan, outcome = 'success', change = {}) {
    const ref = `proof-${++serial}`;
    authoritative.set(ref, { version: 1, receiptId: ref, intentId: plan.intent.intentId,
      intentDigest: digest(plan.intent), requestHash: digest(r), step: plan.intent.step, outcome,
      finishedAt: clock, evidenceRef: ref, evidenceDigest: 'f'.repeat(64),
      summary: { passed: outcome === 'needs_user' ? 0 : 1, failed: 0, skipped: 0,
        exitCode: outcome === 'needs_user' ? null : 0, signal: null }, ...change });
    return { ref };
  }
  return { root, directory, r, options, make, evidence, authoritative,
    time: n => { clock = n; }, auth: fn => { auth = fn; } };
}
function rejects(fn, code) { assert.throws(fn, e => e instanceof ProtocolError && e.code === code); }
function disk(f) { return fs.existsSync(path.join(f.directory, 'state.json')) ? fs.readFileSync(path.join(f.directory, 'state.json'), 'utf8') : ''; }
function complete(f) {
  const seen = [];
  for (const step of ['execution', 'kaneo', 'buzz']) {
    const plan = f.make().next(f.r); assert.equal(plan.status, 'intent'); assert.equal(plan.intent.step, step);
    seen.push(plan); f.make().record(f.r, f.evidence(plan));
  }
  assert.equal(f.make().next(f.r).status, 'complete');
  return seen;
}

test('strict request and fixed registry reject arbitrary operations, paths, shell/env/mount/argv and size', () => {
  assert.deepEqual(request(original), original);
  for (const field of ['shell', 'path', 'env', 'mount', 'argv', 'url', 'requesterId', 'verified']) {
    rejects(() => request({ ...original, [field]: 'SECRET_CANARY' }), 'schema');
  }
  for (const change of [{ baseRef: '--upload-pack=x' }, { repository: '../project' },
    { baseSha: 'x' }, { threadId: 'bad' }, { version: 2 }, { baseRef: 'main/../other' }]) {
    rejects(() => request({ ...original, ...change }), 'schema');
  }
  rejects(() => request({ ...original, shell: 'x'.repeat(5000) }), 'size_limit');
  for (const operationId of ['shell.run', 'checkout.run', 'rollout.run', 'rollback.run', 'credentials.read']) {
    rejects(() => descriptor({ ...original, operationId }, source), 'operation_denied');
  }
  rejects(() => descriptor(original, { ...source, baseSha: 'f'.repeat(40) }), 'scope_mismatch');
});

test('no missing/default verifier and no trust in caller verified booleans', t => {
  const f = fixture(t);
  rejects(() => new HostOperatorJournal({ ...f.options, authorize: null }), 'adapter_required');
  f.auth(() => ({ verified: true })); rejects(() => f.make().next(f.r), 'authorization_denied');
  assert.deepEqual(fs.readdirSync(f.directory), []);
});

test('authorization rejects stale/forged/revoked/mismatched evidence before any journal intent', t => {
  const f = fixture(t), good = attestation(f.r);
  for (const change of [{ enabled: false }, { status: 'completed' }, { expiresAt: now },
    { verifiedAt: now - 60001 }, { verifiedAt: now + 1 }, { requestHash: '0'.repeat(64) }, { descriptorDigest: '0'.repeat(64) },
    { signerPubkey: '0'.repeat(64) }, { ownerPubkey: '0'.repeat(64) }, { eventId: '0'.repeat(64) },
    { taskId: 'other' }, { jobId: 'other' }, { repository: 'other/project' }, { baseRef: 'other' },
    { baseSha: '0'.repeat(40) }, { operationId: 'validate.node' }, { channelId: 'other' },
    { threadId: '0'.repeat(64) }, { role: 'developer' }, { token: 'SECRET_CANARY' }]) {
    f.auth(() => ({ ...good, ...change })); rejects(() => f.make().next(f.r), 'authorization_denied');
    assert.deepEqual(fs.readdirSync(f.directory), []);
  }
  f.auth(() => { throw new Error('SECRET_CANARY /host/credential'); });
  rejects(() => f.make().next(f.r), 'authorization_denied');
});

test('trusted assignment adapter binds delegated identity and immutable registry/workspace', t => {
  const f = fixture(t); f.auth(q => ({ ...attestation(q), requesterId: 'developer-a', role: 'developer',
    kind: 'assignment', signerPubkey: '1'.repeat(64), mentionPubkey: '2'.repeat(64) }));
  const plan = f.make().next(f.r), stored = JSON.parse(disk(f));
  assert.equal(plan.intent.payload.descriptor.workspaceId, source.workspaceId);
  assert.equal(plan.intent.payload.descriptor.sourceDigest, source.sourceDigest);
  assert.equal(plan.intent.payload.descriptor.registryVersion, 'host-operator-offline-v1');
  assert.equal(Object.values(stored.entries)[0].identity.requesterId, 'developer-a');
  // Intent data is detached from both the journal and the internal registry.
  plan.intent.payload.descriptor.timeoutMs = 1;
  assert.equal(f.make().next(f.r).status, 'outcome_unknown');
});

test('intent precedes simulated effect, reports bind task/thread/content, completed replay has zero effects', t => {
  const f = fixture(t), plans = complete(f);
  assert.equal(plans[1].intent.payload.taskId, f.r.taskId);
  assert.equal(plans[2].intent.payload.channelId, f.r.channelId);
  assert.equal(plans[2].intent.payload.threadId, f.r.threadId);
  assert.equal(plans[2].intent.payload.mentionPubkey, ownerPubkey);
  assert.equal(digest(plans[1].intent.payload.result), digest(plans[2].intent.payload.result));
  const before = disk(f);
  for (let i = 0; i < 3; i++) assert.equal(f.make().next(f.r).status, 'complete');
  assert.equal(disk(f), before);
  assert.equal(Object.values(JSON.parse(before).entries)[0].effects.length, 3);
});

for (const boundary of ['execution', 'kaneo', 'buzz']) test(`lost ${boundary} response/restart never resends without positive reconciliation`, t => {
  const f = fixture(t);
  for (const step of ['execution', 'kaneo', 'buzz']) {
    const plan = f.make().next(f.r); assert.equal(plan.intent.step, step);
    const proof = f.evidence(plan); // fake sink did the effect, response may be lost
    if (step === boundary) {
      const before = disk(f);
      for (let i = 0; i < 2; i++) assert.equal(f.make().next(f.r).status, 'outcome_unknown');
      assert.equal(disk(f), before);
      rejects(() => f.make().record(f.r, { ref: 'empty-search-or-chat-done' }), 'receipt_invalid');
      assert.equal(disk(f), before);
    }
    f.make().record(f.r, proof);
  }
  assert.equal(f.make().next(f.r).status, 'complete');
});

test('same request cannot acquire changed payload or identity; other IDs cannot bypass active job/workspace', t => {
  const f = fixture(t); f.make().next(f.r);
  for (const change of [{ taskId: 'other' }, { threadId: '0'.repeat(64) }, { operationId: 'validate.node' }]) {
    rejects(() => f.make().next({ ...f.r, ...change }), 'request_conflict');
  }
  f.auth(q => ({ ...attestation(q), requesterId: 'other' }));
  rejects(() => f.make().next(f.r), 'request_conflict'); f.auth(attestation);
  rejects(() => f.make().next({ ...f.r, requestId: 'other' }), 'workspace_busy');
  rejects(() => f.make().next({ ...f.r, requestId: 'other', jobId: 'other' }), 'workspace_busy');
});

test('different authorized operation may proceed after completion, with a fresh request ID', t => {
  const f = fixture(t); complete(f);
  const plan = f.make().next({ ...f.r, requestId: 'second', operationId: 'validate.node' });
  assert.equal(plan.intent.step, 'execution');
  assert.equal(plan.intent.payload.descriptor.operationId, 'validate.node');
});

test('expired/revoked requests start nothing new; authoritative past receipt can still be recorded', t => {
  const f = fixture(t), plan = f.make().next(f.r), proof = f.evidence(plan);
  f.auth(q => ({ ...attestation(q), expiresAt: now }));
  rejects(() => f.make().next(f.r), 'authorization_denied');
  assert.equal(f.make().record(f.r, proof).status, 'recorded');
  rejects(() => f.make().next(f.r), 'authorization_denied');
  assert.equal(Object.values(JSON.parse(disk(f)).entries)[0].effects.length, 1);
});

test('deadline, cancellation and timeout never imply terminated process or permit another execution', t => {
  const f = fixture(t), plan = f.make().next(f.r);
  f.time(now + 5001);
  assert.equal(f.make().next(f.r).code, 'deadline_elapsed');
  for (const outcome of ['timeout', 'cancelled']) {
    assert.equal(f.make().record(f.r, f.evidence(plan, outcome)).code, 'termination_unproven');
    assert.equal(f.make().next(f.r).status, 'outcome_unknown');
  }
  f.make().record(f.r, f.evidence(plan)); // trusted fixture proves termination + result
  assert.equal(f.make().next(f.r).intent.step, 'kaneo');
});

test('needs_user emits one inert registered command and resumes only with authoritative same-journal proof', t => {
  const f = fixture(t, 'validate.preflight'), plan = f.make().next(f.r);
  f.make().record(f.r, f.evidence(plan, 'needs_user'));
  const handoff = f.make().next(f.r);
  assert.equal(handoff.status, 'needs_user'); assert.equal(handoff.intent.step, 'user');
  assert.deepEqual(handoff.intent.payload.command, ['HOST_OPERATOR_FIXTURE_ONLY', 'prepare-host']);
  assert.equal(f.make().next(f.r).status, 'outcome_unknown');
  rejects(() => f.make().record(f.r, { ref: 'done' }), 'receipt_invalid');
  f.make().record(f.r, f.evidence(handoff));
  f.auth(q => ({ ...attestation(q), enabled: false }));
  rejects(() => f.make().next(f.r), 'authorization_denied');
  f.auth(attestation);
  const resumed = f.make().next(f.r); assert.equal(resumed.intent.step, 'execution');
  f.make().record(f.r, f.evidence(resumed));
  for (const step of ['kaneo', 'buzz']) {
    const report = f.make().next(f.r); assert.equal(report.intent.step, step); f.make().record(f.r, f.evidence(report));
  }
  assert.equal(f.make().next(f.r).status, 'complete');
});

test('unregistered or repeated user action remains blocked without inventing a command', t => {
  for (const op of ['validate.node', 'validate.preflight']) {
    const f = fixture(t, op), plan = f.make().next(f.r);
    f.make().record(f.r, f.evidence(plan, 'needs_user'));
    if (op === 'validate.preflight') {
      const handoff = f.make().next(f.r); f.make().record(f.r, f.evidence(handoff));
      const resumed = f.make().next(f.r); f.make().record(f.r, f.evidence(resumed, 'needs_user'));
    }
    const before = disk(f);
    assert.deepEqual(f.make().next(f.r), { status: 'blocked', code: 'host_preparation_required' });
    assert.equal(disk(f), before);
  }
});

test('invalid/extra/mismatched/oversize/poisoned receipts cannot complete or leak raw data', t => {
  const f = fixture(t), plan = f.make().next(f.r), before = disk(f);
  for (const change of [{ intentId: 'other' }, { requestHash: '0'.repeat(64) },
    { intentDigest: '0'.repeat(64) }, { step: 'buzz' }, { finishedAt: now + 1 },
    { stdout: 'SECRET_CANARY\u001b[31m /host/private' }, { evidenceRef: '/host/private' },
    { summary: { passed: 1, failed: 0, skipped: 0, exitCode: 'SECRET_CANARY', signal: null } },
    { summary: { passed: 1, failed: 1, skipped: 0, exitCode: 0, signal: null } }]) {
    rejects(() => f.make().record(f.r, f.evidence(plan, 'success', change)), 'receipt_invalid');
    assert.equal(disk(f), before);
  }
  rejects(() => f.make().record(f.r, { ref: 'x'.repeat(9000) }), 'size_limit');
  assert.equal(disk(f).includes('SECRET_CANARY'), false);
  const proof = f.evidence(plan); f.make().record(f.r, proof);
  assert.equal(f.make().record(f.r, proof).status, 'recorded');
  rejects(() => f.make().record(f.r, f.evidence(plan)), 'receipt_conflict');
});

for (const fault of ['openSync', 'writeFileSync', 'renameSync', 'fsyncSync']) test(`${fault}/ENOSPC failure emits no intent and preserves old completed state`, t => {
  const f = fixture(t); complete(f); const before = disk(f), original = fs[fault];
  fs[fault] = function(...args) {
    // Let journal.lock open/close operate so the storage fault reaches the state write.
    if (fault !== 'openSync' || String(args[0]).endsWith('.tmp')) {
      const e = new Error('SECRET_CANARY /host/private'); e.code = 'ENOSPC'; throw e;
    }
    return original.apply(this, args);
  };
  try { rejects(() => f.make().next({ ...f.r, requestId: 'second' }), 'journal_io'); }
  finally { fs[fault] = original; }
  assert.equal(disk(f), before); assert.equal(disk(f).includes('SECRET_CANARY'), false);
});

test('lock, symlink, hardlink, nonprivate directory/file and malformed journal fail closed', t => {
  const f = fixture(t), lock = path.join(f.directory, 'journal.lock'), file = path.join(f.directory, 'state.json');
  fs.writeFileSync(lock, '', { mode: 0o600 }); rejects(() => f.make().next(f.r), 'journal_locked'); fs.unlinkSync(lock);
  fs.symlinkSync(path.join(f.root, 'absent'), lock); rejects(() => f.make().next(f.r), 'journal_locked'); fs.unlinkSync(lock);
  fs.chmodSync(f.directory, 0o755); rejects(() => f.make().next(f.r), 'journal_untrusted'); fs.chmodSync(f.directory, 0o700);
  fs.symlinkSync(path.join(f.root, 'absent'), file); rejects(() => f.make().next(f.r), 'journal_untrusted'); fs.unlinkSync(file);
  fs.writeFileSync(file, '{}', { mode: 0o600 }); fs.linkSync(file, path.join(f.root, 'linked'));
  rejects(() => f.make().next(f.r), 'journal_untrusted'); fs.unlinkSync(path.join(f.root, 'linked'));
  fs.chmodSync(file, 0o644); rejects(() => f.make().next(f.r), 'journal_untrusted'); fs.chmodSync(file, 0o600);
  fs.writeFileSync(file, 'SECRET_CANARY invalid json'); rejects(() => f.make().next(f.r), 'journal_io');
  assert.equal(fs.existsSync(path.join(f.root, 'absent')), false);
});

test('symlinked/permissive parent paths and unfinished atomic writes are never adopted', t => {
  const f = fixture(t), link = path.join(f.root, 'linked'); fs.symlinkSync(f.directory, link);
  rejects(() => new HostOperatorJournal({ ...f.options, directory: link }).next(f.r), 'journal_untrusted');
  fs.chmodSync(f.root, 0o777); rejects(() => f.make().next(f.r), 'journal_untrusted'); fs.chmodSync(f.root, 0o700);
  fs.writeFileSync(path.join(f.directory, 'state.json.tmp'), '', { mode: 0o600 });
  rejects(() => f.make().next(f.r), 'journal_unresolved');
});

const journalUrl = new URL('./host-operator-journal.mjs', import.meta.url).href;
function child(f, crash = false) {
  const code = `import fs from 'node:fs'; import {HostOperatorJournal} from ${JSON.stringify(journalUrl)};
    const data=JSON.parse(fs.readFileSync(0,'utf8'));
    const j=new HostOperatorJournal({...data.options,clock:()=>${now},authorize:()=>data.auth,verifyReceipt:()=>null});
    ${crash ? "fs.writeFileSync=()=>process.kill(process.pid,'SIGKILL');" : ''}
    try {console.log(JSON.stringify(j.next(data.request)));}catch(e){console.log(JSON.stringify({code:e.code}));}`;
  return new Promise((resolve, reject) => {
    const c = spawn(process.execPath, ['--input-type=module', '-e', code], { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    c.stdout.on('data', x => { stdout += x; }); c.stderr.on('data', x => { stderr += x; });
    c.on('error', reject); c.on('close', (exit, signal) => resolve({ exit, signal, stdout, stderr }));
    c.stdin.end(JSON.stringify({ options: { directory: f.directory, source, ownerPubkey }, request: f.r, auth: attestation(f.r) }));
  });
}

test('two independent processes serialize one execution intent and persistent workspace reservation', async t => {
  const f = fixture(t), results = await Promise.all([child(f), child(f)]);
  const values = results.map(r => { assert.equal(r.stderr, ''); return JSON.parse(r.stdout); });
  assert.equal(values.filter(v => v.status === 'intent').length, 1);
  assert.equal(values.filter(v => v.status === 'outcome_unknown' || v.code === 'journal_locked').length, 1);
  assert.equal(f.make().next(f.r).status, 'outcome_unknown');
});

test('process death before durable intent leaves a stale lock and never silently replays', async t => {
  const f = fixture(t), result = await child(f, true);
  assert.equal(result.signal, 'SIGKILL'); assert.equal(result.stdout, ''); assert.equal(result.stderr, '');
  rejects(() => f.make().next(f.r), 'journal_locked');
});

test('production modules have no CLI, process runner, network client or credential loader', () => {
  for (const name of ['host-operator-protocol.mjs', 'host-operator-journal.mjs']) {
    const text = fs.readFileSync(new URL(name, import.meta.url), 'utf8');
    assert.doesNotMatch(text, /node:(child_process|net|http|https)|\bfetch\s*\(|process\.argv|process\.env/);
  }
});

for (const phase of ['file_fsync', 'directory_fsync_after_rename']) test(`${phase} failure never exposes an intent or permits blind replay`, t => {
  const f = fixture(t), sync = fs.fsyncSync, rename = fs.renameSync;
  let published = false;
  fs.renameSync = function(...args) { const result = rename.apply(this, args); published = true; return result; };
  fs.fsyncSync = function(fd) {
    if ((phase === 'file_fsync' && fs.fstatSync(fd).isFile()) ||
        (phase === 'directory_fsync_after_rename' && published)) throw new Error('SECRET_CANARY');
    return sync.call(this, fd);
  };
  try { rejects(() => f.make().next(f.r), 'journal_io'); }
  finally { fs.fsyncSync = sync; fs.renameSync = rename; }
  if (phase === 'file_fsync') {
    assert.equal(disk(f), ''); rejects(() => f.make().next(f.r), 'journal_unresolved');
  } else {
    assert.equal(f.make().next(f.r).status, 'outcome_unknown');
    assert.equal(Object.values(JSON.parse(disk(f)).entries)[0].effects.length, 1);
  }
});

test('failure between report intent and receipt preserves prior execution/report evidence', t => {
  const f = fixture(t), execution = f.make().next(f.r);
  f.make().record(f.r, f.evidence(execution));
  const report = f.make().next(f.r), good = f.evidence(report), before = disk(f);
  // A verified negative/ambiguous delivery result is not permission to resend.
  rejects(() => f.make().record(f.r, f.evidence(report, 'failed')), 'receipt_invalid');
  assert.equal(disk(f), before); assert.equal(f.make().next(f.r).status, 'outcome_unknown');
  f.make().record(f.r, good);
  const buzz = f.make().next(f.r), proof = f.evidence(buzz);
  f.authoritative.get(proof.ref).intentDigest = '0'.repeat(64);
  rejects(() => f.make().record(f.r, proof), 'receipt_invalid');
  assert.equal(f.make().next(f.r).status, 'outcome_unknown');
});

test('altered registry, request, intent or receipt journal records are never repaired/adopted', t => {
  const f = fixture(t); complete(f); const original = disk(f), file = path.join(f.directory, 'state.json');
  for (const mutate of [
    e => { e.request.taskId = 'other'; },
    e => { e.descriptor.sourceDigest = '0'.repeat(64); },
    e => { e.effects[0].intent.payload.descriptor.workspaceId = 'other'; },
    e => { e.effects[1].intent.payload.taskId = 'other'; },
    e => { e.effects[2].receipt.intentDigest = '0'.repeat(64); },
    e => { e.effects[0].receipt.stdout = 'SECRET_CANARY'; },
  ]) {
    const state = JSON.parse(original); mutate(Object.values(state.entries)[0]);
    fs.writeFileSync(file, JSON.stringify(state)); const corrupted = disk(f);
    assert.throws(() => f.make().next(f.r), e => e instanceof ProtocolError);
    assert.equal(disk(f), corrupted);
  }
});

test('authorization is checked again under the lock and binds the source/dependency digest', t => {
  const f = fixture(t); let calls = 0;
  f.auth(q => ({ ...attestation(q), enabled: ++calls === 1 }));
  rejects(() => f.make().next(f.r), 'authorization_denied');
  assert.deepEqual(fs.readdirSync(f.directory), []);
  f.auth(attestation);
  const altered = new HostOperatorJournal({ ...f.options, source: { ...source, sourceDigest: '0'.repeat(64) } });
  rejects(() => altered.next(f.r), 'authorization_denied');
  assert.deepEqual(fs.readdirSync(f.directory), []);
});

test('wrong journal ownership is denied without adopting/chowning it', t => {
  const f = fixture(t), lstat = fs.lstatSync;
  fs.lstatSync = function(p, ...args) {
    const s = lstat.call(this, p, ...args);
    if (p === f.directory) s.uid = process.getuid() + 1;
    return s;
  };
  try { rejects(() => f.make().next(f.r), 'journal_untrusted'); }
  finally { fs.lstatSync = lstat; }
  assert.deepEqual(fs.readdirSync(f.directory), []);
});

test('needs_user cannot claim executed tests or an exit status', t => {
  const f = fixture(t, 'validate.preflight'), plan = f.make().next(f.r), before = disk(f);
  const proof = f.evidence(plan, 'needs_user', { summary: { passed: 1, failed: 0, skipped: 0, exitCode: 0, signal: null } });
  rejects(() => f.make().record(f.r, proof), 'receipt_invalid');
  assert.equal(disk(f), before);
});

test('a proven failed execution is reported as failed, never silently rerun or changed to success', t => {
  const f = fixture(t), plan = f.make().next(f.r);
  f.make().record(f.r, f.evidence(plan, 'failed', {
    summary: { passed: 0, failed: 1, skipped: 0, exitCode: 1, signal: null } }));
  for (const step of ['kaneo', 'buzz']) {
    const report = f.make().next(f.r);
    assert.equal(report.intent.step, step);
    assert.equal(report.intent.payload.result.execution.outcome, 'failed');
    f.make().record(f.r, f.evidence(report));
  }
  assert.equal(f.make().next(f.r).result.execution.outcome, 'failed');
});

test('invalid clock/config errors use fixed codes and never echo host values', t => {
  const f = fixture(t);
  rejects(() => new HostOperatorJournal({ ...f.options, directory: null }), 'journal_untrusted');
  for (const clock of [() => -1, () => { throw new Error('SECRET_CANARY /host/private'); }]) {
    rejects(() => new HostOperatorJournal({ ...f.options, clock }).next(f.r), 'clock_invalid');
  }
  assert.deepEqual(fs.readdirSync(f.directory), []);
});

test('A15 optional release hook is never enabled by missing/invalid configuration and generic execution receipt still holds reports',t=>{
  const f=fixture(t);for(const value of [null,true,{},Promise.resolve(true)])rejects(()=>new HostOperatorJournal({...f.options,verifyRevisionCompletion:value}),'adapter_required');const p=f.make().next(f.r);f.make().record(f.r,f.evidence(p));rejects(()=>f.make().next({...f.r,requestId:'second'}),'workspace_busy');const old=f.make().next(f.r);assert.equal(old.intent.step,'kaneo');rejects(()=>f.make().next({...f.r,requestId:'second'}),'workspace_busy');
});
test('A15 arbitrary truthy/malformed hook or wrong normalized receipt cannot release persisted generic success',t=>{
  const f=fixture(t),p=f.make().next(f.r),e=f.evidence(p);f.make().record(f.r,e);const before=disk(f);for(const hook of [()=>true,()=>Promise.resolve(true),()=>({verified:true}),()=>{throw Error('SECRET_CANARY');},()=>({...f.authoritative.get(e.ref),receiptId:'different'})]){const j=new HostOperatorJournal({...f.options,verifyRevisionCompletion:hook});rejects(()=>j.next({...f.r,requestId:'second'}),'workspace_busy');assert.equal(disk(f),before);}
});
test('A15 nonrevision operations and needs_user outcomes retain existing reservation semantics without completion-hook calls',t=>{
  const f=fixture(t,'validate.node'),p=f.make().next(f.r);f.make().record(f.r,f.evidence(p));let calls=0;rejects(()=>new HostOperatorJournal({...f.options,verifyRevisionCompletion:()=>{calls++;throw Error('SECRET_CANARY');}}).next({...f.r,requestId:'second'}),'workspace_busy');assert.equal(calls,0);
  const g=fixture(t),q=g.make().next(g.r);g.make().record(g.r,g.evidence(q,'needs_user'));rejects(()=>new HostOperatorJournal({...g.options,verifyRevisionCompletion:()=>{calls++;throw Error('SECRET_CANARY');}}).next({...g.r,requestId:'second'}),'workspace_busy');assert.equal(calls,0);
});
