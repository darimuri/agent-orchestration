// Offline conformance only: actual writer -> signed A1 / pinned A2 -> actual journal.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { schnorr } from '../host-operator-auth/node_modules/@noble/curves/secp256k1.js';
import { createAuthorizationAdapter } from '../host-operator-auth/authorization.mjs';
import { HostOperatorJournal } from './host-operator-journal.mjs';
import { digest, descriptor, ProtocolError } from './host-operator-protocol.mjs';

// Set only by the provenance-checking test harness in its private build scratch.
const build = process.env.HOST_OPERATOR_TEST_GATEWAY_BUILD;
const integration = (name, fn) => test(name, { skip: !build && 'run check-host-operator-integration.mjs for pinned writer/A2 integration' }, fn);
const createHostPolicySource = build ? (await import(pathToFileURL(path.join(build, 'dist/host-policy-source.js')))).createHostPolicySource : null;
const createHostAdmissionWriter = build ? (await import(pathToFileURL(path.join(build, 'dist/host-admission-writer.js')))).createHostAdmissionWriter : null;
const byteDigest = bytes => createHash('sha256').update(bytes).digest('hex');
// Public BIP-340 vector 0 scalar; NOT an operational key.
const scalar = Buffer.from('0'.repeat(63) + '3', 'hex');
const ownerPubkey = 'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9';
const targetPubkey = 'e'.repeat(64), channelId = '00000000-0000-0000-0000-000000000001', threadId = 'd'.repeat(64);
const now = 1800000000000;
const source = { repository: 'test-org/project', baseRef: 'main', baseSha: 'b'.repeat(40), workspaceId: 'host-fixture', sourceDigest: 'c'.repeat(64) };
const owner = { ownerPubkey, requesterId: 'owner', mentionPubkey: ownerPubkey, targetPubkey };
const baseRequest = { version: 1, requestId: 'request-one', taskId: 'task-one', jobId: 'job-one',
  repository: source.repository, baseRef: source.baseRef, baseSha: source.baseSha, operationId: 'status.revision', channelId, threadId };
const canary = 'SECRET_CANARY';
function signed(r = baseRequest, envelope = {}, fields = {}) {
  const e = { pubkey: ownerPubkey, kind: 9, created_at: now / 1000,
    tags: [['h', channelId], ['e', threadId, '', 'root'], ['p', targetPubkey]],
    content: JSON.stringify({ type: 'host-operator.request', version: 1, request: r,
      descriptorDigest: digest(descriptor(baseRequest, source)), expiresAt: now + 600000, ...envelope }), ...fields };
  e.id = createHash('sha256').update(JSON.stringify([0, e.pubkey, e.created_at, e.kind, e.tags, e.content])).digest('hex');
  e.sig = Buffer.from(schnorr.sign(Buffer.from(e.id, 'hex'), scalar, new Uint8Array(32))).toString('hex');
  return e;
}
function state() {
  return { agents: { agents: [{ id: 'developer-1', role: 'developer', tokenSha256: 'a'.repeat(64), disabled: false,
    expiresAt: new Date(now + 3600000).toISOString() }] }, jobs: { jobs: [{ id: 'job-one', agentId: 'developer-1', role: 'developer',
    repository: source.repository, baseRef: source.baseRef, baseSha: source.baseSha, pullNumber: 7, headSha: '1'.repeat(40), reviewPolicyVersion: 'fixture-v1', status: 'active', expiresAt: new Date(now + 7200000).toISOString(),
    hostAdmission: { version: 1, ...owner, taskId: baseRequest.taskId, channelId, threadId, workspaceId: source.workspaceId,
      sourceDigest: source.sourceDigest, descriptorDigest: digest(descriptor(baseRequest, source)),
      allowedOperations: ['status.revision'], expiresAt: new Date(now + 1800000).toISOString() } },
    { id: 'legacy-job', agentId: 'reviewer-1', role: 'reviewer', repository: 'test-org/legacy', status: 'completed', expiresAt: new Date(now - 1).toISOString() }] } };
}
function fixture(t, { grant = true } = {}) {
  assert.notEqual(process.getuid(), 0, 'ordinary UID required');
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'host-composition-')); fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const journalDir = path.join(directory, 'journal'); fs.mkdirSync(journalDir, { mode: 0o700 });
  const agentsFile = path.join(directory, 'agents.json'), jobsFile = path.join(directory, 'jobs.json');
  // Hostile/legacy raw-write fixtures only; positive capability lifecycle uses the real writer below.
  function write(s = state()) {
    for (const [file, data] of [[agentsFile, s.agents], [jobsFile, s.jobs]]) {
      fs.writeFileSync(file + '.new', JSON.stringify(data), { mode: 0o600 }); fs.renameSync(file + '.new', file);
    }
  }
  const initial = state(); delete initial.jobs.jobs[0].hostAdmission; write(initial);
  let clock = now, event = signed(), calls = 0, hook = () => {}, monotonic = () => 0;
  const r = { ...baseRequest, authorizationEventId: event.id }, receipts = new Map(), privateDigests = new Set();
  const options = { agentsFile, jobsFile, owner, allowedOwners: ['test-org'], uid: process.getuid(), clock: () => clock,
    monotonic: () => monotonic() };
  const { expiresAt: _expiry, ...pinned } = state().jobs.jobs[0].hostAdmission;
  const writer = createHostAdmissionWriter({ jobsFile, uid: process.getuid(), clock: () => clock,
    policy: { jobId: baseRequest.jobId, repository: source.repository, baseRef: source.baseRef, baseSha: source.baseSha, hostAdmission: pinned } });
  const command = (operation = 'set') => ({ version: 1, operation, jobId: baseRequest.jobId,
    expectedDigest: byteDigest(fs.readFileSync(jobsFile)), ...(operation === 'set' && { hostAdmission: state().jobs.jobs[0].hostAdmission }) });
  const admin = operation => {
    const result = writer.mutate(JSON.stringify(command(operation)));
    for (const key of ['oldDigest', 'candidateDigest']) if (result[key]) privateDigests.add(result[key]);
    return result;
  };
  if (grant) assert.equal(admin('set').status, 'confirmed');
  const provider = createHostPolicySource(options);
  let current = (...args) => { calls++; hook(calls); return provider(...args); };
  const adapterOptions = { ...owner, channelId, threadId, source, clock: () => clock,
    resolveEvent: id => id === event.id ? JSON.stringify(event) : null, currentJob: (...args) => current(...args) };
  const adapter = createAuthorizationAdapter(adapterOptions);
  const journal = () => new HostOperatorJournal({ directory: journalDir, source, ownerPubkey, authorize: adapter, clock: () => clock,
    verifyReceipt: evidence => { if (!receipts.has(evidence.ref)) throw Error(canary + directory); return receipts.get(evidence.ref); } });
  function evidence(plan, outcome = 'success') {
    const ref = 'proof-' + receipts.size;
    receipts.set(ref, { version: 1, receiptId: ref, intentId: plan.intent.intentId, intentDigest: digest(plan.intent),
      requestHash: digest(r), step: plan.intent.step, outcome, finishedAt: clock, evidenceRef: ref, evidenceDigest: 'f'.repeat(64),
      summary: { passed: 1, failed: 0, skipped: 0, exitCode: 0, signal: null } });
    return { ref };
  }
  const disk = () => fs.existsSync(path.join(journalDir, 'state.json')) ? fs.readFileSync(path.join(journalDir, 'state.json'), 'utf8') : '';
  return { r, directory, journalDir, agentsFile, jobsFile, write, writer, command, admin, privateDigests, journal, evidence, receipts, disk, adapter, adapterOptions, provider,
    time: value => { clock = value; }, event: value => { event = value; },
    hook: fn => { hook = fn; }, monotonic: fn => { monotonic = fn; }, current: fn => { current = fn; } };
}
function denied(f, fn = () => f.journal().next(f.r)) {
  const before = f.disk();
  assert.throws(fn, e => e instanceof ProtocolError && ['authorization_denied', 'scope_mismatch', 'operation_denied'].includes(e.code) &&
    e.message === e.code && !JSON.stringify(e).includes(canary) && !e.stack.includes(f.directory));
  assert.equal(f.disk(), before); assert.equal(fs.existsSync(path.join(f.journalDir, 'journal.lock')), false);
}
function noLeaks(f, value) {
  const text = JSON.stringify(value);
  for (const secret of [canary, f.directory, 'tokenSha256', 'a'.repeat(64), 'developer-1', ...f.privateDigests]) assert.equal(text.includes(secret), false);
}

integration('real signed A1 + private-file A2 + journal complete replay and separate receipt authority', t => {
  const f = fixture(t);
  const facts = f.provider(f.r, { requesterId: 'owner', role: 'owner', kind: 'owner_event', eventId: f.r.authorizationEventId,
    signerPubkey: ownerPubkey, ownerPubkey, mentionPubkey: ownerPubkey }, descriptor(f.r, source));
  assert.equal(facts.requestHash, digest(f.r)); noLeaks(f, facts);
  assert.equal(fs.readdirSync(f.journalDir).length, 0);
  for (const step of ['execution', 'kaneo', 'buzz']) {
    const plan = f.journal().next(f.r); assert.equal(plan.intent.step, step); noLeaks(f, plan);
    const pending = f.disk(); assert.equal(f.journal().next(f.r).status, 'outcome_unknown'); assert.equal(f.disk(), pending);
    assert.throws(() => f.journal().record(f.r, signed()), e => e.code === 'receipt_invalid');
    assert.throws(() => f.journal().record(f.r, facts), e => e.code === 'receipt_invalid');
    assert.equal(f.disk(), pending);
    const proof = f.evidence(plan); noLeaks(f, f.journal().record(f.r, proof)); f.journal().record(f.r, proof);
  }
  const done = f.disk(); noLeaks(f, f.journal().next(f.r)); assert.equal(f.journal().next(f.r).status, 'complete'); assert.equal(f.disk(), done);
  assert.equal(Object.values(JSON.parse(done).entries)[0].effects.length, 3); noLeaks(f, done);
});

integration('signature, ID, unsigned payload and signed scope substitution produce no intent', t => {
  const f = fixture(t), good = signed();
  for (const change of [{ sig: '0'.repeat(128) }, { id: '0'.repeat(64) }, { content: good.content + ' ' }, { pubkey: '0'.repeat(64) }]) {
    f.event({ ...good, ...change }); denied(f);
  }
  for (const [key, value] of Object.entries({ taskId: 'other', jobId: 'other', repository: 'other/repo', baseRef: 'other',
    baseSha: '0'.repeat(40), channelId: '00000000-0000-0000-0000-000000000002', threadId: '0'.repeat(64), operationId: 'validate.node' })) {
    const event = signed({ ...baseRequest, [key]: value }); f.event(event);
    denied(f, () => f.journal().next({ ...baseRequest, [key]: value, authorizationEventId: event.id }));
  }
  for (const fields of [{ tags: [['h', channelId], ['p', '0'.repeat(64)], ['e', threadId, '', 'root']] }, { kind: 1 }]) {
    const event = signed(baseRequest, {}, fields); f.event(event); denied(f, () => f.journal().next({ ...f.r, authorizationEventId: event.id }));
  }
  f.event(good); denied(f, () => f.journal().next({ ...f.r, requestId: 'other' }));
  const unknown = signed({ ...baseRequest, operationId: 'unknown.operation' }); f.event(unknown);
  denied(f, () => f.journal().next({ ...f.r, operationId: 'unknown.operation', authorizationEventId: unknown.id }));
  const wrongDigest = signed(baseRequest, { descriptorDigest: '0'.repeat(64) }); f.event(wrongDigest);
  denied(f, () => f.journal().next({ ...f.r, authorizationEventId: wrongDigest.id }));
});

integration('every private ledger authority binding is independently enforced through A1 and journal', t => {
  const f = fixture(t);
  const changes = { ownerPubkey: '0'.repeat(64), requesterId: 'other', mentionPubkey: '0'.repeat(64), targetPubkey: '0'.repeat(64),
    taskId: 'other', channelId: '00000000-0000-0000-0000-000000000002', threadId: '0'.repeat(64), workspaceId: 'other',
    sourceDigest: '0'.repeat(64), descriptorDigest: '0'.repeat(64), allowedOperations: ['validate.node'], expiresAt: new Date(now).toISOString() };
  for (const [key, value] of Object.entries(changes)) { const s = state(); s.jobs.jobs[0].hostAdmission[key] = value; f.write(s); denied(f); }
  for (const change of [{ agentId: 'other' }, { role: 'reviewer' }, { id: 'other' }, { repository: 'other/repo' },
    { baseRef: 'other' }, { baseSha: '0'.repeat(40) }, { status: 'completed' }, { status: 'cancelled' }, { expiresAt: new Date(now).toISOString() }]) {
    const s = state(); Object.assign(s.jobs.jobs[0], change); f.write(s); denied(f);
  }
  for (const change of [{ id: 'other' }, { role: 'reviewer' }, { disabled: true }, { expiresAt: new Date(now).toISOString() }]) {
    const s = state(); Object.assign(s.agents.agents[0], change); f.write(s); denied(f);
  }
  const missing = state(); delete missing.jobs.jobs[0].hostAdmission; f.write(missing); denied(f);
  f.write();
  denied(f, () => createAuthorizationAdapter({ ...f.adapterOptions, currentJob: null }));
  f.current(() => Promise.resolve(null)); denied(f);
  f.current(() => { throw Error(canary + f.directory); }); denied(f);
});

for (const revoke of ['capability', 'agent']) for (const at of [1, 2]) integration(`atomic ${revoke} revocation at authorization ${at} creates no intent`, t => {
  const f = fixture(t);
  f.hook(calls => { if (calls === at) { const s = state(); if (revoke === 'agent') s.agents.agents[0].disabled = true;
    else { assert.equal(f.admin('remove').status, 'confirmed'); return; } f.write(s); } });
  denied(f); assert.equal(f.disk(), '');
});
for (const boundary of ['kaneo', 'buzz']) integration(`revocation before later ${boundary} intent preserves prior receipts`, t => {
  const f = fixture(t);
  for (const step of ['execution', 'kaneo']) {
    if (step === boundary) break;
    const plan = f.journal().next(f.r); f.journal().record(f.r, f.evidence(plan));
  }
  assert.equal(f.admin('remove').status, 'confirmed'); denied(f);
});

integration('real reader byte/record/mode/symlink/unstable-generation failures are sanitized by A1', t => {
  const f = fixture(t);
  for (const raw of [canary, Buffer.from([0xc3, 0x28]), Buffer.alloc(1048577, 32),
    JSON.stringify({ jobs: Array(4097).fill({}) }), '{"jobs":[],"jobs":[]}']) {
    fs.writeFileSync(f.jobsFile, raw); denied(f);
  }
  f.write(); fs.chmodSync(f.jobsFile, 0o640); denied(f); fs.chmodSync(f.jobsFile, 0o600);
  fs.renameSync(f.jobsFile, f.jobsFile + '.saved'); fs.symlinkSync(f.jobsFile + '.saved', f.jobsFile); denied(f);
  fs.unlinkSync(f.jobsFile); fs.renameSync(f.jobsFile + '.saved', f.jobsFile);
  let ticks = 0; f.monotonic(() => { if (++ticks === 3) f.write(); return 0; }); denied(f);
  f.monotonic(() => 101 * ticks++); denied(f);
});

integration('signed/agent/job/capability expiry minima and clock units do not renew stale authority', t => {
  const f = fixture(t), d = descriptor(f.r, source);
  assert.equal(f.adapter(f.r, d).expiresAt, now + 600000);
  for (const target of ['agent', 'job', 'capability']) {
    const s = state();
    if (target === 'agent') s.agents.agents[0].expiresAt = new Date(now + 1000).toISOString();
    if (target === 'job') { s.jobs.jobs[0].expiresAt = new Date(now + 1000).toISOString(); delete s.jobs.jobs[0].hostAdmission.expiresAt; }
    if (target === 'capability') s.jobs.jobs[0].hostAdmission.expiresAt = new Date(now + 1000).toISOString();
    f.write(s); assert.equal(f.adapter(f.r, d).expiresAt, now + 1000); f.time(now + 1000); denied(f); f.time(now);
  }
  f.write(); f.time(now + 600000); denied(f); f.time(now / 1000); denied(f);
});

for (const boundary of ['expiry', 'revocation']) integration(`pending timeout and positive historical receipt after ${boundary} never permit a next intent`, t => {
  const f = fixture(t), plan = f.journal().next(f.r), before = f.disk();
  assert.equal(f.journal().record(f.r, f.evidence(plan, 'timeout')).status, 'outcome_unknown'); assert.equal(f.disk(), before);
  f.time(now + 5001); assert.equal(f.journal().next(f.r).code, 'deadline_elapsed'); assert.equal(f.disk(), before);
  if (boundary === 'expiry') f.time(now + 600000);
  else { const s = state(); s.agents.agents[0].disabled = true; f.write(s); }
  denied(f); assert.equal(f.journal().record(f.r, f.evidence(plan)).status, 'recorded');
  const stored = JSON.parse(f.disk()); assert.equal(Object.values(stored.entries)[0].effects.length, 1);
  assert.equal(Object.values(stored.entries)[0].effects[0].receipt.outcome, 'success'); denied(f);
});

integration('cached provider facts cannot refresh their verification time', t => {
  const f = fixture(t);
  const cached = f.provider(f.r, { requesterId: 'owner', role: 'owner', kind: 'owner_event',
    eventId: f.r.authorizationEventId, signerPubkey: ownerPubkey, ownerPubkey, mentionPubkey: ownerPubkey }, descriptor(f.r, source));
  f.current(() => cached); f.time(now + 60001); denied(f);
});

integration('absent capability denies the same signed request; confirmed real-writer grant yields one durable intent without forge changes', t => {
  const f = fixture(t, { grant: false }), before = JSON.parse(fs.readFileSync(f.jobsFile, 'utf8'));
  denied(f); assert.equal(f.disk(), ''); assert.deepEqual(fs.readdirSync(f.journalDir), []);
  const result = f.admin('set'); assert.equal(result.status, 'confirmed'); assert.equal(result.code, 'committed');
  const after = JSON.parse(fs.readFileSync(f.jobsFile, 'utf8')); delete after.jobs[0].hostAdmission;
  assert.deepEqual(after, before); // No schema defaults or forge/other-job fields changed.
  const plan = f.journal().next(f.r); assert.equal(plan.status, 'intent'); assert.equal(plan.intent.step, 'execution');
  assert.deepEqual(plan.intent.payload.descriptor, descriptor(f.r, source)); assert.equal(plan.intent.requestHash, digest(f.r));
  const stored = Object.values(JSON.parse(f.disk()).entries)[0]; assert.equal(stored.effects.length, 1);
  assert.deepEqual(stored.effects[0].intent, plan.intent); noLeaks(f, plan); noLeaks(f, stored);
});

for (const step of ['execution', 'kaneo', 'buzz']) for (const at of [1, 2]) integration(`real writer removes capability at ${step} authorization ${at} without changing journal history`, t => {
  const f = fixture(t);
  for (const prior of ['execution', 'kaneo']) {
    if (prior === step) break;
    const plan = f.journal().next(f.r); assert.equal(plan.intent.step, prior); f.journal().record(f.r, f.evidence(plan));
  }
  const before = f.disk(), jobs = JSON.parse(fs.readFileSync(f.jobsFile, 'utf8')); let observed = 0, removed = 0;
  f.hook(() => {
    if (++observed !== at) return;
    assert.equal(fs.existsSync(path.join(f.journalDir, 'journal.lock')), at === 2);
    assert.equal(f.admin('remove').status, 'confirmed'); removed++;
  });
  denied(f); assert.equal(removed, 1); assert.equal(f.disk(), before);
  delete jobs.jobs[0].hostAdmission; assert.deepEqual(JSON.parse(fs.readFileSync(f.jobsFile, 'utf8')), jobs);
});

for (const step of ['execution', 'kaneo', 'buzz']) integration(`real-writer revocation while ${step} is pending allows only separate historical proof`, t => {
  const f = fixture(t);
  for (const prior of ['execution', 'kaneo']) {
    if (prior === step) break;
    const plan = f.journal().next(f.r); f.journal().record(f.r, f.evidence(plan));
  }
  const pending = f.journal().next(f.r); assert.equal(pending.intent.step, step);
  const before = f.disk(), proof = f.evidence(pending);
  // A newly constructed journal reads persisted pending state, never issues another effect.
  assert.equal(f.journal().next(f.r).status, 'outcome_unknown'); assert.equal(f.disk(), before);
  assert.equal(f.admin('remove').status, 'confirmed'); denied(f);
  const stored = f.journal().record(f.r, proof);
  assert.equal(stored.status, step === 'buzz' ? 'complete' : 'recorded'); noLeaks(f, stored);
  const history = Object.values(JSON.parse(f.disk()).entries)[0].effects;
  assert.equal(history.length, ['execution', 'kaneo', 'buzz'].indexOf(step) + 1);
  assert.equal(history.at(-1).receipt.outcome, 'success'); denied(f);
});

integration('stale-digest conflict and denied writer inputs are not execution or native-report receipts', t => {
  const f = fixture(t), bytes = fs.readFileSync(f.jobsFile), stale = f.command('remove'); stale.expectedDigest = '0'.repeat(64);
  const conflict = f.writer.mutate(JSON.stringify(stale)); assert.equal(conflict.status, 'conflict'); assert.equal(conflict.code, 'digest_conflict');
  const bad = f.writer.mutate(JSON.stringify({ ...f.command('set'), path: canary })); assert.equal(bad.status, 'denied');
  const deniedRemove = f.writer.mutate(JSON.stringify({ ...f.command('remove'), jobId: 'other' })); assert.equal(deniedRemove.status, 'denied');
  assert(fs.readFileSync(f.jobsFile).equals(bytes)); assert.equal(fs.existsSync(f.jobsFile + '.host-admission.lock'), false);
  const confirmed = f.admin('set'); assert.equal(confirmed.status, 'confirmed');
  const observation = f.writer.reconcile(JSON.stringify({ version: 1, oldDigest: confirmed.oldDigest, candidateDigest: confirmed.candidateDigest }));
  assert.equal(observation.status, 'observed'); assert.equal(observation.durability, 'unproven');
  for (const step of ['execution', 'kaneo', 'buzz']) {
    const plan = f.journal().next(f.r); assert.equal(plan.intent.step, step); const pending = f.disk();
    for (const candidate of [conflict, bad, deniedRemove, confirmed, observation, signed(), f.adapter(f.r, descriptor(f.r, source))]) {
      // Even a fixture verifier returning the administration DTO cannot normalize it into a journal receipt.
      f.receipts.set('wrong-authority', candidate);
      assert.throws(() => f.journal().record(f.r, { ref: 'wrong-authority' }), e => e.code === 'receipt_invalid');
      assert.equal(f.disk(), pending);
    }
    f.journal().record(f.r, f.evidence(plan));
  }
  const complete = f.disk(); assert.equal(f.journal().next(f.r).status, 'complete'); assert.equal(f.disk(), complete);
});

integration('unknown writer commit with visible candidate is unproven, separately A2-eligible, and never a receipt or automatic fence', t => {
  const f = fixture(t, { grant: false }), original = fs.fsyncSync, before = fs.readFileSync(f.jobsFile); let calls = 0, result;
  const command = JSON.stringify(f.command('set'));
  fs.fsyncSync = fd => { if (++calls === 4) throw Error(canary + f.directory); original(fd); };
  try { result = f.writer.mutate(command); } finally { fs.fsyncSync = original; }
  assert.equal(result.status, 'outcome_unknown'); assert.equal(result.code, 'commit_unknown');
  f.privateDigests.add(result.oldDigest); f.privateDigests.add(result.candidateDigest);
  const candidate = fs.readFileSync(f.jobsFile); assert(!candidate.equals(before)); assert.equal(byteDigest(candidate), result.candidateDigest);
  assert(fs.existsSync(f.jobsFile + '.host-admission.lock'));
  const entries = fs.readdirSync(f.directory), observation = f.writer.reconcile(JSON.stringify({ version: 1, oldDigest: result.oldDigest, candidateDigest: result.candidateDigest }));
  assert.deepEqual(observation, { status: 'observed', visibility: 'candidate', durability: 'unproven', coordination: 'blocked' });
  assert.deepEqual(fs.readdirSync(f.directory), entries); assert(fs.readFileSync(f.jobsFile).equals(candidate));
  assert.equal(f.disk(), ''); // The administrative result itself created no journal state.
  assert.equal(f.adapter(f.r, descriptor(f.r, source)).jobId, f.r.jobId);
  // Existing A2/journal do NOT consume writer outcome or lock state. Deliberately expose,
  // rather than hide, this boundary; no installed driver/fence/recovery is added here.
  const plan = f.journal().next(f.r); assert.equal(plan.status, 'intent'); assert.equal(plan.intent.step, 'execution');
  noLeaks(f, plan); const pending = f.disk();
  for (const value of [result, observation]) {
    f.receipts.set('admin-only', value);
    assert.throws(() => f.journal().record(f.r, { ref: 'admin-only' }), e => e.code === 'receipt_invalid');
    assert.equal(f.disk(), pending);
  }
  assert.equal(f.journal().next(f.r).status, 'outcome_unknown'); assert.equal(f.disk(), pending);
  // No administrative replay, cleanup, recovery fsync or rollback: artifacts remain.
  assert(fs.existsSync(f.jobsFile + '.host-admission.lock')); assert(fs.readFileSync(f.jobsFile).equals(candidate));
});
