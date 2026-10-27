import { runSyntheticSupervisor } from './host-operator-cgroup-supervisor.test.mjs';
// Offline conformance only: actual writer -> signed A1 / pinned A2 -> actual journal.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawn } from 'node:child_process';
import { createSupervisedRevisionIssuer } from '../host-operator-auth/supervised-revision.mjs';
import { createRevisionEvidenceStore } from '../host-operator-auth/revision-evidence.mjs';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { schnorr } from '../host-operator-auth/node_modules/@noble/curves/secp256k1.js';
import { createRevisionCompletionVerifier } from '../host-operator-auth/revision-completion.mjs';
import { createLocalRevisionInvocation } from '../host-operator-auth/local-invocation.mjs';
import { createRevisionObservationBridge } from '../host-operator-auth/revision-observation.mjs';
import { createLocalEventIngress } from '../host-operator-auth/local-ingress.mjs';
import { createFileEventPlacer } from '../host-operator-auth/event-placement.mjs';
import { createFileEventResolver } from '../host-operator-auth/event-source.mjs';
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
function fixture(t, { grant = true, preplace = true } = {}) {
  assert.notEqual(process.getuid(), 0, 'ordinary UID required');
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'host-composition-')); fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const journalDir = path.join(directory, 'journal'); fs.mkdirSync(journalDir, { mode: 0o700 });
  const agentsFile = path.join(directory, 'agents.json'), jobsFile = path.join(directory, 'jobs.json');
  const eventDir = path.join(directory, 'events'); fs.mkdirSync(eventDir, { mode: 0o700 });
  const eventFile = id => path.join(eventDir, id + '.json');
  const hostileEvent = (value, id = value.id) => {
    fs.writeFileSync(eventFile(id) + '.new', JSON.stringify(value), { mode: 0o600 });
    fs.renameSync(eventFile(id) + '.new', eventFile(id));
  };
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
  const placer = createFileEventPlacer({ directory: eventDir, uid: process.getuid(), ownerPubkey, targetPubkey, channelId, threadId, source, clock: () => clock });
  const placement = preplace ? placer.place(JSON.stringify(event)) : null;
  if (preplace) assert.equal(placement.status, 'confirmed');
  let eventReads = 0, eventHook = () => {};
  const resolveEvent = createFileEventResolver({ directory: eventDir, uid: process.getuid(), clock: () => clock, monotonic: () => 0 });
  const adapterOptions = { ...owner, channelId, threadId, source, clock: () => clock,
    resolveEvent: id => { eventHook(++eventReads); return resolveEvent(id); }, currentJob: (...args) => current(...args) };
  const adapter = createAuthorizationAdapter(adapterOptions);
  const journal = () => new HostOperatorJournal({ directory: journalDir, source, ownerPubkey, authorize: adapter, clock: () => clock,
    verifyReceipt: evidence => { if (!receipts.has(evidence.ref)) throw Error(canary + directory); return receipts.get(evidence.ref); } });
  const ingress = () => createLocalEventIngress({ eventDirectory: eventDir, journalDirectory: journalDir, uid: process.getuid(),
    ...owner, channelId, threadId, source, currentJob: (...args) => current(...args), clock: () => clock, monotonic: () => 0,
    verifyReceipt: evidence => { if (!receipts.has(evidence.ref)) throw Error(canary + directory); return receipts.get(evidence.ref); } });
  const sourceDir = path.join(directory, 'observed-source');
  const bridge = () => {
    if (!fs.existsSync(sourceDir)) { fs.mkdirSync(sourceDir, { mode: 0o700 }); fs.mkdirSync(path.join(sourceDir, '.git'), { mode: 0o700 }); fs.writeFileSync(path.join(sourceDir, '.git/HEAD'), source.baseSha + '\n', { mode: 0o600 }); }
    return createRevisionObservationBridge({ eventDirectory: eventDir, journalDirectory: journalDir, sourceDirectory: sourceDir, uid: process.getuid(),
      ...owner, channelId, threadId, source, currentJob: (...args) => current(...args), clock: () => clock, monotonic: () => 0,
      verifyReceipt: evidence => { if (!receipts.has(evidence.ref)) throw Error(canary + directory); return receipts.get(evidence.ref); } });
  };
  const invocation = () => {
    // Same fixture source namespace; production constructor itself creates nothing.
    if (!fs.existsSync(sourceDir)) { fs.mkdirSync(sourceDir, { mode: 0o700 }); fs.mkdirSync(path.join(sourceDir, '.git'), { mode: 0o700 }); fs.writeFileSync(path.join(sourceDir, '.git/HEAD'), source.baseSha + '\n', { mode: 0o600 }); }
    return createLocalRevisionInvocation({ eventDirectory: eventDir, journalDirectory: journalDir, sourceDirectory: sourceDir, uid: process.getuid(),
      ...owner, channelId, threadId, source, currentJob: (...args) => current(...args), clock: () => clock, monotonic: () => 0,
      verifyReceipt: evidence => { if (!receipts.has(evidence.ref)) throw Error(canary + directory); return receipts.get(evidence.ref); } });
  };
  const completion = () => {
    // Independent synthetic completion authority; NOT a deployed execution issuer.
    const proofs = new Map(); let available = true;
    const verify = createRevisionCompletionVerifier({ source, authorityId: 'fixture-terminal-authority', clock: () => clock,
      resolveCompletion: ref => { if (!available || !proofs.has(ref)) throw Error(canary + directory); return proofs.get(ref); } });
    const proof = (plan, changes = {}) => {
      const p = { version: 1, type: 'host-operator.revision-completion', authorityId: 'fixture-terminal-authority', completionId: 'terminal-proof',
        requestHash: plan.intent.requestHash, intentId: plan.intent.intentId, intentDigest: digest(plan.intent), descriptorDigest: plan.intent.descriptorDigest,
        startedAt: plan.intent.createdAt, finishedAt: clock, outcome: 'success', execution: { kind: 'in_process_read_only', settled: true, descendants: 0 },
        resultDigest: 'f'.repeat(64), summary: { passed: 0, failed: 0, skipped: 0, exitCode: null, signal: null }, ...changes };
      proofs.set('completion-proof', p); return { ref: 'completion-proof', digest: digest(p) };
    };
    const make = () => new HostOperatorJournal({ directory: journalDir, source, ownerPubkey, authorize: adapter, clock: () => clock,
      verifyRevisionCompletion: verify, verifyReceipt: (e, i, c) => {
        if (i.step === 'execution') return verify(e, i, c);
        if (!receipts.has(e.ref)) throw Error(canary); return receipts.get(e.ref);
      } });
    return { proof, make, proofs, available: value => { available = value; } };
  };
  function evidence(plan, outcome = 'success') {
    const ref = 'proof-' + receipts.size;
    receipts.set(ref, { version: 1, receiptId: ref, intentId: plan.intent.intentId, intentDigest: digest(plan.intent),
      requestHash: digest(r), step: plan.intent.step, outcome, finishedAt: clock, evidenceRef: ref, evidenceDigest: 'f'.repeat(64),
      summary: { passed: 1, failed: 0, skipped: 0, exitCode: 0, signal: null } });
    return { ref };
  }
  const disk = () => fs.existsSync(path.join(journalDir, 'state.json')) ? fs.readFileSync(path.join(journalDir, 'state.json'), 'utf8') : '';
  return { r, directory, journalDir, agentsFile, jobsFile, eventDir, eventFile, hostileEvent, placer, placement, write, writer, command, admin, privateDigests, journal, ingress, bridge, invocation, sourceDir, completion, evidence, receipts, disk, adapter, adapterOptions, provider,
    time: value => { clock = value; }, event: value => { event = value; hostileEvent(value, r.authorizationEventId); if (value.id !== r.authorizationEventId) hostileEvent(value); },
    eventHook: fn => { eventHook = fn; },
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
    assert.throws(() => f.journal().record(f.r, f.placement), e => e.code === 'receipt_invalid');
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

for (const step of ['execution', 'kaneo', 'buzz']) for (const at of [1, 2]) for (const fault of ['delete', 'replace']) integration(`file source ${fault} at ${step} authorization ${at} denies without changing journal history`, t => {
  const f = fixture(t);
  for (const prior of ['execution', 'kaneo']) {
    if (prior === step) break;
    const plan = f.journal().next(f.r); f.journal().record(f.r, f.evidence(plan));
  }
  const before = f.disk(); let reads = 0, changed = 0;
  f.eventHook(() => {
    if (++reads !== at) return;
    assert.equal(fs.existsSync(path.join(f.journalDir, 'journal.lock')), at === 2);
    if (fault === 'delete') fs.unlinkSync(f.eventFile(f.r.authorizationEventId));
    else f.hostileEvent(signed({ ...baseRequest, requestId: 'different-valid-event' }), f.r.authorizationEventId);
    changed++;
  });
  denied(f); assert.equal(changed, 1); assert.equal(f.disk(), before); noLeaks(f, before);
});
for (const fault of ['delete', 'malformed']) integration(`missing or ${fault} event does not block separate historical receipt, but denies next intent and complete replay`, t => {
  const f = fixture(t), pending = f.journal().next(f.r), proof = f.evidence(pending), before = f.disk();
  assert.equal(f.journal().next(f.r).status, 'outcome_unknown'); assert.equal(f.disk(), before);
  if (fault === 'delete') fs.unlinkSync(f.eventFile(f.r.authorizationEventId));
  else fs.writeFileSync(f.eventFile(f.r.authorizationEventId), canary);
  denied(f); assert.equal(f.journal().record(f.r, proof).status, 'recorded'); denied(f);
  // Fixture-only restoration: it is not fallback behavior in the source or adapter.
  f.hostileEvent(signed());
  for (const step of ['kaneo', 'buzz']) {
    const plan = f.journal().next(f.r); assert.equal(plan.intent.step, step); f.journal().record(f.r, f.evidence(plan));
  }
  const complete = f.disk(); fs.unlinkSync(f.eventFile(f.r.authorizationEventId)); denied(f); assert.equal(f.disk(), complete);
});
integration('explicit error/Promise raw-event seams cannot replace the real file resolver with authority', t => {
  const f = fixture(t);
  for (const resolveEvent of [() => { throw Error(canary + f.directory); }, () => Promise.resolve(signed()), () => ({ verified: true })]) {
    const adapter = createAuthorizationAdapter({ ...f.adapterOptions, resolveEvent });
    denied(f, () => adapter(f.r, descriptor(f.r, source))); assert.equal(f.disk(), '');
  }
});

integration('real placement unknown is separate from A8 visibility, A2 eligibility and journal receipt authority', t => {
  for (const point of ['two-links', 'parent-sync']) {
    const f = fixture(t); fs.unlinkSync(f.eventFile(f.r.authorizationEventId));
    const name = point === 'two-links' ? 'unlinkSync' : 'fsyncSync', original = fs[name];
    fs[name] = (...args) => {
      if (point === 'two-links' || fs.fstatSync(args[0]).isDirectory()) throw Error(canary + f.directory);
      return original(...args);
    };
    let placement; try { placement = f.placer.place(JSON.stringify(signed())); } finally { fs[name] = original; }
    assert.equal(placement.status, 'outcome_unknown'); noLeaks(f, placement);
    if (point === 'two-links') { denied(f); assert.equal(fs.statSync(f.eventFile(f.r.authorizationEventId)).nlink, 2); }
    else {
      const plan = f.journal().next(f.r); assert.equal(plan.intent.step, 'execution');
      assert.throws(() => f.journal().record(f.r, placement), e => e.code === 'receipt_invalid');
      assert.equal(f.placer.place(JSON.stringify(signed())).status, 'already_present');
      f.admin('remove'); denied(f);
    }
  }
});

integration('A10 actual ingress composes confirmed A9 -> A8/A1 -> real A2/writer -> one journal DATA intent', t => {
  const f = fixture(t, { preplace: false }), ingress = f.ingress();
  assert(!fs.existsSync(f.eventFile(f.r.authorizationEventId))); assert.equal(f.disk(), '');
  const result = ingress.ingest(JSON.stringify(signed())); assert.equal(result.status, 'intent'); assert.equal(result.intent.step, 'execution'); noLeaks(f, result);
  const pending = f.disk(); assert.equal(ingress.ingest(JSON.stringify(signed())).status, 'placement_unconfirmed'); assert.equal(f.disk(), pending);
  assert.throws(() => f.journal().record(f.r, result), e => e.code === 'receipt_invalid');
  const proof = f.evidence(result); fs.unlinkSync(f.eventFile(f.r.authorizationEventId)); f.time(now + 600000);
  assert.equal(f.journal().record(f.r, proof).status, 'recorded'); denied(f);
  assert.equal(ingress.ingest(JSON.stringify(signed())).status, 'ingress_denied');
});
for (const at of [1, 2]) integration(`A10 confirmed placement cannot cache past actual writer revocation before policy check ${at}`, t => {
  const f = fixture(t, { preplace: false }), ingress = f.ingress(); let changed = 0;
  f.hook(call => { if (call === at) { assert.equal(f.admin('remove').status, 'confirmed'); changed++; } });
  const result = ingress.ingest(JSON.stringify(signed())); assert.equal(result.status, 'admission_denied'); assert.equal(changed, 1); assert.equal(f.disk(), '');
  assert.equal(fs.readFileSync(f.eventFile(f.r.authorizationEventId), 'utf8'), JSON.stringify(signed())); noLeaks(f, result);
});
integration('A10 valid placement does not grant disabled/expired/missing/misbound actual A2 policy', t => {
  for (const fault of ['disabled', 'expired', 'missing', 'wrong-binding']) {
    const f = fixture(t, { preplace: false, grant: fault !== 'missing' });
    if (fault !== 'missing') {
      const state = JSON.parse(fs.readFileSync(f.jobsFile, 'utf8')), agents = JSON.parse(fs.readFileSync(f.agentsFile, 'utf8'));
      if (fault === 'disabled') agents.agents[0].disabled = true;
      if (fault === 'expired') state.jobs[0].hostAdmission.expiresAt = new Date(now).toISOString();
      if (fault === 'wrong-binding') state.jobs[0].hostAdmission.taskId = 'different-task';
      f.write({ agents, jobs: state }); // Explicit hostile administrative fixture, not a production grant.
    }
    const result = f.ingress().ingest(JSON.stringify(signed())); assert.equal(result.status, 'admission_denied'); noLeaks(f, result); assert.equal(f.disk(), ''); assert(fs.existsSync(f.eventFile(f.r.authorizationEventId)));
  }
});
integration('A10 unknown visible candidate never advances this coordinator although direct journal eligibility remains separate', t => {
  const f = fixture(t, { preplace: false }), ingress = f.ingress(), original = fs.fsyncSync;
  fs.fsyncSync = fd => { if (fs.fstatSync(fd).isDirectory()) throw Error(canary + f.directory); return original(fd); };
  let result; try { result = ingress.ingest(JSON.stringify(signed())); } finally { fs.fsyncSync = original; }
  assert.equal(result.status, 'placement_unconfirmed'); noLeaks(f, result); assert.equal(f.disk(), '');
  assert.equal(ingress.ingest(JSON.stringify(signed())).status, 'placement_unconfirmed'); assert.equal(f.disk(), '');
  const direct = f.journal().next(f.r); assert.equal(direct.status, 'intent'); assert.equal(direct.intent.step, 'execution');
  // Direct journal API is a separate authority boundary; ingress adds no universal filesystem fence.
});
integration('A10 journal persistence lost response never returns placement success or retries an admitted effect', t => {
  const f = fixture(t, { preplace: false }), ingress = f.ingress(), original = fs.renameSync;
  fs.renameSync = (...args) => { const result = original(...args); if (args[1] === path.join(f.journalDir, 'state.json')) throw Error(canary + f.directory); return result; };
  let result; try { result = ingress.ingest(JSON.stringify(signed())); } finally { fs.renameSync = original; }
  assert.deepEqual(result, { status: 'outcome_unknown', code: 'journal_unconfirmed' }); noLeaks(f, result);
  const before = f.disk(); assert.equal(Object.values(JSON.parse(before).entries)[0].effects.length, 1);
  assert.equal(ingress.ingest(JSON.stringify(signed())).status, 'placement_unconfirmed'); assert.equal(f.disk(), before);
  assert.equal(f.journal().next(f.r).status, 'outcome_unknown');
});

integration('A12 actual ingress -> pending journal -> actual A11 bridge observes/mismatches without consuming execution', t => {
  const f=fixture(t,{preplace:false}),plan=f.ingress().ingest(JSON.stringify(signed())),expected={intentId:plan.intent.intentId,intentDigest:plan.intentDigest},bridge=f.bridge(),before=f.disk();
  const result=bridge.observe(JSON.stringify(signed()),expected);assert.equal(result.status,'observed');assert.equal(result.intentId,plan.intent.intentId);assert.equal(result.observation.observedSha,source.baseSha);noLeaks(f,result);assert.equal(f.disk(),before);
  fs.writeFileSync(path.join(f.sourceDir,'.git/HEAD'),'a'.repeat(40));const mismatch=bridge.observe(JSON.stringify(signed()),expected);assert.equal(mismatch.status,'mismatch');assert.equal(mismatch.observation.observedSha,'a'.repeat(40));assert.equal(f.disk(),before);
  assert.equal(f.journal().next(f.r).status,'outcome_unknown');assert.throws(()=>f.journal().record(f.r,result),e=>e.code==='receipt_invalid');assert.equal(f.disk(),before);
});
for(const at of [1,2,3,4])integration(`A12 actual writer revoke before inspection policy call${at} suppresses result`,t=>{
  const f=fixture(t,{preplace:false}),plan=f.ingress().ingest(JSON.stringify(signed())),expected={intentId:plan.intent.intentId,intentDigest:plan.intentDigest},bridge=f.bridge(),before=f.disk();let calls=0;
  f.hook(()=>{if(++calls===at)assert.equal(f.admin('remove').status,'confirmed');});
  assert.throws(()=>bridge.observe(JSON.stringify(signed()),expected),e=>e.code==='revision_observation_denied'&&e.message===e.code&&e.stack===e.code);assert.equal(f.disk(),before);
});
for(const fault of ['event-delete','receipt-record'])integration(`A12 ${fault} during actual source read suppresses stale observation`,t=>{
  const f=fixture(t,{preplace:false}),plan=f.ingress().ingest(JSON.stringify(signed())),expected={intentId:plan.intent.intentId,intentDigest:plan.intentDigest},bridge=f.bridge(),before=f.disk(),original=fs.readSync;let changed=false;
  fs.readSync=(fd,...args)=>{const count=original(fd,...args);if(fs.fstatSync(fd).size===41&&!changed){changed=true;if(fault==='event-delete')fs.unlinkSync(f.eventFile(f.r.authorizationEventId));else assert.equal(f.journal().record(f.r,f.evidence(plan)).status,'recorded');}return count;};
  try{assert.throws(()=>bridge.observe(JSON.stringify(signed()),expected),e=>e.code==='revision_observation_denied');}finally{fs.readSync=original;}
  assert(changed);if(fault==='event-delete'){assert.equal(f.disk(),before);f.time(now+600000);assert.equal(f.journal().record(f.r,f.evidence(plan)).status,'recorded');}else assert.equal(Object.values(JSON.parse(f.disk()).entries)[0].effects[0].receipt.outcome,'success');
});

integration('A13 actual invocation composes fresh admission and observation; repeat never resumes and busy request cannot observe',t=>{
  const f=fixture(t,{preplace:false}),invocation=f.invocation(),raw=JSON.stringify(signed());const result=invocation.invoke(raw);assert.equal(result.status,'observed');assert.equal(result.observation.observation.observedSha,source.baseSha);noLeaks(f,result);const before=f.disk();assert.equal(Object.values(JSON.parse(before).entries)[0].effects[0].receipt,null);
  assert.deepEqual(invocation.invoke(raw),{status:'not_observed',stage:'admission',code:'placement_unconfirmed'});assert.equal(invocation.invoke(JSON.stringify(signed({...baseRequest,requestId:'request-two'}))).code,'workspace_busy');assert.equal(f.disk(),before);assert.throws(()=>f.journal().record(f.r,result),e=>e.code==='receipt_invalid');
});
integration('A13 actual different HEAD returns mismatch without consuming pending intent',t=>{
  const f=fixture(t,{preplace:false}),invocation=f.invocation();fs.writeFileSync(path.join(f.sourceDir,'.git/HEAD'),'2'.repeat(40));const result=invocation.invoke(JSON.stringify(signed()));assert.equal(result.status,'mismatch');assert.equal(result.observation.observation.observedSha,'2'.repeat(40));assert.equal(f.journal().next(f.r).status,'outcome_unknown');noLeaks(f,result);
});
for(const at of [3,4,5,6])integration(`A13 actual writer revoke at policy call${at} after admission suppresses observation`,t=>{
  const f=fixture(t,{preplace:false}),invocation=f.invocation();f.hook(call=>{if(call===at)assert.equal(f.admin('remove').status,'confirmed');});const result=invocation.invoke(JSON.stringify(signed()));assert.equal(result.status,'not_observed');assert.equal(result.stage,'observation');assert.equal(result.code,'revision_observation_denied');const effect=Object.values(JSON.parse(f.disk()).entries)[0].effects[0];assert.equal(effect.receipt,null);assert.equal(result.admittedIntent.intentId,effect.intent.intentId);noLeaks(f,result);
});
for(const point of ['receipt','event'])integration(`A13 concurrent actual ${point} during source read preserves durable progress without stale result`,t=>{
  const f=fixture(t,{preplace:false}),invocation=f.invocation(),original=fs.readSync;let changed=false;fs.readSync=(fd,...args)=>{const n=original(fd,...args);if(fs.fstatSync(fd).size===41&&!changed){changed=true;if(point==='event')fs.unlinkSync(f.eventFile(f.r.authorizationEventId));else{const i=Object.values(JSON.parse(f.disk()).entries)[0].effects[0].intent;assert.equal(f.journal().record(f.r,f.evidence({intent:i,intentDigest:digest(i)})).status,'recorded');}}return n;};let result;try{result=invocation.invoke(JSON.stringify(signed()));}finally{fs.readSync=original;}assert(changed);assert.equal(result.status,'not_observed');assert.equal(result.stage,'observation');if(point==='receipt')assert.equal(Object.values(JSON.parse(f.disk()).entries)[0].effects[0].receipt.outcome,'success');else assert.equal(Object.values(JSON.parse(f.disk()).entries)[0].effects[0].receipt,null);noLeaks(f,result);
});

integration('A14 actual writer/provider partial admission explicitly resumes without renewal or readmission',t=>{
  const f=fixture(t,{preplace:false}),api=f.invocation(),raw=JSON.stringify(signed()),head=path.join(f.sourceDir,'.git/HEAD');fs.writeFileSync(head,'ref: refs/heads/main\n');const first=api.invoke(raw);assert.equal(first.stage,'observation');assert.equal(first.status,'not_observed');const before=f.disk(),i=Object.values(JSON.parse(before).entries)[0].effects[0].intent;fs.writeFileSync(head,source.baseSha+'\n');const result=api.resume(raw,first.admittedIntent);assert.equal(result.status,'observed');assert.deepEqual(result.admittedIntent,first.admittedIntent);assert.equal(result.observation.requestHash,digest(f.r));assert.equal(f.disk(),before);assert.equal(api.invoke(raw).code,'placement_unconfirmed');assert.throws(()=>f.journal().record(f.r,result),e=>e.code==='receipt_invalid');
  fs.writeFileSync(head,'2'.repeat(40));assert.equal(f.invocation().resume(raw,first.admittedIntent).status,'mismatch');assert.equal(f.disk(),before);f.time(i.deadline);assert.deepEqual(f.invocation().resume(raw,first.admittedIntent),{status:'not_observed',stage:'resume',code:'revision_observation_denied'});assert.equal(f.disk(),before);noLeaks(f,result);
});
for(const at of [1,2,3,4])integration(`A14 actual writer removal at resume policy call${at} denies without state change`,t=>{
  const f=fixture(t,{preplace:false}),api=f.invocation(),raw=JSON.stringify(signed()),first=api.invoke(raw),before=f.disk();let calls=0;f.current((...args)=>{if(++calls===at)assert.equal(f.admin('remove').status,'confirmed');return f.provider(...args);});assert.deepEqual(api.resume(raw,first.admittedIntent),{status:'not_observed',stage:'resume',code:'revision_observation_denied'});assert.equal(f.disk(),before);
});
for(const point of ['receipt','event'])integration(`A14 actual ${point} change during resumed source read suppresses output`,t=>{
  const f=fixture(t,{preplace:false}),api=f.invocation(),raw=JSON.stringify(signed()),first=api.invoke(raw),original=fs.readSync;let changed=false;fs.readSync=(fd,...args)=>{const n=original(fd,...args);if(fs.fstatSync(fd).size===41&&!changed){changed=true;if(point==='event')fs.unlinkSync(f.eventFile(f.r.authorizationEventId));else{const intent=Object.values(JSON.parse(f.disk()).entries)[0].effects[0].intent;assert.equal(f.journal().record(f.r,f.evidence({intent})).status,'recorded');}}return n;};let result;try{result=api.resume(raw,first.admittedIntent);}finally{fs.readSync=original;}assert(changed);assert.deepEqual(result,{status:'not_observed',stage:'resume',code:'revision_observation_denied'});const receipt=Object.values(JSON.parse(f.disk()).entries)[0].effects[0].receipt;assert.equal(receipt?.outcome??null,point==='receipt'?'success':null);noLeaks(f,result);
});

integration('A15 actual signed admission -> independent terminal proof -> durable receipt -> opt-in next execution while old reports remain',t=>{
  const f=fixture(t,{preplace:false}),first=f.ingress().ingest(JSON.stringify(signed())),c=f.completion(),j=c.make(),secondEvent=signed({...baseRequest,requestId:'second'}),second={...baseRequest,requestId:'second',authorizationEventId:secondEvent.id};assert.equal(f.placer.place(JSON.stringify(secondEvent)).status,'confirmed');assert.throws(()=>j.next(second),e=>e.code==='workspace_busy');const proof=c.proof(first);assert.equal(j.record(f.r,proof).status,'recorded');const before=f.disk();assert.throws(()=>f.journal().next(second),e=>e.code==='workspace_busy');assert.equal(f.disk(),before);const next=c.make().next(second);assert.equal(next.intent.step,'execution');assert.equal(Object.values(JSON.parse(f.disk()).entries).find(e=>e.request.requestId===baseRequest.requestId).effects.length,1);
  assert.deepEqual(f.invocation().resume(JSON.stringify(signed()),{intentId:first.intent.intentId,intentDigest:first.intentDigest}),{status:'not_observed',stage:'resume',code:'revision_observation_denied'});
  const kaneo=j.next(f.r);assert.equal(kaneo.intent.step,'kaneo');assert.equal(kaneo.intent.payload.taskId,baseRequest.taskId);assert.throws(()=>j.record(f.r,proof),e=>e.code==='receipt_invalid');j.record(f.r,f.evidence(kaneo));const buzz=j.next(f.r);assert.equal(buzz.intent.step,'buzz');assert.equal(buzz.intent.payload.threadId,threadId);j.record(f.r,f.evidence(buzz));assert.equal(j.next(f.r).status,'complete');assert.equal(Object.values(JSON.parse(f.disk()).entries).find(e=>e.request.requestId==='second').effects[0].receipt,null);noLeaks(f,next);
});
integration('A15 actual Gateway revocation denies new effects while historical completion record remains possible',t=>{
  const f=fixture(t,{preplace:false}),first=f.ingress().ingest(JSON.stringify(signed())),c=f.completion(),proof=c.proof(first),event=signed({...baseRequest,requestId:'second'});f.placer.place(JSON.stringify(event));assert.equal(f.admin('remove').status,'confirmed');f.time(now+7200001);assert.equal(c.make().record(f.r,proof).status,'recorded');assert.throws(()=>c.make().next({...baseRequest,requestId:'second',authorizationEventId:event.id}),e=>e.code==='authorization_denied');assert.equal(Object.values(JSON.parse(f.disk()).entries).length,1);
});
integration('A15 real late settled-failed completion reconciles without timely-success claim and proof disappearance holds reservation',t=>{
  const f=fixture(t,{preplace:false}),first=f.ingress().ingest(JSON.stringify(signed())),c=f.completion();f.time(now+10000);const proof=c.proof(first,{outcome:'failed'});assert.equal(c.make().record(f.r,proof).status,'recorded');const event=signed({...baseRequest,requestId:'second'}),r={...baseRequest,requestId:'second',authorizationEventId:event.id};f.placer.place(JSON.stringify(event));c.available(false);assert.throws(()=>c.make().next(r),e=>e.code==='workspace_busy');c.available(true);assert.equal(c.make().next(r).intent.step,'execution');assert.equal(first.intent.deadline,now+5000);
});
integration('A15 observation/current-policy/locator/caller attestation cannot record or release actual pending execution',t=>{
  const f=fixture(t,{preplace:false}),first=f.ingress().ingest(JSON.stringify(signed())),c=f.completion(),actual=f.bridge().observe(JSON.stringify(signed()),{intentId:first.intent.intentId,intentDigest:first.intentDigest}),before=f.disk();for(const e of [actual,{intentId:first.intent.intentId,intentDigest:first.intentDigest},{ref:'missing',digest:'f'.repeat(64)},state().jobs.jobs[0].hostAdmission])assert.throws(()=>c.make().record(f.r,e),x=>x.code==='receipt_invalid');assert.equal(f.disk(),before);const proof=c.proof(first,{execution:{kind:'in_process_read_only',settled:false,descendants:0}});assert.throws(()=>c.make().record(f.r,proof),x=>x.code==='receipt_invalid');assert.equal(f.disk(),before);
});

function supervisedFixture(f,change=()=>{},wireMode) {
  f.bridge();const evidenceDirectory=f.directory+'/evidence';fs.mkdirSync(evidenceDirectory,{mode:0o700});for(const n of ['claims','objects'])fs.mkdirSync(evidenceDirectory+'/'+n,{mode:0o700});
  const pins={source,authorityId:'synthetic-supervisor-fixture',clockId:'fixture-clock',issuerArtifactDigest:byteDigest(fs.readFileSync(new URL('../host-operator-auth/supervised-revision.mjs',import.meta.url))),workerArtifactDigest:byteDigest(fs.readFileSync(new URL('../host-operator-auth/supervised-revision-worker.mjs',import.meta.url)))};
  let runs=0;const supervisor={async run(spec){runs++;assert(!fs.existsSync(f.journalDir+'/journal.lock'));assert(!fs.existsSync(evidenceDirectory+'/evidence.lock'));
    const child=spawn(spec.executable,[spec.entry],{env:spec.env,stdio:['pipe','pipe','pipe']});let stdout='',stderr='';child.stdout.on('data',b=>{stdout+=b;});child.stderr.on('data',b=>{stderr+=b;});child.stdin.end(spec.input);const terminal=await new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',(exitCode,signal)=>resolve({exitCode,signal}));});
    // SYNTHETIC boundary fixture. Actual child/reap correlation, no kernel proof.
    const answer={status:'settled',stdout,stderr,boundary:{version:1,runId:spec.runId,boundaryId:'synthetic-'+child.pid,requestHash:spec.requestHash,intentDigest:spec.intentDigest,workerArtifactDigest:spec.workerArtifactDigest,clockId:spec.clockId,startedAt:spec.startedAt,leaderExitedAt:spec.startedAt,settledAt:spec.startedAt,leaderReaped:true,noEscape:true,sealed:true,populated:0,...terminal}};await change(answer);if(wireMode){const vm=runSyntheticSupervisor({spec,now:spec.startedAt,source,sourceDirectory:f.sourceDir,stdout,mode:wireMode==='unknown'?'unknown':undefined});assert.equal(vm.status,0,vm.stderr);return vm.value.result;}return answer;}};
  const issuer=createSupervisedRevisionIssuer({eventDirectory:f.eventDir,journalDirectory:f.journalDir,sourceDirectory:f.sourceDir,evidenceDirectory,uid:process.getuid(),...owner,channelId,threadId,...pins,currentJob:f.adapterOptions.currentJob,clock:f.adapterOptions.clock,monotonic:()=>0,settlementWaitMs:5000,supervisor});
  const store=()=>createRevisionEvidenceStore({directory:evidenceDirectory,uid:process.getuid(),...pins});
  const verify=()=>createRevisionCompletionVerifier({source,authorityId:pins.authorityId,resolveCompletion:store().resolveCompletion,clock:f.adapterOptions.clock,supervised:Object.fromEntries(['issuerArtifactDigest','workerArtifactDigest','clockId'].map(k=>[k,pins[k]]))});
  const journal=(optin=true)=>new HostOperatorJournal({directory:f.journalDir,source,ownerPubkey,authorize:f.adapter,clock:f.adapterOptions.clock,...(optin?{verifyRevisionCompletion:verify()}:{}),verifyReceipt:(e,i,c)=>i.step==='execution'?verify()(e,i,c):f.receipts.get(e.ref)});
  return {issuer,store,journal,runs:()=>runs,evidenceDirectory};
}
for(const mismatch of [false,true])integration('A16 actual writer/A1/A2/child/store/v2 record and reservation '+(mismatch?'mismatch':'match'),async t=>{
 const f=fixture(t),plan=f.journal().next(f.r),s=supervisedFixture(f);if(mismatch)fs.writeFileSync(f.sourceDir+'/.git/HEAD','a'.repeat(40));const before=f.disk(),e=await s.issuer.issue(JSON.stringify(signed()),{intentId:plan.intent.intentId,intentDigest:plan.intentDigest});assert.equal(e.status,'issued');assert.equal(e.outcome,'success');assert.equal(f.disk(),before);assert.equal(s.journal().record(f.r,e.evidence).status,'recorded');
 const q={...baseRequest,requestId:'request-two'},event=signed(q),r={...q,authorizationEventId:event.id};assert.equal(f.placer.place(JSON.stringify(event)).status,'confirmed');assert.throws(()=>s.journal(false).next(r),x=>x.code==='workspace_busy');assert.equal(s.journal().next(r).intent.step,'execution');const kaneo=s.journal().next(f.r);assert.equal(kaneo.intent.step,'kaneo');s.journal().record(f.r,f.evidence(kaneo));const buzz=s.journal().next(f.r);assert.equal(buzz.intent.step,'buzz');s.journal().record(f.r,f.evidence(buzz));assert.equal(s.journal().next(f.r).status,'complete');assert.equal(s.runs(),1);
});
for(const point of ['revoke','expire','event','unreaped','descendant','escape'])integration('A16 actual policy/boundary '+point+' cannot confer success',async t=>{
 const f=fixture(t),plan=f.journal().next(f.r),s=supervisedFixture(f,a=>{if(point==='revoke')assert.equal(f.admin('remove').status,'confirmed');if(point==='expire')f.time(now+5000);if(point==='event')fs.unlinkSync(f.eventFile(f.r.authorizationEventId));if(point==='unreaped')a.boundary.leaderReaped=false;if(point==='descendant')a.boundary.populated=1;if(point==='escape')a.boundary.noEscape=false;});const before=f.disk(),v=await s.issuer.issue(JSON.stringify(signed()),{intentId:plan.intent.intentId,intentDigest:plan.intentDigest});assert.equal(f.disk(),before);if(['unreaped','descendant','escape'].includes(point)){assert.equal(v.status,'unknown');assert.deepEqual(fs.readdirSync(s.evidenceDirectory+'/objects'),[]);}else{assert.equal(v.outcome,'failed');assert.equal(s.journal().record(f.r,v.evidence).status,'recorded');}assert.equal(s.runs(),1);
});
integration('A16 current admission revoked before issue never claims or launches; retained proof loss holds reservation',async t=>{const f=fixture(t),plan=f.journal().next(f.r),s=supervisedFixture(f);assert.equal(f.admin('remove').status,'confirmed');const loc={intentId:plan.intent.intentId,intentDigest:plan.intentDigest};assert.equal((await s.issuer.issue(JSON.stringify(signed()),loc)).status,'unknown');assert.equal(s.runs(),0);assert.deepEqual(fs.readdirSync(s.evidenceDirectory+'/claims'),[]);assert.equal(f.admin('set').status,'confirmed');const v=await s.issuer.issue(JSON.stringify(signed()),loc);assert.equal(v.status,'issued');s.journal().record(f.r,v.evidence);fs.unlinkSync(s.evidenceDirectory+'/objects/'+v.evidence.ref+'.json');const q={...baseRequest,requestId:'request-two'},event=signed(q);f.placer.place(JSON.stringify(event));assert.throws(()=>s.journal().next({...q,authorizationEventId:event.id}),e=>e.code==='workspace_busy');});

for(const mode of ['match','mismatch','unknown'])integration('A17 actual policy/issuer -> synthetic new adapter IPC -> custody/receipt '+mode,async t=>{
 const f=fixture(t),plan=f.journal().next(f.r),s=supervisedFixture(f,()=>{},mode);if(mode==='mismatch')fs.writeFileSync(f.sourceDir+'/.git/HEAD','a'.repeat(40));const before=f.disk(),v=await s.issuer.issue(JSON.stringify(signed()),{intentId:plan.intent.intentId,intentDigest:plan.intentDigest});assert.equal(f.disk(),before);if(mode==='unknown'){assert.equal(v.status,'unknown');assert.equal(fs.readdirSync(s.evidenceDirectory+'/objects').length,0);return;}assert.equal(v.status,'issued');assert.equal(v.outcome,'success');assert.equal(s.journal().record(f.r,v.evidence).status,'recorded');assert.equal(s.journal().next(f.r).intent.step,'kaneo');const q={...baseRequest,requestId:'second-native-fixture'},e=signed(q);f.placer.place(JSON.stringify(e));assert.equal(s.journal().next({...q,authorizationEventId:e.id}).intent.step,'execution');
});
