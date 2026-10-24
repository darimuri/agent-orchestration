// Offline conformance only: actual A1 -> pinned built A2 -> actual journal.
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
const integration = (name, fn) => test(name, { skip: !build && 'run check-host-operator-integration.mjs for pinned A2 integration' }, fn);
const createHostPolicySource = build ? (await import(pathToFileURL(path.join(build, 'dist/host-policy-source.js')))).createHostPolicySource : null;
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
    repository: source.repository, baseRef: source.baseRef, baseSha: source.baseSha, status: 'active', expiresAt: new Date(now + 7200000).toISOString(),
    hostAdmission: { version: 1, ...owner, taskId: baseRequest.taskId, channelId, threadId, workspaceId: source.workspaceId,
      sourceDigest: source.sourceDigest, descriptorDigest: digest(descriptor(baseRequest, source)),
      allowedOperations: ['status.revision'], expiresAt: new Date(now + 1800000).toISOString() } }] } };
}
function fixture(t) {
  assert.notEqual(process.getuid(), 0, 'ordinary UID required');
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'host-composition-')); fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const journalDir = path.join(directory, 'journal'); fs.mkdirSync(journalDir, { mode: 0o700 });
  const agentsFile = path.join(directory, 'agents.json'), jobsFile = path.join(directory, 'jobs.json');
  function write(s = state()) {
    for (const [file, data] of [[agentsFile, s.agents], [jobsFile, s.jobs]]) {
      fs.writeFileSync(file + '.new', JSON.stringify(data), { mode: 0o600 }); fs.renameSync(file + '.new', file);
    }
  }
  write();
  let clock = now, event = signed(), calls = 0, hook = () => {}, monotonic = () => 0;
  const r = { ...baseRequest, authorizationEventId: event.id }, receipts = new Map();
  const options = { agentsFile, jobsFile, owner, allowedOwners: ['test-org'], uid: process.getuid(), clock: () => clock,
    monotonic: () => monotonic() };
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
  return { r, directory, journalDir, agentsFile, jobsFile, write, journal, evidence, receipts, disk, adapter, adapterOptions, provider,
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
  for (const secret of [canary, f.directory, 'tokenSha256', 'a'.repeat(64), 'developer-1']) assert.equal(text.includes(secret), false);
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
    else delete s.jobs.jobs[0].hostAdmission; f.write(s); } });
  denied(f); assert.equal(f.disk(), '');
});
for (const boundary of ['kaneo', 'buzz']) integration(`revocation before later ${boundary} intent preserves prior receipts`, t => {
  const f = fixture(t);
  for (const step of ['execution', 'kaneo']) {
    if (step === boundary) break;
    const plan = f.journal().next(f.r); f.journal().record(f.r, f.evidence(plan));
  }
  const s = state(); delete s.jobs.jobs[0].hostAdmission; f.write(s); denied(f);
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
