import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { schnorr } from '../host-operator-auth/node_modules/@noble/curves/secp256k1.js';
import { verifyOwnerEvent } from '../host-operator-auth/owner-event.mjs';
import { createAuthorizationAdapter } from '../host-operator-auth/authorization.mjs';
import { HostOperatorJournal } from './host-operator-journal.mjs';
import { digest, descriptor, ProtocolError } from './host-operator-protocol.mjs';

// PUBLIC BIP-340 vector-0 scalar, used ONLY to sign disposable test data.
// Never use this publicly known scalar or the fixture identities operationally.
// https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
const publicTestScalar = Buffer.from('0'.repeat(63) + '3', 'hex');
const ownerPubkey = 'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9';
const now = 1800000000000, channelId = '00000000-0000-0000-0000-000000000001';
const threadId = 'd'.repeat(64), targetPubkey = 'e'.repeat(64);
const source = { repository: 'test-org/project', baseRef: 'main', baseSha: 'b'.repeat(40),
  workspaceId: 'host-fixture', sourceDigest: 'c'.repeat(64) };
const baseRequest = { version: 1, requestId: 'request-one', taskId: 'task-one', jobId: 'job-one',
  repository: source.repository, baseRef: source.baseRef, baseSha: source.baseSha,
  operationId: 'status.revision', channelId, threadId };
const config = { ownerPubkey, targetPubkey, channelId, threadId, source, now };
const hashEvent = e => createHash('sha256').update(JSON.stringify([
  0, e.pubkey, e.created_at, e.kind, e.tags, e.content,
])).digest('hex');
function sign(event, scalar = publicTestScalar) {
  const e = { ...event, pubkey: Buffer.from(schnorr.getPublicKey(scalar)).toString('hex') };
  e.id = hashEvent(e);
  e.sig = Buffer.from(schnorr.sign(Buffer.from(e.id, 'hex'), scalar, new Uint8Array(32))).toString('hex');
  return e;
}
function signed({ r = baseRequest, envelope = {}, event = {} } = {}) {
  return sign({ pubkey: ownerPubkey, kind: 9, created_at: now / 1000,
    tags: [['h', channelId], ['e', threadId, '', 'root'], ['p', targetPubkey]],
    content: JSON.stringify({ type: 'host-operator.request', version: 1, request: r,
      descriptorDigest: digest(descriptor(r, source)), expiresAt: now + 600000, ...envelope }), ...event });
}
const verify = (event, change = {}) => verifyOwnerEvent(JSON.stringify(event), { ...config, ...change });
function denied(fn) {
  assert.throws(fn, e => e instanceof ProtocolError && e.code === 'authorization_denied' &&
    e.message === 'authorization_denied' && !e.stack.includes('SECRET_CANARY'));
}
function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'owner-auth-fixture-')); fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  let event = signed(), clock = now, calls = 0, provider = () => facts();
  const r = { ...baseRequest, authorizationEventId: event.id }, receipts = new Map();
  function facts() {
    return { ...Object.fromEntries(['taskId', 'jobId', 'repository', 'baseRef', 'baseSha',
      'operationId', 'channelId', 'threadId'].map(k => [k, r[k]])),
      requesterId: 'owner', role: 'owner', ownerPubkey, mentionPubkey: ownerPubkey, targetPubkey,
      workspaceId: source.workspaceId, sourceDigest: source.sourceDigest,
      descriptorDigest: digest(descriptor(r, source)), requestHash: digest(r),
      enabled: true, status: 'active', requesterMember: true, ownerAllowed: true,
      allowedOperations: ['status.revision'], verifiedAt: clock, expiresAt: now + 3600000 };
  }
  const options = { ownerPubkey, requesterId: 'owner', mentionPubkey: ownerPubkey, targetPubkey,
    channelId, threadId, source, clock: () => clock,
    resolveEvent: () => JSON.stringify(event), currentJob: (...args) => { calls++; return provider(...args); } };
  const adapter = createAuthorizationAdapter(options);
  const journal = () => new HostOperatorJournal({ directory, source, ownerPubkey, clock: () => clock,
    authorize: adapter, verifyReceipt: evidence => {
      if (!receipts.has(evidence.ref)) throw new Error('SECRET_CANARY');
      return receipts.get(evidence.ref);
    } });
  function evidence(plan) {
    const ref = `proof-${receipts.size}`;
    receipts.set(ref, { version: 1, receiptId: ref, intentId: plan.intent.intentId,
      intentDigest: digest(plan.intent), requestHash: digest(r), step: plan.intent.step, outcome: 'success',
      finishedAt: clock, evidenceRef: ref, evidenceDigest: 'f'.repeat(64),
      summary: { passed: 1, failed: 0, skipped: 0, exitCode: 0, signal: null } });
    return { ref };
  }
  return { r, directory, facts, options, adapter, journal, evidence, receipts,
    time: n => { clock = n; }, event: e => { event = e; }, provider: p => { provider = p; }, calls: () => calls };
}
const disk = f => fs.readFileSync(path.join(f.directory, 'state.json'), 'utf8');

test('public BIP-340 vector 0 and independently fixed invalid signature', () => {
  const signature = Buffer.from('e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0', 'hex');
  assert.equal(schnorr.verify(signature, new Uint8Array(32), Buffer.from(ownerPubkey, 'hex')), true);
  signature[0] ^= 1;
  assert.equal(schnorr.verify(signature, new Uint8Array(32), Buffer.from(ownerPubkey, 'hex')), false);
});
test('valid direct-owner event derives request and descriptor; UTF-8 bytes accepted', () => {
  const e = signed(), proof = verify(e);
  assert.deepEqual(proof.request, { ...baseRequest, authorizationEventId: e.id });
  assert.deepEqual(proof.descriptor, descriptor(proof.request, source));
  assert.deepEqual(verifyOwnerEvent(Buffer.from(JSON.stringify(e)), config), proof);
});
test('reordered logical request keys preserve binding; event wire content still authenticated', () => {
  const r = Object.fromEntries(Object.entries(baseRequest).reverse());
  assert.equal(digest(verify(signed({ r })).request), digest({ ...baseRequest, authorizationEventId: signed({ r }).id }));
  const e = signed(); e.content = JSON.stringify(JSON.parse(e.content), null, 2);
  denied(() => verify(e)); assert.equal(verify(sign(e)).request.requestId, baseRequest.requestId);
});
test('every signed event field mutation denies, even when a copied ID is retained', () => {
  const e = signed();
  for (const change of [{ content: e.content + ' ' }, { created_at: e.created_at - 1 }, { kind: 1 },
    { tags: [...e.tags, ['alt', 'changed']] }, { id: '0'.repeat(64) }, { sig: '0'.repeat(128) },
    { pubkey: 'a'.repeat(64) }]) denied(() => verify({ ...e, ...change }));
  // Correct recomputed ID does not excuse an invalid signature.
  const forged = { ...e, content: e.content + ' ' }; forged.id = hashEvent(forged); denied(() => verify(forged));
});
test('signed context substitutions, ambiguous/duplicate security tags and wrong kind deny', () => {
  const tags = signed().tags;
  for (const changed of [[['h', channelId], ['p', targetPubkey]],
    [...tags, ['h', channelId]], [...tags, ['p', targetPubkey]], [...tags, ['e', threadId, '', 'reply']],
    tags.map(t => t[0] === 'e' ? ['e', threadId, '', 'reply'] : t),
    tags.map(t => t[0] === 'e' ? ['e', '0'.repeat(64), '', 'root'] : t),
    tags.map(t => t[0] === 'h' ? ['h', 'other'] : t),
    tags.map(t => t[0] === 'p' ? ['p', '0'.repeat(64)] : t)]) denied(() => verify(signed({ event: { tags: changed } })));
  denied(() => verify(signed({ event: { kind: 1 } })));
  denied(() => verify(sign(signed(), Buffer.from('0'.repeat(63) + '4', 'hex'))));
});
test('strict signed envelope/request denies extra identity, delegation and arbitrary execution fields', () => {
  for (const field of ['shell', 'path', 'env', 'mount', 'argv', 'requesterId', 'verified', 'authorizationEventId']) {
    denied(() => verify(signed({ r: { ...baseRequest, [field]: 'SECRET_CANARY' } })));
  }
  for (const change of [{ type: 'assignment' }, { version: 2 }, { verified: true },
    { descriptorDigest: '0'.repeat(64) }, { requesterId: 'owner' }]) denied(() => verify(signed({ envelope: change })));
  denied(() => verify(signed({ r: { ...baseRequest, operationId: 'validate.node' } })));
  denied(() => verify(signed(), { source: { ...source, workspaceId: 'other' } }));
  denied(() => verify(signed(), { source: { ...source, sourceDigest: '0'.repeat(64) } }));
});
test('fixed time bounds reject expired, old, future and excessive lifetime signed events', () => {
  for (const expiresAt of [now, now - 1, now + 600001, 1e100, null, '1800000000001']) {
    denied(() => verify(signed({ envelope: { expiresAt } })));
  }
  denied(() => verify(signed({ event: { created_at: now / 1000 + 61 } })));
  denied(() => verify(signed({ event: { created_at: now / 1000 - 601 } })));
  denied(() => verify(signed({ event: { created_at: 1e100 } })));
  denied(() => verify(signed(), { now: now + 600000 }));
});
test('duplicate raw keys including escaped nested keys are rejected before parse loses evidence', () => {
  const e = signed(), raw = JSON.stringify(e);
  for (const text of [raw.replace('{', '{"id":"' + e.id + '",'),
    raw.replace('{', '{"\\u0069d":"' + e.id + '",')]) denied(() => verifyOwnerEvent(text, config));
  for (const content of [e.content.replace('{', '{"version":1,'),
    e.content.replace('"request":{', '"request":{"\\u0074askId":"task-one",')]) {
    denied(() => verify(sign({ ...e, content })));
  }
});
test('raw objects, cached verdicts, malformed UTF-8/JSON, surrogates and excessive sizes deny', () => {
  const e = signed();
  for (const raw of [e, { ...e, verified: true }, Promise.resolve(e),
    Object.assign(Object.create(e), { verified: true }), Buffer.from([0xc3, 0x28]),
    '"\ud800"', JSON.stringify({ ...e, content: '\ud800' }), '{', 'null', '{}',
    '['.repeat(18) + '0' + ']'.repeat(18), ' '.repeat(16385), JSON.stringify({ ...e, verified: true })]) {
    denied(() => verifyOwnerEvent(raw, config));
  }
  for (const tags of [Array(33).fill(['alt']), [...e.tags, ['alt', 'x'.repeat(257)]], [...e.tags, ['alt', 1]],
    [...e.tags, []], [...e.tags, ['alt', 'a', 'b', 'c', 'd']]]) denied(() => verify(signed({ event: { tags } })));
  denied(() => verify(signed({ event: { content: ' '.repeat(8193) } })));
});
test('mandatory synchronous provider and resolver; no default/static verified result', t => {
  const f = fixture(t);
  for (const key of ['currentJob', 'resolveEvent', 'clock']) denied(() => createAuthorizationAdapter({ ...f.options, [key]: null }));
  for (const p of [() => null, () => Promise.resolve(f.facts()), () => ({ verified: true }),
    () => { throw new Error('SECRET_CANARY /host/private'); }]) {
    f.provider(p); denied(() => f.journal().next(f.r)); assert.deepEqual(fs.readdirSync(f.directory), []);
  }
});
test('strict current-policy DTO rejects each wrong scope, privilege, membership and stale fact before journal writes', t => {
  const f = fixture(t), good = f.facts();
  const changes = { taskId: 'other', jobId: 'other', repository: 'other/repo', baseRef: 'other', baseSha: '0'.repeat(40),
    operationId: 'validate.node', channelId: 'other', threadId: '0'.repeat(64), requesterId: 'other', role: 'developer',
    ownerPubkey: '0'.repeat(64), mentionPubkey: '0'.repeat(64), targetPubkey: '0'.repeat(64), workspaceId: 'other',
    sourceDigest: '0'.repeat(64), descriptorDigest: '0'.repeat(64), requestHash: '0'.repeat(64),
    enabled: false, status: 'completed', requesterMember: false, ownerAllowed: false,
    allowedOperations: ['status.revision', 'validate.node'], verifiedAt: now - 60001, expiresAt: now, token: 'SECRET_CANARY' };
  for (const [k, v] of Object.entries(changes)) {
    f.provider(() => ({ ...good, [k]: v })); denied(() => f.journal().next(f.r));
    assert.deepEqual(fs.readdirSync(f.directory), []);
  }
  f.provider(() => ({ ...good, verifiedAt: now + 1 })); denied(() => f.journal().next(f.r));
});
test('provider prototypes, symbols, getters and cyclic values cannot supply policy', t => {
  const f = fixture(t); let invoked = false;
  const accessor = { ...f.facts() }; Object.defineProperty(accessor, 'enabled', { enumerable: true, get() { invoked = true; return true; } });
  const cyclic = { ...f.facts() }; cyclic.extra = cyclic;
  for (const p of [accessor, Object.assign(Object.create(f.facts()), {}),
    { ...f.facts(), [Symbol('verified')]: true }, cyclic]) {
    f.provider(() => p); denied(() => f.journal().next(f.r)); assert.deepEqual(fs.readdirSync(f.directory), []);
  }
  assert.equal(invoked, false);
});
test('fresh verification on every call rejects changed event and mismatched request or descriptor', t => {
  const f = fixture(t), d = descriptor(f.r, source);
  assert.equal(f.adapter(f.r, d).kind, 'owner_event');
  f.event({ ...signed(), content: signed().content + ' ' }); denied(() => f.journal().next(f.r));
  f.event(signed()); denied(() => f.journal().next({ ...f.r, taskId: 'other' }));
  denied(() => f.adapter(f.r, { ...d, timeoutMs: 1 }));
  assert.deepEqual(fs.readdirSync(f.directory), []);
});
test('policy provider sees verified signer and detached exact request/descriptor; expiry is minimum', t => {
  const f = fixture(t);
  f.provider((r, who, d) => {
    assert.equal(who.signerPubkey, ownerPubkey); assert.deepEqual(r, f.r); assert.deepEqual(d, descriptor(f.r, source));
    r.taskId = 'mutated'; d.workspaceId = 'mutated';
    return { ...f.facts(), expiresAt: now + 1000 };
  });
  assert.equal(f.adapter(f.r, descriptor(f.r, source)).expiresAt, now + 1000);
});
for (const boundary of ['revoke', 'expire']) test(`authorization ${boundary} between prelock and locked recheck emits no intent`, t => {
  const f = fixture(t);
  f.provider(() => {
    const facts = f.facts();
    if (f.calls() === 1) {
      if (boundary === 'expire') f.time(now + 600000);
    } else facts.enabled = false;
    return facts;
  });
  denied(() => f.journal().next(f.r)); assert.deepEqual(fs.readdirSync(f.directory), []);
});
test('real signed authorization integrates existing journal complete replay without new effects', t => {
  const f = fixture(t);
  for (const step of ['execution', 'kaneo', 'buzz']) {
    const plan = f.journal().next(f.r); assert.equal(plan.intent.step, step);
    if (step === 'buzz') assert.equal(plan.intent.payload.mentionPubkey, ownerPubkey);
    f.journal().record(f.r, f.evidence(plan));
  }
  const before = disk(f); assert.equal(f.journal().next(f.r).status, 'complete');
  assert.equal(disk(f), before); assert.equal(Object.values(JSON.parse(before).entries)[0].effects.length, 3);
});
for (const boundary of ['execution', 'kaneo', 'buzz']) test(`signed authorization never clears pending ${boundary} or substitutes for a receipt`, t => {
  const f = fixture(t);
  for (const step of ['execution', 'kaneo', 'buzz']) {
    const plan = f.journal().next(f.r), proof = f.evidence(plan);
    if (step === boundary) {
      const before = disk(f); assert.equal(f.journal().next(f.r).status, 'outcome_unknown');
      assert.throws(() => f.journal().record(f.r, signed()), e => e.code === 'receipt_invalid');
      assert.equal(disk(f), before);
    }
    f.journal().record(f.r, proof);
  }
  assert.equal(f.journal().next(f.r).status, 'complete');
});
test('past receipt can reconcile after signed expiry but next report remains denied', t => {
  const f = fixture(t), plan = f.journal().next(f.r), proof = f.evidence(plan);
  f.time(now + 600001);
  assert.equal(f.journal().record(f.r, proof).status, 'recorded');
  const before = disk(f); denied(() => f.journal().next(f.r)); assert.equal(disk(f), before);
});
test('a pending deadline remains outcome_unknown while owner auth is still valid', t => {
  const f = fixture(t); f.journal().next(f.r); f.time(now + 5001);
  assert.equal(f.journal().next(f.r).code, 'deadline_elapsed');
});
test('exception canaries never enter normalized intent/journal/public report', t => {
  const f = fixture(t); f.journal().next(f.r); const before = disk(f);
  f.provider(() => { throw new Error('SECRET_CANARY'); }); denied(() => f.journal().next(f.r));
  assert.equal(disk(f), before); assert.equal(before.includes('SECRET_CANARY'), false);
  assert.equal(before.includes('"sig"'), false); assert.equal(before.includes('"content"'), false);
});
