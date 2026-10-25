import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { schnorr } from '../host-operator-auth/node_modules/@noble/curves/secp256k1.js';
import { createLocalEventIngress } from '../host-operator-auth/local-ingress.mjs';
import { createFileEventResolver } from '../host-operator-auth/event-source.mjs';
import { HostOperatorJournal } from './host-operator-journal.mjs';
import { descriptor, digest, ProtocolError } from './host-operator-protocol.mjs';

// Public BIP340 vector 0, not an operational key. Policy below is an explicit DTO
// fixture; the separate pinned integration suite uses the actual A2/writer.
const scalar = Buffer.from('0'.repeat(63) + '3', 'hex'), now = 1800000000000;
const ownerPubkey = 'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9';
const targetPubkey = 'e'.repeat(64), channelId = '00000000-0000-0000-0000-000000000001', threadId = 'd'.repeat(64);
const source = { repository: 'test-org/project', baseRef: 'main', baseSha: 'b'.repeat(40), workspaceId: 'fixture', sourceDigest: 'c'.repeat(64) };
const request = { version: 1, requestId: 'one', taskId: 'task-one', jobId: 'job-one', repository: source.repository, baseRef: source.baseRef,
  baseSha: source.baseSha, operationId: 'status.revision', channelId, threadId };
const canary = 'SECRET_INGRESS_CANARY';
function signed(r = request, envelope = {}, fields = {}) {
  const e = { pubkey: ownerPubkey, kind: 9, created_at: now / 1000, tags: [['h', channelId], ['e', threadId, '', 'root'], ['p', targetPubkey]],
    content: JSON.stringify({ type: 'host-operator.request', version: 1, request: r, descriptorDigest: digest(descriptor(request, source)), expiresAt: now + 600000, ...envelope }), ...fields };
  e.id = createHash('sha256').update(JSON.stringify([0, e.pubkey, e.created_at, e.kind, e.tags, e.content])).digest('hex');
  e.sig = Buffer.from(schnorr.sign(Buffer.from(e.id, 'hex'), scalar, new Uint8Array(32))).toString('hex'); return e;
}
function facts(r, who, d) {
  return { ...Object.fromEntries(['taskId', 'jobId', 'repository', 'baseRef', 'baseSha', 'operationId', 'channelId', 'threadId'].map(k => [k, r[k]])),
    requesterId: who.requesterId, role: 'owner', ownerPubkey, mentionPubkey: ownerPubkey, targetPubkey,
    workspaceId: d.workspaceId, sourceDigest: d.sourceDigest, descriptorDigest: digest(d), requestHash: digest(r), enabled: true,
    status: 'active', requesterMember: true, ownerAllowed: true, allowedOperations: ['status.revision'], verifiedAt: now, expiresAt: now + 600000 };
}
function fixture(t) {
  assert.notEqual(process.getuid(), 0);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'local-ingress-')); fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const eventDirectory = path.join(root, 'events'), journalDirectory = path.join(root, 'journal');
  for (const dir of [eventDirectory, journalDirectory]) fs.mkdirSync(dir, { mode: 0o700 });
  const options = { eventDirectory, journalDirectory, uid: process.getuid(), ownerPubkey, targetPubkey, channelId, threadId,
    requesterId: 'owner', mentionPubkey: ownerPubkey, source: { ...source }, currentJob: facts, verifyReceipt: () => { throw Error(canary + root); }, clock: () => now, monotonic: () => 0 };
  const event = signed(), raw = JSON.stringify(event), file = path.join(eventDirectory, event.id + '.json'), state = path.join(journalDirectory, 'state.json');
  const ingress = createLocalEventIngress(options);
  return { root, options, event, raw, file, state, ingress, disk: () => fs.existsSync(state) ? fs.readFileSync(state, 'utf8') : '',
    read: createFileEventResolver({ directory: eventDirectory, uid: process.getuid(), clock: () => now, monotonic: () => 0 }) };
}
function patch(object, name, wrapper, work) { const original = object[name]; object[name] = wrapper(original); try { return work(); } finally { object[name] = original; } }
function safe(f, value) { const text = JSON.stringify(value); for (const x of [f.root, f.raw, f.event.sig, canary, 'tokenSha256']) assert(!text.includes(x)); assert(Buffer.byteLength(text) < 8192); }
function noNext(work) { return patch(HostOperatorJournal.prototype, 'next', () => () => assert.fail('journal.next must not run'), work); }

const child = `import fs from 'node:fs';
import {createLocalEventIngress} from ${JSON.stringify(new URL('../host-operator-auth/local-ingress.mjs', import.meta.url).href)};
import {HostOperatorJournal} from ${JSON.stringify(new URL('./host-operator-journal.mjs', import.meta.url).href)};
import {digest} from ${JSON.stringify(new URL('./host-operator-protocol.mjs', import.meta.url).href)};
const {options,raw,point}=JSON.parse(fs.readFileSync(0,'utf8'));
const facts=${facts.toString()};
const now=${now},ownerPubkey=${JSON.stringify(ownerPubkey)},targetPubkey=${JSON.stringify(targetPubkey)};
const next=HostOperatorJournal.prototype.next;
HostOperatorJournal.prototype.next=function(...args){if(point==='before-journal')process.kill(process.pid,'SIGKILL');const result=next.apply(this,args);if(point==='after-persist')process.kill(process.pid,'SIGKILL');return result;};
const rename=fs.renameSync;fs.renameSync=(...args)=>{const r=rename(...args);if(point==='after-state-rename'&&String(args[1]).endsWith('/state.json'))process.kill(process.pid,'SIGKILL');return r;};
const ingress=createLocalEventIngress({...options,currentJob:facts,verifyReceipt:()=>{throw Error('fixture');},clock:()=>now,monotonic:()=>0});process.stdout.write(JSON.stringify(ingress.ingest(raw)));`;
function launch(f, point) {
  const { currentJob, verifyReceipt, clock, monotonic, ...options } = f.options;
  const p = spawn(process.execPath, ['--input-type=module', '-e', child], { stdio: ['pipe', 'pipe', 'pipe'] });
  let out = '', err = ''; p.stdout.on('data', b => { out += b; }); p.stderr.on('data', b => { err += b; }); p.stdin.end(JSON.stringify({ options, raw: f.raw, point }));
  return new Promise((resolve, reject) => { p.on('error', reject); p.on('exit', (code, signal) => resolve({ code, signal, out, err })); });
}

test('fresh raw snapshot -> real A1/A9/A8/adapter/journal emits one durable DATA intent only after confirmation', t => {
  const f = fixture(t); let calls = 0, links = 0, policy = 0, receipts = 0;
  const options = { ...f.options, currentJob: (...a) => { policy++; return facts(...a); }, verifyReceipt: () => { receipts++; throw Error(canary); } };
  const ingress = createLocalEventIngress(options); assert(Object.isFrozen(ingress)); assert.deepEqual(Object.keys(ingress), ['ingest']);
  const raw = Buffer.from(f.raw);
  const result = patch(HostOperatorJournal.prototype, 'next', orig => function(r) {
    calls++; assert.equal(fs.statSync(f.file).nlink, 1); assert.equal(f.read(r.authorizationEventId).toString(), f.raw); return orig.call(this, r);
  }, () => patch(fs, 'linkSync', orig => (...a) => { links++; raw.fill(88); return orig(...a); }, () => ingress.ingest(raw)));
  assert.equal(result.status, 'intent'); assert.equal(result.intent.step, 'execution'); assert.equal(result.intentDigest, digest(result.intent));
  assert.equal(calls, 1); assert.equal(links, 1); assert.equal(policy, 2); assert.equal(receipts, 0); safe(f, result);
  const state = JSON.parse(f.disk()); assert.equal(Object.values(state.entries).length, 1); assert.equal(Object.values(state.entries)[0].effects.length, 1);
  assert.equal(Object.values(state.entries)[0].effects[0].receipt, null); assert.equal(fs.readFileSync(f.file, 'utf8'), f.raw);
  const before = f.disk(); noNext(() => assert.equal(ingress.ingest(f.raw).status, 'placement_unconfirmed')); assert.equal(f.disk(), before);
});
test('unsafe raw brands/accessors/shared/extended Buffers and extra caller arguments never place or call journal', t => {
  const f = fixture(t); let invoked = 0;
  const getter = Buffer.from(f.raw); Object.defineProperty(getter, 'extra', { get() { invoked++; throw Error(canary); } });
  const extended = Buffer.from(f.raw); extended.extra = true;
  const symbol = Buffer.from(f.raw); symbol[Symbol('x')] = 1;
  const proxy = new Proxy(Buffer.from(f.raw), { get() { invoked++; throw Error(canary); }, getPrototypeOf() { invoked++; throw Error(canary); } });
  const parsed = { get verified() { invoked++; throw Error(canary); } };
  noNext(() => {
    for (const raw of [proxy, parsed, extended, getter, symbol, Buffer.from(new SharedArrayBuffer(5)), new Uint8Array(5), new String(f.raw), Symbol('raw'), null, [], () => f.raw, '', '\ud800', 'x'.repeat(16385), Buffer.alloc(16385)]) {
      const result = f.ingress.ingest(raw); assert.deepEqual(result, { status: 'ingress_denied', code: 'ingress_denied' }); safe(f, result);
    }
    assert.equal(f.ingress.ingest(f.raw, { verified: true, path: canary, env: {}, argv: [] }).status, 'ingress_denied');
  });
  assert.equal(invoked, 0); assert.deepEqual(fs.readdirSync(f.options.eventDirectory), []); assert.equal(f.disk(), '');
});
test('raw boundary/A1 deny BOM, malformed/duplicate/deep input and signed crypto/context/source/operation/expiry substitutions before placement', t => {
  const f = fixture(t);
  const raws = ['\ufeff' + f.raw, Buffer.from([0xc3, 0x28]), '{', f.raw.replace('"kind":9', '"kind":9,"k\\u0069nd":9'), '['.repeat(18) + '0' + ']'.repeat(18),
    JSON.stringify({ ...f.event, sig: '0'.repeat(128) }), JSON.stringify({ ...f.event, id: '0'.repeat(64) }), JSON.stringify({ ...f.event, pubkey: 'a'.repeat(64) }),
    JSON.stringify(signed(request, {}, { tags: [] })), JSON.stringify(signed({ ...request, operationId: 'validate.node' })), JSON.stringify(signed({ ...request, channelId: '00000000-0000-0000-0000-000000000002' })),
    JSON.stringify(signed({ ...request, repository: 'other/repo' })), JSON.stringify(signed(request, { expiresAt: now })), JSON.stringify(signed(request, { descriptorDigest: 'a'.repeat(64) })), JSON.stringify(signed(request, { delegation: true }))];
  noNext(() => { for (const raw of raws) { const result = f.ingress.ingest(raw); assert.equal(result.status, 'ingress_denied'); safe(f, result); } });
  assert.deepEqual(fs.readdirSync(f.options.eventDirectory), []); assert.equal(f.disk(), '');
});
test('constructor snapshots ordinary context/source and rejects missing seams, override fields, proxies/getters and overlapping/unsafe namespaces', t => {
  const f = fixture(t); let invoked = 0;
  const accessor = { ...f.options }; Object.defineProperty(accessor, 'source', { get() { invoked++; throw Error(canary); } });
  const nested = path.join(f.options.eventDirectory, 'nested'); fs.mkdirSync(nested, { mode: 0o700 });
  for (const options of [accessor, new Proxy({}, { getPrototypeOf() { invoked++; throw Error(canary); } }), { ...f.options, currentJob: null }, { ...f.options, verifyReceipt: undefined }, { ...f.options, clock: null }, { ...f.options, monotonic: 1 },
    { ...f.options, uid: 0 }, { ...f.options, uid: process.getuid() + 1 }, { ...f.options, journalDirectory: f.options.eventDirectory }, { ...f.options, journalDirectory: nested }, { ...f.options, eventDirectory: nested, journalDirectory: f.options.eventDirectory },
    { ...f.options, eventDirectory: f.root + '/absent' }, { ...f.options, placer: {} }, { ...f.options, journal: {} }, { ...f.options, [Symbol('key')]: true }]) {
    assert.throws(() => createLocalEventIngress(options), e => e.code === 'ingress_denied' && e.message === 'ingress_denied' && e.stack === 'ingress_denied');
  }
  assert.equal(invoked, 0);
  const saved = { ...f.options, source: { ...source } }, ingress = createLocalEventIngress(saved);
  saved.source.baseSha = 'a'.repeat(40); saved.ownerPubkey = 'a'.repeat(64); saved.currentJob = () => { throw Error(canary); }; saved.journalDirectory = canary;
  assert.equal(ingress.ingest(f.raw).status, 'intent');
  for (const dir of [f.options.eventDirectory, f.options.journalDirectory]) {
    fs.chmodSync(dir, 0o750); assert.throws(() => createLocalEventIngress(f.options), e => e.code === 'ingress_denied'); fs.chmodSync(dir, 0o700);
  }
  fs.renameSync(f.options.eventDirectory, f.options.eventDirectory + '.saved'); fs.symlinkSync(f.options.eventDirectory + '.saved', f.options.eventDirectory);
  assert.throws(() => createLocalEventIngress(f.options), e => e.code === 'ingress_denied');
});
test('preexisting identical or differing wire bytes stop before policy/journal without adoption or replacement', t => {
  for (const equal of [true, false]) {
    const f = fixture(t); fs.writeFileSync(f.file, equal ? f.raw : ' ' + f.raw, { mode: 0o600 }); const before = fs.statSync(f.file);
    noNext(() => assert.equal(f.ingress.ingest(f.raw).status, equal ? 'placement_unconfirmed' : 'placement_conflict'));
    assert.equal(fs.statSync(f.file).ino, before.ino); assert.equal(f.disk(), '');
  }
});
test('actual placement write/sync/link/unlink/readback ambiguity stops before journal, preserving candidates/artifacts', t => {
  for (const point of ['write', 'file-sync', 'link', 'unlink', 'parent-sync', 'readback']) {
    const f = fixture(t); let synced = false;
    const name = point === 'write' ? 'writeSync' : point === 'link' ? 'linkSync' : point === 'unlink' ? 'unlinkSync' : point === 'readback' ? 'readSync' : 'fsyncSync';
    const sync = fs.fsyncSync;
    if (point === 'readback') fs.fsyncSync = fd => { const r = sync(fd); if (fs.fstatSync(fd).isDirectory()) synced = true; return r; };
    let result;
    try { result = noNext(() => patch(fs, name, orig => (...a) => {
      if (point === 'file-sync' && fs.fstatSync(a[0]).isDirectory()) return orig(...a);
      if (point === 'parent-sync' && !fs.fstatSync(a[0]).isDirectory()) return orig(...a);
      if (point === 'readback' && !synced) return orig(...a);
      if (point === 'link') orig(...a);
      throw Error(canary + f.root);
    }, () => f.ingress.ingest(f.raw))); } finally { fs.fsyncSync = sync; }
    assert.equal(result.status, ['write', 'file-sync'].includes(point) ? 'placement_denied' : 'placement_unconfirmed'); safe(f, result); assert.equal(f.disk(), '');
    const entries = fs.readdirSync(f.options.eventDirectory);
    if (['parent-sync', 'readback'].includes(point)) { assert.equal(f.read(f.event.id).toString(), f.raw); noNext(() => assert.equal(f.ingress.ingest(f.raw).status, 'placement_unconfirmed')); }
    assert.deepEqual(fs.readdirSync(f.options.eventDirectory), entries);
  }
});
test('confirmed placement with missing/stale/error/Promise/wrong policy denies admission and retains event', t => {
  for (const currentJob of [() => { throw Error(canary); }, () => Promise.resolve({}), () => ({}), (...a) => ({ ...facts(...a), enabled: false }), (...a) => ({ ...facts(...a), expiresAt: now }), (...a) => ({ ...facts(...a), jobId: 'other' })]) {
    const f = fixture(t), ingress = createLocalEventIngress({ ...f.options, currentJob });
    assert.equal(ingress.ingest(f.raw).status, 'admission_denied'); assert.equal(fs.readFileSync(f.file, 'utf8'), f.raw); assert.equal(f.disk(), '');
  }
});
test('fresh policy and event rechecks outside/inside journal lock deny before new persistence', t => {
  for (const at of [1, 2]) for (const kind of ['policy', 'event']) {
    const f = fixture(t); let calls = 0, started = false, changed = false;
    const ingress = createLocalEventIngress({ ...f.options, currentJob: (...args) => {
      if (++calls === at && kind === 'policy') return { ...facts(...args), status: 'completed' };
      return facts(...args);
    } });
    const result = patch(HostOperatorJournal.prototype, 'next', orig => function(...a) { started = true; return orig.apply(this, a); }, () => patch(fs, 'openSync', orig => (...a) => {
      const locked = fs.existsSync(path.join(f.options.journalDirectory, 'journal.lock'));
      if (kind === 'event' && started && !changed && a[0] === f.file && locked === (at === 2)) { fs.writeFileSync(f.file, canary); changed = true; }
      return orig(...a);
    }, () => ingress.ingest(f.raw)));
    assert.equal(result.status, 'admission_denied'); assert.equal(f.disk(), ''); assert(fs.existsSync(f.file));
    if (kind === 'event') assert(changed);
  }
});
test('journal storage uncertainty is not placement success; pending disk state and repeat stop remain explicit', t => {
  for (const point of ['journal-sync', 'state-rename', 'response']) {
    const f = fixture(t); let result;
    if (point === 'journal-sync') result = patch(fs, 'fsyncSync', orig => fd => { if (fs.fstatSync(fd).isDirectory() && fs.existsSync(path.join(f.options.journalDirectory, 'journal.lock'))) throw Error(canary); return orig(fd); }, () => f.ingress.ingest(f.raw));
    if (point === 'state-rename') result = patch(fs, 'renameSync', orig => (...a) => { const r = orig(...a); if (a[1] === f.state) throw Error(canary); return r; }, () => f.ingress.ingest(f.raw));
    if (point === 'response') result = patch(HostOperatorJournal.prototype, 'next', orig => function(...a) { orig.apply(this, a); throw Error(canary); }, () => f.ingress.ingest(f.raw));
    assert.deepEqual(result, { status: 'outcome_unknown', code: 'journal_unconfirmed' }); safe(f, result); assert(fs.existsSync(f.file));
    const before = f.disk(); if (point !== 'journal-sync') assert.equal(Object.values(JSON.parse(before).entries)[0].effects.length, 1);
    noNext(() => assert.equal(f.ingress.ingest(f.raw).status, 'placement_unconfirmed')); assert.equal(f.disk(), before);
  }
});
test('sanitizer rejects unexpected public shapes, poisoned properties/promises and error getters without leaks', t => {
  const getter = {}; Object.defineProperty(getter, 'status', { get() { throw Error(canary); }, enumerable: true });
  const error = new ProtocolError('journal_io'); Object.defineProperty(error, 'code', { get() { throw Error(canary); } });
  for (const value of [{ status: 'intent', raw: canary }, { status: 'confirmed' }, Promise.resolve({}), getter, new Proxy({}, { getPrototypeOf() { throw Error(canary); } }), { status: 'complete', result: { raw: canary } }]) {
    const f = fixture(t);
    const result = patch(HostOperatorJournal.prototype, 'next', () => () => value, () => f.ingress.ingest(f.raw));
    assert.deepEqual(result, { status: 'outcome_unknown', code: 'journal_unconfirmed' }); safe(f, result);
  }
  const f = fixture(t); const result = patch(HostOperatorJournal.prototype, 'next', () => () => { throw error; }, () => f.ingress.ingest(f.raw));
  assert.deepEqual(result, { status: 'outcome_unknown', code: 'journal_unconfirmed' });
});
test('SIGKILL between placement/admission and after journal persistence leaves split evidence; retransmission never repairs', async t => {
  for (const point of ['before-journal', 'after-state-rename', 'after-persist']) {
    const f = fixture(t), result = await launch(f, point); assert.equal(result.signal, 'SIGKILL', result.err); assert.equal(result.out, '');
    assert.equal(f.read(f.event.id).toString(), f.raw);
    if (point === 'before-journal') assert.equal(f.disk(), ''); else assert.equal(Object.values(JSON.parse(f.disk()).entries)[0].effects.length, 1);
    const before = f.disk(), names = fs.readdirSync(f.options.journalDirectory);
    noNext(() => assert.equal(f.ingress.ingest(f.raw).status, 'placement_unconfirmed')); assert.equal(f.disk(), before); assert.deepEqual(fs.readdirSync(f.options.journalDirectory), names);
  }
});
test('concurrent same-event ingress calls create at most one automated admission, with no operation execution', async t => {
  const f = fixture(t), runs = await Promise.all(Array.from({ length: 4 }, () => launch(f)));
  for (const r of runs) assert.equal(r.code, 0, r.err);
  const results = runs.map(r => JSON.parse(r.out)); assert.equal(results.filter(r => r.status === 'intent').length, 1);
  for (const r of results) assert(['intent', 'placement_unconfirmed', 'placement_denied'].includes(r.status));
  assert.equal(Object.values(JSON.parse(f.disk()).entries)[0].effects.length, 1); assert.equal(fs.readFileSync(f.file, 'utf8'), f.raw);
});

test('clock rollback/invalid/expired verification stops before journal and does not refresh signed time', t => {
  for (const value of [now - 1, now + 600000, NaN, -1]) {
    const f = fixture(t); let ticks = 0;
    const ingress = createLocalEventIngress({ ...f.options, clock: () => ++ticks === 1 ? now : value });
    noNext(() => assert.equal(ingress.ingest(f.raw).status, 'placement_denied')); assert.equal(f.disk(), ''); assert(!fs.existsSync(f.file));
  }
  const f = fixture(t), expired = createLocalEventIngress({ ...f.options, clock: () => now + 600000 });
  noNext(() => assert.equal(expired.ingest(f.raw).status, 'ingress_denied')); assert.equal(f.disk(), '');
});
test('actual existing pending/report/complete results retain public shapes; ingress never exposes a receipt endpoint', async t => {
  const { createAuthorizationAdapter } = await import('../host-operator-auth/authorization.mjs');
  const f = fixture(t), r = { ...request, authorizationEventId: f.event.id }, receipts = new Map();
  const journal = new HostOperatorJournal({ directory: f.options.journalDirectory, source, ownerPubkey, clock: () => now,
    authorize: createAuthorizationAdapter({ ...f.options, resolveEvent: f.read, currentJob: facts }), verifyReceipt: e => receipts.get(e.ref) });
  let result = f.ingress.ingest(f.raw); assert.equal(result.intent.step, 'execution');
  // Explicit synthetic file deletion exercises the existing journal API states;
  // ingress itself never deletes/adopts a file or performs reconciliation.
  fs.unlinkSync(f.file); const pending = f.ingress.ingest(f.raw);
  assert.equal(pending.status, 'outcome_unknown'); assert.equal(pending.code, 'pending_effect'); safe(f, pending);
  for (const step of ['execution', 'kaneo', 'buzz']) {
    assert.equal(result.intent.step, step); safe(f, result);
    const ref = 'fixture-' + step;
    receipts.set(ref, { version: 1, receiptId: ref, intentId: result.intent.intentId, intentDigest: result.intentDigest, requestHash: digest(r), step,
      outcome: 'success', finishedAt: now, evidenceRef: ref, evidenceDigest: 'f'.repeat(64), summary: { passed: 1, failed: 0, skipped: 0, exitCode: 0, signal: null } });
    journal.record(r, { ref }); fs.unlinkSync(f.file); result = f.ingress.ingest(f.raw);
  }
  assert.equal(result.status, 'complete'); safe(f, result); assert.equal(result.result.execution.outcome, 'success');
  const entries = Object.values(JSON.parse(f.disk()).entries); assert.equal(entries[0].effects.length, 3);
  assert.deepEqual(Object.keys(f.ingress), ['ingest']);
});
test('actual workspace reservation maps to bounded blocked without deleting separately placed candidate', t => {
  const f = fixture(t); assert.equal(f.ingress.ingest(f.raw).status, 'intent'); const before = f.disk();
  const other = signed({ ...request, requestId: 'other' }), raw = JSON.stringify(other);
  assert.deepEqual(f.ingress.ingest(raw), { status: 'blocked', code: 'workspace_busy' }); assert.equal(f.disk(), before);
  assert.equal(f.read(other.id).toString(), raw);
});
