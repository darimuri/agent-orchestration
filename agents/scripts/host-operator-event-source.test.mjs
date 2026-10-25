import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { schnorr } from '../host-operator-auth/node_modules/@noble/curves/secp256k1.js';
import { createFileEventResolver } from '../host-operator-auth/event-source.mjs';
import { verifyOwnerEvent } from '../host-operator-auth/owner-event.mjs';
import { createAuthorizationAdapter } from '../host-operator-auth/authorization.mjs';
import { descriptor, digest } from './host-operator-protocol.mjs';

const id = 'a'.repeat(64), canary = 'SECRET_CANARY', now = 1800000000000;
function fixture(t, bytes = Buffer.from(canary)) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'raw-event-source-')); fs.chmodSync(root, 0o700);
  const directory = path.join(root, 'events'); fs.mkdirSync(directory, { mode: 0o700 });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const file = path.join(directory, id + '.json'); fs.writeFileSync(file, bytes, { mode: 0o600 });
  const options = { directory, uid: process.getuid(), clock: () => now, monotonic: () => 0 };
  return { root, directory, file, options, resolve: createFileEventResolver(options) };
}
function denied(fn, f) {
  assert.throws(fn, e => {
    assert.equal(e.code, 'event_source_denied'); assert.equal(e.message, 'event_source_denied'); assert.equal(e.stack, 'event_source_denied');
    for (const value of [canary, id, f?.root].filter(Boolean)) assert(!JSON.stringify(e).includes(value));
    return true;
  });
}
function patch(name, replacement, work) {
  const original = fs[name]; fs[name] = replacement(original);
  try { return work(); } finally { fs[name] = original; }
}

test('source returns detached exact ordinary bytes, including non-JSON; every call reopens without listing or writing', t => {
  const f = fixture(t, Buffer.from([0xc3, 0x28, 0, 255])); const read = fs.readSync; let reads = 0;
  fs.readSync = (...args) => { reads++; return read(...args); };
  try {
    const bytes = f.resolve(id); assert.equal(Object.getPrototypeOf(bytes), Buffer.prototype); assert.deepEqual([...bytes], [0xc3, 0x28, 0, 255]);
    bytes[0] = 0; assert.equal(f.resolve(id)[0], 0xc3); assert.equal(reads, 2);
  } finally { fs.readSync = read; }
  const entries = fs.readdirSync(f.directory);
  patch('readdirSync', () => () => { throw Error(canary); }, () => assert.equal(f.resolve(id).length, 4));
  assert.deepEqual(fs.readdirSync(f.directory), entries);
  fs.writeFileSync(f.file + '.new', 'replacement', { mode: 0o600 }); fs.renameSync(f.file + '.new', f.file);
  assert.equal(f.resolve(id).toString(), 'replacement'); fs.unlinkSync(f.file); denied(() => f.resolve(id), f);
  fs.writeFileSync(f.file, 'fresh', { mode: 0o600 }); assert.equal(f.resolve(id).toString(), 'fresh');
});
test('event ID boundary rejects traversal, case, objects and getters before file access', t => {
  const f = fixture(t); let invoked = 0;
  const object = { get id() { invoked++; throw Error(canary); }, toString() { invoked++; throw Error(canary); } };
  for (const value of ['../' + id, '/' + id, id + '.json', 'A'.repeat(64), id + '\n', '', '0'.repeat(63), 'a'.repeat(100000), object, () => id, new URL('https://example.invalid'), null, Symbol('id')]) {
    patch('lstatSync', () => () => { invoked++; throw Error(canary); }, () => denied(() => f.resolve(value), f));
  }
  assert.equal(invoked, 0);
});
test('trusted constructor enforces exact own data, canonical bounded directory and current ordinary UID', t => {
  const f = fixture(t); let invoked = 0;
  for (const change of [{ directory: '/' }, { directory: 'relative' }, { directory: f.directory + '/' }, { directory: f.directory + '/../events' },
    { directory: '/' + 'x'.repeat(4096) }, { directory: f.directory + '\0' }, { uid: 0 }, { uid: process.getuid() + 1 }, { uid: '10001' }, { clock: null }, { monotonic: false }, { path: canary }]) {
    denied(() => createFileEventResolver({ ...f.options, ...change }), f);
  }
  const options = { ...f.options }; Object.defineProperty(options, 'clock', { get() { invoked++; throw Error(canary); } });
  denied(() => createFileEventResolver(options), f); assert.equal(invoked, 0);
  denied(() => createFileEventResolver({ ...f.options, [Symbol('extra')]: true }), f);
  denied(() => createFileEventResolver(Object.create(f.options)), f);
});
test('directory and ancestry permissions, symlinks and missing namespace deny without repair', t => {
  for (const kind of ['directory-mode', 'ancestor-mode', 'directory-symlink', 'ancestor-symlink', 'missing']) {
    const f = fixture(t);
    if (kind === 'directory-mode') fs.chmodSync(f.directory, 0o750);
    if (kind === 'ancestor-mode') fs.chmodSync(f.root, 0o770);
    if (kind === 'directory-symlink') { fs.renameSync(f.directory, f.directory + '.saved'); fs.symlinkSync(f.directory + '.saved', f.directory); }
    if (kind === 'ancestor-symlink') { fs.symlinkSync(f.root, f.root + '.alias'); t.after(() => fs.unlinkSync(f.root + '.alias')); }
    if (kind === 'missing') fs.renameSync(f.directory, f.directory + '.saved');
    const read = kind === 'ancestor-symlink' ? createFileEventResolver({ ...f.options, directory: path.join(f.root + '.alias', 'events') }) : f.resolve;
    denied(() => read(id), f); fs.chmodSync(f.root, 0o700);
  }
});
test('file bounds and regular/private/single-link metadata deny empty, oversized, directory, FIFO and links', t => {
  for (const kind of ['empty', 'oversize', 'mode', 'special-mode', 'hardlink', 'symlink', 'directory', 'fifo']) {
    const f = fixture(t);
    if (kind === 'empty') fs.writeFileSync(f.file, '');
    if (kind === 'oversize') fs.writeFileSync(f.file, Buffer.alloc(16385));
    if (kind === 'mode') fs.chmodSync(f.file, 0o640);
    if (kind === 'special-mode') fs.chmodSync(f.file, 0o4600);
    if (kind === 'hardlink') fs.linkSync(f.file, f.file + '.alias');
    if (['symlink', 'directory', 'fifo'].includes(kind)) {
      fs.renameSync(f.file, f.file + '.saved');
      if (kind === 'symlink') fs.symlinkSync(f.file + '.saved', f.file);
      if (kind === 'directory') fs.mkdirSync(f.file, { mode: 0o700 });
      if (kind === 'fifo') assert.equal(spawnSync('mkfifo', ['-m', '600', f.file]).status, 0);
    }
    denied(() => f.resolve(id), f);
  }
  const f = fixture(t, Buffer.alloc(16384, 120)); assert.equal(f.resolve(id).length, 16384);
  fs.writeFileSync(f.file, 'x'); assert.equal(f.resolve(id).length, 1);
});
test('wrong-owner/device metadata and each underlying read/open/stat/close error yields only fixed denial', t => {
  const f = fixture(t);
  for (const name of ['realpathSync', 'lstatSync', 'openSync', 'fstatSync', 'readSync', 'closeSync']) {
    // A thrown close after actually closing the descriptor avoids leaks in the fault fixture.
    patch(name, original => (...args) => { if (name === 'closeSync') original(...args); throw Error(canary + f.root); }, () => denied(() => f.resolve(id), f));
  }
  for (const key of ['uid', 'dev']) patch('lstatSync', original => (...args) => {
    const s = original(...args); if (args[0] === f.file) s[key] += 1n; return s;
  }, () => denied(() => f.resolve(id), f));
  patch('lstatSync', original => (...args) => { const s = original(...args); if (args[0] === f.file) s.isFile = () => false; return s; }, () => denied(() => f.resolve(id), f));
});
for (const stage of ['before-open', 'short-read', 'grow', 'same-size-write', 'replace-file', 'replace-directory']) test(`observed ${stage} race never returns candidate bytes`, t => {
  const f = fixture(t); let changed = false;
  if (stage === 'before-open') {
    patch('openSync', original => (...args) => { if (args[0] === f.file && !changed) { changed = true; fs.renameSync(f.file, f.file + '.old'); fs.writeFileSync(f.file, canary, { mode: 0o600 }); } return original(...args); }, () => denied(() => f.resolve(id), f));
    return;
  }
  patch('readSync', original => (...args) => {
    const count = original(...args); changed = true;
    if (stage === 'short-read') return count - 1;
    if (stage === 'grow') fs.appendFileSync(f.file, 'x');
    if (stage === 'same-size-write') { fs.writeFileSync(f.file, 'x'.repeat(canary.length)); fs.utimesSync(f.file, 0, 0); }
    if (stage === 'replace-file') { fs.renameSync(f.file, f.file + '.old'); fs.writeFileSync(f.file, canary, { mode: 0o600 }); }
    if (stage === 'replace-directory') { fs.renameSync(f.directory, f.directory + '.old'); fs.mkdirSync(f.directory, { mode: 0o700 }); fs.writeFileSync(f.file, canary, { mode: 0o600 }); }
    return count;
  }, () => denied(() => f.resolve(id), f));
  assert(changed);
});
test('wall/monotonic clocks enforce observed 100ms, validity and no reversal; no stale budget cache', t => {
  const f = fixture(t);
  for (const key of ['clock', 'monotonic']) for (const values of [[0, 101], [2, 1], [0, NaN], [0, Infinity], [0, -1]]) {
    let i = 0; const read = createFileEventResolver({ ...f.options, [key]: () => values[Math.min(i++, 1)] }); denied(() => read(id), f);
  }
  let elapsed = 0;
  const read = createFileEventResolver({ ...f.options, monotonic: () => elapsed });
  patch('readSync', original => (...args) => { const count = original(...args); elapsed = 100; return count; }, () => assert.equal(read(id).toString(), canary));
  elapsed = 10000; assert.equal(read(id).toString(), canary); // Fresh budget for this call.
  for (const key of ['clock', 'monotonic']) patch('readSync', original => (...args) => {
    const count = original(...args); elapsed = 101; return count;
  }, () => { elapsed = 0; const r = createFileEventResolver({ ...f.options, [key]: () => elapsed }); denied(() => r(id), f); });
});

// PUBLIC BIP340 vector-0 identity, never an operational signing key.
const scalar = Buffer.from('0'.repeat(63) + '3', 'hex');
const ownerPubkey = 'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9';
const source = { repository: 'test-org/project', baseRef: 'main', baseSha: 'b'.repeat(40), workspaceId: 'fixture', sourceDigest: 'c'.repeat(64) };
const request = { version: 1, requestId: 'request-one', taskId: 'task-one', jobId: 'job-one', repository: source.repository, baseRef: 'main', baseSha: source.baseSha,
  operationId: 'status.revision', channelId: '00000000-0000-0000-0000-000000000001', threadId: 'd'.repeat(64) };
const config = { ownerPubkey, targetPubkey: 'e'.repeat(64), channelId: request.channelId, threadId: request.threadId, source, now };
function signed(r = request, envelope = {}, secret = scalar) {
  const event = { pubkey: Buffer.from(schnorr.getPublicKey(secret)).toString('hex'), kind: 9, created_at: now / 1000,
    tags: [['h', request.channelId], ['p', config.targetPubkey], ['e', request.threadId, '', 'root']],
    content: JSON.stringify({ type: 'host-operator.request', version: 1, request: r, descriptorDigest: digest(descriptor(request, source)), expiresAt: now + 600000, ...envelope }) };
  event.id = createHash('sha256').update(JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content])).digest('hex');
  event.sig = Buffer.from(schnorr.sign(Buffer.from(event.id, 'hex'), secret, new Uint8Array(32))).toString('hex'); return event;
}
test('file source does not parse/authenticate: real A1 rejects malformed, forged, expired and wrong-context bytes', t => {
  const f = fixture(t), good = signed(), raw = JSON.stringify(good);
  fs.writeFileSync(f.file, raw); assert.equal(verifyOwnerEvent(f.resolve(id), config).request.authorizationEventId, good.id);
  const wrongOwner = signed(request, {}, Buffer.from('0'.repeat(63) + '4', 'hex'));
  for (const bytes of [Buffer.from([0xc3, 0x28]), '{"id":1,"id":2}', '['.repeat(18) + '0' + ']'.repeat(18), JSON.stringify({ ...good, sig: '0'.repeat(128) }),
    JSON.stringify({ ...good, id: id }), JSON.stringify(wrongOwner), JSON.stringify(signed(request, { expiresAt: now })),
    JSON.stringify(signed({ ...request, channelId: '00000000-0000-0000-0000-000000000002' })), JSON.stringify(signed(request, { descriptorDigest: '0'.repeat(64) })), JSON.stringify(signed({ ...request, operationId: 'validate.node' }))]) {
    fs.writeFileSync(f.file, bytes); assert.deepEqual(f.resolve(id), Buffer.from(bytes));
    assert.throws(() => verifyOwnerEvent(f.resolve(id), config), e => e.code === 'authorization_denied');
  }
  fs.writeFileSync(f.file, raw); assert.throws(() => verifyOwnerEvent(f.resolve(id), { ...config, now: now + 600000 }), e => e.code === 'authorization_denied');
});
test('a valid different event stored under requested filename cannot satisfy A1 exact request/event binding', t => {
  const f = fixture(t), good = signed(), other = signed({ ...request, requestId: 'other' });
  const file = path.join(f.directory, good.id + '.json'); fs.writeFileSync(file, JSON.stringify(other), { mode: 0o600 });
  let policyCalls = 0;
  const adapter = createAuthorizationAdapter({ ...config, requesterId: 'owner', mentionPubkey: ownerPubkey, clock: () => now, resolveEvent: f.resolve,
    currentJob: () => { policyCalls++; throw Error(canary); } });
  assert.throws(() => adapter({ ...request, authorizationEventId: good.id }, descriptor(request, source)), e => e.code === 'authorization_denied');
  assert.equal(policyCalls, 0); // Rejected by real event proof before any policy lookup.
});
