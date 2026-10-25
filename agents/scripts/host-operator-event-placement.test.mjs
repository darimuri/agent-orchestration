import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { schnorr } from '../host-operator-auth/node_modules/@noble/curves/secp256k1.js';
import { createFileEventPlacer } from '../host-operator-auth/event-placement.mjs';
import { createFileEventResolver } from '../host-operator-auth/event-source.mjs';
import { verifyOwnerEvent } from '../host-operator-auth/owner-event.mjs';
import { descriptor, digest } from './host-operator-protocol.mjs';

// Public BIP340 vector 0, never an operational signing key.
const scalar = Buffer.from('0'.repeat(63) + '3', 'hex'), now = 1800000000000;
const ownerPubkey = 'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9';
const targetPubkey = 'e'.repeat(64), channelId = '00000000-0000-0000-0000-000000000001', threadId = 'd'.repeat(64);
const source = { repository: 'test-org/project', baseRef: 'main', baseSha: 'b'.repeat(40), workspaceId: 'fixture', sourceDigest: 'c'.repeat(64) };
const request = { version: 1, requestId: 'one', taskId: 'task-one', jobId: 'job-one', repository: source.repository, baseRef: source.baseRef,
  baseSha: source.baseSha, operationId: 'status.revision', channelId, threadId };
const canary = 'SECRET_PLACEMENT_CANARY';
function signed(r = request, envelope = {}, fields = {}) {
  const e = { pubkey: ownerPubkey, kind: 9, created_at: now / 1000, tags: [['h', channelId], ['e', threadId, '', 'root'], ['p', targetPubkey]],
    content: JSON.stringify({ type: 'host-operator.request', version: 1, request: r, descriptorDigest: digest(descriptor(request, source)), expiresAt: now + 600000, ...envelope }), ...fields };
  e.id = createHash('sha256').update(JSON.stringify([0, e.pubkey, e.created_at, e.kind, e.tags, e.content])).digest('hex');
  e.sig = Buffer.from(schnorr.sign(Buffer.from(e.id, 'hex'), scalar, new Uint8Array(32))).toString('hex'); return e;
}
function fixture(t) {
  assert.notEqual(process.getuid(), 0);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'event-placement-')); fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const directory = path.join(root, 'events'); fs.mkdirSync(directory, { mode: 0o700 });
  const options = { directory, uid: process.getuid(), ownerPubkey, targetPubkey, channelId, threadId, source };
  const event = signed(), raw = JSON.stringify(event), file = path.join(directory, event.id + '.json');
  let clock = now;
  return { root, directory, options, event, raw, file, time: v => { clock = v; },
    placer: createFileEventPlacer({ ...options, clock: () => clock }),
    read: createFileEventResolver({ directory, uid: process.getuid(), clock: () => now, monotonic: () => 0 }) };
}
function patch(name, wrapper, work) { const original = fs[name]; fs[name] = wrapper(original); try { return work(); } finally { fs[name] = original; } }
function safe(f, value) { const text = JSON.stringify(value); for (const x of [f.root, f.raw, f.event.sig, canary]) assert(!text.includes(x)); assert(text.length < 200); }
function denied(f, raw = f.raw) { const r = f.placer.place(raw); assert.equal(r.status, 'denied'); safe(f, r); assert(!fs.existsSync(f.file)); }

// Child processes have no operational network/process capability: they touch only the disposable fixture.
const child = `import fs from 'node:fs';
import { createFileEventPlacer } from ${JSON.stringify(new URL('../host-operator-auth/event-placement.mjs', import.meta.url).href)};
const {options,raw,point}=JSON.parse(fs.readFileSync(0,'utf8'));
let linked=false, unlinked=false;
const kill=()=>process.kill(process.pid,'SIGKILL');
const sync=fs.fsyncSync,link=fs.linkSync,unlink=fs.unlinkSync;
fs.fsyncSync=(fd)=>{ const dir=fs.fstatSync(fd).isDirectory(); if(point==='before-stage-sync'&&!dir)kill(); if(point==='before-parent-sync'&&dir)kill(); const r=sync(fd); if(point==='after-parent-sync'&&dir)kill(); return r; };
fs.linkSync=(...a)=>{ const r=link(...a); linked=true;if(point==='after-link')kill();return r; };
fs.unlinkSync=(...a)=>{ if(point==='before-unlink'&&linked)kill(); const r=unlink(...a);unlinked=true;if(point==='after-unlink')kill();return r; };
const r=createFileEventPlacer({...options,clock:()=>${now}}).place(raw);process.stdout.write(JSON.stringify(r));`;
function launch(f, point, raw = f.raw) {
  const p = spawn(process.execPath, ['--input-type=module', '-e', child], { stdio: ['pipe', 'pipe', 'pipe'] });
  let out = '', err = ''; p.stdout.on('data', b => { out += b; }); p.stderr.on('data', b => { err += b; });
  p.stdin.end(JSON.stringify({ options: f.options, raw, point }));
  return new Promise((resolve, reject) => { p.on('error', reject); p.on('exit', (code, signal) => resolve({ code, signal, out, err })); });
}

test('real A1 proof-derived publication preserves wire bytes, sync order, private final and actual A8/A1 reread', t => {
  const f = fixture(t), order = [], sync = fs.fsyncSync, link = fs.linkSync, unlink = fs.unlinkSync;
  fs.fsyncSync = fd => { order.push(fs.fstatSync(fd).isDirectory() ? 'parent-sync' : 'file-sync'); return sync(fd); };
  fs.linkSync = (...a) => { order.push('link'); const r = link(...a); assert.throws(() => f.read(f.event.id)); return r; };
  fs.unlinkSync = (...a) => { order.push('unlink'); const r = unlink(...a); assert.equal(f.read(f.event.id).toString(), f.raw); return r; };
  let r; try { r = f.placer.place(Buffer.from(f.raw)); } finally { fs.fsyncSync = sync; fs.linkSync = link; fs.unlinkSync = unlink; }
  assert.deepEqual(order, ['file-sync', 'link', 'unlink', 'parent-sync']); assert.equal(r.status, 'confirmed'); assert.equal(r.eventId, f.event.id); safe(f, r);
  assert.deepEqual(fs.readdirSync(f.directory), [f.event.id + '.json']);
  const s = fs.lstatSync(f.file); assert.equal(s.mode & 0o7777, 0o600); assert.equal(s.uid, process.getuid()); assert.equal(s.nlink, 1);
  assert.equal(f.read(f.event.id).toString(), f.raw);
  assert.equal(verifyOwnerEvent(f.read(f.event.id), { ...f.options, now }).request.authorizationEventId, f.event.id);
});
test('same exact bytes are already_present/unproven; whitespace wire variation conflicts without replacement', t => {
  const f = fixture(t); assert.equal(f.placer.place(f.raw).status, 'confirmed'); const ino = fs.statSync(f.file).ino;
  patch('linkSync', () => () => assert.fail('existing entry must not be republished'), () => {
    assert.deepEqual(f.placer.place(f.raw), { status: 'already_present', code: 'durability_unproven', eventId: f.event.id });
    assert.equal(f.placer.place(' ' + f.raw + '\n').status, 'conflict');
  });
  assert.equal(fs.statSync(f.file).ino, ino); assert.equal(fs.readFileSync(f.file, 'utf8'), f.raw); assert.equal(fs.readdirSync(f.directory).length, 1);
});
test('input brands reject proxy/accessor/extra/symbol/shared/extended Buffers without invoking caller code', t => {
  const f = fixture(t); let invoked = 0;
  const hostile = { get raw() { invoked++; throw Error(canary); }, toString() { invoked++; throw Error(canary); } };
  const extended = Buffer.from(f.raw); extended.extra = true;
  const getter = Buffer.from(f.raw); Object.defineProperty(getter, 'foo', { get() { invoked++; throw Error(canary); } });
  const symbol = Buffer.from(f.raw); symbol[Symbol('private')] = true;
  const proxy = new Proxy(Buffer.from(f.raw), { get() { invoked++; throw Error(canary); }, ownKeys() { invoked++; throw Error(canary); }, getPrototypeOf() { invoked++; throw Error(canary); } });
  for (const raw of [hostile, extended, getter, symbol, proxy, new Proxy({}, {}), Symbol('x'), null, [], new String(f.raw), new Uint8Array(2), Buffer.from(new SharedArrayBuffer(2)), '', 'x'.repeat(16385), Buffer.alloc(16385), '\ud800']) denied(f, raw);
  assert.equal(f.placer.place(f.raw, { path: canary }).status, 'denied');
  assert.equal(invoked, 0); assert.deepEqual(fs.readdirSync(f.directory), []);
});
test('constructor rejects unsafe config without getters/proxy traps and has a fixed error', t => {
  const f = fixture(t); let invoked = 0;
  const accessor = { ...f.options }; Object.defineProperty(accessor, 'directory', { get() { invoked++; throw Error(canary); } });
  for (const options of [accessor, new Proxy({}, { getPrototypeOf() { invoked++; throw Error(canary); } }), { ...f.options, uid: 0 }, { ...f.options, uid: process.getuid() + 1 },
    { ...f.options, directory: f.directory + '/' }, { ...f.options, directory: '../events' }, { ...f.options, path: canary }, { ...f.options, [Symbol('x')]: 1 }, { ...f.options, clock: null }]) {
    assert.throws(() => createFileEventPlacer(options), e => e.message === 'event_placement_denied' && e.stack === 'event_placement_denied');
  }
  assert.equal(invoked, 0);
});
test('actual A1 rejects malformed UTF8/duplicate/deep JSON, forged cryptography and signed wrong scope before any staging', t => {
  const f = fixture(t);
  const bad = [Buffer.from([0xc3, 0x28]), '{', f.raw.replace('"kind":9', '"kind":9,"kind":9'), '['.repeat(18) + '0' + ']'.repeat(18),
    JSON.stringify({ ...f.event, sig: '0'.repeat(128) }), JSON.stringify({ ...f.event, id: '0'.repeat(64) }), JSON.stringify({ ...f.event, content: f.event.content + ' ' }),
    JSON.stringify(signed(request, {}, { pubkey: 'a'.repeat(64) })), JSON.stringify(signed(request, {}, { kind: 1 })), JSON.stringify(signed(request, {}, { tags: [] })),
    JSON.stringify(signed({ ...request, operationId: 'validate.node' })), JSON.stringify(signed(request, { expiresAt: now })), JSON.stringify(signed(request, { descriptorDigest: 'a'.repeat(64) })),
    JSON.stringify(signed({ ...request, repository: 'other/repo' })), JSON.stringify(signed({ ...request, threadId: 'a'.repeat(64) })), JSON.stringify(signed(request, { delegation: true }))];
  for (const raw of bad) denied(f, raw);
  assert.deepEqual(fs.readdirSync(f.directory), []);
});
test('clock reversal, invalid time and expiry before publication deny with no final', t => {
  for (const value of [now - 1, now + 600000, NaN, -1]) {
    const f = fixture(t);
    patch('fsyncSync', orig => fd => { const r = orig(fd); f.time(value); return r; }, () => denied(f));
  }
});
test('complete short writes succeed; zero/invalid writes and ENOSPC never publish or delete evidence', t => {
  const f = fixture(t);
  patch('writeSync', orig => (fd, b, offset, size, pos) => orig(fd, b, offset, Math.min(size, 7), pos), () => assert.equal(f.placer.place(f.raw).status, 'confirmed'));
  for (const value of [0, -1, NaN, Infinity, 20000, 'ENOSPC']) {
    const g = fixture(t);
    patch('writeSync', () => () => { if (value === 'ENOSPC') throw Error(canary); return value; }, () => denied(g));
    assert.equal(fs.readdirSync(g.directory).length, 1);
  }
});
test('unsafe namespace modes, symlinks, missing directory and parent replacement deny without repair', t => {
  for (const kind of ['mode', 'ancestor', 'symlink', 'missing', 'replacement']) {
    const f = fixture(t);
    if (kind === 'mode') fs.chmodSync(f.directory, 0o750);
    if (kind === 'ancestor') fs.chmodSync(f.root, 0o770);
    if (kind === 'symlink') { fs.renameSync(f.directory, f.directory + '.saved'); fs.symlinkSync(f.directory + '.saved', f.directory); }
    if (kind === 'missing') fs.renameSync(f.directory, f.directory + '.saved');
    if (kind === 'replacement') {
      patch('writeSync', orig => (...a) => { const r = orig(...a); fs.renameSync(f.directory, f.directory + '.saved'); fs.mkdirSync(f.directory, { mode: 0o700 }); return r; }, () => denied(f));
    } else denied(f);
    fs.chmodSync(f.root, 0o700);
  }
});
test('existing files with unsafe mode/type/link metadata are never adopted or altered', t => {
  for (const kind of ['mode', 'hardlink', 'symlink', 'directory', 'fifo']) {
    const f = fixture(t);
    if (kind === 'directory') fs.mkdirSync(f.file, { mode: 0o700 });
    else if (kind === 'fifo') assert.equal(spawnSync('mkfifo', ['-m', '600', f.file]).status, 0);
    else { fs.writeFileSync(f.file, f.raw, { mode: 0o600 }); if (kind === 'mode') fs.chmodSync(f.file, 0o640);
      if (kind === 'hardlink') fs.linkSync(f.file, f.file + '.alias');
      if (kind === 'symlink') { fs.renameSync(f.file, f.file + '.saved'); fs.symlinkSync(f.file + '.saved', f.file); } }
    const before = fs.lstatSync(f.file); assert.equal(f.placer.place(f.raw).status, 'denied'); assert.equal(fs.lstatSync(f.file).ino, before.ino); assert.equal(fs.lstatSync(f.file).mode, before.mode);
  }
});
test('staged inode/size/bytes substitution and wrong owner/device deny before publication', t => {
  for (const kind of ['inode', 'size', 'bytes', 'uid', 'dev']) {
    const f = fixture(t);
    if (['uid', 'dev'].includes(kind)) {
      patch('fstatSync', orig => (...a) => { const s = orig(...a); if (s.isFile()) s[kind] += 1n; return s; }, () => denied(f));
    } else patch('fsyncSync', orig => fd => {
      const r = orig(fd), stage = path.join(f.directory, fs.readdirSync(f.directory)[0]);
      if (kind === 'inode') { fs.renameSync(stage, stage + '.saved'); fs.writeFileSync(stage, f.raw, { mode: 0o600 }); }
      if (kind === 'size') fs.appendFileSync(stage, ' ');
      if (kind === 'bytes') fs.writeFileSync(stage, 'X' + f.raw.slice(1));
      return r;
    }, () => denied(f));
  }
});
test('file fsync failure denies before link; ambiguous link, unlink and parent sync failures never confirm', t => {
  for (const point of ['file-sync', 'link-before', 'link-after', 'unlink', 'parent-sync', 'readback']) {
    const f = fixture(t); let r;
    if (point.includes('sync')) r = patch('fsyncSync', orig => fd => {
      if (fs.fstatSync(fd).isDirectory() === (point === 'parent-sync')) throw Error(canary + f.root); return orig(fd);
    }, () => f.placer.place(f.raw));
    if (point.startsWith('link-')) r = patch('linkSync', orig => (...a) => { if (point === 'link-after') orig(...a); throw Error(canary); }, () => f.placer.place(f.raw));
    if (point === 'unlink') r = patch('unlinkSync', () => () => { throw Error(canary); }, () => f.placer.place(f.raw));
    if (point === 'readback') {
      const sync = fs.fsyncSync; let synced = false;
      fs.fsyncSync = fd => { const r = sync(fd); if (fs.fstatSync(fd).isDirectory()) synced = true; return r; };
      try { r = patch('readSync', orig => (...a) => { if (synced) throw Error(canary); return orig(...a); }, () => f.placer.place(f.raw)); } finally { fs.fsyncSync = sync; }
    }
    assert.equal(r.status, point === 'file-sync' ? 'denied' : 'outcome_unknown'); safe(f, r);
    const entries = fs.readdirSync(f.directory);
    if (['link-after', 'unlink'].includes(point)) { assert.throws(() => f.read(f.event.id)); assert.equal(fs.statSync(f.file).nlink, 2); assert.equal(f.placer.place(f.raw).status, 'denied'); }
    if (['parent-sync', 'readback'].includes(point)) {
      assert.equal(f.read(f.event.id).toString(), f.raw); assert.equal(verifyOwnerEvent(f.read(f.event.id), { ...f.options, now }).request.authorizationEventId, f.event.id);
      assert.equal(f.placer.place(f.raw).status, 'already_present');
    }
    assert.deepEqual(fs.readdirSync(f.directory), entries);
  }
});
test('SIGKILL at storage boundaries preserves ambiguity; retry never claims prior durability or cleans stale files', async t => {
  for (const point of ['before-stage-sync', 'after-link', 'before-unlink', 'after-unlink', 'before-parent-sync', 'after-parent-sync']) {
    const f = fixture(t), r = await launch(f, point); assert.equal(r.signal, 'SIGKILL'); assert.equal(r.out, ''); assert.equal(r.err, '');
    const entries = fs.readdirSync(f.directory), stages = entries.filter(x => x.startsWith('.event-'));
    if (point === 'before-stage-sync') { assert(!fs.existsSync(f.file)); assert.equal(stages.length, 1); }
    else if (['after-link', 'before-unlink'].includes(point)) { assert.equal(fs.statSync(f.file).nlink, 2); assert.throws(() => f.read(f.event.id)); assert.equal(f.placer.place(f.raw).status, 'denied'); }
    else { assert.equal(f.read(f.event.id).toString(), f.raw); assert.equal(f.placer.place(f.raw).status, 'already_present'); }
    for (const name of stages) assert(fs.existsSync(path.join(f.directory, name)));
  }
});
test('cooperative concurrent same-event publishers never replace/truncate; different signed IDs stay independent', async t => {
  const f = fixture(t), runs = await Promise.all(Array.from({ length: 4 }, () => launch(f)));
  for (const r of runs) { assert.equal(r.code, 0, r.err); assert(['confirmed', 'already_present', 'outcome_unknown', 'denied'].includes(JSON.parse(r.out).status)); }
  // A contender observing the intentional nlink2 interval denies before its own publication attempt.
  assert.equal(runs.filter(r => JSON.parse(r.out).status === 'confirmed').length, 1); assert.equal(fs.readFileSync(f.file, 'utf8'), f.raw); assert.equal(fs.statSync(f.file).nlink, 1);
  const raws = [2, 3].map(n => JSON.stringify(signed({ ...request, requestId: 'request-' + n })));
  const different = await Promise.all(raws.map(raw => launch(f, undefined, raw)));
  assert(different.every(r => r.code === 0 && JSON.parse(r.out).status === 'confirmed'));
  for (const raw of raws) assert.equal(f.read(JSON.parse(raw).id).toString(), raw);
});

test('exclusive staging collision, inaccessible syscalls and short/growing read deny without a false confirmation', t => {
  for (const name of ['realpathSync', 'lstatSync', 'openSync', 'fstatSync', 'readSync', 'closeSync']) {
    const f = fixture(t);
    patch(name, () => () => { throw Error(canary + f.root); }, () => {
      const r = f.placer.place(f.raw); assert.equal(r.status, 'denied'); safe(f, r);
    });
    assert(!fs.existsSync(f.file));
  }
  for (const kind of ['short', 'growth', 'stage-collision']) {
    const f = fixture(t);
    if (kind === 'stage-collision') patch('openSync', orig => (...a) => {
      if (String(a[0]).includes('.event-')) { const error = Error(canary); error.code = 'EEXIST'; throw error; } return orig(...a);
    }, () => denied(f));
    else patch('readSync', orig => (...a) => { const n = orig(...a); return kind === 'short' ? n - 1 : n + 1; }, () => denied(f));
  }
});
test('stage substituted after publication remains evidence and cannot be unlinked as this call-owned inode', t => {
  const f = fixture(t), read = fs.readSync; let linked = false;
  patch('linkSync', orig => (...a) => { orig(...a); linked = true; }, () => {
    fs.readSync = (...a) => {
      const count = read(...a);
      if (linked && fs.fstatSync(a[0]).nlink === 2) {
        const stage = fs.readdirSync(f.directory).find(x => x.startsWith('.event-'));
        if (stage && !stage.endsWith('.saved')) {
          fs.renameSync(path.join(f.directory, stage), path.join(f.directory, stage + '.saved'));
          fs.writeFileSync(path.join(f.directory, stage), canary, { mode: 0o600 }); linked = false;
        }
      }
      return count;
    };
    try { assert.equal(f.placer.place(f.raw).status, 'outcome_unknown'); } finally { fs.readSync = read; }
  });
  const names = fs.readdirSync(f.directory); assert.equal(names.length, 3);
  assert(names.some(name => fs.readFileSync(path.join(f.directory, name), 'utf8') === canary));
});

test('wrong directory owner and unsafe final device/owner observations deny without changing active bytes', t => {
  for (const kind of ['parent-uid', 'file-uid', 'file-dev']) {
    const f = fixture(t);
    if (kind !== 'parent-uid') assert.equal(f.placer.place(f.raw).status, 'confirmed');
    patch('lstatSync', orig => (...a) => {
      const s = orig(...a);
      if (kind === 'parent-uid' && a[0] === f.directory) s.uid += 1n;
      if (kind.startsWith('file-') && a[0] === f.file) s[kind.slice(5)] += 1n;
      return s;
    }, () => assert.equal(f.placer.place(f.raw).status, 'denied'));
    if (kind !== 'parent-uid') assert.equal(fs.readFileSync(f.file, 'utf8'), f.raw);
    else assert(!fs.existsSync(f.file));
  }
});
