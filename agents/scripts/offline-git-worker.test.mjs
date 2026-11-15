import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { OP, LIMITS, HEADER, BINDINGS, binding, encodeFrame, decodeFrame, createSessionState } from '../offline-git-worker/protocol.mjs';
import { createOfflineGitClient } from '../offline-git-worker/client.mjs';
import { buildOfflineGitWorker, offlineGitFlags } from './build-offline-git-worker.mjs';
const root = fileURLToPath(new URL('../', import.meta.url));
const scope = () => Object.fromEntries(BINDINGS.map((k, i) => [k, (i + 1).toString(16).repeat(64)]));
const hash = file => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
function scratch(t) { const p = fs.mkdtempSync(path.join(os.tmpdir(), 'offline-git-source-')); fs.chmodSync(p, 0o700); t.after(() => fs.rmSync(p, { recursive: true, force: true })); return p; }
function run(command, args, cwd) {
  const r = spawnSync(command, args, { cwd, env: { LANG: 'C', LC_ALL: 'C', TZ: 'UTC' }, timeout: 60000, maxBuffer: 1048576, encoding: 'utf8' });
  assert.ifError(r.error); assert.equal(r.signal, null); assert.equal(r.status, 0, r.stderr); return r.stdout;
}
test('OGW1 binary golden header binds all six identities, sequence and length', () => {
  const b = encodeFrame(scope(), 1, OP.INIT);
  assert.equal(b.length, HEADER); assert.equal(b.subarray(0, 16).toString('hex'), '4f475731000100020000000100000000');
  assert.equal(b.subarray(16, 48).toString('hex'), '1'.repeat(64));
  assert.deepEqual(decodeFrame(b, scope(), 1), { op: OP.INIT, payload: Buffer.alloc(0) });
  for (let i = 0; i < BINDINGS.length; i++) {
    const changed = { ...scope(), [BINDINGS[i]]: 'a'.repeat(64) }; assert.throws(() => decodeFrame(b, changed, 1));
  }
});
test('unknown/version/sequence/trailing/duplicate-key object tricks fail closed', () => {
  const b = encodeFrame(scope(), 1, OP.INIT);
  for (const change of [x => x.writeUInt16BE(2, 4), x => x.writeUInt16BE(90, 6), x => x.writeUInt32BE(0, 8), x => x.writeUInt32BE(1, 12)]) {
    const v = Buffer.from(b); change(v); assert.throws(() => decodeFrame(v, scope(), 1));
  }
  assert.throws(() => decodeFrame(Buffer.concat([b, b]), scope(), 1)); assert.throws(() => decodeFrame(b.subarray(0, -1), scope(), 1));
  assert.throws(() => decodeFrame(b, scope(), 2)); assert.throws(() => encodeFrame(scope(), 0x100000000, OP.INIT));
  assert.throws(() => binding({ ...scope(), argv: ['sh'] })); assert.throws(() => binding(new Proxy(scope(), {})));
  let touched = false; const raw = scope(); Object.defineProperty(raw, 'nonce', { get() { touched = true; return 'a'.repeat(64); }, enumerable: true });
  assert.throws(() => binding(raw)); assert.equal(touched, false);
});
test('only raw 20-byte selectors and bounded sealed byte ranges enter operations', () => {
  for (const op of [OP.OBJECT, OP.TREE]) {
    const bytes = Buffer.alloc(20, 255); assert.deepEqual(decodeFrame(encodeFrame(scope(), 1, op, bytes), scope(), 1).payload, bytes);
    for (const b of [Buffer.from('--help'), Buffer.alloc(19), Buffer.alloc(21)]) assert.throws(() => encodeFrame(scope(), 1, op, b));
  }
  const range = Buffer.alloc(16); range.writeBigUInt64BE(4096n); range.writeBigUInt64BE(BigInt(LIMITS.bundle - 4096), 8);
  encodeFrame(scope(), 1, OP.INDEX_PACK, range); range.writeBigUInt64BE(BigInt(LIMITS.bundle - 4095), 8);
  assert.throws(() => encodeFrame(scope(), 1, OP.INDEX_PACK, range));
  assert.throws(() => encodeFrame(scope(), 1, OP.INIT, Buffer.from('/tmp/repo')));
  encodeFrame(scope(), 1, OP.DATA, Buffer.alloc(LIMITS.frame - HEADER));
  assert.throws(() => encodeFrame(scope(), 1, OP.DATA, Buffer.alloc(LIMITS.frame - HEADER + 1)));
});
function indexed() { const s = createSessionState(); for (const op of [OP.INIT, OP.INDEX_PACK, OP.VERIFY_PACK, OP.FSCK]) s.accept(op); return s; }
test('finite stages, replay denial and no post-settlement reads', () => {
  for (const op of [OP.FSCK, OP.OBJECT, OP.TREE, OP.SETTLE, OP.ADOPT]) assert.throws(() => createSessionState().accept(op));
  const s = indexed(); s.accept(OP.TREE); s.accept(OP.SETTLE); assert.throws(() => s.accept(OP.OBJECT)); assert(s.snapshot().dead);
  const replay = createSessionState(); replay.accept(OP.INIT); assert.throws(() => replay.accept(OP.INIT));
  const success = indexed(); success.accept(OP.SETTLE); success.accept(OP.ADOPT); assert.throws(() => success.accept(OP.ADOPT));
});
test('inclusive cumulative read/frame/machine/diagnostic ceilings and +1', () => {
  const s = indexed(); for (let i = 0; i < LIMITS.reads; i++) s.accept(OP.OBJECT); assert.throws(() => s.accept(OP.TREE));
  const bytes = indexed(); bytes.charge(LIMITS.machine, LIMITS.diagnostics); assert.throws(() => bytes.charge(1));
  const diagnostics = indexed(); diagnostics.charge(0, LIMITS.diagnostics); assert.throws(() => diagnostics.charge(0, 1));
  const frames = indexed(); for (let i = 0; i < LIMITS.frames; i++) frames.charge(0); assert.throws(() => frames.charge(0));
});
test('no client-selected transport/command/path/limit or regular-file capability', t => {
  const dir = scratch(t), file = path.join(dir, 'channel'); fs.writeFileSync(file, ''); const fd = fs.openSync(file, 'r'); t.after(() => fs.closeSync(fd));
  assert.throws(() => createOfflineGitClient({ channelFd: fd, binding: scope() }));
  for (const key of ['argv', 'path', 'env', 'limits', 'transport', 'qualified', 'testMode'])
    assert.throws(() => createOfflineGitClient({ channelFd: fd, binding: scope(), [key]: true }));
  assert(Object.isFrozen(LIMITS)); assert(Object.isFrozen(OP));
});
test('build refuses output substitution/nonempty output and has fixed hardened compiler arguments', t => {
  const dir = scratch(t); fs.writeFileSync(path.join(dir, 'existing'), ''); assert.throws(() => buildOfflineGitWorker(dir));
  assert.equal(offlineGitFlags[0], '-B/usr/bin/'); assert(offlineGitFlags.includes('-Werror')); assert(offlineGitFlags.includes('-fstack-protector-strong'));
  assert(offlineGitFlags.includes('-Wl,-z,relro,-z,now,-z,noexecstack')); assert(!offlineGitFlags.some(x => x.includes('OGW_TEST')));
});
test('MANDATORY native production build/inventory; missing compiler is failure, not skip', t => {
  const dir = scratch(t), result = buildOfflineGitWorker(dir), manifest = JSON.parse(fs.readFileSync(result.manifest));
  assert.equal(manifest.qualified, false); assert.equal(manifest.type, 'offline-git.source-build');
  for (const [name, b] of Object.entries(manifest.binaries)) assert.equal(b.digest, hash(path.join(dir, 'ogw-' + name)));
  assert.equal(manifest.sources['custody.c'].digest, hash(path.join(root, 'offline-git-worker/native/custody.c')));
  const denied = spawnSync(path.join(dir, 'ogw-supervisor'), [], { env: {}, timeout: 1000 });
  // Unprivileged invocation cannot initialize the host facility.
  if (process.getuid() !== 0) assert.equal(denied.status, 70);
});
for (const fixture of ['native', 'worker']) for (const sanitizer of [false, true])
  test(`MANDATORY ${fixture} ${sanitizer ? 'ASan+UBSan' : 'hardened'} fixture (not host acceptance)`, t => {
    const dir = scratch(t), binary = path.join(dir, fixture);
    const flags = sanitizer ? [...offlineGitFlags, '-fsanitize=address,undefined', '-fno-omit-frame-pointer'] : offlineGitFlags;
    run('/usr/bin/cc', [...flags, path.join(root, 'tests/offline-git-worker/' + fixture + '.test.c'), '-o', binary], dir);
    assert.match(run(binary, [], dir), /NOT (host|kernel isolation) acceptance/);
  });
