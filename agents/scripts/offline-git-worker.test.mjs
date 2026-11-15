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
function run(command, args, cwd, input) {
  const r = spawnSync(command, args, { cwd, input, env: { LANG: 'C', LC_ALL: 'C', TZ: 'UTC', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0' }, timeout: 60000, maxBuffer: 1048576, encoding: 'utf8' });
  assert.ifError(r.error); assert.equal(r.signal, null); assert.equal(r.status, 0, r.stderr); return r.stdout;
}
function bundleFixture(dir) {
  const git = (args, input) => run('/usr/bin/git', ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', '--git-dir=fixture', ...args], dir, input).trim();
  git(['init', '--bare', '--object-format=sha1', '--template=', 'fixture']);
  const blob = git(['hash-object', '-w', '--stdin'], 'x');
  const tree = git(['mktree'], `100644 blob ${blob}\tb\n`), commit = git(['commit-tree', tree, '-m', 'disposable source fixture']);
  git(['update-ref', 'refs/heads/candidate', commit]);
  git(['bundle', 'create', '--version=2', path.join(dir, 'bundle'), 'refs/heads/candidate']);
  const bytes = fs.readFileSync(path.join(dir, 'bundle')), offset = bytes.indexOf(Buffer.from('\n\n')) + 2;
  assert(offset > 1 && bytes.subarray(offset, offset + 4).toString() === 'PACK');
  fs.writeFileSync(path.join(dir, 'bundle.metadata'), `${blob} ${commit} ${tree} ${offset} ${bytes.length - offset}\n`, { mode: 0o600 });
  return { commit, git };
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
  for (const suffix of [[OP.SETTLE, OP.SETTLE], [OP.SETTLE, OP.ADOPT, OP.SETTLE]]) {
    const terminal = indexed(); for (const op of suffix.slice(0, -1)) terminal.accept(op);
    assert.throws(() => terminal.accept(suffix.at(-1))); assert(terminal.snapshot().dead);
    assert.throws(() => terminal.accept(OP.ADOPT));
  }
});
test('v2 inventory golden separates nested paths from sibling paths', () => {
  const u64 = n => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
  const tree = entries => Buffer.concat([Buffer.from('['), u64(entries.length), ...entries, Buffer.from(']')]);
  const name = s => Buffer.concat([u64(Buffer.byteLength(s)), Buffer.from(s)]);
  const file = s => Buffer.concat([name(s), Buffer.from('F'), u64(1), createHash('sha256').update('x').digest()]);
  const directory = (s, entries) => Buffer.concat([name(s), Buffer.from('D'), tree(entries)]);
  const nested = tree([directory('a', [file('b')])]), sibling = tree([directory('a', []), file('b')]);
  const digest = b => createHash('sha256').update(b).digest('hex');
  assert.notDeepEqual(nested, sibling);
  assert.equal(digest(nested), 'c20ef1a80c71b6fe5b18cb517755317017f444f1ef67638f0f4dbe8d8c3088b5');
  assert.equal(digest(sibling), 'fb75ef870ad78abaf00a8501cf0a90304a3560b5070ff420d363f76ff8d529e0');
  assert.equal(digest(Buffer.concat([Buffer.from('offline-git-runtime/v2\n'), nested])), 'de31271d8e0b8878e4babea43c45c1e02550c6d1d0198b4272ce98e6b0dbf033');
  assert.equal(digest(Buffer.concat([Buffer.from('offline-git-custody/v2\n'), Buffer.alloc(192, 1), sibling])), '1d542292a1562430954671a41413a25b47912f2e32fbe10398d3e531f427cc36');
});
test('real self-contained SHA1 v2 source fixture is independently reproducible', t => {
  const dir = scratch(t), f = bundleFixture(dir);
  assert.match(f.commit, /^[a-f0-9]{40}$/);
  assert.equal(fs.readFileSync(path.join(dir, 'bundle')).subarray(0, 16).toString(), '# v2 git bundle\n');
  assert.match(f.git(['bundle', 'verify', path.join(dir, 'bundle')]), new RegExp(f.commit));
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
    const bundle = fixture === 'worker' ? bundleFixture(dir) : undefined;
    assert.match(run(binary, [], dir), /NOT (host|kernel isolation) acceptance/);
    if (bundle) {
      const original = bundle.git(['cat-file', 'commit', bundle.commit]);
      const imported = run('/usr/bin/git', ['--git-dir=session-0/repo', 'cat-file', 'commit', bundle.commit], dir).trim();
      assert.equal(imported, original);
    }
  });
