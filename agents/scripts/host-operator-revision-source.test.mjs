import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as processTools from 'node:child_process';
import { createDetachedRevisionObserver } from '../host-operator-auth/revision-source.mjs';

const sha = 'b'.repeat(40), different = 'a'.repeat(40), canary = 'SECRET_REVISION_CANARY', now = 1800000000000;
const source = { repository: 'test-org/project', baseRef: 'main', baseSha: sha, workspaceId: 'pointer-fixture', sourceDigest: 'c'.repeat(64) };
function fixture(t, raw = sha + '\n') {
  assert.notEqual(process.getuid(), 0);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'revision-pointer-')); fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const directory = path.join(root, 'source'), metadata = path.join(directory, '.git');
  fs.mkdirSync(directory, { mode: 0o700 }); fs.mkdirSync(metadata, { mode: 0o700 });
  const head = path.join(metadata, 'HEAD'); fs.writeFileSync(head, raw, { mode: 0o600 });
  const options = { sourceDirectory: directory, uid: process.getuid(), source: { ...source }, clock: () => now, monotonic: () => 0 };
  return { root, directory, metadata, head, options, observe: createDetachedRevisionObserver(options).observe };
}
function denied(fn, f) {
  assert.throws(fn, e => {
    assert.equal(e.code, 'revision_source_denied'); assert.equal(e.message, 'revision_source_denied'); assert.equal(e.stack, 'revision_source_denied');
    for (const text of [f?.root, canary].filter(Boolean)) assert(!JSON.stringify(e).includes(text)); return true;
  });
}
function patch(name, wrapper, work) { const original = fs[name]; fs[name] = wrapper(original); try { return work(); } finally { fs[name] = original; } }
function safe(f, result) {
  assert.deepEqual(Object.keys(result).sort(), ['status', 'repository', 'workspaceId', 'expectedSha', 'observedSha', 'observedAt'].sort());
  const text = JSON.stringify(result); assert(Buffer.byteLength(text) <= 4096);
  for (const value of [f.root, canary, source.sourceDigest, 'tree', 'dirty', 'origin', 'verified', 'receipt', 'complete', 'READY']) assert(!text.includes(value));
}

test('real detached pointer observation is fresh, reports mismatch and never proves an object/tree/checkout', t => {
  const f = fixture(t); assert(!fs.existsSync(path.join(f.metadata, 'objects')), 'fixture deliberately has no Git objects');
  const result = f.observe(); safe(f, result); assert(Object.isFrozen(result));
  assert.deepEqual(result, { status: 'observed', repository: source.repository, workspaceId: source.workspaceId, expectedSha: sha, observedSha: sha, observedAt: now });
  fs.writeFileSync(f.head, different); const mismatch = f.observe(); safe(f, mismatch); assert.equal(mismatch.status, 'mismatch'); assert.equal(mismatch.observedSha, different); assert.equal(mismatch.expectedSha, sha);
  fs.writeFileSync(f.head, sha); assert.equal(f.observe().status, 'observed');
  fs.unlinkSync(f.head); denied(f.observe, f); fs.writeFileSync(f.head, different + '\n', { mode: 0o600 }); assert.equal(f.observe().status, 'mismatch');
});
test('exact detached bytes accept only 40 lowercase ASCII hex plus optional single LF', t => {
  for (const raw of [sha, sha + '\n']) { const f = fixture(t, raw); assert.equal(f.observe().observedSha, sha); }
  for (const raw of ['', sha.slice(1), sha + '0', sha + '\n\n', sha + '\r', sha + '\r\n', sha.toUpperCase(), ' '+sha, sha+' ', sha+'\0', 'ref: refs/heads/main\n', 'ref: '+sha, canary,
    'x'.repeat(100000), Buffer.from([0xef, 0xbb, 0xbf, ...Buffer.from(sha)]), Buffer.from([0xe2, ...Buffer.from(sha.slice(1))]), different + '\n' + sha]) {
    const f = fixture(t, raw); denied(f.observe, f);
  }
});
test('observe accepts zero arguments and rejects request/path/env/argv overrides before I/O or getters', t => {
  const f = fixture(t); let invoked = 0;
  const hostile = { get path() { invoked++; throw Error(canary); }, toString() { invoked++; throw Error(canary); } };
  for (const arg of [undefined, null, hostile, { verified: true }, { execute: 'git', argv: [], env: {}, mount: '/' }, '../HEAD', Symbol('path'), new Proxy({}, { get() { invoked++; throw Error(canary); } })]) {
    patch('lstatSync', () => () => { invoked++; throw Error(canary); }, () => denied(() => f.observe(arg), f));
  }
  assert.equal(invoked, 0);
});
test('constructor enforces plain own data and snapshots immutable logical mapping without consulting the filesystem', t => {
  const f = fixture(t); let invoked = 0;
  const accessor = { ...f.options }; Object.defineProperty(accessor, 'sourceDirectory', { get() { invoked++; throw Error(canary); } });
  const sourceAccessor = { ...source }; Object.defineProperty(sourceAccessor, 'baseSha', { get() { invoked++; throw Error(canary); } });
  for (const options of [accessor, new Proxy({}, { getPrototypeOf() { invoked++; throw Error(canary); } }), { ...f.options, source: sourceAccessor },
    { ...f.options, [Symbol('x')]: true }, { ...f.options, execute: () => {} }, { ...f.options, uid: 0 }, { ...f.options, uid: process.getuid()+1 },
    { ...f.options, uid: '10001' }, { ...f.options, sourceDirectory: '/' }, { ...f.options, sourceDirectory: 'relative' }, { ...f.options, sourceDirectory: f.directory+'/' },
    { ...f.options, sourceDirectory: f.directory+'/../source' }, { ...f.options, sourceDirectory: f.directory+'\0' }, { ...f.options, sourceDirectory: '/'+ 'x'.repeat(4096) },
    { ...f.options, clock: null }, { ...f.options, monotonic: false }, { ...f.options, source: { ...source, sourceDigest: 'bad' } }, Object.create(f.options)]) denied(() => createDetachedRevisionObserver(options), f);
  assert.equal(invoked, 0);
  const options = { ...f.options, source: { ...source } };
  const observer = patch('lstatSync', () => () => assert.fail('constructor performs no source lookup'), () => createDetachedRevisionObserver(options));
  assert(Object.isFrozen(observer)); assert.deepEqual(Object.keys(observer), ['observe']);
  options.source.baseSha = different; options.source.repository = 'other/repo'; options.sourceDirectory = '/absent'; options.uid = 0;
  assert.equal(observer.observe().expectedSha, sha); assert.equal(observer.observe().repository, source.repository);
});
test('unsupported symbolic refs/gitfile/worktree/bare/missing layouts deny with no alternate resolution', t => {
  for (const kind of ['gitfile', 'bare', 'missing-head', 'metadata-symlink', 'head-symlink', 'source-symlink', 'ref']) {
    const f = fixture(t);
    if (kind === 'gitfile') { fs.renameSync(f.metadata, f.metadata+'.saved'); fs.writeFileSync(f.metadata, 'gitdir: '+canary+'\n', { mode: 0o600 }); }
    if (kind === 'bare') { fs.renameSync(f.metadata, f.metadata+'.saved'); fs.writeFileSync(path.join(f.directory, 'HEAD'), sha, { mode: 0o600 }); }
    if (kind === 'missing-head') fs.unlinkSync(f.head);
    if (kind === 'metadata-symlink') { fs.renameSync(f.metadata, f.metadata+'.saved'); fs.symlinkSync(f.metadata+'.saved', f.metadata); }
    if (kind === 'head-symlink') { fs.renameSync(f.head, f.head+'.saved'); fs.symlinkSync(f.head+'.saved', f.head); }
    if (kind === 'source-symlink') { fs.renameSync(f.directory, f.directory+'.saved'); fs.symlinkSync(f.directory+'.saved', f.directory); }
    if (kind === 'ref') { fs.writeFileSync(f.head, 'ref: refs/heads/main\n'); fs.mkdirSync(path.join(f.metadata, 'refs','heads'),{recursive:true,mode:0o700}); fs.writeFileSync(path.join(f.metadata,'refs/heads/main'),sha,{mode:0o600}); }
    denied(f.observe, f);
  }
});
test('protected ordinary directories and non-secret HEAD0600/0644 are allowed; unsafe ancestor/metadata modes deny without repair', t => {
  const f = fixture(t); for (const mode of [0o600, 0o644]) { fs.chmodSync(f.head, mode); assert.equal(f.observe().observedSha, sha); }
  fs.chmodSync(f.directory,0o755); fs.chmodSync(f.metadata,0o755); assert.equal(f.observe().status, 'observed');
  for (const target of [f.root, f.directory, f.metadata, f.head]) for (const mode of [0o777, 0o770, 0o2770, 0o4600]) {
    const previous = fs.statSync(target).mode & 0o7777; fs.chmodSync(target, mode); denied(f.observe, f); assert.equal(fs.statSync(target).mode & 0o7777, mode); fs.chmodSync(target, previous);
  }
});
test('HEAD must be a same-device same-UID regular single-link file; no FIFOs, directories, devices or metadata repair', t => {
  for (const kind of ['hardlink', 'directory', 'fifo']) {
    const f = fixture(t);
    if (kind === 'hardlink') fs.linkSync(f.head, f.head+'.alias');
    else { fs.unlinkSync(f.head); if (kind === 'directory') fs.mkdirSync(f.head,{mode:0o700}); else assert.equal(processTools.spawnSync('mkfifo',['-m','600',f.head]).status,0); }
    denied(f.observe, f);
  }
  for (const kind of ['uid', 'dev', 'device']) {
    const f = fixture(t);
    patch('lstatSync', orig => (...a) => { const s=orig(...a); if(a[0]===f.head) { if(kind==='device')s.mode=0o020600n;else s[kind]+=1n; } return s; }, () => denied(f.observe,f));
  }
  for (const target of ['root', 'directory', 'metadata']) {
    const f=fixture(t); patch('lstatSync', orig => (...a)=>{const s=orig(...a);if(a[0]===f[target])s.uid=BigInt(process.getuid()+1);return s;},()=>denied(f.observe,f));
  }
});
test('source/.git/HEAD replacement and metadata/byte-size races are detected around actual positional read', t => {
  for(const kind of ['root','directory','metadata','head','grow','truncate','mtime']) {
    const f=fixture(t);
    patch('readSync', orig => (...a)=>{
      const n=orig(...a);
      if(['root','directory','metadata','head'].includes(kind)) { const target=kind==='head'?f.head:f[kind]; fs.renameSync(target,target+'.saved'); if(kind==='head')fs.writeFileSync(target,sha,{mode:0o600});else fs.mkdirSync(target,{mode:0o700}); }
      if(kind==='grow')fs.appendFileSync(f.head,'0');
      if(kind==='truncate')fs.truncateSync(f.head,40);
      if(kind==='mtime')fs.utimesSync(f.head,new Date(1000),new Date(1000));
      return n;
    },()=>denied(f.observe,f));
    if(kind==='root')fs.rmSync(f.root+'.saved',{recursive:true,force:true});
  }
});
test('source and metadata directory swaps before/open anchoring deny even with still-held original descriptors', t => {
  for(const kind of ['directory','metadata']) {
    const f=fixture(t);let changed=false;
    patch('openSync',orig=>(...a)=>{const fd=orig(...a);if(a[0]===f[kind]&&!changed){changed=true;fs.renameSync(f[kind],f[kind]+'.saved');fs.mkdirSync(f[kind],{mode:0o700});}return fd;},()=>denied(f.observe,f));assert(changed);
  }
});
test('fixed denial for every read/open/stat/realpath/close failure, including close-after-read and short/overrun reads', t => {
  for(const name of ['realpathSync','lstatSync','openSync','fstatSync','readSync','closeSync']) {
    const f=fixture(t);patch(name,()=>()=>{throw Error(canary+f.root);},()=>denied(f.observe,f));
  }
  for(const count of [0,39,42,-1,NaN]) {const f=fixture(t);patch('readSync',orig=>(...a)=>{orig(...a);return count;},()=>denied(f.observe,f));}
  const f=fixture(t);let read=false;
  const original=fs.readSync;fs.readSync=(...a)=>{const n=original(...a);read=true;return n;};
  try{patch('closeSync',orig=>fd=>{const r=orig(fd);if(read)throw Error(canary);return r;},()=>denied(f.observe,f));}finally{fs.readSync=original;}
});
test('observed wall/monotonic100ms limit and clock reversals/nonfinite values deny without inventing observation', t => {
  for(const clockName of ['clock','monotonic']) for(const bad of [-1,NaN,Infinity,'0',clockName==='clock'?now-1:-0.5,clockName==='clock'?now+101:101]) {
    const f=fixture(t);let count=0;
    const observe=createDetachedRevisionObserver({...f.options,[clockName]:()=>++count===1?(clockName==='clock'?now:0):bad}).observe;
    denied(observe,f);
  }
  const f=fixture(t);let wall=now,mono=0;
  const observe=createDetachedRevisionObserver({...f.options,clock:()=>wall,monotonic:()=>mono}).observe;
  patch('readSync',orig=>(...a)=>{const n=orig(...a);wall+=100;mono+=100;return n;},()=>assert.equal(observe().observedAt,now+100));
  // Subsequent independent lookup refreshes actual metadata and timestamp, not a verdict cache.
  wall=now+1000;mono=1000;assert.equal(observe().observedAt,now+1000);
});
test('only fixed .git/HEAD is opened/read: bounded42 bytes and zero writes/listing/config/ref/object/Git lookups', t => {
  const f=fixture(t),allowed=new Set([f.directory,f.metadata,f.head]),opened=new Map();let reads=0;
  const originals=new Map();
  for(const name of ['readFileSync','readdirSync','writeFileSync','writeSync','mkdirSync','unlinkSync','renameSync','chmodSync','chownSync','linkSync','symlinkSync']){originals.set(name,fs[name]);fs[name]=()=>assert.fail('observer must not call '+name);}
  const open=fs.openSync,read=fs.readSync;
  fs.openSync=(name,flags,...a)=>{assert(allowed.has(name));assert(flags&fs.constants.O_NOFOLLOW);assert(flags&fs.constants.O_NONBLOCK);const fd=open(name,flags,...a);opened.set(fd,name);return fd;};
  fs.readSync=(fd,b,offset,length,position)=>{reads++;assert.equal(opened.get(fd),f.head);assert.equal(length,42);assert.equal(position,0);return read(fd,b,offset,length,position);};
  try{safe(f,f.observe());}finally{fs.openSync=open;fs.readSync=read;for(const [name,original]of originals)fs[name]=original;}
  assert.equal(reads,1);assert.equal(opened.size,3);assert.equal(fs.readFileSync(f.head,'utf8'),sha+'\n');
});
test('failed observations never cache error/expected state or leak upstream/path/file canaries', t => {
  const f=fixture(t,canary.padEnd(40,'x'));denied(f.observe,f);fs.writeFileSync(f.head,sha);safe(f,f.observe());
  patch('readSync',()=>()=>{throw Error(canary+'\n'+f.root+'\u001b[31m');},()=>denied(f.observe,f));assert.equal(f.observe().status,'observed');
});

test('module import and constructor start no source observation/process; module loader reads are separate', async t => {
  const f=fixture(t),originals=new Map(),processOriginals=new Map();
  for(const name of ['openSync','readSync','readFileSync','lstatSync','statSync','realpathSync','writeFileSync','readdirSync']){const original=fs[name];originals.set(name,original);fs[name]=(...a)=>{if(name==='writeFileSync'||(typeof a[0]==='string'&&a[0].startsWith(f.root)))assert.fail('import/constructor source access');return original(...a);};}
  for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork']){processOriginals.set(name,processTools.default[name]);processTools.default[name]=()=>assert.fail('no process boundary');}
  try {
    const module=await import('../host-operator-auth/revision-source.mjs?side-effect-fixture');
    const observer=module.createDetachedRevisionObserver(f.options);assert(Object.isFrozen(observer));
  } finally {for(const [name,fn]of originals)fs[name]=fn;for(const [name,fn]of processOriginals)processTools.default[name]=fn;}
});
