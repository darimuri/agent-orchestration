import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { deflateSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { BASE, GATES, refusal, inspect, assessDossier, readBounded, buildSource } from './offline-git-host-acceptance.mjs';
import { fixtureObjects, parseFixtureBundle, checkBatch } from '../tests/offline-git-worker/host-validator.mjs';
const script = fileURLToPath(new URL('./offline-git-host-acceptance.mjs',import.meta.url));
function dossier() { return { version:1,source:BASE,kernel:'fixture-unqualified',arch:'x64',quotaUs:20000,periodUs:100000,
  burstUs:0,parallelism:1,quotaSlackUs:10000,maxRunnableUs:40000000,terminationBoundUs:2000000,trustedCpuUs:500000,
  uncertaintyUs:100000,lifetimeContractSha256:'1'.repeat(64),independentReviewSha256:'2'.repeat(64) }; }
const assess = d => assessDossier(Buffer.from(JSON.stringify(d)));
function packet(type,b) {
  const bytes = []; let n = b.length; bytes.push((type << 4) | (n & 15)); n >>>= 4;
  while(n) { bytes[bytes.length-1] |= 128; bytes.push(n & 127); n >>>= 7; }
  return Buffer.concat([Buffer.from(bytes),deflateSync(b)]);
}
function bundle() {
  const f = fixtureObjects(), header = Buffer.alloc(12); header.write('PACK'); header.writeUInt32BE(2,4); header.writeUInt32BE(3,8);
  const pack = Buffer.concat([header,packet(1,f.commit),packet(2,f.tree),packet(3,f.blob)]);
  return Buffer.concat([Buffer.from(`# v2 git bundle\n${f.commitOid} refs/heads/candidate\n\n`),pack,createHash('sha1').update(pack).digest()]);
}
test('all preparation results refuse admission; caller numbers never prove authority', () => {
  assert.equal(refusal().qualified,false); assert.equal(refusal().status,'UNKNOWN'); assert.equal(GATES.length,6);
  const r = assess(dossier()); assert.equal(r.arithmeticWithinCeiling,true); assert.equal(r.aggregateUpperUs,'9030000');
  assert.equal(r.admission,false); assert.equal(r.assumptionsVerified,false);
  const d = dossier(); d.trustedCpuUs = 2000000;
  assert.equal(assess(d).arithmeticWithinCeiling,false); assert.equal(assess(d).admission,false);
});
test('closed dossier rejects absent, zero, extra, wrong identity, short lifetime and unsafe numbers', () => {
  for (const change of [{version:2},{source:'f'.repeat(40)},{parallelism:0},{parallelism:9},{quotaUs:21000},{burstUs:1},
    {maxRunnableUs:39999999},{terminationBoundUs:0},{trustedCpuUs:0},{uncertaintyUs:0},{quotaSlackUs:-1},
    {quotaSlackUs:1.5},{trustedCpuUs:Number.MAX_SAFE_INTEGER+1},{lifetimeContractSha256:'0'.repeat(64)},
    {independentReviewSha256:''},{arch:'unknown'},{kernel:'x\ny'},{extra:true}]) assert.throws(() => assess({...dossier(),...change}));
  assert.throws(() => assessDossier(Buffer.from('{}'))); assert.throws(() => assessDossier(Buffer.alloc(16385)));
  assert.throws(() => assessDossier(Buffer.from('null')));
  const huge = assess({...dossier(),maxRunnableUs:Number.MAX_SAFE_INTEGER});
  assert.equal(huge.arithmeticWithinCeiling,false); assert.equal(huge.admission,false);
});
test('bounded file inspection refuses symlinks, special files and oversized data', t => {
  const dir = fs.mkdtempSync('/tmp/age30-read-test-'); t.after(() => fs.rmSync(dir,{recursive:true}));
  const file = path.join(dir,'evidence'); fs.writeFileSync(file,'1234');
  assert.equal(readBounded(file,4).toString(),'1234'); assert.throws(() => readBounded(file,3));
  fs.symlinkSync(file,path.join(dir,'link')); assert.throws(() => readBounded(path.join(dir,'link'),4));
  assert.throws(() => readBounded('/dev/null',4)); assert.throws(() => readBounded(file,0));
});
test('nonroot inspect and probe are nonadmitting and reject every privileged/generic option', () => {
  const r = inspect(); assert.equal(r.admission,false); assert.equal(r.support.delegation,'UNKNOWN');
  assert.match(r.observationScope,/unqualified/); assert(!Object.hasOwn(r,'capsule'));
  for (const args of [['probe'],['inspect'],['qualify'],['probe','--run-id','age30-8bbc3a9d-r1'],['sh','-c','true']]) {
    const r = spawnSync(process.execPath,[script,...args],{env:{},encoding:'utf8',timeout:10000});
    assert.equal(r.status,2); assert.equal(JSON.parse(r.stdout || r.stderr).admission,false);
  }
});
test('dossier CLI bounds bytes and time and never accepts caller proof hashes', () => {
  const invoke = input => spawnSync(process.execPath,[script,'dossier'],{input,env:{},encoding:'utf8',timeout:5000});
  const good = invoke(JSON.stringify(dossier())); assert.equal(good.status,2);
  assert.equal(JSON.parse(good.stdout).admission,false);
  const bad = invoke('x'.repeat(16385)); assert.equal(bad.status,2); assert.equal(JSON.parse(bad.stderr).status,'UNKNOWN');
});
test('fixed real SHA1 bundle fixture, raw object identity and bounded malformed inputs', () => {
  const b = bundle(), range = parseFixtureBundle(b); assert.equal(range.offset+range.length,b.length);
  const f = fixtureObjects(), batch = Buffer.concat([Buffer.from(`${f.commitOid} commit ${f.commit.length}\n`),f.commit,Buffer.from('\n')]);
  checkBatch(batch,'commit',f.commitOid,f.commit);
  assert.throws(() => checkBatch(Buffer.concat([batch,Buffer.from('x')]),'commit',f.commitOid,f.commit));
  assert.throws(() => checkBatch(batch,'blob',f.commitOid,f.commit));
  for (const bad of [Buffer.alloc(0), b.subarray(0,-1), Buffer.concat([b,Buffer.from('x')]), Buffer.alloc(33554433)])
    assert.throws(() => parseFixtureBundle(bad));
  const corrupt = Buffer.from(b); corrupt[corrupt.length-21] ^= 1; assert.throws(() => parseFixtureBundle(corrupt));
});
test('fixture pack accepted by real Git without production qualification', t => {
  const dir = fs.mkdtempSync('/tmp/age30-pack-test-'); t.after(() => fs.rmSync(dir,{recursive:true}));
  const b = bundle(), range = parseFixtureBundle(b), f = fixtureObjects();
  const run = (args,input) => { const r = spawnSync('/usr/bin/git',args,{cwd:dir,env:{LANG:'C',GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null'},input,timeout:10000,maxBuffer:1048576});
    assert.equal(r.error,undefined); assert.equal(r.status,0,r.stderr?.toString()); return r.stdout; };
  run(['init','--bare','--object-format=sha1','--template=','repo']);
  run(['--git-dir=repo','index-pack','--stdin','--strict'],b.subarray(range.offset));
  assert.deepEqual(run(['--git-dir=repo','cat-file','commit',f.commitOid]),f.commit);
  assert.deepEqual(run(['--git-dir=repo','cat-file','tree',f.treeOid]),f.tree);
});
test('native and sanitizer source builds are mandatory; absence is FAILURE, never skip', () => {
  const result = buildSource(); assert.equal(result.qualified,false); assert.equal(result.admission,false);
  assert.equal(result.runtime.completeClosure,false); assert(Object.hasOwn(result.artifacts,'host-driver-sanitized'));
});
