import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { deflateSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { BASE, GATES, refusal, inspect, assessDossier, readBounded, buildSource } from './offline-git-host-acceptance.mjs';
import { fixtureObjects, parseFixtureBundle, checkBatch } from '../tests/offline-git-worker/host-validator.mjs';
import { canonicalBytes, decodeQualificationDossier, assessQualificationDossier, dossierTemplate, contextDigest, PRODUCTION, PREPARATION_FILES, POLICY, PROBE, OBLIGATIONS } from '../offline-git-worker/qualification-dossier.mjs';
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
  assert(Object.hasOwn(result.sources,'agents/offline-git-worker/qualification-dossier.mjs'));
  assert.equal(result.runtime.completeClosure,false); assert(Object.hasOwn(result.artifacts,'host-driver-sanitized'));
});

// Complete contexts below are SYNTHETIC in-memory claims, never intended-host evidence.
const copy = v => JSON.parse(JSON.stringify(v));
function contextFixture() {
  return {production:copy(PRODUCTION), preparation:{commit:'a'.repeat(40),tree:'b'.repeat(40),clean:true,
    files:PREPARATION_FILES.map(path=>({path,sha256:'3'.repeat(64)}))}, probe:copy(PROBE),policy:copy(POLICY),
    host:{scope:'CURRENT_PROCESS_UNQUALIFIED',kernelRelease:'fixture-kernel',kernelBuildSha256:'4'.repeat(64),kernelConfigSha256:'5'.repeat(64),
      arch:'x64',uidMapSha256:'6'.repeat(64),gidMapSha256:'7'.repeat(64),cgroupSha256:'8'.repeat(64),
      namespaces:Object.fromEntries(['ipc','mnt','net','pid','user','uts'].map(k=>[k,`${k}:[123]`]))}};
}
function v2() {
  const c=contextFixture();
  const accounting={parallelism:1,quotaSlackUs:10000,maxRunnableUs:40000000,terminationBoundUs:2000000,trustedCpuUs:500000,uncertaintyUs:100000};
  return {version:2,expected:c,claimed:copy(c),accounting,evidence:OBLIGATIONS.map(obligation=>({obligation,
    expectedContextSha256:contextDigest(c),evidenceSha256:'9'.repeat(64),evidenceId:'self-claim',provenance:'SOURCE_CLAIM'}))};
}
const assessV2 = (v,observed=contextFixture()) => assessQualificationDossier(canonicalBytes(v),observed);
function neverAdmits(r) { assert.equal(r.status,'UNKNOWN'); assert.equal(r.admission,false); assert.equal(r.qualified,false); assert.equal(r.assumptionsVerified,false); }
test('v2 literal canonical all-missing golden is bounded, deterministic and nonadmitting', () => {
  const literal='{"accounting":{"maxRunnableUs":null,"parallelism":null,"quotaSlackUs":null,"terminationBoundUs":null,"trustedCpuUs":null,"uncertaintyUs":null},"claimed":null,"evidence":[],"expected":null,"version":2}';
  assert.equal(canonicalBytes(dossierTemplate()).toString(),literal);
  const r=assessQualificationDossier(Buffer.from(literal)); neverAdmits(r);
  assert.equal(r.dossierSha256,'c514f77c94405b25f0ce7f17c34b91fa3d42d5c34da53ae233032ec743180529');
  assert.equal(r.identityMatches,'UNKNOWN'); assert.equal(r.arithmeticWithinCeiling,'UNKNOWN');
  assert(r.obligations.every(o=>o.state==='MISSING')); assert.equal(r.handoff,'MISSING_PRIVILEGED_OBSERVATION');
});
test('v2 forged feasible and self-reviewed complete envelopes never establish proof or freshness', () => {
  for (const provenance of ['SOURCE_CLAIM','NONROOT_OBSERVATION','OWNER_OBSERVATION','INDEPENDENT_REVIEW_REFERENCE']) {
    const v=v2(); v.evidence.forEach(e=>e.provenance=provenance);
    const r=assessV2(v); neverAdmits(r); assert.equal(r.identityMatches,true);
    assert.equal(r.workerUpperUs,'8430000'); assert.equal(r.aggregateUpperUs,'9030000'); assert.equal(r.arithmeticWithinCeiling,true);
    assert(r.obligations.every(o=>o.state===(['SOURCE_CLAIM','NONROOT_OBSERVATION'].includes(provenance)?'CLAIM_ONLY':'REQUIRES_INDEPENDENT_REVIEW')));
    assert.equal(r.handoff,'PREVENTIVE_BOUND_UNSUPPORTED'); assert(r.unprovedTerms.every(t=>!t.proven));
    assert.equal(r.provenanceVerified,false); assert.equal(r.freshness,'UNVERIFIED');
    assert.deepEqual(assessV2(v),r); // repeated matching bytes cannot authenticate freshness
  }
});
test('v2 canonical decoder rejects duplicate, unknown, malformed UTF8, numeric/escape aliases and trailing bytes', () => {
  const good=canonicalBytes(dossierTemplate());
  for (const b of [Buffer.from(good.toString().replace('"version":2','"version":2,"version":2')),
    Buffer.from(good.toString().replace('"version":2','"version":2e0')),
    Buffer.from(good.toString().replace('"version":2','"version":-0')),
    Buffer.from(good.toString().replace('version','\\u0076ersion')),
    Buffer.concat([good,Buffer.from('\n')]),Buffer.concat([Buffer.from([0xff]),good]),
    Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),good]),good.subarray(0,-1),Buffer.alloc(16385),Buffer.from('['.repeat(1000))])
    assert.throws(()=>decodeQualificationDossier(b));
  for (const update of [{version:3},{extra:true},{evidence:{}},{accounting:{}}])
    assert.throws(()=>decodeQualificationDossier(canonicalBytes({...dossierTemplate(),...update})));
  const v=v2(); v.expected.host.extra=true; assert.throws(()=>decodeQualificationDossier(canonicalBytes(v)));
  let touched=0; assert.throws(()=>canonicalBytes({get version(){touched++;return 2;}})); assert.equal(touched,0);
  assert.throws(()=>canonicalBytes(new Proxy({},{}))); assert.throws(()=>canonicalBytes({v:'\ud800'}));
});
test('v2 exact evidence schema enforces sixteen records, 512 bytes, plain identifiers and known enums', () => {
  const v=v2();
  for (const update of [{obligation:'customProof'},{provenance:'PROVEN'},{evidenceSha256:null},{evidenceSha256:'0'.repeat(64)},
    {evidenceId:'https://example.invalid/proof'},{extra:'x'},{evidenceId:'x'.repeat(256),provenance:'INDEPENDENT_REVIEW_REFERENCE'}]) {
    const b=copy(v); b.evidence[0]={...b.evidence[0],...update}; assert.throws(()=>decodeQualificationDossier(canonicalBytes(b)));
  }
  const repeated=copy(v); repeated.evidence.push(copy(repeated.evidence[0])); assert.throws(()=>decodeQualificationDossier(canonicalBytes(repeated)));
  const boundary=copy(v); boundary.evidence[0].provenance='INDEPENDENT_REVIEW_REFERENCE';
  const empty={...boundary.evidence[0],evidenceId:''};
  boundary.evidence[0].evidenceId='x'.repeat(512-canonicalBytes(empty).length);
  assert.equal(canonicalBytes(boundary.evidence[0]).length,512); decodeQualificationDossier(canonicalBytes(boundary));
  boundary.evidence[0].evidenceId+='x'; assert.throws(()=>decodeQualificationDossier(canonicalBytes(boundary)));
  const full=copy(v); full.evidence=Array.from({length:16},(_,i)=>({...v.evidence[i%7],evidenceId:'case-'+i}));
  assert.equal(decodeQualificationDossier(canonicalBytes(full)).evidence.length,16);
  full.evidence.push({...v.evidence[0],evidenceId:'case-17'}); assert.throws(()=>decodeQualificationDossier(canonicalBytes(full)));
});
test('v2 production/preparation/probe/kernel/maps/namespaces and cgroup mismatches are explicit blockers', () => {
  const edits=[c=>c.production.commit='f'.repeat(40),c=>c.production.tree='f'.repeat(40),c=>c.production.files[0].sha256='f'.repeat(64),
    c=>c.preparation.commit='f'.repeat(40),c=>c.preparation.tree='f'.repeat(40),c=>c.preparation.files[0].sha256='f'.repeat(64),
    c=>c.preparation.clean=false,c=>c.probe.sha256='f'.repeat(64),c=>c.probe.version=3,
    c=>c.host.kernelRelease='other',c=>c.host.kernelBuildSha256='f'.repeat(64),c=>c.host.kernelConfigSha256='f'.repeat(64),
    c=>c.host.uidMapSha256='f'.repeat(64),c=>c.host.gidMapSha256='f'.repeat(64),c=>c.host.namespaces.mnt='mnt:[124]',
    c=>c.host.cgroupSha256='f'.repeat(64),c=>c.host.arch='arm64',c=>c.policy.pids=9,c=>c.policy.quotaUs=20001];
  for (const edit of edits) { const v=v2(); edit(v.claimed); const r=assessV2(v); neverAdmits(r);
    assert.equal(r.identityMatches,false); assert(r.blockers.length>0); assert(r.obligations.some(o=>o.state==='CONTRADICTED')); }
  const v=v2(); v.expected.production.commit=v.expected.preparation.commit;
  v.claimed=copy(v.expected); const r=assessV2(v,copy(v.expected)); assert.equal(r.identityMatches,false);
  const b=v2(); b.claimed.preparation.files[0].path='arbitrary/path'; assert.throws(()=>decodeQualificationDossier(canonicalBytes(b)));
});
test('v2 missing context remains UNKNOWN and container-to-host promotion contradicts even matching claims', () => {
  const v=v2(); v.expected.host.kernelBuildSha256=null; v.claimed=copy(v.expected);
  v.evidence.forEach(e=>e.expectedContextSha256=contextDigest(v.expected));
  let r=assessV2(v,copy(v.expected)); neverAdmits(r); assert.equal(r.identityMatches,'UNKNOWN'); assert(r.missing.length);
  const promoted=v2(); promoted.expected.host.scope='INTENDED_HOST_CLAIM'; promoted.claimed=copy(promoted.expected);
  promoted.evidence.forEach(e=>e.expectedContextSha256=contextDigest(promoted.expected));
  r=assessV2(promoted,copy(promoted.expected)); neverAdmits(r); assert.equal(r.identityMatches,false);
  assert(r.blockers.includes('container_or_current_process_cannot_be_promoted_to_intended_host'));
});
test('v2 absence, claims, stale context references and over-ceiling contradictions remain distinct', () => {
  const v=v2(); v.evidence=[]; let r=assessV2(v); assert(r.obligations.every(o=>o.state==='MISSING'));
  v.evidence=copy(v2().evidence); v.evidence[0].expectedContextSha256='e'.repeat(64);
  r=assessV2(v); assert.equal(r.obligations[0].state,'CONTRADICTED'); assert(r.blockers.includes('evidence_context.kernelQuotaBound'));
  for (const term of ['quotaSlackUs','maxRunnableUs','terminationBoundUs','trustedCpuUs','uncertaintyUs']) {
    const missing=v2(); missing.accounting[term]=null; r=assessV2(missing); neverAdmits(r);
    assert.equal(r.arithmeticWithinCeiling,'UNKNOWN'); assert(r.missing.includes('accounting.'+term));
  }
  const complete=v2(); complete.expected.host=null; complete.claimed.host=null;
  complete.evidence.forEach(e=>e.expectedContextSha256=contextDigest(complete.expected));
  assert.equal(assessV2(complete).identityMatches,'UNKNOWN');
});
test('v2 literal threshold/+1, quota rounding, parallelism and safe integer extremes', () => {
  const v=v2(); v.accounting.trustedCpuUs=1470000;
  let r=assessV2(v); assert.equal(r.aggregateUpperUs,'10000000'); assert.equal(r.arithmeticWithinCeiling,true); neverAdmits(r);
  v.accounting.trustedCpuUs++; r=assessV2(v); assert.equal(r.aggregateUpperUs,'10000001'); assert.equal(r.arithmeticWithinCeiling,false);
  assert(r.blockers.includes('aggregate_cpu_ceiling_exceeded'));
  const parallel=v2(); parallel.accounting.parallelism=8; assert.equal(assessV2(parallel).workerUpperUs,'8500000');
  const round=v2(); round.accounting.maxRunnableUs=40000001; assert.equal(assessV2(round).workerUpperUs,'8450000');
  round.accounting.maxRunnableUs=40099999; assert.equal(assessV2(round).workerUpperUs,'8450000');
  round.accounting.maxRunnableUs=40100000; assert.equal(assessV2(round).workerUpperUs,'8450000');
  for (const [term,value] of [['parallelism',0],['parallelism',9],['maxRunnableUs',39999999],['terminationBoundUs',1999999],['trustedCpuUs',0],['uncertaintyUs',0]]) {
    const bad=v2(); bad.accounting[term]=value; r=assessV2(bad); neverAdmits(r); assert(r.blockers.includes('accounting.'+term));
  }
  const huge=v2(); huge.accounting.maxRunnableUs=Number.MAX_SAFE_INTEGER; assert.equal(assessV2(huge).arithmeticWithinCeiling,false);
  for (const value of [Number.MAX_SAFE_INTEGER+1,-1,0.5,Infinity]) { const bad=v2(); bad.accounting.quotaSlackUs=value; assert.throws(()=>canonicalBytes(bad)); }
});
test('v2 probe inventory includes new module; production/native bytes are unchanged', () => {
  const r=inspect(); assert(Object.hasOwn(r.sourceFiles,'agents/offline-git-worker/qualification-dossier.mjs'));
  assert.equal(r.dossierContext.production.commit,BASE); assert.deepEqual(r.probeContract.template,dossierTemplate());
  for (const f of PRODUCTION.files) assert.equal(r.sourceFiles[f.path].sha256,f.sha256);
  for (const name of ['host-entry.c','host-driver.c','host-validator.mjs']) {
    const file='agents/tests/offline-git-worker/'+name;
    const original=spawnSync('/usr/bin/git',['show','f41325db78c87545f454212ad16187c7fbff76c8:'+file],{env:{},maxBuffer:1048576});
    assert.equal(original.status,0); assert.deepEqual(fs.readFileSync(new URL('../tests/offline-git-worker/'+name,import.meta.url)),original.stdout);
  }
});
test('actual v2 CLI refuses complete self-claims, 16KiB overflow, and endless stdin within deadline', async () => {
  const v=v2(); const call=spawnSync(process.execPath,[script,'dossier'],{input:canonicalBytes(v),env:{},encoding:'utf8',timeout:5000});
  assert.equal(call.status,2); neverAdmits(JSON.parse(call.stdout));
  const oversized=Buffer.concat([canonicalBytes(v),Buffer.alloc(16385-canonicalBytes(v).length,32)]);
  const denied=spawnSync(process.execPath,[script,'dossier'],{input:oversized,env:{},encoding:'utf8',timeout:5000});
  assert.equal(denied.status,2); assert.equal(JSON.parse(denied.stderr).admission,false);
  const child=spawn(process.execPath,[script,'dossier'],{env:{},stdio:['pipe','pipe','pipe']});
  child.stdin.on('error',()=>{}); child.stdin.write('{\"version\":2,'); child.stdout.resume(); let error=''; child.stderr.on('data',b=>error+=b);
  const start=performance.now();
  const result=await new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{child.kill();reject(Error('stdin deadline did not close'));},4500);
    child.on('error',e=>{clearTimeout(timer);reject(e);}); child.on('close',code=>{clearTimeout(timer);resolve(code);});
  });
  assert.equal(result,2); assert(performance.now()-start<4000); assert.equal(JSON.parse(error).admission,false);
});
test('synthetic root and non-Linux caller shapes refuse inspection without privileged execution', () => {
  for (const change of ["process.getuid=()=>0;process.geteuid=()=>0;", "Object.defineProperty(process,'platform',{value:'darwin'});"]) {
    const source=change+`const m=await import(${JSON.stringify(new URL('./offline-git-host-acceptance.mjs',import.meta.url).href)});try{m.inspect();process.exitCode=1}catch{process.exitCode=0}`;
    const r=spawnSync(process.execPath,['--input-type=module','-e',source],{env:{},encoding:'utf8',timeout:5000}); assert.equal(r.status,0,r.stderr);
  }
});
