import test from 'node:test';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const script=fileURLToPath(new URL('./qualify-host-approval.sh',import.meta.url));
const recipe=fileURLToPath(new URL('../tests/job-preparation/Dockerfile.approval-qualification',import.meta.url));
const template=JSON.parse(fs.readFileSync(new URL('../tests/job-preparation/qualification-inputs.json',import.meta.url),'utf8'));
// Deliberately synthetic values, never release/admission evidence.
function fixture(t) {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'qualification-inputs-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const archive=path.join(dir,'archive'),lockPath=path.join(dir,'inputs.json');fs.writeFileSync(archive,'synthetic archive bytes');
  const digest=createHash('sha256').update(fs.readFileSync(archive)).digest('hex');
  const lock={...template,nodeVersion:'26.0.0',nodeSourceSha256:digest,builderImage:'example.invalid/builder@sha256:'+'a'.repeat(64),platform:'linux/amd64',packages:{synthetic:'1'},gccVersion:'13.2.0',approval:{advisory:'SYNTHETIC TEST ONLY',sourceUrl:'https://nodejs.org/dist/v26.0.0/node-v26.0.0.tar.xz',signedChecksumEvidence:'SYNTHETIC',signer:'SYNTHETIC'}};
  const env={PATH:process.env.PATH,NODE_VERSION:lock.nodeVersion,NODE_SOURCE_SHA256:digest};
  const run=(mode='plan',extra=[])=>{fs.writeFileSync(lockPath,JSON.stringify(lock));return spawnSync('/bin/bash',[script,mode,lockPath,archive,...extra],{env,encoding:'utf8',timeout:10000});};
  return {dir,archive,lock,env,run};
}
test('qualification plan requires reviewed explicit release inputs and verifies archive before work',t=>{
  const f=fixture(t);let r=f.run();assert.equal(r.status,0,r.stderr);
  const plan=JSON.parse(r.stdout);assert.equal(plan.sourceMount,'read-only');assert.equal(plan.outputMount,'separate writable');
  assert.equal(plan.compiler,'/usr/bin/cc');assert.equal(plan.cxx,'/usr/bin/g++');assert.equal(plan.network,'none');
  assert.deepEqual(plan.gates.map(g=>g.name),['production','strict37','asan37','full-package']);
  assert.deepEqual(plan.diagnostics,['clock-regression','minimal Node-API Promise control']);
  for(const key of ['NODE_VERSION','NODE_SOURCE_SHA256']) {
    const value=f.env[key];for(const bad of [undefined,'',' ','latest','$(false)']){if(bad===undefined)delete f.env[key];else f.env[key]=bad;r=f.run();assert.notEqual(r.status,0);assert.match(r.stderr,/mandatory explicit/);}f.env[key]=value;
  }
  fs.writeFileSync(f.archive,'different');r=f.run();assert.notEqual(r.status,0);assert.match(r.stderr,/source archive hash mismatch/);
});
test('non-executable input template and mismatched/unpinned approval locks fail closed',t=>{
  const f=fixture(t);
  for(const [key,bad,pattern] of [['nodeVersion','26.1.0',/release inputs mismatch/],['nodeSourceSha256','0'.repeat(64),/release inputs mismatch/],['approval',null,/release approval missing/],['builderImage','ubuntu:latest',/digest-pinned/],['platform','linux/unknown',/locked platform/],['packages',{},/package lock/],['gccVersion','',/GCC version/],['target',{commit:'bad',tree:'bad'},/immutable target/]]){
    const old=f.lock[key];f.lock[key]=bad;const r=f.run();assert.notEqual(r.status,0);assert.match(r.stderr,pattern);f.lock[key]=old;
  }
  Object.assign(f.lock,template);const r=f.run();assert.notEqual(r.status,0);assert.match(r.stderr,/release inputs mismatch/);
});
test('inherited sanitizer/compiler controls are rejected, never repaired or retried',t=>{
  const f=fixture(t);for(const key of ['ASAN_OPTIONS','LSAN_OPTIONS','UBSAN_OPTIONS','LD_PRELOAD','LD_LIBRARY_PATH','NODE_OPTIONS','CC','CXX','CFLAGS','CXXFLAGS','LDFLAGS']){
    // Empty still means supplied. No dynamic loader injection during this test.
    f.env[key]='';const r=f.run();assert.notEqual(r.status,0,key);assert.match(r.stderr,/forbidden inherited control/);delete f.env[key];
  }
});
test('writable source checkout is rejected without a probe write or toolchain build',t=>{
  const f=fixture(t);const before=fs.readdirSync(f.dir);const r=f.run('verify-source',[f.dir]);
  assert.notEqual(r.status,0);assert.match(r.stderr,/source must be mounted read-only/);assert.deepEqual(fs.readdirSync(f.dir).filter(p=>p!=='inputs.json'),before.filter(p=>p!=='inputs.json'));
});
test('builder identity/platform mismatch fails before package/toolchain work',t=>{
  const f=fixture(t);const r=f.run('build-runtime');assert.notEqual(r.status,0);assert.match(r.stderr,/builder\/platform mismatch/);
});
test('recipe and harness preserve fixed native toolchain, diagnostics and durable evidence contracts',()=>{
  const sh=fs.readFileSync(script,'utf8'),docker=fs.readFileSync(recipe,'utf8');
  assert.match(docker,/ARG BUILDER_IMAGE\nFROM \$\{BUILDER_IMAGE\}/);assert.match(docker,/RUN --network=none/);assert.match(docker,/USER 10001:10001/);
  assert(!/apt-get|curl |wget |ADD https?:|docker\.sock/.test(docker));
  for(const word of ["exec(driver,['-dumpfullversion'])!==lock.gccVersion","inventory differs from reviewed lock","'-print-file-name='+name","['libasan.so','libubsan.so']","'/usr/bin/cc'","CC:'/usr/bin/cc',CXX:'/usr/bin/g++',LINK:'/usr/bin/g++'","'--enable-asan'","runtime.asan!==(variant==='asan'?1:0)","headers mismatch","sanitizer linkage mismatch"]) assert(sh.includes(word),word);
  for(const word of ["target:targetState,infrastructure:infraState","result.json","name+'.log'","entry.sha256=hash(logPath)","entry.totals","clock-regression","host-approval-service-worker.mjs","napi_create_promise","napi_resolve_deferred","n.control(","PROMISE_CONTROL_SETTLED_OR_ABANDONED","napi_reject_deferred","['resolve','reject','abandon']","PENDING_INDEPENDENT_REVIEW","liveAcceptance:'NOT_READY'"]) assert(sh.includes(word),word);
  assert(!/detect_leaks=0|verify_asan_link_order|suppressions=|--without-snapshot|clang\+\+|LD_PRELOAD\s*[:=]/.test(sh));
  assert(!/\.replace\(.*host-approval|git.*(?:reset|checkout)|chmod.*target/.test(sh));
  // Failures remain failures; there is exactly one dispatch per declared gate.
  assert.match(sh,/for\(const gate of gates\)/);assert.match(sh,/failed\|\|=|failed \|\|=/);
});
test('admission failure retains a machine-readable blocker in fresh output',t=>{
  const f=fixture(t),output=path.join(f.dir,'output');fs.mkdirSync(output,{mode:0o700});
  f.env.NODE_SOURCE_SHA256='';const r=f.run('run',[path.join(f.dir,'target'),path.join(f.dir,'infra'),output]);
  assert.notEqual(r.status,0);const result=JSON.parse(fs.readFileSync(path.join(output,'result.json'),'utf8'));
  assert.equal(result.status,'BLOCKED');assert.match(result.blocker,/mandatory explicit NODE_SOURCE_SHA256/);assert.equal(result.liveAcceptance,'NOT_READY');assert.deepEqual(result.gates,[]);
  const retained=fs.readFileSync(path.join(output,'result.json'),'utf8');f.run('run',[path.join(f.dir,'target'),path.join(f.dir,'infra'),output]);assert.equal(fs.readFileSync(path.join(output,'result.json'),'utf8'),retained);
});

// Execute the verbatim admission functions with real /usr/bin/git. Only the
// read-only mountinfo prerequisite is a bounded facade; no native/Docker run.
function sourceFixture(t) {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'qualification-index-'));
  t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const env={PATH:'/usr/bin:/bin',LANG:'C',LC_ALL:'C',GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null',GIT_OPTIONAL_LOCKS:'0'};
  const git=(...args)=>{
    const r=spawnSync('/usr/bin/git',['-C',dir,...args],{env,timeout:10000});
    assert.ifError(r.error);assert.equal(r.status,0,r.stderr.toString());return r.stdout;
  };
  git('init','--quiet');
  const ordinary='gate.mjs',hostile='- space\nS fake\t雪.mjs';
  for(const file of [ordinary,hostile]) fs.writeFileSync(path.join(dir,file),'reviewed bytes\n');
  git('add','--',ordinary,hostile);
  git('-c','user.name=Synthetic Qualification Fixture','-c','user.email=fixture@example.invalid','-c','core.hooksPath=/dev/null','commit','--quiet','-m','synthetic source');
  const sh=fs.readFileSync(script,'utf8');
  const admission=sh.slice(sh.indexOf('const fail ='),sh.indexOf('const gates ='));
  assert(admission.startsWith('const fail =') && admission.includes('function source(p)'));
  const facade={...fs,readFileSync:(p,...args)=>p==='/proc/self/mountinfo'
    ? `1 0 0:1 / ${dir} ro - synthetic synthetic ro\n`
    : fs.readFileSync(p,...args)};
  const admit=()=>vm.runInNewContext(admission+'\nsource(target)',{
    fs:facade,path,crypto:{createHash},spawnSync,process:{env:{}},target:dir,
  },{timeout:10000});
  const snapshot=()=>({index:fs.readFileSync(path.join(dir,'.git/index')),tags:git('ls-files','-v','-z'),files:[ordinary,hostile].map(p=>fs.readFileSync(path.join(dir,p)))});
  return {dir,git,ordinary,hostile,admit,snapshot};
}
test('real-Git ordinary clean index admits exact identity without rewriting state',t=>{
  const f=sourceFixture(t),before=f.snapshot(),state=f.admit();
  assert.equal(state.commit,f.git('rev-parse','HEAD').toString().trim());
  assert.equal(state.tree,f.git('rev-parse','HEAD^{tree}').toString().trim());
  assert.deepEqual(f.snapshot(),before);
});
for(const flag of ['assume-unchanged','skip-worktree']) {
  for(const special of [false,true]) {
    test(`real-Git ${flag} hidden edit rejects unchanged index/source (${special?'hostile filename':'ordinary filename'})`,t=>{
      const f=sourceFixture(t),file=special?f.hostile:f.ordinary;
      f.git('update-index','--'+flag,'--',file);
      fs.writeFileSync(path.join(f.dir,file),'altered unreviewed bytes\n');
      // Reproduce the defect: status and locked identities still look clean.
      assert.equal(f.git('status','--porcelain','--untracked-files=all').length,0);
      const identity=f.git('rev-parse','HEAD','HEAD^{tree}'),before=f.snapshot();
      const tag=flag==='assume-unchanged'?'h':'S';
      assert(before.tags.includes(Buffer.from(tag+' '+file+'\0')));
      assert.throws(f.admit,/source index has assume-unchanged or skip-worktree entries/);
      assert.deepEqual(f.snapshot(),before);
      assert.deepEqual(f.git('rev-parse','HEAD','HEAD^{tree}'),identity);
    });
  }
}
test('real-Git combined index bits reject and remain set even without an edit',t=>{
  const f=sourceFixture(t);
  f.git('update-index','--assume-unchanged','--',f.hostile);
  f.git('update-index','--skip-worktree','--',f.hostile);
  const before=f.snapshot();assert(before.tags.includes(Buffer.from('s '+f.hostile+'\0')));
  assert.throws(f.admit,/source index has assume-unchanged or skip-worktree entries/);
  assert.deepEqual(f.snapshot(),before);
});
