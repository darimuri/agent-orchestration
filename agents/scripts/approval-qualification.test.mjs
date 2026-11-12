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
    const r=spawnSync('/usr/bin/git',['-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null','-C',dir,...args],{env,timeout:10000});
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
  const admit=(inherited={},observe=()=>{})=>vm.runInNewContext(admission+'\nsource(target)',{
    fs:facade,path,crypto:{createHash},spawnSync:(bin,args,options)=>{observe(bin,args,options);return spawnSync(bin,args,options);},process:{env:inherited},target:dir,
  },{timeout:10000});
  const snapshot=()=>({config:fs.readFileSync(path.join(dir,'.git/config')),worktreeConfig:fs.existsSync(path.join(dir,'.git/config.worktree'))?fs.readFileSync(path.join(dir,'.git/config.worktree')):null,index:fs.readFileSync(path.join(dir,'.git/index')),files:[ordinary,hostile,'.gitattributes'].filter(p=>fs.existsSync(path.join(dir,p))).map(p=>[p,fs.readFileSync(path.join(dir,p))])});
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
      assert(f.git('ls-files','-v','-z').includes(Buffer.from(tag+' '+file+'\0')));
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
  const before=f.snapshot();assert(f.git('ls-files','-v','-z').includes(Buffer.from('s '+f.hostile+'\0')));
  assert.throws(f.admit,/source index has assume-unchanged or skip-worktree entries/);
  assert.deepEqual(f.snapshot(),before);
});

function markerFixture(t) {
  const f=sourceFixture(t);
  // Separate from source, which the admission fixture projects as read-only.
  const scratch=fs.mkdtempSync(path.join(os.tmpdir(),'qualification-command-'));
  t.after(()=>fs.rmSync(scratch,{recursive:true,force:true}));
  const marker=path.join(scratch,'marker'),helper=path.join(scratch,'helper.sh');
  fs.writeFileSync(helper,'printf executed > "$1"\nprintf "token\\n\\0"\n');
  // Explicit interpreter works even on noexec scratch; prove the marker can fire.
  const control=spawnSync('/bin/sh',[helper,marker]);assert.equal(control.status,0);
  assert.equal(fs.readFileSync(marker,'utf8'),'executed');fs.unlinkSync(marker);
  const command=`/bin/sh ${helper} ${marker}`;
  const reject=()=>{
    const before=f.snapshot(),calls=[];
    assert.throws(()=>f.admit({},(bin,args)=>calls.push({bin,args})),/unsafe or malformed source configuration/);
    assert.equal(fs.existsSync(marker),false,'no config command executed');
    assert.deepEqual(f.snapshot(),before,'config/index/bits/tracked source preserved');
    assert.equal(calls.length,1,'rejected by config audit before any index/status operation');
    assert.equal(calls[0].bin,'/usr/bin/git');
    assert.deepEqual(Array.from(calls[0].args).slice(-5),['config','--local','--no-includes','--null','--list']);
  };
  return {...f,scratch,marker,command,reject};
}
for(const key of ['core.fsmonitor','CoRe.FsMoNiToR','core.hooksPath','core.sshCommand','core.editor','core.pager','sequence.editor','pager.status','alias.status','credential.helper','credential.https://example.invalid.helper','diff.external','diff.evil.command','diff.evil.textconv','difftool.evil.cmd','mergetool.evil.cmd','merge.evil.driver','interactive.diffFilter','core.attributesFile','filter.evil.clean','filter.evil.smudge','filter.evil.process','filter.evil.required']) {
  test(`real-Git rejects command/import config ${key} before marker execution without mutation`,t=>{
    const f=markerFixture(t);f.git('config','--local',key,key==='filter.evil.required'?'true':f.command);f.reject();
  });
}
for(const family of ['clean','process']) {
  test(`real-Git tracked attributes and local filter ${family} reject before helper execution`,t=>{
    const f=markerFixture(t);
    fs.writeFileSync(path.join(f.dir,'.gitattributes'),'*.mjs filter=evil\n');
    f.git('add','--','.gitattributes');
    f.git('-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','--quiet','-m','tracked attributes');
    f.git('config','--local','filter.evil.'+family,f.command);
    f.git('config','--local','filter.evil.required','true');
    f.reject();
  });
}
for(const key of ['include.path','includeIf.gitdir:/.path','InClUdE.path']) {
  test(`real-Git rejects ${key} without following external configuration`,t=>{
    const f=markerFixture(t),external=path.join(f.scratch,'external.config');
    fs.writeFileSync(external,`[core]\n fsmonitor = ${f.command}\n[filter "evil"]\n clean = ${f.command}\n`);
    f.git('config','--local',key,external);const bytes=fs.readFileSync(external);f.reject();
    assert.deepEqual(fs.readFileSync(external),bytes);
    // A malformed included file would abort Git if --no-includes were absent.
    fs.writeFileSync(external,'[invalid included config\n');f.reject();
  });
}
test('real-Git worktree-specific configuration is rejected at enablement',t=>{
  const f=markerFixture(t);f.git('config','--local','extensions.worktreeConfig','true');
  fs.writeFileSync(path.join(f.dir,'.git/config.worktree'),`[CoRe]\n FsMoNiToR = ${f.command}\n[filter "evil"]\n process = ${f.command}\n`);
  f.reject();
});
test('real-Git external system/global/XDG/environment config injection is isolated on every call',t=>{
  const f=markerFixture(t),home=path.join(f.scratch,'home'),xdg=path.join(f.scratch,'xdg');
  fs.mkdirSync(home);fs.mkdirSync(path.join(xdg,'git'),{recursive:true});
  const config=`[core]\n fsmonitor = ${f.command}\n[filter "evil"]\n clean = ${f.command}\n`;
  const system=path.join(f.scratch,'system.config'),global=path.join(f.scratch,'global.config');
  for(const p of [system,global,path.join(home,'.gitconfig'),path.join(xdg,'git/config')])fs.writeFileSync(p,config);
  const inherited={HOME:home,XDG_CONFIG_HOME:xdg,GIT_CONFIG_SYSTEM:system,GIT_CONFIG_GLOBAL:global,GIT_CONFIG_NOSYSTEM:'0',GIT_CONFIG_COUNT:'1',GIT_CONFIG_KEY_0:'core.fsmonitor',GIT_CONFIG_VALUE_0:f.command,GIT_CONFIG_PARAMETERS:`'core.fsmonitor=${f.command}'`,GIT_ATTR_NOSYSTEM:'0',GIT_TERMINAL_PROMPT:'1',GIT_EXEC_PATH:f.scratch};
  const before=f.snapshot(),calls=[];
  const state=f.admit(inherited,(bin,args,options)=>{
    assert.equal(bin,'/usr/bin/git');assert.equal(options.env.GIT_CONFIG_NOSYSTEM,'1');assert.equal(options.env.GIT_CONFIG_GLOBAL,'/dev/null');
    assert.equal(options.env.GIT_ATTR_NOSYSTEM,'1');assert.equal(options.env.GIT_TERMINAL_PROMPT,'0');
    assert.equal(options.env.HOME,'/dev/null');assert.equal(options.env.XDG_CONFIG_HOME,'/dev/null');
    for(const k of ['GIT_CONFIG_SYSTEM','GIT_CONFIG_COUNT','GIT_CONFIG_KEY_0','GIT_CONFIG_VALUE_0','GIT_CONFIG_PARAMETERS','GIT_EXEC_PATH'])assert.equal(Object.hasOwn(options.env,k),false,k);
    for(const control of ['core.fsmonitor=false','core.hooksPath=/dev/null','core.attributesFile=/dev/null'])assert(args.includes(control),control);
    assert(args.includes('--no-pager'));calls.push(args);
  });
  assert.equal(state.commit,f.git('rev-parse','HEAD').toString().trim());assert.equal(calls.length,5);
  assert.equal(fs.existsSync(f.marker),false);assert.deepEqual(f.snapshot(),before);
});
test('real-Git ordinary clone and identity structure remains admissible with hostile config values inert',t=>{
  const f=markerFixture(t);
  for(const [key,value] of [['remote.origin.url','https://example.invalid/source.git'],['remote.origin.fetch','+refs/heads/*:refs/remotes/origin/*'],['branch.main.remote','origin'],['branch.main.merge','refs/heads/main'],['user.name','Fixture\ncore.fsmonitor='+f.command],['user.email','fixture@example.invalid'],['user.useConfigOnly','true']])f.git('config','--local',key,value);
  const before=f.snapshot();f.admit();assert.equal(fs.existsSync(f.marker),false);assert.deepEqual(f.snapshot(),before);
});
test('malformed repository-local config fails closed before any worktree helper',t=>{
  const f=markerFixture(t);fs.appendFileSync(path.join(f.dir,'.git/config'),'\n[invalid syntax\n');
  const config=fs.readFileSync(path.join(f.dir,'.git/config')),index=fs.readFileSync(path.join(f.dir,'.git/index'));
  assert.throws(f.admit,/prerequisite command failed/);assert.equal(fs.existsSync(f.marker),false);
  assert.deepEqual(fs.readFileSync(path.join(f.dir,'.git/config')),config);assert.deepEqual(fs.readFileSync(path.join(f.dir,'.git/index')),index);
  for(const file of [f.ordinary,f.hostile])assert.equal(fs.readFileSync(path.join(f.dir,file),'utf8'),'reviewed bytes\n');
});
