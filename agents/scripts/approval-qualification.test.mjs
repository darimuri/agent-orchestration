import test from 'node:test';
import vm from 'node:vm';
import { EventEmitter } from 'node:events';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync, spawn } from 'node:child_process';
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

// Pure contracts are loaded verbatim; no production path/binary override exists.
function diagnosticFunctions(extra={}) {
  const sh=fs.readFileSync(script,'utf8'),code=sh.slice(sh.indexOf('// Explicit diagnostic only:'),sh.indexOf('async function main()'));
  return vm.runInNewContext(code+'\n({diagnosticText,diagnosticEvidence,diagnosticEvidenceCheck,diagnosticTokens,diagnosticResponse,diagnosticObjectReference,diagnosticOutcome,diagnosticFamily,diagnosticProbe,diagnose,diagnosticFlags,comdatHeader,comdatMain})',{
    fs,path,Buffer,setTimeout,clearTimeout,crypto:{createHash},hash:p=>createHash('sha256').update(fs.readFileSync(p)).digest('hex'),fail:m=>{throw Error(m);},fixed:{PATH:'/usr/bin:/bin'},process:{env:{},getuid:()=>process.getuid()},spawn,...extra,
  });
}
const diagnosticResult=(code=0,stdout='',stderr='')=>({code,stdout,stderr,signal:null,error:undefined,timedOut:false,bounded:false});
test('diagnostic controls reject sanitizer silence, clean findings, unexpected exit/signal and resource bounds',()=>{
  const d=diagnosticFunctions();
  d.diagnosticOutcome('clean',diagnosticResult(0,'COMDAT_CLEAN'));
  d.diagnosticOutcome('asan',diagnosticResult(1,'','ERROR: AddressSanitizer: heap-buffer-overflow'));
  d.diagnosticOutcome('ubsan',diagnosticResult(1,'','runtime error: signed integer overflow'));
  for(const [label,r] of [['asan',diagnosticResult()],['ubsan',diagnosticResult()],['asan',diagnosticResult(2,'','ERROR: AddressSanitizer: heap-buffer-overflow')],['clean',diagnosticResult(0,'COMDAT_CLEAN','LeakSanitizer finding')],['clean',diagnosticResult(3)],['clean',diagnosticResult(0,'wrong')]])assert.throws(()=>d.diagnosticOutcome(label,r));
  for(const extra of [{signal:'SIGKILL'},{error:'ENOENT'},{timedOut:true},{bounded:true}])assert.throws(()=>d.diagnosticOutcome('clean',{...diagnosticResult(0,'COMDAT_CLEAN'),...extra}),/terminated/);
});
test('diagnostic identity rejects compiler/version/architecture and sanitizer path or digest mismatches',()=>{
  const d=diagnosticFunctions({fs:{...fs,realpathSync:p=>p}}),runtime={path:'/fixed/libasan.so',sha256:'a'.repeat(64)},base={cc1plus:{path:'/fixed/cc1plus',sha256:'c'.repeat(64)},collect2:{path:'/fixed/collect2',sha256:'d'.repeat(64)},version:'13.3.0',machine:'x86_64-linux-gnu','libasan.so':runtime,'libubsan.so':{...runtime,path:'/fixed/libubsan.so'},'libstdc++.so':{...runtime,path:'/fixed/libstdc++.so'},'libgcc_s.so.1':{...runtime,path:'/fixed/libgcc_s.so.1'}};
  d.diagnosticFamily({gccVersion:'13.3.0',platform:'linux/amd64'},[base,base]);
  for(const changed of [{version:'19.1.0'},{version:'broken'},{machine:'aarch64-linux-gnu'},{'libasan.so':{...runtime,path:'/mixed/libasan.so'}},{'libasan.so':{...runtime,sha256:'b'.repeat(64)}},{'libubsan.so':null}])assert.throws(()=>d.diagnosticFamily({gccVersion:'13.3.0',platform:'linux/amd64'},[base,{...base,...changed}]));
});
test('diagnostic response parsing is bounded data-only and rejects malformed, nested or shell-like tokens',()=>{
  const d=diagnosticFunctions();assert.equal(Array.from(d.diagnosticResponse('left.o\nright.o -o mksnapshot')).join('|'),'left.o|right.o|-o|mksnapshot');
  for(const bad of ['',"'unterminated",'@nested.rsp','$(touch marker)','left.o;false','"space file.o"','x'.repeat(65537),'bad\0token'])assert.throws(()=>d.diagnosticResponse(bad),/malformed|nested/);
  for(const bad of [null,[],['a\nb'],new Array(4097).fill('x')])assert.throws(()=>d.diagnosticTokens(bad),/malformed/);
});
test('diagnostic evidence files reject missing/nonregular/symlink/NUL/oversize without modification',t=>{
  const f=fixture(t),d=diagnosticFunctions(),p=path.join(f.dir,'evidence');fs.writeFileSync(p,'abc');assert.equal(d.diagnosticText(p,3),'abc');
  assert.throws(()=>d.diagnosticText(p,2),/bound/);assert.equal(fs.readFileSync(p,'utf8'),'abc');
  const link=path.join(f.dir,'link');fs.symlinkSync(p,link);assert.throws(()=>d.diagnosticText(link,10),/unavailable/);
  assert.throws(()=>d.diagnosticText(f.dir,10),/unavailable/);assert.throws(()=>d.diagnosticText(p+'-missing',10));
  fs.writeFileSync(p,'a\0b');assert.throws(()=>d.diagnosticText(p,10),/malformed/);
});
test('explicit diagnostic profile and builder failures retain separate blockers without overwriting prior evidence',t=>{
  const f=fixture(t),output=path.join(f.dir,'diagnostic-output');fs.mkdirSync(output,{mode:0o700});
  let r=f.run('diagnose-toolchain',[path.join(f.dir,'failed'),path.join(f.dir,'infra'),output]);assert.notEqual(r.status,0);
  const resultPath=path.join(output,'diagnostic.json'),bytes=fs.readFileSync(resultPath),result=JSON.parse(bytes);
  assert.equal(result.status,'BLOCKED');assert.match(result.blocker,/DIAGNOSTIC_PROFILE/);assert.match(result.scope,/no Node\/V8 compatibility/);assert.equal(result.reportedFailure.R1,'INCOMPLETE');assert.equal(result.liveAcceptance,'NOT_READY');
  f.run('diagnose-toolchain',[path.join(f.dir,'failed'),path.join(f.dir,'infra'),output]);assert.deepEqual(fs.readFileSync(resultPath),bytes);
  const next=path.join(f.dir,'next');fs.mkdirSync(next,{mode:0o700});f.env.DIAGNOSTIC_PROFILE='gcc-comdat-v1';
  r=f.run('diagnose-toolchain',[path.join(f.dir,'failed'),path.join(f.dir,'infra'),next]);assert.notEqual(r.status,0);assert.match(JSON.parse(fs.readFileSync(path.join(next,'diagnostic.json'))).blocker,/builder\/platform/);
});
test('missing diagnostic tool creates BLOCKED evidence and never invokes a compiler/build fallback',async t=>{
  const f=fixture(t),output=path.join(f.dir,'missing-tool');fs.mkdirSync(output,{mode:0o700});
  const proc={env:{DIAGNOSTIC_PROFILE:'gcc-comdat-v1',BUILDER_IMAGE:'example.invalid/builder@sha256:b2ed7cea3b936b4054afd8157944dffc0110ae61988b3644716ddaef5214ed31',QUALIFICATION_PLATFORM:f.lock.platform},getuid:()=>process.getuid()};
  const d=diagnosticFunctions({process:proc,output,target:path.join(f.dir,'failed'),infrastructure:path.join(f.dir,'infra'),lockPath:f.archive,archive:f.archive,source:()=>({commit:'synthetic',tree:'synthetic'}),readonly:()=>{},hash:p=>p===f.archive?'0dbfd0064f4afbd32ceef751d3d1b75685f8a511cd50d394b21232d02ff29307':'a'.repeat(64),toolchain:()=>{throw Error('missing diagnostic tool /usr/bin/cc');},spawn:()=>{assert.fail('compiler must not execute');}});
  await d.diagnose({...f.lock,gccVersion:'13.3.0',nodeSourceSha256:'a7f6204ff63b6a2cd274d48903285abb86ed53a99070e532d4c2fd787457d9e6',builderImage:'example.invalid/builder@sha256:b2ed7cea3b936b4054afd8157944dffc0110ae61988b3644716ddaef5214ed31'});const result=JSON.parse(fs.readFileSync(path.join(output,'diagnostic.json')));
  assert.equal(result.status,'BLOCKED');assert.match(result.blocker,/missing diagnostic tool/);assert.equal(result.commands.length,0);
});
test('MANDATORY real GCC multi-TU COMDAT/ASan/UBSan diagnostic fixture',async t=>{
  const prerequisites=['/usr/bin/cc','/usr/bin/g++','/usr/bin/as','/usr/bin/ld','/usr/bin/readelf','/usr/bin/objdump','/usr/bin/ldd'];
  const missing=prerequisites.filter(p=>!fs.existsSync(p));assert.equal(missing.length,0,'BLOCKED diagnostic compiler/binutils prerequisites: '+missing.join(', '));
  const d=diagnosticFunctions(),dir=fs.mkdtempSync(path.join(process.env.TEST_EXECUTABLE_TMPDIR||os.tmpdir(),'comdat-real-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const env={PATH:'/usr/bin:/bin',LANG:'C',LC_ALL:'C',ASAN_OPTIONS:'detect_leaks=1:halt_on_error=1',UBSAN_OPTIONS:'halt_on_error=1:print_stacktrace=1'};
  const run=(bin,args,label)=>{const r=spawnSync(bin,args,{cwd:dir,env,encoding:'utf8',timeout:20000,maxBuffer:2*1024*1024});d.diagnosticOutcome(label,{...r,code:r.status,timedOut:r.error?.code==='ETIMEDOUT',bounded:r.error?.code==='ENOBUFS'});return r.stdout;};
  const identities=['/usr/bin/cc','/usr/bin/g++'].map(driver=>{
    const version=run(driver,['-dumpfullversion'],'version').trim(),machine=run(driver,['-dumpmachine'],'machine').trim();
    const item={version,machine};for(const helper of ['cc1plus','collect2']){const real=fs.realpathSync(run(driver,['-print-prog-name='+helper],'helper').trim());item[helper]={path:real,sha256:createHash('sha256').update(fs.readFileSync(real)).digest('hex')};}for(const library of ['libasan.so','libubsan.so','libstdc++.so','libgcc_s.so.1']){const p=run(driver,['-print-file-name='+library],'library').trim();assert(path.isAbsolute(p));const real=fs.realpathSync(p);item[library]={path:real,sha256:createHash('sha256').update(fs.readFileSync(real)).digest('hex')};}return item;
  });
  d.diagnosticFamily({gccVersion:'13.3.0',platform:'linux/amd64'},identities);
  await d.diagnosticProbe(async(label,bin,args,expected=label)=>run(bin,Array.from(args),expected).trim(),(name,text)=>fs.writeFileSync(path.join(dir,name),text,{flag:'wx'}),dir,identities);
});

// Full diagnostic state-machine fixture. Binaries/tool inventory/read-only mounts
// are explicit facades here; emitted compiler/ELF text is synthetic, not native PASS.
async function syntheticDiagnostic(t,variant,linkEvidence={}) {
  const f=fixture(t),output=path.join(f.dir,'out'),failed=path.join(f.dir,'failed'),lockPath=path.join(f.dir,'lock');
  fs.mkdirSync(output,{mode:0o700});fs.mkdirSync(failed);fs.writeFileSync(lockPath,'synthetic');
  const lockSha='0dbfd0064f4afbd32ceef751d3d1b75685f8a511cd50d394b21232d02ff29307',archiveSha='a7f6204ff63b6a2cd274d48903285abb86ed53a99070e532d4c2fd787457d9e6';
  const lock={...f.lock,gccVersion:'13.3.0',nodeSourceSha256:archiveSha,builderImage:'example.invalid/builder@sha256:b2ed7cea3b936b4054afd8157944dffc0110ae61988b3644716ddaef5214ed31'};
  if(variant!=='missing-object') {
    fs.writeFileSync(path.join(failed,'wasm-disassembler.o'),'synthetic object');
    const response=Object.hasOwn(linkEvidence,'response')||['response','nested-response','response-positive'].includes(variant);fs.writeFileSync(path.join(failed,'link.json'),JSON.stringify(linkEvidence.argv??['/usr/bin/g++',response?'@link.rsp':variant==='unrelated-object'?'unrelated.o':'wasm-disassembler.o','-o','mksnapshot']));
    fs.writeFileSync(path.join(failed,'diagnostic-inputs.json'),JSON.stringify({schema:'buzz.gcc-comdat-evidence/v1',lockSha256:lockSha,archiveSha256:archiveSha,object:'wasm-disassembler.o',linkArgv:'link.json',...(response?{responseFile:'link.rsp'}:{})}));
    if(response)fs.writeFileSync(path.join(failed,'link.rsp'),linkEvidence.response??(variant==='nested-response'?'@other.rsp':variant==='response-positive'?'wasm-disassembler.o':'"malformed unclosed quote'));
  }
  linkEvidence.prepare?.({failed,output,root:f.dir});
  const virtual=new Set(['/usr/bin/cc','/usr/bin/g++','/usr/bin/as','/usr/bin/ld','/usr/bin/objdump','/fixed/gcc','/fixed/g++','/fixed/libasan.so.8','/fixed/libubsan.so.1','/fixed/mixed.so','/fixed/libstdc++.so.6','/fixed/libgcc_s.so.1','/usr/lib/gcc/fixture/cc1plus','/usr/lib/gcc/fixture/collect2']);
  const realpath=p=>p==='/usr/bin/cc'?'/fixed/gcc':p==='/usr/bin/g++'?'/fixed/g++':virtual.has(p)?p:fs.realpathSync(p);
  const facade={...fs,realpathSync:realpath,statSync:p=>virtual.has(p)?{isFile:()=>true}:fs.statSync(p)};
  const hash=p=>p===lockPath?lockSha:p===f.archive?archiveSha:virtual.has(p)?createHash('sha256').update(p).digest('hex'):createHash('sha256').update(fs.readFileSync(p)).digest('hex');
  let child;
  const proc={env:{DIAGNOSTIC_PROFILE:'gcc-comdat-v1',BUILDER_IMAGE:lock.builderImage,QUALIFICATION_PLATFORM:lock.platform},getuid:()=>10001,kill:()=>{if(variant==='timeout')queueMicrotask(()=>child.emit('close',null,'SIGKILL'));}};
  const fakeSpawn=(bin,args,options)=>{
    assert.equal(options.detached,true);assert.equal(Object.hasOwn(options,'shell'),false);assert.equal(options.env.CXX,'/usr/bin/g++');
    child=new EventEmitter();child.pid=123;child.stdout=new EventEmitter();child.stderr=new EventEmitter();const cp=child;
    queueMicrotask(()=>{
      if(variant==='timeout')return;
      if(bin==='/usr/bin/readelf' && args.at(-1)===path.join(output,'failed-object.o'))linkEvidence.inspect?.({failed,output,args});
      let out='',err='',code=0;
      if(args[0]==='--version')out=bin.endsWith('objdump')?'GNU objdump synthetic':bin.endsWith('/as')?'GNU assembler synthetic':bin.endsWith('/ld')?'GNU ld synthetic':'gcc 13.3.0 Free Software Foundation';
      else if(args[0]==='-dumpfullversion')out='13.3.0';
      else if(args[0]==='-dumpmachine')out='x86_64-linux-gnu';
      else if(args[0]?.startsWith('-print-prog-name=')){const name=args[0].split('=')[1];out=['cc1plus','collect2'].includes(name)?'/usr/lib/gcc/fixture/'+name:'/usr/bin/'+name;}
      else if(args[0]?.startsWith('-print-file-name='))out=args[0].includes('libasan')?'/fixed/libasan.so.8':args[0].includes('libubsan')?'/fixed/libubsan.so.1':args[0].includes('libstdc++')?'/fixed/libstdc++.so.6':'/fixed/libgcc_s.so.1';
      else if(bin==='/usr/bin/readelf')out='ELF DYN COMDAT Values';
      else if(bin==='/usr/bin/ldd')out='libasan.so.8 => '+(variant==='mixed'?'/fixed/mixed.so':'/fixed/libasan.so.8')+' (0x1)\nlibubsan.so.1 => /fixed/libubsan.so.1 (0x2)\nlibstdc++.so.6 => /fixed/libstdc++.so.6 (0x3)\nlibgcc_s.so.1 => /fixed/libgcc_s.so.1 (0x4)';
      else if(bin.endsWith('/comdat-probe')){if(!args.length)out='COMDAT_CLEAN';else if(args[0]==='asan'){code=variant==='silent'?0:1;err=variant==='silent'?'':'ERROR: AddressSanitizer: heap-buffer-overflow';}else{code=1;err='runtime error: signed integer overflow';}}
      if(args.includes('-Wl,-Map,comdat-link.map'))fs.writeFileSync(path.join(output,'comdat-link.map'),'synthetic COMDAT link map');
      if(variant==='bounds')out='X'.repeat(2*1024*1024+1);
      cp.stdout.emit('data',Buffer.from(out));cp.stderr.emit('data',Buffer.from(err));cp.emit('close',code,null);
    });return cp;
  };
  const d=diagnosticFunctions({fs:facade,hash,process:proc,spawn:fakeSpawn,output,target:failed,infrastructure:path.join(f.dir,'infra'),lockPath,archive:f.archive,source:()=>({commit:'synthetic',tree:'synthetic'}),readonly:()=>{},toolchain:()=>({synthetic:true}),setTimeout:(fn,ms)=>setTimeout(fn,variant==='timeout'?1:ms)});
  await d.diagnose(lock);const result=JSON.parse(fs.readFileSync(path.join(output,'diagnostic.json')));
  for(const artifact of result.artifacts){const bytes=fs.readFileSync(path.join(output,artifact.name));assert.equal(bytes.length,artifact.bytes);assert.equal(createHash('sha256').update(bytes).digest('hex'),artifact.sha256);}
  return result;
}
for(const [variant,pattern] of [['missing-object',/ENOENT/],['response',/malformed diagnostic response/],['nested-response',/malformed diagnostic response|nested diagnostic response/],['unrelated-object',/not uniquely referenced/],['mixed',/mixed loaded sanitizer runtime/],['silent',/ASan fault did not fire/],['timeout',/terminated/],['bounds',/terminated/]]) {
  test(`synthetic diagnostic runner preserves BLOCKED evidence for ${variant}`,async t=>{
    const r=await syntheticDiagnostic(t,variant);assert.equal(r.status,'BLOCKED');assert.match(r.blocker,pattern);assert(r.commands.length>0);assert.equal(r.liveAcceptance,'NOT_READY');
    if(variant==='timeout')assert(r.commands.some(c=>c.timedOut&&c.signal==='SIGKILL'));
    if(variant==='bounds')assert(r.commands.some(c=>c.bounded));
  });
}
test('synthetic complete diagnostic retains actual outcome fields/digests and never claims qualification PASS',async t=>{
  const r=await syntheticDiagnostic(t,'complete');assert.equal(r.status,'DIAGNOSTIC_ONLY_PENDING_REVIEW');assert(r.commands.some(c=>c.label==='clean'&&c.code===0));assert(r.commands.some(c=>c.label==='asan'&&c.code===1));assert(r.commands.some(c=>c.label==='ubsan'&&c.code===1));assert.match(r.scope,/no Node\/V8 compatibility/);assert.equal(r.reportedFailure.R1,'INCOMPLETE');assert(r.unavailable.length);
});
test('required GCC helpers reject missing, relative, noncanonical, malformed and mismatched identities',()=>{
  const d=diagnosticFunctions({fs:{...fs,realpathSync:p=>p==='/alias/collect2'?'/fixed/collect2':p}});
  const runtime={path:'/fixed/lib.so',sha256:'a'.repeat(64)},helper={path:'/fixed/helper',sha256:'b'.repeat(64)},base={version:'13.3.0',machine:'x86_64-linux-gnu',cc1plus:helper,collect2:helper,'libasan.so':runtime,'libubsan.so':runtime,'libstdc++.so':runtime,'libgcc_s.so.1':runtime};
  d.diagnosticFamily({gccVersion:'13.3.0',platform:'linux/amd64'},[base,base]);
  for(const key of ['cc1plus','collect2'])for(const bad of [undefined,null,{path:'relative',sha256:'a'.repeat(64)},{path:'/alias/collect2',sha256:'a'.repeat(64)},{path:'/fixed/helper',sha256:'bad'},{path:'/fixed/other',sha256:'b'.repeat(64)},{path:'/fixed/helper',sha256:'c'.repeat(64)}]){
    assert.throws(()=>d.diagnosticFamily({gccVersion:'13.3.0',platform:'linux/amd64'},[base,{...base,[key]:bad}]));
    if(!bad)assert.throws(()=>d.diagnosticFamily({gccVersion:'13.3.0',platform:'linux/amd64'},[{...base,[key]:bad},{...base,[key]:bad}]));
  }
});
test('captured object correlation accepts exact input only, rejects unrelated, output, flags and aliases',()=>{
  const d=diagnosticFunctions(),object='out/wasm-disassembler.o';
  d.diagnosticObjectReference(object,['/usr/bin/g++',object,'-o','mksnapshot'],[]);
  d.diagnosticObjectReference(object,['/usr/bin/g++','@link.rsp','-o','mksnapshot'],[object]);
  for(const args of [['/usr/bin/g++','unrelated.o','-o','mksnapshot'],['/usr/bin/g++','-T',object,'other.o','-o','mksnapshot'],['/usr/bin/g++',object,object,'-o','mksnapshot'],['/usr/bin/g++','out/./wasm-disassembler.o','-o','mksnapshot']])assert.throws(()=>d.diagnosticObjectReference(object,args,[]));
  assert.throws(()=>d.diagnosticObjectReference('out/./wasm-disassembler.o',['/usr/bin/g++','out/./wasm-disassembler.o','-o','mksnapshot'],[]),/noncanonical/);
  assert.throws(()=>d.diagnosticResponse('wasm-disassembler.o @other.rsp'));
});
test('synthetic verified response contains the exact preserved object input',async t=>{const r=await syntheticDiagnostic(t,'response-positive');assert.equal(r.status,'DIAGNOSTIC_ONLY_PENDING_REVIEW');});

// Independent-style transport vectors: expected results are explicit, not
// generated from parser options. Captured arguments remain data throughout.
const linkerObject='out/wasm-disassembler.o';
const validLinkerCaptures=[
  {name:'one direct input',args:[linkerObject]},
  {name:'one verified response input',args:['@link.rsp'],response:[linkerObject]},
  {name:'one comma-forwarded input',args:['-Wl,'+linkerObject]},
  {name:'forwarded group inputs',args:['-Wl,--start-group,out/other.o,'+linkerObject+',--end-group']},
  {name:'response forwards one input',args:['@link.rsp'],response:['-Wl,'+linkerObject]},
  {name:'libraries and distinct forwarded paths',args:['out/other.o','-Wl,lib/helper.a,'+linkerObject+',-z,noexecstack,-L,/usr/lib,-l,stdc++','-lpthread']},
  {name:'whole archive with distinct object',args:['-Wl,--whole-archive,lib/helper.a,--no-whole-archive',linkerObject]},
];
for(const c of validLinkerCaptures)test('linker capture accepts '+c.name,()=>{
  diagnosticFunctions().diagnosticObjectReference(linkerObject,['/usr/bin/g++',...c.args,'-o','mksnapshot'],c.response??[]);
});
const invalidLinkerCaptures=[
  {name:'reported hidden response with direct object',args:[linkerObject,'-Wl,@hidden.rsp']},
  {name:'hidden response amid forwarded options',args:[linkerObject,'-Wl,--start-group,@hidden.rsp,--end-group']},
  {name:'Xlinker response operand',args:[linkerObject,'-Xlinker','@hidden.rsp']},
  {name:'Xlinker embedded response operand',args:[linkerObject,'-Xlinker=@hidden.rsp']},
  {name:'unsupported Xlinker input transport',args:['-Xlinker',linkerObject]},
  {name:'top-level alias duplicate',args:[linkerObject,'out/./wasm-disassembler.o']},
  {name:'forwarded alias duplicate',args:[linkerObject,'-Wl,out/./wasm-disassembler.o']},
  {name:'response alias duplicate',args:['@link.rsp'],response:[linkerObject,'out/./wasm-disassembler.o']},
  {name:'mixed direct-forwarded duplicate',args:[linkerObject,'-Wl,'+linkerObject]},
  {name:'mixed direct-response duplicate',args:[linkerObject,'@link.rsp'],response:[linkerObject]},
  {name:'multiple forwarded duplicates',args:['-Wl,'+linkerObject+','+linkerObject]},
  {name:'response-forwarded duplicate',args:['@link.rsp'],response:[linkerObject,'-Wl,'+linkerObject]},
  {name:'response embeds hidden forwarding',args:['@link.rsp'],response:[linkerObject,'-Wl,@hidden.rsp']},
  {name:'response nests a top-level reference',args:['@link.rsp'],response:[linkerObject,'@nested.rsp']},
  {name:'unrelated alias is also rejected',args:[linkerObject,'out/../other.o']},
  {name:'empty input path component',args:[linkerObject,'out//other.o']},
  {name:'forwarded traversal input',args:['-Wl,out/../out/wasm-disassembler.o']},
  {name:'ambiguous same-basename path',args:[linkerObject,'other/wasm-disassembler.o']},
  {name:'repeated explicit library path',args:[linkerObject,'lib/a.a','-Wl,lib/a.a']},
  {name:'absolute candidate input unsupported',args:[linkerObject,'/out/other.o']},
  {name:'missing comma payload',args:[linkerObject,'-Wl,']},
  {name:'missing comma transport',args:[linkerObject,'-Wl']},
  {name:'empty leading comma field',args:[linkerObject,'-Wl,,out/other.o']},
  {name:'empty trailing comma field',args:[linkerObject,'-Wl,out/other.o,']},
  {name:'unrecognized forwarded option',args:[linkerObject,'-Wl,--unknown,out/other.o']},
  {name:'forwarded output operand unsupported',args:[linkerObject,'-Wl,-o,mksnapshot']},
  {name:'forwarded script may import inputs',args:[linkerObject,'-Wl,--script,input.ld']},
  {name:'driver specs may import inputs',args:[linkerObject,'-specs=inputs.specs']},
  {name:'library exact-filename input unsupported',args:[linkerObject,'-Wl,-l:wasm-disassembler.o']},
  {name:'forwarded flag substring is not an input',args:['-Wl,--defsym,x='+linkerObject]},
  {name:'missing forwarded option operand',args:[linkerObject,'-Wl,-z']},
  {name:'input cannot be a z operand',args:[linkerObject,'-Wl,-z,'+linkerObject]},
  {name:'unterminated forwarded group',args:['-Wl,--start-group,'+linkerObject]},
  {name:'unmatched forwarded group end',args:[linkerObject,'-Wl,--end-group']},
  {name:'nested forwarded groups unsupported',args:['-Wl,--start-group,--start-group,'+linkerObject+',--end-group,--end-group']},
  {name:'multiple top-level response files',args:['@one.rsp','@two.rsp'],response:[linkerObject]},
  {name:'response path alias',args:['@out/./link.rsp'],response:[linkerObject]},
  {name:'unexpected response tokens',args:[linkerObject],response:['other.o']},
  {name:'missing verified response tokens',args:['@link.rsp']},
];
for(const c of invalidLinkerCaptures)test('linker capture rejects '+c.name,()=>{
  assert.throws(()=>diagnosticFunctions().diagnosticObjectReference(linkerObject,['/usr/bin/g++',...c.args,'-o','mksnapshot'],c.response??[]));
});
for(const [name,evidence,valid] of [
  ['direct hidden response',{argv:['/usr/bin/g++','wasm-disassembler.o','-Wl,@hidden.rsp','-o','mksnapshot']},false],
  ['top-level alias duplicate',{argv:['/usr/bin/g++','wasm-disassembler.o','./wasm-disassembler.o','-o','mksnapshot']},false],
  ['response alias duplicate',{argv:['/usr/bin/g++','@link.rsp','-o','mksnapshot'],response:'wasm-disassembler.o ./wasm-disassembler.o'},false],
  ['mixed forwarded duplicate',{argv:['/usr/bin/g++','wasm-disassembler.o','-Wl,wasm-disassembler.o','-o','mksnapshot']},false],
  ['one forwarded group object',{argv:['/usr/bin/g++','-Wl,--start-group,wasm-disassembler.o,--end-group','-o','mksnapshot']},true],
  ['response forwards exactly one',{argv:['/usr/bin/g++','@link.rsp','-o','mksnapshot'],response:'-Wl,wasm-disassembler.o'},true],
])test('synthetic runner enforces linker correlation: '+name,async t=>{
  const r=await syntheticDiagnostic(t,'capture',evidence);assert.equal(r.status,valid?'DIAGNOSTIC_ONLY_PENDING_REVIEW':'BLOCKED');
  if(!valid)assert(!r.commands.some(c=>c.label.startsWith('v8-')||c.label.startsWith('compile-')),'bad captured evidence rejected before inspection/compilation');
});

test('supplied evidence admits a stable single-link file without changing its bytes or identity',t=>{
  const f=fixture(t),p=path.join(f.dir,'evidence');fs.writeFileSync(p,'stable bytes');const d=diagnosticFunctions(),before=fs.statSync(p,{bigint:true});
  const snapshot=d.diagnosticEvidence(p,64);assert.equal(snapshot.bytes.toString(),'stable bytes');assert.equal(snapshot.identity.nlink,'1');
  d.diagnosticEvidenceCheck(p,64,snapshot.identity);d.diagnosticEvidence(p,64,snapshot);
  const after=fs.statSync(p,{bigint:true});for(const k of ['dev','ino','mode','size','nlink','mtimeNs','ctimeNs'])assert.equal(after[k],before[k]);
  assert.equal(fs.readFileSync(p,'utf8'),'stable bytes');
});
test('real outside-projection hardlink mutation is rejected; generated/internal text retains its separate policy',t=>{
  const f=fixture(t),projection=path.join(f.dir,'projection');fs.mkdirSync(projection);const p=path.join(projection,'object'),outside=path.join(f.dir,'outside');
  fs.writeFileSync(p,'original');fs.linkSync(p,outside);assert.equal(fs.statSync(p).nlink,2);fs.writeFileSync(outside,'altered!');assert.equal(fs.readFileSync(p,'utf8'),'altered!');
  const d=diagnosticFunctions();assert.throws(()=>d.diagnosticEvidence(p,64),/unsafe supplied/);assert.equal(fs.readFileSync(p,'utf8'),'altered!');assert.equal(fs.statSync(p).nlink,2);
  // This generic helper serves fresh internally generated maps, not supplied data.
  assert.equal(d.diagnosticText(p,64),'altered!');
});
test('supplied evidence rejects symlinks, nonregular, oversize and stale snapshots',t=>{
  const f=fixture(t),p=path.join(f.dir,'file'),link=path.join(f.dir,'symlink');fs.writeFileSync(p,'abc');fs.symlinkSync(p,link);const d=diagnosticFunctions();
  assert.throws(()=>d.diagnosticEvidence(link,64),/unsafe/);assert.throws(()=>d.diagnosticEvidence(f.dir,64),/unsafe/);assert.throws(()=>d.diagnosticEvidence(p,2),/unsafe/);
  const snapshot=d.diagnosticEvidence(p,64);fs.writeFileSync(p,'xyz');fs.utimesSync(p,new Date(0),new Date(1000));
  assert.throws(()=>d.diagnosticEvidence(p,64,snapshot),/changed/);assert.equal(fs.readFileSync(p,'utf8'),'xyz');
});
for(const kind of ['replace','symlink','hardlink','grow','same-size-change','truncate'])test('actual supplied-file '+kind+' during fd inspection is rejected',t=>{
  const f=fixture(t),p=path.join(f.dir,'file'),sibling=path.join(f.dir,'sibling');fs.writeFileSync(p,'original');let changed=false;
  const facade={...fs,readSync:(...args)=>{const n=fs.readSync(...args);if(!changed){changed=true;
    if(kind==='replace'){fs.renameSync(p,sibling);fs.writeFileSync(p,'original');}
    else if(kind==='symlink'){fs.renameSync(p,sibling);fs.symlinkSync(sibling,p);}
    else if(kind==='hardlink')fs.linkSync(p,sibling);
    else if(kind==='grow')fs.appendFileSync(p,' growth');
    else if(kind==='truncate')fs.truncateSync(p,1);
    else {fs.writeFileSync(p,'modified');fs.utimesSync(p,new Date(0),new Date(1000));}
  }return n;}};
  assert.throws(()=>diagnosticFunctions({fs:facade}).diagnosticEvidence(p,64));assert(changed);
  if(kind==='replace'||kind==='symlink')assert.equal(fs.readFileSync(sibling,'utf8'),'original');
  if(kind==='hardlink'){assert.equal(fs.statSync(p).nlink,2);assert.equal(fs.readFileSync(p,'utf8'),'original');}
});
test('supplied-file symlink swap immediately before open fails O_NOFOLLOW',t=>{
  const f=fixture(t),p=path.join(f.dir,'file'),sibling=path.join(f.dir,'old');fs.writeFileSync(p,'original');let changed=false;
  const facade={...fs,openSync:(file,flags)=>{assert(flags&fs.constants.O_NOFOLLOW);fs.renameSync(p,sibling);fs.symlinkSync(sibling,p);changed=true;return fs.openSync(file,flags);}};
  assert.throws(()=>diagnosticFunctions({fs:facade}).diagnosticEvidence(p,64));assert(changed);assert.equal(fs.readFileSync(sibling,'utf8'),'original');
});
for(const field of ['dev','ino','size','nlink'])test('supplied fd '+field+' identity change is rejected without writing source',t=>{
  const f=fixture(t),p=path.join(f.dir,'file');fs.writeFileSync(p,'original');let calls=0;
  const facade={...fs,fstatSync:(...args)=>{const s=fs.fstatSync(...args);calls++;return calls===2?{...s,[field]:s[field]+1n,isFile:()=>true}:s;}};
  assert.throws(()=>diagnosticFunctions({fs:facade}).diagnosticEvidence(p,64),/changed/);assert.equal(fs.readFileSync(p,'utf8'),'original');
});
for(const name of ['diagnostic-inputs.json','wasm-disassembler.o','link.json','link.rsp'])test('runner rejects real hardlinked supplied '+name,async t=>{
  let observed=false;const r=await syntheticDiagnostic(t,'capture',{
    argv:['/usr/bin/g++','@link.rsp','-o','mksnapshot'],response:'wasm-disassembler.o',
    prepare:({failed,root})=>{const p=path.join(failed,name),sibling=path.join(root,'outside-'+name);fs.linkSync(p,sibling);observed=fs.statSync(p).nlink===2;},
  });
  assert(observed);assert.equal(r.status,'BLOCKED');assert.match(r.blocker,/unsafe supplied/);assert(!r.commands.some(c=>c.label.startsWith('v8-')||c.label.startsWith('compile-')));
});
for(const name of ['diagnostic-inputs.json','wasm-disassembler.o','link.json','link.rsp'])test('runner detects supplied '+name+' mutation during inspection of frozen object',async t=>{
  let observed=false;const r=await syntheticDiagnostic(t,'capture',{
    argv:['/usr/bin/g++','@link.rsp','-o','mksnapshot'],response:'wasm-disassembler.o',
    inspect:({failed,output,args})=>{assert.equal(args.at(-1),path.join(output,'failed-object.o'));assert.equal(fs.readFileSync(args.at(-1),'utf8'),'synthetic object');fs.appendFileSync(path.join(failed,name),' changed');observed=true;},
  });
  assert(observed);assert.equal(r.status,'BLOCKED');assert.match(r.blocker,/supplied diagnostic evidence changed/);assert(!r.commands.some(c=>c.label.startsWith('compile-')));
});
test('linker parser rejects missing library operands in direct and forwarded argument streams',()=>{
  const d=diagnosticFunctions(),object='out/wasm-disassembler.o';
  for(const argv of [['/usr/bin/g++',object,'-o','mksnapshot','-l'],['/usr/bin/g++',object,'-o','mksnapshot','-Wl,-l'],['/usr/bin/g++',object,'-l','-o','mksnapshot']])assert.throws(()=>d.diagnosticObjectReference(object,argv,[]));
});
