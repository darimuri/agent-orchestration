#!/bin/bash
# Run through bash (ordinary 100644 source). Owner executes Docker, never this agent.
set -euo pipefail
exec node --input-type=module - "$@" <<'JS'
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { pathToFileURL } from 'node:url';
const [mode, lockPath, archive, target, infrastructure, output] = process.argv.slice(2);
const fail = message => { throw Error(message); };
const hash = p => crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
const fixed = {PATH:'/usr/bin:/bin',LANG:'C',LC_ALL:'C',TZ:'UTC',SOURCE_DATE_EPOCH:'0',GIT_OPTIONAL_LOCKS:'0'};
const exec = (bin, args, cwd) => {
  const r = spawnSync(bin,args,{cwd,env:fixed,encoding:'utf8',timeout:30000,maxBuffer:16*1024*1024});
  if(r.error || r.status !== 0) fail('prerequisite command failed: '+bin+' '+args.join(' '));
  return r.stdout.trim();
};
function inputs() {
  // Reject inherited controls, including otherwise benign values: no hidden policy.
  for (const key of ['ASAN_OPTIONS','LSAN_OPTIONS','UBSAN_OPTIONS','LD_PRELOAD','LD_LIBRARY_PATH','NODE_OPTIONS','CC','CXX','CFLAGS','CXXFLAGS','LDFLAGS'])
    if(Object.hasOwn(process.env,key)) fail('forbidden inherited control: '+key);
  const version=process.env.NODE_VERSION, digest=process.env.NODE_SOURCE_SHA256;
  if(!/^26\.\d+\.\d+$/.test(version??'')) fail('mandatory explicit NODE_VERSION (exact approved Node26 release)');
  if(!/^[a-f0-9]{64}$/.test(digest??'')) fail('mandatory explicit NODE_SOURCE_SHA256');
  const lock=JSON.parse(fs.readFileSync(lockPath,'utf8'));
  if(lock.schema!=='buzz.approval-qualification-inputs/v1') fail('inputs schema');
  if(version!==lock.nodeVersion || digest!==lock.nodeSourceSha256) fail('release inputs mismatch');
  const approval=lock.approval;
  if(!approval || !['advisory','signedChecksumEvidence','signer'].every(k=>typeof approval[k]==='string' && approval[k].trim())) fail('reviewed release approval missing');
  if(approval.sourceUrl!==`https://nodejs.org/dist/v${version}/node-v${version}.tar.xz`) fail('official source URL mismatch');
  if(!/^[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}$/.test(lock.builderImage??'')) fail('digest-pinned prepared builder required');
  if(!/^linux\/(amd64|arm64)$/.test(lock.platform??'')) fail('locked platform required');
  if(mode==='build-runtime' && (process.env.BUILDER_IMAGE!==lock.builderImage || process.env.QUALIFICATION_PLATFORM!==lock.platform)) fail('builder/platform mismatch');
  if(!lock.packages || !Object.keys(lock.packages).length || !Object.entries(lock.packages).every(([k,v])=>/^[a-z0-9][a-z0-9+.:_-]*$/.test(k) && typeof v==='string' && v.trim())) fail('complete package lock required');
  if(!/^\d+\.\d+\.\d+$/.test(lock.gccVersion??'')) fail('GCC version lock required');
  if(lock.target?.commit!=='1312e7a9dec6fac055b61993c145be7f6847e216' || lock.target?.tree!=='3868efaef2c500a13d2bde30cd645d5aa372ab59') fail('immutable target mismatch');
  if(!fs.lstatSync(archive).isFile() || hash(archive)!==digest) fail('source archive hash mismatch');
  return lock;
}
function toolchain(lock) {
  const inventory=Object.fromEntries(exec('/usr/bin/dpkg-query',['-W','-f=${binary:Package}\t${Version}\n']).split('\n').map(s=>s.split('\t')));
  if(JSON.stringify(Object.entries(inventory).sort())!==JSON.stringify(Object.entries(lock.packages).sort())) fail('installed package inventory differs from reviewed lock');
  const tools=['/usr/bin/cc','/usr/bin/g++','/usr/bin/as','/usr/bin/ld','/usr/bin/make','/usr/bin/python3','/usr/bin/pkg-config','/usr/bin/readelf','/usr/bin/ldd','/usr/bin/dbus-daemon','/usr/bin/git','/usr/bin/tar'];
  const records=tools.map(p=>({path:p,realpath:fs.realpathSync(p),sha256:hash(fs.realpathSync(p))}));
  if(!/gcc/.test(fs.realpathSync('/usr/bin/cc')) || !/g\+\+/.test(fs.realpathSync('/usr/bin/g++'))) fail('fixed GCC/G++ drivers required');
  for(const driver of ['/usr/bin/cc','/usr/bin/g++'])
    if(exec(driver,['-dumpfullversion'])!==lock.gccVersion) fail('mixed compiler family');
  const systemd=exec('/usr/bin/pkg-config',['--modversion','libsystemd']);
  if(Number.parseInt(systemd,10)<255 || !/^\d/.test(systemd)) fail('libsystemd >=255 required');
  const libraries=['libasan.so','libubsan.so'].map(name=>{
    const p=exec('/usr/bin/cc',['-print-file-name='+name]);
    if(!path.isAbsolute(p)) fail('missing sanitizer runtime');
    return {path:fs.realpathSync(p),sha256:hash(fs.realpathSync(p))};
  });
  return {records,libraries,systemd,packages:inventory,compiler:exec('/usr/bin/cc',['--version']),linker:exec('/usr/bin/ld',['--version'])};
}
function readonly(p) {
  if(!path.isAbsolute(p) || fs.realpathSync(p)!==p) fail('canonical absolute source path required');
  const mounts=fs.readFileSync('/proc/self/mountinfo','utf8').trim().split('\n').map(l=>l.split(' '));
  const mount=mounts.filter(m=>p===m[4] || p.startsWith(m[4]==='/'?'/':m[4]+'/')).sort((a,b)=>b[4].length-a[4].length)[0];
  if(!mount?.[5].split(',').includes('ro')) fail('source must be mounted read-only: '+p);
}
function source(p) {
  readonly(p);
  const git=(...a)=>exec('/usr/bin/git',['-c','safe.directory='+p,'-C',p,...a]);
  if(git('status','--porcelain','--untracked-files=all')) fail('source is dirty');
  return {commit:git('rev-parse','HEAD'),tree:git('rev-parse','HEAD^{tree}')};
}
const gates = [
  {name:'production',runtime:'normal',args:['--test','--test-name-pattern=MANDATORY protected offline production','agents/scripts/host-approval-service.test.mjs']},
  {name:'strict37',runtime:'normal',args:['--test','--test-name-pattern=journal strict C17','agents/scripts/host-approval-service.test.mjs']},
  {name:'asan37',runtime:'asan',args:['--test','--test-name-pattern=ASan\\+UBSan Node lifetime','agents/scripts/host-approval-service.test.mjs']},
  {name:'full-package',runtime:'asan',full:true},
];
// Diagnostic reproduction uses the UNCHANGED worker with a separate fixture build.
const promiseSource = `#include <node_api.h>
NAPI_MODULE_EXPORT int32_t NODE_API_MODULE_GET_API_VERSION(void);
static napi_value control(napi_env env, napi_callback_info info) {
  (void)info; napi_deferred deferred; napi_value promise, value, arg; size_t argc=1; int32_t mode=0;
  if(napi_get_cb_info(env,info,&argc,&arg,NULL,NULL)!=napi_ok) return NULL;
  if(argc && napi_get_value_int32(env,arg,&mode)!=napi_ok) return NULL;
  if(napi_create_promise(env,&deferred,&promise)!=napi_ok) return NULL;
  if(napi_get_undefined(env,&value)!=napi_ok) return NULL;
  if(mode==0 && napi_resolve_deferred(env,deferred,value)!=napi_ok) return NULL;
  if(mode==1 && napi_reject_deferred(env,deferred,value)!=napi_ok) return NULL;
  return promise;
}
NAPI_MODULE_INIT() {
  napi_value fn;
  if(napi_create_function(env,"control",NAPI_AUTO_LENGTH,control,NULL,&fn)!=napi_ok) return NULL;
  if(napi_set_named_property(env,exports,"control",fn)!=napi_ok) return NULL;
  return exports;
}
`;
async function main() {
  if(!['plan','verify-source','build-runtime','run'].includes(mode)) fail('usage: bash qualify-host-approval.sh plan|build-runtime|run LOCK ARCHIVE [TARGET INFRA OUTPUT]');
  const lock=inputs();
  if(mode==='plan') {
    console.log(JSON.stringify({lock,gates,diagnostics:['clock-regression','minimal Node-API Promise control'],sourceMount:'read-only',outputMount:'separate writable',compiler:'/usr/bin/cc',cxx:'/usr/bin/g++',network:'none'})); return;
  }
  if(mode==='verify-source') { console.log(JSON.stringify(source(target))); return; }
  const measured=toolchain(lock);
  if(mode==='build-runtime') {
    if(!/^[1-4]$/.test(process.env.BUILD_JOBS??'')) fail('explicit bounded BUILD_JOBS 1..4 required');
    fs.mkdirSync('/build',{mode:0o700});
    // Inspect archive names before extraction; checksum was admitted before any build.
    const entries=exec('/usr/bin/tar',['-tJf',archive]).split('\n');
    if(entries.some(p=>!p.startsWith('node-v'+lock.nodeVersion+'/') || p.split('/').includes('..'))) fail('archive path escape');
    fs.writeFileSync('/qualification/toolchain.json',JSON.stringify({lock,measured},null,2));
    for(const variant of ['normal','asan']) {
      const dir='/build/'+variant;fs.mkdirSync(dir);
      exec('/usr/bin/tar',['-xJf',archive,'--strip-components=1','-C',dir,'--no-same-owner']);
      const env={...fixed,CC:'/usr/bin/cc',CXX:'/usr/bin/g++',LINK:'/usr/bin/g++'};
      for(const [bin,args] of [
        ['/usr/bin/python3',['configure','--prefix=/opt/node-'+variant,...(variant==='asan'?['--enable-asan']:[])]],
        ['/usr/bin/make',['-j'+process.env.BUILD_JOBS]],['/usr/bin/make',['install']]
      ]) {
        const log=fs.openSync('/qualification/build-'+variant+'-'+path.basename(bin)+'-'+args[0].replaceAll('/','_')+'.log','w',0o600);
        const cp=spawn(bin,args,{cwd:dir,env,stdio:['ignore','pipe','pipe']});
        const retain=chunk=>{fs.writeSync(log,chunk);process.stdout.write(chunk);};
        cp.stdout.on('data',retain);cp.stderr.on('data',retain);
        const timer=setTimeout(()=>cp.kill('SIGKILL'),14400000);
        let code,signal;
        try { [code,signal]=await once(cp,'close'); } finally { clearTimeout(timer);fs.closeSync(log); }
        if(code!==0 || signal) fail('Node build failed; retain owner build stream and /qualification build logs: '+variant);
      }
    }
    return;
  }
  if(process.getuid()===0) fail('qualification must run nonroot');
  const targetState=source(target),infraState=source(infrastructure);
  if(targetState.commit!==lock.target.commit || targetState.tree!==lock.target.tree) fail('target source identity mismatch');
  for(const [file,copied] of [['agents/scripts/qualify-host-approval.sh','/qualification/qualify-host-approval.sh'],['agents/tests/job-preparation/Dockerfile.approval-qualification','/qualification/Dockerfile.approval-qualification']]) {
    if(hash(path.join(infrastructure,file))!==hash(copied)) fail('infrastructure recipe/script mismatch');
  }
  if(!path.isAbsolute(output) || fs.realpathSync(output)!==output || [target,infrastructure].some(p=>output===p || output.startsWith(p+'/'))) fail('separate canonical output required');
  const stat=fs.statSync(output);
  if(stat.uid!==process.getuid() || (stat.mode&0o777)!==0o700 || fs.readdirSync(output).length) fail('fresh owned 0700 output required');
  const manifest={schema:'buzz.approval-qualification-result/v1',status:'INCOMPLETE',target:targetState,infrastructure:infraState,lock,measured,build:JSON.parse(fs.readFileSync('/qualification/toolchain.json')),runtimes:{},gates:[],liveAcceptance:'NOT_READY'};
  const save=()=>fs.writeFileSync(path.join(output,'result.json'),JSON.stringify(manifest,null,2),{mode:0o600});
  if(JSON.stringify(manifest.build.lock)!==JSON.stringify(lock)) fail('build/run input lock mismatch');
  save();
  let failed=false;
  async function logged(name,bin,args,cwd=target,extra={}) {
    const logPath=path.join(output,name+'.log'),fd=fs.openSync(logPath,'wx',0o600);
    const entry={name,command:[bin,...args],log:path.basename(logPath),status:'INCOMPLETE'};manifest.gates.push(entry);save();
    const cp=spawn(bin,args,{cwd,env:{...fixed,TEST_EXECUTABLE_TMPDIR:output,...extra},stdio:['ignore',fd,fd],detached:true});
    let timedOut=false;
    const timer=setTimeout(()=>{timedOut=true;try{process.kill(-cp.pid,'SIGKILL');}catch{}},1800000);
    try {const [code,signal]=await once(cp,'exit');entry.exitCode=code;entry.signal=signal;entry.status=code===0&&!signal&&!timedOut?'PASS':'FAIL';}
    catch(e){entry.status='FAIL';entry.error=e.message;}
    finally {clearTimeout(timer);try{process.kill(-cp.pid,'SIGKILL');}catch{}fs.closeSync(fd);entry.sha256=hash(logPath);const text=fs.readFileSync(logPath,'utf8');entry.totals=Object.fromEntries([...text.matchAll(/^# (tests|pass|fail|cancelled|skipped|todo) (\d+)$/gm)].map(m=>[m[1],Number(m[2])]));if(['production','strict37','asan37','full-package'].includes(name) && (!entry.totals.pass || entry.totals.fail || entry.totals.cancelled || entry.totals.todo)) entry.status='FAIL';if(name==='full-package' && (!entry.totals.tests || entry.totals.fail || entry.totals.cancelled || entry.totals.skipped || entry.totals.todo)) entry.status='FAIL';failed ||= entry.status!=='PASS';save();}
    return entry;
  }
  try {
    for(const variant of ['normal','asan']) {
      const bin='/opt/node-'+variant+'/bin/node';
      const runtime=JSON.parse(exec(bin,['-p','JSON.stringify({version:process.versions.node,asan:Number(process.config.variables.asan||0),arch:process.arch,abi:process.versions.modules})']));
      if(runtime.version!==lock.nodeVersion || runtime.asan!==(variant==='asan'?1:0) || runtime.arch!==(lock.platform==='linux/amd64'?'x64':'arm64')) fail('runtime admission mismatch');
      const headers='/opt/node-'+variant+'/include/node';
      const version=fs.readFileSync(headers+'/node_version.h','utf8');
      for(const [i,k] of ['MAJOR','MINOR','PATCH'].entries()) if(!new RegExp('#define NODE_'+k+'_VERSION\\s+'+lock.nodeVersion.split('.')[i]+'\\b').test(version)) fail('headers mismatch');
      const linkage=exec('/usr/bin/ldd',[bin]);
      if(/clang|compiler-rt/i.test(linkage) || (variant==='asan'&&!/libasan/.test(linkage))) fail('sanitizer linkage mismatch');
      manifest.runtimes[variant]={...runtime,sha256:hash(bin),nodeApiSha256:hash(headers+'/node_api.h'),nodeVersionSha256:hash(headers+'/node_version.h'),linkage};save();
    }
    for(const gate of gates) {
      const args=gate.full?['--test',...['agents/docker','agents/scripts'].flatMap(dir=>fs.readdirSync(path.join(target,dir)).filter(f=>f.endsWith('.test.mjs')).sort().map(f=>dir+'/'+f))]:gate.args;
      await logged(gate.name,'/opt/node-'+gate.runtime+'/bin/node',args);
    }
    // The worker and public flags are imported from the immutable target, unchanged.
    const diagnostic=path.join(output,'clock-driver.mjs');
    fs.writeFileSync(diagnostic,`import fs from 'node:fs';import path from 'node:path';import {spawnSync} from 'node:child_process';
import {nodeFlags} from ${JSON.stringify(pathToFileURL(path.join(target,'agents/scripts/build-host-approval-node.mjs')).href)};
const dir=${JSON.stringify(output)},src=${JSON.stringify(target)};
function run(bin,args){const r=spawnSync(bin,args,{stdio:'inherit',timeout:30000});if(r.error||r.status!==0)process.exit(1);}
const flags=spawnSync('/usr/bin/pkg-config',['--cflags','--libs','libsystemd'],{encoding:'utf8'});if(flags.status!==0)process.exit(1);
const libs=flags.stdout.trim().split(/\\s+/),instrument=['-O1','-fsanitize=address,undefined','-fno-omit-frame-pointer'];
run('/usr/bin/cc',[...nodeFlags,...instrument,'-DHA_TEST','-I/opt/node-asan/include/node',src+'/agents/job-preparation/native/host-approval-node.c',src+'/agents/job-preparation/native/host-approval-dbus.c','-o',dir+'/clock.node',...libs,'-lm']);
run('/usr/bin/cc',[...nodeFlags.filter(f=>f!=='-shared'&&f!=='-fPIC'),...instrument,'-DHA_TEST','-fPIE','-pie',src+'/agents/tests/job-preparation/host-approval-service-fixture.c','-o',dir+'/clock-fixture',...libs,'-lm']);
const home=path.join(dir,'clock-home');fs.mkdirSync(home,{mode:0o700});
run(process.execPath,['--expose-gc',src+'/agents/tests/job-preparation/host-approval-service-worker.mjs',home,dir+'/clock.node',dir+'/clock-fixture','clock-regression']);
`,{mode:0o600});
    await logged('clock-regression','/opt/node-asan/bin/node',[diagnostic],output,{ASAN_OPTIONS:'detect_leaks=1:abort_on_error=1',UBSAN_OPTIONS:'halt_on_error=1:print_stacktrace=1'});
    fs.writeFileSync(path.join(output,'promise-control.c'),promiseSource,{mode:0o600});
    const controlBuild=await logged('promise-build','/usr/bin/cc',['-std=c17','-Wall','-Wextra','-Werror','-Wmissing-prototypes','-DNAPI_VERSION=8','-fPIC','-shared','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I/opt/node-asan/include/node',path.join(output,'promise-control.c'),'-o',path.join(output,'promise.node')],output);
    if(controlBuild.status==='PASS') for(const [index,label] of ['resolve','reject','abandon'].entries()) {
      await logged('minimal-promise-'+label,'/opt/node-asan/bin/node',['--expose-gc','-e',`const n=require(${JSON.stringify(path.join(output,'promise.node'))});(async()=>{for(let i=0;i<1000;i++){const promise=n.control(${index});if(${index}!==2)await promise.catch(()=>{});}global.gc();console.log('PROMISE_CONTROL_SETTLED_OR_ABANDONED');})().catch(()=>process.exitCode=1);`],output,{ASAN_OPTIONS:'detect_leaks=1:abort_on_error=1',UBSAN_OPTIONS:'halt_on_error=1:print_stacktrace=1'});
    }
    if(JSON.stringify(source(target))!==JSON.stringify(targetState) || JSON.stringify(source(infrastructure))!==JSON.stringify(infraState)) fail('source changed during qualification');
    manifest.status=failed?'FAIL':'PENDING_INDEPENDENT_REVIEW';
    manifest.scope='Focused bridge/package evidence only; pinned integration, dossier review and all live H1-H9 require separate evidence.';
  } catch(e) {manifest.status='BLOCKED';manifest.blocker=e.message;failed=true;}
  finally {save();}
  if(failed) process.exitCode=1;
}
main().catch(e=>{
  // Even admission failures receive a machine-readable result when fresh output
  // is safely available; never overwrite prior evidence or source paths.
  if(mode==='run') try {
    const stat=fs.lstatSync(output);
    if(path.isAbsolute(output) && fs.realpathSync(output)===output && stat.isDirectory() && stat.uid===process.getuid() && (stat.mode&0o777)===0o700 && !fs.readdirSync(output).length && ![target,infrastructure].some(p=>p && (output===p || output.startsWith(p+'/'))))
      fs.writeFileSync(path.join(output,'result.json'),JSON.stringify({schema:'buzz.approval-qualification-result/v1',status:'BLOCKED',blocker:e.message,gates:[],liveAcceptance:'NOT_READY'},null,2),{mode:0o600});
  } catch {}
  console.error('BLOCKED: '+e.message);process.exitCode=1;
});
JS
