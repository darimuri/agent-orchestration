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
const fixed = {PATH:'/usr/bin:/bin',LANG:'C',LC_ALL:'C',TZ:'UTC',SOURCE_DATE_EPOCH:'0',GIT_OPTIONAL_LOCKS:'0',GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null',GIT_ATTR_NOSYSTEM:'1',GIT_TERMINAL_PROMPT:'0',HOME:'/dev/null',XDG_CONFIG_HOME:'/dev/null'};
const exec = (bin, args, cwd, raw=false) => {
  const r = spawnSync(bin,args,{cwd,env:fixed,encoding:'utf8',timeout:30000,maxBuffer:16*1024*1024});
  if(r.error || r.status !== 0) fail('prerequisite command failed: '+bin+' '+args.join(' '));
  return raw ? r.stdout : r.stdout.trim();
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
  // The config query itself must not invoke helpers or follow includes. Keep
  // the same defensive argv/environment on EVERY Git call, including the audit.
  const git=(args,raw=false)=>exec('/usr/bin/git',['--no-pager','-c','safe.directory='+p,'-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null','-c','core.attributesFile=/dev/null','-C',p,...args],undefined,raw);
  const config=git(['config','--local','--no-includes','--null','--list'],true);
  if(config && !config.endsWith('\0')) fail('invalid source configuration listing');
  // Deliberately allow only inert clone/identity structure. Unknown keys fail
  // closed: includes, worktreeConfig/extensions, filters, aliases, helper/tool
  // families and future command-bearing settings cannot bypass a denylist.
  const structural=/^(?:core\.(?:repositoryformatversion|filemode|bare|logallrefupdates|ignorecase|precomposeunicode)|user\.(?:name|email|useconfigonly)|remote\.origin\.(?:url|fetch)|branch\.[^\x00-\x20]+\.(?:remote|merge))$/i;
  for(const entry of config ? config.slice(0,-1).split('\0') : []) {
    const separator=entry.indexOf('\n');
    if(separator<1 || !structural.test(entry.slice(0,separator))) fail('unsafe or malformed source configuration');
  }
  // Status hides edits under these index flags. Inspect tags, never formatted paths
  // or source bytes, before accepting either projection. Preserve the index as-is.
  const index=git(['ls-files','-v','-z'],true);
  if(index && !index.endsWith('\0')) fail('invalid source index listing');
  for(const entry of index ? index.slice(0,-1).split('\0') : []) {
    if(!/^[A-Za-z?] .+$/s.test(entry)) fail('invalid source index entry');
    if(/^[a-zS] /.test(entry)) fail('source index has assume-unchanged or skip-worktree entries');
  }
  if(git(['status','--porcelain','--untracked-files=all'])) fail('source is dirty');
  return {commit:git(['rev-parse','HEAD']),tree:git(['rev-parse','HEAD^{tree}'])};
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
// Explicit diagnostic only: never called from build-runtime/run or used as a fallback.
const diagnosticProfile='gcc-comdat-v1';
const diagnosticFlags=['-std=c++17','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer','-fno-sanitize-recover=all','-v'];
function diagnosticText(p,limit) {
  const s=fs.lstatSync(p);
  if(!s.isFile() || fs.realpathSync(p)!==p || s.size>limit) fail('diagnostic evidence unavailable or exceeds bound');
  const b=fs.readFileSync(p);if(b.length>limit || b.includes(0)) fail('malformed diagnostic text');
  return b.toString('utf8');
}
function diagnosticTokens(tokens) {
  if(!Array.isArray(tokens) || !tokens.length || tokens.length>4096 || tokens.some(t=>typeof t!=='string' || !/^[A-Za-z0-9_./+:,=@%-]{1,4096}$/.test(t))) fail('malformed diagnostic argv/response');
  return tokens;
}
function diagnosticResponse(text) {
  if(text.includes('@')) fail('nested diagnostic response reference');
  if(!text.trim() || Buffer.byteLength(text)>65536 || /[^A-Za-z0-9_./+:,=% \t\r\n-]/.test(text)) fail('malformed diagnostic response file');
  const tokens=diagnosticTokens(text.trim().split(/\s+/));
  if(tokens.some(token=>token.includes('@'))) fail('nested diagnostic response reference');
  return tokens; // No quoting, nesting, expansion or execution.
}
function diagnosticObjectReference(object,argv,responseTokens) {
  if(typeof object!=='string' || path.isAbsolute(object) || path.posix.normalize(object)!==object || object.split('/').some(p=>!p||p==='.'||p==='..')) fail('noncanonical diagnostic object identity');
  const tokens=argv.slice(1).flatMap(t=>t.startsWith('@')?responseTokens:[t]);
  let references=0,outputs=0;
  const operands=new Set(['-o','-L','-l','-T','-u','-z','-Xlinker','-x','-B','-I','-isystem','-include','-imacros','-MF','-MT','-MQ','--sysroot','-specs','--script','--entry']);
  for(let i=0;i<tokens.length;i++) {
    const token=tokens[i];
    if(operands.has(token)){const value=tokens[++i];if(!value || value.startsWith('-') || value.includes('@')) fail('malformed captured linker operand');if(token==='-o'){if(path.basename(value)!=='mksnapshot')fail('mksnapshot link output missing');outputs++;}continue;}
    if(token.startsWith('-')){if(!/^(?:-Wl,.+|-W(?:all|extra|error|no-[A-Za-z0-9-]+)|-f(?:PIC|pic|PIE|pie|no-[A-Za-z0-9-]+|[A-Za-z0-9-]+=.+)|-m(?:32|64|[A-Za-z0-9-]+=.+)|-O[0-3sg]|-g(?:[0-3]|dwarf-[0-9]+)?|-L.+|-l.+|-B.+|-I.+|--sysroot=.+|-pthread|-shared|-pie|-rdynamic|-static|-s|-v|-nostdlib|-nodefaultlibs)$/.test(token))fail('unsupported captured linker option');continue;}
    if(!/\.(?:o|a|so(?:\.\d+)*)$/.test(token)) fail('unsupported captured linker input');
    if(token===object)references++;
  }
  if(outputs!==1 || references!==1) fail('preserved object not uniquely referenced as linker input');
}
function diagnosticOutcome(label,r) {
  if(r.error || r.signal || r.timedOut || r.bounded) fail('diagnostic command terminated: '+label);
  const text=r.stdout+'\n'+r.stderr;
  if(label==='asan') {
    if(r.code!==1 || !/ERROR: AddressSanitizer: heap-buffer-overflow/.test(text)) fail('expected ASan fault did not fire');
  } else if(label==='ubsan') {
    if(r.code!==1 || !/runtime error: signed integer overflow/.test(text)) fail('expected UBSan fault did not fire');
  } else if(r.code!==0 || /AddressSanitizer|runtime error:|LeakSanitizer/.test(text) && label==='clean') fail('diagnostic control/command failed: '+label);
  if(label==='clean' && r.stdout.trim()!=='COMDAT_CLEAN') fail('COMDAT clean result mismatch');
}
function diagnosticFamily(lock,identities) {
  if(!Array.isArray(identities) || identities.length!==2 || !/^\d+\.\d+\.\d+$/.test(lock.gccVersion) || identities.some(i=>i?.version!==lock.gccVersion) || identities[0].machine!==identities[1].machine || !/^(x86_64|aarch64)-[a-z0-9_-]+$/.test(identities[0].machine)) fail('malformed or mixed compiler identity');
  if(identities[0].machine.split('-')[0]!==({'linux/amd64':'x86_64','linux/arm64':'aarch64'}[lock.platform])) fail('compiler platform mismatch');
  for(const helper of ['cc1plus','collect2']) {
    for(const item of identities) {const h=item[helper];if(!h || typeof h.path!=='string' || !path.isAbsolute(h.path) || fs.realpathSync(h.path)!==h.path || !/^[a-f0-9]{64}$/.test(h.sha256??'')) fail('missing/malformed GCC helper identity');}
    if(identities[0][helper].path!==identities[1][helper].path || identities[0][helper].sha256!==identities[1][helper].sha256) fail('mixed GCC helper identity');
  }
  for(const library of ['libasan.so','libubsan.so','libstdc++.so','libgcc_s.so.1']) {
    const a=identities[0][library],b=identities[1][library];
    if(!a || !b || !path.isAbsolute(a.path) || a.path!==b.path || !/^[a-f0-9]{64}$/.test(a.sha256) || a.sha256!==b.sha256) fail('mixed sanitizer runtime identity');
  }
}
const comdatHeader=`template<int Tag> struct Values { static const int data[4]; };
template<int Tag> const int Values<Tag>::data[4]={3,5,7,11};
inline const int* constants(){return Values<7>::data;}
inline const int* localConstants(){static const int data[4]={3,5,7,11};return data;}
`;
const comdatMain=`#include <cstdio>
#include <cstring>
#include <climits>
extern const int* left(); extern const int* right(); extern const int* leftLocal(); extern const int* rightLocal();
int main(int argc,char** argv){
 if(argc==2 && std::strcmp(argv[1],"asan")==0){volatile int* p=new int[1];p[argc+8]=1;delete[] p;return 0;}
 if(argc==2 && std::strcmp(argv[1],"ubsan")==0){volatile int n=INT_MAX;std::printf("%d\\n",n+argc);return 0;}
 const int* a=left();const int* b=right();int sum=0;for(int i=0;i<4;i++)sum+=a[i];
 if(a!=b || sum!=26 || leftLocal()!=rightLocal() || leftLocal()[3]!=11){return 2;}std::puts("COMDAT_CLEAN");return 0;
}
`;
async function diagnosticProbe(command,retain,output,identities) {
    retain('constants.hpp',comdatHeader);retain('left.cc','#include "constants.hpp"\nconst int* left(){return constants();}\nconst int* leftLocal(){return localConstants();}\n');retain('right.cc','#include "constants.hpp"\nconst int* right(){return constants();}\nconst int* rightLocal(){return localConstants();}\n');retain('main.cc',comdatMain);
    for(const file of ['left','right','main'])await command('compile-'+file,'/usr/bin/g++',[...diagnosticFlags,'-c',file+'.cc','-o',file+'.o']);
    for(const file of ['left','right']){const groups=await command('probe-groups-'+file,'/usr/bin/readelf',['--section-groups','--wide',file+'.o']);if(!/COMDAT/.test(groups)||!groups.includes('Values'))fail('COMDAT evidence missing');}
    await command('probe-link','/usr/bin/g++',[...diagnosticFlags,'left.o','right.o','main.o','-Wl,-Map,comdat-link.map','-o','comdat-probe']);
    retain('probe-link-map.txt',diagnosticText(path.join(output,'comdat-link.map'),2*1024*1024));
    const linkage=await command('probe-runtime','/usr/bin/ldd',[path.join(output,'comdat-probe')]);
    if(/not found|clang|compiler-rt/i.test(linkage))fail('mixed/missing loaded sanitizer runtime');
    for(const library of ['libasan.so','libubsan.so','libstdc++.so','libgcc_s.so.1']){const soname=library.replace(/\.so(?:\.\d+)?$/,'.so');const line=linkage.split('\n').find(l=>l.trim().startsWith(soname+'.'));const match=line?.match(/=>\s+(\/\S+)\s+\(/);if(!match || fs.realpathSync(match[1])!==identities[0][library].path || hash(fs.realpathSync(match[1]))!==identities[0][library].sha256)fail('mixed loaded sanitizer runtime');}
    for(const label of ['clean','asan','ubsan'])await command(label,path.join(output,'comdat-probe'),label==='clean'?[]:[label]);
}
async function diagnose(lock) {
  // OUT must be fresh: old R1/R2 results and artifacts are never reused/overwritten.
  const stat=fs.lstatSync(output);
  if(!path.isAbsolute(output) || fs.realpathSync(output)!==output || !stat.isDirectory() || stat.uid!==process.getuid() || (stat.mode&0o777)!==0o700 || fs.readdirSync(output).length || [target,infrastructure].some(p=>p && (output===p || output.startsWith(p+'/')))) fail('fresh separate owned 0700 diagnostic output required');
  const result={schema:'buzz.gcc-comdat-diagnostic/v1',status:'INCOMPLETE',scope:'Toolchain diagnostic only; no Node/V8 compatibility, G0 or AGE20 qualification PASS',liveAcceptance:'NOT_READY',profile:diagnosticProfile,commands:[],artifacts:[],unavailable:['Owner R1/R2 logs and BuildKit filesystem are not supplied by this source checkout.'],reportedFailure:{node:'26.13.1',archiveSha256:'a7f6204ff63b6a2cd274d48903285abb86ed53a99070e532d4c2fd787457d9e6',lockSha256:'0dbfd0064f4afbd32ceef751d3d1b75685f8a511cd50d394b21232d02ff29307',ownerLogSha256:'fb8c7fd9083e60fbc0f6e05157fea15472ceacf845762f1061af11b94f49cbb8',R1:'INCOMPLETE',R2:'ASan mksnapshot link failed; not independently reproduced'}};
  const resultPath=path.join(output,'diagnostic.json');fs.writeFileSync(resultPath,JSON.stringify(result,null,2),{flag:'wx',mode:0o600});
  const save=()=>fs.writeFileSync(resultPath,JSON.stringify(result,null,2));
  let retained=0;const deadline=Date.now()+180000;
  const retain=(name,text)=>{
    const bytes=Buffer.byteLength(text);if(bytes>2*1024*1024 || retained+bytes>32*1024*1024) fail('diagnostic evidence bound exceeded');
    retained+=bytes;const p=path.join(output,name);fs.writeFileSync(p,text,{flag:'wx',mode:0o600});result.artifacts.push({name,bytes,sha256:hash(p)});save();return p;
  };
  const env={...fixed,CC:'/usr/bin/cc',CXX:'/usr/bin/g++',LINK:'/usr/bin/g++',ASAN_OPTIONS:'detect_leaks=1:halt_on_error=1',UBSAN_OPTIONS:'halt_on_error=1:print_stacktrace=1'};
  async function command(label,bin,args,expected=label) {
    if(Date.now()>=deadline || result.commands.length>=64) fail('diagnostic deadline/command bound exceeded');
    const record={label,argv:[bin,...args],status:'INCOMPLETE'};result.commands.push(record);save();
    let stdout='',stderr='',bytes=0,bounded=false,timedOut=false,error;
    const cp=spawn(bin,args,{cwd:output,env,stdio:['ignore','pipe','pipe'],detached:true});
    const kill=()=>{try{process.kill(-cp.pid,'SIGKILL');}catch{}};
    const timer=setTimeout(()=>{timedOut=true;kill();},Math.min(20000,deadline-Date.now()));
    cp.on('error',e=>{error=e.code||'spawn error';});
    const chunk=(which,b)=>{bytes+=b.length;if(bytes>2*1024*1024){bounded=true;kill();return;}if(which==='out')stdout+=b.toString('utf8');else stderr+=b.toString('utf8');};
    cp.stdout.on('data',b=>chunk('out',b));cp.stderr.on('data',b=>chunk('err',b));
    const [code,signal]=await new Promise(resolve=>cp.once('close',(code,signal)=>resolve([code,signal])));
    clearTimeout(timer);kill();Object.assign(record,{code,signal,error,timedOut,bounded});
    retain(String(result.commands.length).padStart(2,'0')+'-'+label+'.log',stdout+'\n--- stderr ---\n'+stderr);
    try{diagnosticOutcome(expected,{stdout,stderr,code,signal,error,timedOut,bounded});record.status='OBSERVED_EXPECTED';}catch(e){record.status='BLOCKED';save();throw e;}save();return stdout.trim();
  }
  const identity=p=>{const realpath=fs.realpathSync(p);if(!fs.statSync(realpath).isFile())fail('missing diagnostic tool/runtime');return {path:realpath,sha256:hash(realpath)};};
  try {
    if(process.getuid()!==10001) fail('diagnostic requires UID10001');
    if(process.env.DIAGNOSTIC_PROFILE!==diagnosticProfile) fail('explicit DIAGNOSTIC_PROFILE=gcc-comdat-v1 required');
    if(process.env.BUILDER_IMAGE!==lock.builderImage || process.env.QUALIFICATION_PLATFORM!==lock.platform) fail('diagnostic builder/platform mismatch');
    if(hash(lockPath)!==result.reportedFailure.lockSha256 || lock.nodeSourceSha256!==result.reportedFailure.archiveSha256 || lock.gccVersion!=='13.3.0' || lock.platform!=='linux/amd64' || !lock.builderImage.endsWith('@sha256:b2ed7cea3b936b4054afd8157944dffc0110ae61988b3644716ddaef5214ed31')) fail('preserved failure admission mismatch');
    result.inputLockSha256=hash(lockPath);result.sourceArchiveSha256=hash(archive);result.lock=lock;
    result.infrastructure=source(infrastructure);readonly(target);
    result.defaultConfigureArgumentsReference={normal:['configure','--prefix=/opt/node-normal'],asan:['configure','--prefix=/opt/node-asan','--enable-asan']};result.environment=env;result.compileFlags=diagnosticFlags;save();
    result.measured=toolchain(lock);
    result.extraTools={objdump:identity('/usr/bin/objdump')};
    if(!/^GNU objdump/.test(await command('objdump-version','/usr/bin/objdump',['--version']))) fail('malformed diagnostic objdump identity');
    for(const [label,bin] of [['assembler','/usr/bin/as'],['linker','/usr/bin/ld'],['cc','/usr/bin/cc'],['cxx','/usr/bin/g++']]) {
      const version=await command(label+'-version',bin,['--version']);
      if(label==='assembler'?!/^GNU assembler/.test(version):label==='linker'?!/^GNU ld/.test(version):!version.includes(lock.gccVersion)||!version.includes('Free Software Foundation')) fail('malformed or mixed diagnostic tool version');
    }
    const identities=[];
    for(const [index,driver] of ['/usr/bin/cc','/usr/bin/g++'].entries()) {
      if(!/gcc|g\+\+/.test(fs.realpathSync(driver)))fail('GCC-only diagnostic driver required');
      const item={...identity(driver),version:await command('driver-'+index+'-version',driver,['-dumpfullversion']),machine:await command('driver-'+index+'-machine',driver,['-dumpmachine'])};
      for(const tool of ['as','ld']) {
        const selected=await command('driver-'+index+'-'+tool,driver,['-print-prog-name='+tool]);
        if((path.isAbsolute(selected)?fs.realpathSync(selected):selected===tool?fs.realpathSync('/usr/bin/'+tool):'')!==fs.realpathSync('/usr/bin/'+tool))fail('mixed assembler/linker identity');
      }
      for(const library of ['libasan.so','libubsan.so','libstdc++.so','libgcc_s.so.1']) {
        const p=await command('driver-'+index+'-'+library,driver,['-print-file-name='+library]);
        if(!path.isAbsolute(p))fail('missing sanitizer runtime');item[library]=identity(p);
        const elf=await command('driver-'+index+'-'+library+'-elf','/usr/bin/readelf',['--file-header','--notes',item[library].path]);
        if(!/ELF/.test(elf)||!/\bDYN\b/.test(elf)) fail('malformed sanitizer ELF identity');
      }
      for(const helper of ['cc1plus','collect2']) {
        const selected=await command('driver-'+index+'-'+helper,driver,['-print-prog-name='+helper]);
        if(!path.isAbsolute(selected) || !fs.realpathSync(selected).startsWith('/usr/lib/gcc/') || path.basename(selected)!==helper) fail('mixed/malformed GCC helper identity');
        item[helper]=identity(selected);await command('driver-'+index+'-'+helper+'-version',selected,['--version']);
      }
      identities.push(item);
    }
    diagnosticFamily(lock,identities);result.identities=identities;save();
    // Evidence files are data only. Never execute or replay owner-recorded argv.
    const request=JSON.parse(diagnosticText(path.join(target,'diagnostic-inputs.json'),65536));
    if(request.schema!=='buzz.gcc-comdat-evidence/v1' || request.lockSha256!==hash(lockPath) || request.archiveSha256!==lock.nodeSourceSha256)fail('diagnostic evidence identity mismatch');
    const evidencePath=rel=>{if(typeof rel!=='string' || !/^[A-Za-z0-9_./+-]{1,512}$/.test(rel) || path.isAbsolute(rel) || path.posix.normalize(rel)!==rel || rel.split('/').some(p=>p==='.'||p==='..'||!p))fail('malformed diagnostic evidence path');const p=path.join(target,rel);if(fs.realpathSync(p)!==p || !fs.lstatSync(p).isFile())fail('unavailable diagnostic evidence');return p;};
    const object=evidencePath(request.object),argvFile=evidencePath(request.linkArgv);
    if(path.basename(object)!=='wasm-disassembler.o' || fs.statSync(object).size>64*1024*1024)fail('known V8 object unavailable/bounded');
    const argv=diagnosticTokens(JSON.parse(diagnosticText(argvFile,65536)));
    if(argv[0]!=='/usr/bin/g++' || !argv.some(a=>a.endsWith('mksnapshot')) || !argv.some(a=>a.endsWith('.o')||a.startsWith('@')))fail('mksnapshot link argv unavailable');
    retain('failed-link-argv.json',JSON.stringify(argv,null,2));
    const refs=argv.filter(a=>a.startsWith('@'));
    if(refs.length>1 || refs.length!==Number(Boolean(request.responseFile)) || refs.length && refs[0]!=='@'+request.responseFile)fail('malformed/missing response file reference');
    let responseTokens=[];
    if(request.responseFile){const p=evidencePath(request.responseFile),text=diagnosticText(p,65536);responseTokens=diagnosticResponse(text);retain('failed-link-response.txt',text);}
    diagnosticObjectReference(request.object,argv,responseTokens);
    result.failedEvidence={object:{relative:request.object,sha256:hash(object)},argv:{relative:request.linkArgv,sha256:hash(argvFile)},requestSha256:hash(path.join(target,'diagnostic-inputs.json'))};result.unavailable=['Raw R1/R2 owner logs remain unavailable; only the supplied failed-object/argv projection is measured.'];save();
    for(const [label,args] of [['groups',['--section-groups','--wide']],['relocations',['--relocs','--wide']],['symbols',['--symbols','--wide']]])await command('v8-'+label,'/usr/bin/readelf',[...args,object]);
    await command('v8-objdump','/usr/bin/objdump',['--section-headers','--reloc','--syms',object]);
    await diagnosticProbe(command,retain,output,identities);
    if(JSON.stringify(source(infrastructure))!==JSON.stringify(result.infrastructure))fail('infrastructure changed during diagnostic');
    result.status='DIAGNOSTIC_ONLY_PENDING_REVIEW';
  } catch(e) {result.status='BLOCKED';result.blocker=e.message;process.exitCode=1;}
  finally {save();}
}

async function main() {
  if(!['plan','verify-source','build-runtime','run','diagnose-toolchain'].includes(mode)) fail('usage: bash qualify-host-approval.sh plan|build-runtime|run LOCK ARCHIVE [TARGET INFRA OUTPUT]');
  const lock=inputs();
  if(mode==='plan') {
    console.log(JSON.stringify({lock,gates,diagnostics:['clock-regression','minimal Node-API Promise control'],sourceMount:'read-only',outputMount:'separate writable',compiler:'/usr/bin/cc',cxx:'/usr/bin/g++',network:'none'})); return;
  }
  if(mode==='verify-source') { console.log(JSON.stringify(source(target))); return; }
  if(mode==='diagnose-toolchain') { await diagnose(lock); return; }
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
  if(mode==='run' || mode==='diagnose-toolchain') try {
    const stat=fs.lstatSync(output);
    if(path.isAbsolute(output) && fs.realpathSync(output)===output && stat.isDirectory() && stat.uid===process.getuid() && (stat.mode&0o777)===0o700 && !fs.readdirSync(output).length && ![target,infrastructure].some(p=>p && (output===p || output.startsWith(p+'/'))))
      fs.writeFileSync(path.join(output,mode==='run'?'result.json':'diagnostic.json'),JSON.stringify({schema:mode==='run'?'buzz.approval-qualification-result/v1':'buzz.gcc-comdat-diagnostic/v1',status:'BLOCKED',blocker:e.message,gates:[],liveAcceptance:'NOT_READY'},null,2),{flag:'wx',mode:0o600});
  } catch {}
  console.error('BLOCKED: '+e.message);process.exitCode=1;
});
JS
