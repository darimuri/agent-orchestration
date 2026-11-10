// Mandatory synthetic bridge gates. Missing prerequisites FAIL as BLOCKED.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { createApprovalDecisionService } from '../job-preparation/approval-service.mjs';
import { buildHostApprovalNode, nodePrerequisites, nodeFlags, nodeImports } from './build-host-approval-node.mjs';
const native=fileURLToPath(new URL('../job-preparation/native/host-approval-node.c',import.meta.url));
const authority=fileURLToPath(new URL('../job-preparation/native/host-approval-dbus.c',import.meta.url));
const service=fileURLToPath(new URL('../job-preparation/approval-service.mjs',import.meta.url));
const fixture=fileURLToPath(new URL('../tests/job-preparation/host-approval-service-fixture.c',import.meta.url));
const worker=fileURLToPath(new URL('../tests/job-preparation/host-approval-service-worker.mjs',import.meta.url));
const env=Object.freeze({LANG:'C',LC_ALL:'C',TZ:'UTC'});
const sha=p=>createHash('sha256').update(fs.readFileSync(p)).digest('hex');
function scratch(t){const p=fs.mkdtempSync(path.join(process.env.TEST_EXECUTABLE_TMPDIR??os.tmpdir(),'approval-service-'));fs.chmodSync(p,0o700);t.after(()=>fs.rmSync(p,{recursive:true,force:true}));return p;}
function run(bin,args,cwd){const r=spawnSync(bin,args,{cwd,env,encoding:'utf8',timeout:60000,maxBuffer:16777216});assert.ifError(r.error);assert.equal(r.status,0,r.stderr);return r.stdout;}
export const bridgeScenarios=Object.freeze(['approve','reject','inspect','handles','denied','malformed','hold','abort','close-pending','gc-pending','gc-live','env-shutdown','authority-loss','clock-regression','reentry',...['requestId','intentDigest','decision','ownerId','policyDigest'].map(k=>'binding-'+k),'lock','enospc','zero-write','short-write','fsync','readback','candidate-crash','final-crash','reply-failure','native-allocation','native-send','native-watch','native-credentials','reference-failure','wrapper-allocation','double-completion','null-completion']);

test('bridge import is inert and nonroot construction fails without journal writes',t=>{
  const dir=scratch(t),before=fs.readdirSync(dir);
  assert.throws(()=>createApprovalDecisionService({directory:dir,policy:{},ownerUid:1000,clock:Date.now,nativeArtifact:{}}),/approval_unavailable/);
  assert.deepEqual(fs.readdirSync(dir),before);
  const js=fs.readFileSync(service,'utf8');
  assert.deepEqual([...js.matchAll(/^export (?:async )?function (\w+)/gm)].map(x=>x[1]),['createApprovalDecisionService']);
  assert(!/process\.env|child_process|\.submit\(|\.reserve\(|setInterval|setTimeout|http:|https:/.test(js));
});
test('Node-API code pins handles, thread affinity and lease ownership through reply',()=>{
  const c=fs.readFileSync(native,'utf8');
  const prototype=c.indexOf('NAPI_MODULE_EXPORT int32_t NODE_API_MODULE_GET_API_VERSION(void);');
  assert(prototype>=0 && prototype<c.indexOf('NAPI_MODULE_INIT() {'), 'version export must have a prior prototype under -Wmissing-prototypes');
  for(const word of ['napi_type_tag_object','napi_check_object_type_tag','napi_create_reference','napi_add_env_cleanup_hook','SYS_gettid','ha_authorize','ha_call_reply','ha_lease_valid','ha_lease_free','HA_MAX_HANDLES','HA_MAX_SERVERS'])assert(c.includes(word),word);
  assert(c.indexOf('int r = ok ? ha_call_reply')<c.indexOf('finish(c); s->operation = false'));
  const production=c.replace(/#ifdef HA_TEST[\s\S]*?#else/g,'').replace(/#ifdef HA_TEST[\s\S]*?#endif/g,'');assert(!/getenv\(|system\(|execve\(|fork\(/.test(production));
});
test('HA_TEST construction requires bounded ready processing and fixture observes async phases',()=>{
  const c=fs.readFileSync(native,'utf8'),w=fs.readFileSync(worker,'utf8');
  const handshake=c.slice(c.indexOf('static int test_bus_ready'),c.indexOf('static unsigned node_fault'));
  assert(handshake.includes('turn < 1024u'));assert(handshake.includes('now >= deadline'));
  assert(handshake.includes('sd_bus_is_ready(bus)'));assert(handshake.includes('sd_bus_process(bus, NULL)'));
  assert(handshake.includes('sd_bus_wait(bus, left < 10000u ? left : 10000u)'));
  assert(handshake.includes('return -ETIMEDOUT'));
  const start=c.indexOf('r = sd_bus_start(bus)'),ready=c.indexOf('r = test_bus_ready(bus)'),construct=c.indexOf('r = ha_test_server_new');
  assert(start>=0 && start<ready && ready<construct && construct<c.indexOf('sd_bus_unref(bus)',construct));
  assert(w.includes('inspect:2,decide:1,authorize:1,authorized:1,settled:1,reply:1'));
  assert(w.includes('await pendingFault'));assert(w.includes('await ready(authority,/CHECK'));
  assert(!/setTimeout\(.*(?:service\.close|authority\.cp\.kill|time=epoch-1|process\.exit)/.test(w));
});
test('offline addon flags and exact Node imports retain hardening without standalone -z defs',()=>{
  assert(Object.isFrozen(nodeFlags)&&Object.isFrozen(nodeImports));
  for(const f of ['-std=c17','-Werror','-Wconversion','-Wshadow','-fPIC','-shared','-DNAPI_VERSION=8','-Wl,-z,relro,-z,now,-z,noexecstack'])assert(nodeFlags.includes(f));
  assert(!nodeFlags.some(f=>f.includes(',defs')));
  const used=new Set([...fs.readFileSync(native,'utf8').matchAll(/\b(napi_\w+)\s*\(/g)].map(m=>m[1]));assert.deepEqual([...used].sort(),[...nodeImports].sort());
  assert(nodePrerequisites().every(p=>path.isAbsolute(p)));
});
test('MANDATORY protected offline production addon/manifest and actual inert load',t=>{
  const missing=nodePrerequisites();if(missing.length)t.diagnostic('BLOCKED native addon prerequisites: '+missing.join(', '));
  const dir=scratch(t),built=buildHostApprovalNode(dir),m=JSON.parse(fs.readFileSync(built.manifestPath,'utf8'));
  assert.equal(m.type,'buzz.host-approval-node');assert.equal(m.test,false);assert.equal(m.napi,8);assert.equal(m.runtime.version,process.version);assert.equal(m.abi,process.versions.modules);
  assert.equal(built.digest,sha(built.path));assert.equal(built.manifestDigest,sha(built.manifestPath));assert.equal(fs.statSync(built.path).mode&0o7777,0o755);assert.equal(fs.statSync(built.manifestPath).mode&0o7777,0o600);
  assert(m.inputs.some(p=>p.path.endsWith('/node_api.h')));assert(m.inputs.some(p=>p.path.endsWith('/systemd/sd-bus.h')));assert(m.inputs.some(p=>p.path.endsWith('/host-approval-dbus.c')));
  assert(m.imports.filter(s=>s.startsWith('napi_')).every(s=>nodeImports.includes(s)));
  const symbols=run('/usr/bin/readelf',['-Ws',built.path],dir);assert(!/ha_test_|fixture/.test(symbols));assert(!m.argv.some(s=>s.includes('HA_TEST')));
  const output=run(process.execPath,['--input-type=module','-e',"import{createRequire}from'node:module';const n=createRequire(import.meta.url)(process.argv[1]);console.log(Reflect.ownKeys(n));try{n.createServer({},{});process.exit(1)}catch{}",built.path],dir);assert(output.includes('createServer'));
});
for(const sanitizer of [false,true])test('MANDATORY actual terminal/addon/service/journal '+(sanitizer?'ASan+UBSan Node lifetime':'strict C17'),{timeout:240000},async t=>{
  const missing=[...nodePrerequisites(),...(!fs.existsSync('/usr/bin/dbus-daemon')?['/usr/bin/dbus-daemon']:[])];
  assert.equal(missing.length,0,'BLOCKED compiler/libsystemd/broker/Node prerequisites: '+missing.join(', '));
  // An instrumented Node host is required, not an LD_PRELOAD/order suppression.
  if(sanitizer)assert.equal(Number(process.config.variables.asan),1,'BLOCKED compatible measured ASan Node runtime required; no preload/suppression fallback');
  const dir=scratch(t),addon=path.join(dir,'fixture.node'),executable=path.join(dir,'fixture');
  const flags=run('/usr/bin/pkg-config',['--cflags','--libs','libsystemd'],dir).trim().split(/\s+/);assert(flags.every(f=>['-lsystemd','-pthread'].includes(f)||/^-[IL]\/[A-Za-z0-9_./+-]+$/.test(f)));
  const instrument=sanitizer?['-O1','-fsanitize=address,undefined','-fno-omit-frame-pointer']:[];
  const header=path.resolve(path.dirname(process.execPath),'../include/node');
  // Regress permissive host umasks: the unchanged client must still accept
  // this fixture as its protected synthetic agent, without relaxing its checks.
  const previous=process.umask(0o002);
  try {
    run('/usr/bin/cc',[...nodeFlags,...instrument,'-DHA_TEST','-I'+header,native,authority,'-o',addon,...flags,'-lm'],dir);
    run('/usr/bin/cc',[...nodeFlags.filter(f=>f!=='-shared'&&f!=='-fPIC'),...instrument,'-fPIE','-pie',fixture,'-o',executable,...flags,'-lm'],dir);
  } finally { process.umask(previous); }
  for(const artifact of [addon,executable]) {
    fs.chmodSync(artifact,0o755);
    const stat=fs.lstatSync(artifact);
    assert(stat.isFile());assert.equal(stat.uid,process.getuid());assert.equal(stat.nlink,1);
    assert.equal(stat.mode&0o7777,0o755);
  }
  for(const scenario of bridgeScenarios){
    const home=path.join(dir,scenario);fs.mkdirSync(home,{mode:0o700});
    const cp=spawn(process.execPath,['--expose-gc',worker,home,addon,executable,scenario],{cwd:dir,env:{...env,...(sanitizer?{ASAN_OPTIONS:'detect_leaks=1:abort_on_error=1',UBSAN_OPTIONS:'halt_on_error=1:print_stacktrace=1'}:{})},detached:true,stdio:['ignore','pipe','pipe']});
    let stdout='',stderr='';cp.stdout.on('data',b=>stdout+=b);cp.stderr.on('data',b=>stderr+=b);const timer=setTimeout(()=>cp.kill('SIGKILL'),12000);
    try{
      const [code,signal]=await once(cp,'exit');
      if(scenario.endsWith('-crash')){assert.equal(signal,'SIGKILL');const files=fs.readdirSync(path.join(home,'journal'));assert(files.includes('admission.lock'));assert(files.some(n=>n.endsWith('.decision.candidate')));if(scenario==='final-crash')assert(files.some(n=>n.endsWith('.decision.json')));const restart=run(process.execPath,[worker,home,addon,executable,'restart-deny'],dir);assert(restart.includes('RESTART_DENIED'));}
      else if(scenario==='env-shutdown'){assert.equal(code,0,stderr);assert(stdout.includes('ENV_SHUTDOWN'));}
      else{assert.equal(signal,null,stderr);assert.equal(code,0,stderr);assert(stdout.includes('NOT live Polkit/TTY/root/store acceptance'),scenario);}
      assert(!/AddressSanitizer|runtime error:/.test(stderr),stderr);
    }finally{clearTimeout(timer);try{process.kill(-cp.pid,'SIGKILL');}catch(e){if(e.code!=='ESRCH')throw e;}}
    t.diagnostic('synthetic actual bridge scenario: '+scenario);
  }
  t.diagnostic(bridgeScenarios.length+' actual bridge scenarios; simulated root/session metadata; no live acceptance');
});
