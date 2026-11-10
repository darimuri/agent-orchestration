// Isolated synthetic worker. Only metadata and test transport are substituted;
// decisions still require an actual native call/lease and actual journal writes.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mock } from 'node:test';
import { createAdmissionStore } from '../../job-preparation/admission-store.mjs';
import { digest, DEVELOPER_CAPABILITIES } from '../../job-preparation/intent.mjs';
const [directory, addon, executable, scenario] = process.argv.slice(2);
assert(directory && addon && executable && scenario);
const actualUid = process.getuid(), id = '1'.repeat(32), children = new Set();
const root = fileURLToPath(new URL('../../job-preparation/', import.meta.url));
let time = Date.now(); const epoch = time;
const policy = Object.freeze({ version:1,ownerId:'fixture-owner',developerAgentId:'developer-a',repository:'example/project',baseRef:'main',baseSha:'a'.repeat(40),policyVersion:'p1',capabilityProfileVersion:'developer-v1',capabilityProfileDigest:digest({version:'developer-v1',role:'developer',capabilities:DEVELOPER_CAPABILITIES}),slotNamespace:'fixture-v1',approvalLifetimeMs:20000,jobLifetimeMs:30000,authorityTimeoutMs:1500 });
const clock = () => time;
function custody() {
  for (const key of ['lstatSync','fstatSync']) {
    const original = fs[key]; mock.method(fs,key,(...args)=> {
      const s = original(...args), big = typeof s.uid === 'bigint';
      const copy = Object.assign(Object.create(Object.getPrototypeOf(s)),s);
      if ([0,actualUid].includes(Number(s.uid))) copy.uid = big ? 0n : 0;
      if (s.isDirectory()) copy.mode = big ? s.mode & ~0o7022n : s.mode & ~0o7022;
      return copy;
    });
  }
  mock.method(process,'getuid',()=>0); mock.method(process,'geteuid',()=>0);
}
function child(bin,args) {
  const cp = spawn(bin,args,{env:{LANG:'C',LC_ALL:'C',TZ:'UTC'},stdio:['ignore','pipe','pipe']});children.add(cp);
  let stdout='',stderr='';cp.stdout.on('data',b=>{stdout+=b;});cp.stderr.on('data',b=>{stderr+=b;});
  const done = new Promise((resolve,reject)=>{cp.once('error',reject);cp.once('close',(code,signal)=>{children.delete(cp);resolve({code,signal,stdout,stderr});});});
  return {cp,done,output:()=>stdout};
}
async function ready(c,pattern) {
  const until=Date.now()+5000;
  while(!pattern.test(c.output())) {if(c.cp.exitCode!==null||c.cp.signalCode!==null||Date.now()>until)throw Error('fixture readiness: '+c.output());await new Promise(r=>setTimeout(r,5));}
}
let service,interval;
try {
  if(scenario==='restart-deny') {
    custody();const restarted=createAdmissionStore({directory:path.join(directory,'journal'),policy,clock,decisionAuthority:()=>{throw Error('restart must not authorize');}});
    assert.equal(restarted.inspect(id).phase,'outcome_unknown');console.log('RESTART_DENIED synthetic');
  } else {
  const busDir=path.join(directory,'bus');fs.mkdirSync(busDir,{mode:0o700});
  const broker=child('/usr/bin/dbus-daemon',['--session','--nofork','--nopidfile','--print-address=1','--address=unix:path='+path.join(busDir,'socket')]);
  await ready(broker,/\n/);const address=broker.output().trim();assert.match(address,/^unix:path=/);
  const authorityMode = ['denied','malformed','hold'].includes(scenario) ? scenario : ['abort','close-pending','gc-pending','env-shutdown','authority-loss','clock-regression'].includes(scenario)?'hold':'happy';
  const authority=child(executable,['authority',address,authorityMode]);await ready(authority,/READY/);
  // Do not place broker socket evidence inside the actual store inventory.
  const storeDir=path.join(directory,'journal');fs.mkdirSync(storeDir,{mode:0o700});
  custody();const storeOptions={directory:storeDir,policy,clock,decisionAuthority:()=>{throw Error('fixture seeding has no decision authority');}};
  const seed=createAdmissionStore(storeOptions);
  const proposal=JSON.stringify({version:1,requestId:id,jobId:'bridge-fixture',repository:policy.repository,baseRef:policy.baseRef,baseSha:policy.baseSha,approvalExpiresAt:new Date(epoch+20000).toISOString(),jobExpiresAt:new Date(epoch+30000).toISOString(),taskId:'task55',assignmentId:'assignment55',channelId:'00000000-0000-0000-0000-000000000000',threadId:'b'.repeat(64)});
  assert.equal(seed.submit(proposal).phase,'pending');
  const require=createRequire(import.meta.url);const native=require(addon);
  globalThis.__fixtureNative=native;globalThis.__fixtureAddress=address;
  let captures=0,lastCall,errors=0;
  const phases={inspect:0,decide:0,authorize:0,authorized:0,settled:0,reply:0};
  globalThis.__fixturePhase=name=>{assert(Object.hasOwn(phases,name));phases[name]++;};
  const afterCheck=['abort','close-pending','gc-pending','env-shutdown','authority-loss','clock-regression'];
  let pendingFault,faultApplied=false;
  globalThis.__fixtureAuthorize=()=>{
    phases.authorize++;
    if(afterCheck.includes(scenario)) {
      assert.equal(pendingFault,undefined);
      pendingFault=ready(authority,/CHECK subject=:[0-9.]+ action=org\.buzz\.host-approval\.approve flags=0/).then(()=>{
        if(scenario==='abort')globalThis.__fixtureAbort.abort();
        if(scenario==='close-pending')service.close();
        if(scenario==='gc-pending')globalThis.gc();
        if(scenario==='authority-loss')authority.cp.kill('SIGTERM');
        if(scenario==='clock-regression')time=epoch-1;
        if(scenario==='env-shutdown'){console.log('ENV_SHUTDOWN after CHECK synthetic');process.exit(0);}
        faultApplied=true;
      }).catch(error=>{errors++;console.error(error);service.close();});
    }
  };
  globalThis.__fixtureBeforeReply=()=>{if(scenario==='reply-failure')native.testFault(2);};
  globalThis.__fixtureObserve=(call,request,decision)=> {
    const prior=lastCall;captures++;phases[decision?'decide':'inspect']++;lastCall=call;assert.equal(request,id);
    if(prior)assert.throws(()=>prior.authorize.call(call,{},epoch+1000,new AbortController().signal));
    for(const fake of [{},{...call},JSON.parse(JSON.stringify(call))])assert.throws(()=>call.reply.call(fake,{phase:'pending',intentDigest:'',summary:''}));
    if(scenario.startsWith('binding-')&&decision){const wrong={requestId:id,intentDigest:seed.inspect(id).intentDigest,decision,ownerId:policy.ownerId,policyDigest:digest(policy)};const field=scenario.slice(8);wrong[field]=field==='requestId'?'f'.repeat(32):field==='decision'?'reject':field.includes('Digest')?'f'.repeat(64):'wrong-owner';try{void call.authorize(wrong,epoch+1000,new AbortController().signal).catch(()=>{});}catch{}}
    assert.throws(()=>call.authorize.call({...call},{},epoch+1000,new AbortController().signal));
    if(scenario==='reentry'&&decision)assert.throws(()=>service.processOnce());
    if(scenario==='abort'&&decision){globalThis.__fixtureAbort=new AbortController();globalThis.__fixtureSignal=globalThis.__fixtureAbort.signal;}
  };
  let source=fs.readFileSync(path.join(root,'approval-service.mjs'),'utf8');
  source=source.replace("createRequire(import.meta.url)",`createRequire(${JSON.stringify(pathToFileURL(path.join(root,'approval-service.mjs')).href)})`)
    .replace("new URL('./native/', import.meta.url)",`new URL(${JSON.stringify(pathToFileURL(path.join(root,'native/')).href)})`)
    .replace("from './admission-store.mjs'",`from ${JSON.stringify(pathToFileURL(path.join(root,'admission-store.mjs')).href)}`)
    .replace("from './intent.mjs'",`from ${JSON.stringify(pathToFileURL(path.join(root,'intent.mjs')).href)}`)
    .replace('options.ownerUid === 10001','false /* synthetic UID mapping only */')
    .replace('const native = loadArtifact(options.nativeArtifact);','const native = globalThis.__fixtureNative;')
    .replace('native.createServer(config, callbacks)','native.createServer(config, callbacks, globalThis.__fixtureAddress)')
    .replace('inspect(call, id) {','inspect(call, id) { globalThis.__fixtureObserve(call, id);')
    .replace('decide(call, id, decision) {','decide(call, id, decision) { globalThis.__fixtureObserve(call, id, decision);')
    .replace('const lease = await call.authorize(binding, attemptDeadline, signal);','globalThis.__fixtureAuthorize(); const lease = await call.authorize(binding, attemptDeadline, signal); globalThis.__fixturePhase("authorized");')
    .replace('const result = check(await store.decide(id, decision));','const result = check(await store.decide(id, decision)); globalThis.__fixturePhase("settled");')
    .replace('call.reply({ phase: result.phase, receiptId });','globalThis.__fixtureBeforeReply(); call.reply({ phase: result.phase, receiptId }); globalThis.__fixturePhase("reply");');
  if(scenario==='gc-live')source=source.replace('usable(); const authorizedAt = clock();','globalThis.gc(); usable(); const authorizedAt = clock();');
  if(scenario==='abort')source=source.replace('call.authorize(binding, attemptDeadline, signal)','call.authorize(binding, attemptDeadline, globalThis.__fixtureSignal)');
  const module=await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'));
  if(scenario==='native-watch') {
    native.testFault(3);assert.throws(()=>module.createApprovalDecisionService({directory:storeDir,policy,ownerUid:actualUid,clock,nativeArtifact:{}}));
    console.log(JSON.stringify({scenario,synthetic:true,notLive:'NOT live Polkit/TTY/root/store acceptance'}));
  } else {
  service=module.createApprovalDecisionService({directory:storeDir,policy,ownerUid:actualUid,clock,nativeArtifact:{}});
  assert.deepEqual(Reflect.ownKeys(service).sort(),['close','processOnce']);assert(Object.isFrozen(service));
  interval=setInterval(()=>{try{service.processOnce();}catch{errors++;}},1);
  const disk=()=>fs.readdirSync(storeDir).sort().map(n=>[n,fs.readFileSync(path.join(storeDir,n),'utf8')]);
  const before=disk();let result=await child(executable,['raw',address,'Inspect',id,'approve']).done;assert.equal(result.code,0,result.stderr);assert.deepEqual(disk(),before);assert.equal(authority.output().includes('CHECK'),false);
  if(scenario==='inspect') { assert.equal(captures,1); }
  else {
    let fault=false;
    const original={writeSync:fs.writeSync,fsyncSync:fs.fsyncSync,readSync:fs.readSync,openSync:fs.openSync};
    const fileFor=fd=>{try{return fs.readlinkSync('/proc/self/fd/'+fd);}catch{return '';}};
    if(['enospc','zero-write','short-write','fsync','readback','candidate-crash','final-crash'].includes(scenario)) {
      mock.method(fs,'writeSync',(...args)=>{
        const file=fileFor(args[0]);
        if(file.includes('.decision.')&&!fault){fault=true;
          if(scenario==='enospc')throw Object.assign(Error('synthetic enospc'),{code:'ENOSPC'});
          if(scenario==='zero-write')return 0;
          if(scenario==='short-write')return original.writeSync(args[0],args[1],args[2],Math.max(1,Math.floor(args[3]/2)),args[4]);
        }
        const n=original.writeSync(...args);
        if((scenario==='candidate-crash'&&file.endsWith('.decision.candidate'))||(scenario==='final-crash'&&file.endsWith('.decision.json')))process.kill(process.pid,'SIGKILL');
        return n;
      });
      if(scenario==='fsync')mock.method(fs,'fsyncSync',(...args)=>{if(fileFor(args[0]).includes('.decision.'))throw Error('synthetic fsync');return original.fsyncSync(...args);});
      if(scenario==='readback')mock.method(fs,'readSync',(...args)=>{if(fileFor(args[0]).includes('.decision.'))throw Error('synthetic readback');return original.readSync(...args);});
    }
    if(scenario==='lock')fs.writeFileSync(path.join(storeDir,'admission.lock'),'{}',{mode:0o600});
    const faultModes={'native-allocation':1,'native-send':2,'native-watch':3,'native-credentials':4,'reference-failure':5,'wrapper-allocation':6,'double-completion':7,'null-completion':8};
    if(faultModes[scenario])native.testFault(faultModes[scenario]);
    const decision=scenario==='reject'?'reject':'approve';
    result=await child(executable,['terminal',address,decision,id,executable,scenario]).done;
    const positive=['approve','reject','short-write','handles','gc-live'].includes(scenario);
    if(positive) {
      assert.equal(result.code,0,JSON.stringify({result,phases,errors,authority:authority.output(),files:fs.readdirSync(storeDir)}));assert.equal(errors,0);
      assert.deepEqual(phases,{inspect:2,decide:1,authorize:1,authorized:1,settled:1,reply:1});
      await ready(authority,/CHECK subject=:[0-9.]+ action=org\.buzz\.host-approval\.(approve|reject) flags=1/);
      const observed=seed.inspect(id);assert.equal(observed.phase,decision==='approve'?'approved':'rejected');assert.match(observed.decisionReceiptId,/^[a-f0-9]{32}$/);assert(result.stdout.includes(observed.decisionReceiptId));
      const summary=result.stdout.indexOf('Root-provided summary'),agent=result.stdout.indexOf('FAKE_AGENT');assert(summary>=0&&agent>summary);
      const subject=/FAKE_AGENT subject=(:[0-9.]+)/.exec(result.stdout)?.[1];assert(subject&&authority.output().includes('subject='+subject+' '));
      assert.equal(fs.readdirSync(storeDir).length,4);assert.deepEqual(fs.readFileSync(path.join(storeDir,id+'.decision.candidate')),fs.readFileSync(path.join(storeDir,id+'.decision.json')));
      const history=disk(),checks=authority.output().split('CHECK').length;
      result=await child(executable,['raw',address,'Decide',id,decision]).done;assert.equal(result.code,0);assert(result.stdout.includes(observed.decisionReceiptId));assert.deepEqual(disk(),history);
      result=await child(executable,['raw',address,'Decide',id,decision==='approve'?'reject':'approve']).done;assert.equal(result.code,0);assert(result.stdout.includes('conflict'));assert.deepEqual(disk(),history);assert.equal(authority.output().split('CHECK').length,checks);
      const restart=createAdmissionStore(storeOptions);assert.deepEqual(restart.inspect(id),observed);assert(!fs.readdirSync(storeDir).some(n=>n.includes('reservation')));
    } else {
      assert.notEqual(result.code,0);
      if(scenario==='reply-failure'){assert.equal(seed.inspect(id).phase,'approved');assert.equal(fs.readdirSync(storeDir).length,4);assert.throws(()=>service.processOnce());}
      else assert.notEqual(seed.inspect(id).phase,'approved');
      if(['enospc','zero-write','fsync','readback','lock'].includes(scenario)){assert.throws(()=>service.processOnce());assert.throws(()=>module.createApprovalDecisionService({directory:storeDir,policy,ownerUid:actualUid,clock,nativeArtifact:{}}));}
    }
    if(afterCheck.includes(scenario)) {
      assert(pendingFault);await pendingFault;assert.equal(faultApplied,true);
      assert.equal(phases.decide,1);assert.equal(phases.authorize,1);
      assert.match(authority.output(),/CHECK subject=/);
    }
    if(lastCall)assert.throws(()=>lastCall.authorize({},epoch+1000,new AbortController().signal));
  }
  console.log(JSON.stringify({scenario,captures,phases,synthetic:true,notLive:'NOT live Polkit/TTY/root/store acceptance'}));
  }
  }
} finally {
  clearInterval(interval);try{service?.close();}catch{}mock.restoreAll();
  for(const cp of children){if(cp.exitCode===null&&cp.signalCode===null){const done=once(cp,'exit');cp.kill('SIGTERM');const timer=setTimeout(()=>cp.kill('SIGKILL'),500);try{await done;}finally{clearTimeout(timer);}}}
}
