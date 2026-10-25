import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { schnorr } from '../host-operator-auth/node_modules/@noble/curves/secp256k1.js';
import { createRevisionObservationBridge } from '../host-operator-auth/revision-observation.mjs';
import { createFileEventPlacer } from '../host-operator-auth/event-placement.mjs';
import { createLocalEventIngress } from '../host-operator-auth/local-ingress.mjs';
import { createFileEventResolver } from '../host-operator-auth/event-source.mjs';
import { createAuthorizationAdapter } from '../host-operator-auth/authorization.mjs';
import { HostOperatorJournal } from './host-operator-journal.mjs';
import { descriptor, digest, ProtocolError } from './host-operator-protocol.mjs';

// Public BIP340 vector 0. Standalone DTO policy is an explicit fixture; actual
// Gateway provider/writer composition is covered by the separate pinned suite.
const scalar=Buffer.from('0'.repeat(63)+'3','hex'),now=1800000000000;
const ownerPubkey='f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9',targetPubkey='e'.repeat(64),channelId='00000000-0000-0000-0000-000000000001',threadId='d'.repeat(64);
const source={repository:'test-org/project',baseRef:'main',baseSha:'b'.repeat(40),workspaceId:'fixture',sourceDigest:'c'.repeat(64)};
const request={version:1,requestId:'one',taskId:'task-one',jobId:'job-one',repository:source.repository,baseRef:source.baseRef,baseSha:source.baseSha,operationId:'status.revision',channelId,threadId};
const canary='SECRET_OBSERVATION_CANARY';
function signed(r=request,changes={}) {
  const e={pubkey:ownerPubkey,kind:9,created_at:now/1000,tags:[['h',channelId],['e',threadId,'','root'],['p',targetPubkey]],content:JSON.stringify({type:'host-operator.request',version:1,request:r,descriptorDigest:digest(descriptor(request,source)),expiresAt:now+600000}),...changes};
  e.id=createHash('sha256').update(JSON.stringify([0,e.pubkey,e.created_at,e.kind,e.tags,e.content])).digest('hex');e.sig=Buffer.from(schnorr.sign(Buffer.from(e.id,'hex'),scalar,new Uint8Array(32))).toString('hex');return e;
}
function facts(r,who,d) {
  return {...Object.fromEntries(['taskId','jobId','repository','baseRef','baseSha','operationId','channelId','threadId'].map(k=>[k,r[k]])),requesterId:who.requesterId,role:'owner',ownerPubkey,mentionPubkey:ownerPubkey,targetPubkey,
    workspaceId:d.workspaceId,sourceDigest:d.sourceDigest,descriptorDigest:digest(d),requestHash:digest(r),enabled:true,status:'active',requesterMember:true,ownerAllowed:true,allowedOperations:['status.revision'],verifiedAt:now,expiresAt:now+600000};
}
function fixture(t,{admit=true}={}) {
  assert.notEqual(process.getuid(),0);const root=fs.mkdtempSync(path.join(os.tmpdir(),'revision-bridge-'));fs.chmodSync(root,0o700);t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const eventDirectory=path.join(root,'events'),journalDirectory=path.join(root,'journal'),sourceDirectory=path.join(root,'source');for(const p of [eventDirectory,journalDirectory,sourceDirectory])fs.mkdirSync(p,{mode:0o700});
  fs.mkdirSync(path.join(sourceDirectory,'.git'),{mode:0o700});const head=path.join(sourceDirectory,'.git/HEAD');fs.writeFileSync(head,source.baseSha+'\n',{mode:0o600});
  let clock=now,calls=0,hook=()=>{},current=facts;const receipts=new Map();
  const options={eventDirectory,journalDirectory,sourceDirectory,uid:process.getuid(),ownerPubkey,requesterId:'owner',mentionPubkey:ownerPubkey,targetPubkey,channelId,threadId,source:{...source},clock:()=>clock,monotonic:()=>0,
    currentJob:(...a)=>{hook(++calls);return current(...a);},verifyReceipt:e=>{if(!receipts.has(e.ref))throw Error(canary+root);return receipts.get(e.ref);}};
  const event=signed(),raw=JSON.stringify(event),r={...request,authorizationEventId:event.id};
  const {sourceDirectory:_source,...ingressOptions}=options;
  const ingress=createLocalEventIngress(ingressOptions),plan=admit?ingress.ingest(raw):null;
  if(admit)assert.equal(plan.status,'intent');calls=0;
  const resolver=createFileEventResolver({directory:eventDirectory,uid:options.uid,clock:options.clock,monotonic:options.monotonic});
  const journal=new HostOperatorJournal({directory:journalDirectory,source,ownerPubkey,authorize:createAuthorizationAdapter({...options,resolveEvent:resolver}),verifyReceipt:options.verifyReceipt,clock:options.clock});
  const bridge=createRevisionObservationBridge(options),state=path.join(journalDirectory,'state.json'),eventFile=path.join(eventDirectory,event.id+'.json');
  const expected=plan?{intentId:plan.intent.intentId,intentDigest:plan.intentDigest}:{intentId:'absent',intentDigest:'f'.repeat(64)};
  const record=(p=plan)=>{const ref='receipt-'+receipts.size;receipts.set(ref,{version:1,receiptId:ref,intentId:p.intent.intentId,intentDigest:p.intentDigest,requestHash:digest(r),step:p.intent.step,outcome:'success',finishedAt:clock,evidenceRef:ref,evidenceDigest:'f'.repeat(64),summary:{passed:1,failed:0,skipped:0,exitCode:0,signal:null}});return journal.record(r,{ref});};
  return {root,head,options,event,raw,r,expected,plan,ingress,journal,bridge,state,eventFile,record,receipts,disk:()=>fs.existsSync(state)?fs.readFileSync(state,'utf8'):'',time:v=>{clock=v;},hook:fn=>{calls=0;hook=fn;},current:fn=>{current=fn;},calls:()=>calls};
}
function patch(object,name,wrapper,work){const orig=object[name];object[name]=wrapper(orig);try{return work();}finally{object[name]=orig;}}
function denied(fn,f,code='revision_observation_denied'){assert.throws(fn,e=>{assert.equal(e.code,code);assert.equal(e.message,code);assert.equal(e.stack,code);assert(!JSON.stringify(e).includes(canary));assert(!JSON.stringify(e).includes(f.root));return true;});}
function safe(f,value){const text=JSON.stringify(value);assert(Buffer.byteLength(text)<=4096);for(const x of [f.root,f.raw,f.event.sig,canary,'receipt','completed','READY'])assert(!text.includes(x));}
function noHead(f,work){let calls=0;const result=patch(fs,'openSync',orig=>(name,...a)=>{if(name===f.head)calls++;return orig(name,...a);},work);assert.equal(calls,0,'no observation allowed');return result;}
const child=`import fs from 'node:fs';
import {createRevisionObservationBridge} from ${JSON.stringify(new URL('../host-operator-auth/revision-observation.mjs',import.meta.url).href)};
import {digest} from ${JSON.stringify(new URL('./host-operator-protocol.mjs',import.meta.url).href)};
const {options,raw,expected,point}=JSON.parse(fs.readFileSync(0,'utf8'));
const now=${now},ownerPubkey=${JSON.stringify(ownerPubkey)},targetPubkey=${JSON.stringify(targetPubkey)},facts=${facts.toString()};
const sync=fs.fsyncSync;let held=false;fs.fsyncSync=fd=>{if(fs.existsSync(options.journalDirectory+'/journal.lock')&&!held){held=true;if(point==='kill')process.kill(process.pid,'SIGKILL');if(point==='hold')Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,25);}return sync(fd);};
const bridge=createRevisionObservationBridge({...options,currentJob:facts,verifyReceipt:()=>{throw Error('fixture');},clock:()=>now,monotonic:()=>0});
try{process.stdout.write(JSON.stringify(bridge.observe(raw,expected)));}catch(e){process.stdout.write(JSON.stringify({code:e.code}));}`;
function launch(f,point){const {currentJob,verifyReceipt,clock,monotonic,...options}=f.options;const p=spawn(process.execPath,['--input-type=module','-e',child],{stdio:['pipe','pipe','pipe']});let out='',err='';p.stdout.on('data',b=>{out+=b;});p.stderr.on('data',b=>{err+=b;});p.stdin.end(JSON.stringify({options,raw:f.raw,expected:f.expected,point}));return new Promise((resolve,reject)=>{p.on('error',reject);p.on('exit',(code,signal)=>resolve({code,signal,out,err}));});}

test('actual ingress pending inspection is detached/non-consuming; bridge observes twice-authorized pointer without state writes or held source lock',t=>{
  const f=fixture(t),before=f.disk(),stat=fs.statSync(f.state,{bigint:true});let locks=0,reads=0;
  const result=patch(fs,'openSync',orig=>(name,...a)=>{if(name===path.join(f.options.journalDirectory,'journal.lock'))locks++;if(name===f.head){reads++;assert(!fs.existsSync(path.join(f.options.journalDirectory,'journal.lock')));}return orig(name,...a);},()=>patch(fs,'writeFileSync',()=>()=>assert.fail('no save'),()=>patch(HostOperatorJournal.prototype,'next',()=>()=>assert.fail('no next'),()=>patch(HostOperatorJournal.prototype,'record',()=>()=>assert.fail('no record'),()=>f.bridge.observe(f.raw,f.expected)))));
  assert.equal(result.status,'observed');assert.equal(result.intentId,f.plan.intent.intentId);assert.equal(result.intentDigest,f.plan.intentDigest);assert.equal(result.requestHash,digest(f.r));assert.equal(result.observation.observedSha,source.baseSha);safe(f,result);
  assert.equal(locks,2);assert.equal(reads,1);assert.equal(f.calls(),4);assert.equal(f.disk(),before);assert.equal(fs.statSync(f.state,{bigint:true}).mtimeNs,stat.mtimeNs);
  const inspected=f.journal.inspectPendingExecution(f.r,f.expected);inspected.intent.payload.descriptor.baseSha='0'.repeat(40);assert.equal(f.journal.inspectPendingExecution(f.r,f.expected).intent.payload.descriptor.baseSha,source.baseSha);assert.equal(f.disk(),before);
  assert.equal(f.journal.next(f.r).status,'outcome_unknown');
});
test('actual mismatch and repeated bridge observations are allowed while pending remains unchanged',t=>{
  const f=fixture(t),before=f.disk();fs.writeFileSync(f.head,'a'.repeat(40));for(let n=0;n<3;n++){const result=f.bridge.observe(f.raw,f.expected);assert.equal(result.status,'mismatch');assert.equal(result.observation.observedSha,'a'.repeat(40));safe(f,result);}assert.equal(f.disk(),before);assert.equal(f.journal.next(f.r).status,'outcome_unknown');
});
test('missing entry, forged id/digest/request, report/recorded/complete state and deadline cannot become observation authority',t=>{
  const missing=fixture(t,{admit:false});
  assert.equal(createFileEventPlacer({directory:missing.options.eventDirectory,uid:missing.options.uid,ownerPubkey,targetPubkey,channelId,threadId,source,clock:()=>now}).place(missing.raw).status,'confirmed');
  denied(()=>missing.journal.inspectPendingExecution(missing.r,missing.expected),missing,'pending_execution_denied');assert.equal(missing.disk(),'');assert(!fs.existsSync(missing.state));
  const f=fixture(t),before=f.disk();for(const expected of [{...f.expected,intentId:'forged'},{...f.expected,intentDigest:'0'.repeat(64)}])noHead(f,()=>denied(()=>f.bridge.observe(f.raw,expected),f));
  denied(()=>f.journal.inspectPendingExecution({...f.r,requestId:'different'},f.expected),f,'pending_execution_denied');denied(()=>f.journal.inspectPendingExecution({...f.r,operationId:'validate.node'},f.expected),f,'pending_execution_denied');assert.equal(f.disk(),before);
  f.time(now+5000);noHead(f,()=>denied(()=>f.bridge.observe(f.raw,f.expected),f));f.time(now);f.record();noHead(f,()=>denied(()=>f.bridge.observe(f.raw,f.expected),f));
  for(const step of ['kaneo','buzz']){const p=f.journal.next(f.r);assert.equal(p.intent.step,step);noHead(f,()=>denied(()=>f.bridge.observe(f.raw,{intentId:p.intent.intentId,intentDigest:p.intentDigest}),f));f.record(p);}
  noHead(f,()=>denied(()=>f.bridge.observe(f.raw,f.expected),f));
});
test('inspection hardens own primitive inputs before JSON helpers or auth and bridge hardens raw/expected args',t=>{
  const f=fixture(t);let invoked=0;const getter={};Object.defineProperty(getter,'intentId',{get(){invoked++;throw Error(canary);},enumerable:true});
  const proxy=new Proxy({}, {getPrototypeOf(){invoked++;throw Error(canary);}}),extended=Buffer.from(f.raw);extended.extra=1;
  const symbolic={...f.expected,[Symbol('x')]:1};
  for(const expected of [getter,proxy,symbolic,{...f.expected,extra:true},{...f.expected,intentDigest:'x'.repeat(100000)},[],null,Promise.resolve(f.expected)]){
    noHead(f,()=>denied(()=>f.bridge.observe(f.raw,expected),f));denied(()=>f.journal.inspectPendingExecution(f.r,expected),f,'pending_execution_denied');
  }
  for(const raw of [getter,proxy,extended,Buffer.from(new SharedArrayBuffer(4)),Buffer.alloc(16385),'\ufeff'+f.raw,'{',JSON.stringify({...f.event,sig:'0'.repeat(128)}),JSON.stringify(signed({...request,requestId:'other'}))])noHead(f,()=>denied(()=>f.bridge.observe(raw,f.expected),f));
  denied(()=>f.journal.inspectPendingExecution(getter,f.expected),f,'pending_execution_denied');denied(()=>f.journal.inspectPendingExecution(proxy,f.expected),f,'pending_execution_denied');
  denied(()=>f.bridge.observe(f.raw),f);denied(()=>f.bridge.observe(f.raw,f.expected,{path:canary}),f);assert.equal(invoked,0);
});
test('constructor rejects injected journal/observer/seams/unsafe or nested roots and snapshots source/config',t=>{
  const f=fixture(t);let invoked=0;const getter={...f.options};Object.defineProperty(getter,'source',{get(){invoked++;throw Error(canary);}});
  for(const options of [getter,new Proxy({}, {getPrototypeOf(){invoked++;throw Error(canary);}}),{...f.options,observer:{}},{...f.options,journal:{}},{...f.options,currentJob:null},{...f.options,verifyReceipt:null},{...f.options,uid:0},{...f.options,sourceDirectory:f.options.eventDirectory},{...f.options,eventDirectory:f.root},{...f.options,sourceDirectory:f.root},{...f.options,clock:null},{...f.options,[Symbol('x')]:1}])denied(()=>createRevisionObservationBridge(options),f);
  assert.equal(invoked,0);const config={...f.options,source:{...source}},bridge=createRevisionObservationBridge(config);config.source.baseSha='a'.repeat(40);config.currentJob=()=>{throw Error(canary);};config.sourceDirectory='/absent';assert.equal(bridge.observe(f.raw,f.expected).status,'observed');
  fs.chmodSync(f.options.eventDirectory,0o755);denied(()=>createRevisionObservationBridge(f.options),f);fs.chmodSync(f.options.eventDirectory,0o700);
  fs.renameSync(f.options.sourceDirectory,f.options.sourceDirectory+'.saved');fs.symlinkSync(f.options.sourceDirectory+'.saved',f.options.sourceDirectory);denied(()=>createRevisionObservationBridge(f.options),f);
});
test('current policy outside/inside either inspection can revoke, suppressing result without changing state',t=>{
  for(const at of [1,2,3,4]){const f=fixture(t),before=f.disk();let denyPolicy=false,reads=0;
    f.hook(call=>{assert.equal(fs.existsSync(path.join(f.options.journalDirectory,'journal.lock')),call%2===0);if(call===at)denyPolicy=true;});f.current((...a)=>({...facts(...a),enabled:!denyPolicy}));
    patch(fs,'openSync',orig=>(name,...a)=>{if(name===f.head)reads++;return orig(name,...a);},()=>denied(()=>f.bridge.observe(f.raw,f.expected),f));assert.equal(reads,at<=2?0:1);assert.equal(f.disk(),before);
  }
  for(const provider of [()=>Promise.resolve({}),()=>{throw Error(canary);},(...a)=>({...facts(...a),verifiedAt:now-60001})]){const f=fixture(t);f.current(provider);noHead(f,()=>denied(()=>f.bridge.observe(f.raw,f.expected),f));}
});
test('event removal/substitution or genuine execution receipt during observation suppresses stale output; historical receipt survives',t=>{
  for(const action of ['delete','replace','record']){const f=fixture(t),before=f.disk();let changed=false;
    patch(fs,'readSync',orig=>(fd,...a)=>{const n=orig(fd,...a);if(fs.fstatSync(fd).size<=41&&!changed){changed=true;if(action==='delete')fs.unlinkSync(f.eventFile);if(action==='replace')fs.writeFileSync(f.eventFile,canary);if(action==='record')assert.equal(f.record().status,'recorded');}return n;},()=>denied(()=>f.bridge.observe(f.raw,f.expected),f));assert(changed);
    if(action==='record')assert.equal(Object.values(JSON.parse(f.disk()).entries)[0].effects[0].receipt.outcome,'success');else{assert.equal(f.disk(),before);f.time(now+600000);assert.equal(f.record().status,'recorded');}
  }
});
test('actual A11 safety and clock failures become only fixed bridge denial, never stale observation',t=>{
  for(const kind of ['missing','ref','symlink','hardlink','mode','io','clock']){const f=fixture(t),before=f.disk();
    if(kind==='missing')fs.unlinkSync(f.head);if(kind==='ref')fs.writeFileSync(f.head,'ref: refs/heads/main\n');if(kind==='symlink'){fs.renameSync(f.head,f.head+'.saved');fs.symlinkSync(f.head+'.saved',f.head);}if(kind==='hardlink')fs.linkSync(f.head,f.head+'.alias');if(kind==='mode')fs.chmodSync(f.head,0o666);
    if(kind==='io')patch(fs,'readSync',()=>()=>{throw Error(canary+f.root);},()=>denied(()=>f.bridge.observe(f.raw,f.expected),f));else if(kind==='clock'){f.time(now+5000);denied(()=>f.bridge.observe(f.raw,f.expected),f);}else denied(()=>f.bridge.observe(f.raw,f.expected),f);assert.equal(f.disk(),before);
  }
});
test('unresolved temp/stale lock/invalid state and lock sync/unlink failure deny without state rewrite or cleanup',t=>{
  for(const kind of ['temp','lock','invalid','sync','unlink']){const f=fixture(t);if(kind==='temp')fs.writeFileSync(f.state+'.tmp',canary,{mode:0o600});if(kind==='lock')fs.writeFileSync(path.join(f.options.journalDirectory,'journal.lock'),canary,{mode:0o600});if(kind==='invalid')fs.writeFileSync(f.state,canary);const before=f.disk();
    if(kind==='sync')patch(fs,'fsyncSync',()=>()=>{throw Error(canary);},()=>denied(()=>f.bridge.observe(f.raw,f.expected),f));else if(kind==='unlink')patch(fs,'unlinkSync',()=>()=>{throw Error(canary);},()=>denied(()=>f.bridge.observe(f.raw,f.expected),f));else noHead(f,()=>denied(()=>f.bridge.observe(f.raw,f.expected),f));assert.equal(f.disk(),before);
    if(kind==='temp')assert(fs.existsSync(f.state+'.tmp'));if(['lock','unlink'].includes(kind))assert(fs.existsSync(path.join(f.options.journalDirectory,'journal.lock')));
  }
});
test('bridge result/inspection/signature/policy data cannot satisfy independent execution receipt authority',t=>{
  const f=fixture(t),before=f.disk(),result=f.bridge.observe(f.raw,f.expected),inspection=f.journal.inspectPendingExecution(f.r,f.expected);
  for(const value of [result,inspection,f.event,facts(f.r,{requesterId:'owner'},descriptor(f.r,source))])assert.throws(()=>f.journal.record(f.r,value),e=>e instanceof ProtocolError&&e.code==='receipt_invalid');assert.equal(f.disk(),before);
});
test('multiple process observations are non-consuming; inspection death leaves stale lock, never auto-cleared',async t=>{
  const f=fixture(t),before=f.disk(),runs=await Promise.all(Array.from({length:3},()=>launch(f,'hold')));for(const r of runs)assert.equal(r.code,0,r.err);const results=runs.map(r=>JSON.parse(r.out));assert(results.some(r=>r.status==='observed'));assert(results.every(r=>r.status==='observed'||r.code==='revision_observation_denied'));assert.equal(f.disk(),before);
  const killed=await launch(f,'kill');assert.equal(killed.signal,'SIGKILL');assert(fs.existsSync(path.join(f.options.journalDirectory,'journal.lock')));assert.equal(f.disk(),before);denied(()=>f.bridge.observe(f.raw,f.expected),f);assert(fs.existsSync(path.join(f.options.journalDirectory,'journal.lock')));
});

test('deadline passing during trusted policy check denies before observer and inspection clock rollback never grants pending authority',t=>{
  const f=fixture(t);f.hook(call=>{if(call===2)f.time(now+5000);});noHead(f,()=>denied(()=>f.bridge.observe(f.raw,f.expected),f));
  const g=fixture(t);let ticks=0;const journal=new HostOperatorJournal({directory:g.options.journalDirectory,source,ownerPubkey,authorize:createAuthorizationAdapter({...g.options,resolveEvent:createFileEventResolver({directory:g.options.eventDirectory,uid:g.options.uid,clock:()=>now,monotonic:()=>0})}),verifyReceipt:g.options.verifyReceipt,clock:()=>++ticks===1?now+1:now});
  denied(()=>journal.inspectPendingExecution(g.r,g.expected),g,'pending_execution_denied');
});
