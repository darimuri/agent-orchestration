import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { schnorr } from '../host-operator-auth/node_modules/@noble/curves/secp256k1.js';
import { createLocalRevisionInvocation } from '../host-operator-auth/local-invocation.mjs';
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
const canary='SECRET_INVOCATION_CANARY';
function signed(r=request,changes={}) {
  const e={pubkey:ownerPubkey,kind:9,created_at:now/1000,tags:[['h',channelId],['e',threadId,'','root'],['p',targetPubkey]],content:JSON.stringify({type:'host-operator.request',version:1,request:r,descriptorDigest:digest(descriptor(request,source)),expiresAt:now+600000}),...changes};
  e.id=createHash('sha256').update(JSON.stringify([0,e.pubkey,e.created_at,e.kind,e.tags,e.content])).digest('hex');e.sig=Buffer.from(schnorr.sign(Buffer.from(e.id,'hex'),scalar,new Uint8Array(32))).toString('hex');return e;
}
function facts(r,who,d) {
  return {...Object.fromEntries(['taskId','jobId','repository','baseRef','baseSha','operationId','channelId','threadId'].map(k=>[k,r[k]])),requesterId:who.requesterId,role:'owner',ownerPubkey,mentionPubkey:ownerPubkey,targetPubkey,
    workspaceId:d.workspaceId,sourceDigest:d.sourceDigest,descriptorDigest:digest(d),requestHash:digest(r),enabled:true,status:'active',requesterMember:true,ownerAllowed:true,allowedOperations:['status.revision'],verifiedAt:now,expiresAt:now+600000};
}
function fixture(t,{admit=false}={}) {
  assert.notEqual(process.getuid(),0);const root=fs.mkdtempSync(path.join(os.tmpdir(),'local-invocation-'));fs.chmodSync(root,0o700);t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
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
  const invocation=createLocalRevisionInvocation(options),bridge=createRevisionObservationBridge(options),state=path.join(journalDirectory,'state.json'),eventFile=path.join(eventDirectory,event.id+'.json');
  const expected=plan?{intentId:plan.intent.intentId,intentDigest:plan.intentDigest}:{intentId:'absent',intentDigest:'f'.repeat(64)};
  const record=(p=plan)=>{const ref='receipt-'+receipts.size;receipts.set(ref,{version:1,receiptId:ref,intentId:p.intent.intentId,intentDigest:p.intentDigest,requestHash:digest(r),step:p.intent.step,outcome:'success',finishedAt:clock,evidenceRef:ref,evidenceDigest:'f'.repeat(64),summary:{passed:1,failed:0,skipped:0,exitCode:0,signal:null}});return journal.record(r,{ref});};
  return {root,head,options,event,raw,r,expected,plan,ingress,journal,bridge,invocation,state,eventFile,record,receipts,disk:()=>fs.existsSync(state)?fs.readFileSync(state,'utf8'):'',time:v=>{clock=v;},hook:fn=>{calls=0;hook=fn;},current:fn=>{current=fn;},calls:()=>calls};
}
function patch(object,name,wrapper,work){const orig=object[name];object[name]=wrapper(orig);try{return work();}finally{object[name]=orig;}}
function denied(fn,f,code='local_invocation_denied'){assert.throws(fn,e=>{assert.equal(e.code,code);assert.equal(e.message,code);assert.equal(e.stack,code);assert(!JSON.stringify(e).includes(canary));assert(!JSON.stringify(e).includes(f.root));return true;});}
function safe(f,value){const text=JSON.stringify(value);assert(Buffer.byteLength(text)<=8192);for(const x of [f.root,f.raw,f.event.sig,canary,'receipt','completed','READY'])assert(!text.includes(x));}
function noHead(f,work){let calls=0;const result=patch(fs,'openSync',orig=>(name,...a)=>{if(name===f.head)calls++;return orig(name,...a);},work);assert.equal(calls,0,'no observation allowed');return result;}
function pending(f) { const state=JSON.parse(f.disk()),entry=Object.values(state.entries)[0];assert.equal(entry.effects.length,1);assert.equal(entry.effects[0].receipt,null);return entry.effects[0].intent; }
function stopped(value,stage,code){assert.equal(value.status,'not_observed');assert.equal(value.stage,stage);assert.equal(value.code,code);}

test('actual new-event invocation admits once then observes once without consuming state or holding journal lock over HEAD',t=>{
  const f=fixture(t);let nexts=0,records=0,heads=0,receipts=0,locks=0,after,mtime;
  const invocation=createLocalRevisionInvocation({...f.options,verifyReceipt:()=>{receipts++;throw Error(canary);}});
  const value=patch(HostOperatorJournal.prototype,'next',orig=>function(...a){nexts++;const result=orig.apply(this,a);after=f.disk();mtime=fs.statSync(f.state,{bigint:true}).mtimeNs;return result;},()=>patch(HostOperatorJournal.prototype,'record',orig=>function(...a){records++;return orig.apply(this,a);},()=>patch(fs,'openSync',orig=>(name,...a)=>{if(name===f.head){heads++;assert(!fs.existsSync(f.options.journalDirectory+'/journal.lock'));}if(name===f.options.journalDirectory+'/journal.lock')locks++;return orig(name,...a);},()=>invocation.invoke(f.raw))));
  assert.equal(value.status,'observed');assert.equal(value.observation.observation.observedSha,source.baseSha);const intent=pending(f);assert.equal(value.admittedIntent.intentId,intent.intentId);assert.equal(value.admittedIntent.intentDigest,digest(intent));assert.equal(f.disk(),after);assert.equal(fs.statSync(f.state,{bigint:true}).mtimeNs,mtime);assert.equal(nexts,1);assert.equal(heads,1);assert.equal(locks,3);assert.equal(records,0);assert.equal(receipts,0);assert.equal(f.calls(),6);safe(f,value);
  assert(Object.isFrozen(value)&&Object.isFrozen(value.admittedIntent)&&Object.isFrozen(value.observation.observation));assert.deepEqual(Object.keys(invocation),['invoke','resume']);assert.equal(f.journal.next(f.r).status,'outcome_unknown');assert.throws(()=>f.journal.record(f.r,value),e=>e.code==='receipt_invalid');assert.equal(f.disk(),after);
});
test('actual mismatched pointer is returned; same raw never resumes; different request on busy workspace cannot observe',t=>{
  const f=fixture(t);fs.writeFileSync(f.head,'a'.repeat(40));const value=f.invocation.invoke(Buffer.from(f.raw));assert.equal(value.status,'mismatch');assert.equal(value.observation.observation.observedSha,'a'.repeat(40));const before=f.disk();noHead(f,()=>{stopped(f.invocation.invoke(f.raw),'admission','placement_unconfirmed');stopped(createLocalRevisionInvocation(f.options).invoke(f.raw),'admission','placement_unconfirmed');stopped(f.invocation.invoke(JSON.stringify(signed({...request,requestId:'two'}))),'admission','workspace_busy');});assert.equal(f.disk(),before);pending(f);
});
test('bridge source preflight fails before any event placement or journal creation; constructor inputs are fixed ordinary trusted fields',t=>{
  const f=fixture(t);let getters=0;const accessor={...f.options};Object.defineProperty(accessor,'source',{get(){getters++;throw Error(canary);}});
  for(const options of [accessor,new Proxy({}, {getPrototypeOf(){getters++;throw Error(canary);}}),{...f.options,ingress:{}},{...f.options,observer:{}},{...f.options,journal:{}},{...f.options,context:{}},{...f.options,currentJob:null},{...f.options,verifyReceipt:null},{...f.options,sourceDirectory:f.root},{...f.options,sourceDirectory:f.options.eventDirectory},{...f.options,sourceDirectory:f.root+'/absent'},{...f.options,clock:null},{...f.options,[Symbol('x')]:1}])denied(()=>createLocalRevisionInvocation(options),f);
  assert.equal(getters,0);assert.equal(f.disk(),'');assert.deepEqual(fs.readdirSync(f.options.eventDirectory),[]);fs.renameSync(f.options.sourceDirectory,f.options.sourceDirectory+'.saved');fs.symlinkSync(f.options.sourceDirectory+'.saved',f.options.sourceDirectory);denied(()=>createLocalRevisionInvocation(f.options),f);assert.equal(f.disk(),'');
});
test('raw snapshot rejects caller authority/extra args/proxies/accessors/BOM/shared/oversize before admission; guard releases',t=>{
  const f=fixture(t);let invoked=0;const getter={get raw(){invoked++;return f.raw;}},proxy=new Proxy(Buffer.from(f.raw),{getPrototypeOf(){invoked++;throw Error(canary);}}),extended=Buffer.from(f.raw);extended.extra=true;
  for(const raw of [getter,proxy,extended,Buffer.from(new SharedArrayBuffer(4)),Promise.resolve(f.raw),null,[],Buffer.alloc(16385),'x'.repeat(16385),'\ud800','\ufeff'+f.raw,''])denied(()=>f.invocation.invoke(raw),f);
  denied(()=>f.invocation.invoke(f.raw,{intentId:'caller'}),f);assert.equal(invoked,0);assert.equal(f.disk(),'');assert.deepEqual(fs.readdirSync(f.options.eventDirectory),[]);assert.equal(f.invocation.invoke(f.raw).status,'observed');
});
test('malformed/forged signed scope inputs cannot place or observe; genuine policy failure preserves placed event only',t=>{
  const f=fixture(t);for(const raw of ['{',JSON.stringify({...f.event,sig:'0'.repeat(128)}),JSON.stringify(signed({...request,repository:'other/repo'})),JSON.stringify(signed({...request,operationId:'validate.node'}))])noHead(f,()=>stopped(f.invocation.invoke(raw),'admission','ingress_denied'));assert.equal(f.disk(),'');assert.deepEqual(fs.readdirSync(f.options.eventDirectory),[]);
  f.current(()=>{throw Error(canary+f.root);});noHead(f,()=>stopped(f.invocation.invoke(f.raw),'admission','admission_denied'));assert(fs.existsSync(f.eventFile));assert.equal(f.disk(),'');
});
test('trusted policy may mutate caller Buffer/config but both stages use original snapshot and selected context',t=>{
  const f=fixture(t),raw=Buffer.from(f.raw),options={...f.options,source:{...source}};const invocation=createLocalRevisionInvocation(options);
  f.hook(()=>{raw.fill(88);options.source.baseSha='a'.repeat(40);options.sourceDirectory='/absent';options.currentJob=()=>{throw Error(canary);};});const result=invocation.invoke(raw);assert.equal(result.status,'observed');assert.equal(fs.readFileSync(f.eventFile,'utf8'),f.raw);assert.equal(result.observation.observation.expectedSha,source.baseSha);pending(f);
});
for(const point of ['revoke','expire','delete','replace','record','head','throw'])test(`partial durable admission survives ${point} between actual ingress return and bridge`,t=>{
  const f=fixture(t);let after,receiptAfter,called=0;
  const value=patch(HostOperatorJournal.prototype,'next',orig=>function(...a){called++;const result=orig.apply(this,a);after=f.disk();
    if(point==='revoke')f.current((...a)=>({...facts(...a),enabled:false}));if(point==='expire')f.time(now+5000);if(point==='delete')fs.unlinkSync(f.eventFile);if(point==='replace')fs.writeFileSync(f.eventFile,canary);if(point==='record'){assert.equal(f.record(result).status,'recorded');receiptAfter=f.disk();}if(point==='head')fs.writeFileSync(f.head,'ref: refs/heads/main\n');if(point==='throw')throw Error(canary+f.root);return result;},()=>f.invocation.invoke(f.raw));
  stopped(value,point==='throw'?'admission':'observation',point==='throw'?'admission_unconfirmed':'revision_observation_denied');assert.equal(called,1);assert.equal(f.disk(),receiptAfter??after);if(point!=='record')pending(f);safe(f,value);assert(fs.existsSync(f.eventFile)||point==='delete');noHead(f,()=>assert.equal(f.invocation.invoke(f.raw).status,'not_observed'));
});
test('receipt or event change during actual HEAD read suppresses final output and preserves independent receipt',t=>{
  for(const point of ['record','delete']){const f=fixture(t);let plan,changed=false;const result=patch(HostOperatorJournal.prototype,'next',orig=>function(...a){plan=orig.apply(this,a);return plan;},()=>patch(fs,'readSync',orig=>(fd,...a)=>{const count=orig(fd,...a);if(fs.fstatSync(fd).size===41&&!changed){changed=true;if(point==='record')f.record(plan);else fs.unlinkSync(f.eventFile);}return count;},()=>f.invocation.invoke(f.raw)));assert(changed);stopped(result,'observation','revision_observation_denied');if(point==='record')assert.equal(Object.values(JSON.parse(f.disk()).entries)[0].effects[0].receipt.outcome,'success');else pending(f);}
});
test('same-instance reentry from policy throws fixed error without second placement/next, then releases local guard',t=>{
  const f=fixture(t);let reentries=0,nexts=0;f.hook(()=>{denied(()=>f.invocation.invoke(f.raw),f);reentries++;});const result=patch(HostOperatorJournal.prototype,'next',orig=>function(...a){nexts++;return orig.apply(this,a);},()=>f.invocation.invoke(f.raw));assert.equal(result.status,'observed');assert.equal(reentries,6);assert.equal(nexts,1);stopped(f.invocation.invoke(f.raw),'admission','placement_unconfirmed');
  const g=fixture(t);g.hook(()=>g.invocation.invoke(g.raw));stopped(g.invocation.invoke(g.raw),'admission','admission_denied');g.hook(()=>{});stopped(g.invocation.invoke(g.raw),'admission','placement_unconfirmed');
});
test('actual lock/temp/state/fsync faults refuse observation without cleanup or retry',t=>{
  for(const point of ['lock','temp','invalid','fsync']){const f=fixture(t);if(point==='lock')fs.writeFileSync(f.options.journalDirectory+'/journal.lock',canary,{mode:0o600});if(point==='temp')fs.writeFileSync(f.state+'.tmp',canary,{mode:0o600});if(point==='invalid')fs.writeFileSync(f.state,canary,{mode:0o600});const before=f.disk();let result;
    if(point==='fsync')result=patch(fs,'fsyncSync',()=>()=>{throw Error(canary);},()=>f.invocation.invoke(f.raw));else result=noHead(f,()=>f.invocation.invoke(f.raw));assert.equal(result.status,'not_observed');assert.equal(f.disk(),before);if(point==='lock')assert(fs.existsSync(f.options.journalDirectory+'/journal.lock'));if(point==='temp')assert(fs.existsSync(f.state+'.tmp'));safe(f,result);
  }
});
test('malformed actual next projection never advances; nonexecution/complete/unknown/blocked stop with sanitized fixed codes',t=>{
  // Fault instrumentation is after real next, never an injected ingress/observer.
  for(const point of ['hash','digest','step','accessor','complete','report','unknown','blocked']){const f=fixture(t);let heads=0;const result=patch(HostOperatorJournal.prototype,'next',orig=>function(...a){const actual=orig.apply(this,a);if(point==='hash')actual.intent.requestHash='x';if(point==='digest')actual.intentDigest='0'.repeat(64);if(point==='step')actual.intent.step='bogus';if(point==='accessor')Object.defineProperty(actual,'status',{get(){throw Error(canary);}});if(point==='complete')return {status:'complete',result:{}};if(point==='report'){actual.intent.step='kaneo';actual.intentDigest=digest(actual.intent);}if(point==='unknown')return {status:'outcome_unknown',code:'pending_effect',intentId:actual.intent.intentId};if(point==='blocked')return {status:'blocked',code:'host_preparation_required'};return actual;},()=>patch(fs,'openSync',orig=>(name,...a)=>{if(name===f.head)heads++;return orig(name,...a);},()=>f.invocation.invoke(f.raw)));assert.equal(result.status,'not_observed');assert.equal(heads,0);pending(f);safe(f,result);}
});

test('ENOSPC and shared clock reversal stop without leaking errors or retrying durable progress',t=>{
  const f=fixture(t);const result=patch(fs,'writeSync',()=>()=>{const e=Error(canary+f.root);e.code='ENOSPC';throw e;},()=>f.invocation.invoke(f.raw));stopped(result,'admission','placement_denied');assert.equal(f.disk(),'');safe(f,result);
  const g=fixture(t);let after;const value=patch(HostOperatorJournal.prototype,'next',orig=>function(...a){const p=orig.apply(this,a);after=g.disk();g.time(now-1);return p;},()=>g.invocation.invoke(g.raw));stopped(value,'observation','revision_observation_denied');assert.equal(g.disk(),after);pending(g);
});
const child=`import fs from 'node:fs';
import {createLocalRevisionInvocation} from ${JSON.stringify(new URL('../host-operator-auth/local-invocation.mjs',import.meta.url).href)};
import {HostOperatorJournal} from ${JSON.stringify(new URL('./host-operator-journal.mjs',import.meta.url).href)};
import {digest} from ${JSON.stringify(new URL('./host-operator-protocol.mjs',import.meta.url).href)};
const {options,raw,point}=JSON.parse(fs.readFileSync(0,'utf8')),now=${now},ownerPubkey=${JSON.stringify(ownerPubkey)},targetPubkey=${JSON.stringify(targetPubkey)},facts=${facts.toString()};
let admitted=false;const next=HostOperatorJournal.prototype.next;HostOperatorJournal.prototype.next=function(...a){if(point==='placed')process.kill(process.pid,'SIGKILL');const result=next.apply(this,a);admitted=true;if(point==='admitted')process.kill(process.pid,'SIGKILL');return result;};
const sync=fs.fsyncSync;fs.fsyncSync=fd=>{const r=sync(fd);if(point==='inspection'&&admitted)process.kill(process.pid,'SIGKILL');return r;};
const open=fs.openSync;fs.openSync=(p,...a)=>{if(point==='head'&&p===options.sourceDirectory+'/.git/HEAD')process.kill(process.pid,'SIGKILL');return open(p,...a);};
const invocation=createLocalRevisionInvocation({...options,currentJob:facts,verifyReceipt:()=>{throw Error('fixture');},clock:()=>now,monotonic:()=>0});process.stdout.write(JSON.stringify(invocation.invoke(raw)));`;
function launch(f,point){const {currentJob,verifyReceipt,clock,monotonic,...options}=f.options,p=spawn(process.execPath,['--input-type=module','-e',child],{stdio:['pipe','pipe','pipe']});let out='',err='';p.stdout.on('data',b=>{out+=b;});p.stderr.on('data',b=>{err+=b;});p.stdin.end(JSON.stringify({options,raw:f.raw,point}));return new Promise((resolve,reject)=>{p.on('error',reject);p.on('exit',(code,signal)=>resolve({code,signal,out,err}));});}
test('death after placement/admission/inspection/HEAD never schedules resume or resets event/pending/stale lock',async t=>{
  for(const point of ['placed','admitted','inspection','head']){const f=fixture(t),r=await launch(f,point);assert.equal(r.signal,'SIGKILL',r.err);assert.equal(r.out,'');assert(fs.existsSync(f.eventFile));if(point==='placed')assert.equal(f.disk(),'');else pending(f);const before=f.disk();if(point==='inspection')assert(fs.existsSync(f.options.journalDirectory+'/journal.lock'));noHead(f,()=>stopped(createLocalRevisionInvocation(f.options).invoke(f.raw),'admission','placement_unconfirmed'));assert.equal(f.disk(),before);if(point==='inspection')assert(fs.existsSync(f.options.journalDirectory+'/journal.lock'));}
});

function resumeDenied(f,raw=f.raw,locator=f.expected){const result=f.invocation.resume(raw,locator);assert.deepEqual(result,{status:'not_observed',stage:'resume',code:'revision_observation_denied'});safe(f,result);return result;}
test('A14 explicit resume of actual partial admission observes same pending without admission/write/receipt or held source lock',t=>{
  const f=fixture(t);fs.writeFileSync(f.head,'ref: refs/heads/main\n');const first=f.invocation.invoke(f.raw);stopped(first,'observation','revision_observation_denied');fs.writeFileSync(f.head,source.baseSha+'\n');const before=f.disk(),mtime=fs.statSync(f.state,{bigint:true}).mtimeNs;let heads=0,locks=0,nexts=0,records=0,links=0,receipts=0;
  const invocation=createLocalRevisionInvocation({...f.options,verifyReceipt:()=>{receipts++;throw Error(canary);}});
  const result=patch(HostOperatorJournal.prototype,'next',orig=>function(...a){nexts++;return orig.apply(this,a);},()=>patch(HostOperatorJournal.prototype,'record',orig=>function(...a){records++;return orig.apply(this,a);},()=>patch(fs,'linkSync',orig=>(...a)=>{links++;return orig(...a);},()=>patch(fs,'openSync',orig=>(name,...a)=>{if(name===f.head){heads++;assert(!fs.existsSync(f.options.journalDirectory+'/journal.lock'));}if(name===f.options.journalDirectory+'/journal.lock')locks++;return orig(name,...a);},()=>invocation.resume(f.raw,first.admittedIntent)))));
  assert.equal(result.status,'observed');assert.deepEqual(result.admittedIntent,first.admittedIntent);assert.equal(result.observation.requestHash,digest(f.r));assert.equal(result.observation.descriptorDigest,digest(descriptor(f.r,source)));assert.equal(result.observation.observation.observedSha,source.baseSha);assert.equal(heads,1);assert.equal(locks,2);assert.equal(nexts+records+links+receipts,0);assert.equal(f.disk(),before);assert.equal(fs.statSync(f.state,{bigint:true}).mtimeNs,mtime);safe(f,result);assert(Object.isFrozen(result.observation.observation)&&Object.isFrozen(result.admittedIntent));
  assert.throws(()=>f.journal.record(f.r,result),e=>e.code==='receipt_invalid');assert.equal(f.disk(),before);
  fs.writeFileSync(f.head,'2'.repeat(40));for(const api of [invocation,createLocalRevisionInvocation(f.options)]){const repeated=api.resume(f.raw,first.admittedIntent);assert.equal(repeated.status,'mismatch');assert.equal(repeated.observation.observation.observedSha,'2'.repeat(40));assert.equal(f.disk(),before);}noHead(f,()=>stopped(invocation.invoke(f.raw),'admission','placement_unconfirmed'));
});
test('A14 locator is not authority: missing state/event, other signed request/job and forged ID/digest never create work',t=>{
  const absent=fixture(t);noHead(absent,()=>resumeDenied(absent));assert.equal(absent.disk(),'');assert.deepEqual(fs.readdirSync(absent.options.eventDirectory),[]);
  const placed=fixture(t);assert.equal(createFileEventPlacer({directory:placed.options.eventDirectory,uid:process.getuid(),ownerPubkey,targetPubkey,channelId,threadId,source,clock:()=>now}).place(placed.raw).status,'confirmed');noHead(placed,()=>resumeDenied(placed));assert.equal(placed.disk(),'');
  const f=fixture(t,{admit:true}),before=f.disk();for(const [raw,locator] of [[f.raw,{...f.expected,intentId:'forged'}],[f.raw,{...f.expected,intentDigest:'0'.repeat(64)}],[JSON.stringify(signed({...request,requestId:'other'})),f.expected],[JSON.stringify(signed({...request,jobId:'other-job'})),f.expected],[JSON.stringify({...f.event,sig:'0'.repeat(128)}),f.expected]])noHead(f,()=>resumeDenied(f,raw,locator));assert.equal(f.disk(),before);
  for(const mutation of ['delete','replace']){const g=fixture(t,{admit:true}),before=g.disk();if(mutation==='delete')fs.unlinkSync(g.eventFile);else fs.writeFileSync(g.eventFile,canary);noHead(g,()=>resumeDenied(g));assert.equal(g.disk(),before);}
});
test('A14 hardened two-argument input rejects envelopes/receipts/DTOs/getters/proxies before any clock callback',t=>{
  const f=fixture(t,{admit:true});let clocks=0,getters=0;const api=createLocalRevisionInvocation({...f.options,clock:()=>{clocks++;return now;}}),getter={};Object.defineProperty(getter,'intentId',{enumerable:true,get(){getters++;throw Error(canary);}});const proxy=new Proxy({},{getPrototypeOf(){getters++;throw Error(canary);}}),extended=Buffer.from(f.raw);extended.extra=1;
  for(const locator of [getter,proxy,[],null,Promise.resolve(f.expected),{...f.expected,extra:true},{...f.expected,[Symbol('x')]:1},{...f.expected,intentId:'x'.repeat(100000)},Object.create(f.expected),{admittedIntent:f.expected},f.event,facts(f.r,{requesterId:'owner'},descriptor(f.r,source))])denied(()=>api.resume(f.raw,locator),f);
  for(const raw of [proxy,getter,extended,Buffer.from(new SharedArrayBuffer(4)),Promise.resolve(f.raw),Buffer.alloc(16385),'\ufeff'+f.raw,'\ud800',''])denied(()=>api.resume(raw,f.expected),f);
  denied(()=>api.resume(f.raw),f);denied(()=>api.resume(f.raw,f.expected,{}),f);assert.equal(getters,0);assert.equal(clocks,0);assert.equal(api.resume(f.raw,f.expected).status,'observed');
});
test('A14 snapshots raw and locator before trusted clock/provider mutation and keeps selected context',t=>{
  const f=fixture(t,{admit:true}),raw=Buffer.from(f.raw),locator={...f.expected},options={...f.options,source:{...source},clock:()=>{raw.fill(88);locator.intentId='forged';locator.intentDigest='0'.repeat(64);options.source.baseSha='2'.repeat(40);return now;}};const api=createLocalRevisionInvocation(options),result=api.resume(raw,locator);assert.equal(result.status,'observed');assert.deepEqual(result.admittedIntent,f.expected);assert.equal(result.observation.requestHash,digest(f.r));
  const g=fixture(t,{admit:true}),bytes=Buffer.from(g.raw),lookup={...g.expected};g.hook(()=>{bytes.fill(88);lookup.intentId='forged';});assert.equal(g.invocation.resume(bytes,lookup).status,'observed');
});
test('A14 original deadline is never renewed by resume or fresh factory; check deadline crossing during HEAD',t=>{
  const f=fixture(t,{admit:true}),before=f.disk();f.time(now+4999);assert.equal(createLocalRevisionInvocation(f.options).resume(f.raw,f.expected).status,'observed');f.time(now+5000);noHead(f,()=>resumeDenied(f));noHead(f,()=>assert.deepEqual(createLocalRevisionInvocation(f.options).resume(f.raw,f.expected),{status:'not_observed',stage:'resume',code:'revision_observation_denied'}));assert.equal(f.disk(),before);
  const g=fixture(t,{admit:true});let changed=false;const value=patch(fs,'readSync',orig=>(fd,...a)=>{const n=orig(fd,...a);if(fs.fstatSync(fd).size===41){changed=true;g.time(now+5000);}return n;},()=>resumeDenied(g));assert(changed);assert(!Object.hasOwn(value,'admittedIntent'));assert.equal(pending(g).deadline,now+5000);
});
test('A14 consumed/report/complete entries cannot resume; genuine historical receipt stays independent',t=>{
  const f=fixture(t,{admit:true});assert.equal(f.record().status,'recorded');noHead(f,()=>resumeDenied(f));for(const step of ['kaneo','buzz']){const p=f.journal.next(f.r);assert.equal(p.intent.step,step);noHead(f,()=>resumeDenied(f,f.raw,{intentId:p.intent.intentId,intentDigest:p.intentDigest}));f.record(p);}const before=f.disk();noHead(f,()=>resumeDenied(f));assert.equal(f.disk(),before);
});
test('A14 fresh current policy and context required, regardless of locator retention',t=>{
  for(const current of [()=>{throw Error(canary);},()=>Promise.resolve({}),(...a)=>({...facts(...a),enabled:false}),(...a)=>({...facts(...a),expiresAt:now})]){const f=fixture(t,{admit:true}),before=f.disk();f.current(current);noHead(f,()=>resumeDenied(f));assert.equal(f.disk(),before);}
  const f=fixture(t,{admit:true});for(const delta of [{requesterId:'other'},{channelId:'00000000-0000-0000-0000-000000000002'},{source:{...source,sourceDigest:'2'.repeat(64)}},{source:{...source,baseSha:'2'.repeat(40)}}])noHead(f,()=>assert.deepEqual(createLocalRevisionInvocation({...f.options,...delta}).resume(f.raw,f.expected),{status:'not_observed',stage:'resume',code:'revision_observation_denied'}));
});
for(const change of ['policy','receipt','event'])test(`A14 ${change} during actual source read suppresses resume and preserves durable state`,t=>{
  const f=fixture(t,{admit:true}),before=f.disk();let changed=false,after=before;patch(fs,'readSync',orig=>(fd,...a)=>{const n=orig(fd,...a);if(fs.fstatSync(fd).size===41&&!changed){changed=true;if(change==='policy')f.current((...a)=>({...facts(...a),enabled:false}));if(change==='receipt'){f.record();after=f.disk();}if(change==='event')fs.unlinkSync(f.eventFile);}return n;},()=>resumeDenied(f));assert(changed);assert.equal(f.disk(),after);if(change==='receipt')assert.equal(Object.values(JSON.parse(after).entries)[0].effects[0].receipt.outcome,'success');
});
test('A14 lock/temp/state/open/sync/unlink/ENOSPC/clock faults deny with no cleanup, admission or locator echo',t=>{
  for(const fault of ['lock','temp','invalid','open','sync','unlink','enospc','clock']){const f=fixture(t,{admit:true});if(fault==='lock')fs.writeFileSync(f.options.journalDirectory+'/journal.lock',canary,{mode:0o600});if(fault==='temp')fs.writeFileSync(f.state+'.tmp',canary,{mode:0o600});if(fault==='invalid')fs.writeFileSync(f.state,canary);const before=f.disk();
    if(['open','sync','unlink'].includes(fault)){const name={open:'openSync',sync:'fsyncSync',unlink:'unlinkSync'}[fault];patch(fs,name,()=>()=>{throw Error(canary+f.root);},()=>resumeDenied(f));}else if(fault==='enospc')patch(fs,'openSync',()=>()=>{const e=Error(canary);e.code='ENOSPC';throw e;},()=>resumeDenied(f));else if(fault==='clock'){let calls=0;assert.deepEqual(createLocalRevisionInvocation({...f.options,clock:()=>++calls===1?now:now-1}).resume(f.raw,f.expected),{status:'not_observed',stage:'resume',code:'revision_observation_denied'});}else noHead(f,()=>resumeDenied(f));assert.equal(f.disk(),before);if(['lock','unlink'].includes(fault))assert(fs.existsSync(f.options.journalDirectory+'/journal.lock'));if(fault==='temp')assert(fs.existsSync(f.state+'.tmp'));
  }
});
test('A14 invoke/resume cross-method reentrancy shares one guard and releases it after failure',t=>{
  const f=fixture(t,{admit:true});let reentries=0;f.hook(()=>{denied(()=>f.invocation.invoke(f.raw),f);denied(()=>f.invocation.resume(f.raw,f.expected),f);reentries++;});assert.equal(f.invocation.resume(f.raw,f.expected).status,'observed');assert.equal(reentries,4);f.hook(()=>{});assert.equal(f.invocation.resume(f.raw,f.expected).status,'observed');
  const g=fixture(t);g.hook(()=>denied(()=>g.invocation.resume(g.raw,g.expected),g));assert.equal(g.invocation.invoke(g.raw).status,'observed');
  const h=fixture(t,{admit:true});h.hook(()=>h.invocation.invoke(h.raw));resumeDenied(h);h.hook(()=>{});assert.equal(h.invocation.resume(h.raw,h.expected).status,'observed');
});
const resumeChild=`import fs from 'node:fs';
import {createLocalRevisionInvocation} from ${JSON.stringify(new URL('../host-operator-auth/local-invocation.mjs',import.meta.url).href)};
import {digest} from ${JSON.stringify(new URL('./host-operator-protocol.mjs',import.meta.url).href)};
const {options,raw,expected,point}=JSON.parse(fs.readFileSync(0,'utf8')),now=${now},ownerPubkey=${JSON.stringify(ownerPubkey)},targetPubkey=${JSON.stringify(targetPubkey)},facts=${facts.toString()};
const sync=fs.fsyncSync;fs.fsyncSync=fd=>{const r=sync(fd);if(point==='inspection')process.kill(process.pid,'SIGKILL');return r;};
const read=fs.readSync;fs.readSync=(fd,...a)=>{const n=read(fd,...a);if(point==='head'&&fs.fstatSync(fd).size===41)process.kill(process.pid,'SIGKILL');return n;};
const api=createLocalRevisionInvocation({...options,currentJob:facts,verifyReceipt:()=>{throw Error('fixture');},clock:()=>now,monotonic:()=>0});process.stdout.write(JSON.stringify(api.resume(raw,expected)));`;
function launchResume(f,point){const {currentJob,verifyReceipt,clock,monotonic,...options}=f.options,p=spawn(process.execPath,['--input-type=module','-e',resumeChild],{stdio:['pipe','pipe','pipe']});let out='',err='';p.stdout.on('data',b=>{out+=b;});p.stderr.on('data',b=>{err+=b;});p.stdin.end(JSON.stringify({options,raw:f.raw,expected:f.expected,point}));return new Promise((resolve,reject)=>{p.on('error',reject);p.on('exit',(code,signal)=>resolve({code,signal,out,err}));});}
test('A14 process death during inspection/after HEAD preserves pending; stale lock denied without cleanup',async t=>{
  for(const point of ['inspection','head']){const f=fixture(t,{admit:true}),before=f.disk(),r=await launchResume(f,point);assert.equal(r.signal,'SIGKILL',r.err);assert.equal(r.out,'');assert.equal(f.disk(),before);if(point==='inspection'){assert(fs.existsSync(f.options.journalDirectory+'/journal.lock'));noHead(f,()=>resumeDenied(f));assert(fs.existsSync(f.options.journalDirectory+'/journal.lock'));}else assert.equal(createLocalRevisionInvocation(f.options).resume(f.raw,f.expected).status,'observed');assert.equal(f.disk(),before);}
});
