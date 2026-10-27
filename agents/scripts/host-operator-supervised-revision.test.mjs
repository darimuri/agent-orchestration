import { runSyntheticSupervisor } from './host-operator-cgroup-supervisor.test.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { schnorr } from '../host-operator-auth/node_modules/@noble/curves/secp256k1.js';
import { createSupervisedRevisionIssuer } from '../host-operator-auth/supervised-revision.mjs';
import { createRevisionEvidenceStore } from '../host-operator-auth/revision-evidence.mjs';
import { createRevisionCompletionVerifier } from '../host-operator-auth/revision-completion.mjs';
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


const artifact=name=>createHash('sha256').update(fs.readFileSync(new URL('../host-operator-auth/'+name,import.meta.url))).digest('hex');
function supervised(f,run) {
  const evidenceDirectory=f.root+'/evidence';if(!fs.existsSync(evidenceDirectory)){fs.mkdirSync(evidenceDirectory,{mode:0o700});for(const n of ['claims','objects'])fs.mkdirSync(evidenceDirectory+'/'+n,{mode:0o700});}
  const {verifyReceipt,...base}=f.options;
  const options={...base,evidenceDirectory,authorityId:'synthetic-fixture-authority',issuerArtifactDigest:artifact('supervised-revision.mjs'),workerArtifactDigest:artifact('supervised-revision-worker.mjs'),clockId:'fixture-clock',settlementWaitMs:5000,supervisor:{run}};
  const store=()=>createRevisionEvidenceStore({directory:evidenceDirectory,uid:options.uid,...Object.fromEntries(['source','authorityId','issuerArtifactDigest','workerArtifactDigest','clockId'].map(k=>[k,options[k]]))});
  return {options,issuer:createSupervisedRevisionIssuer(options),store,objects:()=>fs.readdirSync(evidenceDirectory+'/objects'),claims:()=>fs.readdirSync(evidenceDirectory+'/claims')};
}
// REAL child and close/reap correlation. Empty/sealed/no-escape are SYNTHETIC
// fixture claims, never kernel/cgroup quiescence acceptance.
function syntheticRun(f,change=()=>{}) { return async spec=>{
  assert(Object.isFrozen(spec)&&Object.isFrozen(spec.env));assert.equal(spec.executable,process.execPath);assert(spec.entry.endsWith('/supervised-revision-worker.mjs'));assert.deepEqual(Object.keys(spec.env).sort(),['LANG','TZ']);assert(!spec.input.includes(f.event.sig));
  assert(!fs.existsSync(f.options.journalDirectory+'/journal.lock'));assert(!fs.existsSync(f.root+'/evidence/evidence.lock'));
  const child=spawn(spec.executable,[spec.entry],{env:spec.env,stdio:['pipe','pipe','pipe']});let stdout='',stderr='';child.stdout.on('data',b=>{stdout+=b;});child.stderr.on('data',b=>{stderr+=b;});child.stdin.end(spec.input);
  const terminal=await new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',(exitCode,signal)=>resolve({exitCode,signal}));});
  const answer={status:'settled',stdout,stderr,boundary:{version:1,runId:spec.runId,boundaryId:'synthetic-'+child.pid,requestHash:spec.requestHash,intentDigest:spec.intentDigest,workerArtifactDigest:spec.workerArtifactDigest,clockId:spec.clockId,startedAt:spec.startedAt,leaderExitedAt:spec.startedAt,settledAt:spec.startedAt,leaderReaped:true,noEscape:true,sealed:true,populated:0,...terminal}};
  await change(answer,spec);return answer;
};}
for(const mismatch of [false,true])test(`actual fixed child ${mismatch?'mismatch':'match'} publishes retained bundle only; explicit record required`,async t=>{
  const f=fixture(t,{admit:true});if(mismatch)fs.writeFileSync(f.head,'a'.repeat(40));const s=supervised(f,syntheticRun(f)),before=f.disk(),mtime=fs.statSync(f.state,{bigint:true}).mtimeNs;
  const result=await s.issuer.issue(f.raw,f.expected);assert.equal(result.status,'issued');assert.equal(result.outcome,'success');assert.equal(f.disk(),before);assert.equal(fs.statSync(f.state,{bigint:true}).mtimeNs,mtime);assert.equal(s.objects().length,1);assert.equal(s.claims().length,1);
  const proof=s.store().resolveCompletion(result.evidence.ref);assert.equal(proof.version,2);const bundle=JSON.parse(fs.readFileSync(s.options.evidenceDirectory+'/objects/'+result.evidence.ref+'.json'));assert.equal(bundle.result.status,mismatch?'mismatch':'observed');assert.equal(proof.resultDigest,digest(bundle.result));assert.equal(proof.execution.boundaryDigest,digest(bundle.boundary));
  const verify=createRevisionCompletionVerifier({source,authorityId:s.options.authorityId,resolveCompletion:s.store().resolveCompletion,supervised:Object.fromEntries(['issuerArtifactDigest','workerArtifactDigest','clockId'].map(k=>[k,s.options[k]])),clock:f.options.clock});
  const j=new HostOperatorJournal({directory:f.options.journalDirectory,source,ownerPubkey,authorize:createAuthorizationAdapter({...f.options,resolveEvent:createFileEventResolver({directory:f.options.eventDirectory,uid:f.options.uid,clock:f.options.clock,monotonic:()=>0})}),verifyReceipt:verify,verifyRevisionCompletion:verify,clock:f.options.clock});
  assert.equal(j.record(f.r,result.evidence).status,'recorded');assert.equal(j.next(f.r).intent.step,'kaneo');assert.equal((await s.issuer.issue(f.raw,f.expected)).status,'unknown');assert.equal(s.objects().length,1);
});
for(const point of ['leaderReaped','noEscape','sealed','populated','runId','requestHash','workerArtifactDigest','clockId','future','terminal','throw','unknown'])test(`unproven ${point} boundary never publishes or retries`,async t=>{
  const f=fixture(t,{admit:true});let runs=0;const run=syntheticRun(f,a=>{if(['leaderReaped','noEscape','sealed'].includes(point))a.boundary[point]=false;else if(point==='populated')a.boundary.populated=1;else if(['runId','clockId'].includes(point))a.boundary[point]='wrong';else if(['requestHash','workerArtifactDigest'].includes(point))a.boundary[point]='0'.repeat(64);else if(point==='future')a.boundary.settledAt=now+1;else if(point==='terminal')a.boundary.exitCode=null;else if(point==='throw')throw Error(canary);else if(point==='unknown')a.status='unknown';});
  const s=supervised(f,async x=>{runs++;return run(x);}),before=f.disk();assert.equal((await s.issuer.issue(f.raw,f.expected)).status,'unknown');assert.equal(s.objects().length,0);assert.equal(s.claims().length,1);assert.equal((await createSupervisedRevisionIssuer(s.options).issue(f.raw,f.expected)).status,'unknown');assert.equal(runs,1);assert.equal(f.disk(),before);
});
for(const point of ['nonzero','signal','malformed','limit','late','revoke','event'])test(`positively settled ${point} failure suppresses SHA and can be retained`,async t=>{
  const f=fixture(t,{admit:true}),s=supervised(f,syntheticRun(f,a=>{if(point==='nonzero')a.boundary.exitCode=1;if(point==='signal'){a.boundary.exitCode=null;a.boundary.signal='SIGKILL';}if(point==='malformed')a.stdout='{}';if(point==='limit')a.stderr='x'.repeat(4097);if(point==='late')f.time(now+5000);if(point==='revoke')f.current((...x)=>({...facts(...x),enabled:false}));if(point==='event')fs.unlinkSync(f.eventFile);}));const before=f.disk(),v=await s.issuer.issue(f.raw,f.expected);assert.equal(v.status,'issued');assert.equal(v.outcome,'failed');const b=JSON.parse(fs.readFileSync(s.options.evidenceDirectory+'/objects/'+v.evidence.ref+'.json'));assert(!Object.hasOwn(b.result,'observedSha'));assert.equal(b.proof.finishedAt,point==='late'?now+5000:now);assert.equal(f.disk(),before);
});
test('locator and raw are bounded data, not authority; no implicit admission',async t=>{
 const f=fixture(t),s=supervised(f,()=>{throw Error('must not launch');});assert.equal((await s.issuer.issue(f.raw,f.expected)).status,'unknown');assert.equal(s.claims().length,0);let calls=0;const getter={};Object.defineProperty(getter,'intentId',{enumerable:true,get(){calls++;}});for(const loc of [getter,new Proxy({},{}),{...f.expected,extra:true},Promise.resolve(f.expected),{intentId:'x',intentDigest:'no'}])await assert.rejects(s.issuer.issue(f.raw,loc),e=>e.code==='supervised_revision_denied');for(const raw of ['',Buffer.alloc(16385),Buffer.from(new SharedArrayBuffer(4)),{},'\ufeff'+f.raw])await assert.rejects(s.issuer.issue(raw,f.expected),e=>e.code==='supervised_revision_denied');assert.equal(calls,0);assert.equal(f.disk(),'');
});
test('owner construction requires explicit supervisor/pins/protected separate namespaces',t=>{const f=fixture(t,{admit:true}),s=supervised(f,syntheticRun(f));for(const change of [{supervisor:null},{supervisor:{run:()=>{},extra:1}},{settlementWaitMs:0},{settlementWaitMs:60001},{issuerArtifactDigest:'0'.repeat(64)},{workerArtifactDigest:'0'.repeat(64)},{evidenceDirectory:f.options.journalDirectory},{sourceDirectory:f.root},{currentJob:null},{executor:()=>{}}])assert.throws(()=>createSupervisedRevisionIssuer({...s.options,...change}),e=>e.code==='supervised_revision_denied');});
test('concurrent and recursive calls share guard; restart and claim races never reexecute',async t=>{const f=fixture(t,{admit:true});let release,runs=0;const wait=new Promise(r=>{release=r;}),run=syntheticRun(f),s=supervised(f,async spec=>{runs++;await wait;return run(spec);});const first=s.issuer.issue(f.raw,f.expected);await assert.rejects(s.issuer.issue(f.raw,f.expected),e=>e.code==='supervised_revision_denied');assert.equal((await createSupervisedRevisionIssuer(s.options).issue(f.raw,f.expected)).status,'unknown');release();assert.equal((await first).status,'issued');assert.equal(runs,1);});
test('bounded settlement timeout never publishes from a late supervisor continuation',async t=>{const f=fixture(t,{admit:true});let release;const wait=new Promise(r=>{release=r;});const s=supervised(f,async spec=>{await wait;return syntheticRun(f)(spec);}),issuer=createSupervisedRevisionIssuer({...s.options,settlementWaitMs:5});assert.equal((await issuer.issue(f.raw,f.expected)).status,'unknown');release();await new Promise(r=>setTimeout(r,200));assert.equal(s.objects().length,0);assert.equal(s.claims().length,1);});
test('wall/monotonic reversal and lost worker attribution are UNKNOWN',async t=>{for(const point of ['wall','mono','correlation']){const f=fixture(t,{admit:true});let m=0;const s=supervised(f,syntheticRun(f,a=>{if(point==='wall')f.time(now-1);if(point==='mono')m=-1;if(point==='correlation'){const v=JSON.parse(a.stdout);v.runId='other';a.stdout=JSON.stringify(v,Object.keys(v).sort());}}));const issuer=createSupervisedRevisionIssuer({...s.options,monotonic:()=>m});assert.equal((await issuer.issue(f.raw,f.expected)).status,'unknown');assert.equal(s.objects().length,0);}});
const issuerCrash=`import fs from 'node:fs';import assert from 'node:assert/strict';import {spawn} from 'node:child_process';import {createSupervisedRevisionIssuer} from ${JSON.stringify(new URL('../host-operator-auth/supervised-revision.mjs',import.meta.url).href)};import {digest} from ${JSON.stringify(new URL('./host-operator-protocol.mjs',import.meta.url).href)};const {options,raw,expected,point,head}=JSON.parse(fs.readFileSync(0,'utf8')),now=${now},ownerPubkey=${JSON.stringify(ownerPubkey)},targetPubkey=${JSON.stringify(targetPubkey)},facts=${facts.toString()};const f={head,root:options.evidenceDirectory.slice(0,-9),event:{sig:'not-present-fixture'},options};const syntheticRun=${syntheticRun.toString()};const issuer=createSupervisedRevisionIssuer({...options,clock:()=>now,monotonic:()=>0,currentJob:facts,supervisor:{async run(spec){if(point==='before_launch')process.kill(process.pid,'SIGKILL');return syntheticRun(f,()=>{if(point==='settled')process.kill(process.pid,'SIGKILL');})(spec);}}});const result=await issuer.issue(raw,expected);if(point==='confirmed')process.kill(process.pid,'SIGKILL');process.stdout.write(JSON.stringify(result));`;
for(const point of ['before_launch','settled','confirmed'])test(`issuer SIGKILL ${point} cannot create a second worker after restart`,async t=>{const f=fixture(t,{admit:true});let runs=0;const s=supervised(f,async()=>{runs++;throw Error('must not run');}),{currentJob,clock,monotonic,supervisor,...options}=s.options,p=spawn(process.execPath,['--input-type=module','-e',issuerCrash],{stdio:['pipe','pipe','pipe']});let err='';p.stderr.on('data',b=>{err+=b;});p.stdin.end(JSON.stringify({options,raw:f.raw,expected:f.expected,point,head:f.head}));const killed=await new Promise((resolve,reject)=>{p.once('error',reject);p.once('close',(code,signal)=>resolve({code,signal}));});assert.equal(killed.signal,'SIGKILL',err);assert.equal((await s.issuer.issue(f.raw,f.expected)).status,'unknown');assert.equal(runs,0);assert.equal(s.claims().length,1);assert.equal(s.objects().length,point==='confirmed'?1:0);pending(f);});
test('prelaunch policy change consumes durable claim without launch or retry',async t=>{const f=fixture(t,{admit:true});let runs=0;const s=supervised(f,()=>{runs++;throw Error('must not run');});let inspections=0;const old=HostOperatorJournal.prototype.inspectPendingExecution;HostOperatorJournal.prototype.inspectPendingExecution=function(...a){if(++inspections===2)f.current((...x)=>({...facts(...x),enabled:false}));return old.apply(this,a);};try{assert.equal((await s.issuer.issue(f.raw,f.expected)).status,'unknown');}finally{HostOperatorJournal.prototype.inspectPendingExecution=old;}assert.equal(s.claims().length,1);assert.equal(runs,0);f.current(facts);assert.equal((await s.issuer.issue(f.raw,f.expected)).status,'unknown');assert.equal(runs,0);});

for(const mismatch of [false,true])test('A17 actual issuer/worker plus new adapter VM protocol '+(mismatch?'mismatch':'match'),async t=>{
 const f=fixture(t,{admit:true});if(mismatch)fs.writeFileSync(f.head,'a'.repeat(40));const actual=syntheticRun(f);const s=supervised(f,async spec=>{const observed=await actual(spec);const vm=runSyntheticSupervisor({spec,now:spec.startedAt,source,sourceDirectory:f.options.sourceDirectory,stdout:observed.stdout});assert.equal(vm.status,0,vm.stderr);assert.equal(vm.value.result.status,'settled');return vm.value.result;});const before=f.disk(),v=await s.issuer.issue(f.raw,f.expected);assert.equal(v.status,'issued');assert.equal(v.outcome,'success');assert.equal(f.disk(),before);assert.equal(s.store().resolveCompletion(v.evidence.ref).execution.kind,'supervised_process_v1');
});
test('A17 safe backend UNKNOWN preserves actual issuer claim, no completion or reexecution',async t=>{const f=fixture(t,{admit:true});let calls=0;const s=supervised(f,async spec=>{calls++;const vm=runSyntheticSupervisor({spec,now:spec.startedAt,source,sourceDirectory:f.options.sourceDirectory,mode:'unknown'});assert.equal(vm.status,0,vm.stderr);return vm.value.result;});assert.equal((await s.issuer.issue(f.raw,f.expected)).status,'unknown');assert.equal((await s.issuer.issue(f.raw,f.expected)).status,'unknown');assert.equal(calls,1);assert.equal(s.objects().length,0);assert.equal(s.claims().length,1);pending(f);});
