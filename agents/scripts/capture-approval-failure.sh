#!/bin/bash
# Ordinary 100644 owner-run source. No Node/V8 workload is authorized by this slice.
set -euo pipefail
exec /usr/bin/node --input-type=module - "$@" <<'JS'
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawn} from 'node:child_process';
const [mode, manifestPath, output] = process.argv.slice(2);
const schema='buzz.approval-capture/v1';
const env={PATH:'/usr/bin:/bin',LANG:'C',LC_ALL:'C',TZ:'UTC',HOME:'/dev/null',DOCKER_CONFIG:null};
let hostCancel=null;const activeDocker=new Set();
let dockerCustody=null;
const caps={cpus:2,memory:2147483648,pids:128,seconds:900,work:2147483648,output:1073741824,stream:67108864,text:134217728};
function need(ok,message){if(!ok)throw Error(message);}
const digest=b=>crypto.createHash('sha256').update(b).digest('hex');
function ordinary(p,bound){
  need(path.isAbsolute(p)&&fs.realpathSync(p)===p,'canonical input');
  const a=fs.lstatSync(p,{bigint:true});need(a.isFile()&&a.nlink===1n&&a.size<=BigInt(bound),'ordinary bounded input');
  const fd=fs.openSync(p,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  try{
    const chunks=[];let total=0;const buffer=Buffer.alloc(65536);while(true){const n=fs.readSync(fd,buffer,0,Math.min(buffer.length,bound+1-total),null);if(!n)break;total+=n;need(total<=bound,'input overflow');chunks.push(Buffer.from(buffer.subarray(0,n)));}
    const b=Buffer.concat(chunks);const c=fs.fstatSync(fd,{bigint:true}),d=fs.lstatSync(p,{bigint:true});
    for(const k of ['dev','ino','mode','nlink','size','mtimeNs','ctimeNs'])need(a[k]===c[k]&&a[k]===d[k],'input mutation');
    need(b.length<=bound&&BigInt(b.length)===a.size,'input bound');return b;
  }finally{fs.closeSync(fd);}
}
function save(p,value){
  const tmp=p+'.tmp-'+crypto.randomBytes(16).toString('hex');
  const fd=fs.openSync(tmp,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
  try{fs.writeFileSync(fd,Buffer.isBuffer(value)?value:JSON.stringify(value,null,2)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
  fs.linkSync(tmp,p);fs.unlinkSync(tmp);
  const dir=fs.openSync(path.dirname(p),fs.constants.O_RDONLY|fs.constants.O_DIRECTORY);try{fs.fsyncSync(dir);}finally{fs.closeSync(dir);}
}
function validate(m){
  if(m.purpose===nativePurpose)return validateNative(m);
  need(m.schema===schema&&m.purpose==='owner-synthetic-fixture','fixture schema/authority');
  need(/^[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}$/.test(m.image),'immutable repository manifest');
  need(m.platform==='linux/amd64','admitted fixture platform');
  need(/^sha256:[a-f0-9]{64}$/.test(m.imageId),'full config image ID');
  need(Object.keys(m.resources).sort().join(',')===Object.keys(caps).sort().join(','),'resource keys');
  for(const [k,v]of Object.entries(caps))need(Number.isSafeInteger(m.resources[k])&&m.resources[k]>0&&m.resources[k]<=v,'resource bound '+k);
  need(m.resources.memory===2147483648&&m.resources.cpus===2&&m.resources.pids===128,'fixture resource identity');
  const roots=[m.source,m.control,m.work,m.output];
  need(roots.every(p=>typeof p==='string'&&path.isAbsolute(p)&&!/[\s,:\\]/.test(p)),'mount path syntax');
  need(typeof m.dockerCustodyRoot==='string'&&path.isAbsolute(m.dockerCustodyRoot)&&m.dockerCustodyRoot!=='/'&&path.resolve(m.dockerCustodyRoot)===m.dockerCustodyRoot&&!/[\s,:\\]/.test(m.dockerCustodyRoot)&&m.control.startsWith(m.dockerCustodyRoot+'/'),'explicit Docker custody root/control path');
  for(const [i,a]of roots.entries())for(const [j,b]of roots.entries())if(i!==j)need(a!==b&&!a.startsWith(b+'/'),'overlapping mounts');
  need(m.recorder?.work==='/work'&&m.recorder?.output==='/output','recorder roots');
  need(m.recorder.schema===schema&&m.recorder.purpose===m.purpose,'recorder schema');
  const fixed={PATH:'/usr/bin:/bin',LANG:'C',LC_ALL:'C',TZ:'UTC',SOURCE_DATE_EPOCH:'0',CC:'/control/cc',CXX:'/control/cxx',LINK:'/control/link'};
  need(JSON.stringify(Object.entries(m.recorder.environment).sort())===JSON.stringify(Object.entries(fixed).sort()),'fixed environment');
  need(Object.keys(m.recorder.roles).sort().join(',')==='cc,cxx,link,workload','fixed role set');
  for(const tool of Object.values(m.recorder.roles))need(/^\/usr\/[a-zA-Z0-9_+./-]+$/.test(tool.path)&&!tool.path.split('/').slice(1).some(p=>p==='.'||p==='..'||p==='')&&/^[a-f0-9]{64}$/.test(tool.sha256),'pinned canonical real tool');
  need(Array.isArray(m.fixtureArgvBase64)&&m.fixtureArgvBase64.length<=10000,'fixture argv');
  for(const v of m.fixtureArgvBase64)need(typeof v==='string'&&Buffer.from(v,'base64').toString('base64')===v&&!Buffer.from(v,'base64').includes(0),'base64 argv');
  need(m.fixtureArgvBase64.reduce((n,v)=>n+Buffer.from(v,'base64').length+1,0)<=1048576,'argv byte bound');
  // Docker CLI cannot losslessly represent non-UTF8 arguments. Those are exercised
  // directly against Python fixtures; the fixed container entry reads these bytes.
  const limits={args:10000,argvBytes:1048576,responseFile:1048576,responseTotal:16777216,stream:caps.stream,text:caps.text,seconds:30,records:20000};
  need(Object.keys(m.recorder.limits).sort().join(',')===Object.keys(limits).sort().join(','),'recorder limits');
  for(const [k,v]of Object.entries(limits))need(Number.isSafeInteger(m.recorder.limits[k])&&m.recorder.limits[k]>0&&m.recorder.limits[k]<=v,'recorder bound');
  need(m.recorder.limits.stream<=m.resources.stream&&m.recorder.limits.text<=m.resources.text,'stream resource mapping');
  return m;
}
// Admission policy only. No native launcher is implemented by this source slice.
const nativePurpose='owner-nodev8-prerequisite-measurement/v1';
const nativePolicy={
  infrastructureBase:'2630a768e0617a6599376d7a92baf663a689d337',infrastructureTree:'d3e1fde2b2599df0e15d99d86a9517ced0120f17',
  approvalSource:'1312e7a9dec6fac055b61993c145be7f6847e216',approvalTree:'3868efaef2c500a13d2bde30cd645d5aa372ab59',
  archiveSha256:'a7f6204ff63b6a2cd274d48903285abb86ed53a99070e532d4c2fd787457d9e6',lockSha256:'0dbfd0064f4afbd32ceef751d3d1b75685f8a511cd50d394b21232d02ff29307',
  sourceAdmissionSha256:'62c5eb0af7c71d8d21838f3442433e8ca16b9350ff6edd5f54332157446bb63d',contextSha256:'a76bd9260f09bfd877a07e28a056e90ee82ce2cac8d5e09a223a71ca95bcd5f0',graphReportSha256:'d5cf17ce74fa607abe246e3b4e88438d081d757b6193a9f6e0274cbfb7c56276',decisionSha256:'34c7e4affc4cf8cc53c95e864f5ae020c69f7c4f2909f81749f4f214701e278c',correctionSha256:'ed137291897adfbd9887191f01fbd1cd5f9eca382f2fc5dd06a0453eed664a8d',
  repository:'127.0.0.1:5007/age20/approval-builder@sha256:b2ed7cea3b936b4054afd8157944dffc0110ae61988b3644716ddaef5214ed31',
  b0Sha256:'f6a2b2cf5781a8a4bbd6ab13c3fd11566c3448c7123cc30ed095fc19f2378e7d',
  manifestDigest:'sha256:b2ed7cea3b936b4054afd8157944dffc0110ae61988b3644716ddaef5214ed31',imageId:'sha256:4088bab6dd858541a6ef1702ef856faf485a8052f06cc997003f14383fd1aa06',platform:'linux/amd64',
  goal:'Release/obj.target/v8_base_without_compiler/deps/v8/src/wasm/wasm-disassembler.o',jobs:1,actionMaximum:256,
  deadlines:{workload:1500,cc:300,cxx:300,generator:120,link:120,admission:120},
  resources:{cpus:2,memory:8589934592,pids:256,seconds:1800,work:17179869184,output:2147483648,stream:67108864,text:134217728}
};
function same(a,b){return JSON.stringify(a)===JSON.stringify(b);}
function keys(value,expected,message){need(value&&typeof value==='object'&&!Array.isArray(value),message+': object required');const missing=expected.filter(k=>!Object.hasOwn(value,k)),extra=Object.keys(value).filter(k=>!expected.includes(k));need(!missing.length&&!extra.length,message+': missing='+missing.join(',')+' unexpected='+extra.join(','));}
function sha(value){return typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);}
function nativeCommand(){return ['/usr/bin/make','-C','/work/node/out','BUILDTYPE=Release','V=1','-j1',nativePolicy.goal];}
function validateNative(m){
  need(m.schema===schema&&m.purpose===nativePurpose,'native purpose/version');
  need(m.platform===nativePolicy.platform&&m.imageId===nativePolicy.imageId&&m.image===nativePolicy.repository,'native image/config/platform identity');
  keys(m.resources,Object.keys(nativePolicy.resources),'native resource keys');
  for(const [k,ceiling]of Object.entries(nativePolicy.resources))need(Number.isSafeInteger(m.resources[k])&&m.resources[k]>0&&m.resources[k]<=ceiling,'native resource ceiling '+k);
  need(m.resources.cpus===2&&m.resources.memory===8589934592&&m.resources.pids===256,'native CPU/RAM/pids identity');
  const n=m.native;
  keys(n,['identity','goal','jobs','command','deadlines','taskCount','evidence'],'native profile keys');
  const expected=Object.fromEntries(Object.entries(nativePolicy).filter(([k])=>!['goal','jobs','actionMaximum','deadlines','resources'].includes(k)));
  keys(n.identity,Object.keys(expected),'native identity keys');for(const [k,v]of Object.entries(expected))need(n.identity[k]===v,'native identity '+k);
  need(n.goal===nativePolicy.goal&&n.jobs===1&&same(n.command,nativeCommand()),'native fixed single goal/-j1 command');
  keys(n.deadlines,Object.keys(nativePolicy.deadlines),'native deadline keys');
  for(const [k,v]of Object.entries(nativePolicy.deadlines))need(Number.isSafeInteger(n.deadlines[k])&&n.deadlines[k]>0&&n.deadlines[k]<=v&&n.deadlines[k]<=m.resources.seconds,'native stage deadline '+k);
  need(Number.isSafeInteger(n.taskCount)&&n.taskCount>0&&n.taskCount<=nativePolicy.actionMaximum,'native exact action count');
  keys(n.evidence,['b0','allowlist','lock','archive','tools','context','sourceAdmission','graphReport','decision','correction'],'native evidence keys');
  for(const [k,ref]of Object.entries(n.evidence)){
    keys(ref,['path','sha256'],'native evidence reference');
    need(typeof ref.path==='string'&&path.isAbsolute(ref.path)&&path.resolve(ref.path)===ref.path&&sha(ref.sha256),'native evidence path/hash '+k);
    need(ref.path.startsWith(m.source+'/')||ref.path.startsWith(m.control+'/'),'native evidence outside source/control projections');
  }
  for(const [k,key]of [['b0','b0Sha256'],['lock','lockSha256'],['archive','archiveSha256'],['context','contextSha256'],['sourceAdmission','sourceAdmissionSha256'],['graphReport','graphReportSha256'],['decision','decisionSha256'],['correction','correctionSha256']])need(n.evidence[k].sha256===nativePolicy[key],'native frozen evidence '+k);
  need(!Object.hasOwn(m,'fixtureArgvBase64'),'native rejects caller fixture argv');
  // Reuse the unchanged fixture validator for common custody/env/tool shapes;
  // native budgets/roles are validated above/below, never admitted via fixture.
  keys(m.recorder.roles,['cc','cxx','link','generator','workload'],'native fixed roles');
  need(m.recorder.roles.workload.path==='/usr/bin/make','native fixed make executable');
  for(const tool of Object.values(m.recorder.roles)){keys(tool,['path','sha256'],'native tool keys');need(tool&&/^\/usr\/[A-Za-z0-9_+./-]+$/.test(tool.path)&&path.resolve(tool.path)===tool.path&&sha(tool.sha256),'native canonical pinned tool');}
  const surrogate=JSON.parse(JSON.stringify(m));surrogate.purpose='owner-synthetic-fixture';surrogate.resources={...caps};surrogate.fixtureArgvBase64=[];
  surrogate.recorder.purpose=surrogate.purpose;delete surrogate.recorder.roles.generator;surrogate.recorder.limits.seconds=30;
  validate(surrogate);
  need(m.recorder.limits.stream<=m.resources.stream&&m.recorder.limits.text<=m.resources.text,'native stream resource mapping');
  need(m.recorder.limits.records>=n.taskCount+1,'native record/task ceiling');
  need(m.recorder.purpose===nativePurpose&&m.recorder.limits.seconds===n.deadlines.workload,'native recorder purpose/deadline');
  need(same(m.recorder.native,n)&&same(m.recorder.resources,m.resources),'host/recorder native policy/resources mismatch');
  return m;
}
function nativeActions(doc,m){
  const n=m.native;
  keys(doc,['schema','b0Sha256','goal','taskCount','actions','unresolved','context'],'supplemental action schema');
  need(doc.schema==='buzz.native-microtarget-actions/v1'&&doc.b0Sha256===nativePolicy.b0Sha256&&doc.goal===nativePolicy.goal,'supplemental B0/goal binding');
  need(Array.isArray(doc.unresolved)&&doc.unresolved.length===0,'STOP_UNRESOLVED_TRANSITIVE_CLOSURE');
  need(doc.taskCount===n.taskCount&&Array.isArray(doc.actions)&&doc.actions.length===n.taskCount,'supplemental exact task count');
  const seen=new Set(),outputs=new Set();
  const workPath=p=>typeof p==='string'&&p.startsWith('/work/node/')&&path.resolve(p)===p&&!p.includes('$');
  need(Array.isArray(doc.context)&&doc.context.length>0&&doc.context.length<=20000&&doc.context.every(f=>workPath(f?.path)&&sha(f.sha256)),'supplemental retained context hashes');
  need(new Set(doc.context.map(f=>f.path)).size===doc.context.length,'duplicate context path');
  const input=item=>{keys(item,['path','sha256'],'action input');need(workPath(item.path)&&sha(item.sha256)&&doc.context.some(f=>f.path===item.path&&f.sha256===item.sha256),'action input/context hash');};
  for(const a of doc.actions){
    keys(a,['id','role','tool','argvBase64','cwd','inputs','outputs','dependencies','orderOnly','ruleSha256','seconds'],'supplemental action keys');
    need(typeof a.id==='string'&&/^[a-z][a-z0-9-]{0,63}$/.test(a.id)&&!seen.has(a.id),'unique action ID');
    need(['cc','cxx','generator','link'].includes(a.role),'STOP_UNLISTED_ACTION_TYPE');
    need(same(a.tool,m.recorder.roles[a.role])&&sha(a.ruleSha256)&&doc.context.some(f=>f.sha256===a.ruleSha256),'action pinned tool/rule hash');
    need(Number.isSafeInteger(a.seconds)&&a.seconds>0&&a.seconds<=n.deadlines[a.role],'action deadline');
    need(workPath(a.cwd)&&Array.isArray(a.argvBase64)&&a.argvBase64.length>0&&a.argvBase64.length<=10000,'action cwd/argv');
    let bytes=0;for(const v of a.argvBase64){need(typeof v==='string'&&Buffer.from(v,'base64').toString('base64')===v&&!Buffer.from(v,'base64').includes(0)&&!Buffer.from(v,'base64').includes(36),'action canonical/expanded argv');bytes+=Buffer.from(v,'base64').length+1;}need(bytes<=1048576,'action argv ceiling');
    need(Buffer.from(a.argvBase64[0],'base64').equals(Buffer.from(a.tool.path)),'action executable argv0');
    need(Array.isArray(a.inputs)&&a.inputs.length>0&&a.inputs.length<=10000,'action exact inputs');for(const i of a.inputs)input(i);
    need(Array.isArray(a.outputs)&&a.outputs.length>0&&a.outputs.length<=10000,'action outputs');
    for(const out of a.outputs){need(workPath(out)&&!outputs.has(out)&&!/(^|\/)mksnapshot(?:$|\.)/.test(out),'no duplicate/mksnapshot output');outputs.add(out);}
    for(const deps of [a.dependencies,a.orderOnly])need(Array.isArray(deps)&&new Set(deps).size===deps.length&&deps.every(d=>seen.has(d)),'missing/unresolved/transitive edge or cycle');
    seen.add(a.id);
  }
  const terminal=doc.actions.find(a=>a.outputs.includes('/work/node/out/'+nativePolicy.goal));need(terminal,'missing fixed object output');
  const closure=new Set();function visit(id){if(closure.has(id))return;closure.add(id);const a=doc.actions.find(x=>x.id===id);for(const d of [...a.dependencies,...a.orderOnly])visit(d);}visit(terminal.id);
  need(closure.size===doc.actions.length,'extraneous action outside fixed goal closure');return doc;
}
function nativeInputs(m){
  const n=m.native,raw={};
  // Raw archive/source/lock references are never normalized into new evidence.
  for(const [k,ref]of Object.entries(n.evidence)){
    const bound=k==='archive'?536870912:67108864;raw[k]=ordinary(ref.path,bound);
    need(digest(raw[k])===ref.sha256,'native raw evidence hash '+k);
  }
  const b0=JSON.parse(raw.b0),lock=JSON.parse(raw.lock),tools=JSON.parse(raw.tools);
  need(b0.schema==='darimuri.age20.solution2-b0-closure/v1'&&b0.goal===nativePolicy.goal&&b0.classification==='NEW_REPRODUCTION_NOT_RECOVERED_R2'&&b0.status==='B0_READ_ONLY_CLOSURE_COMPLETE_NATIVE_EXECUTION_BLOCKED','native B0 dossier schema/goal/status');
  need(lock.nodeVersion==='26.13.1'&&lock.nodeSourceSha256===nativePolicy.archiveSha256&&lock.builderImage===m.image&&lock.platform===m.platform&&lock.gccVersion==='13.3.0'&&lock.target?.commit===nativePolicy.approvalSource&&lock.target?.tree===nativePolicy.approvalTree,'native lock tuple');
  need(lock.packages&&Object.keys(lock.packages).length===200,'native exact package inventory');
  need(same(Object.entries(tools.packages??{}).sort(),Object.entries(lock.packages).sort())&&tools.gccVersion==='13.3.0'&&tools.toolchain==='gcc-13.3.0;x86_64-linux-gnu;python-3.12.3;make-4.3'&&Array.isArray(tools.records),'native tool/package evidence');
  for(const tool of Object.values(m.recorder.roles))need(tools.records.some(t=>t.realpath===tool.path&&t.sha256===tool.sha256),'native missing canonical tool hash');

  return nativeActions(JSON.parse(raw.allowlist),m);
}
function stopNative(){throw Error('STOP_NATIVE_ACTION_BOUNDARY_UNIMPLEMENTED: fixed make/hashed recipes/wrappers do not confine descendant exec; no native Docker or tool launch');}
function nativeAdmission(m,persist=false){
  let status='STOP_NATIVE_ACTION_BOUNDARY_UNIMPLEMENTED',blocker='No reviewed descendant/action-boundary enforcement; no native Docker or tool launch';
  try{validateNative(m);nativeInputs(m);}catch(e){status='STOP_NATIVE_ADMISSION';blocker=e.message;}
  const report={schema,purpose:nativePurpose,status,blocker,goal:nativePolicy.goal,b0Sha256:nativePolicy.b0Sha256,actionCount:m.native?.taskCount??null,nativeExecution:'NOT_STARTED',capture:'NOT_STARTED',qualification:'NOT_EVALUATED',R1:'INCOMPLETE',R2:'BLOCKED',internalCollect2LdArgv:'UNOBSERVED',nodeFidelity:'NOT_PROVEN'};
  if(persist){
    need(output===m.output&&path.isAbsolute(output)&&fs.realpathSync(output)===output&&fs.lstatSync(output).isDirectory()&&fs.readdirSync(output).length===0,'fresh canonical native admission output required');
    save(path.join(output,'native-admission.json'),report);
  }
  return report;
}

// Metadata exception is bound to the original immutable tuple, never to a key alone.
const originalBuilder={manifest:'sha256:b2ed7cea3b936b4054afd8157944dffc0110ae61988b3644716ddaef5214ed31',imageId:'sha256:4088bab6dd858541a6ef1702ef856faf485a8052f06cc997003f14383fd1aa06',platform:'linux/amd64',environment:['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','DEBIAN_FRONTEND=noninteractive']};
function imageEnvironment(m,platformDigest,config,image){
  const raw=config.config?.Env,inspected=image.Config?.Env;
  need(Array.isArray(raw)&&Array.isArray(inspected)&&raw.length===inspected.length&&raw.every((entry,i)=>typeof entry==='string'&&entry===inspected[i]),'raw/inspect ordered image environment mismatch');
  const keys=new Set();
  for(const entry of raw){
    need(/^[A-Za-z_][A-Za-z0-9_]*=[^\x00\r\n]*$/.test(entry),'malformed image environment');
    const key=entry.slice(0,entry.indexOf('='));need(!keys.has(key),'duplicate image environment');keys.add(key);
  }
  const exact=m.image.split('@')[1]===originalBuilder.manifest&&platformDigest===originalBuilder.manifest&&m.imageId===originalBuilder.imageId&&image.Id===originalBuilder.imageId&&m.platform===originalBuilder.platform&&config.os==='linux'&&config.architecture==='amd64'&&image.Os==='linux'&&image.Architecture==='amd64';
  if(exact)need(JSON.stringify(raw)===JSON.stringify(originalBuilder.environment),'original builder environment differs');
  else for(const key of keys)need(['PATH','LANG','LC_ALL','TZ','SOURCE_DATE_EPOCH'].includes(key),'unsafe image environment');
}
function recorderCommand(m){
  if(m.purpose!=='owner-synthetic-fixture')stopNative();
  // No image Env, host Env, shell or PATH-selected launcher reaches Python.
  return ['-i',...Object.entries(m.recorder.environment).map(([k,v])=>k+'='+v),'/usr/bin/python3','-I','-B','-S','/control/recorder.py','fixture','/control/manifest.json'];
}
function mapping(m,repoBytes,platformBytes,configBytes,image){
  need('sha256:'+digest(repoBytes)===m.image.split('@')[1],'repository digest mapping');
  const root=JSON.parse(repoBytes),platform=JSON.parse(platformBytes),config=JSON.parse(configBytes);
  if(Array.isArray(root.manifests)){
    const match=root.manifests.filter(d=>d.platform?.os==='linux'&&d.platform?.architecture==='amd64'&&!d.platform?.variant);
    need(match.length===1&&match[0].digest==='sha256:'+digest(platformBytes)&&match[0].size===platformBytes.length,'OCI platform mapping');
  }else need(repoBytes.equals(platformBytes),'direct repository/platform mapping');
  need(platform.schemaVersion===2&&platform.config?.digest===m.imageId&&platform.config.size===configBytes.length,'OCI config descriptor');
  need('sha256:'+digest(configBytes)===m.imageId&&config.os==='linux'&&config.architecture==='amd64','config identity/platform');
  need(image.Id===m.imageId&&image.Os==='linux'&&image.Architecture==='amd64'&&image.RepoDigests?.includes(m.image),'local image mapping');
  imageEnvironment(m,'sha256:'+digest(platformBytes),config,image);
  return {repository:m.image,platformDigest:'sha256:'+digest(platformBytes),configImageId:m.imageId,platform:m.platform};
}
function createArgs(m,name){return ['create','--name',name,'--platform',m.platform,'--pull','never','--network','none','--read-only','--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges:true','--cpus',String(m.resources.cpus),'--memory',String(m.resources.memory),'--memory-swap',String(m.resources.memory),'--pids-limit',String(m.resources.pids),'--log-driver','none','--ulimit','core=0:0','--workdir','/work',...[[m.source,'/source',true],[m.control,'/control',true],[m.work,'/work',false],[m.output,'/output',false]].flatMap(([s,d,ro])=>['--mount',`type=bind,src=${s},dst=${d}${ro?',readonly':''}`]),'--entrypoint','/usr/bin/env',m.imageId,...recorderCommand(m)];}
function containerIdentity(m,c){
  const h=c.HostConfig;need(c.Image===m.imageId&&c.Config.User==='10001:10001','container image/UID');
  need(JSON.stringify(c.Config.Entrypoint)===JSON.stringify(['/usr/bin/env'])&&JSON.stringify(c.Config.Cmd)===JSON.stringify(recorderCommand(m)),'container fixed clean-environment invocation');
  need(h.NetworkMode==='none'&&h.ReadonlyRootfs&&h.Memory===m.resources.memory&&h.MemorySwap===m.resources.memory&&h.NanoCpus===m.resources.cpus*1e9&&h.PidsLimit===m.resources.pids,'container resources');
  need(h.CapDrop?.length===1&&h.CapDrop[0].toUpperCase()==='ALL'&&!h.CapAdd?.length&&!h.Privileged&&!h.AutoRemove,'container capabilities/lifetime');
  need(h.SecurityOpt?.length===1&&h.SecurityOpt[0]==='no-new-privileges:true'&&h.LogConfig?.Type==='none','container security/log caps');
  need(!h.Devices?.length&&!h.DeviceRequests?.length&&!h.PidMode&&h.IpcMode==='private'&&!Object.keys(h.PortBindings??{}).length,'container isolation');
  const mounts=[[m.source,'/source',false],[m.control,'/control',false],[m.work,'/work',true],[m.output,'/output',true]];
  need(c.Mounts?.length===4&&mounts.every(([s,d,rw])=>c.Mounts.some(x=>x.Type==='bind'&&x.Source===s&&x.Destination===d&&x.RW===rw)),'container mounts');
}
function storage(m){
  const rows=fs.readFileSync('/proc/self/mountinfo','utf8').trim().split('\n').map(x=>{const [a,b]=x.split(' - ');return {fields:a.split(' '),type:b.split(' ')[0]};});
  for(const [p,bound]of [[m.work,m.resources.work],[m.output,m.resources.output]]){
    need(fs.realpathSync(p)===p&&fs.statSync(p).isDirectory(),'canonical storage');
    const row=rows.find(r=>r.fields[4]===p);need(row?.type==='ext4'&&row.fields[5].split(',').includes('rw'),'dedicated bounded ext4 mount');
    const size=fs.statfsSync(p,{bigint:true});need(size.blocks*size.bsize<=BigInt(bound),'storage capacity exceeds ceiling');
    need(fs.readdirSync(p).length===0,'fresh storage only');
  }
  need(fs.statSync(m.work).dev!==fs.statSync(m.output).dev,'separate work/output devices');
  for(const p of [m.source,m.control])need(fs.realpathSync(p)===p&&rows.filter(r=>p===r.fields[4]||p.startsWith(r.fields[4]+'/')).sort((a,b)=>b.fields[4].length-a.fields[4].length)[0]?.fields[5].split(',').includes('ro'),'read-only source/control projection');
}
function dockerConfig(control,root=dockerCustody?.root){
  // Supported trust domain: host root controls mounts and POSIX DAC; workload
  // UID10001 (including its groups/ACL entries) has no host mount/DAC bypass.
  // Protect directory ENTRIES from / downward, not just the two leaf inodes.
  need(typeof root==='string'&&path.isAbsolute(root)&&root!=='/'&&path.resolve(root)===root&&!/[\s,:\\]/.test(root),'explicit canonical Docker custody root');
  need(typeof control==='string'&&path.isAbsolute(control)&&path.resolve(control)===control&&control.startsWith(root+'/'),'control outside Docker custody root');
  const config=path.join(control,'docker-config'),parts=config.split('/').slice(1);
  need(parts.length<=128,'Docker custody depth');
  const rows=fs.readFileSync('/proc/self/mountinfo','utf8').trim().split('\n').map(line=>{
    const sides=line.split(' - '),f=sides[0].split(' '),type=sides[1]?.split(' ')[0];
    need(sides.length===2&&f.length>=6&&/^\d+$/.test(f[0])&&/^\d+$/.test(f[1]),'malformed Docker custody mountinfo');
    return {f,type};
  });
  const mounts=rows.filter(r=>r.f[4]===root);
  need(mounts.length===1&&mounts[0].f[5].split(',').includes('ro'),'explicit read-only Docker custody mount');
  // No intervening mount can redirect the admitted subtree, even another ro bind.
  need(!rows.some(r=>r.f[4].startsWith(root+'/')&&(config===r.f[4]||config.startsWith(r.f[4]+'/'))),'nested Docker custody mount escape');
  const chain=[];let p='/';
  for(let i=0;i<=parts.length;i++){
    if(i)p=path.join(p,parts[i-1]);
    need(fs.realpathSync(p)===p,'canonical Docker custody component');
    const st=fs.lstatSync(p,{bigint:true}),inside=p===root||p.startsWith(root+'/');
    // POSIX access-ACL named user/group write is bounded by the group class
    // mask (mode 0020). Denying group/other writes also denies those ACL paths.
    need(st.isDirectory()&&!st.isSymbolicLink()&&st.uid===0n&&st.gid===0n&&(st.mode&(inside?0o222n:0o022n))===0n,'protected Docker custody component');
    const covering=rows.filter(r=>p===r.f[4]||p.startsWith(r.f[4]==='/'?'/':r.f[4]+'/')).sort((a,b)=>b.f[4].length-a.f[4].length);
    need(covering.length>0&&['ext4','xfs','tmpfs','overlay'].includes(covering[0].type),'unsupported Docker custody filesystem');
    need(covering.filter(r=>r.f[4]===covering[0].f[4]).length===1,'ambiguous Docker custody mount');
    if(inside)need(covering[0].f[0]===mounts[0].f[0]&&covering[0].f[5].split(',').includes('ro'),'Docker custody mount escape');
    chain.push({path:p,identity:['dev','ino','mode','uid','gid'].map(k=>st[k].toString()),mount:covering[0]});
  }
  // Empty only: no config.json, auth, helpers, contexts, plugins or aliases.
  need(fs.readdirSync(config).length===0,'empty credential-free Docker config required');
  if(dockerCustody)need(dockerCustody.root===root&&dockerCustody.control===control&&JSON.stringify(dockerCustody.chain)===JSON.stringify(chain),'Docker custody chain changed');
  else dockerCustody={root,control,chain};
  return config;
}
async function docker(args,timeout=30000,bound=1048576,raw=false,totalBound=2*bound){
  need(env.DOCKER_CONFIG===dockerConfig(path.dirname(env.DOCKER_CONFIG??'')),'explicit Docker config required');
  return await new Promise(resolve=>{
    const chunks={stdout:[],stderr:[]},counts={stdout:0,stderr:0};let error=null;
    const child=spawn('/usr/bin/docker',['--host','unix:///var/run/docker.sock',...args],{env,stdio:['ignore','pipe','pipe']});
    activeDocker.add(child);
    const timer=setTimeout(()=>{error='docker deadline';child.kill('SIGKILL');},timeout);
    for(const k of ['stdout','stderr'])child[k].on('data',b=>{counts[k]+=b.length;if(counts[k]>bound||counts.stdout+counts.stderr>totalBound){error='docker output bound';child.kill('SIGKILL');}else chunks[k].push(b);});
    child.on('error',e=>{error=e.code;});
    child.on('close',(code,signal)=>{activeDocker.delete(child);clearTimeout(timer);const encoding=raw?'base64':'utf8';const bytes=Object.fromEntries(['stdout','stderr'].map(k=>[raw?k+'Base64':k,Buffer.concat(chunks[k]).toString(encoding)]));resolve({code,signal,error,...bytes});});
  });
}
function ok(r){need(!r.error&&r.code===0&&!r.signal,'docker operation failed');return r.stdout;}
function inventory(root,bound){
  const result=[];let total=0,count=0;const deadline=Date.now()+30000;
  function walk(p,depth=0){need(depth<=128,'inventory depth bound');const dir=fs.opendirSync(p);try{let entry;while((entry=dir.readSync())!==null){
    need(++count<=20000&&Date.now()<deadline,'inventory count/deadline bound');const f=path.join(p,entry.name),st=fs.lstatSync(f);
    if(st.isDirectory()){need(fs.realpathSync(f)===f,'inventory directory alias');walk(f,depth+1);}
    else {
      need(st.isFile()&&st.nlink===1,'nonordinary retained artifact');total+=st.size;need(total<=bound,'inventory storage bound');
      const before=fs.lstatSync(f,{bigint:true});const fd=fs.openSync(f,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);const hash=crypto.createHash('sha256');let bytes=0;
      try{const buffer=Buffer.alloc(65536);while(true){need(Date.now()<deadline,'inventory hash deadline');const n=fs.readSync(fd,buffer,0,buffer.length,null);if(!n)break;bytes+=n;need(bytes<=st.size,'inventory mutation bound');hash.update(buffer.subarray(0,n));}const after=fs.fstatSync(fd,{bigint:true}),named=fs.lstatSync(f,{bigint:true});for(const k of ['dev','ino','mode','nlink','size','mtimeNs','ctimeNs'])need(before[k]===after[k]&&before[k]===named[k],'inventory mutation');need(bytes===st.size,'inventory size changed');}finally{fs.closeSync(fd);}
      result.push({path:path.relative(root,f),bytes,sha256:hash.digest('hex')});
    }
  }}finally{dir.closeSync();}}walk(root);return result.sort((a,b)=>a.path.localeCompare(b.path,'en'));
}
function encoded(value){
  need(typeof value==='string'&&Buffer.from(value,'base64').toString('base64')===value,'canonical byte base64');
  const b=Buffer.from(value,'base64');need(!b.includes(0),'NUL in recorded bytes');return b;
}
function vector(value,limits){
  need(Array.isArray(value)&&value.length>0&&value.length<=limits.args,'recorded argv count');
  const args=value.map(encoded);need(args.reduce((n,b)=>n+b.length+1,0)<=limits.argvBytes,'recorded argv bytes');return args;
}
function bytePath(b,root){
  need(b[0]===47&&!b.subarray(1).toString('latin1').split('/').some(x=>!x||x==='.'||x==='..'),'recorded path alias');
  need(b.equals(Buffer.from(root))||b.subarray(0,Buffer.byteLength(root)+1).equals(Buffer.from(root+'/')),'recorded path root');return b;
}
function statRecord(item,limit,single=true){
  need(item&&typeof item==='object'&&Number.isSafeInteger(item.size)&&item.size>=0&&item.size<=limit&&/^[a-f0-9]{64}$/.test(item.sha256),'recorded evidence size/hash');
  const i=item.identity;need(Array.isArray(i)&&i.length===7&&i.every(n=>Number.isFinite(n)&&Number.isInteger(n)&&n>=0),'recorded stat identity');
  need(i.slice(0,5).every(Number.isSafeInteger)&&(i[2]&0o170000)===0o100000&&i[3]>0&&(!single||i[3]===1)&&i[4]===item.size,'recorded ordinary identity');
}
function completion(m,attach){
  if(m.purpose===nativePurpose)stopNative();
  const limits=m.recorder.limits,control=ordinary(path.join(m.control,'manifest.json'),1048576);
  const root=path.join(m.output,'records');need(fs.existsSync(root),'missing records');const ids=fs.readdirSync(root);need(ids.length>0&&ids.length<=limits.records,'record count');
  let workload=null;
  for(const id of ids){
    need(/^[a-f0-9]{32}$/.test(id),'record ID');const p=path.join(root,id);
    const read=(name,bound)=>JSON.parse(ordinary(path.join(p,name),bound));
    const start=read('start.json',4*1048576),spawned=read('spawn.json',1048576),responses=read('responses.json',8*1048576),end=read('completion.json',1048576);
    need(start.schema===schema&&start.status==='STARTED'&&Object.hasOwn(m.recorder.roles,start.role),'invocation start/role');
    need(start.internalCollect2LdArgv==='UNOBSERVED'&&start.nodeFidelity==='NOT_PROVEN'&&end.internalCollect2LdArgv==='UNOBSERVED','fidelity labels');
    need(Number.isInteger(start.recorderPid)&&start.recorderPid>0&&start.recorderPid<=2147483647&&Number.isInteger(spawned.pid)&&spawned.pid>0&&spawned.pid<=2147483647&&spawned.pid!==start.recorderPid&&spawned.processGroup===spawned.pid,'mandatory spawn identity');
    need(Number.isFinite(start.startedMonotonicNs)&&Number.isInteger(start.startedMonotonicNs)&&start.startedMonotonicNs>=0&&Number.isFinite(end.finishedMonotonicNs)&&Number.isInteger(end.finishedMonotonicNs)&&end.finishedMonotonicNs>=start.startedMonotonicNs,'invocation timing');
    const received=vector(start.receivedArgvBase64,limits),forwarded=vector(start.forwardedArgvBase64,limits),cwd=bytePath(encoded(start.cwdBase64),'/work');
    const tool=m.recorder.roles[start.role];
    need(received[0].equals(Buffer.from('/control/'+start.role))&&forwarded[0].equals(Buffer.from(tool.path))&&received.length===forwarded.length&&received.slice(1).every((b,i)=>b.equals(forwarded[i+1])),'received/forwarded argv correlation');
    need(start.tool?.path===tool.path&&start.tool.sha256===tool.sha256&&(start.tool.identity?.[2]&0o111)!==0,'pinned tool correlation');
    statRecord({...start.tool,size:start.tool.identity?.[4]},Number.MAX_SAFE_INTEGER,false);
    need(JSON.stringify(Object.entries(start.environment??{}).sort())===JSON.stringify(Object.entries(m.recorder.environment).sort()),'recorded environment correlation');
    statRecord(start.manifest,1048576);need(encoded(start.manifest.pathBase64).equals(Buffer.from('/control/manifest.json'))&&start.manifest.size===control.length&&start.manifest.sha256===digest(control),'manifest evidence correlation');
    const expected=[];
    for(let position=0;position<received.length-1;position++){
      const arg=received[position+1];if(!arg.includes(64))continue;
      need(arg[0]===64&&arg.length>1&&arg.subarray(1).indexOf(64)===-1,'unsupported recorded response transport');
      const input=arg.subarray(1);const absolute=input[0]===47?input:Buffer.concat([cwd,Buffer.from('/'),input]);
      expected.push({position,path:bytePath(absolute,'/work')});
    }
    need(Array.isArray(responses)&&responses.length===expected.length,'mandatory response metadata');let responseBytes=0;
    const artifacts=['start.json','spawn.json','responses.json','completion.json','stdout.bin','stderr.bin'];
    for(let i=0;i<expected.length;i++){
      const item=responses[i],ref=expected[i],artifact='response-'+String(ref.position).padStart(6,'0')+'.bin';
      statRecord(item,limits.responseFile);need(item.position===ref.position&&item.artifact===artifact&&encoded(item.cwdBase64).equals(cwd)&&encoded(item.pathBase64).equals(ref.path),'response argv/identity correlation');
      const raw=ordinary(path.join(p,artifact),limits.responseFile);responseBytes+=raw.length;need(responseBytes<=limits.responseTotal&&item.size===raw.length&&item.sha256===digest(raw),'response snapshot seal mismatch');artifacts.push(artifact);
    }
    need(JSON.stringify(fs.readdirSync(p).sort())===JSON.stringify(artifacts.sort()),'unexpected/missing invocation stage');
    need(end.schema===schema&&end.status==='CAPTURE_COMPLETE'&&end.blocker===null&&end.cancelSignal===null&&Number.isInteger(end.returncode)&&end.returncode>=-64&&end.returncode<=255,'missing/incomplete recorder completion');
    need(end.signal===(end.returncode<0?-end.returncode:null),'raw exit/signal contradiction');
    let textBytes=0;
    for(const k of ['stdout','stderr']){
      const b=ordinary(path.join(p,k+'.bin'),Math.min(limits.stream,m.resources.stream)),stream=end.streams?.[k];textBytes+=b.length;
      need(stream&&Number.isSafeInteger(stream.bytes)&&stream.bytes===b.length&&stream.sha256===digest(b)&&stream.relayedBytes===stream.bytes&&stream.relayedSha256===stream.sha256,'stream/caller seal mismatch');
    }
    need(textBytes<=limits.text&&textBytes<=m.resources.text,'aggregate stream bound');
    if(start.role==='workload'){
      if(attach!==undefined)for(const k of ['stdout','stderr']){
        const value=attach[k+'Base64'];
        need(typeof value==='string'&&Buffer.from(value,'base64').toString('base64')===value,'canonical raw attach bytes');
        const raw=Buffer.from(value,'base64'),stream=end.streams[k];
        need(raw.length===stream.bytes&&digest(raw)===stream.sha256&&raw.length===stream.relayedBytes&&digest(raw)===stream.relayedSha256,'host attach/spool/relay mismatch '+k);
      }
      need(workload===null&&JSON.stringify(start.receivedArgvBase64.slice(1))===JSON.stringify(m.fixtureArgvBase64),'workload argv/unique completion');workload=end.returncode;
    }
  }
  need(workload!==null,'missing workload completion');return workload<0?128-workload:workload;
}
async function run(m){
  if(typeof m.purpose==='string'&&m.purpose.startsWith('owner-nodev8-prerequisite-measurement')){nativeAdmission(m,true);return 125;}
  const runDeadline=Date.now()+m.resources.seconds*1000;
  storage(m);need(output===m.output,'explicit output mismatch');
  env.DOCKER_CONFIG=dockerConfig(m.control,m.dockerCustodyRoot);
  const control=JSON.parse(ordinary(path.join(m.control,'manifest.json'),1048576));need(JSON.stringify(control)===JSON.stringify({...m.recorder,fixtureArgvBase64:m.fixtureArgvBase64}),'control manifest mismatch');
  const recorder=ordinary(path.join(m.control,'recorder.py'),1048576);need(digest(recorder)===m.recorderSha256,'reviewed recorder digest');
  // Wrappers are owner-created before read-only projection, not trusted by name.
  for(const role of ['cc','cxx','link'])need(ordinary(path.join(m.control,role),4096).toString()===wrapper(role),'fixed wrapper bytes');
  const image=JSON.parse(ok(await docker(['image','inspect',m.imageId])));need(image.length===1,'image inspect count');
  const map=mapping(m,ordinary(m.repositoryManifest,1048576),ordinary(m.platformManifest,1048576),ordinary(m.configImage,1048576),image[0]);
  const name='approval-capture-'+crypto.randomBytes(16).toString('hex');
  save(path.join(m.output,'host-start.json'),{schema,status:'STARTED',name,mapping:map,instrumentation:'NEW wrapper/supervisor topology',internalCollect2LdArgv:'UNOBSERVED'});
  let created=false,blocker=null,final=null;
  try{
    need(!hostCancel,'host cancellation before create');created=true;const r=await docker(createArgs(m,name));save(path.join(m.output,'create.json'),r);ok(r);
    let c=JSON.parse(ok(await docker(['inspect',name])))[0];containerIdentity(m,c);save(path.join(m.output,'prestart-inspect.json'),c);
    need(!hostCancel&&Date.now()<runDeadline,'outer deadline/cancel before start');const attach=await docker(['start','--attach',name],Math.max(1,runDeadline-Date.now()),m.resources.stream,true,m.resources.text);save(path.join(m.output,'attach.json'),attach);
    if(attach.error||attach.signal||hostCancel){const stop=await docker(['stop','--time','2',name]);save(path.join(m.output,'stop.json'),stop);}
    const wait=await docker(['wait',name]);save(path.join(m.output,'wait.json'),wait);ok(wait);
    final=JSON.parse(ok(await docker(['inspect',name])))[0];containerIdentity(m,final);save(path.join(m.output,'final-inspect.json'),final);
    need(!hostCancel&&!final.State.Running&&!final.State.OOMKilled&&!final.State.Error&&!attach.error&&!attach.signal,'container failure/resource termination');
    const code=completion(m,attach);need(code===final.State.ExitCode&&String(code)===wait.stdout.trim()&&attach.code===code,'exit/completion mapping');
  }catch(e){blocker=e.message;}
  finally{
    if(created&&!final){const stop=await docker(['stop','--time','2',name]);save(path.join(m.output,'recovery-stop.json'),stop);const read=await docker(['inspect',name]);save(path.join(m.output,'recovery-inspect.json'),read);}
    // Never rm/prune; persistent storage + exact container survive attach/tool failure.
    try{save(path.join(m.output,'work-inventory.json'),inventory(m.work,m.resources.work));save(path.join(m.output,'output-inventory.json'),inventory(m.output,m.resources.output));}catch(e){blocker??=e.message;}
    save(path.join(m.output,'seal.json'),{schema,status:blocker?'CAPTURE_INCOMPLETE':'CAPTURE_COMPLETE',blocker,container:name,hostCancel,workloadExit:final?.State?.ExitCode??null,internalCollect2LdArgv:'UNOBSERVED',nodeFidelity:'NOT_PROVEN',qualification:'NOT_EVALUATED',custody:'owner must seal storage read-only after container stopped; not tamper-proof against workload UID'});
  }
  need(!blocker,'CAPTURE_INCOMPLETE: '+blocker);
  return final.State.ExitCode;
}
function wrapper(role){return '#!/bin/sh\nexec /usr/bin/python3 -I -B -S /control/recorder.py record /control/manifest.json '+role+' /control/'+role+' "$@"\n';}
try{
  need(['plan','run'].includes(mode),'plan|run manifest.json [output]');
  const parsed=JSON.parse(ordinary(manifestPath,1048576));
  const m=typeof parsed.purpose==='string'&&parsed.purpose.startsWith('owner-nodev8-prerequisite-measurement')?parsed:validate(parsed);
  if(mode==='plan'&&typeof m.purpose==='string'&&m.purpose.startsWith('owner-nodev8-prerequisite-measurement')){console.log(JSON.stringify(nativeAdmission(m),null,2));process.exitCode=125;}
  else if(mode==='plan')console.log(JSON.stringify({schema,status:'PLAN_ONLY',create:createArgs(m,'approval-capture-PLAN'),wrappers:Object.fromEntries(['cc','cxx','link'].map(r=>[r,wrapper(r)])),limits:caps,instrumentation:'NEW wrapper/process topology',internalCollect2LdArgv:'UNOBSERVED',qualification:'NOT_EVALUATED'},null,2));
  else {
    for(const sig of ['SIGTERM','SIGINT','SIGHUP'])process.on(sig,()=>{hostCancel??=sig;for(const child of activeDocker)child.kill('SIGKILL');});
    process.exitCode=await run(m);
  }
}catch(e){console.error('CAPTURE_INCOMPLETE/BLOCKED: '+e.message);process.exitCode=125;}
JS
