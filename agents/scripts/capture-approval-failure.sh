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
const env={PATH:'/usr/bin:/bin',LANG:'C',LC_ALL:'C',TZ:'UTC',HOME:'/dev/null',DOCKER_CONFIG:'/dev/null'};
let hostCancel=null;const activeDocker=new Set();
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
  need(m.schema===schema&&m.purpose==='owner-synthetic-fixture','fixture schema/authority');
  need(/^[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}$/.test(m.image),'immutable repository manifest');
  need(m.platform==='linux/amd64','admitted fixture platform');
  need(/^sha256:[a-f0-9]{64}$/.test(m.imageId),'full config image ID');
  need(Object.keys(m.resources).sort().join(',')===Object.keys(caps).sort().join(','),'resource keys');
  for(const [k,v]of Object.entries(caps))need(Number.isSafeInteger(m.resources[k])&&m.resources[k]>0&&m.resources[k]<=v,'resource bound '+k);
  need(m.resources.memory===2147483648&&m.resources.cpus===2&&m.resources.pids===128,'fixture resource identity');
  const roots=[m.source,m.control,m.work,m.output];
  need(roots.every(p=>typeof p==='string'&&path.isAbsolute(p)&&!/[\s,:\\]/.test(p)),'mount path syntax');
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
async function docker(args,timeout=30000,bound=1048576,raw=false,totalBound=2*bound){
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
function completion(m){
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
      need(workload===null&&JSON.stringify(start.receivedArgvBase64.slice(1))===JSON.stringify(m.fixtureArgvBase64),'workload argv/unique completion');workload=end.returncode;
    }
  }
  need(workload!==null,'missing workload completion');return workload<0?128-workload:workload;
}
async function run(m){
  const runDeadline=Date.now()+m.resources.seconds*1000;
  storage(m);need(output===m.output,'explicit output mismatch');
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
    const code=completion(m);need(code===final.State.ExitCode&&String(code)===wait.stdout.trim()&&attach.code===code,'exit/completion mapping');
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
  const m=validate(JSON.parse(ordinary(manifestPath,1048576)));
  if(mode==='plan')console.log(JSON.stringify({schema,status:'PLAN_ONLY',create:createArgs(m,'approval-capture-PLAN'),wrappers:Object.fromEntries(['cc','cxx','link'].map(r=>[r,wrapper(r)])),limits:caps,instrumentation:'NEW wrapper/process topology',internalCollect2LdArgv:'UNOBSERVED',qualification:'NOT_EVALUATED'},null,2));
  else {
    for(const sig of ['SIGTERM','SIGINT','SIGHUP'])process.on(sig,()=>{hostCancel??=sig;for(const child of activeDocker)child.kill('SIGKILL');});
    process.exitCode=await run(m);
  }
}catch(e){console.error('CAPTURE_INCOMPLETE/BLOCKED: '+e.message);process.exitCode=125;}
JS
