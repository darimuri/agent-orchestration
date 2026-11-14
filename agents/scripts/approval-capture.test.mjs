import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import {EventEmitter} from 'node:events';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const script=fileURLToPath(new URL('./capture-approval-failure.sh',import.meta.url));
const recorder=fileURLToPath(new URL('./approval-capture-recorder.py',import.meta.url));
const sh=fs.readFileSync(script,'utf8');
const js=sh.slice(sh.indexOf("const schema="),sh.indexOf('\ntry{\n  need(['));
function helpers(extra={}){return vm.runInNewContext(js+'\n({env,dockerConfig,validate,mapping,imageEnvironment,recorderCommand,createArgs,containerIdentity,completion,inventory,ordinary,wrapper,run,storage,docker})',{
  fs,path,crypto,Buffer,setTimeout,clearTimeout,process:{argv:[]},...extra}, {timeout:1000});}
const digest=b=>crypto.createHash('sha256').update(b).digest('hex');
function fixture(){
  const roles=Object.fromEntries(['cc','cxx','link','workload'].map(r=>[r,{path:'/usr/bin/fake',sha256:'a'.repeat(64)}]));
  return {schema:'buzz.approval-capture/v1',purpose:'owner-synthetic-fixture',image:'example.invalid/builder@sha256:'+'b'.repeat(64),platform:'linux/amd64',imageId:'sha256:'+'c'.repeat(64),source:'/host/source',control:'/host/control',work:'/host/work',output:'/host/output',resources:{cpus:2,memory:2147483648,pids:128,seconds:900,work:2147483648,output:1073741824,stream:67108864,text:134217728},fixtureArgvBase64:[],recorder:{schema:'buzz.approval-capture/v1',purpose:'owner-synthetic-fixture',roles,work:'/work',output:'/output',limits:{args:10000,argvBytes:1048576,responseFile:1048576,responseTotal:16777216,stream:67108864,text:134217728,seconds:30,records:20000},environment:{PATH:'/usr/bin:/bin',LANG:'C',LC_ALL:'C',TZ:'UTC',SOURCE_DATE_EPOCH:'0',CC:'/control/cc',CXX:'/control/cxx',LINK:'/control/link'}}};
}
test('plan validates explicit fixture ceilings and fixed wrapper argv without Docker',()=>{
  const h=helpers(),m=fixture();h.validate(m);const a=Array.from(h.createArgs(m,'fixture'));
  for(const flag of ['create','--network','none','--read-only','--user','10001:10001','--cap-drop','ALL','no-new-privileges:true','--memory-swap','--pids-limit','--pull','never','--log-driver'])assert(a.includes(flag),flag);
  assert(!a.includes('--rm'));assert(!a.includes('pull'));assert(!a.some(x=>/seccomp-unconfined|privileged|docker\.sock/.test(x)));
  assert(a.includes(m.imageId));assert(a.includes('-I'));assert(a.includes('-S'));assert.equal(a.filter(x=>x.startsWith('type=bind')).length,4);
  assert.match(h.wrapper('cc'),/record \/control\/manifest.json cc \/control\/cc "\$@"/);
});
for(const [label,change] of [
  ['mutable image',m=>m.image='ubuntu:latest'],['wrong platform',m=>m.platform='linux/arm64'],['short image ID',m=>m.imageId='sha256:123'],
  ['CPU ceiling',m=>m.resources.cpus=3],['swap/resource injection',m=>m.resources.swap=1],['RAM ceiling',m=>m.resources.memory=8589934592],
  ['deadline',m=>m.resources.seconds=901],['storage',m=>m.resources.work=2147483649],['log cap',m=>m.resources.stream=67108865],
  ['overlap',m=>m.output=m.work+'/nested'],['mount injection',m=>m.source='/a,readonly'],['nonfixture authority',m=>m.purpose='Node-build'],
  ['PATH tool',m=>m.recorder.roles.cc.path='gcc'],['alias tool',m=>m.recorder.roles.cc.path='/usr/bin/../gcc'],['tool hash',m=>m.recorder.roles.cc.sha256='latest'],
  ['env injection',m=>m.recorder.environment.LD_PRELOAD='/evil'],['response ceiling',m=>m.recorder.limits.responseFile=1048577],
  ['unbounded recorder',m=>m.recorder.limits.seconds=31],['malformed argv',m=>m.fixtureArgvBase64=['!!!!']],['NUL argv',m=>m.fixtureArgvBase64=['AA==']],
])test('plan rejects '+label,()=>{const m=fixture();change(m);assert.throws(()=>helpers().validate(m));});
function mapped(rawEnv=['PATH=/usr/bin:/bin'],inspectEnv=rawEnv){
  const m=fixture(),config=Buffer.from(JSON.stringify({os:'linux',architecture:'amd64',config:{Env:rawEnv}}));m.imageId='sha256:'+digest(config);
  const platform=Buffer.from(JSON.stringify({schemaVersion:2,config:{digest:m.imageId,size:config.length},layers:[]}));
  const repo=Buffer.from(JSON.stringify({schemaVersion:2,manifests:[{platform:{os:'linux',architecture:'amd64'},digest:'sha256:'+digest(platform),size:platform.length}]}));
  m.image='example.invalid/builder@sha256:'+digest(repo);
  const image={Id:m.imageId,Os:'linux',Architecture:'amd64',RepoDigests:[m.image],Config:{Env:inspectEnv}};
  return {m,config,platform,repo,image};
}
test('OCI index→platform→config→local image mapping and direct manifest positive controls',()=>{
  const h=helpers(),f=mapped();assert.equal(h.mapping(f.m,f.repo,f.platform,f.config,f.image).configImageId,f.m.imageId);
  f.m.image='example.invalid/builder@sha256:'+digest(f.platform);f.image.RepoDigests=[f.m.image];h.mapping(f.m,f.platform,f.platform,f.config,f.image);
});
for(const [label,change]of [
  ['repo bytes',f=>f.repo=Buffer.from('{}')],['platform bytes',f=>f.platform=Buffer.from('{}')],['config bytes',f=>f.config=Buffer.from('{}')],
  ['missing RepoDigests',f=>delete f.image.RepoDigests],['different local ID',f=>f.image.Id='sha256:'+'d'.repeat(64)],
  ['image environment injection',f=>f.image.Config.Env=['LD_PRELOAD=/evil']],['wrong architecture',f=>f.image.Architecture='arm64'],
])test('mapping fails closed on '+label,()=>{const f=mapped();change(f);assert.throws(()=>helpers().mapping(f.m,f.repo,f.platform,f.config,f.image));});

// Policy fixture uses the owner's exact identity labels after mapping checks.
// Owner raw OCI config/manifest bytes are not available in this container: this
// is not a claim that synthetic JSON hashes to those real content identities.
function originalImage(){
  const m=fixture();const platformDigest='sha256:b2ed7cea3b936b4054afd8157944dffc0110ae61988b3644716ddaef5214ed31';
  m.image='example.invalid/builder@'+platformDigest;m.imageId='sha256:4088bab6dd858541a6ef1702ef856faf485a8052f06cc997003f14383fd1aa06';
  const entries=['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','DEBIAN_FRONTEND=noninteractive'];
  return {m,platformDigest,config:{os:'linux',architecture:'amd64',config:{Env:[...entries]}},image:{Id:m.imageId,Os:'linux',Architecture:'amd64',Config:{Env:[...entries]}}};
}
const audit=f=>helpers().imageEnvironment(f.m,f.platformDigest,f.config,f.image);
test('only the original manifest/platform/config-image tuple admits the exact ordered metadata',()=>{
  const f=originalImage(),before=JSON.stringify(f);audit(f);assert.equal(JSON.stringify(f),before);
  const g=mapped(['PATH=/usr/bin:/bin','LANG=C']);helpers().mapping(g.m,g.repo,g.platform,g.config,g.image);
});
for(const [label,mutate]of [
  ['repository digest',f=>f.m.image='example.invalid/builder@sha256:'+'0'.repeat(64)],
  ['platform manifest digest',f=>f.platformDigest='sha256:'+'0'.repeat(64)],
  ['config image ID',f=>f.m.imageId='sha256:'+'0'.repeat(64)],
  ['local inspect image ID',f=>f.image.Id='sha256:'+'0'.repeat(64)],
  ['requested platform',f=>f.m.platform='linux/arm64'],
  ['raw platform',f=>f.config.architecture='arm64'],
  ['inspect platform',f=>f.image.Architecture='arm64'],
])test('metadata exception rejects wrong '+label,()=>{const f=originalImage();mutate(f);assert.throws(()=>audit(f));});
for(const [label,entries]of [
  ['missing PATH',['DEBIAN_FRONTEND=noninteractive']],
  ['missing DEBIAN_FRONTEND',['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin']],
  ['reordered entries',['DEBIAN_FRONTEND=noninteractive','PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin']],
  ['different PATH',['PATH=/usr/bin:/bin','DEBIAN_FRONTEND=noninteractive']],
  ['different value',['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','DEBIAN_FRONTEND=interactive']],
  ['different casing',['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','debian_frontend=noninteractive']],
  ['different value casing',['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','DEBIAN_FRONTEND=NONINTERACTIVE']],
  ['normalization',['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','DEBIAN_FRONTEND=noninteractive ']],
  ['duplicate PATH',['PATH=/usr/bin:/bin','PATH=/usr/bin:/bin']],
  ['duplicate DEBIAN_FRONTEND',['DEBIAN_FRONTEND=noninteractive','DEBIAN_FRONTEND=noninteractive']],
  ['missing equals',['PATH=/usr/bin:/bin','DEBIAN_FRONTEND']],
  ['malformed key',['PATH=/usr/bin:/bin','=noninteractive']],
  ['nonstring entry',['PATH=/usr/bin:/bin',7]],
  ['NUL entry',['PATH=/usr/bin:/bin','DEBIAN_FRONTEND=noninteractive\0']],
  ['newline entry',['PATH=/usr/bin:/bin','DEBIAN_FRONTEND=noninteractive\n']],
  ['empty arrays',[]],
])test('original builder metadata rejects '+label,()=>{const f=originalImage();f.config.config.Env=entries;f.image.Config.Env=[...entries];assert.throws(()=>audit(f));});
for(const [label,mutate]of [
  ['absent raw Env',f=>delete f.config.config.Env],['absent inspect Env',f=>delete f.image.Config.Env],
  ['absent both Env',f=>{delete f.config.config.Env;delete f.image.Config.Env;}],
  ['non-array raw Env',f=>f.config.config.Env='PATH=/usr/bin:/bin'],['non-array inspect Env',f=>f.image.Config.Env={}],
  ['raw/inspect mismatch',f=>f.image.Config.Env[0]='PATH=/usr/bin:/bin'],
  ['raw/inspect reordering',f=>f.image.Config.Env.reverse()],
])test('raw-config/inspect agreement rejects '+label,()=>{const f=originalImage();mutate(f);assert.throws(()=>audit(f));});
for(const key of ['LD_PRELOAD','PYTHONPATH','PYTHONHOME','CC','CFLAGS','ASAN_OPTIONS','AWS_ACCESS_KEY_ID','CREDENTIAL_HELPER','UNEXPECTED'])
  test('both original and other images reject extra '+key,()=>{
    const f=originalImage();f.config.config.Env.push(key+'=synthetic');f.image.Config.Env.push(key+'=synthetic');assert.throws(()=>audit(f));
    const g=mapped(['PATH=/usr/bin:/bin',key+'=synthetic']);assert.throws(()=>helpers().mapping(g.m,g.repo,g.platform,g.config,g.image));
  });
test('full hash-valid synthetic mapping rejects reordering/duplicates and generic DEBIAN_FRONTEND',()=>{
  for(const [raw,inspect]of [[['PATH=/usr/bin:/bin','LANG=C'],['LANG=C','PATH=/usr/bin:/bin']],[['PATH=/usr/bin:/bin','PATH=/usr/bin:/bin'],['PATH=/usr/bin:/bin','PATH=/usr/bin:/bin']],[['PATH=/usr/bin:/bin','DEBIAN_FRONTEND=noninteractive'],['PATH=/usr/bin:/bin','DEBIAN_FRONTEND=noninteractive']]]){
    const f=mapped(raw,inspect);assert.throws(()=>helpers().mapping(f.m,f.repo,f.platform,f.config,f.image));
  }
});
test('generated Docker/recorder invocation excludes image metadata and keeps the fixed Python environment',()=>{
  const f=originalImage(),h=helpers(),before=JSON.stringify(f.m.recorder);audit(f);
  const args=Array.from(h.createArgs(f.m,'fixture')),command=Array.from(h.recorderCommand(f.m));
  assert.equal(args[args.indexOf('--entrypoint')+1],'/usr/bin/env');assert.equal(command[0],'-i');
  const python=command.indexOf('/usr/bin/python3');assert.deepEqual(command.slice(1,python),Object.entries(f.m.recorder.environment).map(([k,v])=>k+'='+v));
  assert(!args.some(v=>v.includes('DEBIAN_FRONTEND')));assert(!args.includes(f.config.config.Env[0]));assert.equal(JSON.stringify(f.m.recorder),before);
  const py=fs.readFileSync(recorder,'utf8'),fixed=py.match(/FIXED_ENV = (\{[\s\S]*?\})/)[1];
  const entries=[...fixed.matchAll(/'([A-Z_]+)':\s*'([^']*)'/g)].map(([,k,v])=>[k,v]);assert.deepEqual(Object.fromEntries(entries),f.m.recorder.environment);
  assert(!Object.hasOwn(f.m.recorder.environment,'DEBIAN_FRONTEND'));assert(!fixed.includes('DEBIAN_FRONTEND'));
  const bad=fixture();bad.recorder.environment.DEBIAN_FRONTEND='noninteractive';assert.throws(()=>h.validate(bad));
});
test('local env -i synthetic child receives only the fixed environment, not observed image metadata',()=>{
  const f=originalImage(),command=Array.from(helpers().recorderCommand(f.m));
  const prefix=command.slice(0,command.indexOf('/usr/bin/python3'));
  const metadata=Object.fromEntries(f.config.config.Env.map(s=>{const i=s.indexOf('=');return [s.slice(0,i),s.slice(i+1)];}));
  // Real local clean-environment launcher + available Node as an inert env probe.
  // This executes neither Docker nor the owner/Python workload fixture.
  const result=spawnSync('/usr/bin/env',[...prefix,process.execPath,'-e','process.stdout.write(JSON.stringify(process.env))'],{env:metadata,encoding:'utf8',timeout:5000,maxBuffer:16384});
  assert.ifError(result.error);assert.equal(result.status,0,result.stderr);
  const actual=JSON.parse(result.stdout);assert.deepEqual(actual,f.m.recorder.environment);assert(!Object.hasOwn(actual,'DEBIAN_FRONTEND'));
});
function container(m){return {Image:m.imageId,Config:{User:'10001:10001',Entrypoint:['/usr/bin/env'],Cmd:Array.from(helpers().recorderCommand(m))},HostConfig:{NetworkMode:'none',ReadonlyRootfs:true,Memory:m.resources.memory,MemorySwap:m.resources.memory,NanoCpus:2e9,PidsLimit:128,CapDrop:['ALL'],CapAdd:[],Privileged:false,AutoRemove:false,SecurityOpt:['no-new-privileges:true'],LogConfig:{Type:'none'},IpcMode:'private'},Mounts:[[m.source,'/source',false],[m.control,'/control',false],[m.work,'/work',true],[m.output,'/output',true]].map(([Source,Destination,RW])=>({Type:'bind',Source,Destination,RW}))};}
test('inspect readback accepts exact security, mapping, resources and mounts',()=>{const m=fixture();helpers().containerIdentity(m,container(m));});
for(const [label,change]of [
  ['direct image-env entrypoint',c=>c.Config.Entrypoint=['/usr/bin/python3']],
  ['missing clean-environment flag',c=>c.Config.Cmd.shift()],
  ['forwarded metadata entry',c=>c.Config.Cmd.splice(1,0,'DEBIAN_FRONTEND=noninteractive')],
  ['image',c=>c.Image='other'],['UID',c=>c.Config.User='0'],['network',c=>c.HostConfig.NetworkMode='host'],['writable root',c=>c.HostConfig.ReadonlyRootfs=false],
  ['swap',c=>c.HostConfig.MemorySwap=-1],['CPU',c=>c.HostConfig.NanoCpus=3e9],['pids',c=>c.HostConfig.PidsLimit=0],['caps',c=>c.HostConfig.CapAdd=['SYS_PTRACE']],
  ['auto remove',c=>c.HostConfig.AutoRemove=true],['security',c=>c.HostConfig.SecurityOpt=['seccomp:unconfined']],['devices',c=>c.HostConfig.Devices=[{}]],
  ['writable source',c=>c.Mounts[0].RW=true],['extra mount',c=>c.Mounts.push({})],['unbounded log',c=>c.HostConfig.LogConfig.Type='json-file'],
])test('container readback rejects '+label,()=>{const m=fixture(),c=container(m);change(c);assert.throws(()=>helpers().containerIdentity(m,c));});
// Explicit custody metadata facade: no root, mounts or Docker are used by tests.
function custodyFs(control,variant){
  const config=path.join(control,'docker-config');
  return {...fs,
    readFileSync(p,...args){if(p==='/proc/self/mountinfo')return '1 0 1:1 / '+control+' '+(variant==='writable mount'?'rw':'ro')+' - ext4 fixture ro\n'+(variant==='nested writable mount'?'2 1 1:2 / '+config+' rw - ext4 fixture rw\n':'');return fs.readFileSync(p,...args);},
    lstatSync(p,...args){const st=fs.lstatSync(p,...args);if(p===control||p===config){st.uid=variant==='wrong owner'?10001:0;st.gid=variant==='wrong group'?10001:0;st.mode=(st.mode&~0o777)|((variant==='writable directory'||(variant==='writable control'&&p===control))?0o755:0o555);}return st;}
  };
}
test('Docker attach retains byte-safe relay output within existing stream/text caps',async()=>{
  let payload=Buffer.from([0,255,128,65]);
  const spawn=(bin,args,options)=>{
    assert.equal(bin,'/usr/bin/docker');assert.equal(options.env.HOME,'/dev/null');
    const child=new EventEmitter();child.stdout=new EventEmitter();child.stderr=new EventEmitter();child.kill=()=>true;
    queueMicrotask(()=>{child.stdout.emit('data',payload);child.stderr.emit('data',Buffer.from('err'));child.emit('close',0,null);});return child;
  };
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'capture-docker-'));try{
  fs.mkdirSync(path.join(dir,'docker-config'));const h=helpers({spawn,fs:custodyFs(dir)});h.env.DOCKER_CONFIG=h.dockerConfig(dir);let r=await h.docker(['start','--attach','fixture'],1000,16,true,24);
  assert.equal(r.error,null);assert.deepEqual(Buffer.from(r.stdoutBase64,'base64'),payload);assert.equal(Buffer.from(r.stderrBase64,'base64').toString(),'err');
  payload=Buffer.alloc(17);r=await h.docker(['start','--attach','fixture'],1000,16,true,24);assert.equal(r.error,'docker output bound');
  }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
test('host collection rejects missing completion, hardlinks, symlinks and mutation',t=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'capture-host-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const h=helpers(),p=path.join(dir,'f');fs.writeFileSync(p,'bytes');assert.equal(h.ordinary(p,100).toString(),'bytes');
  const hard=path.join(dir,'hard');fs.linkSync(p,hard);assert.throws(()=>h.ordinary(p,100));fs.unlinkSync(hard);
  const sym=path.join(dir,'sym');fs.symlinkSync(p,sym);assert.throws(()=>h.ordinary(sym,100));assert.throws(()=>h.completion({...fixture(),output:dir}));
  assert.throws(()=>h.inventory(dir,1));fs.unlinkSync(sym);
  const facade={...fs,readSync(fd,...args){fs.writeFileSync(p,'changed');return fs.readSync(fd,...args);}};
  assert.throws(()=>helpers({fs:facade}).ordinary(p,100),/mutation/);
});
function record(m,args=['@args.rsp'],code=0){
  const id=path.join(m.output,'records','a'.repeat(32));fs.mkdirSync(id,{recursive:true});
  m.fixtureArgvBase64=args.map(x=>Buffer.from(x).toString('base64'));
  const control=Buffer.from(JSON.stringify({...m.recorder,fixtureArgvBase64:m.fixtureArgvBase64}));fs.mkdirSync(m.control,{recursive:true});fs.writeFileSync(path.join(m.control,'manifest.json'),control);
  const enc=x=>Buffer.from(x).toString('base64'),identity=(n,links=1,mode=0o100644)=>[1,2,mode,links,n,1,1];
  const start={schema:m.schema,status:'STARTED',role:'workload',recorderPid:11,startedMonotonicNs:10,cwdBase64:enc('/work'),receivedArgvBase64:[enc('/control/workload'),...m.fixtureArgvBase64],forwardedArgvBase64:[enc(m.recorder.roles.workload.path),...m.fixtureArgvBase64],environment:m.recorder.environment,tool:{...m.recorder.roles.workload,identity:identity(123,2,0o100755)},manifest:{pathBase64:enc('/control/manifest.json'),size:control.length,sha256:digest(control),identity:identity(control.length)},internalCollect2LdArgv:'UNOBSERVED',nodeFidelity:'NOT_PROVEN'};
  const spawned={pid:12,processGroup:12},responses=[];
  args.forEach((arg,position)=>{if(!arg.startsWith('@'))return;const bytes=Buffer.from('synthetic response bytes'),artifact='response-'+String(position).padStart(6,'0')+'.bin';fs.writeFileSync(path.join(id,artifact),bytes);responses.push({position,artifact,pathBase64:enc('/work/'+arg.slice(1)),cwdBase64:enc('/work'),size:bytes.length,sha256:digest(bytes),identity:identity(bytes.length)});});
  const end={schema:m.schema,status:'CAPTURE_COMPLETE',returncode:code,signal:code<0?-code:null,cancelSignal:null,blocker:null,finishedMonotonicNs:20,internalCollect2LdArgv:'UNOBSERVED',streams:{}};
  for(const k of ['stdout','stderr']){const raw=Buffer.from(k);fs.writeFileSync(path.join(id,k+'.bin'),raw);end.streams[k]={bytes:raw.length,sha256:digest(raw),relayedBytes:raw.length,relayedSha256:digest(raw)};}
  const write=(name,value)=>fs.writeFileSync(path.join(id,name),JSON.stringify(value));
  const flush=()=>{for(const [name,value]of [['start.json',start],['spawn.json',spawned],['responses.json',responses],['completion.json',end]])write(name,value);};flush();
  return {id,start,spawned,responses,end,flush};
}
function recorded(t){const dir=fs.mkdtempSync(path.join(os.tmpdir(),'capture-record-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));const m=fixture();m.output=path.join(dir,'output');m.control=path.join(dir,'control');return {m,...record(m)};}
test('complete stage/response/relay control preserves positive, nonzero and signal mappings',t=>{
  const f=recorded(t),h=helpers();assert.equal(h.completion(f.m),0);
  f.end.returncode=7;f.flush();assert.equal(h.completion(f.m),7);
  f.end.returncode=-15;f.end.signal=15;f.flush();assert.equal(h.completion(f.m),143);
});
const corruptions=[
  ['missing start',f=>fs.unlinkSync(path.join(f.id,'start.json'))],
  ['missing spawn',f=>fs.unlinkSync(path.join(f.id,'spawn.json'))],
  ['missing completion',f=>fs.unlinkSync(path.join(f.id,'completion.json'))],
  ['missing response metadata',f=>fs.unlinkSync(path.join(f.id,'responses.json'))],
  ['missing response bytes',f=>fs.unlinkSync(path.join(f.id,'response-000000.bin'))],
  ['corrupt response bytes',f=>fs.writeFileSync(path.join(f.id,'response-000000.bin'),'corrupt')],
  ['contradictory exit0/signal9',f=>{f.end.signal=9;f.flush();}],
  ['negative exit without signal',f=>{f.end.returncode=-15;f.flush();}],
  ['cancel despite complete',f=>{f.end.cancelSignal=15;f.flush();}],
  ['bad spawn PID',f=>{f.spawned.pid=0;f.flush();}],
  ['bad process group',f=>{f.spawned.processGroup=99;f.flush();}],
  ['missing argv',f=>{delete f.start.receivedArgvBase64;f.flush();}],
  ['forwarded argv differs',f=>{f.start.forwardedArgvBase64.pop();f.flush();}],
  ['malformed base64',f=>{f.start.receivedArgvBase64[1]='!!!!';f.flush();}],
  ['wrong argv0',f=>{f.start.forwardedArgvBase64[0]=Buffer.from('/evil').toString('base64');f.flush();}],
  ['role mismatch',f=>{f.start.role='evil';f.flush();}],
  ['unpinned tool',f=>{f.start.tool.sha256='b'.repeat(64);f.flush();}],
  ['wrong environment',f=>{f.start.environment={LD_PRELOAD:'/evil'};f.flush();}],
  ['bad manifest hash',f=>{f.start.manifest.sha256='0'.repeat(64);f.flush();}],
  ['response row absent',f=>{f.responses.length=0;f.flush();}],
  ['response position',f=>{f.responses[0].position=1;f.flush();}],
  ['response artifact alias',f=>{f.responses[0].artifact='../else';f.flush();}],
  ['response cwd mismatch',f=>{f.responses[0].cwdBase64=Buffer.from('/work/other').toString('base64');f.flush();}],
  ['response path mismatch',f=>{f.responses[0].pathBase64=Buffer.from('/work/other').toString('base64');f.flush();}],
  ['response identity absent',f=>{delete f.responses[0].identity;f.flush();}],
  ['response hardlink identity',f=>{f.responses[0].identity[3]=2;f.flush();}],
  ['response size contradiction',f=>{f.responses[0].size++;f.flush();}],
  ['response hash contradiction',f=>{f.responses[0].sha256='0'.repeat(64);f.flush();}],
  ['corrupt JSON',f=>fs.writeFileSync(path.join(f.id,'spawn.json'),'{')],
  ['wrong relay count',f=>{f.end.streams.stdout.relayedBytes=0;f.flush();}],
  ['wrong relay hash',f=>{f.end.streams.stderr.relayedSha256='0'.repeat(64);f.flush();}],
  ['corrupt stream',f=>fs.writeFileSync(path.join(f.id,'stderr.bin'),'tampered')],
];
for(const [label,mutate]of corruptions)test('completion rejects '+label,t=>{const f=recorded(t);mutate(f);assert.throws(()=>helpers().completion(f.m));});
test('no-response and ordered duplicate references remain valid controls',t=>{
  for(const args of [[],['@args.rsp','@args.rsp']]){const f=recorded(t);fs.rmSync(f.m.output,{recursive:true});record(f.m,args);assert.equal(helpers().completion(f.m),0);}
});

async function controllerCompletion(t,mutate,options={}){
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'capture-complete-controller-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const f=mapped(),m=f.m;for(const k of ['source','control','work','output']){m[k]=path.join(dir,k);fs.mkdirSync(m[k]);}
  const config=path.join(m.control,'docker-config');fs.mkdirSync(config);
  if(options.custody==='missing')fs.rmdirSync(config);
  if(options.custody==='file'){fs.rmdirSync(config);fs.writeFileSync(config,'');}
  if(options.custody==='symlink'){fs.rmdirSync(config);fs.symlinkSync(m.source,config);}
  if(options.custody?.startsWith('entry:'))fs.writeFileSync(path.join(config,options.custody.slice(6)),'{}');
  for(const [key,name,raw]of [['repositoryManifest','repo.json',f.repo],['platformManifest','platform.json',f.platform],['configImage','config.json',f.config]]){m[key]=path.join(dir,name);fs.writeFileSync(m[key],raw);}
  fs.writeFileSync(path.join(m.control,'recorder.py'),'synthetic recorder bytes');m.recorderSha256=digest(Buffer.from('synthetic recorder bytes'));
  for(const role of ['cc','cxx','link'])fs.writeFileSync(path.join(m.control,role),helpers().wrapper(role));
  const code=options.code??0,stages={m,...record(m,['@args.rsp'],code)};
  const streams={stdout:Buffer.from([0,255,128,65]),stderr:Buffer.from([254,0,10,129])};
  for(const [k,raw]of Object.entries(streams)){fs.writeFileSync(path.join(stages.id,k+'.bin'),raw);stages.end.streams[k]={bytes:raw.length,sha256:digest(raw),relayedBytes:raw.length,relayedSha256:digest(raw)};}
  stages.flush();if(mutate)mutate(stages);
  const attached={...streams};if(options.attach)options.attach(attached);
  if(options.custody==='relative')m.control=path.relative(process.cwd(),m.control);
  if(options.custody==='alias')m.control=m.control+'/../control';
  const calls=[],spawn=(bin,argv,opts)=>{
    assert.equal(bin,'/usr/bin/docker');assert.deepEqual(Array.from(argv.slice(0,2)),['--host','unix:///var/run/docker.sock']);
    assert.deepEqual({...opts.env},{PATH:'/usr/bin:/bin',LANG:'C',LC_ALL:'C',TZ:'UTC',HOME:'/dev/null',DOCKER_CONFIG:config});
    const args=argv.slice(2);calls.push(args);let stdout='',stderr='',exit=0;
    if(args[0]==='image')stdout=JSON.stringify([f.image]);
    if(args[0]==='inspect'){const c=container(m);c.State={Running:false,OOMKilled:false,Error:'',ExitCode:code};stdout=JSON.stringify([c]);}
    if(args[0]==='wait')stdout=code+'\n';
    if(args[0]==='start'){stdout=attached.stdout;stderr=attached.stderr;exit=code;}
    const child=new EventEmitter();child.stdout=new EventEmitter();child.stderr=new EventEmitter();child.kill=()=>true;
    queueMicrotask(()=>{child.stdout.emit('data',Buffer.from(stdout));child.stderr.emit('data',Buffer.from(stderr));child.emit('close',exit,null);});return child;
  };
  // Only storage prerequisites and OS custody metadata are facades. Real run,
  // Docker transport, completion validation, raw persistence and seal execute.
  const body=js.slice(0,js.indexOf('function storage(m){'))+'function storage(m){}\n'+js.slice(js.indexOf('function dockerConfig(control){'));
  const h=vm.runInNewContext(body+'\n({run})',{fs:custodyFs(m.control,options.custody),path,crypto,Buffer,output:m.output,spawn,setTimeout,clearTimeout},{timeout:1000});
  if(options.custody){await assert.rejects(()=>h.run(m));assert.equal(calls.length,0);assert(!fs.existsSync(path.join(m.output,'host-start.json')));return;}
  if(mutate||options.attach)await assert.rejects(()=>h.run(m),/CAPTURE_INCOMPLETE/);else assert.equal(await h.run(m),code);
  const seal=JSON.parse(fs.readFileSync(path.join(m.output,'seal.json')));
  assert.equal(seal.status,mutate||options.attach?'CAPTURE_INCOMPLETE':'CAPTURE_COMPLETE');assert.equal(seal.workloadExit,code);
  const saved=JSON.parse(fs.readFileSync(path.join(m.output,'attach.json')));
  for(const k of ['stdout','stderr'])assert.deepEqual(Buffer.from(saved[k+'Base64'],'base64'),attached[k]);
  if(options.attach)assert(seal.blocker.startsWith("host attach/spool/relay mismatch"));
  assert.deepEqual(calls.map(x=>x[0]),['image','create','inspect','start','wait','inspect']);
}
test('whole controller binary attach/spool/relay equality completes intentional exit7',t=>controllerCompletion(t,null,{code:7}));
for(const [label,attach]of [
  ['Docker warning prefix',s=>s.stderr=Buffer.concat([Buffer.from('WARNING: Error loading config file: open /dev/null/config.json: not a directory\n'),s.stderr])],
  ['extra byte',s=>s.stdout=Buffer.concat([s.stdout,Buffer.from([0])])],
  ['truncated stderr',s=>s.stderr=s.stderr.subarray(1)],
  ['missing stdout',s=>s.stdout=Buffer.alloc(0)],
  ['mutated stdout',s=>s.stdout=Buffer.from([0,255,129,65])],
  ['swapped streams',s=>[s.stdout,s.stderr]=[s.stderr,s.stdout]],
])test('whole controller retains raw attach and seals INCOMPLETE for '+label,t=>controllerCompletion(t,null,{code:7,attach}));
for(const custody of ['missing','file','symlink','relative','alias','wrong owner','wrong group','writable directory','writable control','writable mount','nested writable mount','entry:config.json','entry:auths','entry:contexts','entry:credHelpers','entry:alias','entry:unexpected'])
  test('whole controller rejects Docker config before Docker: '+custody,t=>controllerCompletion(t,null,{custody}));
test('whole controller seals COMPLETE for a fully correlated invocation',t=>controllerCompletion(t));
for(const [label,mutate]of corruptions.filter(([label])=>['missing start','missing spawn','missing completion','missing response metadata','missing response bytes','corrupt response bytes','contradictory exit0/signal9','wrong relay hash'].includes(label)))
  test('whole controller seals INCOMPLETE for '+label,t=>controllerCompletion(t,mutate));
test('runner retains failure collection and does not provide cleanup/build/acquisition verbs',()=>{
  for(const word of ['host-start.json','prestart-inspect.json','final-inspect.json','recovery-stop.json','recovery-inspect.json','work-inventory.json','output-inventory.json','seal.json','CAPTURE_INCOMPLETE','UNOBSERVED'])assert(sh.includes(word),word);
  assert(!/\['(?:rm|prune|build|pull)'/.test(sh));assert.match(sh,/if\(created&&!final\)/);assert.match(sh,/finally\{/);
  assert(!/strace|ptrace|LD_PRELOAD|--privileged/.test(sh));
});
test('bounded storage/Docker facade executes failed attach→stop→wait→inspect→collect→seal without workload',async t=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'capture-custody-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const f=mapped(),m=f.m;for(const k of ['source','control','work','output']){m[k]=path.join(dir,k);fs.mkdirSync(m[k]);}
  m.repositoryManifest=path.join(dir,'repo.json');fs.writeFileSync(m.repositoryManifest,f.repo);
  m.platformManifest=path.join(dir,'platform.json');fs.writeFileSync(m.platformManifest,f.platform);
  m.configImage=path.join(dir,'config.json');fs.writeFileSync(m.configImage,f.config);
  fs.writeFileSync(path.join(m.control,'recorder.py'),'synthetic recorder bytes');m.recorderSha256=digest(Buffer.from('synthetic recorder bytes'));
  fs.writeFileSync(path.join(m.control,'manifest.json'),JSON.stringify({...m.recorder,fixtureArgvBase64:m.fixtureArgvBase64}));
  for(const role of ['cc','cxx','link'])fs.writeFileSync(path.join(m.control,role),helpers().wrapper(role));
  const calls=[];const fakeDocker=async args=>{
    calls.push(args);let value='';let code=0,error=null;
    if(args[0]==='image')value=JSON.stringify([f.image]);
    if(args[0]==='inspect'){const c=container(m);c.State={Running:false,OOMKilled:false,Error:'',ExitCode:7};value=JSON.stringify([c]);}
    if(args[0]==='start'){fs.writeFileSync(path.join(m.work,'failed-object.o'),'retained');code=1;error='synthetic lost attach';}
    if(args[0]==='wait')value='7\n';return {code,error,signal:null,stdout:value,stderr:''};
  };
  // Only these two host boundaries are explicit test facades. Production keeps
  // dedicated ext4 + fixed Docker prerequisites and is never invoked here.
  const body=js.slice(0,js.indexOf('function storage(m){'))+'function storage(m){}\n'+
    'function dockerConfig(control){return path.join(control,"docker-config");}\nasync function docker(args,timeout,bound){return fakeDocker(args,timeout,bound);}\n'+
    js.slice(js.indexOf('function ok(r)'));
  const h=vm.runInNewContext(body+'\n({run})',{fs,path,crypto,Buffer,output:m.output,fakeDocker},{timeout:1000});
  await assert.rejects(()=>h.run(m),/CAPTURE_INCOMPLETE/);
  assert.deepEqual(calls.map(x=>x[0]),['image','create','inspect','start','stop','wait','inspect']);
  assert.equal(fs.readFileSync(path.join(m.work,'failed-object.o'),'utf8'),'retained');
  for(const name of ['attach.json','stop.json','wait.json','final-inspect.json','work-inventory.json','output-inventory.json','seal.json'])assert(fs.existsSync(path.join(m.output,name)),name);
  assert.equal(JSON.parse(fs.readFileSync(path.join(m.output,'seal.json'))).status,'CAPTURE_INCOMPLETE');
});

// These are executable behavior fixtures, never a source-pattern substitute for
// Python, Docker, Node/V8 fidelity or the independent owner replay gate.
const behavior=String.raw`
import importlib.util, os, sys, tempfile, json, hashlib, base64, subprocess, signal, concurrent.futures
spec=importlib.util.spec_from_file_location('capture',sys.argv[1]); r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
def check(ok):
    if not ok: raise AssertionError('synthetic capture invariant')
with tempfile.TemporaryDirectory(prefix='capture-behavior-') as root:
    work=root+'/work';out=root+'/output';os.mkdir(work);os.mkdir(out);os.chdir(work)
    tool=root+'/fake';open(tool,'w').write('#!'+sys.executable+'\n'+'''import os,sys,json,signal,time
a=sys.argv[1:]
if a and a[0]=='exit': sys.exit(7)
if a and a[0]=='signal': os.kill(os.getpid(),signal.SIGTERM)
if a and a[0]=='sleep': time.sleep(10)
if a and a[0]=='overflow': os.write(1,b'x'*8192);sys.exit(0)
if a and a[0]=='mutate': open(a[1][1:],'wb').write(b'changed')
os.write(1,json.dumps({'argv':[os.fsencode(x).hex() for x in a],'env':dict(os.environ)},sort_keys=True).encode())
os.write(2,b'separate-stderr')
''');os.chmod(tool,0o700)
    # Independent fake query/binary/dual-stream commands produce output BEFORE a
    # nonzero exit or signal, so an empty caller stream cannot pass by accident.
    original_tool=open(tool).read();prefix='''import threading
def send(fd,data):
    view=memoryview(data)
    while view:
        n=os.write(fd,view);view=view[n:]
if a and a[0] in ['query','binary','burst','exit','signal']:
    mode=a[0]
    if mode=='query':send(1,b'x86_64-synthetic-query\\n');send(2,b'query-stderr\\n')
    elif mode=='burst':
        def flood(fd,byte):
            for _ in range(128):send(fd,byte*32768)
        threads=[threading.Thread(target=flood,args=(1,b'A')),threading.Thread(target=flood,args=(2,b'B'))]
        for thread in threads:thread.start()
        for thread in threads:thread.join()
    else:send(1,bytes(range(256)));send(2,bytes(reversed(range(256))))
    if mode=='exit':sys.exit(7)
    if mode=='signal':os.kill(os.getpid(),signal.SIGTERM)
    sys.exit(0)
'''
    open(tool,'w').write(original_tool.replace("a=sys.argv[1:]\n","a=sys.argv[1:]\n"+prefix))
    manifest=root+'/manifest';open(manifest,'wb').write(b'{}');_,e=r.snapshot(manifest,100)
    m={'roles':{k:{'path':tool,'sha256':hashlib.sha256(open(tool,'rb').read()).hexdigest()} for k in ['cc','cxx','link','workload']},'limits':dict(r.CEILINGS),'work':work,'output':out}
    # Remove ambient Python/loader controls before the recorder guard; nothing is forwarded.
    for k in list(os.environ):
        if k.startswith(('LD_','ASAN_','LSAN_','UBSAN_','GCC_','COMPILER_')) or k in ['PYTHONPATH','PYTHONHOME']: del os.environ[k]
    def invoke(args,_code=None,**options):
        p=subprocess.run([sys.executable,'-I','-B','-S','-c',_code or runner,sys.argv[1],json.dumps(m),json.dumps(e),json.dumps([r.b64(x) for x in args])],env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C',**options},stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=8)
        return p
    runner='''import importlib.util,sys,json,base64
s=importlib.util.spec_from_file_location('r',sys.argv[1]);r=importlib.util.module_from_spec(s);s.loader.exec_module(r)
sys.exit(r.execute(json.loads(sys.argv[2]),json.loads(sys.argv[3]),'cc',[b'/control/cc']+[base64.b64decode(x) for x in json.loads(sys.argv[4])]))
'''
    def latest():
        p=max([out+'/records/'+x for x in os.listdir(out+'/records')],key=os.path.getmtime)
        return p,json.load(open(p+'/completion.json'))
    args=[b'space value',b'quote"single\'',b'',b'-dash',b'\xff']
    direct=subprocess.run([os.fsencode(tool)]+args,env=r.FIXED_ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    p=invoke(args);check(p.returncode==0);d,end=latest();start=json.load(open(d+'/start.json'))
    check(p.stdout==direct.stdout and p.stderr==direct.stderr)
    check(open(d+'/stdout.bin','rb').read()==direct.stdout and open(d+'/stderr.bin','rb').read()==direct.stderr)
    check([base64.b64decode(x) for x in start['receivedArgvBase64']]==[b'/control/cc']+args)
    check([base64.b64decode(x) for x in start['forwardedArgvBase64']]==[os.fsencode(tool)]+args)
    for mode in [b'query',b'binary',b'exit',b'signal',b'burst']:
        direct=subprocess.run([os.fsencode(tool),mode],env=r.FIXED_ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=8)
        p=invoke([mode]);d,end=latest()
        check(p.returncode==direct.returncode and p.stdout==direct.stdout and p.stderr==direct.stderr)
        for name,raw in [('stdout',p.stdout),('stderr',p.stderr)]:
            check(open(d+'/'+name+'.bin','rb').read()==raw)
            check(end['streams'][name]['bytes']==end['streams'][name]['relayedBytes']==len(raw))
            check(end['streams'][name]['sha256']==end['streams'][name]['relayedSha256']==hashlib.sha256(raw).hexdigest())
        check(end['status']=='CAPTURE_COMPLETE')
    # A caller that does not drain cannot make the recorder wait forever or mark
    # a partial relay complete. A closed caller stream must also fail closed.
    m['limits']['seconds']=1
    p=subprocess.Popen([sys.executable,'-I','-B','-S','-c',runner,sys.argv[1],json.dumps(m),json.dumps(e),json.dumps([r.b64(b'burst')])],env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'},stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    check(p.wait(timeout=5)==125);p.communicate(timeout=2);check(latest()[1]['status']=='CAPTURE_INCOMPLETE')
    m['limits']=dict(r.CEILINGS)
    p=subprocess.Popen([sys.executable,'-I','-B','-S','-c',runner,sys.argv[1],json.dumps(m),json.dumps(e),json.dumps([r.b64(b'binary')])],env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'},stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    p.stdout.close();check(p.wait(timeout=5)==125);p.stderr.close();check(latest()[1]['status']=='CAPTURE_INCOMPLETE')
    short=runner.replace('sys.exit(r.execute', '''original=r.os.write
def short_write(fd,data):return original(fd,data[:7])
r.os.write=short_write
sys.exit(r.execute''')
    p=invoke([b'binary'],_code=short);d,end=latest();check(p.returncode==0)
    check(p.stdout==bytes(range(256))==open(d+'/stdout.bin','rb').read())
    check(p.stderr==bytes(reversed(range(256)))==open(d+'/stderr.bin','rb').read())
    for fault in ['read','logger']:
        injection='''original=r.durable
def after_spawn(p,data):
    original(p,data)
    if p.endswith('/spawn.json'):
        def broken(*args):raise OSError('synthetic read failure')
        r.os.read=broken
r.durable=after_spawn
''' if fault=='read' else '''original=r.os.write
def broken(fd,data):
    if r.os.readlink('/proc/self/fd/'+str(fd)).endswith('.bin'):raise OSError('synthetic ENOSPC logger failure')
    return original(fd,data)
r.os.write=broken
'''
        p=invoke([b'binary'],_code=runner.replace('sys.exit(r.execute',injection+'sys.exit(r.execute'))
        check(p.returncode==125 and latest()[1]['status']=='CAPTURE_INCOMPLETE')
    check('SECRET_TOKEN' not in direct.stdout.decode('ascii',errors='ignore'));check(start['internalCollect2LdArgv']=='UNOBSERVED')
    p=invoke(args,SECRET_TOKEN='never-forward');check(p.returncode==0 and b'SECRET_TOKEN' not in p.stdout and b'never-forward' not in p.stdout)
    response=work+'/args.rsp';data=b'"space value"\n\tother';open(response,'wb').write(data)
    check(invoke([b'@args.rsp',b'@args.rsp']).returncode==0);d,end=latest();rs=json.load(open(d+'/responses.json'))
    check([x['position'] for x in rs]==[0,1]);check(open(d+'/response-000000.bin','rb').read()==data)
    check(rs[0]['sha256']==hashlib.sha256(data).hexdigest() and base64.b64decode(rs[0]['cwdBase64'])==os.fsencode(work))
    for mode in ['symlink','hardlink','missing','oversize','nested','selection']:
        pth=work+'/bad.rsp'
        if os.path.lexists(pth): os.unlink(pth)
        if mode=='symlink':os.symlink(response,pth)
        if mode=='hardlink':os.link(response,pth)
        if mode=='oversize':open(pth,'wb').write(b'x'*(m['limits']['responseFile']+1))
        if mode=='nested':open(pth,'wb').write(b'@nested')
        if mode=='selection':open(pth,'wb').write(b'-B/evil')
        check(invoke([b'@bad.rsp']).returncode==125)
        if os.path.lexists(pth):os.unlink(pth)
    check(invoke([b'-Wl,@args.rsp']).returncode==125)
    check(invoke([b'mutate',b'@args.rsp']).returncode==125)
    for a in [b'-B/evil',b'--specs=/evil',b'-fplugin=/evil']:
        check(invoke([a]).returncode!=0)
    check(invoke([],LD_PRELOAD='').returncode!=0)
    for bad in ['missing','digest','role']:
        old=json.loads(json.dumps(m['roles']))
        if bad=='missing':m['roles']['cc']['path']=root+'/missing-tool'
        if bad=='digest':m['roles']['cc']['sha256']='0'*64
        if bad=='role':del m['roles']['cc']
        check(invoke([]).returncode!=0);m['roles']=old
    check(invoke([b'exit']).returncode==7);check(latest()[1]['returncode']==7)
    check(invoke([b'signal']).returncode==-signal.SIGTERM);check(latest()[1]['signal']==signal.SIGTERM)
    m['limits']['seconds']=1;check(invoke([b'sleep']).returncode==125);check('deadline' in latest()[1]['blocker'])
    m['limits']['stream']=128;check(invoke([b'overflow']).returncode==125);check('overflow' in latest()[1]['blocker'])
    m['limits']=dict(r.CEILINGS)
    # Cancellation is propagated as a signal; durable completion records incomplete.
    p=subprocess.Popen([sys.executable,'-I','-B','-S','-c',runner,sys.argv[1],json.dumps(m),json.dumps(e),json.dumps([r.b64(b'sleep')])],env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'})
    import time
    deadline=time.monotonic()+3
    while time.monotonic()<deadline:
        if any(os.path.exists(out+'/records/'+x+'/stdout.bin') and not os.path.exists(out+'/records/'+x+'/completion.json') for x in os.listdir(out+'/records')):break
        time.sleep(.02)
    p.send_signal(signal.SIGTERM);check(p.wait(timeout=5)==-signal.SIGTERM);check(latest()[1]['status']=='CAPTURE_INCOMPLETE')
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        check(all(x.returncode==0 for x in pool.map(lambda _:invoke([b'parallel']),range(8))))
    ids=os.listdir(out+'/records');check(len(ids)==len(set(ids)))
    # Actual abrupt loss of recorder completion; separately reap its test child group.
    p=subprocess.Popen([sys.executable,'-I','-B','-S','-c',runner,sys.argv[1],json.dumps(m),json.dumps(e),json.dumps([r.b64(b'sleep')])],env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'})
    deadline=time.monotonic()+3;lost=None
    while time.monotonic()<deadline:
        for x in set(os.listdir(out+'/records'))-set(ids):
            candidate=out+'/records/'+x
            if os.path.exists(candidate+'/spawn.json'):lost=candidate;break
        if lost:break
        time.sleep(.02)
    check(lost is not None);p.kill();check(p.wait(timeout=3)==-signal.SIGKILL)
    os.killpg(json.load(open(lost+'/spawn.json'))['pid'],signal.SIGKILL)
    check(os.path.exists(lost+'/start.json') and not os.path.exists(lost+'/completion.json'))
    # Deterministic mutation during O_NOFOLLOW read, plus logger/quota failures.
    original=r.os.read
    def mutate(fd,n):
        b=original(fd,n);open(response,'wb').write(b'other');return b
    r.os.read=mutate
    try:r.snapshot(response,100);raise AssertionError('mutation accepted')
    except r.Blocked:pass
    finally:r.os.read=original
    original_write=r.os.write
    def quota(fd,data):raise OSError('synthetic ENOSPC')
    r.os.write=quota
    try:r.durable(out+'/disk-failure',b'x');raise AssertionError('disk failure accepted')
    except OSError:pass
    finally:r.os.write=original_write
    # A killed recorder may lack completion. Never infer PASS from a start record.
    missing=out+'/records/'+'f'*32;os.mkdir(missing);open(missing+'/start.json','w').write('{}');check(not os.path.exists(missing+'/completion.json'))
print('synthetic behavior and direct replay only; Node/internal linker fidelity NOT_PROVEN')
`;
test('MANDATORY real Python recorder behavior and direct-vs-recorded synthetic replay',()=>{
  assert(fs.existsSync('/usr/bin/python3'),'mandatory /usr/bin/python3 unavailable; recorder behaviors NOT VERIFIED');
  const r=spawnSync('/usr/bin/python3',['-I','-B','-S','-c',behavior,recorder],{env:{PATH:'/usr/bin:/bin',LANG:'C',LC_ALL:'C'},encoding:'utf8',timeout:45000,maxBuffer:1024*1024});
  assert.ifError(r.error);assert.equal(r.status,0,r.stderr);assert.match(r.stdout,/NOT_PROVEN/);
});
