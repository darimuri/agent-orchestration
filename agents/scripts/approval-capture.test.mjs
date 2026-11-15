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
function helpers(extra={}){return vm.runInNewContext(js+'\n({nativePolicy,nativePurpose,nativeCommand,validateNative,nativeActions,nativeInputs,nativeAdmission,env,dockerConfig,validate,mapping,imageEnvironment,recorderCommand,createArgs,containerIdentity,completion,inventory,ordinary,wrapper,run,storage,docker})',{
  fs,path,crypto,Buffer,setTimeout,clearTimeout,process:{argv:[]},...extra}, {timeout:1000});}
const digest=b=>crypto.createHash('sha256').update(b).digest('hex');
function fixture(){
  const roles=Object.fromEntries(['cc','cxx','link','workload'].map(r=>[r,{path:'/usr/bin/fake',sha256:'a'.repeat(64)}]));
  return {schema:'buzz.approval-capture/v1',purpose:'owner-synthetic-fixture',image:'example.invalid/builder@sha256:'+'b'.repeat(64),platform:'linux/amd64',imageId:'sha256:'+'c'.repeat(64),dockerCustodyRoot:'/host',source:'/host/source',control:'/host/control',work:'/host/work',output:'/host/output',resources:{cpus:2,memory:2147483648,pids:128,seconds:900,work:2147483648,output:1073741824,stream:67108864,text:134217728},fixtureArgvBase64:[],recorder:{schema:'buzz.approval-capture/v1',purpose:'owner-synthetic-fixture',roles,work:'/work',output:'/output',limits:{args:10000,argvBytes:1048576,responseFile:1048576,responseTotal:16777216,stream:67108864,text:134217728,seconds:30,records:20000},environment:{PATH:'/usr/bin:/bin',LANG:'C',LC_ALL:'C',TZ:'UTC',SOURCE_DATE_EPOCH:'0',CC:'/control/cc',CXX:'/control/cxx',LINK:'/control/link'}}};
}
test('plan validates explicit fixture ceilings and fixed wrapper argv without Docker',()=>{
  const h=helpers(),m=fixture();h.validate(m);const a=Array.from(h.createArgs(m,'fixture'));
  for(const flag of ['create','--network','none','--read-only','--user','10001:10001','--cap-drop','ALL','no-new-privileges:true','--memory-swap','--pids-limit','--pull','never','--log-driver'])assert(a.includes(flag),flag);
  assert(!a.includes('--rm'));assert(!a.includes('pull'));assert(!a.some(x=>/seccomp-unconfined|privileged|docker\.sock/.test(x)));
  assert(a.includes(m.imageId));assert(a.includes('-I'));assert(a.includes('-S'));assert.equal(a.filter(x=>x.startsWith('type=bind')).length,4);
  assert.match(h.wrapper('cc'),/record \/control\/manifest.json cc \/control\/cc "\$@"/);
});
for(const [label,change] of [
  ['missing custody root',m=>delete m.dockerCustodyRoot],['relative custody root',m=>m.dockerCustodyRoot='host'],['global custody root',m=>m.dockerCustodyRoot='/'],['custody root escape',m=>m.dockerCustodyRoot='/different'],['aliased custody root',m=>m.dockerCustodyRoot='/host/../host'],
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
function custodyFs(control,variant,root=path.dirname(control)){
  const config=path.join(control,'docker-config'),ancestor=path.dirname(root);
  return {...fs,
    readFileSync(p,...args){
      if(p!=='/proc/self/mountinfo')return fs.readFileSync(p,...args);
      if(variant==='malformed mountinfo')return 'bad mountinfo';
      const base='1 0 1:1 / / rw - '+(variant==='non-POSIX filesystem'?'nfs4':'ext4')+' fixture rw\n';
      const projection=variant==='missing root mount'?'':'2 1 1:2 / '+root+' '+(variant==='writable mount'?'rw':'ro')+' - ext4 fixture ro\n';
      const nested=['nested writable mount','nested readonly mount'].includes(variant)?'3 2 1:3 / '+control+' '+(variant==='nested writable mount'?'rw':'ro')+' - ext4 fixture ro\n':'';
      return base+projection+nested+(variant==='ambiguous mount'?projection:'');
    },
    lstatSync(p,...args){
      const st=fs.lstatSync(p,...args),big=typeof st.mode==='bigint';
      if(big)for(const k of ['uid','gid','mode'])st[k]=Number(st[k]);
      if(p==='/'||p===config||config.startsWith(p+'/')){
        const inside=p===root||p.startsWith(root+'/');st.uid=0;st.gid=0;st.mode=(st.mode&~0o777)|(inside?0o555:0o755);
        if(p===control||p===config){if(variant==='wrong owner')st.uid=10001;if(variant==='wrong group')st.gid=10001;if(variant==='writable directory'||(variant==='writable control'&&p===control))st.mode|=0o200;}
        if(p===ancestor){
          if(variant==='untrusted ancestor')st.uid=10001;
          if(variant==='writable ancestor')st.mode|=0o022;
          if(variant==='group writable ancestor'||variant==='ACL write mask')st.mode|=0o020;
          if(variant==='other writable ancestor')st.mode|=0o002;
          if(variant==='wrong ancestor group')st.gid=10001;
        }
      }
      if(big)for(const k of ['uid','gid','mode'])st[k]=BigInt(st[k]);
      return st;
    }
  };
}
// Scratch directory operations are real. Only mount/UID metadata and Docker
// spawn are synthetic; no credential file or privileged operation is involved.
function custodyScratch(t){
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'capture-chain-'));
  t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const ancestor=path.join(dir,'replaceable'),root=path.join(ancestor,'trusted'),control=path.join(root,'control'),config=path.join(control,'docker-config');
  fs.mkdirSync(config,{recursive:true});return {dir,ancestor,root,control,config};
}
test('Reviewer rename/substitution reproduction is rejected before final leaf read or spawn',async t=>{
  const f=custodyScratch(t);let swapped=false,spawned=0;
  const substitute=()=>{
    fs.renameSync(f.ancestor,f.ancestor+'-old');fs.mkdirSync(f.config,{recursive:true});
    fs.writeFileSync(path.join(f.config,'config.json'),'synthetic sentinel');swapped=true;
  };
  const facade=custodyFs(f.control,'untrusted ancestor',f.root);
  facade.readdirSync=p=>{const result=fs.readdirSync(p);if(p===f.config)substitute();return result;};
  const h=helpers({fs:facade,spawn(){spawned++;throw Error('must not spawn');}});
  assert.throws(()=>h.dockerConfig(f.control,f.root),/protected Docker custody component/);
  h.env.DOCKER_CONFIG=f.config;await assert.rejects(()=>h.docker(['image','inspect','fixture']));
  assert.equal(spawned,0);assert.equal(swapped,false);
  // Prove the intended concurrent-actor scratch rename/replacement is possible,
  // rather than a broken attack hook accidentally making this test pass.
  substitute();assert.equal(fs.readFileSync(path.join(f.config,'config.json'),'utf8'),'synthetic sentinel');
});
for(const change of ['config entry','ancestor replacement','ancestor permissions','mount change'])
  test('custody revalidation blocks next Docker call after '+change,async t=>{
    const f=custodyScratch(t);let calls=0,changed=false;
    const facade=custodyFs(f.control,null,f.root),readMount=facade.readFileSync,stat=facade.lstatSync;
    facade.readFileSync=(p,...args)=>changed&&change==='mount change'&&p==='/proc/self/mountinfo'?readMount(p,...args).replace('2 1 1:2','9 1 1:2'):readMount(p,...args);
    facade.lstatSync=(p,...args)=>{const st=stat(p,...args);if(changed&&change==='ancestor permissions'&&p===f.ancestor)st.mode|=0o020n;return st;};
    const spawn=()=>{calls++;const child=new EventEmitter();child.stdout=new EventEmitter();child.stderr=new EventEmitter();child.kill=()=>true;queueMicrotask(()=>child.emit('close',0,null));return child;};
    const h=helpers({fs:facade,spawn});h.env.DOCKER_CONFIG=h.dockerConfig(f.control,f.root);
    assert.equal((await h.docker(['image','inspect','fixture'])).code,0);assert.equal(calls,1);
    if(change==='config entry')fs.writeFileSync(path.join(f.config,'config.json'),'synthetic sentinel');
    if(change==='ancestor replacement'){fs.renameSync(f.ancestor,f.ancestor+'-old');fs.mkdirSync(f.config,{recursive:true});}
    changed=true;
    await assert.rejects(()=>h.docker(['image','inspect','fixture']),/Docker custody|credential-free/);
    assert.equal(calls,1);
  });

test('Docker attach retains byte-safe relay output within existing stream/text caps',async()=>{
  let payload=Buffer.from([0,255,128,65]);
  const spawn=(bin,args,options)=>{
    assert.equal(bin,'/usr/bin/docker');assert.equal(options.env.HOME,'/dev/null');
    const child=new EventEmitter();child.stdout=new EventEmitter();child.stderr=new EventEmitter();child.kill=()=>true;
    queueMicrotask(()=>{child.stdout.emit('data',payload);child.stderr.emit('data',Buffer.from('err'));child.emit('close',0,null);});return child;
  };
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'capture-docker-'));try{
  const control=path.join(dir,'control');fs.mkdirSync(control);fs.mkdirSync(path.join(control,'docker-config'));const h=helpers({spawn,fs:custodyFs(control,null,dir)});h.env.DOCKER_CONFIG=h.dockerConfig(control,dir);let r=await h.docker(['start','--attach','fixture'],1000,16,true,24);
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
  m.dockerCustodyRoot=dir;
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
  if(options.custody==='missing root')delete m.dockerCustodyRoot;
  if(options.custody==='root escape')m.dockerCustodyRoot=path.join(dir,'elsewhere');
  if(options.custody==='ancestor symlink'){const target=dir+'-real';fs.renameSync(dir,target);fs.symlinkSync(target,dir);t.after(()=>{if(fs.existsSync(dir))fs.unlinkSync(dir);fs.rmSync(target,{recursive:true,force:true});});}
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
  const body=js.slice(0,js.indexOf('function storage(m){'))+'function storage(m){}\n'+js.slice(js.indexOf('function dockerConfig(control,root='));
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
for(const custody of ['missing root','root escape','missing root mount','malformed mountinfo','ambiguous mount','non-POSIX filesystem','writable ancestor','untrusted ancestor','group writable ancestor','other writable ancestor','ACL write mask','wrong ancestor group','ancestor symlink','nested readonly mount','missing','file','symlink','relative','alias','wrong owner','wrong group','writable directory','writable control','writable mount','nested writable mount','entry:config.json','entry:auths','entry:contexts','entry:credHelpers','entry:alias','entry:unexpected'])
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

test('native recorder policy matches host pins and has no duplicate top-level functions',()=>{
  const source=fs.readFileSync(recorder,'utf8');
  const policy=source.match(/NATIVE_POLICY = json.loads\(r'''([\s\S]*?)'''\)/);
  assert(policy);assert.deepEqual(JSON.parse(policy[1]),clone(helpers().nativePolicy));
  const names=Array.from(source.matchAll(/^def ([a-z_]+)\(/gm),m=>m[1]);
  assert.equal(new Set(names).size,names.length);
  assert.equal((source.match(/^if __name__ == '__main__':/gm)||[]).length,1);
});

// Native fixtures below are synthetic policy data, not historical B0/archive or
// executable B1 closure evidence. No Docker, make, configure or compiler runs.
const clone=value=>JSON.parse(JSON.stringify(value));
function nativeFixture(){
  const p=clone(helpers().nativePolicy),m=fixture();m.purpose=helpers().nativePurpose;
  delete m.fixtureArgvBase64;m.source='/native-fixture';m.resources=clone(p.resources);m.image=p.repository;m.imageId=p.imageId;
  m.recorder.purpose=m.purpose;m.recorder.roles.generator={path:'/usr/bin/python3',sha256:'a'.repeat(64)};
  m.recorder.roles.workload={path:'/usr/bin/make',sha256:'b'.repeat(64)};
  m.recorder.limits.seconds=1500;m.recorder.resources=clone(m.resources);
  const identity=Object.fromEntries(Object.entries(p).filter(([k])=>!['goal','jobs','actionMaximum','deadlines','resources'].includes(k)));
  const pins={b0:'b0Sha256',lock:'lockSha256',archive:'archiveSha256',context:'contextSha256',sourceAdmission:'sourceAdmissionSha256',graphReport:'graphReportSha256',decision:'decisionSha256',correction:'correctionSha256'};
  const evidence=Object.fromEntries(['b0','allowlist','lock','archive','tools','context','sourceAdmission','graphReport','decision','correction'].map(k=>[k,{path:'/native-fixture/'+k,sha256:p[pins[k]]??'c'.repeat(64)}]));
  m.native={identity,goal:p.goal,jobs:1,command:Array.from(helpers().nativeCommand()),deadlines:clone(p.deadlines),taskCount:1,evidence};m.recorder.native=m.native;
  const source={path:'/work/node/src/synthetic.cc',sha256:'d'.repeat(64)},rule={path:'/work/node/out/synthetic.mk',sha256:'e'.repeat(64)};
  const action={id:'compile',role:'cxx',tool:clone(m.recorder.roles.cxx),argvBase64:[m.recorder.roles.cxx.path,'-c',source.path,'-o','/work/node/out/'+p.goal].map(x=>Buffer.from(x).toString('base64')),cwd:'/work/node/out',inputs:[source],outputs:['/work/node/out/'+p.goal],dependencies:[],orderOnly:[],ruleSha256:rule.sha256,seconds:300};
  const doc={schema:'buzz.native-microtarget-actions/v1',b0Sha256:p.b0Sha256,goal:p.goal,taskCount:1,actions:[action],unresolved:[],context:[source,rule]};
  return {m,p,doc};
}
test('native purpose has separate fixed tuple, single make goal, budgets and role set',()=>{
  const {m,doc}=nativeFixture(),h=helpers();h.validate(m);h.nativeActions(doc,m);
  assert.equal(m.native.taskCount,1);assert.equal(m.resources.memory,8589934592);assert.equal(m.native.command.at(-2),'-j1');
  assert.throws(()=>h.recorderCommand(m),/STOP_NATIVE_ACTION_BOUNDARY_UNIMPLEMENTED/);
  assert.throws(()=>h.createArgs(m,'native'),/STOP_NATIVE_ACTION_BOUNDARY_UNIMPLEMENTED/);
  assert.throws(()=>h.completion(m,{}),/STOP_NATIVE_ACTION_BOUNDARY_UNIMPLEMENTED/);
  const old=fixture();h.validate(old);assert.equal(old.resources.memory,2147483648);assert.equal(old.recorder.limits.seconds,30);
});
for(const [label,change]of [
  ['version',m=>m.purpose+='2'],['source identity',m=>m.native.identity.approvalSource='0'.repeat(40)],
  ['B0 identity',m=>m.native.identity.b0Sha256='0'.repeat(64)],['archive identity',m=>m.native.identity.archiveSha256='0'.repeat(64)],
  ['lock identity',m=>m.native.evidence.lock.sha256='0'.repeat(64)],['context identity',m=>m.native.evidence.context.sha256='0'.repeat(64)],
  ['source-admission identity',m=>m.native.evidence.sourceAdmission.sha256='0'.repeat(64)],
  ['image repository',m=>m.image='elsewhere@'+m.image.split('@')[1]],['config ID',m=>m.imageId='sha256:'+'0'.repeat(64)],['platform',m=>m.platform='linux/arm64'],
  ['default-all',m=>m.native.command.pop()],['extra target',m=>m.native.command.push('all')],['install',m=>m.native.command[6]='install'],['mksnapshot link',m=>m.native.command[6]='Release/mksnapshot'],
  ['parallel jobs',m=>m.native.command[5]='-j2'],['configure',m=>m.native.command=['/usr/bin/python3','configure']],
  ['missing task count',m=>delete m.native.taskCount],['aggregate15 count',m=>m.native.taskCount='15'],['task cap',m=>m.native.taskCount=257],
  ['missing allowlist',m=>delete m.native.evidence.allowlist],['missing allowlist hash',m=>delete m.native.evidence.allowlist.sha256],
  ['missing tool hash',m=>delete m.recorder.roles.generator.sha256],['unknown role',m=>m.recorder.roles.shell=m.recorder.roles.generator],
  ['caller argv',m=>m.fixtureArgvBase64=[]],['environment override',m=>m.recorder.environment.CFLAGS='-O0'],
  ['CPU cap',m=>m.resources.cpus=3],['memory cap',m=>m.resources.memory++],['swap field',m=>m.resources.swap=1],['pids cap',m=>m.resources.pids++],
  ['outer cap',m=>m.resources.seconds++],['work quota',m=>m.resources.work++],['output quota',m=>m.resources.output++],
  ['make deadline',m=>m.native.deadlines.workload++],['compiler deadline',m=>m.native.deadlines.cxx++],['generator deadline',m=>m.native.deadlines.generator++],['bootstrap deadline',m=>m.native.deadlines.link++],
  ['record cap',m=>m.recorder.limits.records=20001],['insufficient records',m=>m.recorder.limits.records=1],['stream cap',m=>m.resources.stream=67108865],
  ['outside evidence projection',m=>m.native.evidence.allowlist.path='/outside/allowlist'],['relative evidence',m=>m.native.evidence.allowlist.path='relative'],['custody root',m=>m.dockerCustodyRoot='/different'],
])test('native metadata rejects '+label,()=>{const {m}=nativeFixture();change(m);assert.throws(()=>helpers().validateNative(m));});
for(const [label,change]of [
  ['unresolved expansion',d=>d.unresolved=['$(OBJS)']],['count disagreement',d=>d.taskCount=15],['missing transitive edge',d=>d.actions[0].dependencies=['missing']],
  ['unknown helper',d=>d.actions[0].role='shell'],['tool substitution',d=>d.actions[0].tool.path='/usr/bin/unlisted-helper'],
  ['missing rule hash',d=>delete d.actions[0].ruleSha256],['wrong rule hash',d=>d.actions[0].ruleSha256='f'.repeat(64)],
  ['missing input hash',d=>delete d.actions[0].inputs[0].sha256],['context mismatch',d=>d.context=[]],['duplicate context',d=>d.context.push(d.context[0])],
  ['expanded argv missing',d=>d.actions[0].argvBase64=[]],['unexpanded argv',d=>d.actions[0].argvBase64.push(Buffer.from('$(OBJS)').toString('base64'))],
  ['noncanonical argv',d=>d.actions[0].argvBase64.push('!!!!')],['wrong argv0',d=>d.actions[0].argvBase64[0]=Buffer.from('/usr/bin/else').toString('base64')],
  ['output escape',d=>d.actions[0].outputs=['/tmp/escape']],['mksnapshot output',d=>d.actions[0].outputs=['/work/node/out/Release/mksnapshot']],
  ['goal output missing',d=>d.actions[0].outputs=['/work/node/out/other.o']],['compiler cap',d=>d.actions[0].seconds=301],
])test('supplemental actions reject '+label,()=>{const {m,doc}=nativeFixture();change(doc);assert.throws(()=>helpers().nativeActions(doc,m));});
function nativeEvidenceFixture(){
  const f=nativeFixture(),{m,p,doc}=f,pack=Object.fromEntries(Array.from({length:200},(_,i)=>['synthetic-package-'+i,'1']));
  const raw={b0:Buffer.from(JSON.stringify({schema:'darimuri.age20.solution2-b0-closure/v1',goal:p.goal,classification:'NEW_REPRODUCTION_NOT_RECOVERED_R2',status:'B0_READ_ONLY_CLOSURE_COMPLETE_NATIVE_EXECUTION_BLOCKED'})),
    lock:Buffer.from(JSON.stringify({nodeVersion:'26.13.1',nodeSourceSha256:p.archiveSha256,builderImage:p.repository,platform:p.platform,gccVersion:'13.3.0',target:{commit:p.approvalSource,tree:p.approvalTree},packages:pack})),
    tools:Buffer.from(JSON.stringify({toolchain:'gcc-13.3.0;x86_64-linux-gnu;python-3.12.3;make-4.3',gccVersion:'13.3.0',packages:pack,records:Object.values(m.recorder.roles).map(t=>({realpath:t.path,sha256:t.sha256}))})),
    allowlist:Buffer.from(JSON.stringify(doc))};
  for(const k of Object.keys(m.native.evidence))raw[k]??=Buffer.from('SYNTHETIC POLICY LABEL ONLY: '+k);
  // Historical raw bytes are unavailable. Only this explicit digest boundary
  // maps synthetic fixture bytes to historical labels; allowlist/tools use real
  // SHA256. No production hash pin or schema is weakened by the test.
  const labels=new Map();for(const [k,b]of Object.entries(raw)){
    if(['allowlist','tools'].includes(k))m.native.evidence[k].sha256=digest(b);
    else labels.set(digest(b),m.native.evidence[k].sha256);
  }
  const cryptoFacade={...crypto,createHash(alg){const hash=crypto.createHash(alg);return {update(b){hash.update(b);return this;},digest(encoding){const actual=hash.digest('hex'),value=labels.get(actual)??actual;return encoding==='hex'?value:Buffer.from(value,'hex');}};}};
  return {...f,raw,cryptoFacade};
}
function nativeHarness(f,extra={}){
  const body=js+'\nordinary=(p,bound)=>{const key=Object.keys(fixtureRaw).find(k=>"/native-fixture/"+k===p);if(!key)throw Error("missing native evidence");const b=fixtureRaw[key];if(!b||b.length>bound)throw Error("native evidence bound/missing "+key);return b;};\n({nativeAdmission,run})';
  return vm.runInNewContext(body,{fs,path,crypto:f.cryptoFacade,Buffer,setTimeout,clearTimeout,fixtureRaw:f.raw,output:f.m.output,spawn(){assert.fail('native path must never spawn');},...extra},{timeout:1000});
}
// Context-only rule paths: keep the valid rule hash and every action/input/argv
// unchanged so a rejection can only come from the context-row path predicate.
const contextPathCases=[
  ['make variable','/work/node/\u0024(UNRESOLVED)/rule.mk',false],
  ['literal dollar','/work/node/\u0024/rule.mk',false],
  ['brace variable','/work/node/\u0024{NAME}/rule.mk',false],
  ['parent segment','/work/node/out/../rule.mk',false],
  ['dot segment','/work/node/./rule.mk',false],
  ['double slash','/work/node//rule.mk',false],
  ['trailing slash','/work/node/rule.mk/',false],
  ['outside root','/work/other/rule.mk',false],
  ['relative path','work/node/rule.mk',false],
  ['canonical rule','/work/node/out/rule.mk',true],
  ['canonical nested rule','/work/node/generated/a-b_1/rule.mk',true],
];
function contextPathFixture(contextPath){
  const f=nativeEvidenceFixture();f.doc.context[1].path=contextPath;
  f.raw.allowlist=Buffer.from(JSON.stringify(f.doc));
  f.m.native.evidence.allowlist.sha256=digest(f.raw.allowlist);
  return f;
}
for(const [label,contextPath,accepted]of contextPathCases)
  test('context-only path predicate and mocked no-spawn STOP: '+label,async t=>{
    const f=contextPathFixture(contextPath),h=helpers();
    assert.equal(f.doc.context[1].sha256,f.doc.actions[0].ruleSha256);
    assert.equal(digest(f.raw.allowlist),f.m.native.evidence.allowlist.sha256);
    if(accepted)h.nativeActions(f.doc,f.m);
    else {
      assert.throws(()=>h.nativeActions(f.doc,f.m),/^Error: supplemental retained context hashes$/);
      // Repair only the path: identical hashes/actions must then validate.
      const repaired=clone(f.doc);repaired.context[1].path='/work/node/out/rule.mk';
      h.nativeActions(repaired,f.m);
    }
    const dir=fs.mkdtempSync(path.join(os.tmpdir(),'context-path-stop-'));
    t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));f.m.output=dir;
    assert.equal(await nativeHarness(f).run(f.m),125);
    const report=JSON.parse(fs.readFileSync(path.join(dir,'native-admission.json')));
    assert.equal(report.status,accepted?'STOP_NATIVE_ACTION_BOUNDARY_UNIMPLEMENTED':'STOP_NATIVE_ADMISSION');
    if(!accepted)assert.equal(report.blocker,'supplemental retained context hashes');
    assert.equal(report.nativeExecution,'NOT_STARTED');assert.equal(report.capture,'NOT_STARTED');
    assert(!fs.existsSync(path.join(dir,'seal.json')));
  });
test('context path source parity wiring (static evidence only)',()=>{
  const host=js.slice(js.indexOf('function nativeActions('),js.indexOf('function nativeInputs('));
  assert(host.indexOf('const workPath=')<host.indexOf('need(Array.isArray(doc.context)'));
  assert(host.includes('doc.context.every(f=>workPath(f?.path)&&sha(f.sha256))'));
  const py=fs.readFileSync(recorder,'utf8');
  assert.match(py,/def work_path\(p\):\n        return [^\n]+and '\u0024' not in p/);
  assert(py.includes("work_path(f.get('path')) and native_sha(f.get('sha256'))"));
});
test('MANDATORY real Python context-only parser parity; mocked evidence and denied helper spawn',()=>{
  assert(fs.existsSync('/usr/bin/python3'),'mandatory /usr/bin/python3 unavailable; context-path Python parity NOT VERIFIED');
  const f=nativeEvidenceFixture();
  const payload={manifest:f.m.recorder,doc:f.doc,cases:contextPathCases,
    raw:Object.fromEntries(Object.entries(f.raw).map(([k,b])=>[k,b.toString('base64')]))};
  const code=String.raw`
import base64, contextlib, hashlib, importlib.util, io, json, sys
spec=importlib.util.spec_from_file_location('capture',sys.argv[1])
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
payload=json.load(sys.stdin)
def denied(*args,**kwargs):
    raise AssertionError('context admission attempted helper/tool spawn')
r.subprocess.Popen=denied;r.tool_identity=denied
for label,path,accepted in payload['cases']:
    m=json.loads(json.dumps(payload['manifest']));doc=json.loads(json.dumps(payload['doc']))
    doc['context'][1]['path']=path
    assert doc['context'][1]['sha256']==doc['actions'][0]['ruleSha256']
    try:
        r.native_actions(doc,m)
        assert accepted,label
    except r.Blocked as exc:
        assert not accepted and str(exc)=='supplemental retained context hashes',(label,str(exc))
        repaired=json.loads(json.dumps(doc));repaired['context'][1]['path']='/work/node/out/rule.mk'
        r.native_actions(repaired,m)
    raw={k:base64.b64decode(v) for k,v in payload['raw'].items()}
    raw['allowlist']=json.dumps(doc).encode()
    m['native']['evidence']['allowlist']['sha256']=hashlib.sha256(raw['allowlist']).hexdigest()
    # Historical identity bytes are unavailable: snapshot custody is explicitly
    # mocked; the allowlist uses its real digest and native_actions is unchanged.
    def snapshot(p,limit):
        if p=='/synthetic/manifest':return json.dumps(m).encode(),{}
        key=next(k for k,v in m['native']['evidence'].items() if v['path']==p)
        assert len(raw[key])<=limit
        sha=hashlib.sha256(raw[key]).hexdigest() if key=='allowlist' else m['native']['evidence'][key]['sha256']
        return raw[key],{'sha256':sha}
    r.snapshot=snapshot;r.sys.argv=['recorder','native-admission','/synthetic/manifest']
    output=io.StringIO()
    with contextlib.redirect_stdout(output):assert r.main()==125
    report=json.loads(output.getvalue())
    assert report['status']==('STOP_NATIVE_ACTION_BOUNDARY_UNIMPLEMENTED' if accepted else 'STOP_NATIVE_ADMISSION')
    if not accepted:assert report['blocker']=='supplemental retained context hashes'
    assert report['nativeExecution']==report['capture']=='NOT_STARTED'
print('actual Python context parser cases='+str(len(payload['cases']))+'; evidence custody mocked; no helper spawn')
`;
  const result=spawnSync('/usr/bin/python3',['-I','-B','-S','-c',code,recorder],{
    input:JSON.stringify(payload),env:{PATH:'/usr/bin:/bin',LANG:'C',LC_ALL:'C'},encoding:'utf8',timeout:10000,maxBuffer:1048576});
  assert.ifError(result.error);assert.equal(result.status,0,result.stderr);
  assert.match(result.stdout,/actual Python context parser cases=11; evidence custody mocked; no helper spawn/);
});
test('complete synthetic native admission still persists STOP before Docker/spawn',async t=>{
  const f=nativeEvidenceFixture(),dir=fs.mkdtempSync(path.join(os.tmpdir(),'native-stop-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));f.m.output=dir;
  const h=nativeHarness(f);assert.equal(h.nativeAdmission(f.m).status,'STOP_NATIVE_ACTION_BOUNDARY_UNIMPLEMENTED');
  assert.equal(await h.run(f.m),125);const report=JSON.parse(fs.readFileSync(path.join(dir,'native-admission.json')));
  assert.equal(report.status,'STOP_NATIVE_ACTION_BOUNDARY_UNIMPLEMENTED');assert.equal(report.nativeExecution,'NOT_STARTED');assert.equal(report.capture,'NOT_STARTED');assert(!fs.existsSync(path.join(dir,'seal.json')));
  await assert.rejects(()=>h.run(f.m),/fresh canonical/);
});
for(const key of ['allowlist','tools','b0','context','archive','lock','sourceAdmission'])
  test('raw native '+key+' mutation stops admission before any execution',()=>{const f=nativeEvidenceFixture();f.raw[key]=Buffer.from('mutated');const result=nativeHarness(f).nativeAdmission(f.m);assert.equal(result.status,'STOP_NATIVE_ADMISSION');assert.match(result.blocker,/raw evidence hash/);});
test('missing supplemental input and unlisted helper stop earlier than final boundary',()=>{
  for(const fault of ['missing','helper','count','tool-inventory','toolchain']){
    const f=nativeEvidenceFixture();
    if(fault==='missing')delete f.raw.allowlist;
    else if(fault==='tool-inventory'||fault==='toolchain'){const tools=JSON.parse(f.raw.tools);if(fault==='tool-inventory')tools.records=[];else tools.toolchain='unlisted';f.raw.tools=Buffer.from(JSON.stringify(tools));f.m.native.evidence.tools.sha256=digest(f.raw.tools);}
    else {const doc=clone(f.doc);if(fault==='helper')doc.actions[0].role='shell';else doc.taskCount=15;f.raw.allowlist=Buffer.from(JSON.stringify(doc));f.m.native.evidence.allowlist.sha256=digest(f.raw.allowlist);}
    const result=nativeHarness(f).nativeAdmission(f.m);assert.equal(result.status,'STOP_NATIVE_ADMISSION');assert.notEqual(result.blocker,'No reviewed descendant/action-boundary enforcement; no native Docker or tool launch');
  }
});
test('native missing metadata produces precise STOP and no Docker call',async t=>{
  const {m}=nativeFixture(),dir=fs.mkdtempSync(path.join(os.tmpdir(),'native-invalid-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));m.output=dir;delete m.native.taskCount;
  const h=helpers({output:dir,spawn(){assert.fail('native metadata must not spawn');}});
  assert.equal(await h.run(m),125);const report=JSON.parse(fs.readFileSync(path.join(dir,'native-admission.json')));assert.equal(report.status,'STOP_NATIVE_ADMISSION');assert.match(report.blocker,/native profile keys/);
});
test('runner and recorder native policy constants agree; no native execute path',()=>{
  const py=fs.readFileSync(recorder,'utf8'),json=py.match(/NATIVE_POLICY = json.loads\(r'''([\s\S]*?)'''\)/)[1];
  assert.deepEqual(JSON.parse(json),clone(helpers().nativePolicy));
  assert.match(py,/def execute\([^\n]*\):\n    require\([^\n]+startswith\('owner-nodev8-prerequisite-measurement'\)[^\n]+STOP_NATIVE_ACTION_BOUNDARY_UNIMPLEMENTED/);
});

// These are executable behavior fixtures, never a source-pattern substitute for
// Python, Docker, Node/V8 fidelity or the independent owner replay gate.
const behavior=String.raw`
import importlib.util, os, sys, tempfile, json, hashlib, base64, subprocess, signal, concurrent.futures
spec=importlib.util.spec_from_file_location('capture',sys.argv[1]); r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
def check(ok):
    if not ok: raise AssertionError('synthetic capture invariant')
native_payload=json.loads(sys.argv[2]);native=native_payload['manifest'];actions=native_payload['actions']
r.native_metadata(native);r.native_actions(actions,native)
for field in ['goal','taskCount','evidence']:
    bad=json.loads(json.dumps(native));del bad['native'][field]
    try:r.native_metadata(bad);raise AssertionError('missing native metadata accepted')
    except r.Blocked:pass
for role in ['cc','cxx','link','generator','workload','unlisted']:
    try:r.execute(native,{},role,[b'/control/'+role.encode()]);raise AssertionError('native execute accepted')
    except r.Blocked as exc:check('STOP_NATIVE_ACTION_BOUNDARY_UNIMPLEMENTED' in str(exc))
original_snapshot=r.snapshot
fixture_raw={k:base64.b64decode(v) for k,v in native_payload['raw'].items()}
def native_snapshot(p,limit):
    key=next(k for k,v in native['native']['evidence'].items() if v['path']==p)
    data=fixture_raw[key];check(len(data)<=limit)
    return data,{'sha256':native['native']['evidence'][key]['sha256']}
r.snapshot=native_snapshot
check(r.native_admission(native)['status']=='STOP_NATIVE_ACTION_BOUNDARY_UNIMPLEMENTED')
bad=json.loads(json.dumps(actions));bad['actions'][0]['role']='unlisted-helper'
fixture_raw['allowlist']=json.dumps(bad).encode()
check(r.native_admission(native)['status']=='STOP_NATIVE_ADMISSION')
r.snapshot=original_snapshot
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
  const r=spawnSync('/usr/bin/python3',['-I','-B','-S','-c',behavior,recorder,JSON.stringify((()=>{const f=nativeEvidenceFixture();return {manifest:f.m.recorder,actions:f.doc,raw:Object.fromEntries(Object.entries(f.raw).map(([k,b])=>[k,b.toString('base64')]))};})())],{env:{PATH:'/usr/bin:/bin',LANG:'C',LC_ALL:'C'},encoding:'utf8',timeout:45000,maxBuffer:1024*1024});
  assert.ifError(r.error);assert.equal(r.status,0,r.stderr);assert.match(r.stdout,/NOT_PROVEN/);
});
