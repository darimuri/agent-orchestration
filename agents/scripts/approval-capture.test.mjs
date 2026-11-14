import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const script=fileURLToPath(new URL('./capture-approval-failure.sh',import.meta.url));
const recorder=fileURLToPath(new URL('./approval-capture-recorder.py',import.meta.url));
const sh=fs.readFileSync(script,'utf8');
const js=sh.slice(sh.indexOf("const schema="),sh.indexOf('\ntry{\n  need(['));
function helpers(extra={}){return vm.runInNewContext(js+'\n({validate,mapping,createArgs,containerIdentity,completion,inventory,ordinary,wrapper,run,storage})',{
  fs,path,crypto,Buffer,process:{argv:[]},...extra}, {timeout:1000});}
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
function mapped(){
  const m=fixture(),config=Buffer.from(JSON.stringify({os:'linux',architecture:'amd64'}));m.imageId='sha256:'+digest(config);
  const platform=Buffer.from(JSON.stringify({schemaVersion:2,config:{digest:m.imageId,size:config.length},layers:[]}));
  const repo=Buffer.from(JSON.stringify({schemaVersion:2,manifests:[{platform:{os:'linux',architecture:'amd64'},digest:'sha256:'+digest(platform),size:platform.length}]}));
  m.image='example.invalid/builder@sha256:'+digest(repo);
  const image={Id:m.imageId,Os:'linux',Architecture:'amd64',RepoDigests:[m.image],Config:{Env:['PATH=/usr/bin:/bin']}};
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
function container(m){return {Image:m.imageId,Config:{User:'10001:10001'},HostConfig:{NetworkMode:'none',ReadonlyRootfs:true,Memory:m.resources.memory,MemorySwap:m.resources.memory,NanoCpus:2e9,PidsLimit:128,CapDrop:['ALL'],CapAdd:[],Privileged:false,AutoRemove:false,SecurityOpt:['no-new-privileges:true'],LogConfig:{Type:'none'},IpcMode:'private'},Mounts:[[m.source,'/source',false],[m.control,'/control',false],[m.work,'/work',true],[m.output,'/output',true]].map(([Source,Destination,RW])=>({Type:'bind',Source,Destination,RW}))};}
test('inspect readback accepts exact security, mapping, resources and mounts',()=>{const m=fixture();helpers().containerIdentity(m,container(m));});
for(const [label,change]of [
  ['image',c=>c.Image='other'],['UID',c=>c.Config.User='0'],['network',c=>c.HostConfig.NetworkMode='host'],['writable root',c=>c.HostConfig.ReadonlyRootfs=false],
  ['swap',c=>c.HostConfig.MemorySwap=-1],['CPU',c=>c.HostConfig.NanoCpus=3e9],['pids',c=>c.HostConfig.PidsLimit=0],['caps',c=>c.HostConfig.CapAdd=['SYS_PTRACE']],
  ['auto remove',c=>c.HostConfig.AutoRemove=true],['security',c=>c.HostConfig.SecurityOpt=['seccomp:unconfined']],['devices',c=>c.HostConfig.Devices=[{}]],
  ['writable source',c=>c.Mounts[0].RW=true],['extra mount',c=>c.Mounts.push({})],['unbounded log',c=>c.HostConfig.LogConfig.Type='json-file'],
])test('container readback rejects '+label,()=>{const m=fixture(),c=container(m);change(c);assert.throws(()=>helpers().containerIdentity(m,c));});
test('host collection rejects missing completion, hardlinks, symlinks and mutation',t=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'capture-host-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const h=helpers(),p=path.join(dir,'f');fs.writeFileSync(p,'bytes');assert.equal(h.ordinary(p,100).toString(),'bytes');
  const hard=path.join(dir,'hard');fs.linkSync(p,hard);assert.throws(()=>h.ordinary(p,100));fs.unlinkSync(hard);
  const sym=path.join(dir,'sym');fs.symlinkSync(p,sym);assert.throws(()=>h.ordinary(sym,100));assert.throws(()=>h.completion({...fixture(),output:dir}));
  assert.throws(()=>h.inventory(dir,1));fs.unlinkSync(sym);
  const facade={...fs,readSync(fd,...args){fs.writeFileSync(p,'changed');return fs.readSync(fd,...args);}};
  assert.throws(()=>helpers({fs:facade}).ordinary(p,100),/mutation/);
});
test('a completely captured nonzero exit remains nonzero, while missing/corrupt evidence is incomplete',t=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'capture-completion-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const m={...fixture(),output:dir},id=path.join(dir,'records','a'.repeat(32));fs.mkdirSync(id,{recursive:true});
  fs.writeFileSync(path.join(id,'start.json'),JSON.stringify({schema:m.schema,role:'workload'}));
  const end={schema:m.schema,status:'CAPTURE_COMPLETE',returncode:7,streams:{}};
  for(const k of ['stdout','stderr']){const b=Buffer.from(k);fs.writeFileSync(path.join(id,k+'.bin'),b);end.streams[k]={bytes:b.length,sha256:digest(b)};}
  const finish=()=>fs.writeFileSync(path.join(id,'completion.json'),JSON.stringify(end));finish();assert.equal(helpers().completion(m),7);
  end.returncode=-15;finish();assert.equal(helpers().completion(m),143);
  fs.writeFileSync(path.join(id,'stderr.bin'),'tampered');assert.throws(()=>helpers().completion(m),/seal mismatch/);
  fs.unlinkSync(path.join(id,'completion.json'));assert.throws(()=>helpers().completion(m));
});
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
    'async function docker(args,timeout,bound){return fakeDocker(args,timeout,bound);}\n'+
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
    manifest=root+'/manifest';open(manifest,'wb').write(b'{}');_,e=r.snapshot(manifest,100)
    m={'roles':{k:{'path':tool,'sha256':hashlib.sha256(open(tool,'rb').read()).hexdigest()} for k in ['cc','cxx','link','workload']},'limits':dict(r.CEILINGS),'work':work,'output':out}
    # Remove ambient Python/loader controls before the recorder guard; nothing is forwarded.
    for k in list(os.environ):
        if k.startswith(('LD_','ASAN_','LSAN_','UBSAN_','GCC_','COMPILER_')) or k in ['PYTHONPATH','PYTHONHOME']: del os.environ[k]
    def invoke(args,**options):
        p=subprocess.run([sys.executable,'-I','-B','-S','-c',runner,sys.argv[1],json.dumps(m),json.dumps(e),json.dumps([r.b64(x) for x in args])],env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C',**options},stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=8)
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
    check(open(d+'/stdout.bin','rb').read()==direct.stdout and open(d+'/stderr.bin','rb').read()==direct.stderr)
    check([base64.b64decode(x) for x in start['receivedArgvBase64']]==[b'/control/cc']+args)
    check([base64.b64decode(x) for x in start['forwardedArgvBase64']]==[os.fsencode(tool)]+args)
    check('SECRET_TOKEN' not in open(d+'/stdout.bin').read());check(start['internalCollect2LdArgv']=='UNOBSERVED')
    check(invoke(args,SECRET_TOKEN='never-forward').returncode==0)
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
