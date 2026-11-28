// Isolated VM filesystem: exercises real helper control flow without host privileges/mounts.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { validateMount } from './state-storage.mjs';
import { validateStateStorage } from '../docker/check-state-storage.mjs';
const here=fileURLToPath(import.meta.url);
if(!vm.SourceTextModule) {
 test('isolated real-helper transaction fault matrix',()=>{
  const env={...process.env};delete env.NODE_TEST_CONTEXT;
  const r=spawnSync(process.execPath,['--experimental-vm-modules',here],{encoding:'utf8',env});
  assert.equal(r.status,0,r.stdout+r.stderr);
 });
} else {
 async function fixture() {
  const root='/tmp/publication-fault/runtime',store=root+'/publication-storage',target=store+'/records',image=store+'/records.img';
  const files=new Map(),fds=new Map();let next=10,ino=50,mounted=false,fault=null,beforeLock=null,beforeLink=null;
  const volume=new Map();
  const history=[];
  function entry(type='dir',mode=0o700){return {type,uid:0,gid:0,mode,nlink:1,size:0,blocks:0,dev:1,ino:ino++,text:''};}
  for(let p=root;;p=path.dirname(p)){files.set(p,entry());if(p==='/')break;}
  const error=()=>{throw Object.assign(Error('injected IO failure'),{code:'EIO'});};
  const hit=(name)=>{if(name===fault)error();};
  function get(p){if(!files.has(p))throw Object.assign(Error('missing'),{code:'ENOENT'});return files.get(p);}
  const stats=p=>{const e=get(p);return {...e,isDirectory:()=>e.type==='dir',isFile:()=>e.type==='file',isSymbolicLink:()=>e.type==='link'};};
  const mock={constants:fs.constants,
   lstatSync:stats,statSync:stats,
   mkdirSync(p,{mode}){hit('mkdir');if(files.has(p))throw Object.assign(Error('exists'),{code:'EEXIST'});files.set(p,entry('dir',mode));history.push(['mkdir',p]);},
   readdirSync(p){get(p);return [...files.keys()].filter(q=>path.dirname(q)===p&&q!==p).map(q=>path.basename(q));},
   openSync(p,flags,mode){if(flags==='wx'&&p===store+'/.provision.lock'&&beforeLock){const hook=beforeLock;beforeLock=null;hook();}hit('open');if(flags==='wx'){if(files.has(p))throw Object.assign(Error('exists'),{code:'EEXIST'});files.set(p,entry('file',mode));}else get(p);const fd=next++;fds.set(fd,{p,e:get(p)});history.push(['open',p]);return fd;},
   fstatSync(fd){const e=fds.get(fd).e;return {...e,isFile:()=>e.type==='file'};},
   closeSync(fd){fds.delete(fd);},fsyncSync(fd){if(fds.get(fd).p.endsWith('records.img.creating'))hit('fsync');},
   linkSync(a,b){if(beforeLink)beforeLink(a,b);hit('link');hit(b.endsWith('identity.json')?'seal-link':'image-link');if(files.has(b))throw Object.assign(Error('exists'),{code:'EEXIST'});const e=get(a);e.nlink++;files.set(b,e);history.push(['link',a,b]);},
   chownSync(p,uid,gid){hit('chown');Object.assign(get(p),{uid,gid});history.push(['chown',p]);},
   chmodSync(p,mode){hit('chmod');get(p).mode=mode;history.push(['chmod',p]);},
   writeFileSync(fd,text){hit('write');const e=fds.get(fd).e;e.text=text;e.size=Buffer.byteLength(text);},
   readFileSync(p){return get(p).text;},
   unlinkSync(p){hit('unlink');hit(p.endsWith('records.img.creating')?'image-unlink':p.endsWith('identity.json.creating')?'seal-unlink':'lock-unlink');get(p).nlink--;files.delete(p);history.push(['unlink',p]);},
   statfsSync(){return {type:0xef53n,bsize:4096n,blocks:15000n};},
  };
  const mountInfo=()=>({target,source:'/dev/loop8',fstype:'ext4',options:'rw,nosuid,nodev'});
  const loop=()=>({name:'/dev/loop8','back-file':image,offset:0,sizelimit:0,ro:0});
  const runner=(command,args)=>{
   history.push([command,...args]);if(command===fault)return {status:1,stdout:'',stderr:'injected'};
   if(command==='which')return {status:0,stdout:'/bin/'+args[0]};
   if(command==='findmnt')return {status:mounted?0:1,stdout:JSON.stringify({filesystems:mounted?[mountInfo()]:[]})};
   if(command==='losetup')return {status:0,stdout:JSON.stringify({loopdevices:mounted?[loop()]:[]})};
   if(command==='fallocate')Object.assign(get(args.at(-1)),{size:Number(args[1]),blocks:Number(args[1])/512});
   if(command==='mount'){mounted=true;if(!volume.size)volume.set(target,entry());for(const [p,e] of volume)files.set(p,e);}
   if(command==='umount'){mounted=false;volume.clear();for(const [p,e] of files)if(p===target||p.startsWith(target+'/')){volume.set(p,e);files.delete(p);}files.set(target,entry('dir',0));}
   return {status:0,stdout:''};
  };
  const context=vm.createContext({console:{log(){}},URL,process:{platform:'linux',getuid:()=>0,argv:[],env:{}},Buffer});
  const source=fs.readFileSync(new URL('./gateway-publication-storage.mjs',import.meta.url),'utf8');
  const mod=new vm.SourceTextModule(source,{context,initializeImportMeta(meta){meta.url='file:///trusted/repository/agents/scripts/gateway-publication-storage.mjs';}});
  const modules={
   'node:fs':{default:mock},'node:path':{default:path},'node:child_process':{spawnSync:runner},
   'node:url':{fileURLToPath,pathToFileURL},'./state-storage.mjs':{validateMount},'../docker/check-state-storage.mjs':{validateStateStorage},
  };
  await mod.link(spec=>{const exports=modules[spec];const m=new vm.SyntheticModule(Object.keys(exports),function(){for(const [k,v]of Object.entries(exports))this.setExport(k,v);},{context});return m;});
  await mod.evaluate();
  const env={AGENT_RUNTIME_ROOT:root,GITHUB_GATEWAY_CREDENTIALS_ROOT:'/tmp/credentials',GITHUB_GATEWAY_RUNTIME_DIR:root+'/gateway'};
  for(const r of ['DISPATCHER','DEVELOPER','REVIEWER']){env[r+'_WORKSPACE']=root+'/'+r+'/workspace';env[r+'_CREDENTIALS_DIR']=root+'/'+r+'/credentials';}
  return {call:a=>mod.namespace.storage(a,env),files,history,root,store,target,image,setFault:v=>fault=v,onLock:fn=>beforeLock=fn,onLink:fn=>beforeLink=fn,snapshot:()=>JSON.stringify([...files])};
 }
 for(const failure of ['fallocate','mkfs.ext4','mount','chown','chmod','fsync','image-link','seal-link','image-unlink','seal-unlink','write','lock-unlink'])test('interrupted '+failure+' retains evidence and refuses implicit retry',async()=>{
  const f=await fixture();f.setFault(failure);assert.throws(()=>f.call('prepare'));
  const before=f.snapshot();f.setFault(null);assert.throws(()=>f.call('prepare'));assert.equal(f.snapshot(),before);
 });
 test('prepare/check preserve records, image identity and existing metadata; check never repairs',async()=>{
  const f=await fixture();f.call('prepare');
  for(const suffix of ['pending','commit','pull-pending','pull','staged','ambiguous'])f.files.set(f.target+'/record.'+suffix,{type:'file',text:'retained',ino:999});
  const before=f.snapshot();f.call('check');assert.equal(f.snapshot(),before);
  const image=f.files.get(f.image);f.call('prepare');assert.equal(f.files.get(f.image),image);
  for(const suffix of ['pending','commit','pull-pending','pull','staged','ambiguous'])assert.equal(f.files.get(f.target+'/record.'+suffix).text,'retained');
  f.files.get(f.target).gid=1001;const bad=f.snapshot();assert.throws(()=>f.call('check'));assert.throws(()=>f.call('prepare'));f.files.delete(f.store+'/.provision.lock');assert.equal(f.snapshot(),bad);
 });
 test('stale lock, orphan image and nonempty unmounted target rejected without adoption',async()=>{
  for(const kind of ['lock','orphan','nonempty']){
   const f=await fixture();f.call('prepare');f.call('unmount');
   if(kind==='lock')f.files.set(f.store+'/.provision.lock',{type:'file'});
   if(kind==='orphan')f.files.delete(f.store+'/identity.json');
   if(kind==='nonempty')f.files.set(f.target+'/unknown',{type:'file'});
   const before=f.snapshot();assert.throws(()=>f.call('prepare'));if(kind!=='lock')f.files.delete(f.store+'/.provision.lock');assert.equal(f.snapshot(),before);
  }
 });
 test('delayed lock acquisition after competing prepare/unmount preserves image, seal and records without a second format',async()=>{
  const f=await fixture();let originalImage,originalSeal;
  f.onLock(()=>{
   // A is paused immediately before exclusive acquisition; B completes prepare/unmount.
   // The old implementation already inspected empty state at this point.
   f.call('prepare');
   f.files.set(f.target+'/retained',{type:'file',text:'journal bytes',ino:1234});
   originalImage=f.files.get(f.image);originalSeal=f.files.get(f.store+'/identity.json');
   f.call('unmount');
  });
  f.call('prepare');
  assert.equal(f.files.get(f.image),originalImage);assert.equal(f.files.get(f.store+'/identity.json'),originalSeal);
  assert.equal(f.files.get(f.target+'/retained').text,'journal bytes');
  assert.equal(f.history.filter(h=>h[0]==='mkfs.ext4').length,1);
  const before=f.snapshot();f.call('check');assert.equal(f.snapshot(),before);
 });
 test('prepare and unmount inspect seal/mount/placeholder only under their own exclusive lock',async()=>{
  for(const action of ['prepare','unmount']){
   const f=await fixture();f.call('prepare');if(action==='prepare')f.call('unmount');
   f.onLock(()=>{f.files.get(f.store+'/identity.json').text='changed seal';});
   const start=f.history.length;assert.throws(()=>f.call(action));
   assert.equal(f.files.get(f.store+'/identity.json').text,'changed seal');
   assert(!f.history.slice(start).some(h=>['mount','umount','mkfs.ext4','link'].includes(h[0])));
  }
 });
 test('create-only image/seal installation refuses a destination appearing after inspection',async()=>{
  for(const leaf of ['records.img','identity.json']){
   const f=await fixture();let retained;
   f.onLink((a,b)=>{if(b===f.store+'/'+leaf){retained={type:'file',text:'foreign retained bytes',ino:987};f.files.set(b,retained);}});
   assert.throws(()=>f.call('prepare'));assert.equal(f.files.get(f.store+'/'+leaf),retained);
   assert.equal(retained.text,'foreign retained bytes');
   const before=f.snapshot();assert.throws(()=>f.call('prepare'));assert.equal(f.snapshot(),before);
   assert.equal(f.history.filter(h=>h[0]==='mkfs.ext4').length,1);
  }
 });
 test('foreign lock appearing at acquisition rejects both mutations without touching existing state',async()=>{
  for(const action of ['prepare','unmount']){
   const f=await fixture();f.call('prepare');f.onLock(()=>f.files.set(f.store+'/.provision.lock',{type:'file',text:'foreign',ino:999}));
   const original=f.files.get(f.image),seal=f.files.get(f.store+'/identity.json');const start=f.history.length;
   assert.throws(()=>f.call(action));assert.equal(f.files.get(f.image),original);assert.equal(f.files.get(f.store+'/identity.json'),seal);
   assert.equal(f.files.get(f.store+'/.provision.lock').text,'foreign');
   assert(!f.history.slice(start).some(h=>['mount','umount','mkfs.ext4','link'].includes(h[0])));
  }
 });

 test('mutations revalidate image, mounted permissions and unmounted placeholder after lock acquisition',async()=>{
  for(const action of ['prepare','unmount'])for(const bad of ['image','mount','placeholder']){
   const f=await fixture();f.call('prepare');
   if(bad==='placeholder')f.call('unmount');
   f.onLock(()=>{if(bad==='image')f.files.get(f.image).nlink=2;else f.files.get(f.target).mode=0o777;});
   const start=f.history.length;assert.throws(()=>f.call(action));
   assert(!f.history.slice(start).some(h=>['mount','umount','mkfs.ext4','link'].includes(h[0])));
  }
 });
 test('a replaced owned lock is not mistaken for ownership or removed on completion',async()=>{
  const f=await fixture();f.onLink((a,b)=>{if(b===f.store+'/identity.json')f.files.set(f.store+'/.provision.lock',{type:'file',uid:0,gid:0,mode:0o600,nlink:1,dev:1,ino:999,text:'foreign'});});
  assert.throws(()=>f.call('prepare'));assert.equal(f.files.get(f.store+'/.provision.lock').text,'foreign');
  const before=f.snapshot();assert.throws(()=>f.call('unmount'));assert.equal(f.snapshot(),before);
 });

}
