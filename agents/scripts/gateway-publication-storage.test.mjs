import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import { plan, image, directory, overlaps, exactMount } from './gateway-publication-storage.mjs';
import { validateMount } from './state-storage.mjs';
import { validateStartup } from './gateway-publication-startup-guard.mjs';
export function environment(root) {
 return {AGENT_RUNTIME_ROOT:root,GITHUB_GATEWAY_RUNTIME_DIR:root+'/github-gateway',GITHUB_GATEWAY_CREDENTIALS_ROOT:root+'/gateway-credentials',...Object.fromEntries(['DISPATCHER','DEVELOPER','REVIEWER'].flatMap(r=>[[''+r+'_WORKSPACE',root+'/'+r.toLowerCase()+'/workspace'],[r+'_CREDENTIALS_DIR',root+'/'+r.toLowerCase()+'/credentials']]))};
}
test('derived plan validates all overlaps without mutation',t=>{
 const root=fs.mkdtempSync(os.tmpdir()+'/publication-plan-');t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const env=environment(root+'/runtime');const p=plan(env);assert.equal(p.bytes,67108864);assert.deepEqual(fs.readdirSync(root),[]);
 for(const key of Object.keys(env).filter(k=>k!=='AGENT_RUNTIME_ROOT')) for(const val of [p.store,p.target,p.store+'/nested',root])assert.throws(()=>plan({...env,[key]:val}));
 for(const val of ['/', '/workspace/bad/runtime',root+'/../bad','relative'])assert.throws(()=>plan({...env,AGENT_RUNTIME_ROOT:val}));
 for(const val of ['0','12','67108865','68719476737','-1'])assert.throws(()=>plan({...env,GITHUB_GATEWAY_PUBLICATION_RECORDS_BYTES:val}));
 assert.throws(()=>plan({...env,GITHUB_GATEWAY_PUBLICATION_RECORDS_DIR:root+'/state-storage/developer-a'}));
 fs.symlinkSync(root,root+'/link');assert.throws(()=>plan(environment(root+'/link/runtime')));
 assert(overlaps('/a','/a/b'));assert(!overlaps('/a','/ab'));
});
const stat={isFile:()=>true,isDirectory:()=>false,isSymbolicLink:()=>false,nlink:1,uid:0,gid:0,mode:0o100600,size:67108864,blocks:131072};
test('image rejects identity/allocation/type/full mode errors',()=>{
 image(stat,67108864);
 for(const patch of [{nlink:2},{uid:1000},{gid:1000},{mode:0o104600},{mode:0o100660},{size:67108865},{blocks:1},{isFile:()=>false},{isSymbolicLink:()=>true}])assert.throws(()=>image({...stat,...patch},67108864));
});
const dir={...stat,isFile:()=>false,isDirectory:()=>true,uid:1000,gid:1000,mode:0o40700};
test('directory rejects UID/GID/special bits/links',()=>{
 directory(dir,1000,1000,0o700);
 for(const patch of [{uid:0},{gid:0},{mode:0o44700},{mode:0o41700},{mode:0o40750},{isDirectory:()=>false},{isSymbolicLink:()=>true}])assert.throws(()=>directory({...dir,...patch},1000,1000,0o700));
});
const p={image:'/fixture/records.img',target:'/fixture/records'};
const info={target:p.target,source:'/dev/loop8',fstype:'ext4',options:'rw,nosuid,nodev'};
const loop={name:'/dev/loop8','back-file':p.image,offset:0,sizelimit:0,ro:0};
test('exact loop/mount negatives',()=>{
 validateMount(p,info,[loop]);
 for(const patch of [{offset:1},{sizelimit:67108864},{ro:1},{name:'/dev/loop9'},{'back-file':'/other'}])assert.throws(()=>validateMount(p,info,[{...loop,...patch}]));
 for(const patch of [{target:'/wrong'},{fstype:'tmpfs'},{fstype:'xfs'},{options:'rw,nodev'},{options:'ro,nosuid,nodev'}])assert.throws(()=>validateMount(p,{...info,...patch},[loop]));
 for(const loops of [[],[loop,loop]])assert.throws(()=>validateMount(p,info,loops));
 assert.throws(()=>validateMount(p,null,[loop]));
});
const env={GATEWAY_PUBLICATION_RECORDS_DIRECTORY:'/run/gateway-publications',GATEWAY_PUBLICATION_CAPACITY_BYTES:'67108864'};
const stats={type:0xef53n,bsize:4096n,blocks:15000n};
const entry='41 30 7:8 / /run/gateway-publications rw,nosuid,nodev - ext4 /dev/loop8 rw';
test('startup guard covers reboot/no mount, ordinary directory, tmpfs and wrong UID/mode/capacity',()=>{
 validateStartup(dir,stats,[entry],env,1000,1000);
 for(const entries of [[],[entry,entry],[entry.replace('ext4','tmpfs')],[entry.replace('/dev/loop8','/dev/sda1')],[entry.replace('rw,nosuid,nodev','rw')],[entry.replace('7:8 / ','7:8 /subdir ')]])assert.throws(()=>validateStartup(dir,stats,entries,env,1000,1000));
 for(const patch of [{type:0x1021994n},{blocks:999999n},{blocks:1n}])assert.throws(()=>validateStartup(dir,{...stats,...patch},[entry],env,1000,1000));
 assert.throws(()=>validateStartup({...dir,mode:0},stats,[entry],env,1000,1000));
 assert.throws(()=>validateStartup(dir,stats,[entry],env,0,0));
 assert.throws(()=>validateStartup(dir,stats,[entry],{...env,GATEWAY_PUBLICATION_RECORDS_DIRECTORY:'/wrong'},1000,1000));
});

test('malformed command output and contradictory flags fail closed',()=>{
 exactMount(p,info,[loop]);
 for(const patch of [{offset:null},{offset:''},{sizelimit:null},{sizelimit:false},{ro:null},{ro:''}])assert.throws(()=>exactMount(p,info,[{...loop,...patch}]));
 for(const value of [null,{},[loop,loop],[null]])assert.throws(()=>exactMount(p,info,value));
 for(const patch of [{options:null},{options:'rw,ro,nosuid,nodev'},{source:'/wrong'}])assert.throws(()=>exactMount(p,{...info,...patch},[loop]));
});

import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
test('CLI rejection has no mutation and fixed diagnostic',t=>{
 const root=fs.mkdtempSync(os.tmpdir()+'/publication-cli-');t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const script=fileURLToPath(new URL('./gateway-publication-storage.mjs',import.meta.url));
 for(const args of [[],['repair'],['prepare','extra'],['validate']]) {
  const r=spawnSync(process.execPath,[script,...args],{encoding:'utf8',env:{PATH:process.env.PATH,AGENT_RUNTIME_ROOT:root+'/runtime'}});
  assert.equal(r.status,1);assert.match(r.stderr,/retain image, records and partial artifacts/);assert.deepEqual(fs.readdirSync(root),[]);
 }
});
