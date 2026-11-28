#!/usr/bin/env node
// Trusted host only. Never reads records or credentials; never repairs existing objects.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { validateMount } from './state-storage.mjs';
import { validateStateStorage } from '../docker/check-state-storage.mjs';
const repository = fileURLToPath(new URL('../..', import.meta.url)).replace(/\/$/, '');
const deny = () => { throw Error('publication storage blocked; preserve all artifacts for host review'); };
const exists = p => { try { fs.lstatSync(p); return true; } catch(e) { if(e.code === 'ENOENT') return false; throw e; } };
export const overlaps = (a,b) => a === b || a.startsWith(b+'/') || b.startsWith(a+'/');
export function canonical(p) {
  if (typeof p !== 'string' || !path.isAbsolute(p) || path.resolve(p) !== p || !/^\/[A-Za-z0-9_./-]+$/.test(p)) deny();
  for(let q=p;q!=='/';q=path.dirname(q)) {
    try { if(exists(q) && fs.lstatSync(q).isSymbolicLink()) deny(); }
    catch(e) {
      // Private root-owned store ancestors are intentionally unreadable to the host user.
      // Planning may defer access checks; every privileged action repeats them without this exception.
      if(e.code!=='EACCES' || process.getuid()===0) throw e;
    }
  }
  return p;
}
export function plan(env) {
  const root=canonical(env.AGENT_RUNTIME_ROOT);
  if(root.split('/').length<4 || ['/etc','/usr','/dev','/proc','/sys','/run','/var/lib/docker','/workspace'].some(p=>overlaps(root,p)) || overlaps(root,repository)) deny();
  const store=root+'/publication-storage', target=canonical(env.GITHUB_GATEWAY_PUBLICATION_RECORDS_DIR ?? store+'/records');
  if(target !== store+'/records') deny();
  const bytes=env.GITHUB_GATEWAY_PUBLICATION_RECORDS_BYTES ?? '67108864';
  validateStateStorage({type:0xef53n,bsize:4096n,blocks:/^[1-9][0-9]*$/.test(bytes)?BigInt(bytes)/4096n:0n},bytes);
  const forbidden=[root+'/state-storage', ...['dispatcher-planner','developer-a','reviewer-a','host-operator'].map(r=>root+'/'+r)];
  for(const [key,value] of Object.entries(env)) if(/(?:CREDENTIALS_(?:ROOT|DIR)|WORKSPACE|GITHUB_GATEWAY_RUNTIME_DIR|(?:JOURNAL|JOBS|IMAGE|HOME|STATE)_(?:DIR|DIRECTORY|FILE|PATH)|HOST_OPERATOR_STATE_DIR)$/.test(key) && value) forbidden.push(canonical(value));
  // Selected provisioning still requires the configured Gateway/legacy roots so overrides cannot escape overlap validation.
  for(const key of ['GITHUB_GATEWAY_CREDENTIALS_ROOT','GITHUB_GATEWAY_RUNTIME_DIR','DISPATCHER_CREDENTIALS_DIR','DEVELOPER_CREDENTIALS_DIR','REVIEWER_CREDENTIALS_DIR','DISPATCHER_WORKSPACE','DEVELOPER_WORKSPACE','REVIEWER_WORKSPACE']) if(!env[key]) deny();
  if(forbidden.some(p=>overlaps(store,p))) deny();
  return {root,store,target,image:store+'/records.img',seal:store+'/identity.json',lock:store+'/.provision.lock',bytes:Number(bytes)};
}
export function directory(s,uid,gid,mode) {
  if(!s.isDirectory() || s.isSymbolicLink() || s.uid!==uid || s.gid!==gid || (s.mode & 0o7777)!==mode) deny();
}
export function image(s,bytes) {
  if(!s.isFile() || s.isSymbolicLink() || s.nlink!==1 || s.uid!==0 || s.gid!==0 || (s.mode&0o7777)!==0o600 || s.size!==bytes || s.blocks*512<bytes) deny();
}
function run(cmd,args,allowed=[0]) {
  const r=spawnSync(cmd,args,{encoding:'utf8',stdio:['ignore','pipe','pipe']});
  if(r.error || !allowed.includes(r.status)) deny(); return r;
}
function sync(p) { const fd=fs.openSync(p,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW); try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);} }
function mount(p) {
  const r=run('findmnt',['--json','--mountpoint',p.target,'--output','TARGET,SOURCE,FSTYPE,OPTIONS'],[0,1]);
  if(r.status===1) return null;
  const entries=JSON.parse(r.stdout).filesystems;
  if(!Array.isArray(entries)||entries.length!==1) deny(); return entries[0];
}
function loops() {
  const entries=JSON.parse(run('losetup',['--json','--list','--output','NAME,BACK-FILE,OFFSET,SIZELIMIT,RO']).stdout).loopdevices;
  if(!Array.isArray(entries)) deny(); return entries;
}
function identity(p) { const s=fs.lstatSync(p.image); return {version:1,dev:s.dev,ino:s.ino,bytes:p.bytes}; }
function seal(p) {
  const s=fs.lstatSync(p.seal);
  if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1||s.uid!==0||s.gid!==0||(s.mode&0o7777)!==0o600||s.size>1024) deny();
  if(fs.readFileSync(p.seal,'utf8')!==JSON.stringify(identity(p))) deny();
}
function placeholder(p) { directory(fs.lstatSync(p.target),0,0,0); if(fs.readdirSync(p.target).length) deny(); }
export function exactMount(p,info,entries) {
  if(!info || !Array.isArray(entries) || typeof info.options!=='string' || !/^\/dev\/loop[0-9]+$/.test(info.source)) deny();
  validateMount(p,info,entries);
  if(info.options.split(',').includes('ro')) deny();
  const selected=entries.filter(l=>l?.['back-file']===p.image);
  if(selected.length!==1)deny();
  const l=selected[0];
  for(const key of ['offset','sizelimit']) if(l[key]!==0 && l[key]!=='0')deny();
  if(![0,'0',false].includes(l.ro))deny();
}
function verified(p) {
  image(fs.lstatSync(p.image),p.bytes); seal(p);
  const info=mount(p); exactMount(p,info,loops());
  if(!/^\/dev\/loop[0-9]+$/.test(info.source)) deny();
  directory(fs.lstatSync(p.target),1000,1000,0o700);
  validateStateStorage(fs.statfsSync(p.target,{bigint:true}),String(p.bytes));
}
function inspect(p) {
  directory(fs.lstatSync(p.store),0,0,0o700);
  if(exists(p.lock)||exists(p.image+'.creating')||exists(p.seal+'.creating')) deny();
  const hasImage=exists(p.image), hasSeal=exists(p.seal), info=mount(p);
  if(hasImage!==hasSeal) deny(); // No implicit adoption of orphan/partially initialized images.
  if(hasImage){image(fs.lstatSync(p.image),p.bytes);seal(p);}
  if(info) { if(!hasImage) deny(); verified(p); }
  else {
    if(exists(p.target)) placeholder(p);
    if(loops().some(l=>l['back-file']===p.image)) deny();
  }
  return {hasImage,info};
}
export function storage(action,env=process.env) {
  if(!['validate','prepare','check','unmount'].includes(action)) deny();
  const p=plan(env);
  if(action==='validate') return p;
  if(process.platform!=='linux'||process.getuid()!==0) deny();
  if(!fs.statSync(p.root).isDirectory()) deny();
  for(const tool of ['findmnt','losetup',...(action==='prepare'?['fallocate','mkfs.ext4','mount']:[]),...(action==='unmount'?['umount']:[])]) run('which',[tool]);
  // No related runtime, credential or record mutation is performed by this helper.
  if(!exists(p.store)) {
    if(action!=='prepare') deny();
    fs.mkdirSync(p.store,{mode:0o700}); sync(p.root);
  }
  const before=inspect(p);
  if(action==='check') { verified(p); return p; } // Fully non-repairing; no lock creation.
  const fd=fs.openSync(p.lock,'wx',0o600);
  let complete=false;
  try {
    if(action==='unmount') {
      if(before.info) { verified(p); run('umount',['--',p.target]); }
      placeholder(p);
      if(loops().some(l=>l['back-file']===p.image)) deny();
    } else {
      if(!before.hasImage) {
        if(exists(p.target)) placeholder(p); else fs.mkdirSync(p.target,{mode:0});
        const tmp=p.image+'.creating';
        const out=fs.openSync(tmp,'wx',0o600); fs.closeSync(out);
        run('fallocate',['--length',String(p.bytes),tmp]);
        run('mkfs.ext4',['-q','-F','-m','0','-E','nodiscard,lazy_itable_init=0,lazy_journal_init=0',tmp]);
        sync(tmp); image(fs.lstatSync(tmp),p.bytes);
        fs.renameSync(tmp,p.image); sync(p.store);
        run('mount',['-t','ext4','-o','loop,rw,nosuid,nodev',p.image,p.target]);
        // Ownership changes only for this exclusively-created filesystem, after exact mount validation.
        exactMount(p,mount(p),loops());
        fs.chownSync(p.target,1000,1000); fs.chmodSync(p.target,0o700); sync(p.target);
        const sealFd=fs.openSync(p.seal+'.creating','wx',0o600);
        try{fs.writeFileSync(sealFd,JSON.stringify(identity(p)));fs.fsyncSync(sealFd);}finally{fs.closeSync(sealFd);}
        fs.renameSync(p.seal+'.creating',p.seal); sync(p.store);
      } else if(!before.info) {
        placeholder(p); run('mount',['-t','ext4','-o','loop,rw,nosuid,nodev',p.image,p.target]);
      }
      verified(p);
    }
    complete=true;
  } finally {
    fs.closeSync(fd);
    // A failed mutation leaves its lock/artifacts for explicit review; never repair or replay.
    if(complete){fs.unlinkSync(p.lock);sync(p.store);}
  }
  return p;
}
if(process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href) {
  try { if(process.argv.length!==3) deny(); storage(process.argv[2]); console.log('Gateway publication storage '+process.argv[2]+' PASS'); }
  catch { console.error('Gateway publication storage blocked; retain image, records and partial artifacts; no automatic repair'); process.exitCode=1; }
}
