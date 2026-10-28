#!/usr/bin/env node
// Trusted Linux host only. No Docker, credentials, fstab edits or implicit sudo.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { safePath } from '../docker/git-identity.mjs';
import { validateRecoveryDirectory } from '../docker/host-operator-entrypoint.mjs';
import { validateStateStorage } from '../docker/check-state-storage.mjs';

export const roles = ['dispatcher-planner', 'developer-a', 'reviewer-a'];
export const defaults = ['536870912', '2147483648', '1073741824'];
const repository = fileURLToPath(new URL('../..', import.meta.url)).replace(/\/$/, '');
function fail() { throw new Error('state storage validation failed'); }
export function plan(root, sizes = defaults) {
  if (typeof root !== 'string' || !path.isAbsolute(root) || path.resolve(root) !== root ||
      !/^\/[A-Za-z0-9_./-]+$/.test(root) || root.split('/').length < 4 ||
      ['/etc', '/usr', '/dev', '/proc', '/sys', '/run', '/var/lib/docker', '/workspace'].some(p => root === p || root.startsWith(`${p}/`)) ||
      root === repository || root.startsWith(`${repository}/`) || repository.startsWith(`${root}/`) ||
      !Array.isArray(sizes) || sizes.length !== 3) fail();
  for (let p = root; p !== '/'; p = path.dirname(p)) {
    try { if (!fs.lstatSync(p).isDirectory() || fs.lstatSync(p).isSymbolicLink()) fail(); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  return roles.map((role, index) => {
    const bytes = sizes[index];
    validateStateStorage({ type: 0xef53n, bsize: 4096n, blocks: /^[1-9][0-9]*$/.test(bytes) ? BigInt(bytes) / 4096n : 0n }, bytes);
    return { role, bytes: Number(bytes), image: `${root}/state-storage/${role}.img`, target: `${root}/state-storage/${role}` };
  });
}
export function planHost(root, bytes = '536870912') {
  // Reuse all legacy root/capacity checks without changing its roles/defaults/API.
  const template=plan(root,[bytes,bytes,bytes])[0];
  return [{...template,role:'host-operator',image:root+'/state-storage/host-operator.img',target:root+'/state-storage/host-operator'}];
}
function run(command, args, allowed = [0]) {
  const result = spawnSync(command, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  if (result.error || !allowed.includes(result.status)) throw new Error(`state storage command failed: ${command}`);
  return result;
}
function privateStore(store) {
  const stat = fs.lstatSync(store);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== 0 || stat.gid !== 0 || (stat.mode & 0o777) !== 0o700) fail();
}
export function validateImage(s, bytes) {
  if (!s.isFile() || s.isSymbolicLink() || s.nlink !== 1 || s.uid !== 0 || s.gid !== 0 || (s.mode & 0o777) !== 0o600 || s.size !== bytes || s.blocks * 512 < bytes) fail();
}
function imageCheck(p) { validateImage(fs.lstatSync(p.image), p.bytes); }
function exists(p) {
  try { fs.lstatSync(p); return true; } catch (e) { if (e.code === 'ENOENT') return false; throw e; }
}
function mountInfo(p) {
  const result = run('findmnt', ['--json', '--mountpoint', p.target, '--output', 'TARGET,SOURCE,FSTYPE,OPTIONS'], [0, 1]);
  if (result.status === 1) return null;
  const entries = JSON.parse(result.stdout).filesystems;
  if (entries?.length !== 1) fail();
  return entries[0];
}
export function validateMount(p, info, loops) {
  if (!info || info.target !== p.target || info.fstype !== 'ext4' || !['rw', 'nosuid', 'nodev'].every(o => info.options.split(',').includes(o))) fail();
  const matches = loops.filter(l => l['back-file'] === p.image);
  if (matches.length !== 1 || matches[0].name !== info.source || Number(matches[0].offset) !== 0 || Number(matches[0].sizelimit) !== 0 || Number(matches[0].ro) !== 0) fail();
}
function verify(p) {
  imageCheck(p);
  const loops = JSON.parse(run('losetup', ['--json', '--list', '--output', 'NAME,BACK-FILE,OFFSET,SIZELIMIT,RO']).stdout).loopdevices;
  validateMount(p, mountInfo(p), loops);
  const stat = fs.lstatSync(p.target);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== 10001 || stat.gid !== 10001 || (stat.mode & 0o777) !== 0o700) fail();
  validateStateStorage(fs.statfsSync(p.target, { bigint: true }), String(p.bytes));
  if(p.role==='host-operator' && exists(p.target+'/lost+found')) {
    validateRecoveryDirectory(fs.lstatSync(p.target+'/lost+found'));
    if(fs.readdirSync(p.target+'/lost+found').length)fail();
  }
  console.log(`${p.role}: bounded persistent ext4 PASS (${p.bytes} bytes backing image)`);
}
function requireStoppedHost(p) {
  const file=p.target+'/.local/state/host-operator/instance.lock';
  safePath(file);
  if(!exists(file))return;
  // Cooperative same-HOME check, not a host-global admission lease. Owner must
  // keep the fourth stopped throughout maintenance; never unlink this lock.
  const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
  try {
    const st=fs.fstatSync(fd),entry=fs.lstatSync(file);
    if(!st.isFile()||st.nlink!==1||st.uid!==10001||st.gid!==10001||(st.mode&0o7777)!==0o600||st.ino!==entry.ino||st.dev!==entry.dev)fail();
    const result=spawnSync('/usr/bin/flock',['-n','3'],{stdio:['ignore','pipe','pipe',fd]});
    if(result.error||result.status!==0)fail();
  }finally{fs.closeSync(fd);}
}
export function storage(action, root, sizes = defaults, selectedHost = false) {
  if (!['prepare', 'check', 'unmount'].includes(action) || process.platform !== 'linux' || process.getuid() !== 0) fail();
  const plans = selectedHost ? planHost(root,sizes[0]) : plan(root, sizes);
  if (!fs.statSync(root).isDirectory()) fail();
  const store = `${root}/state-storage`;
  if (action === 'prepare' && !exists(store)) fs.mkdirSync(store, { mode: 0o700 });
  privateStore(store);
  // Exclusive creation is conservative on crash: an orphan lock needs host review.
  const lock = `${store}/.provision.lock`;
  const fd = fs.openSync(lock, 'wx', 0o600);
  try {
    // Check every existing object before any allocation/mount; never format/resize an existing image.
    for (const p of plans) {
      if(selectedHost)requireStoppedHost(p);
      if (exists(p.image)) imageCheck(p);
      if (exists(p.target)) {
        const stat = fs.lstatSync(p.target);
        if (!stat.isDirectory() || stat.isSymbolicLink()) fail();
        if (mountInfo(p)) verify(p);
        else if (stat.uid !== 0 || (stat.mode & 0o777) !== 0 || fs.readdirSync(p.target).length) fail();
      }
      if (exists(`${p.image}.creating`)) fail();
    }
    for (const p of plans) {
      if (action === 'unmount') {
        if (mountInfo(p)) { verify(p); run('umount', ['--', p.target]); }
        continue;
      }
      if (action === 'check') { verify(p); continue; }
      let created = false;
      if (!exists(p.image)) {
        if (mountInfo(p)) fail();
        const temporary = `${p.image}.creating`;
        const imageFd = fs.openSync(temporary, 'wx', 0o600);
        fs.closeSync(imageFd);
        try {
          run('fallocate', ['--length', String(p.bytes), temporary]);
          run('mkfs.ext4', ['-q', '-F', '-m', '0', '-E', 'nodiscard,lazy_itable_init=0,lazy_journal_init=0', temporary]);
          const syncFd = fs.openSync(temporary, 'r');
          try { fs.fsyncSync(syncFd); } finally { fs.closeSync(syncFd); }
          fs.renameSync(temporary, p.image);
          const storeFd = fs.openSync(store, 'r');
          try { fs.fsyncSync(storeFd); } finally { fs.closeSync(storeFd); }
          created = true;
        } catch (error) {
          // Leave partial file for explicit host inspection, never retry formatting blindly.
          throw error;
        }
      }
      imageCheck(p);
      if (!exists(p.target)) fs.mkdirSync(p.target, { mode: 0 });
      if (!mountInfo(p)) run('mount', ['-t', 'ext4', '-o', 'loop,nosuid,nodev', p.image, p.target]);
      if (created) {
        fs.chownSync(p.target, 10001, 10001);
        fs.chmodSync(p.target, 0o700);
      }
      verify(p);
    }
  } finally {
    fs.closeSync(fd);
    fs.unlinkSync(lock);
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const args=process.argv.slice(2);
    if(args[0]==='--agent') {
      if(args[1]!=='host-operator' || args.length<4 || args.length>5)fail();
      storage(args[2],args[3],[args[4]??'536870912'],true);
    } else {
      if(args.some(a=>a.startsWith('--')))fail();
      storage(args[0],args[1],args.length===2?defaults:args.slice(2));
    }
  }
  catch { console.error('state-storage: blocked; check host privileges, canonical paths, private ownership, image size/allocation and exact loop mounts; existing data was not reformatted'); process.exitCode = 1; }
}
