import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { plan, defaults } from './state-storage.mjs';
test('three independent bounded images, stable defaults and no mutation during planning', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'state-plan-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const plans = plan(`${root}/runtime`);
  assert.equal(new Set(plans.map(p => p.target)).size, 3);
  assert.deepEqual(plans.map(p => String(p.bytes)), defaults);
  assert.deepEqual(fs.readdirSync(root), []);
});
test('unsafe roots, links, invalid capacity and implicit resize inputs rejected', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'state-plan-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.symlinkSync(root, `${root}/link`);
  for (const unsafe of ['/', '/home', '/workspace/test/state', '/var/lib/docker/test', 'relative', `${root}/../bad`, `${root}/link/runtime`])
    assert.throws(() => plan(unsafe));
  for (const sizes of [[], ['0', ...defaults.slice(1)], ['4097', ...defaults.slice(1)], ['9999999999999999999', ...defaults.slice(1)]])
    assert.throws(() => plan(`${root}/runtime`, sizes));
});

test('preallocation and exact private image ownership required; sparse/linked/wrong-size images rejected', async () => {
  const { validateImage } = await import('./state-storage.mjs');
  const stat = { isFile: () => true, isSymbolicLink: () => false, nlink: 1, uid: 0, gid: 0, mode: 0o600, size: 67108864, blocks: 131072 };
  assert.doesNotThrow(() => validateImage(stat, 67108864));
  for (const mutation of [{ blocks: 0 }, { size: 134217728 }, { uid: 10001 }, { gid: 10001 }, { nlink: 2 }, { mode: 0o644 }, { isSymbolicLink: () => true }])
    assert.throws(() => validateImage({ ...stat, ...mutation }, 67108864));
});
test('loop mount must match exact image, device, security flags, zero offset and total size', async () => {
  const { validateMount } = await import('./state-storage.mjs');
  const p = { image: '/safe/runtime/state-storage/developer-a.img', target: '/safe/runtime/state-storage/developer-a' };
  const info = { target: p.target, source: '/dev/loop123', fstype: 'ext4', options: 'rw,nosuid,nodev,relatime' };
  const loop = { name: '/dev/loop123', 'back-file': p.image, offset: 0, sizelimit: 0, ro: false };
  assert.doesNotThrow(() => validateMount(p, info, [loop]));
  for (const mutation of [{ name: '/dev/loop124' }, { 'back-file': '/wrong.img' }, { offset: 4096 }, { sizelimit: 67108864 }, { ro: true }])
    assert.throws(() => validateMount(p, info, [{ ...loop, ...mutation }]));
  for (const mutation of [{ fstype: 'tmpfs' }, { options: 'rw' }, { options: 'ro,nosuid,nodev' }, { target: '/wrong' }])
    assert.throws(() => validateMount(p, { ...info, ...mutation }, [loop]));
  assert.throws(() => validateMount(p, null, [loop]));
  assert.throws(() => validateMount(p, info, [loop, loop]));
});

test('selected fourth plan is isolated and does not expand legacy roles/defaults',async t=>{
 const{planHost,roles}=await import('./state-storage.mjs');const root=fs.mkdtempSync(path.join(os.tmpdir(),'host-state-plan-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const selected=planHost(root+'/runtime');assert.equal(selected.length,1);assert.equal(selected[0].role,'host-operator');assert.equal(selected[0].bytes,536870912);assert(selected[0].image.endsWith('/state-storage/host-operator.img'));
 assert.equal(plan(root+'/runtime').length,3);assert.deepEqual(roles,['dispatcher-planner','developer-a','reviewer-a']);assert.equal(planHost(root+'/runtime','67108864')[0].bytes,67108864);assert.throws(()=>planHost(root+'/runtime','0'));assert.deepEqual(fs.readdirSync(root),[]);
});
