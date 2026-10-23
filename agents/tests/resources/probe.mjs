import assert from 'node:assert/strict';
import fs from 'node:fs';
import { Worker } from 'node:worker_threads';
import { validateStateStorage } from '../../docker/check-state-storage.mjs';
const read = file => fs.readFileSync(`/sys/fs/cgroup/${file}`, 'utf8').trim();
assert.equal(read('memory.max'), String(256 * 1024 ** 2));
assert.equal(read('memory.swap.max'), '0');
const [quota, period] = read('cpu.max').split(' ').map(Number);
assert.equal(quota / period, 0.25);
if (process.argv[2] === 'oom') {
  // Touch every allocation; Buffer length alone may reserve virtual address space.
  const retained = [];
  setInterval(() => retained.push(Buffer.alloc(8 * 1024 ** 2, 0x5a)), 10);
} else {
  validateStateStorage(fs.statfsSync('/home/agent', { bigint: true }), String(64 * 1024 ** 2));
  const marker = '/home/agent/persistence-marker';
  if (fs.existsSync(marker)) {
    assert.equal(fs.readFileSync(marker, 'utf8'), 'restart-safe');
    console.log('restart persistence PASS');
  } else {
    const fd = fs.openSync(marker, 'wx', 0o600);
    fs.writeFileSync(fd, 'restart-safe'); fs.fsyncSync(fd); fs.closeSync(fd);
    console.log('initial state PASS');
  }
  const filename = '/home/agent/exhaustion-fixture';
  const fd = fs.openSync(filename, 'wx', 0o600);
  let bytes = 0;
  let exhausted = false;
  try {
    const chunk = Buffer.alloc(1024 ** 2, 0x5a);
    while (bytes <= 80 * 1024 ** 2) bytes += fs.writeSync(fd, chunk);
  } catch (e) { assert.equal(e.code, 'ENOSPC'); exhausted = true; }
  finally { fs.closeSync(fd); fs.unlinkSync(filename); }
  assert.ok(exhausted, 'fixed-size persistent filesystem must reject writes');
  assert.ok(bytes < 64 * 1024 ** 2);
  console.log('state ENOSPC PASS');
  const throttled = () => Number(read('cpu.stat').match(/nr_throttled (\d+)/)[1]);
  const before = throttled();
  const workers = Array.from({ length: 2 }, () => new Worker('while (true) {}', { eval: true }));
  await new Promise(resolve => setTimeout(resolve, 3000));
  await Promise.all(workers.map(w => w.terminate()));
  assert.ok(throttled() > before, 'CPU saturation must increment cgroup throttle counter');
  console.log('CPU/memory/swap config and CPU throttling PASS');
}
