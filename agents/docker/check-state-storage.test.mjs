import test from 'node:test';
import assert from 'node:assert/strict';
import { validateStateStorage } from './check-state-storage.mjs';
const capacity = 512 * 1024 ** 2;
const ext4 = { type: 0xef53n, bsize: 4096n, blocks: BigInt(capacity / 4096 - 2048) };
test('bounded ext4 accepts filesystem metadata overhead', () => {
  assert.doesNotThrow(() => validateStateStorage(ext4, String(capacity)));
});
test('HOME fallback, tmpfs, wrong sizes and unlimited/malformed capacity fail closed', () => {
  for (const stats of [{ ...ext4, type: 0x01021994n }, { ...ext4, type: 0x794c7630n },
    { ...ext4, blocks: BigInt(capacity) }, { ...ext4, blocks: 1n }])
    assert.throws(() => validateStateStorage(stats, String(capacity)));
  for (const bytes of ['0', '-1', '512m', 'Infinity', '4097', '999999999999999999999'])
    assert.throws(() => validateStateStorage(ext4, bytes));
});

test('image wrapper refuses an oversized/unbounded HOME before starting the credential entrypoint', async () => {
  const { spawnSync } = await import('node:child_process');
  const { fileURLToPath } = await import('node:url');
  const r = spawnSync('bash', [fileURLToPath(new URL('./bounded-agent-entrypoint.sh', import.meta.url)), 'true'], {
    env: { PATH: process.env.PATH, HOME: '/', AGENT_STATE_CAPACITY_BYTES: '67108864' }, encoding: 'utf8',
  });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /bounded persistent HOME is required/);
  assert.doesNotMatch(r.stderr, /credential|No such file/);
});
