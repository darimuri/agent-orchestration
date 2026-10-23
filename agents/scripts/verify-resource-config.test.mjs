import test from 'node:test';
import assert from 'node:assert/strict';
import { verifyResourceConfig } from './verify-resource-config.mjs';
const fixture = () => ({ services: Object.fromEntries(['dispatcher-planner', 'developer-a', 'reviewer-a'].map(role => [role, {
  cpus: 1, mem_limit: 2147483648, memswap_limit: 2147483648, read_only: true,
  cap_drop: ['ALL'], security_opt: ['no-new-privileges:true'],
  environment: { AGENT_STATE_CAPACITY_BYTES: '536870912' },
  volumes: [{ type: 'bind', source: `/tmp/runtime/state-storage/${role}`, target: '/home/agent', bind: { create_host_path: false } },
    { target: '/run/agent/credentials', read_only: true }],
}])) });
test('normalized Compose resource policy and dangerous overrides', () => {
  assert.ok(verifyResourceConfig(fixture()));
  for (const mutate of [s => delete s.cpus, s => { s.cpus = 0; }, s => { s.mem_limit = 0; },
    s => { s.memswap_limit = -1; }, s => { s.memswap_limit *= 2; }, s => { s.privileged = true; },
    s => { s.volumes[0].bind.create_host_path = true; }, s => { s.volumes[0].type = 'volume'; },
    s => { s.volumes.push({ target: '/home/agent/.cache' }); }, s => { s.volumes[1].read_only = false; },
    s => { s.environment.CODEX_PATH = '/usr/local/bin/codex'; }, s => { s.environment.AGENT_STATE_CAPACITY_BYTES = '0'; }]) {
    const config = fixture(); mutate(config.services['developer-a']);
    assert.throws(() => verifyResourceConfig(config));
  }
});
