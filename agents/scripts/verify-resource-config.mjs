#!/usr/bin/env node
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
import { validateStateStorage } from '../docker/check-state-storage.mjs';
export function verifyResourceConfig(config) {
  for (const role of ['dispatcher-planner', 'developer-a', 'reviewer-a']) {
    const s = config.services?.[role];
    if (!s || !Number.isFinite(Number(s.cpus)) || Number(s.cpus) <= 0 ||
        !Number.isSafeInteger(Number(s.mem_limit)) || Number(s.mem_limit) < 64 * 1024 ** 2 || Number(s.memswap_limit) !== Number(s.mem_limit) ||
        s.read_only !== true || s.privileged === true || !s.cap_drop?.includes('ALL') ||
        !s.security_opt?.includes('no-new-privileges:true')) throw new Error('hard limits missing');
    const state = s.volumes?.filter(v => v.target === '/home/agent' || v.target?.startsWith('/home/agent/'));
    if (state?.length !== 1 || state[0].type !== 'bind' || state[0].read_only === true ||
        !state[0].bind || state[0].bind.create_host_path === true || !state[0].source?.endsWith(`/state-storage/${role}`)) throw new Error('persistent HOME missing');
    const credentials = s.volumes?.filter(v => v.target === '/run/agent/credentials');
    if (credentials?.length !== 1 || credentials[0].read_only !== true) throw new Error('read-only credential mount missing');
    if (s.environment?.CODEX_PATH !== undefined) throw new Error('ACP runtime override forbidden');
    const bytes = String(s.environment?.AGENT_STATE_CAPACITY_BYTES);
    validateStateStorage({ type: 0xef53n, bsize: 4096n, blocks: /^[1-9][0-9]*$/.test(bytes) ? BigInt(bytes) / 4096n : 0n }, bytes);
  }
  return true;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { verifyResourceConfig(JSON.parse(fs.readFileSync(process.argv[2], 'utf8'))); console.log('Compose resource policy PASS'); }
  catch { console.error('Compose resource policy failed'); process.exitCode = 1; }
}
