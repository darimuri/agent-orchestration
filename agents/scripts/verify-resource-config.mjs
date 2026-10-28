#!/usr/bin/env node
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
import { validateStateStorage } from '../docker/check-state-storage.mjs';
export function verifyResourceConfig(config) {
  for (const role of ['dispatcher-planner', 'developer-a', 'reviewer-a', ...(config.services?.['host-operator'] ? ['host-operator'] : [])]) {
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
    if (role === 'host-operator') verifyHostOperator(s);
    const bytes = String(s.environment?.AGENT_STATE_CAPACITY_BYTES);
    validateStateStorage({ type: 0xef53n, bsize: 4096n, blocks: /^[1-9][0-9]*$/.test(bytes) ? BigInt(bytes) / 4096n : 0n }, bytes);
  }
  return true;
}
function verifyHostOperator(s) {
  const env=s.environment??{};
  const fixed={AGENT_ROLE:'host-operator',AGENT_PROVIDER:'codex',AGENT_ROLE_PROMPT:'/run/agent/prompts/HOST_OPERATOR.md',BUZZ_ACP_SESSION_TITLE:'Host Operator',ENABLE_NATIVE_MCP:'true',ENABLE_KANEO_MCP:'false',ENABLE_GITHUB_GATEWAY_MCP:'false',BUZZ_ACP_AGENTS:'1',BUZZ_ACP_RESPOND_TO:'owner-only'};
  if (Object.entries(fixed).some(([k,v])=>env[k]!==v) || JSON.stringify(s.profiles)!=='["host-operator"]' ||
      s.depends_on && Object.keys(s.depends_on).length || s.ports?.length || s.devices?.length || s.cap_add?.length || s.group_add?.length ||
      s.pid || s.ipc || s.network_mode || s.userns_mode || s.privileged || s.user || s.entrypoint || s.command ||
      s.build?.dockerfile!=='docker/Dockerfile.codex') throw Error('fourth role authority forbidden');
  if(Object.keys(env).some(k=>/^(?:GH_|GITHUB_|SSH_|DOCKER_|HOST_EXECUTOR|EXECUTOR_|CODEX_PATH$|AGENT_MCP_DEFINITION$|BUZZ_ACP_MCP_COMMAND$)/.test(k))) throw Error('fourth role authority environment');
  const volumes=s.volumes??[];const home=volumes.find(v=>v.target==='/home/agent');
  const suffix='/state-storage/host-operator';const root=home?.source?.slice(0,-suffix.length);
  if(!root || !home.source.endsWith(suffix) || volumes.length!==4) throw Error('fourth role mount contract');
  for(const [target,source,ro] of [['/home/agent',root+suffix,false],['/workspace',root+'/host-operator/workspace',true],['/run/agent/credentials',root+'/host-operator/credentials',true],['/run/agent/prompts',null,true]]) {
    const matches=volumes.filter(v=>v.target===target);const v=matches[0];
    if(matches.length!==1 || v.type!=='bind' || !v.bind || typeof v.bind!=='object' || Array.isArray(v.bind) || v.bind.create_host_path===true || !!v.read_only!==ro ||
        (source?v.source!==source:!v.source?.endsWith('/prompts'))) throw Error('fourth role mount contract');
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { verifyResourceConfig(JSON.parse(fs.readFileSync(process.argv[2], 'utf8'))); console.log('Compose resource policy PASS'); }
  catch { console.error('Compose resource policy failed'); process.exitCode = 1; }
}
