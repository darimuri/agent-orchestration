import test from 'node:test';
import assert from 'node:assert/strict';
import { verifyResourceConfig } from './verify-resource-config.mjs';
const fixture = () => ({ services: { 'github-gateway': gatewayFixture(), ...Object.fromEntries(['dispatcher-planner', 'developer-a', 'reviewer-a'].map(role => [role, {
  cpus: 1, mem_limit: 2147483648, memswap_limit: 2147483648, read_only: true,
  cap_drop: ['ALL'], security_opt: ['no-new-privileges:true'],
  environment: { AGENT_STATE_CAPACITY_BYTES: '536870912' },
  volumes: [{ type: 'bind', source: `/tmp/runtime/state-storage/${role}`, target: '/home/agent', bind: { create_host_path: false } },
    { target: '/run/agent/credentials', read_only: true }],
}])) } });
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

function fourth(){const f=fixture();f.services['host-operator']={...structuredClone(f.services['developer-a']),profiles:['host-operator'],build:{dockerfile:'docker/Dockerfile.codex'},environment:{AGENT_STATE_CAPACITY_BYTES:'536870912',AGENT_ROLE:'host-operator',AGENT_PROVIDER:'codex',AGENT_ROLE_PROMPT:'/run/agent/prompts/HOST_OPERATOR.md',BUZZ_ACP_SESSION_TITLE:'Host Operator',ENABLE_NATIVE_MCP:'true',ENABLE_KANEO_MCP:'false',ENABLE_GITHUB_GATEWAY_MCP:'false',BUZZ_ACP_AGENTS:'1',BUZZ_ACP_RESPOND_TO:'owner-only'},volumes:[{type:'bind',source:'/tmp/runtime/state-storage/host-operator',target:'/home/agent',bind:{create_host_path:false}},...['credentials','workspace'].map(n=>({type:'bind',source:'/tmp/runtime/host-operator/'+n,target:n==='workspace'?'/workspace':'/run/agent/credentials',read_only:true,bind:{create_host_path:false}})),{type:'bind',source:'/tmp/fixture/prompts',target:'/run/agent/prompts',read_only:true,bind:{create_host_path:false}}]};return f;}
test('optional fourth definition is bounded and disconnected; three-only fixtures remain valid',()=>{assert(verifyResourceConfig(fixture()));assert(verifyResourceConfig(fourth()));});
for(const [name,mutate] of Object.entries({profile:s=>s.profiles=[],provider:s=>s.environment.AGENT_PROVIDER='claude',prompt:s=>s.environment.AGENT_ROLE_PROMPT='foreign',gateway:s=>s.environment.ENABLE_GITHUB_GATEWAY_MCP='true',token:s=>s.environment.GITHUB_GATEWAY_AGENT_TOKEN='sentinel',socket:s=>s.volumes.push({target:'/run/executor.sock'}),workspace:s=>s.volumes[2].read_only=false,create:s=>s.volumes[1].bind.create_host_path=true,path:s=>s.volumes[1].source='/tmp/other/credentials',ports:s=>s.ports=[123],groups:s=>s.group_add=[0],hostpid:s=>s.pid='host',depends:s=>s.depends_on={'github-gateway':{}},caps:s=>s.cap_add=['SYS_ADMIN'],command:s=>s.entrypoint=['sh'],image:s=>s.build.dockerfile='foreign'}))test('fourth resource boundary rejects '+name,()=>{const f=fourth();mutate(f.services['host-operator']);assert.throws(()=>verifyResourceConfig(f));});

test('Compose-normalized empty bind objects preserve fourth-role mount policy', () => {
  const config = fourth();
  for (const volume of config.services['host-operator'].volumes) volume.bind = {};
  assert.equal(verifyResourceConfig(config), true);
});

test('each normalized fourth bind still rejects create_host_path true and missing/non-object bind', () => {
  for (let i = 0; i < 4; i++) {
    for (const bind of [undefined, null, true, 'bind', [], { create_host_path: true }]) {
      const config = fourth();
      for (const volume of config.services['host-operator'].volumes) volume.bind = {};
      if (bind === undefined) delete config.services['host-operator'].volumes[i].bind;
      else config.services['host-operator'].volumes[i].bind = bind;
      assert.throws(() => verifyResourceConfig(config));
    }
  }
});

test('normalized binds retain exact read-only, path and authority checks', () => {
  for (const mutate of [s => { s.volumes[1].source = '/tmp/foreign/credentials'; },
    s => { s.volumes[2].read_only = false; }, s => { s.volumes[3].read_only = false; },
    s => { s.environment.ENABLE_GITHUB_GATEWAY_MCP = 'true'; }]) {
    const config = fourth();
    for (const volume of config.services['host-operator'].volumes) volume.bind = {};
    mutate(config.services['host-operator']);
    assert.throws(() => verifyResourceConfig(config));
  }
});

function gatewayFixture() {
 return {read_only:true,cap_drop:['ALL'],security_opt:['no-new-privileges:true'],environment:{GATEWAY_PUBLICATION_RECORDS_DIRECTORY:'/run/gateway-publications',GATEWAY_PUBLICATION_CAPACITY_BYTES:'67108864',GATEWAY_PUBLICATION_STARTUP_GUARD:'1',NODE_OPTIONS:'--import=/run/gateway-publication-guard.mjs'},volumes:[
 {type:'bind',source:'/tmp/runtime/publication-storage/records',target:'/run/gateway-publications',bind:{create_host_path:false}},
 {type:'bind',source:'/tmp/config',target:'/run/gateway',read_only:true},
 {type:'bind',source:'/tmp/secrets',target:'/run/secrets/github-apps',read_only:true},
 {type:'bind',source:'/tmp/source/scripts/gateway-publication-startup-guard.mjs',target:'/run/gateway-publication-guard.mjs',read_only:true,bind:{create_host_path:false}}]};
}
test('Gateway mount, guard and isolation negatives',()=>{
 for(const mutate of [s=>s.volumes[0].bind.create_host_path=true,s=>s.volumes[0].read_only=true,s=>s.volumes[1].read_only=false,s=>s.volumes[0].source='/tmp/ordinary',s=>s.volumes[0].source='/tmp/foreign/publication-storage/records',s=>s.tmpfs=['/run:rw'],s=>s.volumes.push({...s.volumes[0],target:'/alias'}),s=>s.environment.NODE_OPTIONS='',s=>s.environment.GATEWAY_PUBLICATION_STARTUP_GUARD='0',s=>s.environment.GATEWAY_PUBLICATION_RECORDS_DIRECTORY='/wrong',s=>s.environment.GATEWAY_PUBLICATION_CAPACITY_BYTES='0',s=>s.read_only=false,s=>s.user='0',s=>s.cap_add=['SYS_ADMIN'],s=>s.volumes[3].read_only=false]) {
  const c=fixture();mutate(c.services['github-gateway']);assert.throws(()=>verifyResourceConfig(c));
 }
 const c=fixture();c.services['developer-a'].volumes.push({...c.services['github-gateway'].volumes[0]});assert.throws(()=>verifyResourceConfig(c));
});
