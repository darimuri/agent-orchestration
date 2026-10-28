// Fourth-role guard only. No Executor client, authority or credential provisioning.
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { validateStateStorage } from './check-state-storage.mjs';
import { safePath, render } from './git-identity.mjs';
const owner = Object.freeze({ uid: 10001, gid: 10001 });
const layout = Object.freeze({ home: '/home/agent', credentials: '/run/agent/credentials',
  prompts: '/run/agent/prompts', workspace: '/workspace' });
const deny = () => { throw Error('host_operator_startup_denied'); };
function exists(file) { try { return fs.lstatSync(file); } catch (e) { if (e.code === 'ENOENT') return null; throw e; } }
function directory(file, identity, mode = 0o700) {
  safePath(file); const s = fs.lstatSync(file);
  if (!s.isDirectory() || s.uid !== identity.uid || s.gid !== identity.gid || (s.mode & 0o7777) !== mode) deny();
}
function privateFile(file, identity) {
  safePath(file); const s = fs.lstatSync(file);
  if (!s.isFile() || s.nlink !== 1 || s.uid !== identity.uid || s.gid !== identity.gid ||
      (s.mode & 0o7777) !== 0o600 || !s.size || s.size > 1048576) deny();
  return fs.readFileSync(file, 'utf8');
}
function expectedMcp(url) {
  return '# BEGIN buzz-agent managed MCP servers\n[mcp_servers.kaneo]\ncommand = "kaneo-mcp-safe-proxy"\nargs = []\nrequired = true\n\n[mcp_servers.kaneo.env]\nKANEO_API_URL = ' + JSON.stringify(url) + '\n# END buzz-agent managed MCP servers\n';
}
function mounts(paths) {
  const records = fs.readFileSync('/proc/self/mountinfo', 'utf8').trim().split('\n').map(line => line.split(' '));
  for (const [target, readonly] of [[paths.credentials,true],[paths.prompts,true],[paths.workspace,true],[paths.home,false]]) {
    const record = records.find(r => r[4] === target);
    if (!record || !record[5].split(',').includes(readonly ? 'ro' : 'rw')) deny();
  }
}
// ext4 recovery metadata is root-owned, never agent configuration or repairable state.
export function validateRecoveryDirectory(stat) {
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid!==0 || stat.gid!==0 ||
      (stat.mode&0o7777)!==0o700 || stat.nlink!==2) deny();
}
// Dependency injection is a library-only fixture seam; CLI has no override flags or env.
export function validateHostOperator({ env = process.env, paths = layout, identity = owner,
  uid = process.getuid(), gid = process.getgid(), statfs = fs.statfsSync, checkMounts = mounts } = {}) {
  if (uid !== identity.uid || gid !== identity.gid) deny();
  const expected = { HOME:paths.home, CODEX_HOME:paths.home+'/.codex', XDG_CONFIG_HOME:paths.home+'/.config',
    XDG_CACHE_HOME:paths.home+'/.cache', AGENT_ROLE:'host-operator', AGENT_PROVIDER:'codex',
    AGENT_ROLE_PROMPT:paths.prompts+'/HOST_OPERATOR.md', ENABLE_NATIVE_MCP:'true', ENABLE_KANEO_MCP:'false',
    ENABLE_GITHUB_GATEWAY_MCP:'false', BUZZ_ACP_AGENTS:'1', BUZZ_ACP_RESPOND_TO:'owner-only' };
  for (const [name,value] of Object.entries(expected)) if (env[name] !== value) deny();
  for (const name of Object.keys(env)) {
    if ((/^CODEX_/.test(name) && name !== 'CODEX_HOME') || (/^XDG_/.test(name) && !['XDG_CONFIG_HOME','XDG_CACHE_HOME'].includes(name)) || /^OPENAI_/.test(name) || /^BASH_FUNC_|^SHELLOPTS$|^BASHOPTS$/.test(name) || /^(?:GH_|GITHUB_|SSH_|DOCKER_|HOST_EXECUTOR|EXECUTOR_|CLAUDE_|ANTHROPIC_|GIT_CONFIG|BASH_ENV$|ENV$|NODE_OPTIONS$|NODE_PATH$|LD_|DYLD_)/.test(name) ||
        ['CODEX_PATH','AGENT_MCP_DEFINITION','BUZZ_ACP_MCP_COMMAND','BUZZ_PRIVATE_KEY','BUZZ_AUTH_TAG','OPENAI_API_KEY','CODEX_API_KEY','BUZZ_API_TOKEN'].includes(name)) deny();
  }
  if ((env.AGENT_CREDENTIALS_DIR && env.AGENT_CREDENTIALS_DIR !== paths.credentials) ||
      (env.AGENT_COMMON_PROMPT && env.AGENT_COMMON_PROMPT !== paths.prompts+'/COMMON.md') ||
      (env.BUZZ_ACP_AGENT_COMMAND && env.BUZZ_ACP_AGENT_COMMAND !== 'codex-acp') || env.BUZZ_ACP_AGENT_ARGS ||
      env.BUZZ_ACP_SYSTEM_PROMPT_FILE !== paths.home+'/.agent/system-prompt.md' ||
      !/^[a-f0-9]{64}$/.test(env.BUZZ_ACP_AGENT_OWNER ?? '') || !env.BUZZ_RELAY_URL || !env.KANEO_API_URL) deny();
  directory(paths.home, identity); directory(paths.credentials, identity);
  safePath(paths.workspace); safePath(paths.prompts);
  checkMounts(paths);
  validateStateStorage(statfs(paths.home, { bigint:true }), env.AGENT_STATE_CAPACITY_BYTES ?? '');
  for (const name of ['COMMON.md','HOST_OPERATOR.md']) {
    const file=path.join(paths.prompts,name); safePath(file); const s=fs.lstatSync(file);
    if (!s.isFile() || s.nlink !== 1 || !s.size || (s.mode & 0o022)) deny();
  }
  const allowed = ['buzz-private-key','buzz-auth-tag','gitconfig','kaneo-credentials.json','codex-auth.json','openai-api-key'];
  const names=fs.readdirSync(paths.credentials);
  if (names.some(n=>!allowed.includes(n)) || ['buzz-private-key','buzz-auth-tag','gitconfig','kaneo-credentials.json'].some(n=>!names.includes(n)) ||
      !names.some(n=>['codex-auth.json','openai-api-key'].includes(n))) deny();
  for (const name of names) privateFile(path.join(paths.credentials,name),identity);
  const git=privateFile(paths.credentials+'/gitconfig',identity);
  const match=git.match(/^# Managed agent Git identity v1: host-operator\n\[user\]\n\tname = ("(?:[^"\\\n]|\\["\\])*")\n\temail = ("(?:[^"\\\n]|\\["\\])*")\n\tuseConfigOnly = true\n$/);
  if (!match) deny();
  const name=JSON.parse(match[1]),email=JSON.parse(match[2]);
  if (!name.trim() || name !== name.trim() || name.length>254 || email.length>254 || /[\p{Cc}\p{Cf}<>]/u.test(name+email) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(email) || render({agentId:'host-operator',name,email}) !== git) deny();
  // Reject configuration authority while allowing session/cache files on restart.
  const recovery=paths.home+'/lost+found';
  if (exists(recovery)) { safePath(recovery); validateRecoveryDirectory(fs.lstatSync(recovery)); }
  const homeNames=['lost+found','.agent','.cache','.config','.codex','.local','.npm','.gitconfig'];
  if (fs.readdirSync(paths.home).some(n=>!homeNames.includes(n))) deny();
  for (const dir of ['.agent','.cache','.config','.codex','.local','.npm']) if (exists(paths.home+'/'+dir)) directory(paths.home+'/'+dir,identity);
  const persisted=paths.home+'/.gitconfig'; if (exists(persisted) && privateFile(persisted,identity)!==git) deny();
  for (const [dir,allowedNames] of [['.agent',['system-prompt.md']],['.config',['kaneo-mcp']],['.local',['state']]]) {
    if (exists(paths.home+'/'+dir) && fs.readdirSync(paths.home+'/'+dir).some(n=>!allowedNames.includes(n))) deny();
  }
  if (exists(paths.home+'/.codex')) {
    for (const n of fs.readdirSync(paths.home+'/.codex')) if (/\.toml|^AGENTS\.md$|mcp|hook|settings|instructions/i.test(n) && n!=='config.toml') deny();
    const config=paths.home+'/.codex/config.toml'; if (exists(config) && privateFile(config,identity)!==expectedMcp(env.KANEO_API_URL)) deny();
  }
  // Generic loader writes through these directories; never follow persisted links.
  for (const dir of ['.config/kaneo-mcp','.local/state','.local/state/host-operator']) if (exists(paths.home+'/'+dir)) directory(paths.home+'/'+dir,identity);
  if (exists(paths.home+'/.local/state') && fs.readdirSync(paths.home+'/.local/state').some(n=>n!=='host-operator')) deny();
  if (exists(paths.home+'/.local/state/host-operator') && fs.readdirSync(paths.home+'/.local/state/host-operator').some(n=>n!=='instance.lock')) deny();
  for (const file of ['.agent/system-prompt.md','.config/kaneo-mcp/credentials.json','.codex/auth.json']) if (exists(paths.home+'/'+file)) privateFile(paths.home+'/'+file,identity);
  return true;
}
export function openInstanceLock(home = layout.home, identity = owner) {
  let fd;
  try {
    directory(home,identity);
    for (const suffix of ['.local','.local/state','.local/state/host-operator']) {
      const dir=home+'/'+suffix;
      if (!exists(dir)) { try { fs.mkdirSync(dir,{mode:0o700}); } catch(e) { if(e.code!=='EEXIST')throw e; } }
      directory(dir,identity);
    }
    const file=home+'/.local/state/host-operator/instance.lock';
    try { fd=fs.openSync(file,fs.constants.O_RDWR|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600); }
    catch(e) { if(e.code!=='EEXIST')throw e; fd=fs.openSync(file,fs.constants.O_RDWR|fs.constants.O_NOFOLLOW); }
    const a=fs.fstatSync(fd),b=fs.lstatSync(file);
    if (!a.isFile() || a.nlink!==1 || a.uid!==identity.uid || a.gid!==identity.gid || (a.mode&0o7777)!==0o600 || a.dev!==b.dev || a.ino!==b.ino) deny();
    return fd;
  } catch { if(fd!==undefined)fs.closeSync(fd); deny(); }
}
export function launchHostOperator(argv, options = {}) {
  validateHostOperator(options);
  const paths=options.paths??layout, identity=options.identity??owner;
  const fd=openInstanceLock(paths.home,identity);
  let child;
  try {
    child=spawn('/bin/bash',['-c','/usr/bin/flock -n -E 75 3 || exit $?; exec "$@"','host-operator',options.entrypoint??'/usr/local/bin/agent-entrypoint',...argv],
      {env:options.env??process.env,stdio:['inherit','inherit','inherit',fd]});
  } finally { fs.closeSync(fd); }
  return child;
}
if (process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  try {
    const child=launchHostOperator(process.argv.slice(2));
    for(const signal of ['SIGTERM','SIGINT','SIGHUP'])process.on(signal,()=>child.kill(signal));
    child.on('error',()=>{console.error('host-operator: startup denied');process.exitCode=1;});
    child.on('exit',(code,signal)=>{if(signal){process.removeAllListeners(signal);process.kill(process.pid,signal);}else process.exitCode=code??1;});
  } catch { console.error('host-operator: startup denied');process.exitCode=1; }
}
