import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { personas, validateManifest, loadManifest, render, install as installIdentity, check as checkIdentity, applyIdentity as applyWithOwner } from './git-identity.mjs';

const fixtureOwner = Object.freeze({ uid: process.getuid(), gid: process.getgid() });
const install = (records, dirs) => installIdentity(records, dirs, fixtureOwner);
const check = (records, dirs) => checkIdentity(records, dirs, fixtureOwner);
const applyIdentity = (source, destination, role) => applyWithOwner(source, destination, role, fixtureOwner);

const here = path.dirname(fileURLToPath(import.meta.url));
const example = path.join(here, '../git-identities.example.json');
const fixture = () => JSON.parse(fs.readFileSync(example, 'utf8'));
function setup(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'git-identity-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const directories = personas.map(id => path.join(root, id));
  return { root, directories, records: validateManifest(fixture()) };
}
function run(command, args, options = {}) {
  return spawnSync(command, args, { encoding: 'utf8', ...options });
}
function isolatedEnv(home) {
  // Only fixture environment enters child Git/entrypoint processes.
  return { PATH: process.env.PATH, HOME: home, XDG_CONFIG_HOME: path.join(home, '.config'),
    XDG_CACHE_HOME: path.join(home, '.cache'), CODEX_HOME: path.join(home, '.codex'),
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: path.join(home, '.gitconfig') };
}

test('complete, unique mapping is required; malformed input never leaks values', () => {
  assert.equal(loadManifest(example).length, 3);
  const mutations = [
    v => { v.identities.pop(); },
    v => { v.identities[1].agentId = v.identities[0].agentId; },
    v => { v.identities[1].name = v.identities[0].name.toUpperCase(); },
    v => { v.identities[1].email = v.identities[0].email.toUpperCase(); },
    v => { v.identities[0].name = ''; },
    v => { v.identities[0].name = '  '; },
    v => { v.identities[0].email = 'bad'; },
    v => { v.identities[0].name = 'private\nvalue'; },
    v => { v.identities[0].email = 'private\u0000@example.test'; },
    v => { v.identities[0].name = 'hidden\u202evalue'; },
    v => { v.identities[0].include = '/private'; },
    v => { v.identities[0].agentId = 'unknown'; },
  ];
  for (const mutate of mutations) { const v = fixture(); mutate(v); assert.throws(() => validateManifest(v)); }
});

test('install, repeat, apply and real local commits preserve three distinct identities', t => {
  const { root, directories, records } = setup(t);
  install(records, directories); check(records, directories);
  const before = directories.map(dir => fs.readFileSync(path.join(dir, 'gitconfig'), 'utf8'));
  install(records, directories); check(records, directories);
  assert.deepEqual(directories.map(dir => fs.readFileSync(path.join(dir, 'gitconfig'), 'utf8')), before);
  for (let i = 0; i < records.length; i++) {
    const home = path.join(root, 'home-' + i), repo = path.join(root, 'repo-' + i);
    fs.mkdirSync(home); fs.mkdirSync(repo);
    const target = path.join(home, '.gitconfig');
    fs.writeFileSync(target, '[user]\n name = stale\n email = stale@agents.example.test\n');
    applyIdentity(path.join(directories[i], 'gitconfig'), target, records[i].agentId);
    const stat = fs.statSync(target);
    assert.equal(stat.mode & 0o777, 0o600); assert.equal(stat.uid, fixtureOwner.uid); assert.equal(stat.gid, fixtureOwner.gid);
    const env = isolatedEnv(home);
    assert.equal(run('git', ['init', '-q', repo], { env }).status, 0);
    assert.equal(run('git', ['config', '--local', '--get', 'user.name'], { cwd: repo, env }).status, 1);
    assert.equal(run('git', ['config', '--global', '--get', 'user.useConfigOnly'], { env }).stdout.trim(), 'true');
    assert.equal(run('git', ['commit', '--allow-empty', '-qm', 'fixture'], { cwd: repo, env }).status, 0);
    assert.equal(run('git', ['log', '-1', '--format=%an|%ae|%cn|%ce'], { cwd: repo, env }).stdout.trim(),
      [records[i].name, records[i].email, records[i].name, records[i].email].join('|'));
    applyIdentity(path.join(directories[i], 'gitconfig'), target, records[i].agentId);
    assert.equal(fs.readFileSync(target, 'utf8'), before[i]);
  }
});

test('last-persona conflict aborts before writing other identities; unmanaged config is preserved', t => {
  const { directories, records } = setup(t);
  fs.mkdirSync(directories[2]);
  const conflict = path.join(directories[2], 'gitconfig');
  fs.writeFileSync(conflict, '[include]\n path = /do-not-read\n');
  assert.throws(() => install(records, directories));
  assert.equal(fs.existsSync(directories[0]), false);
  assert.equal(fs.readFileSync(conflict, 'utf8'), '[include]\n path = /do-not-read\n');
});

test('symlinks, hardlinks, nested directories and nonregular targets are rejected', t => {
  const { root, directories, records } = setup(t);
  fs.mkdirSync(directories[0]);
  const file = path.join(directories[0], 'gitconfig');
  fs.symlinkSync(path.join(root, 'missing'), file);
  assert.throws(() => install(records, directories)); fs.unlinkSync(file);
  fs.writeFileSync(path.join(root, 'shared'), render(records[0]));
  fs.linkSync(path.join(root, 'shared'), file);
  assert.throws(() => install(records, directories)); fs.unlinkSync(file);
  fs.mkdirSync(file); assert.throws(() => install(records, directories)); fs.rmdirSync(file);
  fs.symlinkSync(directories[0], path.join(root, 'link'));
  assert.throws(() => install(records, [path.join(root, 'link/child'), ...directories.slice(1)]));
  assert.throws(() => install(records, [directories[0], path.join(directories[0], 'child'), directories[2]]));
});

test('preflight validation rejects missing, wrong persona/value/useConfigOnly and permissions', t => {
  const { directories, records } = setup(t);
  install(records, directories);
  const file = path.join(directories[0], 'gitconfig');
  for (const content of [render(records[1]), render(records[0]).replace('true', 'false'),
    render(records[0]).replace(records[0].name, 'Wrong Fixture')]) {
    fs.writeFileSync(file, content);
    assert.throws(() => check(records, directories));
  }
  fs.writeFileSync(file, render(records[0]));
  fs.chmodSync(file, 0o644); assert.throws(() => check(records, directories));
  fs.chmodSync(file, 0o600);
  fs.chmodSync(directories[0], 0o755); assert.throws(() => check(records, directories));
  fs.chmodSync(directories[0], 0o700);
  fs.unlinkSync(file); assert.throws(() => check(records, directories));
});

test('identity application rejects stale HOME fallback and supports repeated application', t => {
  const { root, directories, records } = setup(t);
  install(records, directories);
  const home = path.join(root, 'home'); fs.mkdirSync(home);
  const destination = path.join(home, '.gitconfig');
  const stale = '[user]\n name = stale\n email = stale@agents.example.test\n';
  fs.writeFileSync(destination, stale);
  const source = path.join(directories[1], 'gitconfig');
  const apply = () => applyIdentity(source, destination, 'developer');
  fs.unlinkSync(source);
  assert.throws(apply);
  assert.equal(fs.readFileSync(destination, 'utf8'), stale);
  install(records, directories);
  fs.writeFileSync(source, render(records[0]));
  assert.throws(apply);
  assert.equal(fs.readFileSync(destination, 'utf8'), stale);
  fs.writeFileSync(source, render(records[1]));
  apply(); apply();
  assert.equal(fs.readFileSync(destination, 'utf8'), render(records[1]));
  fs.unlinkSync(destination); fs.symlinkSync(path.join(root, 'outside'), destination);
  assert.throws(apply); assert.equal(fs.existsSync(path.join(root, 'outside')), false);
});

test('ownership checks reject both UID and GID mismatches independently', t => {
  const { root, directories, records } = setup(t);
  install(records, directories);
  for (const owner of [
    { ...fixtureOwner, uid: fixtureOwner.uid + 1 },
    { ...fixtureOwner, gid: fixtureOwner.gid + 1 },
  ]) {
    assert.throws(() => checkIdentity(records, directories, owner));
    assert.throws(() => applyWithOwner(path.join(directories[0], 'gitconfig'),
      path.join(root, '.gitconfig'), records[0].agentId, owner));
  }
});

test('production CLI keeps fixed 10001:10001 ownership and offers no fixture override', t => {
  const { root, directories, records } = setup(t);
  install(records, directories);
  const cli = path.join(here, 'git-identity.mjs');
  const args = [cli, 'check', example, ...directories];
  const matchesRuntime = fixtureOwner.uid === 10001 && fixtureOwner.gid === 10001;
  const result = run('node', args);
  assert.equal(result.status, matchesRuntime ? 0 : 1);
  if (!matchesRuntime) assert.match(result.stderr, /10001:10001/);
  const apply = run('node', [cli, 'apply', path.join(directories[1], 'gitconfig'),
    path.join(root, '.gitconfig'), 'developer']);
  assert.equal(apply.status, matchesRuntime ? 0 : 1);
  // Extra CLI arguments cannot inject the library-only ownership parameter.
  assert.notEqual(run('node', [...args, '--uid', String(fixtureOwner.uid)]).status, 0);
  assert.notEqual(run('node', [cli, 'apply', path.join(directories[1], 'gitconfig'),
    path.join(root, '.gitconfig'), 'developer', String(fixtureOwner.uid)]).status, 0);
});

// Actual shell entrypoint integration needs the runtime UID and workspace mount.
// The image suite runs this check; portable helper/CLI tests above run on every host.
test('container entrypoint fails before credential loading and supports restart', {
  skip: fixtureOwner.uid !== 10001 || fixtureOwner.gid !== 10001 || !fs.existsSync('/workspace'),
}, t => {
  const { root, directories, records } = setup(t);
  install(records, directories);
  const home = path.join(root, 'home'); fs.mkdirSync(home);
  const prompt = path.join(root, 'prompt'); fs.writeFileSync(prompt, 'fixture');
  const marker = path.join(root, 'started');
  const destination = path.join(home, '.gitconfig');
  fs.writeFileSync(destination, '[user]\n name = stale\n email = stale@agents.example.test\n');
  const env = { ...isolatedEnv(home), AGENT_ROLE: 'developer', AGENT_PROVIDER: 'codex',
    AGENT_CREDENTIALS_DIR: directories[1], AGENT_COMMON_PROMPT: prompt, AGENT_ROLE_PROMPT: prompt,
    BUZZ_RELAY_URL: 'wss://buzz.example.test', BUZZ_ACP_AGENT_OWNER: 'fixture' };
  const start = () => run('bash', [path.join(here, 'agent-entrypoint.sh'), 'touch', marker], { env });
  const source = path.join(directories[1], 'gitconfig');
  fs.unlinkSync(source);
  const missing = start(); assert.notEqual(missing.status, 0); assert.match(missing.stderr, /Git identity is required/);
  assert.equal(fs.existsSync(marker), false);
  install(records, directories);
  fs.writeFileSync(source, render(records[0]));
  assert.notEqual(start().status, 0); assert.equal(fs.existsSync(marker), false);
  fs.writeFileSync(source, render(records[1]));
  fs.writeFileSync(path.join(directories[1], 'buzz-private-key'), 'fixture');
  fs.writeFileSync(path.join(directories[1], 'codex-auth.json'), '{}');
  assert.equal(start().status, 0); assert.equal(fs.existsSync(marker), true);
  assert.equal(start().status, 0);
  assert.equal(fs.readFileSync(destination, 'utf8'), render(records[1]));
  fs.unlinkSync(destination); fs.symlinkSync(path.join(root, 'outside'), destination);
  assert.notEqual(start().status, 0); assert.equal(fs.existsSync(path.join(root, 'outside')), false);
});

test('quoted names roundtrip through Git without interpreting config directives', t => {
  const { root, directories, records } = setup(t);
  records[0].name = 'Fixture "Quoted" \\ Agent #1';
  install(records, directories);
  const target = path.join(root, '.gitconfig');
  applyIdentity(path.join(directories[0], 'gitconfig'), target, records[0].agentId);
  assert.equal(run('git', ['config', '--file', target, '--get', 'user.name']).stdout.trim(), records[0].name);
});

test('CLI rejects malformed JSON with value-free diagnostics', t => {
  const { root } = setup(t);
  const file = path.join(root, 'bad.json'); fs.writeFileSync(file, '{private-sentinel');
  const result = run('node', [path.join(here, 'git-identity.mjs'), 'validate', file]);
  assert.notEqual(result.status, 0); assert.equal(result.stdout, '');
  assert.ok(!result.stderr.includes('private-sentinel'));
});

test('fourth persona is apply-only; legacy manifest and persona order stay exactly three', t => {
  const {root,records}=setup(t); const dir=path.join(root,'host');fs.mkdirSync(dir,{mode:0o700});
  const record={agentId:'host-operator',name:'Fixture Host Operator',email:'host@agents.example.test'};
  const source=path.join(dir,'gitconfig'),destination=path.join(root,'.gitconfig');fs.writeFileSync(source,render(record),{mode:0o600});
  applyIdentity(source,destination,'host-operator');assert.equal(fs.readFileSync(destination,'utf8'),render(record));
  assert.deepEqual(personas,['dispatcher-planner','developer-a','reviewer-a']);
  assert.throws(()=>validateManifest({identities:[...records,record]}));
  assert.throws(()=>validateManifest({identities:[record,...records.slice(1)]}));
  assert.throws(()=>applyIdentity(source,destination,'developer'));
  fs.writeFileSync(source,render(records[0]));assert.throws(()=>applyIdentity(source,destination,'host-operator'));
  assert.equal(fs.readFileSync(destination,'utf8'),render(record));
});

test('separate fourth manifest rejects shared/corrupt records and preserves legacy defaults',async t=>{
 const{validateHostManifest,loadHostManifest,installHostIdentity,checkHostInstall}=await import('./git-identity.mjs');
 const{root,records}=setup(t),legacy=fixture(),record={agentId:'host-operator',name:'Fixture Host Operator',email:'host@example.test'},value={identities:[record]};
 assert.deepEqual(validateHostManifest(value,legacy),record);
 for(const bad of [{identities:[]},{identities:[record,record]},{identities:[{...record,agentId:'developer-a'}]},{identities:[{...record,name:records[0].name.toUpperCase()}]},{identities:[{...record,email:records[1].email.toUpperCase()}]},{identities:[{...record,extra:true}]}])assert.throws(()=>validateHostManifest(bad,legacy));
 const file=root+'/host.json';fs.writeFileSync(file,JSON.stringify(value));assert.deepEqual(loadHostManifest(file,example),record);
 const dir=root+'/selected';installHostIdentity(record,dir,fixtureOwner);checkHostInstall(record,dir,fixtureOwner,true);const ino=fs.statSync(dir).ino;installHostIdentity(record,dir,fixtureOwner);assert.equal(fs.statSync(dir).ino,ino);
 fs.writeFileSync(dir+'/gh-token','sentinel',{mode:0o600});assert.throws(()=>installHostIdentity(record,dir,fixtureOwner));assert.equal(fs.readFileSync(dir+'/gitconfig','utf8'),render(record));
});
test('fourth public Buzz mapping rejects copied/owner/unknown/malformed identities',async()=>{
 const{validateHostBuzzKeys}=await import('./git-identity.mjs');const owner='a'.repeat(64),keys=['1','2','3'].map(n=>n.repeat(64)).join(','),fourth='4'.repeat(64);
 assert(validateHostBuzzKeys(owner,keys,fourth));
 for(const args of [[owner,keys,owner],[owner,keys,'1'.repeat(64)],[owner,keys,fourth,'5'.repeat(64)],[owner,keys.split(',').slice(1).join(','),fourth],[owner,keys.replace('2'.repeat(64),'1'.repeat(64)),fourth],[owner,keys,'nothex']])assert.throws(()=>validateHostBuzzKeys(...args));
});
test('fourth layout validates paths without mutation and denies aliases/overlap/foreign metadata',async t=>{
 const{validateHostLayout}=await import('./git-identity.mjs');const{root}=setup(t),runtime=root+'/runtime';const paths=validateHostLayout(runtime,{});assert.equal(paths.credentials,runtime+'/host-operator/credentials');assert(!fs.existsSync(runtime));
 fs.symlinkSync(root,root+'/link');assert.throws(()=>validateHostLayout(root+'/link/runtime',{}));assert.throws(()=>validateHostLayout(runtime,{DEVELOPER_WORKSPACE:runtime+'/host-operator'}));assert.throws(()=>validateHostLayout('/workspace/runtime/test',{}));
 fs.mkdirSync(runtime);fs.mkdirSync(runtime+'/host-operator',{mode:0o700});assert.throws(()=>validateHostLayout(runtime,{}));
});

test('explicit fourth selectors reject repeated/mixed/unknown input before writes or auth',t=>{
 const{root}=setup(t);const missing=root+'/missing.env';
 for(const script of ['provision-runtime.sh','provision-agent-repository.sh','preflight.sh','provision-kaneo-credential.sh']){
  const file=path.join(here,'../scripts',script);
  for(const args of [['--agent','developer-a',missing],['--agent','host-operator','--agent','host-operator',missing]]){
   const result=run('/bin/bash',[file,...args],{env:{PATH:process.env.PATH,HOME:root}});assert.notEqual(result.status,0);assert(!fs.existsSync(root+'/host-operator'));
  }
 }
});

test('synthetic root facade: umask0077 selected layout preparation is repeatable without repairing conflicts', t => {
 const {root}=setup(t), runtime=root+'/runtime';
 // Real filesystem/umask, synthetic root/chown only: no privileged host fixture.
 const source=`
 const fs=await import('node:fs'),vm=await import('node:vm'),path=await import('node:path'),url=await import('node:url');
 const filename=process.argv[1],runtime=process.argv[2];process.umask(0o077);
 const native=fs.default,base=runtime+'/host-operator',created=[];
 const facade={...native,chownSync(p,uid,gid){if(uid!==10001||gid!==10001)throw Error('unexpected owner');created.push(p);},
 lstatSync(p){const st=native.lstatSync(p);return p===base||p.startsWith(base+'/')?new Proxy(st,{get(o,k){return k==='uid'||k==='gid'?10001:Reflect.get(o,k);}}):st;}};
 const context=vm.createContext({console,process:{getuid:()=>0,argv:[],env:{}}});
 const imports={'node:fs':facade,'node:path':path.default,'node:url':url};
 const mod=new vm.SourceTextModule(native.readFileSync(filename,'utf8'),{context,initializeImportMeta(meta){meta.url=url.pathToFileURL(filename).href;}});
 await mod.link(async name=>{const value=imports[name];if(!value)throw Error('unexpected import');const keys=name==='node:fs'||name==='node:path'?['default']:Object.keys(value);const m=new vm.SyntheticModule(keys,function(){for(const k of keys)this.setExport(k,k==='default'?value:value[k]);},{context});return m;});await mod.evaluate();
 const api=mod.namespace;api.prepareHostLayout(runtime,{});
 for(const [p,mode]of[[runtime,0o755],[base,0o755],[base+'/credentials',0o700],[base+'/workspace',0o755]])if((native.statSync(p).mode&0o7777)!==mode)throw Error('umask changed requested mode');
 const before=[base,base+'/credentials',base+'/workspace'].map(p=>native.statSync(p).ino);
 api.prepareHostLayout(runtime,{});api.validateHostLayout(runtime,{});
 if(created.length!==3||before.some((ino,i)=>ino!==native.statSync([base,base+'/credentials',base+'/workspace'][i]).ino))throw Error('repeat mutated existing layout');
 native.chmodSync(base+'/workspace',0o700);let rejected=false;try{api.prepareHostLayout(runtime,{});}catch{rejected=true;}
 if(!rejected||(native.statSync(base+'/workspace').mode&0o7777)!==0o700)throw Error('conflict repaired');
 `;
 const result=run(process.execPath,['--experimental-vm-modules','--input-type=module','-e',source,path.join(here,'git-identity.mjs'),runtime]);
 assert.equal(result.status,0,result.stderr);
});

test('synthetic private-store permissions: repository API never traverses private or legacy boundaries', t => {
 const {root}=setup(t), runtime=root+'/runtime';
 const source=`
 const fs=await import('node:fs'),vm=await import('node:vm'),path=await import('node:path'),url=await import('node:url'),assert=(await import('node:assert/strict')).default;
 const filename=process.argv[1],root=process.argv[2],native=fs.default,base=root+'/host-operator',store=root+'/state-storage',legacy=root+'/legacy-private';
 for(const [p,mode]of[[root,0o755],[base,0o755],[base+'/credentials',0o700],[base+'/workspace',0o755],[store,0o700],[legacy,0o700]]){native.mkdirSync(p,{mode});native.chmodSync(p,mode);}
 const accesses=[];let badPath=null,bad={};
 const facade={...native,lstatSync(p){accesses.push(p);if(p.startsWith(store+'/')||p.startsWith(legacy+'/'))throw Object.assign(Error('synthetic private EACCES'),{code:'EACCES'});const st=native.lstatSync(p);return new Proxy(st,{get(o,k){if(p===badPath&&k in bad)return bad[k];if(p===store&&(k==='uid'||k==='gid'))return 0;if((p===base||p.startsWith(base+'/'))&&(k==='uid'||k==='gid'))return 10001;return Reflect.get(o,k);}});}};
 const context=vm.createContext({console,process:{getuid:()=>10001,argv:[],env:{}}}),imports={'node:fs':facade,'node:path':path.default,'node:url':url};
 const mod=new vm.SourceTextModule(native.readFileSync(filename,'utf8'),{context,initializeImportMeta(meta){meta.url=url.pathToFileURL(filename).href;}});
 await mod.link(async name=>{const value=imports[name];if(!value)throw Error('unexpected import');const keys=name==='node:fs'||name==='node:path'?['default']:Object.keys(value);return new vm.SyntheticModule(keys,function(){for(const k of keys)this.setExport(k,k==='default'?value:value[k]);},{context});});await mod.evaluate();
 const {validateHostLayout:full,validateHostRepositoryLayout:repositoryLayout,validateHostCredentialLayout:credentialLayout}=mod.namespace;
 const publicLayout=(root,env)=>{const a=credentialLayout(root,env),b=repositoryLayout(root,env);assert.deepEqual(a,b);return a;};
 const env={DEVELOPER_CREDENTIALS_DIR:legacy+'/credentials',GITHUB_GATEWAY_CREDENTIALS_ROOT:legacy+'/gateway'};
 const before=[store,base,base+'/credentials',base+'/workspace'].map(p=>{const s=native.statSync(p);return[s.ino,s.mode,s.uid,s.gid];});
 assert.throws(()=>full(root,env),e=>e.code==='EACCES');accesses.length=0;
 for(let i=0;i<2;i++){const p=publicLayout(root,env);assert.equal(p.workspace,base+'/workspace');assert.equal(p.home,store+'/host-operator');}
 assert(!accesses.some(p=>p===store||p.startsWith(store+'/')||p===legacy||p.startsWith(legacy+'/')));
 assert.deepEqual([store,base,base+'/credentials',base+'/workspace'].map(p=>{const s=native.statSync(p);return[s.ino,s.mode,s.uid,s.gid];}),before);
 for(const key of ['DISPATCHER_CREDENTIALS_DIR','DEVELOPER_CREDENTIALS_DIR','REVIEWER_CREDENTIALS_DIR','DISPATCHER_WORKSPACE','DEVELOPER_WORKSPACE','REVIEWER_WORKSPACE','GITHUB_GATEWAY_RUNTIME_DIR','GITHUB_GATEWAY_CREDENTIALS_ROOT'])for(const p of [base,base+'/workspace/nested',store+'/host-operator',store+'/host-operator/child',store+'/host-operator.img',store+'/host-operator.img/child',root])assert.throws(()=>publicLayout(root,{[key]:p}));
 for(const p of [root+'/../runtime',root+'/',root+'//child','relative','/workspace/fixture/root','/etc/fixture/root'])assert.throws(()=>publicLayout(p,{}));
 for(const p of [base,base+'/credentials',base+'/workspace'])for(const fields of [{uid:12345},{gid:12345},{mode:0o40777}]){badPath=p;bad=fields;assert.throws(()=>publicLayout(root,{}));}badPath=root;for(const fields of [{uid:12345},{mode:0o40777}]){bad=fields;assert.throws(()=>publicLayout(root,{}));}badPath=null;
 native.writeFileSync(base+'/foreign','sentinel');assert.throws(()=>publicLayout(root,{}));native.unlinkSync(base+'/foreign');
 for(const p of [base+'/workspace',base+'/credentials']){native.renameSync(p,p+'-saved');native.symlinkSync(p+'-saved',p);assert.throws(()=>publicLayout(root,{}));native.unlinkSync(p);native.renameSync(p+'-saved',p);}
 native.symlinkSync(root,root+'-alias');assert.throws(()=>publicLayout(root+'-alias',{}));
 assert.throws(()=>publicLayout(root,{DEVELOPER_CREDENTIALS_DIR:legacy+'/../alias'}));
 assert.throws(()=>full(root,env),e=>e.code==='EACCES');
 `;
 const result=run(process.execPath,['--experimental-vm-modules','--input-type=module','-e',source,path.join(here,'git-identity.mjs'),runtime]);
 assert.equal(result.status,0,result.stderr);
});

test('repository-public CLI arguments and selected-only caller preserve full-validator dispatch', t => {
 const {root}=setup(t), module=path.join(here,'git-identity.mjs'),runtime=root+'/runtime';
 const env={PATH:process.env.PATH,HOME:root};
 assert.equal(run(process.execPath,[module,'validate-host-repository-layout',runtime],{env}).status,0);
 for(const args of [[],[runtime,'extra'],['relative']])assert.notEqual(run(process.execPath,[module,'validate-host-repository-layout',...args],{env}).status,0);
 const scripts=path.join(here,'../scripts');
 const callers=fs.readdirSync(scripts).filter(f=>f.endsWith('.sh')&&!f.startsWith('test-')&&fs.readFileSync(path.join(scripts,f),'utf8').includes('validate-host-repository-layout'));
 assert.deepEqual(callers,['provision-agent-repository.sh']);
 const script=fs.readFileSync(path.join(scripts,callers[0]),'utf8');
 assert.match(script,/if \[\[ "\$selected_host" == true \]\]; then\n  required_variables=[\s\S]*?validate-host-repository-layout/);
 for(const name of ['provision-runtime.sh','preflight.sh'])assert(fs.readFileSync(path.join(scripts,name),'utf8').includes('validate-host-layout'));
 const credentialCallers=fs.readdirSync(scripts).filter(f=>f.endsWith('.sh')&&!f.startsWith('test-')&&fs.readFileSync(path.join(scripts,f),'utf8').includes('validate-host-credential-layout'));
 assert.deepEqual(credentialCallers,['provision-buzz-agent-identity.sh','provision-kaneo-credential.sh']);
 assert.equal(run(process.execPath,[module,'validate-host-credential-layout',runtime],{env}).status,0);
 for(const args of [[],[runtime,'extra'],['relative']])assert.notEqual(run(process.execPath,[module,'validate-host-credential-layout',...args],{env}).status,0);
 assert.deepEqual(personas,['dispatcher-planner','developer-a','reviewer-a']);
});
