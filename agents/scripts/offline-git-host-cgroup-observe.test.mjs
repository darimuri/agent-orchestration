// Source-only builds. Production observer is NEVER executed by this test runner.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { offlineGitFlags } from './build-offline-git-worker.mjs';
const root = fileURLToPath(new URL('../../', import.meta.url));
const native = path.join(root, 'agents/tests/offline-git-worker');
const base = '30a01e5a3c00b57f3d08946cf6f3d2c845227b86';
const files = ['agents/tests/offline-git-worker/host-cgroup-observe.c',
  'agents/tests/offline-git-worker/host-cgroup-observe.test.c',
  'agents/scripts/offline-git-host-cgroup-observe.test.mjs', 'agents/OFFLINE_GIT_HOST_ACCEPTANCE.md'];
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const env = { LANG:'C', LC_ALL:'C', TZ:'UTC', SOURCE_DATE_EPOCH:'0' };
function git(args) {
  const r = spawnSync('/usr/bin/git', args, { cwd:root, env, encoding:'utf8', timeout:10000, maxBuffer:1048576 });
  assert.equal(r.status, 0, r.stderr); return r.stdout.trim();
}
const source = () => fs.readFileSync(path.join(native, 'host-cgroup-observe.c'), 'utf8');
test('observer has a closed effect surface and fixed no-argument entry', () => {
  const s = source();
  for (const call of ['execve','execvp','execl','execv','posix_spawn','popen','fork','clone','system','socket','connect','mount','unmount','unlink','rmdir','kill','setuid','setgid','setresuid','setresgid','getenv'])
    assert(!new RegExp('\\b' + call + '\\s*\\(').test(s), call);
  assert.match(s, /argc==1&&linux_os&&uid==0&&euid==0&&gid==0&&egid==0/);
  assert.match(s, /SYS_close_range/); assert.match(s, /clearenv\(\)/);
  assert.match(s, /RESOLVE_BENEATH\|RESOLVE_NO_SYMLINKS\|RESOLVE_NO_MAGICLINKS/);
  assert.match(s, /STATX_MNT_ID/); assert.match(s, /O_RDWR\|O_CREAT\|O_EXCL/);
  assert.match(s, /"cpu.max","cpu.max.burst","memory.max","memory.swap.max","memory.oom.group","pids.max"/);
  assert(s.includes('"20000 100000\\n","0\\n","536870912\\n","0\\n","1\\n","8\\n"'));
  assert(!/qualified\\":true|admission\\":true|assumptionsVerified\\":true/.test(s));
  assert.match(s, /errorErrno/); assert.match(s, /return 2;/);
});
test('all nonallowlisted tracked bytes equal the exact base, including frozen host entry and inventories', () => {
  const changed = git(['diff', base, '--name-only']).split('\n').filter(Boolean);
  assert(changed.every(p => files.includes(p)), changed.join('\n'));
  const tracked = git(['ls-tree','-r','--name-only',base]).split('\n');
  for (const file of tracked.filter(p => !files.includes(p))) {
    const r = spawnSync('/usr/bin/git',['show',`${base}:${file}`],{cwd:root,env,maxBuffer:8388608});
    assert.equal(r.status,0); assert.deepEqual(fs.readFileSync(path.join(root,file)),r.stdout,file);
  }
});
test('fixture suite includes independent literal trace, exhaustive IO faults, retained interruption and race', () => {
  const s = fs.readFileSync(path.join(native,'host-cgroup-observe.test.c'),'utf8');
  for (const marker of ['golden_values','at<=boundaries','_exit(91)','waitpid','READ_BOUND+1U','EVIDENCE_BOUND-REPORT_BOUND','SIMULATED','getuid()!=0']) assert(s.includes(marker),marker);
  assert.match(s, /#define OBSERVER_TEST 1/);
  assert(!/\b(?:unlink|rmdir|system|execve|mount)\s*\(/.test(s));
});
for (const sanitizer of [false,true]) test(`mandatory ${sanitizer?'ASan/UBSan':'hardened'} observer compile and separate nonroot fixtures`, () => {
  assert.equal(process.getuid() === 0, false, 'ordinary-user tests only');
  const out = fs.mkdtempSync('/tmp/age30-cgroup-source-'); fs.chmodSync(out,0o700);
  const manifest = { version:1,status:'UNKNOWN',admission:false,qualified:false,assumptionsVerified:false,
    scope:'SIMULATED_SOURCE_ONLY',base,head:git(['rev-parse','HEAD']),tree:git(['rev-parse','HEAD^{tree}']),
    worktreeDiffSha256:hash(git(['diff',base,'--',...files])),
    sources:Object.fromEntries(files.map(p=>[p,hash(fs.readFileSync(path.join(root,p)))])),
    compiler:'/usr/bin/cc',sanitizer,commands:[],artifacts:{},productionExecuted:false,complete:false };
  let sequence = 0;
  const run = (file,args) => {
    manifest.commands.push({file,args});
    const r = spawnSync(file,args,{cwd:out,env:{...env,...(sanitizer?{ASAN_OPTIONS:'detect_leaks=1:abort_on_error=1',UBSAN_OPTIONS:'halt_on_error=1'}:{})},encoding:'utf8',timeout:180000,maxBuffer:1048576});
    fs.writeFileSync(path.join(out,`command-${++sequence}.json`),JSON.stringify({file,args,status:r.status,signal:r.signal,error:r.error?.code,stdout:r.stdout,stderr:r.stderr})+'\n',{flag:'wx',mode:0o600});
    assert.equal(r.error,undefined,`mandatory tool failure; retained ${out}: ${r.error?.message}`);
    assert.equal(r.status,0,`retained ${out}: ${r.stderr}`); return r.stdout;
  };
  try {
    const flags = [...offlineGitFlags,...(sanitizer?['-fsanitize=address,undefined','-fno-omit-frame-pointer']:[]),`-ffile-prefix-map=${native}=observer`];
    manifest.tools=Object.fromEntries(['/usr/bin/cc','/usr/bin/ld','/usr/bin/readelf',process.execPath].map(p=>[p,{realPath:fs.realpathSync(p),sha256:hash(fs.readFileSync(p))}]));
    manifest.compilerVersion=run('/usr/bin/cc',['--version']);
    manifest.linkerVersion=run('/usr/bin/ld',['--version']);
    for (const [name,file] of [['observer','host-cgroup-observe.c'],['fixture','host-cgroup-observe.test.c']]) {
      const binary=path.join(out,name); run('/usr/bin/cc',[...flags,path.join(native,file),'-o',binary]);
      manifest.artifacts[name]={sha256:hash(fs.readFileSync(binary)),executed:name==='fixture'};
      run('/usr/bin/readelf',['-h','-l','-d',binary]);
    }
    const result=run(path.join(out,'fixture'),[]); assert.match(result,/SIMULATED fixtures complete/);
    manifest.traceSha256=hash(fs.readFileSync(path.join(out,'simulated-trace.txt')));
    for(const [p,identity] of Object.entries(manifest.tools)) assert.equal(hash(fs.readFileSync(p)),identity.sha256,`tool changed: ${p}`);
    for(const [p,digest] of Object.entries(manifest.sources)) assert.equal(hash(fs.readFileSync(path.join(root,p))),digest,`source changed: ${p}`);
    assert.equal(git(['rev-parse','HEAD']),manifest.head,'HEAD changed during build');
    manifest.complete=true;
  } catch (error) {
    manifest.failure={code:error.code ?? 'SOURCE_CHECK_FAILED',message:String(error.message).slice(0,2048)};
    throw error;
  } finally {
    fs.writeFileSync(path.join(out,'build.json'),JSON.stringify(manifest,null,2)+'\n',{flag:'wx',mode:0o600});
    console.log(`Retained nonadmitting source inventory: ${out}/build.json`);
  }
});
