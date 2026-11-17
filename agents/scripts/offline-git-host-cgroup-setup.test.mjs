// Mandatory source tests. Missing compiler/Python is failure, never a skip.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { offlineGitFlags } from './build-offline-git-worker.mjs';
import { BASE,BASE_TREE,FILES,hash,run,embeddedHeader,inspectELF,runtimePins,renderOwnerEntry,verifierSource } from './offline-git-host-cgroup-setup.mjs';
const root=fileURLToPath(new URL('../../',import.meta.url));
const native=path.join(root,'agents/tests/offline-git-worker');
const source=p=>fs.readFileSync(path.join(root,p),'utf8');
const git=args=>run('/usr/bin/git',args,root).trim();
const environment={LANG:'C',LC_ALL:'C',TZ:'UTC',SOURCE_DATE_EPOCH:'0'};
const payload={size:4,sha256:hash('SAFE')};
const pins=[{path:'/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2',size:1,sha256:'1'.repeat(64)},
  {path:'/usr/lib/x86_64-linux-gnu/libc.so.6',size:1,sha256:'2'.repeat(64)}];
test('literal owner verifier pins have no manifest/path/command input',()=>{
  const code=verifierSource(payload,pins),text=renderOwnerEntry(payload,pins);
  assert(code.includes(`EXPECTED_SHA256 = '${hash('SAFE')}'`));assert(code.includes('EXPECTED_SIZE = 4'));
  assert(text.startsWith('INERT REVIEW TEXT'));assert(text.includes('sudo -- /usr/bin/python3 -I -c'));
  for(const token of ['F_SEAL_WRITE','F_SEAL_GROW','F_SEAL_SHRINK','F_SEAL_SEAL','os.supports_fd','os.fstat(0)','identity(s)','os.closerange','os.execve(fd,'])assert(code.includes(token),token);
  for(const forbidden of ['sys.argv','os.environ[','subprocess','shell=True','/tmp/','manifest','pickle','eval(','exec('])assert(!code.includes(forbidden),forbidden);
  assert.throws(()=>verifierSource({...payload,size:1048577},pins));assert.throws(()=>verifierSource({...payload,sha256:'x'},pins));
  assert.throws(()=>verifierSource(payload,[{...pins[0],path:'/tmp/loader'},pins[1]]));
  assert.throws(()=>verifierSource(payload,[{...pins[0],path:"/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2'; evil"},pins[1]]));
  assert.throws(()=>embeddedHeader(Buffer.alloc(262145)));assert.throws(()=>embeddedHeader(Buffer.alloc(0)));
  const exact=embeddedHeader(Buffer.from('SAFE'));assert(exact.includes('0x53,0x41,0x46,0x45'));assert(exact.includes(hash('SAFE')));
});
test('closed native effect surface and independent fixture oracle',()=>{
  const s=source(FILES[0]),t=source(FILES[1]);
  for(const call of ['execve','execv','execl','posix_spawn','popen','fork','clone','system','socket','connect','mount','umount','unlink','rmdir','kill','setuid','setgid','chown','getenv'])assert(!new RegExp('\\b'+call+'\\s*\\(').test(s),call);
  for(const token of ['RESOLVE_NO_SYMLINKS','RESOLVE_NO_MAGICLINKS','RESOLVE_NO_XDEV','STATX_MNT_ID','SYS_close_range','clearenv()','O_CREAT|O_EXCL','observer_comparison','NO_ERRNO','RUNTIME_ONLY','FALLOC_FL_KEEP_SIZE'])assert(s.includes(token),token);
  assert.equal((s.match(/write_once\(s,fd,"\+cpu \+memory \+pids\\n",19U\)/g)??[]).length,1);
  assert(!s.includes('"cgroup.procs",O_WRONLY'));assert(!s.includes('"cgroup.kill"'));assert(!s.includes('"cgroup.freeze"'));
  assert(s.indexOf('report(s,1,false)')<s.indexOf('s->parent=mkdir_node'));
  for(const token of ['const char golden[]','at<=boundaries','_exit(91)','waitpid','READ_BOUND+1U','effects_after_error','getuid()!=0'])assert(t.includes(token),token);
});
test('unchanged tracked inputs equal immutable base, separate five-file inventory',()=>{
  assert.equal(git(['rev-parse',`${BASE}^{tree}`]),BASE_TREE);
  const changes=git(['diff','--name-only',BASE]).split('\n').filter(Boolean);assert(changes.every(p=>FILES.includes(p)),changes.join('\n'));
  for(const p of git(['ls-tree','-r','--name-only',BASE]).split('\n').filter(p=>!FILES.includes(p))){
    const r=spawnSync('/usr/bin/git',['show',`${BASE}:${p}`],{cwd:root,env:environment,maxBuffer:8388608});assert.equal(r.status,0);assert.deepEqual(fs.readFileSync(path.join(root,p)),r.stdout,p);
  }
});
for(const sanitizer of [false,true])test(`mandatory ${sanitizer?'ASan+UBSan':'hardened'} setup build and nonroot IO fixture`,()=>{
  assert(process.getuid()!==0&&process.geteuid()!==0);
  const out=fs.mkdtempSync('/tmp/age30-cgroup-setup-source-');fs.chmodSync(out,0o700);
  const names=[...new Set([...git(['ls-files']).split('\n'),...FILES])];
  const m={status:'UNKNOWN',admission:false,qualified:false,assumptionsVerified:false,productionExecuted:false,scope:'SIMULATED_SOURCE_ONLY',base:BASE,baseTree:BASE_TREE,head:git(['rev-parse','HEAD']),tree:git(['rev-parse','HEAD^{tree}']),sanitizer,complete:false,commands:[],sources:Object.fromEntries(names.map(p=>[p,hash(fs.readFileSync(path.join(root,p)))]))};
  function execute(file,args){m.commands.push({file,args});const r=spawnSync(file,args,{cwd:out,env:{...environment,ASAN_OPTIONS:'detect_leaks=1:abort_on_error=1',UBSAN_OPTIONS:'halt_on_error=1'},encoding:'utf8',timeout:180000,maxBuffer:8388608});fs.writeFileSync(path.join(out,`command-${m.commands.length}.json`),JSON.stringify({file,args,status:r.status,signal:r.signal,error:r.error?.code,stdout:r.stdout,stderr:r.stderr})+'\n',{flag:'wx',mode:0o600});assert.equal(r.error,undefined,`mandatory tool failed: ${r.error?.code}`);assert.equal(r.status,0,r.stderr);return r.stdout;}
  try {
    m.tools=Object.fromEntries(['/usr/bin/cc','/usr/bin/ld','/usr/bin/readelf',process.execPath].map(p=>[p,{real:fs.realpathSync(p),sha256:hash(fs.readFileSync(p))}]));
    m.versions={cc:execute('/usr/bin/cc',['--version']),ld:execute('/usr/bin/ld',['--version'])};
    const observer=path.join(out,'observer');execute('/usr/bin/cc',[...offlineGitFlags,`-ffile-prefix-map=${native}=observer`,path.join(native,'host-cgroup-observe.c'),'-o',observer]);
    const bytes=fs.readFileSync(observer);m.observerELF=inspectELF(observer);const header=embeddedHeader(bytes);fs.writeFileSync(path.join(out,'setup-observer-data.h'),header,{flag:'wx',mode:0o600});m.embeddedDataSha256=hash(header);m.observer={size:bytes.length,sha256:hash(bytes)};
    const flags=[...offlineGitFlags,...sanitizer?['-fsanitize=address,undefined','-fno-omit-frame-pointer']:[],`-ffile-prefix-map=${native}=setup`,'-I',out];
    m.artifacts={};
    for(const [name,file] of [['setup','host-cgroup-setup.c'],['fixture','host-cgroup-setup.test.c']]){const binary=path.join(out,name);execute('/usr/bin/cc',[...flags,path.join(native,file),'-o',binary]);const data=fs.readFileSync(binary);assert(data.length<=1048576);m.artifacts[name]={sha256:hash(data),size:data.length,executed:name==='fixture'};m.artifacts[name].elf=execute('/usr/bin/readelf',['-h','-l','-d',binary]);if(!sanitizer&&name==='setup')inspectELF(binary);}
    assert.match(execute(path.join(out,'fixture'),[]),/SIMULATED setup fixtures complete/);m.traceSha256=hash(fs.readFileSync(path.join(out,'simulated-setup-trace.txt')));
    for(const [p,id] of Object.entries(m.tools))assert.equal(hash(fs.readFileSync(p)),id.sha256,`tool changed ${p}`);
    for(const [p,digest] of Object.entries(m.sources))assert.equal(hash(fs.readFileSync(path.join(root,p))),digest,`source changed ${p}`);
    assert.equal(git(['rev-parse','HEAD']),m.head);m.complete=true;
  }catch(e){m.failure=String(e);throw e;}
  finally{fs.writeFileSync(path.join(out,'build.json'),JSON.stringify(m,null,2)+'\n',{flag:'wx',mode:0o600});console.log(`Retained UNKNOWN setup fixture inventory: ${out}/build.json`);}
});
test('mandatory isolated Python NONROOT verifier form: pin/bounds/mutation/seals/path replacement',()=>{
  assert(process.getuid()!==0);const out=fs.mkdtempSync('/tmp/age30-cgroup-setup-source-');fs.chmodSync(out,0o700);
  // This separate test form checks a fixed four-byte harmless data fixture. It
  // has no fd-exec and never receives real setup bytes. Owner template has no mode.
  const code=verifierSource(payload,runtimePins());
  const guard='require(os.getuid() == 0 and os.geteuid() == 0 and os.getgid() == 0 and os.getegid() == 0)';
  assert(code.includes(guard));
  const exec="os.execve(fd, ['age30-setup-v1'], {})";
  assert(code.endsWith(exec+'\n'));
  const form=code.replace(guard,'require(os.getuid() != 0 and os.geteuid() != 0)').replace(exec,"require(os.read(fd, EXPECTED_SIZE + 1) == b'SAFE'); print('SEALED_FIXED_DATA')");
  function execute(data,script=form){const file=path.join(out,`input-${hash(data)}-${hash(script).slice(0,8)}`);if(!fs.existsSync(file))fs.writeFileSync(file,data,{flag:'wx',mode:0o600});const fd=fs.openSync(file,'r');try{const r=spawnSync('/usr/bin/python3',['-I','-c',script],{cwd:out,env:environment,stdio:[fd,'pipe','pipe'],encoding:'utf8',timeout:10000,maxBuffer:1048576});assert.equal(r.error,undefined,`mandatory Python missing: ${r.error?.code}`);return r;}finally{fs.closeSync(fd);}}
  assert.equal(execute('SAFE').status,0);
  for(const data of ['SAF','SAFE!','EVIL',''])assert.notEqual(execute(data).status,0);
  assert.notEqual(execute('SAFE',form.replace('os.MFD_ALLOW_SEALING','0')).status,0);
  assert.notEqual(execute('SAFE',form.replace("require(os.execve in os.supports_fd and hasattr(os, 'memfd_create'))","require(False)")).status,0);
  const replaced=form.replace("os.lseek(fd, 0, os.SEEK_SET)\n# No compiler","os.rename('replacement', 'pathname')\nos.lseek(fd, 0, os.SEEK_SET)\n# No compiler");
  fs.writeFileSync(path.join(out,'pathname'),'SAFE',{flag:'wx',mode:0o600});fs.writeFileSync(path.join(out,'replacement'),'EVIL',{flag:'wx',mode:0o600});
  const held=fs.openSync(path.join(out,'pathname'),'r');try{const r=spawnSync('/usr/bin/python3',['-I','-c',replaced],{cwd:out,env:environment,stdio:[held,'pipe','pipe'],encoding:'utf8',timeout:10000});assert.equal(r.status,0,r.stderr);}finally{fs.closeSync(held);}
  const mutated=form.replace('data = os.read(0, EXPECTED_SIZE + 1)',"os.utime('mutable', None)\ndata = os.read(0, EXPECTED_SIZE + 1)");fs.writeFileSync(path.join(out,'mutable'),'SAFE',{flag:'wx',mode:0o600});const fd=fs.openSync(path.join(out,'mutable'),'r');try{assert.notEqual(spawnSync('/usr/bin/python3',['-I','-c',mutated],{cwd:out,env:environment,stdio:[fd,'pipe','pipe'],timeout:10000}).status,0);}finally{fs.closeSync(fd);}
});
