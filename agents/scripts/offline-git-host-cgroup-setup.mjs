// Nonroot preparation only. The owner entry is INERT TEXT, never executed here.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { offlineGitFlags } from './build-offline-git-worker.mjs';
export const BASE = 'cc71fb96f0be40b681821c5061675285a6f66244';
export const BASE_TREE = '3caab46e535de0cf5ab25774dea8c7a45e1d9817';
export const FILES = Object.freeze(['agents/tests/offline-git-worker/host-cgroup-setup.c',
  'agents/tests/offline-git-worker/host-cgroup-setup.test.c','agents/scripts/offline-git-host-cgroup-setup.mjs',
  'agents/scripts/offline-git-host-cgroup-setup.test.mjs','agents/OFFLINE_GIT_HOST_ACCEPTANCE.md']);
const root = fileURLToPath(new URL('../../',import.meta.url));
const native = path.join(root,'agents/tests/offline-git-worker');
const env = Object.freeze({LANG:'C',LC_ALL:'C',TZ:'UTC',SOURCE_DATE_EPOCH:'0'});
export const hash = b => createHash('sha256').update(b).digest('hex');
const check = (ok,why) => {if(!ok)throw Error(why);};
export function run(file,args,cwd=root) {
  const r=spawnSync(file,args,{cwd,env,encoding:'utf8',timeout:120000,maxBuffer:8388608});
  check(!r.error&&!r.signal&&r.status===0,`tool_failed ${file}: ${r.error?.code??r.status} ${r.stderr?.slice(0,2048)}`);return r.stdout;
}
export function trusted(file) {
  const real=fs.realpathSync(file);let at=real;
  while(true){const s=fs.lstatSync(at);check(!s.isSymbolicLink()&&s.uid===0&&s.gid===0&&!(s.mode&0o7022),`untrusted ${at}`);if(at==='/')break;at=path.dirname(at);}
  const s=fs.statSync(real);check(s.isFile()&&s.size<=268435456,`not_file ${real}`);
  return {path:real,size:s.size,sha256:hash(fs.readFileSync(real))};
}
export function inspectELF(file,execute=run) {
  const text=execute('/usr/bin/readelf',['-h','-l','-d',file]);
  check(/Machine:\s+Advanced Micro Devices X86-64/.test(text),'architecture');
  check(!/\((?:RPATH|RUNPATH)\)/.test(text),'elf_search_path');
  const interpreter=[...text.matchAll(/Requesting program interpreter: ([^\]]+)\]/g)].map(m=>m[1]);
  const needed=[...text.matchAll(/\(NEEDED\).*\[([^\]]+)\]/g)].map(m=>m[1]);
  check(interpreter.length===1&&interpreter[0]==='/lib64/ld-linux-x86-64.so.2','elf_interpreter');
  check(needed.length===1&&needed[0]==='libc.so.6','elf_dependencies');return text;
}
// Only these known system aliases may be resolved. No caller path is accepted.
export function runtimePins() {
  check(process.platform==='linux'&&process.arch==='x64','unsupported_host');
  const pins=[trusted('/lib64/ld-linux-x86-64.so.2'),trusted('/lib/x86_64-linux-gnu/libc.so.6')];
  check(pins[0].path==='/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2'||pins[0].path==='/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2','loader_alias');
  check(pins[1].path==='/usr/lib/x86_64-linux-gnu/libc.so.6'||pins[1].path==='/lib/x86_64-linux-gnu/libc.so.6','libc_alias');return pins;
}
// Literal root verifier template. Pins are independently approved literals in the
// command, never loaded from an adjacent manifest or from the payload's contents.
export function verifierSource(payload,runtime) {
  check(/^[a-f0-9]{64}$/.test(payload.sha256)&&Number.isSafeInteger(payload.size)&&payload.size>0&&payload.size<=1048576,'payload_pin');
  check(runtime.length===2,'runtime_pins');
  const allowed=[['/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2','/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2'],['/usr/lib/x86_64-linux-gnu/libc.so.6','/lib/x86_64-linux-gnu/libc.so.6']];
  runtime.forEach((p,i)=>check(allowed[i].includes(p.path)&&/^[a-f0-9]{64}$/.test(p.sha256)&&Number.isSafeInteger(p.size)&&p.size>0&&p.size<=268435456,'runtime_pin'));
  return `import os, sys, stat, hashlib, fcntl, resource
EXPECTED_SIZE = ${payload.size}
EXPECTED_SHA256 = '${payload.sha256}'
RUNTIME = ${JSON.stringify(runtime.map(p=>[p.path,p.size,p.sha256]))}
def require(ok):
    if not ok: raise RuntimeError('AGE30 UNKNOWN: verifier refused')
def identity(s):
    return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def system_file(name, size, digest):
    # Every component is opened relative to a held trusted parent, no symlinks.
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        parts = name.split('/')[1:]
        for i, component in enumerate(parts):
            before = os.fstat(fd)
            require(before.st_uid == 0 and before.st_gid == 0 and not before.st_mode & 0o7022)
            nxt = os.open(component, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | (os.O_DIRECTORY if i < len(parts)-1 else 0), dir_fd=fd)
            os.close(fd)
            fd = nxt
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_gid == 0 and not before.st_mode & 0o7022 and before.st_size == size)
        data = os.read(fd, size + 1)
        require(len(data) == size and os.read(fd, 1) == b'' and hashlib.sha256(data).hexdigest() == digest and identity(before) == identity(os.fstat(fd)))
    finally:
        os.close(fd)
require(sys.flags.isolated == 1 and sys.flags.ignore_environment == 1 and sys.flags.no_user_site == 1)
require(os.getuid() == 0 and os.geteuid() == 0 and os.getgid() == 0 and os.getegid() == 0)
require(sys.platform == 'linux' and os.uname().machine == 'x86_64')
require(os.execve in os.supports_fd and hasattr(os, 'memfd_create'))
for pin in RUNTIME: system_file(*pin)
s = os.fstat(0)
require(stat.S_ISREG(s.st_mode) and s.st_size == EXPECTED_SIZE and os.lseek(0, 0, os.SEEK_CUR) == 0)
data = os.read(0, EXPECTED_SIZE + 1)
require(len(data) == EXPECTED_SIZE and os.read(0, 1) == b'' and hashlib.sha256(data).hexdigest() == EXPECTED_SHA256 and identity(s) == identity(os.fstat(0)))
fd = os.memfd_create('age30-setup-v1', os.MFD_ALLOW_SEALING)
require(os.write(fd, data) == EXPECTED_SIZE)
require(os.lseek(fd, 0, os.SEEK_SET) == 0)
require(os.read(fd, EXPECTED_SIZE + 1) == data)
seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
require(fcntl.fcntl(fd, fcntl.F_GET_SEALS) == seals)
os.lseek(fd, 0, os.SEEK_SET)
# No compiler, shell, pathname reopen, root temporary executable or child process.
ceiling = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
require(ceiling != resource.RLIM_INFINITY and ceiling <= 1048576)
os.closerange(3, fd)
os.closerange(fd+1, ceiling)
os.execve(fd, ['age30-setup-v1'], {})
`;
}
export function renderOwnerEntry(payload,runtime) {
  const code=verifierSource(payload,runtime);
  // POSIX quoting is applied to the literal code, not interpreted input.
  return `INERT REVIEW TEXT — NOT A SCRIPT. Requires separate exact-digest owner authorization.\n`+
    `sudo -- /usr/bin/python3 -I -c '${code.replaceAll("'", "'\\''")}' < APPROVED_PAYLOAD_REGULAR_FILE\n`;
}
export function embeddedHeader(bytes) {
  check(bytes.length>0&&bytes.length<=262144,'observer_bound');
  return `static const unsigned char observer_bytes[]={${[...bytes].map(b=>`0x${b.toString(16).padStart(2,'0')}`).join(',')}};\nstatic const char observer_sha256[]="${hash(bytes)}";\n`;
}
function sourceInventory() {
  const names=run('/usr/bin/git',['ls-files']).trim().split('\n');
  return Object.fromEntries(names.map(p=>[p,hash(fs.readFileSync(path.join(root,p)))]));
}
export function prepare() {
  check(process.getuid()!==0&&process.geteuid()!==0,'ordinary_user_required');
  const out=fs.mkdtempSync('/tmp/age30-cgroup-setup-source-');fs.chmodSync(out,0o700);
  const m={status:'UNKNOWN',admission:false,qualified:false,assumptionsVerified:false,productionExecuted:false,complete:false,base:BASE,baseTree:BASE_TREE,commands:[]};
  const execute=(file,args)=>{m.commands.push({file,args});const n=m.commands.length;try{const stdout=run(file,args,out);fs.writeFileSync(path.join(out,`command-${n}.json`),JSON.stringify({file,args,status:0,stdout})+'\n',{flag:'wx',mode:0o600});return stdout;}catch(e){fs.writeFileSync(path.join(out,`command-${n}.json`),JSON.stringify({file,args,error:String(e)})+'\n',{flag:'wx',mode:0o600});throw e;}};
  try {
    check(run('/usr/bin/git',['status','--porcelain']).trim()==='','clean_reviewed_source_required');
    check(run('/usr/bin/git',['rev-parse',`${BASE}^{tree}`]).trim()===BASE_TREE,'base_tree');
    check(run('/usr/bin/git',['merge-base','HEAD',BASE]).trim()===BASE,'base_ancestry');
    const changed=run('/usr/bin/git',['diff','--name-only',BASE,'HEAD']).trim().split('\n').filter(Boolean);
    check(changed.length===5&&FILES.every(p=>changed.includes(p)),'five_file_scope');
    m.head=run('/usr/bin/git',['rev-parse','HEAD']).trim();m.tree=run('/usr/bin/git',['rev-parse','HEAD^{tree}']).trim();
    m.sources=sourceInventory();m.tools=Object.fromEntries(['/usr/bin/cc','/usr/bin/ld','/usr/bin/readelf','/usr/bin/git','/usr/bin/python3',process.execPath].map(p=>[p,trusted(p)]));
    m.runtime=runtimePins();
    // Python -I trusts the system stdlib. Record its closed import closure and
    // validate each existing module file plus its ancestry before handoff.
    const python=execute('/usr/bin/python3',['-I','-c',"import os,sys,stat,hashlib,fcntl,resource,json; print(json.dumps(sorted(set(getattr(m,'__file__','') for m in sys.modules.values() if getattr(m,'__file__',None)))))"]);
    m.pythonModules=Object.fromEntries(JSON.parse(python).map(p=>[p,trusted(p)]));
    m.versions={cc:execute('/usr/bin/cc',['--version']),ld:execute('/usr/bin/ld',['--version']),readelf:execute('/usr/bin/readelf',['--version']),node:process.version};
    const observer=path.join(out,'observer');execute('/usr/bin/cc',[...offlineGitFlags,`-ffile-prefix-map=${native}=observer`,path.join(native,'host-cgroup-observe.c'),'-o',observer]);
    m.observerELF=inspectELF(observer,execute);const bytes=fs.readFileSync(observer);m.observer={size:bytes.length,sha256:hash(bytes)};
    const header=embeddedHeader(bytes);fs.writeFileSync(path.join(out,'setup-observer-data.h'),header,{flag:'wx',mode:0o600});m.embeddedDataSha256=hash(header);
    const setup=path.join(out,'setup');execute('/usr/bin/cc',[...offlineGitFlags,`-ffile-prefix-map=${native}=setup`,'-I',out,path.join(native,'host-cgroup-setup.c'),'-o',setup]);
    m.setupELF=inspectELF(setup,execute);const payload=fs.readFileSync(setup);check(payload.length<=1048576,'setup_bound');m.setup={size:payload.length,sha256:hash(payload)};
    for(const [p,id] of Object.entries(m.tools))check(JSON.stringify(trusted(p))===JSON.stringify(id),'tool_changed');
    for(const [p,id] of Object.entries(m.pythonModules))check(JSON.stringify(trusted(p))===JSON.stringify(id),'python_changed');
    check(JSON.stringify(runtimePins())===JSON.stringify(m.runtime),'runtime_changed');
    check(JSON.stringify(sourceInventory())===JSON.stringify(m.sources)&&run('/usr/bin/git',['status','--porcelain']).trim()===''&&run('/usr/bin/git',['rev-parse','HEAD']).trim()===m.head,'source_changed');
    fs.writeFileSync(path.join(out,'owner-entry.txt'),renderOwnerEntry(m.setup,m.runtime),{flag:'wx',mode:0o600});m.complete=true;
  } catch(e) {m.failure=String(e).slice(0,2048);throw e;}
  finally {fs.writeFileSync(path.join(out,'build.json'),JSON.stringify(m,null,2)+'\n',{flag:'wx',mode:0o600});console.log(`Retained UNKNOWN source build: ${out}/build.json`);}
  return out;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  try {check(process.argv.length===3&&process.argv[2]==='prepare','fixed_prepare_command_required');prepare();process.exitCode=2;}
  catch(e){console.error(`UNKNOWN: ${e.message}`);process.exitCode=2;}
}
