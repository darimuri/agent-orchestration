// SOURCE ONLY. Fixed nonroot prepare/collect; never invokes privileged binaries.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { offlineGitFlags } from './build-offline-git-worker.mjs';
export const BASE='34b7768a70d64141be52b36d3fbe729b8a02c55c';
export const BASE_TREE='18ac126ce52b8da030f3f25b7fc6866b4c447f3d';
export const FILES=Object.freeze(['agents/tests/offline-git-worker/host-cgroup-evidence-read.c','agents/tests/offline-git-worker/host-cgroup-evidence-read.test.c','agents/scripts/offline-git-host-cgroup-evidence.mjs','agents/scripts/offline-git-host-cgroup-evidence.test.mjs','agents/OFFLINE_GIT_HOST_ACCEPTANCE.md']);
export const BOUND=524288;
export const OBJECTS=Object.freeze(['start','inventory','result','observer','root.controllers','root.subtree_control','parent.type','parent.controllers','parent.subtree_control','parent.procs','parent.events','parent.entries']);
export const hash=b=>createHash('sha256').update(b).digest('hex');
const root=fileURLToPath(new URL('../../',import.meta.url));
const native=path.join(root,'agents/tests/offline-git-worker');
const env=Object.freeze({LANG:'C',LC_ALL:'C',TZ:'UTC',SOURCE_DATE_EPOCH:'0',ASAN_OPTIONS:'detect_leaks=1:abort_on_error=1',UBSAN_OPTIONS:'halt_on_error=1'});
const check=(p,why)=>{if(!p)throw Error(why);};
const ordinary=()=>check(process.getuid()!==0&&process.geteuid()!==0,'ordinary_user_required');
export function run(file,args,cwd=root){const r=spawnSync(file,args,{cwd,env,encoding:'utf8',timeout:180000,maxBuffer:8388608});check(!r.error&&!r.signal&&r.status===0,'tool_failed '+file+': '+(r.error?.code??r.status)+' '+r.stderr?.slice(0,1024));return r.stdout;}
export function trusted(file){const real=fs.realpathSync(file);let at=real;while(true){const s=fs.lstatSync(at);check(!s.isSymbolicLink()&&s.uid===0&&s.gid===0&&!(s.mode&0o7022),'untrusted '+at);if(at==='/')break;at=path.dirname(at);}const s=fs.statSync(real);check(s.isFile()&&s.size<=268435456,'not_file');return {path:real,size:s.size,sha256:hash(fs.readFileSync(real))};}
export function runtimePins(){check(process.platform==='linux'&&process.arch==='x64','unsupported_host');const p=[trusted('/lib64/ld-linux-x86-64.so.2'),trusted('/lib/x86_64-linux-gnu/libc.so.6')];check(['/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2','/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2'].includes(p[0].path)&&['/usr/lib/x86_64-linux-gnu/libc.so.6','/lib/x86_64-linux-gnu/libc.so.6'].includes(p[1].path),'runtime_alias');return p;}
export function inspectELF(file,execute=run){const text=execute('/usr/bin/readelf',['-h','-l','-d',file]);check(/Machine:\s+Advanced Micro Devices X86-64/.test(text)&&!/\((?:RPATH|RUNPATH)\)/.test(text),'elf');const i=[...text.matchAll(/Requesting program interpreter: ([^\]]+)\]/g)].map(m=>m[1]),d=[...text.matchAll(/\(NEEDED\).*\[([^\]]+)\]/g)].map(m=>m[1]);check(i.length===1&&i[0]==='/lib64/ld-linux-x86-64.so.2'&&d.length===1&&d[0]==='libc.so.6','elf_closure');return text;}
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
fd = os.memfd_create('age30-evidence-read-v1', os.MFD_ALLOW_SEALING)
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
os.execve(fd, ['age30-evidence-read-v1'], {})
`;
}
export function renderOwnerEntry(payload,runtime) {
  const code=verifierSource(payload,runtime);
  // POSIX quoting is applied to the literal code, not interpreted input.
  return `INERT REVIEW TEXT — NOT A SCRIPT. Requires separate exact-digest owner authorization.\n`+
    `sudo -- /usr/bin/python3 -I -c '${code.replaceAll("'", "'\\''")}' < APPROVED_PAYLOAD_REGULAR_FILE\n`;
}
// Bounded strict parser rejects duplicate decoded keys, trailing input and depth.
export function strictJSON(text){
 check(typeof text==='string'&&Buffer.byteLength(text)<=BOUND,'json_bound');let at=0;
 const ws=()=>{while(/[\x20\t\r\n]/.test(text[at]??'!'))at++;};
 function string(){const start=at++;while(at<text.length){const c=text[at++];if(c==='"')return JSON.parse(text.slice(start,at));if(c==='\\')at++;}throw Error('json_string');}
 function value(depth){check(depth<=16,'json_depth');ws();const c=text[at];
  if(c==='"')return string();
  if(c==='{'){at++;const out=Object.create(null),keys=new Set();ws();if(text[at]==='}'){at++;return out;}while(true){ws();check(text[at]==='"','json_key');const k=string();check(!keys.has(k),'duplicate_key');keys.add(k);ws();check(text[at++]===':','json_colon');out[k]=value(depth+1);ws();const sep=text[at++];if(sep==='}')return out;check(sep===',','json_object');}}
  if(c==='['){at++;const out=[];ws();if(text[at]===']'){at++;return out;}while(true){out.push(value(depth+1));ws();const sep=text[at++];if(sep===']')return out;check(sep===',','json_array');}}
  const m=/^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(at));check(m,'json_value');at+=m[0].length;return JSON.parse(m[0]);
 }
 const parsed=value(0);ws();check(at===text.length,'json_trailing');return parsed;
}
function exactKeys(o,keys){check(o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===keys.length&&keys.every(k=>Object.hasOwn(o,k)),'schema_keys');}
const META=['dev','ino','mount','mode','uid','gid','nlink','size','mtimeSec','mtimeNsec','ctimeSec','ctimeNsec'];
function metadata(o){if(o===null)return;exactKeys(o,META);for(const k of ['dev','ino','mount','nlink'])check(typeof o[k]==='string'&&/^(0|[1-9][0-9]{0,19})$/.test(o[k]),'metadata_integer');for(const k of ['size','mtimeSec','ctimeSec'])check(typeof o[k]==='string'&&/^-?(0|[1-9][0-9]{0,19})$/.test(o[k]),'metadata_signed');for(const k of ['mode','uid','gid'])check(Number.isSafeInteger(o[k])&&o[k]>=0&&o[k]<=4294967295,'metadata_number');for(const k of ['mtimeNsec','ctimeNsec'])check(Number.isSafeInteger(o[k])&&o[k]>=0&&o[k]<1000000000,'metadata_time');}
export function decode(raw){
 check(Buffer.isBuffer(raw)&&raw.length<=BOUND,'encoded_bound');const text=new TextDecoder('utf-8',{fatal:true}).decode(raw);const m=strictJSON(text);
 exactKeys(m,['version','status','admission','qualified','assumptionsVerified','collectionComplete','atomic','cgroupDurability','error','errorErrno','objects']);
 check(m.version===1&&m.status==='UNKNOWN'&&m.admission===false&&m.qualified===false&&m.assumptionsVerified===false&&typeof m.collectionComplete==='boolean'&&m.atomic===false&&m.cgroupDurability==='RUNTIME_ONLY','admission_schema');
 check(typeof m.error==='string'&&/^[a-z_]{1,64}$/.test(m.error)&&Number.isSafeInteger(m.errorErrno)&&m.errorErrno>=0&&m.errorErrno<=4095,'error_schema');
 check(Array.isArray(m.objects)&&m.objects.length===12,'objects');const decoded=[];
 for(let i=0;i<12;i++){
  const o=m.objects[i],bound=i<3?16384:i===3?262144:4096;exactKeys(o,['name','status','size','before','after','base64']);
  check(o.name===OBJECTS[i]&&['ok','missing','unread','unsafe','partial','unexpected_entries'].includes(o.status),'object_schema');
  check(Number.isSafeInteger(o.size)&&o.size>=0&&o.size<=bound+(o.status==='partial'?1:0)&&typeof o.base64==='string','object_bound');
  check(o.base64.length===4*Math.ceil(o.size/3)&&/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(o.base64),'base64');
  const bytes=Buffer.from(o.base64,'base64');check(bytes.length===o.size&&bytes.toString('base64')===o.base64,'base64_canonical');metadata(o.before);metadata(o.after);
  if(['missing','unread'].includes(o.status))check(o.size===0&&o.before===null&&o.after===null,'missing_schema');
  if(o.status==='ok'||o.status==='unexpected_entries')check(o.before!==null&&o.after!==null,'complete_metadata');
  if(o.status==='unexpected_entries')check(i===11,'directory_status');
  if(m.collectionComplete)check(['ok','missing','unexpected_entries'].includes(o.status)&&m.error==='none'&&m.errorErrno===0,'completion_schema');
  decoded.push({name:o.name,status:o.status,size:bytes.length,sha256:hash(bytes),bytes,receiptState:i<3?receiptState(bytes):undefined});
 }
 return {manifest:m,decoded};
}
// Receipt validity is an observation, never host/setup/durability admission.
function receiptState(bytes){if(!bytes.length)return 'empty';try{const value=strictJSON(new TextDecoder('utf-8',{fatal:true}).decode(bytes));return value&&typeof value==='object'&&!Array.isArray(value)?'json_object':'non_object';}catch{return 'malformed_or_partial';}}
function fresh(prefix){ordinary();const out=fs.mkdtempSync('/tmp/'+prefix);fs.chmodSync(out,0o700);return out;}
function save(out,name,bytes){fs.writeFileSync(path.join(out,name),bytes,{flag:'wx',mode:0o600});}
export function collectBytes(raw,{overflow=false,inputError=false}={}){
 const out=fresh('age30-cgroup-evidence-collect-');const retained=raw.subarray(0,BOUND+1);save(out,'raw.json',retained);
 const result={version:1,status:'UNKNOWN',admission:false,qualified:false,assumptionsVerified:false,collectionComplete:false,retentionComplete:!overflow&&!inputError,rawSize:retained.length,rawSha256:hash(retained),cgroupDurability:'RUNTIME_ONLY',complete:false};
 try{check(!overflow&&!inputError,'input_incomplete');const {manifest,decoded}=decode(retained);result.collectionComplete=manifest.collectionComplete;result.readerError=manifest.error;result.objects=decoded.map(({bytes,...o},i)=>{const file=String(i).padStart(2,'0')+'.bin';save(out,file,bytes);return {...o,file};});result.complete=true;}catch(e){result.failure=e.message;}
 save(out,'collection.json',JSON.stringify(result,null,2)+'\n');return out;
}
export async function collectInput(input){ordinary();const chunks=[];let length=0,overflow=false,inputError=false;try{for await(const chunk of input){const b=Buffer.isBuffer(chunk)?chunk:Buffer.from(chunk);const n=Math.min(b.length,BOUND+1-length);if(n>0){chunks.push(b.subarray(0,n));length+=n;}if(length>BOUND){overflow=true;input.destroy();break;}}}catch{inputError=true;}return collectBytes(Buffer.concat(chunks),{overflow,inputError});}
function inventory(){const names=[...new Set([...run('/usr/bin/git',['ls-files']).trim().split('\n'),...FILES])];return Object.fromEntries(names.map(p=>[p,hash(fs.readFileSync(path.join(root,p)))]));}
export function buildNative(out,sanitizer=false){
 ordinary();const st=fs.lstatSync(out);check(path.isAbsolute(out)&&fs.realpathSync(out)===out&&st.isDirectory()&&st.uid===process.getuid()&&(st.mode&0o7777)===0o700&&fs.readdirSync(out).length===0,'exclusive_build_directory');const commands=[];const execute=(file,args)=>{const n=commands.push({file,args});try{const stdout=run(file,args,out);save(out,'command-'+n+'.json',JSON.stringify({file,args,status:0,stdout})+'\n');return stdout;}catch(e){save(out,'command-'+n+'.json',JSON.stringify({file,args,error:e.message})+'\n');throw e;}};
 const m={version:1,status:'UNKNOWN',admission:false,qualified:false,assumptionsVerified:false,productionExecuted:false,setupEvidenceRevision:BASE,exporterHead:run('/usr/bin/git',['rev-parse','HEAD']).trim(),exporterTree:run('/usr/bin/git',['rev-parse','HEAD^{tree}']).trim(),sanitizer,complete:false,commands};
 try{
  m.sources=inventory();m.tools=Object.fromEntries(['/usr/bin/cc','/usr/bin/ld','/usr/bin/readelf','/usr/bin/git','/usr/bin/python3',process.execPath].map(p=>[p,trusted(p)]));m.runtime=runtimePins();
  const imports=execute('/usr/bin/python3',['-I','-c',"import os,sys,stat,hashlib,fcntl,resource,json; print(json.dumps(sorted(set(getattr(m,'__file__','') for m in sys.modules.values() if getattr(m,'__file__',None)))))"]);m.pythonModules=Object.fromEntries(JSON.parse(imports).map(p=>[p,trusted(p)]));
  m.versions={cc:execute('/usr/bin/cc',['--version']),ld:execute('/usr/bin/ld',['--version']),readelf:execute('/usr/bin/readelf',['--version']),node:process.version};
  const flags=[...offlineGitFlags,...sanitizer?['-fsanitize=address,undefined','-fno-omit-frame-pointer']:[], '-ffile-prefix-map='+native+'=evidence'];m.artifacts={};
  for(const [name,source] of [['reader','host-cgroup-evidence-read.c'],['fixture','host-cgroup-evidence-read.test.c']]){const file=path.join(out,name);execute('/usr/bin/cc',[...flags,path.join(native,source),'-o',file]);const bytes=fs.readFileSync(file);check(bytes.length<=1048576,'binary_bound');m.artifacts[name]={size:bytes.length,sha256:hash(bytes),executed:name==='fixture',elf:execute('/usr/bin/readelf',['-h','-l','-d',file])};if(name==='reader'&&!sanitizer)inspectELF(file,execute);}
  check(/SIMULATED read-only evidence fixture/.test(execute(path.join(out,'fixture'),[])),'fixture');
  if(!sanitizer){const entry=renderOwnerEntry(m.artifacts.reader,m.runtime);save(out,'owner-entry.txt',entry);m.entry={size:Buffer.byteLength(entry),sha256:hash(entry)};}
  for(const [p,id] of Object.entries(m.tools))check(JSON.stringify(trusted(p))===JSON.stringify(id),'tool_changed');for(const [p,id] of Object.entries(m.pythonModules))check(JSON.stringify(trusted(p))===JSON.stringify(id),'python_changed');
  check(JSON.stringify(runtimePins())===JSON.stringify(m.runtime),'runtime_changed');check(JSON.stringify(inventory())===JSON.stringify(m.sources)&&run('/usr/bin/git',['rev-parse','HEAD']).trim()===m.exporterHead,'source_changed');m.complete=true;
 }catch(e){m.failure=e.message;throw e;}finally{save(out,'build.json',JSON.stringify(m,null,2)+'\n');console.log('Retained UNKNOWN reader build: '+out+'/build.json');}return m;
}
export function prepare(){
 const out=fresh('age30-cgroup-evidence-source-');let started=false;try{check(run('/usr/bin/git',['status','--porcelain']).trim()==='','clean_source_required');check(run('/usr/bin/git',['rev-parse',BASE+'^{tree}']).trim()===BASE_TREE&&run('/usr/bin/git',['merge-base','HEAD',BASE]).trim()===BASE,'base_identity');const changed=run('/usr/bin/git',['diff','--name-only',BASE,'HEAD']).trim().split('\n');check(changed.length===5&&FILES.every(p=>changed.includes(p)),'five_file_scope');started=true;const result=buildNative(out);check(run('/usr/bin/git',['status','--porcelain']).trim()==='','source_dirty_after_build');return {out,result};}catch(e){if(!started)save(out,'build.json',JSON.stringify({status:'UNKNOWN',admission:false,qualified:false,assumptionsVerified:false,productionExecuted:false,complete:false,failure:e.message})+'\n');console.error('Retained UNKNOWN prepare: '+out);throw e;}
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{check(process.argv.length===3&&['prepare','collect'].includes(process.argv[2]),'fixed_command_required');if(process.argv[2]==='prepare')prepare();else console.log('Retained UNKNOWN collection: '+await collectInput(process.stdin));process.exitCode=2;}catch(e){console.error('UNKNOWN: '+e.message);process.exitCode=2;}
}
