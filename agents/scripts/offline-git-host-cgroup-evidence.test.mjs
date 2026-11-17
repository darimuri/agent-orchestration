// Mandatory source-only evidence-reader tests. No privileged executable is run.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { Readable } from 'node:stream';
import { BASE,BASE_TREE,FILES,BOUND,OBJECTS,hash,run,strictJSON,decode,collectBytes,collectInput,buildNative,runtimePins,verifierSource,renderOwnerEntry } from './offline-git-host-cgroup-evidence.mjs';
const root=fileURLToPath(new URL('../../',import.meta.url));
const read=p=>fs.readFileSync(path.join(root,p),'utf8');
const git=args=>run('/usr/bin/git',args,root).trim();
const meta=()=>({dev:'1',ino:'2',mount:'3',mode:0o600,uid:0,gid:0,nlink:'1',size:'2',mtimeSec:'1',mtimeNsec:0,ctimeSec:'1',ctimeNsec:0});
function snapshot(){return {version:1,status:'UNKNOWN',admission:false,qualified:false,assumptionsVerified:false,collectionComplete:true,atomic:false,cgroupDurability:'RUNTIME_ONLY',error:'none',errorErrno:0,objects:OBJECTS.map(name=>({name,status:'ok',size:2,before:meta(),after:meta(),base64:Buffer.from([255,0]).toString('base64')}))};}
const bytes=m=>Buffer.from(JSON.stringify(m)+'\n');
function refused(m){assert.throws(()=>decode(bytes(m)));}
test('exact frozen five-file source allowance, all existing setup/observer/build bytes unchanged',()=>{
 assert.equal(git(['rev-parse',BASE+'^{tree}']),BASE_TREE);
 const changes=git(['diff','--name-only',BASE]).split('\n').filter(Boolean);assert(changes.every(p=>FILES.includes(p)),changes.join('\n'));
 const entries=git(['ls-tree','-r','--name-only',BASE]).split('\n');
 for(const p of entries.filter(p=>p!==FILES[4]))assert.deepEqual(fs.readFileSync(path.join(root,p)),spawnSync('/usr/bin/git',['show',BASE+':'+p],{cwd:root,maxBuffer:8388608}).stdout,p);
 for(const p of FILES.slice(0,4))assert(!entries.includes(p),p);
});
test('fixed read-only native scope and independent literal oracle',()=>{
 const s=read(FILES[0]),fixture=read(FILES[1]);
 for(const call of ['execve','execv','system','popen','fork','clone','socket','connect','mount','unlink','rmdir','mkdir','mkdirat','fchmod','chmod','chown','fchown','fsync','fallocate','utimensat','setuid','setgid','getenv'])assert(!new RegExp('\\b'+call+'\\s*\\(').test(s),call);
 for(const token of ['RESOLVE_BENEATH','RESOLVE_NO_SYMLINKS','RESOLVE_NO_MAGICLINKS','RESOLVE_NO_XDEV','STATX_MNT_ID','O_NOATIME','S_ISFIFO','st.st_uid!=0','OUTPUT_BOUND 524288U','IO_DENTS(s->nodes[parent].fd','IO_WRITE(1,','s.complete=snapshot','No retry'])assert(s.includes(token),token);
 assert(!s.includes('"cgroup.threads"'));assert(!s.includes('"cgroup.kill"'));
 assert.equal((s.match(/IO_WRITE\(/g)??[]).length,1);
 for(const token of ['const char golden[]','at<=boundaries','missing=p','EPIPE','EINTR','getuid()!=0','plus<2U','!complete()'])assert(fixture.includes(token),token);
 const cli=read(FILES[2]);assert(!cli.includes("from './offline-git-host-cgroup-setup.mjs'"));assert(!cli.includes("'-o',observer"));assert(!cli.includes('ldd'));
});
test('strict JSON: duplicate decoded keys, grammar, trailing and depth refusal',()=>{
 for(const s of ['{"a":1,"a":2}','{"a":1,"\\u0061":2}','{"a":{"x":0,"x":1}}','{}{}','{} garbage','{"a":01}','{"a":true,}','[1,]','[','"unterminated','"bad\\q"',' '.repeat(BOUND+1),'['.repeat(18)+'0'+']'.repeat(18)])assert.throws(()=>strictJSON(s),s.slice(0,30));
 assert.equal(strictJSON('{"a":[true,false,null,-2.5e2,"x\\n"]}').a[3],-250);
});
test('collector preserves exact arbitrary bytes, decoded hashes and malformed receipt observations',()=>{
 const raw=bytes(snapshot()),value=decode(raw);assert.equal(value.decoded.length,12);
 for(const o of value.decoded){assert.deepEqual(o.bytes,Buffer.from([255,0]));assert.equal(o.sha256,hash(Buffer.from([255,0])));}
 const out=collectBytes(raw),m=JSON.parse(fs.readFileSync(path.join(out,'collection.json')));
 assert.deepEqual(fs.readFileSync(path.join(out,'raw.json')),raw);assert.equal(m.rawSha256,hash(raw));assert.equal(m.collectionComplete,true);assert.equal(m.complete,true);assert.equal(m.qualified,false);assert.equal(m.objects[0].receiptState,'malformed_or_partial');
 assert.equal(fs.statSync(out).mode&0o7777,0o700);
 for(const name of fs.readdirSync(out))assert.equal(fs.statSync(path.join(out,name)).mode&0o7777,0o600);
 for(let i=0;i<12;i++)assert.deepEqual(fs.readFileSync(path.join(out,m.objects[i].file)),Buffer.from([255,0]));
 assert.throws(()=>fs.writeFileSync(path.join(out,'raw.json'),'overwrite',{flag:'wx'}));
 const other=collectBytes(raw);assert.notEqual(out,other);assert.deepEqual(fs.readFileSync(path.join(out,'raw.json')),raw);
});
test('partial/missing/empty receipts remain evidence, collection does not certify claims',()=>{
 const m=snapshot();m.collectionComplete=false;m.error='read';m.errorErrno=5;m.objects[0]={name:'start',status:'partial',size:2,before:meta(),after:null,base64:'ewA='};m.objects[1]={name:'inventory',status:'missing',size:0,before:null,after:null,base64:''};m.objects[2]={name:'result',status:'ok',size:0,before:meta(),after:meta(),base64:''};
 assert.equal(decode(bytes(m)).decoded[2].receiptState,'empty');
 const out=collectBytes(bytes(m)),result=JSON.parse(fs.readFileSync(path.join(out,'collection.json')));assert.equal(result.collectionComplete,false);assert.equal(result.complete,true);assert.equal(result.readerError,'read');assert(!Object.hasOwn(result,'setupComplete'));
 const fake=snapshot();fake.objects[2].base64=Buffer.from('{"setupComplete":true,"qualified":true}').toString('base64');fake.objects[2].size=Buffer.from(fake.objects[2].base64,'base64').length;
 const collected=JSON.parse(fs.readFileSync(path.join(collectBytes(bytes(fake)),'collection.json')));assert.equal(collected.qualified,false);assert(!Object.hasOwn(collected,'setupComplete'));
});
test('schema/base64/bounds/flags/metadata rejection and raw incomplete retention',()=>{
 for(const mutate of [m=>m.version=2,m=>m.qualified=true,m=>m.admission=true,m=>m.assumptionsVerified=true,m=>m.atomic=true,m=>m.status='PASS',m=>m.cgroupDurability='DURABLE',m=>m.setupComplete=true,m=>m.objects.pop(),m=>m.objects[1].name='start',m=>m.objects[0].status='other',m=>m.objects[0].size=-1,m=>m.objects[0].size=16385,m=>m.objects[0].base64='/wA',m=>m.objects[0].base64='/wB=',m=>m.objects[0].before.uid=-1,m=>m.objects[0].after=null,m=>m.objects[0].before.mount=3,m=>m.objects[0].before.extra=0,m=>m.objects[0].status='missing',m=>m.objects[0].status='unread',m=>m.error='read',m=>m.errorErrno=5,m=>m.objects[0].status='unexpected_entries']){const m=snapshot();mutate(m);refused(m);}
 assert.throws(()=>decode(Buffer.from([255])));assert.throws(()=>decode(Buffer.alloc(BOUND+1)));
 for(const raw of [Buffer.from('{'),Buffer.from('{} trailing'),Buffer.from('{"a":1,"a":2}'),Buffer.alloc(0)]){const out=collectBytes(raw),m=JSON.parse(fs.readFileSync(path.join(out,'collection.json')));assert.equal(m.complete,false);assert.equal(m.collectionComplete,false);assert.deepEqual(fs.readFileSync(path.join(out,'raw.json')),raw);}
});
test('each decoded bound and +1 including overflow byte in incomplete object',()=>{
 for(let index=0;index<12;index++){
  const limit=index<3?16384:index===3?262144:4096;const m=snapshot(),b=Buffer.alloc(limit);Object.assign(m.objects[index],{size:b.length,base64:b.toString('base64')});assert.equal(decode(bytes(m)).decoded[index].size,limit);
  const large=Buffer.alloc(limit+1);Object.assign(m.objects[index],{size:large.length,base64:large.toString('base64')});refused(m);
  m.collectionComplete=false;m.error='read_bound';m.objects[index].status='partial';m.objects[index].after=null;assert.equal(decode(bytes(m)).decoded[index].size,limit+1);
 }
});
test('stream encoded bound +1 and interrupted input are retained incomplete without draining',async()=>{
 const out=await collectInput(Readable.from([Buffer.alloc(BOUND),Buffer.alloc(20)]));const m=JSON.parse(fs.readFileSync(path.join(out,'collection.json')));assert.equal(m.retentionComplete,false);assert.equal(m.rawSize,BOUND+1);assert.equal(m.collectionComplete,false);
 async function* partial(){yield Buffer.from('{');throw Error('interrupted');}
 const interrupted=await collectInput(Readable.from(partial())),n=JSON.parse(fs.readFileSync(path.join(interrupted,'collection.json')));assert.equal(n.retentionComplete,false);assert.equal(n.failure,'input_incomplete');
});
const payload={size:4,sha256:hash('SAFE')};
const pins=[{path:'/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2',size:1,sha256:'1'.repeat(64)},{path:'/usr/lib/x86_64-linux-gnu/libc.so.6',size:1,sha256:'2'.repeat(64)}];
test('reader-specific inert literal verifier/quoting and no caller execution interface',()=>{
 const code=verifierSource(payload,pins),entry=renderOwnerEntry(payload,pins);assert(entry.startsWith('INERT REVIEW TEXT'));
 assert(code.includes("os.memfd_create('age30-evidence-read-v1'"));assert(code.endsWith("os.execve(fd, ['age30-evidence-read-v1'], {})\n"));assert(!code.includes('age30-setup-v1'));
 assert(entry.includes(code.replaceAll("'","'\\''")));
 for(const token of ['F_SEAL_WRITE','F_SEAL_GROW','F_SEAL_SHRINK','F_SEAL_SEAL','identity(s)','sys.flags.isolated','os.closerange'])assert(code.includes(token));
 for(const token of ['sys.argv','subprocess','os.environ[','/tmp/','manifest','shell=True','pickle','eval('])assert(!code.includes(token),token);
 for(const bad of [{size:0,sha256:hash('')},{size:1048577,sha256:hash('x')},{size:1,sha256:"';bad"}])assert.throws(()=>verifierSource(bad,pins));
 assert.throws(()=>verifierSource(payload,[{...pins[0],path:"/tmp/';bad"},pins[1]]));assert.throws(()=>verifierSource(payload,[{...pins[0],sha256:'bad'},pins[1]]));
});
for(const sanitizer of [false,true])test('MANDATORY '+(sanitizer?'ASan+UBSan':'hardened')+' production compile / NONROOT simulated reader fixture',()=>{
 assert(process.getuid()!==0&&process.geteuid()!==0);const out=fs.mkdtempSync('/tmp/age30-evidence-native-test-');fs.chmodSync(out,0o700);const m=buildNative(out,sanitizer);assert(m.complete);assert.equal(m.productionExecuted,false);assert(m.artifacts.fixture.executed);assert.equal(m.artifacts.reader.executed,false);
});
test('MANDATORY isolated NONROOT harmless verifier: pins/bounds/metadata/seals/runtime/path replacement',()=>{
 assert(process.getuid()!==0);const out=fs.mkdtempSync('/tmp/age30-evidence-python-test-');fs.chmodSync(out,0o700);const code=verifierSource(payload,runtimePins());
 const guard='require(os.getuid() == 0 and os.geteuid() == 0 and os.getgid() == 0 and os.getegid() == 0)',exec="os.execve(fd, ['age30-evidence-read-v1'], {})";assert(code.includes(guard)&&code.endsWith(exec+'\n'));
 const form=code.replace(guard,'require(os.getuid() != 0 and os.geteuid() != 0)').replace(exec,"require(os.read(fd, EXPECTED_SIZE + 1) == b'SAFE'); print('SEALED_FIXED_DATA')");
 function execute(data,script=form){const file=path.join(out,'input-'+hash(data)+'-'+hash(script));if(!fs.existsSync(file))fs.writeFileSync(file,data,{flag:'wx',mode:0o600});const fd=fs.openSync(file,'r');try{const r=spawnSync('/usr/bin/python3',['-I','-c',script],{cwd:out,env:{LANG:'C',LC_ALL:'C',TZ:'UTC'},stdio:[fd,'pipe','pipe'],encoding:'utf8',timeout:10000});assert.equal(r.error,undefined,'mandatory Python '+r.error?.code);return r;}finally{fs.closeSync(fd);}}
 assert.equal(execute('SAFE').status,0);for(const b of ['SAF','SAFE!','EVIL',''])assert.notEqual(execute(b).status,0);
 assert.notEqual(execute('SAFE',form.replace('os.MFD_ALLOW_SEALING','0')).status,0);
 const actual=runtimePins();assert.notEqual(execute('SAFE',form.replace(actual[0].sha256,'0'.repeat(64))).status,0);
 fs.writeFileSync(path.join(out,'mutable'),'SAFE',{flag:'wx',mode:0o600});const fd=fs.openSync(path.join(out,'mutable'),'r');try{const mutate=form.replace('data = os.read(0, EXPECTED_SIZE + 1)',"os.utime('mutable', None)\ndata = os.read(0, EXPECTED_SIZE + 1)");const r=spawnSync('/usr/bin/python3',['-I','-c',mutate],{cwd:out,env:{LANG:'C'},stdio:[fd,'pipe','pipe'],timeout:10000});assert.equal(r.error,undefined);assert.notEqual(r.status,0);}finally{fs.closeSync(fd);}
 fs.writeFileSync(path.join(out,'held'),'SAFE',{flag:'wx',mode:0o600});fs.writeFileSync(path.join(out,'replacement'),'EVIL',{flag:'wx',mode:0o600});const held=fs.openSync(path.join(out,'held'),'r');try{const replace=form.replace('os.lseek(fd, 0, os.SEEK_SET)\n# No compiler',"os.rename('replacement', 'held')\nos.lseek(fd, 0, os.SEEK_SET)\n# No compiler");const r=spawnSync('/usr/bin/python3',['-I','-c',replace],{cwd:out,env:{LANG:'C'},stdio:[held,'pipe','pipe'],timeout:10000});assert.equal(r.error,undefined);assert.equal(r.status,0);}finally{fs.closeSync(held);}
});

test('fixed collect CLI has no path/pin/command input and never launches reader',()=>{
 const script=path.join(root,FILES[2]),raw=bytes(snapshot());
 const r=spawnSync(process.execPath,[script,'collect'],{input:raw,encoding:'utf8',env:{LANG:'C',LC_ALL:'C',TZ:'UTC'},timeout:10000});assert.equal(r.error,undefined);assert.equal(r.status,2,r.stderr);
 const out=/Retained UNKNOWN collection: (\/tmp\/age30-cgroup-evidence-collect-[A-Za-z0-9]+)/.exec(r.stdout)?.[1];assert(out);assert.deepEqual(fs.readFileSync(path.join(out,'raw.json')),raw);assert.equal(JSON.parse(fs.readFileSync(path.join(out,'collection.json'))).qualified,false);
 for(const args of [[],['collect','/etc/passwd'],['prepare','--pin','arbitrary'],['reader'],['collect;bad']]){const denied=spawnSync(process.execPath,[script,...args],{input:raw,encoding:'utf8',env:{LANG:'C'},timeout:10000});assert.equal(denied.error,undefined);assert.equal(denied.status,2);assert.match(denied.stderr,/fixed_command_required/);assert(!denied.stdout.includes('Retained'));}
});
