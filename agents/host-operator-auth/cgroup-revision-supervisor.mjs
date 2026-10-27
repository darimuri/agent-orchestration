// Fixed owner-config service backend; never imported by an activation/bootstrap path.
import fs from 'node:fs';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { ownData, evidenceData, canonicalEvidence, parseEvidence, terminalBoundary, protectedDirectory } from './revision-evidence.mjs';
import { binding, digest, exact, identifier, hexadecimal, timestamp } from '../scripts/host-operator-protocol.mjs';
const deny=()=>{const e=Error('cgroup_supervisor_denied');e.code=e.message;e.stack=e.message;throw e;};
const unknown=()=>Object.freeze({status:'unknown'}),hash=b=>createHash('sha256').update(b).digest('hex');
const RUNTIME='fde6a4bf8d0562f7751d1a2d6cb9b417c4cfe107bbcb0aa3e9a24e125e348f48';
const worker=fileURLToPath(new URL('./supervised-revision-worker.mjs',import.meta.url));
const properties=Object.freeze({Id:'host-operator.service',LoadState:'loaded',ActiveState:'active',SubState:'running',Delegate:'yes',DelegateSubgroup:'supervisor',Type:'exec',ExitType:'main',RemainAfterExit:'no',Restart:'no',KillMode:'control-group',KillSignal:'15',FinalKillSignal:'9',SendSIGKILL:'yes',TimeoutStopUSec:'2s',NoNewPrivileges:'yes',CapabilityBoundingSet:'',AmbientCapabilities:'',UMask:'0077'});
function frozen(v){if(v&&typeof v==='object'){Object.values(v).forEach(frozen);Object.freeze(v);}return v;}
function stable(s){return [s.dev,s.ino,s.uid,s.gid,s.mode,s.nlink,s.size,s.mtimeNs,s.ctimeNs].join(':');}
function artifact(name,expected,limit,executable=false,allowRoot=false){
  hexadecimal(expected);if(typeof name!=='string'||!name.isWellFormed()||!path.isAbsolute(name)||path.normalize(name)!==name||fs.realpathSync(name)!==name||name.includes('\0'))deny();
  const s=fs.lstatSync(name,{bigint:true});if(!s.isFile()||(!allowRoot&&s.uid!==1000n)||(allowRoot&&![0n,1000n].includes(s.uid))||s.nlink!==1n||(s.mode&0o7022n)||s.size<1n||s.size>BigInt(limit)||(executable&&!(s.mode&0o100n)))deny();
  // Root-owned ancestors are accepted; final artifact must be ordinary owner UID.
  protectedDirectory(path.dirname(name),1000,false);const fd=fs.openSync(name,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  try{rehash(fd,name,expected,s);return {fd,name,expected,stat:s};}catch{fs.closeSync(fd);deny();}
}
function rehash(fd,name,expected,before){if(stable(fs.fstatSync(fd,{bigint:true}))!==stable(before))deny();const h=createHash('sha256'),b=Buffer.alloc(65536);let offset=0,n;do{n=fs.readSync(fd,b,0,b.length,offset);if(n>0){h.update(b.subarray(0,n));offset+=n;}}while(n>0&&offset<=Number(before.size));if(offset!==Number(before.size)||h.digest('hex')!==expected||stable(fs.fstatSync(fd,{bigint:true}))!==stable(before)||stable(fs.lstatSync(name,{bigint:true}))!==stable(before))deny();}
function openRoot(name){protectedDirectory(name,1000,false);const before=fs.lstatSync(name,{bigint:true}),fd=fs.openSync(name,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);if(stable(before)!==stable(fs.fstatSync(fd,{bigint:true}))){fs.closeSync(fd);deny();}return {fd,stat:before};}
function uint(n,size){const b=Buffer.alloc(size);if(size===8)b.writeBigUInt64BE(BigInt(n));else if(size===4)b.writeUInt32BE(n);else b.writeUInt16BE(n);return b;}
function string(s,max=4096){if(typeof s!=='string'||!s.isWellFormed()||s.includes('\0'))deny();const b=Buffer.from(s);if(!b.length||b.length>max)deny();return Buffer.concat([uint(b.length,2),b]);}
function frame(magic,parts){const p=Buffer.concat(parts);if(p.length>16384)deny();return Buffer.concat([Buffer.from(magic),uint(p.length,4),p]);}
class Reader{constructor(bytes){this.b=bytes;this.at=0;}bytes(n){if(!Number.isSafeInteger(n)||n<0||this.at+n>this.b.length)deny();const b=this.b.subarray(this.at,this.at+n);this.at+=n;return b;}u(n){const b=this.bytes(n);const v=n===8?Number(b.readBigUInt64BE()):n===4?b.readUInt32BE():n===2?b.readUInt16BE():b[0];if(!Number.isSafeInteger(v))deny();return v;}text(max=128){const n=this.u(2);if(!n||n>max)deny();const s=new TextDecoder('utf-8',{fatal:true}).decode(this.bytes(n));if(s.includes('\0'))deny();return s;}end(){if(this.at!==this.b.length)deny();}}
export function createCgroupRevisionSupervisor(config){
  const held=[];let poisoned=false,inFlight=false;
  try{
    const c=ownData(config);exact(c,['uid','unitName','invocationId','controlGroup','cgroupMount','controlDirectory','sourceDirectory','source','clockId','runtimePath','runtimeDigest','workerPath','workerDigest','helperPath','helperDigest','managerPath','managerDigest','managerEnvironment']);
    if(process.platform!=='linux'||c.uid!==1000||process.getuid()!==1000||process.geteuid()!==1000||process.getgid()!==1000||process.getegid()!==1000||c.unitName!=='host-operator.service'||!/^[a-f0-9]{32}$/.test(c.invocationId)||c.runtimePath!==process.execPath||fs.realpathSync('/proc/self/exe')!==c.runtimePath||process.version!=='v22.23.3'||c.runtimeDigest!==RUNTIME||c.workerPath!==worker)deny();
    c.source=frozen(binding(evidenceData(c.source)));identifier(c.clockId);c.managerEnvironment=evidenceData(c.managerEnvironment);exact(c.managerEnvironment,['XDG_RUNTIME_DIR','DBUS_SESSION_BUS_ADDRESS','LANG','TZ']);if(c.managerEnvironment.LANG!=='C.UTF-8'||c.managerEnvironment.TZ!=='UTC'||typeof c.managerEnvironment.XDG_RUNTIME_DIR!=='string'||typeof c.managerEnvironment.DBUS_SESSION_BUS_ADDRESS!=='string')deny();
    if(typeof c.controlGroup!=='string'||!c.controlGroup.startsWith('/')||path.normalize(c.controlGroup)!==c.controlGroup||c.controlGroup==='/'||c.controlGroup.includes('\0'))deny();
    protectedDirectory(c.cgroupMount,1000,false);protectedDirectory(c.controlDirectory,1000);protectedDirectory(c.sourceDirectory,1000,false);
    const root=path.join(c.cgroupMount,c.controlGroup);if(!root.startsWith(c.cgroupMount+'/'))deny();
    const separate=[root,c.controlDirectory,c.sourceDirectory];for(const a of separate)for(const b of separate)if(a!==b&&(b.startsWith(a+'/')||a===b))deny();if(new Set(separate).size!==3)deny();
    const cap=/^Cap(?:Inh|Prm|Eff|Amb):\s*([a-f0-9]+)$/gm;const caps=[...fs.readFileSync('/proc/self/status','utf8').matchAll(cap)];if(caps.length!==4||caps.some(m=>BigInt('0x'+m[1])!==0n))deny();
    const hold=(...args)=>{const a=artifact(...args);held.push(a);return a;};
    const runtime=hold(c.runtimePath,c.runtimeDigest,268435456,true),workerArtifact=hold(c.workerPath,c.workerDigest,131072),helper=hold(c.helperPath,c.helperDigest,16777216,true),manager=hold(c.managerPath,c.managerDigest,16777216,true,true);
    const rootFd=openRoot(root);held.push({fd:rootFd.fd});if(Number(fs.fstatfsSync(rootFd.fd).type)!==0x63677270)deny();
    const rootAnchor=[rootFd.stat.dev,rootFd.stat.ino].join(':');
    // Protected owner-accepted inventory is data, not a bootstrap/config loader.
    // Exact complete installed auth closure is checked against these hashes.
    const installFile=path.join(c.controlDirectory,'artifacts.json'),installStat=fs.lstatSync(installFile);if(!installStat.isFile()||installStat.uid!==1000||installStat.nlink!==1||(installStat.mode&0o7777)!==0o600||installStat.size>1048576)deny();
    const installBytes=fs.readFileSync(installFile),install=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(installBytes));exact(install,['version','issuerDigest','files']);if(install.version!==1)deny();hexadecimal(install.issuerDigest);const files=install.files;if(!files||Object.getPrototypeOf(files)!==Object.prototype||Object.keys(files).length>4096)deny();for(const value of Object.values(files))hexadecimal(value);
    function closure(){if(!fs.readFileSync(installFile).equals(installBytes))deny();const names=[];function walk(dir,prefix=''){for(const name of fs.readdirSync(dir).sort()){const rel=prefix+name,p=path.join(dir,name),s=fs.lstatSync(p);if(s.isSymbolicLink())deny();if(s.isDirectory()){if(s.mode&0o7022)deny();walk(p,rel+'/');}else if(s.isFile()){names.push(rel);if(names.length>4096||!Object.hasOwn(files,rel))deny();const a=artifact(p,files[rel],16777216);fs.closeSync(a.fd);}else deny();}}walk(path.dirname(worker));if(names.length!==Object.keys(files).length||files['supervised-revision.mjs']!==install.issuerDigest)deny();}
    function context(activeRun){
      rehash(manager.fd,manager.name,manager.expected,manager.stat);
      const args=['--user','show','host-operator.service','--no-pager',...Object.keys({...properties,MainPID:'',InvocationID:'',ControlGroup:''}).map(k=>'--property='+k)];
      const r=spawnSync(c.managerPath,args,{env:c.managerEnvironment,timeout:250,maxBuffer:8192,encoding:'utf8',shell:false});if(r.error||r.status!==0||r.signal||r.stderr)deny();
      const values=Object.create(null);for(const line of r.stdout.trimEnd().split('\n')){const at=line.indexOf('=');if(at<1)deny();const k=line.slice(0,at);if(Object.hasOwn(values,k))deny();values[k]=line.slice(at+1);}
      const expected={...properties,MainPID:String(process.pid),InvocationID:c.invocationId,ControlGroup:c.controlGroup};if(Object.keys(values).length!==Object.keys(expected).length||Object.entries(expected).some(([k,v])=>values[k]!==v))deny();
      if(fs.readFileSync('/proc/self/cgroup','utf8')!=='0::'+c.controlGroup+'/supervisor\n')deny();const s=fs.lstatSync(root,{bigint:true});if([s.dev,s.ino].join(':')!==rootAnchor||[...fs.readdirSync(root)].some(n=>fs.lstatSync(path.join(root,n)).isDirectory()&&n!=='supervisor'&&n!=='run_'+activeRun))deny();
      const capsNow=[...fs.readFileSync('/proc/self/status','utf8').matchAll(cap)];if(capsNow.length!==4||capsNow.some(m=>BigInt('0x'+m[1])!==0n))deny();
    }
    context();closure();
    function fatal(){poisoned=true;process.exit(70);deny();}
    return Object.freeze({async run(input){
      if(poisoned)return unknown();if(inFlight)return unknown();inFlight=true;let child,lock,started=false,timer;let cancelled=false;
      try{
        if(arguments.length!==1)deny();const s=evidenceData(input);exact(s,['executable','entry','input','stdoutLimitBytes','stderrLimitBytes','inputLimitBytes','env','runId','requestHash','intentDigest','workerArtifactDigest','clockId','startedAt','deadline','settlementWaitMs']);
        identifier(s.runId);identifier(s.clockId);for(const k of ['requestHash','intentDigest','workerArtifactDigest'])hexadecimal(s[k]);timestamp(s.startedAt);timestamp(s.deadline);
        if(s.executable!==c.runtimePath||s.entry!==worker||s.workerArtifactDigest!==c.workerDigest||s.clockId!==c.clockId||s.stdoutLimitBytes!==4096||s.stderrLimitBytes!==4096||s.inputLimitBytes!==8192||canonicalEvidence(s.env)!==canonicalEvidence({LANG:'C.UTF-8',TZ:'UTC'})||!Number.isSafeInteger(s.settlementWaitMs)||s.settlementWaitMs<1||s.settlementWaitMs>60000||s.deadline<=s.startedAt||s.deadline-s.startedAt>5000||typeof s.input!=='string')deny();
        const data=parseEvidence(s.input,8192);exact(data,['sourceDirectory','uid','source','runId','requestHash','intentDigest','startedAt']);if(data.sourceDirectory!==c.sourceDirectory||data.uid!==1000||digest(data.source)!==digest(c.source)||data.runId!==s.runId||data.requestHash!==s.requestHash||data.intentDigest!==s.intentDigest||data.startedAt!==s.startedAt)deny();
        const begin=performance.now(),now=Date.now();if(now<s.startedAt||now>=s.deadline)deny();context();closure();for(const a of [runtime,workerArtifact,helper])rehash(a.fd,a.name,a.expected,a.stat);
        const lockName=path.join(c.controlDirectory,'supervisor.lock');try{lock=fs.openSync(lockName,fs.constants.O_RDWR|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);}catch(e){if(e.code!=='EEXIST')throw e;lock=fs.openSync(lockName,fs.constants.O_RDWR|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);}
        const ls=fs.fstatSync(lock);if(!ls.isFile()||ls.uid!==1000||ls.nlink!==1||(ls.mode&0o7777)!==0o600)deny();
        const wait=s.settlementWaitMs-Math.ceil(performance.now()-begin);if(wait<1)deny();const q=frame('Q17A',[string(s.runId,128),Buffer.from(s.requestHash,'hex'),Buffer.from(s.intentDigest,'hex'),Buffer.from(s.workerArtifactDigest,'hex'),string(s.clockId,128),uint(s.startedAt,8),uint(s.deadline,8),uint(wait,4),string(s.input,8192),string(c.runtimePath),string(worker),...([runtime,workerArtifact].flatMap(a=>[uint(a.stat.dev,8),uint(a.stat.ino,8),uint(a.stat.size,8)]))]);
        child=spawn(c.helperPath,[],{cwd:c.sourceDirectory,env:{LANG:'C.UTF-8',TZ:'UTC'},shell:false,stdio:['pipe','pipe','pipe',rootFd.fd,runtime.fd,workerArtifact.fd,lock]});started=true;fs.closeSync(lock);lock=undefined;
        let bytes=Buffer.alloc(0),diagnostic=0,ready,terminal,bad=false,go=false,exited=false;
        const answer=await new Promise(resolve=>{
          function fail(){bad=true;cancelled=true;child.stdin.destroy();}
          child.on('error',()=>{bad=true;});child.stderr.on('data',b=>{diagnostic+=b.length;if(diagnostic>256)fail();});
          child.stdout.on('data',b=>{try{if(terminal||bytes.length+b.length>32784)deny();bytes=Buffer.concat([bytes,b]);while(bytes.length>=8){const n=bytes.readUInt32BE(4),magic=bytes.subarray(0,4).toString('ascii');if(n<1||n>16384)deny();if(bytes.length<8+n)break;const payload=bytes.subarray(8,8+n);bytes=bytes.subarray(8+n);const r=new Reader(payload);
            if(magic==='R17A'&&!ready&&!terminal){if(r.text()!==s.runId)deny();ready=r.bytes(32).toString('hex');if(r.u(8)!==Number(rootFd.stat.dev)||r.u(8)!==Number(rootFd.stat.ino))deny();r.end();context(s.runId);closure();for(const a of [runtime,workerArtifact,helper])rehash(a.fd,a.name,a.expected,a.stat);if(cancelled||Date.now()>=s.deadline||Date.now()<now||performance.now()<begin||performance.now()-begin>=s.settlementWaitMs)deny();child.stdin.write(Buffer.from([0x47]));go=true;
            }else if(magic==='T17A'&&!terminal){const status=r.u(1),reason=r.u(2),run=r.text(),boundaryId=r.bytes(32).toString('hex'),requestHash=r.bytes(32).toString('hex'),intentDigest=r.bytes(32).toString('hex'),workerArtifactDigest=r.bytes(32).toString('hex'),clockId=r.text(),startedAt=r.u(8),leaderExitedAt=r.u(8),settledAt=r.u(8),rootDev=r.u(8),rootIno=r.u(8),childDev=r.u(8),childIno=r.u(8),leaderReaped=r.u(1),noEscape=r.u(1),sealed=r.u(1),populated=r.u(1),exitRaw=r.u(4),signalRaw=r.u(2),cleanup=r.u(1);const outN=r.u(2);if(outN>4096)deny();const stdout=new TextDecoder('utf-8',{fatal:true}).decode(r.bytes(outN)),errN=r.u(2);if(errN>4096)deny();const stderr=new TextDecoder('utf-8',{fatal:true}).decode(r.bytes(errN));r.end();
              if(![0,1].includes(status)||reason>12||cleanup!==1||run!==s.runId||requestHash!==s.requestHash||intentDigest!==s.intentDigest||workerArtifactDigest!==s.workerArtifactDigest||clockId!==s.clockId||startedAt!==s.startedAt)deny();
              if(status===0){terminal={value:unknown(),code:2};continue;}if(!go||ready!==boundaryId||reason!==0||rootDev!==Number(rootFd.stat.dev)||rootIno!==Number(rootFd.stat.ino)||childDev!==rootDev||!childIno||leaderReaped!==1||noEscape!==1||sealed!==1||populated!==0||!([0,9,15].includes(signalRaw)))deny();
              const exitCode=exitRaw===0xffffffff?null:exitRaw,signal=signalRaw===0?null:signalRaw===9?'SIGKILL':'SIGTERM';const boundary=terminalBoundary({version:1,runId:s.runId,boundaryId,requestHash,intentDigest,workerArtifactDigest,clockId,startedAt,leaderExitedAt,settledAt,leaderReaped:true,noEscape:true,sealed:true,populated:0,exitCode,signal},{runId:s.runId,requestHash:s.requestHash,intentDigest:s.intentDigest,workerArtifactDigest:s.workerArtifactDigest,clockId:s.clockId,startedAt:s.startedAt});if(boundary.settledAt>Date.now()||Date.now()<now)deny();terminal={value:frozen({status:'settled',boundary,stdout,stderr}),code:0};
            }else deny();
          }}catch{fail();}});
          child.on('close',(code,signal)=>{exited=true;if(bad||signal||bytes.length||!terminal||code!==terminal.code){resolve(null);return;}resolve(terminal.value);});
          child.stdin.on('error',fail);
          timer=setTimeout(()=>{cancelled=true;child.stdin.destroy();timer=setTimeout(()=>{if(!exited)fatal();},2000);},Math.max(1,wait));
          child.stdin.write(q);
        });
        clearTimeout(timer);if(!answer)fatal();if(cancelled)return unknown();return answer;
      }catch{if(started)fatal();return unknown();}
      finally{clearTimeout(timer);if(lock!==undefined)fs.closeSync(lock);inFlight=false;}
    }});
  }catch{for(const a of held){try{fs.closeSync(a.fd);}catch{}}deny();}
}
