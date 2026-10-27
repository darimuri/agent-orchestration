// Fixed offline build; no CC/CFLAGS/PATH fallback and no installation.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const directory=fileURLToPath(new URL('../host-operator-auth/native/',import.meta.url));
export const supervisorFlags=Object.freeze(['-std=c17','-D_GNU_SOURCE','-O2','-Wall','-Wextra','-Werror','-Wformat=2','-Wconversion','-Wshadow','-fstack-protector-strong','-D_FORTIFY_SOURCE=2','-fPIE','-pie','-Wl,-z,relro,-z,now,-z,noexecstack']);
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const denied=()=>{const e=Error('native_supervisor_build_failed');e.code=e.message;e.stack=e.message;throw e;};
const env=Object.freeze({LANG:'C',LC_ALL:'C',TZ:'UTC',SOURCE_DATE_EPOCH:'0'});
function command(file,args,cwd){const r=spawnSync(file,args,{cwd,env,encoding:'utf8',timeout:60000,maxBuffer:1048576});if(r.error||r.status!==0)denied();return r.stdout.trim();}
function inventory(file){const canonical=fs.realpathSync(file),s=fs.lstatSync(canonical);if(!s.isFile()||s.nlink!==1||(s.mode&0o7022))denied();return {path:canonical,digest:hash(fs.readFileSync(canonical)),size:s.size};}
function sync(dir){const fd=fs.openSync(dir,fs.constants.O_DIRECTORY|fs.constants.O_RDONLY);try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
export function buildHostOperatorSupervisor(outputDirectory){
  try{
    if(process.platform!=='linux'||typeof outputDirectory!=='string'||fs.realpathSync(outputDirectory)!==outputDirectory)denied();
    const s=fs.lstatSync(outputDirectory);if(!s.isDirectory()||s.uid!==process.getuid()||(s.mode&0o7777)!==0o700)denied();
    const runtime=inventory(process.execPath);if(process.version!=='v22.23.3'||runtime.digest!=='fde6a4bf8d0562f7751d1a2d6cb9b417c4cfe107bbcb0aa3e9a24e125e348f48')denied();
    const compiler=inventory('/usr/bin/cc'),version=command('/usr/bin/cc',['--version'],outputDirectory),target=command('/usr/bin/cc',['-dumpmachine'],outputDirectory);
    const linker=inventory(command('/usr/bin/cc',['-print-prog-name=ld'],outputDirectory).startsWith('/')?command('/usr/bin/cc',['-print-prog-name=ld'],outputDirectory):'/usr/bin/ld');
    const source=inventory(path.join(directory,'revision-supervisor.c')),header=inventory(path.join(directory,'revision-supervisor-protocol.h'));
    const staging=fs.mkdtempSync(path.join(outputDirectory,'.native-build-'));fs.chmodSync(staging,0o700);
    const binary=path.join(staging,'revision-supervisor'),argv=[...supervisorFlags,'-ffile-prefix-map='+directory+'=native',source.path,'-o',binary];
    command('/usr/bin/cc',argv,staging);
    const elf=command('/usr/bin/readelf',['-lW',binary],staging),dynamic=command('/usr/bin/ldd',[binary],staging),inputs=[];
    const loader=/Requesting program interpreter:\s*([^\]]+)/.exec(elf)?.[1];if(!loader)denied();inputs.push(inventory(loader));
    for(const line of dynamic.split('\n')){const resolved=/=>\s*(\/\S+)/.exec(line)?.[1]??/^\s*(\/\S+)/.exec(line)?.[1];if(resolved&&!inputs.some(x=>x.path===fs.realpathSync(resolved)))inputs.push(inventory(resolved));if(line.includes('not found'))denied();}
    const manifest={version:1,type:'host-operator.native-supervisor-build',source,header,runtime:{version:process.version,...runtime},compiler,compilerVersion:version,target,linker,argv:argv.map(x=>x===binary?'revision-supervisor':x),binary:inventory(binary),elfInputs:inputs,platform:process.platform,architecture:process.arch};manifest.binary.path='revision-supervisor';
    for(const old of [compiler,linker,source,header,...inputs])if(inventory(old.path).digest!==old.digest)denied();
    fs.chmodSync(binary,0o755);const text=JSON.stringify(manifest,null,2)+'\n',mf=path.join(staging,'revision-supervisor.build.json');fs.writeFileSync(mf,text,{mode:0o600,flag:'wx'});
    for(const f of [binary,mf]){const fd=fs.openSync(f,'r');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
    const out=path.join(outputDirectory,'revision-supervisor'),outManifest=path.join(outputDirectory,'revision-supervisor.build.json');if(fs.existsSync(out)||fs.existsSync(outManifest))denied();
    fs.renameSync(binary,out);fs.renameSync(mf,outManifest);sync(outputDirectory);
    if(hash(fs.readFileSync(out))!==manifest.binary.digest||fs.readFileSync(outManifest,'utf8')!==text)denied();fs.rmdirSync(staging);return Object.freeze({binary:out,manifest:outManifest,digest:manifest.binary.digest});
  }catch{denied();}
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{if(process.argv.length!==3)denied();const r=buildHostOperatorSupervisor(process.argv[2]);console.log(JSON.stringify(r));}catch{console.error('native_supervisor_build_failed');process.exitCode=1;}
}
