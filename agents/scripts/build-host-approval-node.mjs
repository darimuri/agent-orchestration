// Offline, explicit build. Import has no compiler, bus or filesystem effects.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const root = fileURLToPath(new URL('../job-preparation/native/', import.meta.url));
const fixedEnv = Object.freeze({ LANG: 'C', LC_ALL: 'C', TZ: 'UTC', SOURCE_DATE_EPOCH: '0' });
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const blocked = () => { const e = Error('host_approval_node_build_blocked'); e.code = e.message; throw e; };
export const nodeFlags = Object.freeze(['-B/usr/bin/', '-std=c17', '-D_GNU_SOURCE', '-DNAPI_VERSION=8', '-O2', '-Wall', '-Wextra', '-Werror', '-Wconversion', '-Wshadow', '-Wformat=2', '-Wstrict-prototypes', '-Wmissing-prototypes', '-fstack-protector-strong', '-D_FORTIFY_SOURCE=2', '-fPIC', '-shared', '-Wl,-z,relro,-z,now,-z,noexecstack']);
// This exact set is the only Node-API dynamic-import surface. Other imports
// must resolve from inventoried ELF dependencies; weak CRT imports are explicit.
export const nodeImports = Object.freeze([
'napi_new_instance','napi_set_named_property','napi_add_env_cleanup_hook','napi_call_function','napi_check_object_type_tag','napi_create_error','napi_create_function','napi_create_int32','napi_create_object','napi_create_promise','napi_create_reference','napi_create_string_utf8','napi_define_properties','napi_delete_reference','napi_get_all_property_names','napi_get_array_length','napi_get_boolean','napi_get_cb_info','napi_get_global','napi_get_instance_data','napi_get_named_property','napi_get_reference_value','napi_get_undefined','napi_get_value_bool','napi_get_value_double','napi_get_value_string_utf8','napi_instanceof','napi_is_exception_pending','napi_object_freeze','napi_reject_deferred','napi_resolve_deferred','napi_set_instance_data','napi_throw_error','napi_type_tag_object','napi_typeof','napi_unwrap','napi_wrap',
]);
const headersDirectory = () => path.resolve(path.dirname(process.execPath), '../include/node');
export function nodePrerequisites() {
  return Object.freeze(['/usr/bin/cc','/usr/bin/pkg-config','/usr/bin/readelf','/usr/bin/ldd','/usr/include/systemd/sd-bus.h','/usr/include/systemd/sd-login.h',path.join(headersDirectory(),'node_api.h'),path.join(headersDirectory(),'node_version.h')].filter(p => !fs.existsSync(p)));
}
function inventory(file) {
  const resolved = fs.realpathSync(file), s = fs.lstatSync(resolved);
  if (!s.isFile() || s.nlink !== 1 || ![0, process.getuid()].includes(s.uid) || (s.mode & 0o7022)) blocked();
  for (let p = path.dirname(resolved); ; p = path.dirname(p)) {
    const stat = fs.lstatSync(p), scratch = p === '/tmp' && stat.uid === 0 && (stat.mode & 0o1000);
    if (!stat.isDirectory() || stat.isSymbolicLink() || ![0, process.getuid()].includes(stat.uid) || (!scratch && (stat.mode & 0o7022))) blocked();
    if (p === path.dirname(p)) break;
  }
  return { path: resolved, digest: hash(fs.readFileSync(resolved)), size: s.size };
}
function run(bin, args, cwd) {
  const r = spawnSync(bin, args, { cwd, env: fixedEnv, encoding: 'utf8', timeout: 60000, maxBuffer: 16777216 });
  if (r.error || r.status !== 0) blocked(); return r.stdout;
}
function symbols(file, cwd) {
  return run('/usr/bin/readelf', ['--dyn-syms','--wide',file], cwd).split('\n').flatMap(line => {
    const m = /^\s*\d+:\s+\S+\s+\d+\s+\S+\s+(\S+)\s+\S+\s+(\S+)\s+(\S+)/.exec(line);
    return m ? [{ binding: m[1], index: m[2], name: m[3].split('@')[0] }] : [];
  });
}
export function buildHostApprovalNode(directory) {
  try {
    if (process.platform !== 'linux' || process.getuid() === 0 || nodePrerequisites().length || typeof directory !== 'string' || /\s/.test(directory) || fs.realpathSync(directory) !== directory) blocked();
    const s = fs.lstatSync(directory);
    if (!s.isDirectory() || s.uid !== process.getuid() || (s.mode & 0o7777) !== 0o700) blocked();
    const inputs = new Map(), measure = p => { const record = inventory(p); inputs.set(record.path, record); return record; };
    const runtime = { ...measure(process.execPath), version: process.version };
    const compiler = measure('/usr/bin/cc'), pkgConfig = measure('/usr/bin/pkg-config'), readelf = measure('/usr/bin/readelf'), ldd = measure('/usr/bin/ldd');
    const headerRoot = headersDirectory(), nodeVersion = fs.readFileSync(measure(path.join(headerRoot,'node_version.h')).path,'utf8');
    for (const [key, value] of ['MAJOR','MINOR','PATCH'].map((key,i)=>[key,Number(process.versions.node.split('.')[i])])) {
      const m = new RegExp('^#define NODE_' + key + '_VERSION\\s+(\\d+)', 'm').exec(nodeVersion); if (!m || Number(m[1]) !== value) blocked();
    }
    const version = run('/usr/bin/pkg-config',['--modversion','libsystemd'],directory).trim();
    if (!/^\d+[\w.+-]*$/.test(version) || Number.parseInt(version,10) < 255) blocked();
    const packageFlags = run('/usr/bin/pkg-config',['--cflags','--libs','libsystemd'],directory).trim().split(/\s+/);
    if (!packageFlags.includes('-lsystemd') || packageFlags.some(f => !['-lsystemd','-pthread'].includes(f) && !/^-[IL]\/[A-Za-z0-9_./+-]+$/.test(f))) blocked();
    for (const f of packageFlags.filter(f=>/^-[IL]/.test(f))) if (fs.realpathSync(f.slice(2)) !== f.slice(2) || (fs.statSync(f.slice(2)).mode & 0o022)) blocked();
    const compilerVersion = run('/usr/bin/cc',['--version'],directory), target = run('/usr/bin/cc',['-dumpmachine'],directory).trim();
    const subordinate = ['cc1','as','ld'].map(name => {
      const p = run('/usr/bin/cc',['-B/usr/bin/','-print-prog-name='+name],directory).trim();
      const tool = measure(p.startsWith('/') ? p : '/usr/bin/'+p); return { ...tool, version: run(tool.path,['--version'],directory) };
    });
    const sources = ['host-approval-node.c','host-approval-dbus.c'].map(p=>measure(path.join(root,p)).path); measure(path.join(root,'host-approval-dbus.h'));
    const staging = fs.mkdtempSync(path.join(directory,'.approval-node-')); fs.chmodSync(staging,0o700);
    const objects = [], headerInputs = new Set(), argvs = [];
    for (const [i, source] of sources.entries()) {
      const object = path.join(staging,i+'.o'), deps = path.join(staging,i+'.d');
      const argv = [...nodeFlags.filter(f=>f!=='-shared' && !f.startsWith('-Wl,')),'-I'+headerRoot,'-MD','-MF',deps,'-c',source,'-o',object,...packageFlags.filter(f=>f.startsWith('-I')||f==='-pthread')];
      run('/usr/bin/cc',argv,staging); argvs.push(argv); objects.push(object);
      const dependency = fs.readFileSync(deps,'utf8').replace(/\\\n/g,' '); const split = dependency.indexOf(':'); if (split<0) blocked();
      for (const file of dependency.slice(split+1).trim().split(/\s+/)) headerInputs.add(path.resolve(staging,file));
    }
    for (const p of headerInputs) measure(p);
    if (![...headerInputs].some(p=>p.endsWith('/node_api.h')) || ![...headerInputs].some(p=>p.endsWith('/systemd/sd-bus.h'))) blocked();
    const binary = path.join(staging,'host-approval.node');
    const link = [...nodeFlags,...objects,'-o',binary,...packageFlags]; run('/usr/bin/cc',link,staging); argvs.push(link); fs.chmodSync(binary,0o755);
    const elf = run('/usr/bin/readelf',['-hW','-lW','-dW',binary],staging);
    if (!/DYN/.test(elf)||!/GNU_RELRO/.test(elf)||!/BIND_NOW|NOW/.test(elf)||!/GNU_STACK[^\n]* RW /.test(elf)||/GNU_STACK[^\n]*RWE/.test(elf)) blocked();
    const elfInputs = [];
    for (const file of [binary,process.execPath]) for (const line of run('/usr/bin/ldd',[file],staging).split('\n')) {
      if (line.includes('not found')) blocked(); const p = /=>\s*(\/\S+)/.exec(line)?.[1] ?? /^\s*(\/\S+)/.exec(line)?.[1];
      if (p) { const record = measure(p); if (!elfInputs.some(x=>x.path===record.path)) elfInputs.push(record); }
    }
    const runtimeElf = run('/usr/bin/readelf',['-lW',process.execPath],staging), loader = /Requesting program interpreter:\s*([^\]]+)/.exec(runtimeElf)?.[1]; if (!loader) blocked(); measure(loader);
    const exports = new Set([runtime.path,...elfInputs.map(x=>x.path)].flatMap(p=>symbols(p,staging).filter(x=>x.index!=='UND').map(x=>x.name)));
    const imports = symbols(binary,staging).filter(x=>x.index==='UND');
    for (const symbol of imports) {
      if (symbol.name.startsWith('napi_') ? !nodeImports.includes(symbol.name)||!exports.has(symbol.name) :
          !exports.has(symbol.name) && !(symbol.binding === 'WEAK' && ['__gmon_start__','_ITM_deregisterTMCloneTable','_ITM_registerTMCloneTable'].includes(symbol.name))) blocked();
    }
    if (symbols(binary,staging).some(x=>/ha_test_|fixture/.test(x.name))) blocked();
    // Actual load is mandatory, but construction is not: no system bus opened.
    run(process.execPath,['--input-type=module','-e',"import{createRequire}from'node:module';const n=createRequire(import.meta.url)(process.argv[1]);if(typeof n.createServer!=='function'||Reflect.ownKeys(n).length!==1)process.exit(1)",binary],staging);
    for (const old of inputs.values()) if (inventory(old.path).digest !== old.digest) blocked();
    const artifact = { path:'host-approval.node',digest:hash(fs.readFileSync(binary)) };
    const manifest = { version:1,type:'buzz.host-approval-node',test:false,napi:8,abi:process.versions.modules,platform:process.platform,architecture:process.arch,runtime,compiler,compilerVersion,target,subordinate,pkgConfig,readelf,ldd,libsystemdVersion:version,packageFlags,headerRoot,inputs:[...inputs.values()],elfInputs,imports:imports.map(x=>x.name).sort(),argv:argvs.flat(),artifact };
    const manifestFile = path.join(staging,'host-approval-node.build.json');fs.writeFileSync(manifestFile,JSON.stringify(manifest,null,2)+'\n',{mode:0o600,flag:'wx'});
    for (const p of [binary,manifestFile]) { const fd=fs.openSync(p,'r');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);} }
    const addon=path.join(directory,'host-approval.node'),receipt=path.join(directory,'host-approval-node.build.json');if(fs.existsSync(addon)||fs.existsSync(receipt))blocked();
    fs.renameSync(binary,addon);fs.renameSync(manifestFile,receipt);const fd=fs.openSync(directory,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY);try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
    if(hash(fs.readFileSync(addon))!==artifact.digest)blocked();
    for(const file of fs.readdirSync(staging))fs.unlinkSync(path.join(staging,file));fs.rmdirSync(staging);
    return Object.freeze({path:addon,digest:artifact.digest,manifestPath:receipt,manifestDigest:hash(fs.readFileSync(receipt))});
  } catch { blocked(); }
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  try { if(process.argv.length!==3)blocked();console.log(JSON.stringify(buildHostApprovalNode(process.argv[2]))); }
  catch { console.error('host_approval_node_build_blocked');process.exitCode=1; }
}
