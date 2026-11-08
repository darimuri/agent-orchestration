// Fixed offline terminal-executable build only. No install, name registration or bus.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const sourceRoot = fileURLToPath(new URL('../job-preparation/native/', import.meta.url));
export const clientFlags = Object.freeze(['-B/usr/bin/', '-std=c17', '-D_GNU_SOURCE', '-O2', '-Wall', '-Wextra', '-Werror', '-Wconversion', '-Wshadow', '-Wformat=2', '-Wstrict-prototypes', '-Wmissing-prototypes', '-fstack-protector-strong', '-D_FORTIFY_SOURCE=2', '-fPIE', '-pie', '-Wl,-z,defs,-z,relro,-z,now,-z,noexecstack']);
const env = Object.freeze({ LANG: 'C', LC_ALL: 'C', TZ: 'UTC', SOURCE_DATE_EPOCH: '0' });
const hash = b => createHash('sha256').update(b).digest('hex');
const denied = () => { const e = Error('host_approval_client_build_blocked'); e.code = e.message; throw e; };
function command(executable, argv, cwd) {
  const r = spawnSync(executable, argv, { cwd, env, encoding: 'utf8', timeout: 60000, maxBuffer: 2097152 });
  if (r.error || r.status !== 0) denied(); return r.stdout.trim();
}
function inventory(file) {
  const resolved = fs.realpathSync(file), s = fs.lstatSync(resolved);
  if (!s.isFile() || s.nlink !== 1 || (s.mode & 0o7022) || ![0, process.getuid()].includes(s.uid)) denied();
  for (let p = path.dirname(resolved); ; p = path.dirname(p)) {
    const st = fs.lstatSync(p), temporary = p === '/tmp' && (st.mode & 0o1000) && st.uid === 0;
    if (!st.isDirectory() || st.isSymbolicLink() || ![0, process.getuid()].includes(st.uid) || (!temporary && (st.mode & 0o7022))) denied();
    if (p === path.dirname(p)) break;
  }
  return { path: resolved, digest: hash(fs.readFileSync(resolved)), size: s.size };
}
export function clientPrerequisites() {
  const fixed = ['/usr/bin/cc', '/usr/bin/pkg-config', '/usr/bin/readelf', '/usr/bin/ldd', '/usr/include/systemd/sd-bus.h'];
  return Object.freeze(fixed.filter(p => !fs.existsSync(p)));
}
export function buildHostApproval(outputDirectory) {
  try {
    if (process.platform !== 'linux' || process.getuid() === 0 || typeof outputDirectory !== 'string' || /\s/.test(outputDirectory) || fs.realpathSync(outputDirectory) !== outputDirectory || clientPrerequisites().length) denied();
    const outStat = fs.lstatSync(outputDirectory);
    if (!outStat.isDirectory() || outStat.uid !== process.getuid() || (outStat.mode & 0o7777) !== 0o700) denied();
    const compiler = inventory('/usr/bin/cc'), pkgConfig = inventory('/usr/bin/pkg-config'), readelf = inventory('/usr/bin/readelf'), ldd = inventory('/usr/bin/ldd');
    const runtime = { version: process.version, ...inventory(process.execPath) };
    const version = command('/usr/bin/pkg-config', ['--modversion', 'libsystemd'], outputDirectory);
    if (!/^\d+(?:[.\w+-]*)$/.test(version) || Number.parseInt(version, 10) < 255) denied();
    const packageFlags = command('/usr/bin/pkg-config', ['--cflags', '--libs', 'libsystemd'], outputDirectory).split(/\s+/).filter(Boolean);
    if (!packageFlags.includes('-lsystemd') || packageFlags.some(f => f !== '-lsystemd' && f !== '-pthread' && !/^-[IL]\/[A-Za-z0-9_./+-]+$/.test(f))) denied();
    for (const f of packageFlags.filter(f => /^-[IL]/.test(f))) { const dir = f.slice(2); if (fs.realpathSync(dir) !== dir || (fs.statSync(dir).mode & 0o022)) denied(); }
    const source = inventory(path.join(sourceRoot, 'host-approval.c'));
    const compilerVersion = command('/usr/bin/cc', ['--version'], outputDirectory), target = command('/usr/bin/cc', ['-dumpmachine'], outputDirectory);
    const tool = name => { const result = command('/usr/bin/cc', ['-B/usr/bin/', '-print-prog-name=' + name], outputDirectory); return inventory(result.startsWith('/') ? result : '/usr/bin/' + result); };
    const subordinate = [tool('cc1'), tool('as'), tool('ld')];
    const toolVersions = { pkgConfig: command('/usr/bin/pkg-config', ['--version'], outputDirectory), readelf: command('/usr/bin/readelf', ['--version'], outputDirectory), ldd: command('/usr/bin/ldd', ['--version'], outputDirectory), subordinate: subordinate.map(input => ({ path: input.path, version: command(input.path, ['--version'], outputDirectory) })) };
    const staging = fs.mkdtempSync(path.join(outputDirectory, '.approval-client-build-')); fs.chmodSync(staging, 0o700);
    const binary = path.join(staging, 'host-approval'), dependencies = path.join(staging, 'headers.d');
    const argv = [...clientFlags, '-MD', '-MF', dependencies, '-ffile-prefix-map=' + sourceRoot + '=native', source.path, '-o', binary, ...packageFlags];
    command('/usr/bin/cc', argv, staging);
    // Only normalize the new artifact in our private staging directory; never
    // relax protected input/runtime/ancestor checks or mutate caller umask.
    fs.chmodSync(binary, 0o755);
    const dependencyText = fs.readFileSync(dependencies, 'utf8').replace(/\\\n/g, ' '), split = dependencyText.indexOf(':');
    if (split < 0) denied();
    const headers = [...new Set(dependencyText.slice(split + 1).trim().split(/\s+/))].map(p => inventory(path.resolve(staging, p)));
    if (!headers.some(h => h.path === fs.realpathSync('/usr/include/systemd/sd-bus.h'))) denied();
    const elf = command('/usr/bin/readelf', ['-hW', '-dW', binary], staging);
    if (!/DYN/.test(elf) || !/BIND_NOW|NOW/.test(elf) || !/FLAGS_1.*PIE/.test(elf)) denied();
    const program = command('/usr/bin/readelf', ['-lW', binary], staging);
    if (!/GNU_RELRO/.test(program) || !/GNU_STACK[^\n]* RW /.test(program) || /GNU_STACK[^\n]*RWE/.test(program)) denied();
    const linked = command('/usr/bin/ldd', [binary], staging), elfInputs = [];
    for (const line of linked.split('\n')) {
      if (line.includes('not found')) denied();
      const resolved = /=>\s*(\/\S+)/.exec(line)?.[1] ?? /^\s*(\/\S+)/.exec(line)?.[1];
      if (resolved && !elfInputs.some(x => x.path === fs.realpathSync(resolved))) elfInputs.push(inventory(resolved));
    }
    if (!elfInputs.some(x => /libsystemd[.-]/.test(path.basename(x.path)))) denied();
    const runtimeElf = command('/usr/bin/readelf', ['-lW', process.execPath], staging), loader = /Requesting program interpreter:\s*([^\]]+)/.exec(runtimeElf)?.[1];
    if (!loader) denied();
    const loaderInput = inventory(loader), library = inventory(binary);
    const artifactLoader = /Requesting program interpreter:\s*([^\]]+)/.exec(program)?.[1];
    if (!artifactLoader) denied();
    const executableLoader = inventory(artifactLoader);
    const manifest = { version: 1, type: 'buzz.host-approval-client', source, headers, runtime, compiler, compilerVersion, target, subordinate, toolVersions, pkgConfig, libsystemdVersion: version, packageFlags, readelf, ldd, loader: loaderInput, executableLoader, elfInputs, argv: argv.map(v => v === binary ? 'host-approval' : v === dependencies ? 'headers.d' : v), executable: { ...library, path: 'host-approval' }, platform: process.platform, architecture: process.arch };
    for (const old of [compiler, pkgConfig, readelf, ldd, source, ...headers, ...subordinate, ...elfInputs, loaderInput, executableLoader, runtime]) if (inventory(old.path).digest !== old.digest) denied();
    const manifestPath = path.join(staging, 'host-approval.build.json'), text = JSON.stringify(manifest, null, 2) + '\n';
    fs.writeFileSync(manifestPath, text, { mode: 0o600, flag: 'wx' });
    for (const p of [binary, manifestPath]) { const fd = fs.openSync(p, 'r'); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); } }
    const artifact = path.join(outputDirectory, 'host-approval'), receipt = path.join(outputDirectory, 'host-approval.build.json');
    if (fs.existsSync(artifact) || fs.existsSync(receipt)) denied();
    fs.renameSync(binary, artifact); fs.renameSync(manifestPath, receipt);
    const fd = fs.openSync(outputDirectory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    if (hash(fs.readFileSync(artifact)) !== library.digest || fs.readFileSync(receipt, 'utf8') !== text) denied();
    // Only builder-owned compiler bookkeeping is removed on successful build.
    fs.unlinkSync(dependencies); fs.rmdirSync(staging);
    return Object.freeze({ executable: artifact, manifest: receipt, digest: library.digest });
  } catch { denied(); }
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { if (process.argv.length !== 3) denied(); console.log(JSON.stringify(buildHostApproval(process.argv[2]))); }
  catch { console.error('host_approval_client_build_blocked'); process.exitCode = 1; }
}
