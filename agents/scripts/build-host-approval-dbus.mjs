// Fixed offline shared-library build only. No install, name registration or bus.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const sourceRoot = fileURLToPath(new URL('../job-preparation/native/', import.meta.url));
export const approvalFlags = Object.freeze(['-B/usr/bin/', '-std=c17', '-D_GNU_SOURCE', '-O2', '-Wall', '-Wextra', '-Werror', '-Wconversion', '-Wshadow', '-Wformat=2', '-Wstrict-prototypes', '-Wmissing-prototypes', '-fstack-protector-strong', '-D_FORTIFY_SOURCE=2', '-fPIC', '-shared', '-Wl,-z,defs,-z,relro,-z,now,-z,noexecstack']);
const env = Object.freeze({ LANG: 'C', LC_ALL: 'C', TZ: 'UTC', SOURCE_DATE_EPOCH: '0' });
const hash = b => createHash('sha256').update(b).digest('hex');
const denied = () => { const e = Error('host_approval_native_build_blocked'); e.code = e.message; throw e; };
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
export function approvalPrerequisites() {
  const fixed = ['/usr/bin/cc', '/usr/bin/pkg-config', '/usr/bin/readelf', '/usr/bin/ldd', '/usr/include/systemd/sd-bus.h', '/usr/include/systemd/sd-login.h'];
  return Object.freeze(fixed.filter(p => !fs.existsSync(p)));
}
export function buildHostApprovalDbus(outputDirectory) {
  try {
    if (process.platform !== 'linux' || process.getuid() === 0 || typeof outputDirectory !== 'string' || /\s/.test(outputDirectory) || fs.realpathSync(outputDirectory) !== outputDirectory || approvalPrerequisites().length) denied();
    const outStat = fs.lstatSync(outputDirectory);
    if (!outStat.isDirectory() || outStat.uid !== process.getuid() || (outStat.mode & 0o7777) !== 0o700) denied();
    const compiler = inventory('/usr/bin/cc'), pkgConfig = inventory('/usr/bin/pkg-config'), readelf = inventory('/usr/bin/readelf'), ldd = inventory('/usr/bin/ldd');
    const runtime = { version: process.version, ...inventory(process.execPath) };
    const version = command('/usr/bin/pkg-config', ['--modversion', 'libsystemd'], outputDirectory);
    if (!/^\d+(?:[.\w+-]*)$/.test(version) || Number.parseInt(version, 10) < 255) denied();
    const packageFlags = command('/usr/bin/pkg-config', ['--cflags', '--libs', 'libsystemd'], outputDirectory).split(/\s+/).filter(Boolean);
    if (!packageFlags.includes('-lsystemd') || packageFlags.some(f => f !== '-lsystemd' && f !== '-pthread' && !/^-[IL]\/[A-Za-z0-9_./+-]+$/.test(f))) denied();
    for (const f of packageFlags.filter(f => /^-[IL]/.test(f))) { const dir = f.slice(2); if (fs.realpathSync(dir) !== dir || (fs.statSync(dir).mode & 0o022)) denied(); }
    const source = inventory(path.join(sourceRoot, 'host-approval-dbus.c')), header = inventory(path.join(sourceRoot, 'host-approval-dbus.h'));
    const compilerVersion = command('/usr/bin/cc', ['--version'], outputDirectory), target = command('/usr/bin/cc', ['-dumpmachine'], outputDirectory);
    const tool = name => { const result = command('/usr/bin/cc', ['-B/usr/bin/', '-print-prog-name=' + name], outputDirectory); return inventory(result.startsWith('/') ? result : '/usr/bin/' + result); };
    const subordinate = [tool('cc1'), tool('as'), tool('ld')];
    const staging = fs.mkdtempSync(path.join(outputDirectory, '.approval-build-')); fs.chmodSync(staging, 0o700);
    const binary = path.join(staging, 'libhost-approval-dbus.so'), dependencies = path.join(staging, 'headers.d');
    const argv = [...approvalFlags, '-MD', '-MF', dependencies, '-ffile-prefix-map=' + sourceRoot + '=native', source.path, '-o', binary, ...packageFlags];
    command('/usr/bin/cc', argv, staging);
    const dependencyText = fs.readFileSync(dependencies, 'utf8').replace(/\\\n/g, ' '), split = dependencyText.indexOf(':');
    if (split < 0) denied();
    const headers = [...new Set(dependencyText.slice(split + 1).trim().split(/\s+/))].map(p => inventory(path.resolve(staging, p)));
    if (!headers.some(h => h.path === fs.realpathSync('/usr/include/systemd/sd-bus.h')) || !headers.some(h => h.path === fs.realpathSync('/usr/include/systemd/sd-login.h'))) denied();
    const elf = command('/usr/bin/readelf', ['-hW', '-dW', binary], staging);
    if (!/DYN/.test(elf) || !/BIND_NOW|NOW/.test(elf)) denied();
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
    const manifest = { version: 1, type: 'buzz.host-approval-dbus-library', source, header, headers, runtime, compiler, compilerVersion, target, subordinate, pkgConfig, libsystemdVersion: version, packageFlags, readelf, ldd, loader: loaderInput, elfInputs, argv: argv.map(v => v === binary ? 'libhost-approval-dbus.so' : v === dependencies ? 'headers.d' : v), library: { ...library, path: 'libhost-approval-dbus.so' }, platform: process.platform, architecture: process.arch };
    for (const old of [compiler, pkgConfig, readelf, ldd, source, header, ...headers, ...subordinate, ...elfInputs, loaderInput, runtime]) if (inventory(old.path).digest !== old.digest) denied();
    const manifestPath = path.join(staging, 'host-approval-dbus.build.json'), text = JSON.stringify(manifest, null, 2) + '\n';
    fs.writeFileSync(manifestPath, text, { mode: 0o600, flag: 'wx' }); fs.chmodSync(binary, 0o755);
    for (const p of [binary, manifestPath]) { const fd = fs.openSync(p, 'r'); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); } }
    const artifact = path.join(outputDirectory, 'libhost-approval-dbus.so'), receipt = path.join(outputDirectory, 'host-approval-dbus.build.json');
    if (fs.existsSync(artifact) || fs.existsSync(receipt)) denied();
    fs.renameSync(binary, artifact); fs.renameSync(manifestPath, receipt);
    const fd = fs.openSync(outputDirectory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    if (hash(fs.readFileSync(artifact)) !== library.digest || fs.readFileSync(receipt, 'utf8') !== text) denied();
    // Only builder-owned compiler bookkeeping is removed on successful build.
    fs.unlinkSync(dependencies); fs.rmdirSync(staging);
    return Object.freeze({ library: artifact, manifest: receipt, digest: library.digest });
  } catch { denied(); }
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { if (process.argv.length !== 3) denied(); console.log(JSON.stringify(buildHostApprovalDbus(process.argv[2]))); }
  catch { console.error('host_approval_native_build_blocked'); process.exitCode = 1; }
}
