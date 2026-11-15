// Offline, disposable build only. No download/install, CC/CFLAGS/PATH fallback.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const native = fileURLToPath(new URL('../offline-git-worker/native/', import.meta.url));
const hash = b => createHash('sha256').update(b).digest('hex');
const fail = () => { throw Error('offline_git_build_failed'); };
export const offlineGitFlags = Object.freeze(['-B/usr/bin/', '-std=c17', '-D_GNU_SOURCE', '-O2',
  '-Wall', '-Wextra', '-Werror', '-Wformat=2', '-Wconversion', '-Wshadow',
  '-Wno-misleading-indentation', '-fstack-protector-strong', '-D_FORTIFY_SOURCE=2',
  '-fPIE', '-pie', '-Wl,-z,relro,-z,now,-z,noexecstack']);
const env = Object.freeze({ LANG: 'C', LC_ALL: 'C', TZ: 'UTC', SOURCE_DATE_EPOCH: '0' });
function run(file, args, cwd) {
  const r = spawnSync(file, args, { cwd, env, encoding: 'utf8', timeout: 60000, maxBuffer: 1048576 });
  if (r.error || r.signal || r.status !== 0) fail(); return r.stdout;
}
function artifact(file) {
  const real = fs.realpathSync(file), s = fs.lstatSync(real);
  if (!s.isFile() || s.nlink !== 1 || (s.mode & 0o7022) || s.size > 268435456) fail();
  return { path: real, size: s.size, digest: hash(fs.readFileSync(real)) };
}
function sync(file) { const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); } }
export function buildOfflineGitWorker(output) {
  if (process.platform !== 'linux' || typeof output !== 'string' || !path.isAbsolute(output) || fs.realpathSync(output) !== output) fail();
  const s = fs.lstatSync(output);
  if (!s.isDirectory() || s.uid !== process.getuid() || (s.mode & 0o7777) !== 0o700 || fs.readdirSync(output).length) fail();
  // The compiler/linker identity is recorded, not invented as a qualified pin.
  const compiler = artifact('/usr/bin/cc'), linker = artifact('/usr/bin/ld'), runtime = artifact(process.execPath);
  const compilerVersion = run('/usr/bin/cc', ['--version'], output);
  const target = run('/usr/bin/cc', ['-dumpmachine'], output).trim();
  const files = ['protocol.h', 'custody.h', 'custody.c', 'supervisor.c', 'worker.c'];
  const sources = Object.fromEntries(files.map(f => [f, artifact(path.join(native, f))]));
  const binaries = {}, invocations = [];
  for (const name of ['supervisor', 'worker']) {
    const binary = path.join(output, 'ogw-' + name);
    const args = [...offlineGitFlags, '-ffile-prefix-map=' + native + '=native',
      path.join(native, name + '.c'), path.join(native, 'custody.c'), '-o', binary];
    run('/usr/bin/cc', args, output);
    const elf = run('/usr/bin/readelf', ['-lW', binary], output), needed = run('/usr/bin/ldd', [binary], output);
    const loader = /Requesting program interpreter:\s*([^\]]+)/.exec(elf)?.[1]; if (!loader) fail();
    const closure = [artifact(loader)];
    for (const line of needed.split('\n')) {
      if (line.includes('not found')) fail();
      const p = /=>\s*(\/\S+)/.exec(line)?.[1] ?? /^\s*(\/\S+)/.exec(line)?.[1];
      if (p && !closure.some(a => a.path === fs.realpathSync(p))) closure.push(artifact(p));
    }
    fs.chmodSync(binary, 0o755); sync(binary);
    binaries[name] = { ...artifact(binary), path: path.basename(binary), closure };
    invocations.push(args.map(a => a === binary ? path.basename(binary) : a));
  }
  for (const a of [compiler, linker, runtime, ...Object.values(sources), ...Object.values(binaries).flatMap(x => x.closure)])
    if (artifact(a.path).digest !== a.digest) fail();
  const manifest = { version: 1, type: 'offline-git.source-build', qualified: false,
    compiler, linker, compilerVersion, target, runtime, sources, invocations, binaries };
  const bytes = JSON.stringify(manifest, null, 2) + '\n', file = path.join(output, 'build.json');
  fs.writeFileSync(file, bytes, { mode: 0o600, flag: 'wx' }); sync(file); sync(output);
  if (fs.readFileSync(file, 'utf8') !== bytes) fail();
  return Object.freeze({ manifest: file, digest: hash(bytes), binaries: Object.freeze(binaries) });
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { if (process.argv.length !== 3) fail(); console.log(JSON.stringify(buildOfflineGitWorker(process.argv[2]))); }
  catch { console.error('offline_git_build_failed'); process.exitCode = 1; }
}
