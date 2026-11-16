// Source-only AGE30 preparation. This module cannot issue an OGC2 capsule.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { assessQualificationDossier, decodeQualificationDossier, dossierTemplate, PRODUCTION, PREPARATION_FILES, PROBE, POLICY } from '../offline-git-worker/qualification-dossier.mjs';
import { exact } from '../offline-git-worker/protocol.mjs';
import { buildOfflineGitWorker, offlineGitFlags } from './build-offline-git-worker.mjs';
export const BASE = '8bbc3a9d052d428e67eebd3b7cf56c43ffe4490a';
export const BASE_TREE = '8c5c76161e3e2580c463f644bff7f893a47bbb54';
const root = fileURLToPath(new URL('../../', import.meta.url));
const fixture = path.join(root, 'agents/tests/offline-git-worker');
const env = Object.freeze({ LANG: 'C', LC_ALL: 'C', TZ: 'UTC', SOURCE_DATE_EPOCH: '0', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' });
const SOURCES = Object.freeze([
  'agents/offline-git-worker/protocol.mjs','agents/offline-git-worker/client.mjs','agents/offline-git-worker/qualification-dossier.mjs',
  ...['protocol.h','custody.h','custody.c','supervisor.c','worker.c'].map(n => 'agents/offline-git-worker/native/' + n),
  'agents/scripts/build-offline-git-worker.mjs','agents/scripts/offline-git-worker.test.mjs',
  'agents/tests/offline-git-worker/native.test.c','agents/tests/offline-git-worker/worker.test.c','agents/OFFLINE_GIT_WORKER.md',
  'agents/scripts/offline-git-host-acceptance.mjs','agents/scripts/offline-git-host-acceptance.test.mjs',
  ...['host-entry.c','host-driver.c','host-validator.mjs'].map(n => 'agents/tests/offline-git-worker/' + n),
  'agents/OFFLINE_GIT_HOST_ACCEPTANCE.md'
]);
const fail = () => { throw Error('age30_unknown'); };
const digest = b => createHash('sha256').update(b).digest('hex');
export const GATES = Object.freeze(['independent_cpu_prevention_proof', 'independent_lifetime_owner_contract',
  'reviewed_privileged_launcher', 'pinned_complete_runtime_closure', 'intended_host_kernel_evidence',
  'independent_evidence_review']);
export function refusal(reasons = GATES) {
  return Object.freeze({ version: 1, status: 'UNKNOWN', qualified: false, admission: false, reasons: [...reasons] });
}
function nonroot() { if (process.platform !== 'linux' || process.getuid() === 0 || process.geteuid() === 0) fail(); }
function run(file, args, cwd = root) {
  const safeArgs = file === '/usr/bin/git' ? ['-c','core.fsmonitor=false',...args] : args;
  const r = spawnSync(file, safeArgs, { cwd, env, encoding: 'utf8', timeout: 60000, maxBuffer: 1048576 });
  if (r.error || r.signal || r.status !== 0) fail(); return r.stdout.trim();
}
// No following arbitrary links, no device/FIFO reads and no unbounded proc/stdin reads.
export function readBounded(file, maximum) {
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 33554432) fail();
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.size > BigInt(maximum)) fail();
    const b = Buffer.alloc(maximum + 1); let n = 0;
    while (n <= maximum) { const got = fs.readSync(fd, b, n, b.length - n, null); if (!got) break; n += got; }
    const after = fs.fstatSync(fd, { bigint: true });
    if (n > maximum || ['dev','ino','size','mtimeNs','ctimeNs'].some(k => before[k] !== after[k])) fail();
    return b.subarray(0, n);
  } finally { fs.closeSync(fd); }
}
function observation(file) { try { return { observed: readBounded(file, 16384).toString('utf8') }; } catch { return { status: 'UNKNOWN' }; } }
function artifact(file) {
  const actual = fs.realpathSync(file), b = readBounded(actual, 33554432);
  return { path: actual, bytes: b.length, sha256: digest(b) };
}
export function inspect() {
  nonroot();
  const tools = {};
  for (const [name, file, args] of [['git','/usr/bin/git',['--version']], ['node','/usr/bin/node',['--version']],
    ['cc','/usr/bin/cc',['--version']], ['readelf','/usr/bin/readelf',['--version']]]) {
    try { tools[name] = { ...artifact(file), version: run(file, args) }; } catch { tools[name] = { status: 'MISSING_OR_UNVERIFIED' }; }
  }
  let source;
  try { source = { head: run('/usr/bin/git', ['rev-parse','HEAD']), tree: run('/usr/bin/git',['rev-parse','HEAD^{tree}']),
    clean: run('/usr/bin/git',['status','--porcelain','--untracked-files=all']) === '',
    basePresent: run('/usr/bin/git',['rev-parse', BASE + '^{tree}']) === BASE_TREE }; } catch { source = { status: 'UNKNOWN' }; }
  const result = { ...refusal(), type: 'age30.nonadmitting-inspection', observationScope: 'current-process-container-or-host-unqualified',
    sourceFiles: Object.fromEntries(SOURCES.map(n => { try { return [n,artifact(path.join(root,n))]; } catch { return [n,{status:'UNKNOWN'}]; } })),
    kernel: os.release(), arch: process.arch, uid: process.getuid(), source, tools,
    uidMap: observation('/proc/self/uid_map'), gidMap: observation('/proc/self/gid_map'),
    controllers: observation('/sys/fs/cgroup/cgroup.controllers'),
    namespaces: Object.fromEntries(['mnt','net','pid','ipc','uts','user'].map(n => {
      try { return [n, fs.readlinkSync('/proc/self/ns/' + n)]; } catch { return [n, 'UNKNOWN']; }
    })),
    // Existence does not establish effective delegation, seccomp, ext4 or UID authority.
    support: { delegation: 'UNKNOWN', seccompEnforcement: 'UNKNOWN', ext4Durability: 'UNKNOWN', uidAuthority: 'UNKNOWN' } };
  const digestObservation = value => typeof value?.observed === 'string' ? digest(value.observed) : null;
  const fileInventory = paths => paths.map(path => ({path,sha256:result.sourceFiles[path]?.sha256 ?? null}));
  result.dossierContext = {
    production:{commit:source.basePresent ? BASE : null,tree:source.basePresent ? BASE_TREE : null,
      files:fileInventory(PRODUCTION.files.map(f=>f.path))},
    preparation:{commit:source.head ?? null,tree:source.tree ?? null,clean:source.clean ?? null,files:fileInventory(PREPARATION_FILES)},
    probe:PROBE, policy:POLICY,
    host:{scope:'CURRENT_PROCESS_UNQUALIFIED',kernelRelease:result.kernel,arch:['x64','arm64'].includes(result.arch) ? result.arch : null,
      kernelBuildSha256:null,kernelConfigSha256:null,uidMapSha256:digestObservation(result.uidMap),gidMapSha256:digestObservation(result.gidMap),
      namespaces:Object.fromEntries(Object.entries(result.namespaces).map(([k,v])=>[k,v === 'UNKNOWN' ? null : v])),
      cgroupSha256:digestObservation(observation('/proc/self/cgroup'))}
  };
  result.probeContract = {identity:PROBE, canObserve:['current source bytes and Git identity','release/architecture','current UID/GID maps','current namespace and cgroup identifiers'],
    cannotObserve:['intended-host authority','kernel build/config identity','effective quota/slack/carry prevention','finite owner-loss/starvation lifetime','trusted aggregate CPU reserve','escape/migration enforcement'],
    missingProofInputs:[...GATES], template:dossierTemplate()};
  return result;
}
export function assessDossier(bytes, observation = null) {
  if (!Buffer.isBuffer(bytes) || bytes.length > 16384) fail();
  const d = JSON.parse(bytes.toString('utf8'));
  if (d?.version === 2) return assessQualificationDossier(bytes,observation);
  exact(d, ['version','source','kernel','arch','quotaUs','periodUs','burstUs','parallelism','quotaSlackUs',
    'maxRunnableUs','terminationBoundUs','trustedCpuUs','uncertaintyUs','lifetimeContractSha256','independentReviewSha256']);
  if (d.version !== 1 || d.source !== BASE || !['x64','arm64'].includes(d.arch) ||
      typeof d.kernel !== 'string' || !/^[a-zA-Z0-9._+-]{1,128}$/.test(d.kernel)) fail();
  for (const k of ['quotaUs','periodUs','burstUs','parallelism','quotaSlackUs','maxRunnableUs','terminationBoundUs','trustedCpuUs','uncertaintyUs'])
    if (!Number.isSafeInteger(d[k]) || d[k] < 0) fail();
  for (const k of ['lifetimeContractSha256','independentReviewSha256'])
    if (typeof d[k] !== 'string' || !/^[a-f0-9]{64}$/.test(d[k]) || /^0+$/.test(d[k])) fail();
  if (d.quotaUs !== 20000 || d.periodUs !== 100000 || d.burstUs !== 0 || d.parallelism < 1 || d.parallelism > 8 ||
      d.maxRunnableUs < 40000000 || d.terminationBoundUs < 2000000 || d.trustedCpuUs === 0 || d.uncertaintyUs === 0) fail();
  const lifetime = BigInt(d.maxRunnableUs) + BigInt(d.terminationBoundUs);
  // Conditional arithmetic only. Kernel-specific slack/latency and trusted reserves need independent proof.
  const periods = (lifetime + 99999n) / 100000n + 1n;
  const worker = periods * 20000n + BigInt(d.parallelism) * BigInt(d.quotaSlackUs);
  const total = worker + BigInt(d.trustedCpuUs) + BigInt(d.uncertaintyUs);
  return { ...refusal(), type: 'age30.conditional-dossier-feasibility', dossierSha256: digest(bytes),
    workerUpperUs: worker.toString(), aggregateUpperUs: total.toString(),
    arithmeticWithinCeiling: total <= 10000000n,
    assumptionsVerified: false, explanation: 'Caller numbers and review digests convey no proof or authority; admission remains refused.' };
}
export function buildSource() {
  nonroot();
  // Create an exclusive private directory; retain on success AND failure, never reuse or clean recursively.
  const output = fs.mkdtempSync('/tmp/age30-source-'); fs.chmodSync(output, 0o700);
  try {
    const production = buildOfflineGitWorker(output);
    const artifacts = {};
    for (const name of ['host-entry','host-driver']) {
      const binary = path.join(output, name);
      run('/usr/bin/cc', [...offlineGitFlags, '-ffile-prefix-map=' + fixture + '=age30', path.join(fixture, name + '.c'), '-o', binary], output);
      artifacts[name] = { ...artifact(binary), elf: run('/usr/bin/readelf', ['-lWd',binary], output) };
      const sanitized = path.join(output, name + '-sanitized');
      run('/usr/bin/cc', [...offlineGitFlags, '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-ffile-prefix-map=' + fixture + '=age30',
        path.join(fixture,name + '.c'), '-o', sanitized], output);
      artifacts[name + '-sanitized'] = artifact(sanitized);
    }
    const manifest = { ...refusal(), type: 'age30.source-build', output, production,
      artifacts, sources: Object.fromEntries(SOURCES.map(n => [n,artifact(path.join(root,n))])), validator: artifact(path.join(fixture,'host-validator.mjs')),
      runtime: { node: artifact('/usr/bin/node'), git: artifact('/usr/bin/git'), completeClosure: false },
      flags: offlineGitFlags, execution: 'no native entry or driver executed' };
    fs.writeFileSync(path.join(output,'host-build.json'), JSON.stringify(manifest,null,2) + '\n', { flag:'wx',mode:0o600 });
    return manifest;
  } catch { throw Error('age30_build_unknown_retained:' + output); }
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 3) fail();
    let result;
    switch (process.argv[2]) {
      case 'inspect': case 'probe': result = inspect(); break;
      case 'build-source': result = buildSource(); break;
      case 'dossier': {
        nonroot(); const chunks = []; let size = 0;
        const timer = setTimeout(() => process.stdin.destroy(Error('age30_unknown')), 2000);
        try {
          for await (const b of process.stdin) { size += b.length; if (size > 16384) { process.stdin.destroy(); fail(); } chunks.push(b); }
          const input = Buffer.concat(chunks);
          if (JSON.parse(input.toString('utf8'))?.version === 2) {
            decodeQualificationDossier(input); // reject malformed v2 before any inspection
            result = assessDossier(input,inspect().dossierContext);
          } else result = assessDossier(input);
        } finally { clearTimeout(timer); }
        break;
      }
      default: fail();
    }
    console.log(JSON.stringify(result)); process.exitCode = 2; // UNKNOWN, including successful source preparation
  } catch (e) { console.error(JSON.stringify({ ...refusal(), error: e.message.startsWith('age30_build_unknown_retained:') ? e.message : 'age30_unknown' })); process.exitCode = 2; }
}
