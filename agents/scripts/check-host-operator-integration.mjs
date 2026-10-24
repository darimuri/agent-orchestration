// Test-only, fixed build/check operations. Never imported by production code.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const gatewayHead = '59fca5e863c99dd44b7d8d0ad762e00f03402517';
const gatewayTree = 'b1e1430793bcd26b02df9a77aa49a5b5ce16a24b';
const base = '1b3bc2b41e2767273053e8e03bd89e9d3149d3e1';
const orchestration = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
// No inherited agent credentials, npm configuration, NODE_OPTIONS or transport.
const env = { PATH: process.env.PATH, HOME: os.homedir(), LANG: 'C.UTF-8',
  npm_config_userconfig: '/dev/null' };
let stage = 'arguments', scratch;
function run(command, args, cwd, extra = {}) {
  const result = spawnSync(command, args, { cwd, env: { ...env, ...extra },
    encoding: 'utf8', timeout: 300000, maxBuffer: 16 * 1024 * 1024 });
  if (result.error || result.status !== 0) {
    if (scratch) fs.writeFileSync(path.join(scratch, stage + '.failure.log'), String(result.stdout ?? '') + String(result.stderr ?? ''), { mode: 0o600 });
    throw Error('check_failed');
  }
  return result.stdout.trim();
}
function git(cwd, ...args) { return run('git', args, cwd); }
function provenance(cwd, expected, origin, tree) {
  if (fs.realpathSync(cwd) !== path.resolve(cwd) ||
      git(cwd, 'rev-parse', '--show-toplevel') !== path.resolve(cwd) ||
      git(cwd, 'remote', 'get-url', 'origin') !== origin ||
      git(cwd, 'rev-parse', 'HEAD') !== expected ||
      git(cwd, 'status', '--porcelain', '--untracked-files=normal') !== '' ||
      (tree && git(cwd, 'rev-parse', 'HEAD^{tree}') !== tree)) throw Error('provenance_failed');
  return { head: expected, tree: git(cwd, 'rev-parse', 'HEAD^{tree}') };
}
function archive(source, head, destination) {
  fs.mkdirSync(destination, { mode: 0o700 });
  const tar = path.join(scratch, path.basename(destination) + '.tar');
  run('git', ['archive', '--format=tar', '--output=' + tar, head], source);
  run('tar', ['-xf', tar, '-C', destination], scratch);
  fs.unlinkSync(tar);
}
function check(label, command, args, cwd, extra) {
  stage = label;
  const output = run(command, args, cwd, extra);
  if (label === 'orchestration-test' && !/^# skipped 0$/m.test(output)) throw Error('integration_skipped');
  fs.writeFileSync(path.join(scratch, label + '.log'), output + '\n', { mode: 0o600 });
  // Fixed summary only; never dump upstream errors, private paths or ledgers.
  console.log(JSON.stringify({ stage: label, status: 'pass',
    summary: output.split('\n').filter(s => /^# (tests|pass|fail|skipped) \d+$/.test(s)) }));
}
try {
  const [dependency, expected, ...rest] = process.argv.slice(2);
  if (!dependency || !/^[a-f0-9]{40}$/.test(expected ?? '') || rest.length ||
      process.platform !== 'linux' || !process.getuid || process.getuid() === 0) throw Error('arguments');
  stage = 'provenance';
  const a1 = provenance(orchestration, expected, 'https://github.com/darimuri/agent-orchestration.git');
  git(orchestration, 'merge-base', '--is-ancestor', base, expected);
  const a2 = provenance(path.resolve(dependency), gatewayHead,
    'https://github.com/darimuri/github-app-agent-gateway.git', gatewayTree);
  console.log(JSON.stringify({ orchestration: a1, gateway: a2 }));
  stage = 'scratch';
  const parent = path.resolve(process.env.TEST_EXECUTABLE_TMPDIR ?? os.tmpdir());
  if (fs.realpathSync(parent) !== parent || [orchestration, path.resolve(dependency)].some(root => parent === root || parent.startsWith(root + '/'))) throw Error('scratch');
  for (let dir = parent; ; dir = path.dirname(dir)) {
    const stat = fs.lstatSync(dir);
    const stickyTmp = dir === '/tmp' && (stat.mode & 0o1000);
    if (!stat.isDirectory() || stat.isSymbolicLink() || ![0, process.getuid()].includes(stat.uid) ||
        (!stickyTmp && (stat.mode & 0o022)) || (dir === parent && !stickyTmp && (stat.uid !== process.getuid() || (stat.mode & 0o077)))) throw Error('scratch');
    if (dir === '/') break;
  }
  scratch = fs.mkdtempSync(path.join(parent, 'host-integration-')); fs.chmodSync(scratch, 0o700);
  env.TMPDIR = scratch; env.TEST_EXECUTABLE_TMPDIR = scratch;
  const globalConfig = path.join(scratch, 'empty-global.npmrc');
  fs.writeFileSync(globalConfig, '', { mode: 0o600 }); env.npm_config_globalconfig = globalConfig;
  const app = path.join(scratch, 'orchestration'), gateway = path.join(scratch, 'gateway');
  stage = 'archive'; archive(orchestration, expected, app); archive(dependency, gatewayHead, gateway);
  const install = ['ci', '--ignore-scripts', '--offline', '--no-audit', '--no-fund'];
  check('gateway-install', 'npm', install, gateway);
  for (const script of ['check', 'test', 'build']) check('gateway-' + script, 'npm', ['run', script], gateway);
  check('auth-install', 'npm', install, path.join(app, 'agents/host-operator-auth'));
  // Existing state-storage fixtures intentionally reject /workspace roots; keep
  // data in private /tmp children, and executable AGE #5 fixtures in scratch.
  const testEnv = { HOST_OPERATOR_TEST_GATEWAY_BUILD: gateway, TMPDIR: os.tmpdir() };
  const scripts = path.join(app, 'agents/scripts'), docker = path.join(app, 'agents/docker');
  const tests = [docker, scripts].flatMap(dir => fs.readdirSync(dir).filter(f => f.endsWith('.test.mjs')).sort().map(f => path.join(dir, f)));
  check('orchestration-test', process.execPath, ['--test', ...tests], app, testEnv);
  // Compose rendering and App shell fixtures have host tool prerequisites.
  // Do not fabricate tools or claim an unavailable suite passed.
  const unavailable = ['gh/Docker/Compose/root host acceptance (not run by this offline harness)'];
  stage = 'source-recheck';
  provenance(orchestration, expected, 'https://github.com/darimuri/agent-orchestration.git', a1.tree);
  provenance(path.resolve(dependency), gatewayHead, 'https://github.com/darimuri/github-app-agent-gateway.git', gatewayTree);
  console.log(JSON.stringify({ status: 'pass', orchestration: a1, gateway: a2,
    unavailable }));
} catch {
  console.error(JSON.stringify({ status: 'failed', stage })); process.exitCode = 1;
} finally {
  if (scratch && !process.exitCode) fs.rmSync(scratch, { recursive: true, force: true });
}
