// Mandatory gates. Missing native/broker/PTY/executable resources are failures.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { clientFlags, clientPrerequisites, buildHostApproval } from './build-host-approval.mjs';

const source = fileURLToPath(new URL('../job-preparation/native/host-approval.c', import.meta.url));
const harness = fileURLToPath(new URL('../tests/job-preparation/host-approval-cli.test.c', import.meta.url));
const fixedEnv = Object.freeze({ LANG: 'C', LC_ALL: 'C', TZ: 'UTC' });
const sha = p => createHash('sha256').update(fs.readFileSync(p)).digest('hex');
export const clientScenarios = Object.freeze([
  'approve', 'reject', 'terminal_bytes', 'password', 'ignore_term',
  ...['absent', 'approved', 'rejected', 'expired', 'reserved', 'conflict', 'capacity', 'denied', 'outcome_unknown'].map(p => 'historical_' + p),
  'invalid_id', 'invalid_decision', 'extra_arg', 'root_identity', 'privileged_identity', 'shared_agent_uid',
  'wrong_service_uid', 'wrong_broker_uid', 'wrong_broker', 'wrong_path', 'wrong_interface',
  'no_tty', 'redirected_stdout', 'background_tty', 'synthetic_tty_loss',
  'inspect_wrong_sender', 'inspect_timeout', 'inspect_signature', 'inspect_trailing', 'inspect_phase', 'inspect_digest',
  'inspect_summary', 'inspect_upper_digest', 'inspect_oversized', 'service_replaced', 'service_disconnect',
  'broker_disconnect', 'daemon_death', 'exec_failure', 'notify_never', 'notify_exit', 'notify_data',
  'registration_conflict', 'child_before_ready', 'child_after_ready', 'child_during_decide', 'pidfd_failure',
  'signal_before', 'signal_decide_int', 'signal_decide_term', 'signal_decide_hup', 'deadline_start',
  'lost_reply', 'decide_wrong_sender', 'decide_signature', 'decide_trailing', 'decide_phase', 'decide_missing_receipt',
  'decide_invalid_receipt', 'decide_unknown', 'decide_denied', 'decide_conflict', 'decide_reserved',
  'decide_opposite', 'cleanup_failure', 'parent_death', 'parent_death_gate',
]);
function scratch(t) {
  const dir = fs.mkdtempSync(path.join(process.env.TEST_EXECUTABLE_TMPDIR ?? os.tmpdir(), 'approval-cli-'));
  fs.chmodSync(dir, 0o700); t.after(() => fs.rmSync(dir, { recursive: true, force: true })); return dir;
}
function run(executable, argv, cwd) {
  const r = spawnSync(executable, argv, { cwd, env: fixedEnv, encoding: 'utf8', timeout: 60000, maxBuffer: 1048576 });
  assert.ifError(r.error); assert.equal(r.status, 0, 'native build/tool failed: ' + r.stderr); return r.stdout.trim();
}
async function stop(cp) {
  if (!cp.pid || cp.exitCode !== null || cp.signalCode !== null) return;
  const exited = once(cp, 'exit'); cp.kill('SIGTERM');
  const timer = setTimeout(() => cp.kill('SIGKILL'), 1000);
  try { await exited; } finally { clearTimeout(timer); }
}
async function broker(dir) {
  const cp = spawn('/usr/bin/dbus-daemon', ['--session', '--nofork', '--nopidfile', '--print-address=1', '--address=unix:path=' + path.join(dir, 'broker')], { env: fixedEnv, stdio: ['ignore', 'pipe', 'pipe'] });
  try {
    const address = await new Promise((resolve, reject) => {
      let output = ''; const timer = setTimeout(() => reject(Error('BLOCKED disposable broker readiness')), 5000);
      cp.once('error', e => { clearTimeout(timer); reject(e); });
      cp.once('exit', () => { clearTimeout(timer); reject(Error('BLOCKED disposable broker exited')); });
      cp.stdout.on('data', chunk => {
        output += chunk.toString();
        if (output.length > 4096) { clearTimeout(timer); reject(Error('broker output bound')); }
        else if (output.includes('\n')) { clearTimeout(timer); resolve(output.split('\n')[0]); }
      });
    });
    assert.match(address, /^unix:path=/); return { cp, address };
  } catch (error) { await stop(cp); throw error; }
}
async function scenarioRun(executable, address, scenario, agent, cwd, daemon, sanitizer) {
  const env = sanitizer ? { ...fixedEnv, ASAN_OPTIONS: 'detect_leaks=1:abort_on_error=1', UBSAN_OPTIONS: 'halt_on_error=1:print_stacktrace=1' } : fixedEnv;
  const cp = spawn(executable, [address, scenario, agent, 'synthetic'], { cwd, env, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  cp.stdout.on('data', chunk => { stdout += chunk.toString(); if (stdout.includes('KILL_DISPOSABLE_BROKER') && daemon.exitCode === null && daemon.signalCode === null) daemon.kill('SIGKILL'); });
  cp.stderr.on('data', chunk => { stderr += chunk.toString(); });
  const timer = setTimeout(() => cp.kill('SIGKILL'), 10000);
  try {
    const [code, signal] = await once(cp, 'exit');
    assert.equal(signal, null, `${scenario}: signal ${signal}; ${stderr}`);
    assert.equal(code, 0, `${scenario}: ${stderr}`);
    assert(stdout.includes('NOT live Polkit/TTY/root/store acceptance'), scenario);
    assert(!stdout.includes('SYNTHETIC_PASSWORD_DO_NOT_LOG') && !stderr.includes('SYNTHETIC_PASSWORD_DO_NOT_LOG'));
    assert(!/AddressSanitizer|runtime error:/.test(stderr), `${scenario}: ${stderr}`);
  } finally { clearTimeout(timer); await stop(cp); }
}

test('terminal client exposes only fixed source-only approval protocol and owned exec', () => {
  const text = fs.readFileSync(source, 'utf8');
  assert(text.includes('unix:path=/run/dbus/system_bus_socket'));
  assert(text.includes('"/usr/bin/pkttyagent"'));
  assert(text.includes('"--system-bus-name", c->unique, "--notify-fd", "3"'));
  assert(!/getenv\s*\(|system\s*\(|popen\s*\(|sd_bus_open_system|--process|--fallback|admission\.lock|store\.reserve/.test(text));
  assert.equal([...text.matchAll(/"Decide", argv\[2\], argv\[1\], true/g)].length, 1);
  assert(text.includes('PR_SET_PDEATHSIG, SIGKILL') && text.includes('SYS_pidfd_send_signal') && text.includes('SYS_close_range'));
  // Frozen XML/server order: digest, summary, phase (all strings).
  assert(text.includes('sd_bus_message_read(c.reply, "sss", &digest, &summary, &state)'));
  assert(text.includes('c->delivered = true') && text.includes('outcome_unknown'));
});
test('offline executable build fixes toolchain/hardening and reports missing prerequisites', () => {
  assert(Object.isFrozen(clientFlags));
  for (const flag of ['-B/usr/bin/', '-std=c17', '-Werror', '-Wconversion', '-Wshadow', '-Wformat=2', '-fPIE', '-pie', '-fstack-protector-strong', '-Wl,-z,defs,-z,relro,-z,now,-z,noexecstack']) assert(clientFlags.includes(flag));
  assert(!clientFlags.includes('-shared') && !clientFlags.includes('-fPIC'));
  assert(clientPrerequisites().every(p => p.startsWith('/usr/')));
});
test('MANDATORY production terminal executable, protected inventory and manifest', t => {
  const missing = clientPrerequisites(); if (missing.length) t.diagnostic('BLOCKED native prerequisites: ' + missing.join(', '));
  const dir = scratch(t), previous = process.umask(0o002); let built;
  try { built = buildHostApproval(dir); } finally { process.umask(previous); }
  const manifest = JSON.parse(fs.readFileSync(built.manifest, 'utf8'));
  assert.equal(manifest.type, 'buzz.host-approval-client');
  assert.equal(manifest.executable.digest, sha(built.executable)); assert.equal(manifest.source.digest, sha(source));
  assert.equal(fs.statSync(built.executable).mode & 0o7777, 0o755);
  assert.equal(fs.statSync(built.manifest).mode & 0o7777, 0o600);
  assert(manifest.headers.some(h => h.path.endsWith('/systemd/sd-bus.h')));
  assert(manifest.elfInputs.some(h => /libsystemd[.-]/.test(path.basename(h.path))));
  assert(!manifest.argv.some(a => a.includes('HOST_APPROVAL_CLI_TEST')));
  for (const key of ['loader', 'executableLoader', 'runtime', 'compiler']) assert.match(manifest[key].digest, /^[a-f0-9]{64}$/);
  const symbols = run('/usr/bin/readelf', ['-Ws', built.executable], dir);
  assert(!/\bfixture\b|\bagent_main\b|\bscenario\b/.test(symbols));
  for (const args of [[], ['approve'], ['approve', 'INVALID'], ['--help'], ['reject', 'a'.repeat(32), 'extra']]) {
    const r = spawnSync(built.executable, args, { env: fixedEnv, encoding: 'utf8', timeout: 2000 });
    assert.ifError(r.error); assert.equal(r.status, 1); assert.equal(r.stdout, ''); assert.equal(r.stderr, '');
  }
});
for (const sanitizer of [false, true]) test('MANDATORY real client/disposable broker/fake agent/PTY ' + (sanitizer ? 'ASan+UBSan' : 'strict C17'), { timeout: 240000 }, async t => {
  const missing = [...clientPrerequisites(), ...(!fs.existsSync('/usr/bin/dbus-daemon') ? ['/usr/bin/dbus-daemon'] : [])];
  assert.equal(missing.length, 0, 'BLOCKED compiler/libsystemd/broker prerequisites: ' + missing.join(', '));
  assert.notEqual(process.getuid(), 0);
  const dir = scratch(t), executable = path.join(dir, 'cli-fixture');
  const packageFlags = run('/usr/bin/pkg-config', ['--cflags', '--libs', 'libsystemd'], dir).split(/\s+/).filter(Boolean);
  assert(packageFlags.every(f => f === '-lsystemd' || f === '-pthread' || /^-[IL]\/[A-Za-z0-9_./+-]+$/.test(f)));
  const sanitizerFlags = sanitizer ? ['-O1', '-fsanitize=address,undefined', '-fno-omit-frame-pointer'] : [];
  run('/usr/bin/cc', [...clientFlags, ...sanitizerFlags, harness, '-o', executable, ...packageFlags], dir);
  for (const scenario of clientScenarios) {
    const agent = path.join(dir, 'agent-' + scenario);
    if (scenario === 'exec_failure') fs.writeFileSync(agent, 'intentionally invalid executable format\n', { mode: 0o755 });
    else { fs.copyFileSync(executable, agent); fs.chmodSync(agent, 0o755); }
    const busDir = fs.mkdtempSync(path.join(dir, 'bus-')); const disposable = await broker(busDir);
    try { await scenarioRun(executable, disposable.address, scenario, agent, dir, disposable.cp, sanitizer); }
    finally { await stop(disposable.cp); }
    t.diagnostic('synthetic scenario passed: ' + scenario);
  }
  t.diagnostic(`${clientScenarios.length} synthetic broker/agent/PTY scenarios; NOT installed pkttyagent, real Polkit, root service/store or live H1-H9 acceptance`);
});
