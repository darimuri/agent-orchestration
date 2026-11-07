// Mandatory native gates. Missing resources are FAIL/BLOCKED, never a skipped PASS.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { approvalFlags, approvalPrerequisites, buildHostApprovalDbus } from './build-host-approval-dbus.mjs';
const native = fileURLToPath(new URL('../job-preparation/native/host-approval-dbus.c', import.meta.url));
const harness = fileURLToPath(new URL('../tests/job-preparation/host-approval-dbus.test.c', import.meta.url));
const xml = fileURLToPath(new URL('../job-preparation/org.buzz.HostApproval1.xml', import.meta.url));
const fixedEnv = Object.freeze({ LANG: 'C', LC_ALL: 'C', TZ: 'UTC' });
const sha = p => createHash('sha256').update(fs.readFileSync(p)).digest('hex');
function scratch(t) {
  const dir = fs.mkdtempSync(path.join(process.env.TEST_EXECUTABLE_TMPDIR ?? os.tmpdir(), 'approval-native-')); fs.chmodSync(dir, 0o700);
  t.after(() => fs.rmSync(dir, { recursive: true, force: true })); return dir;
}
function run(executable, argv, cwd, sanitizer = false) {
  const env = sanitizer ? { ...fixedEnv, ASAN_OPTIONS: 'detect_leaks=1:abort_on_error=1', UBSAN_OPTIONS: 'halt_on_error=1:print_stacktrace=1' } : fixedEnv;
  const r = spawnSync(executable, argv, { cwd, env, encoding: 'utf8', timeout: 15000, maxBuffer: 65536 });
  assert.ifError(r.error); assert.equal(r.status, 0, `native fixture failed: ${r.stderr}`); return r.stdout.trim();
}
async function broker(t, dir) {
  // Never inherits DBUS_* or credentials and never contacts the host system bus.
  const cp = spawn('/usr/bin/dbus-daemon', ['--session', '--nofork', '--nopidfile', '--print-address=1', '--address=unix:path=' + path.join(dir, 'broker')], { env: fixedEnv, stdio: ['ignore', 'pipe', 'pipe'] });
  t.after(async () => {
    if (!cp.pid || cp.exitCode !== null || cp.signalCode !== null) return;
    const stopped = once(cp, 'exit'); cp.kill('SIGTERM'); const timer = setTimeout(() => cp.kill('SIGKILL'), 2000);
    try { await stopped; } finally { clearTimeout(timer); }
  });
  let bytes = ''; const address = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => { cp.kill('SIGKILL'); reject(Error('disposable_broker_blocked')); }, 5000);
    cp.once('error', error => { clearTimeout(timer); reject(error); });
    cp.stdout.on('data', chunk => { bytes += chunk.toString(); if (bytes.length > 4096) { clearTimeout(timer); cp.kill('SIGKILL'); reject(Error('broker_output_bound')); } else if (bytes.includes('\n')) { clearTimeout(timer); resolve(bytes.split('\n')[0]); } });
    cp.once('exit', () => { clearTimeout(timer); reject(Error('disposable_broker_exited')); });
  });
  assert.match(address, /^unix:path=/);
  return address;
}
const scenarios = Object.freeze(['happy','reject','inspect','distinct','spoof_sender','spoof_body','wrong_owner','malformed_id','malformed_decision','unknown_method','wrong_path','wrong_interface','output_bound','binding_owner','binding_policy','binding_request','binding_decision','past_deadline','denied','challenge','implicit_yes','retained','cached_id','authority_error','malformed_authority','allocation','lease_allocation','send','watch','credentials','cancel','duplicate','inflight_bound','disconnect','replacement','broker_disconnect','timeout','short_deadline','regression','clock_failure','teardown','lease_disconnect','lease_replacement','service_name_loss','lease_free','stale_handle']);

test('frozen XML and compiled public vtable expose exactly Inspect/Decide, no authority transport', () => {
  const contract = fs.readFileSync(xml, 'utf8'), source = fs.readFileSync(native, 'utf8');
  assert.deepEqual([...contract.matchAll(/<method name="([^"]+)"/g)].map(m => m[1]), ['Inspect', 'Decide']);
  assert.deepEqual([...source.matchAll(/SD_BUS_METHOD\("([^"]+)", "([^"]+)", "([^"]+)"/g)].map(m => m.slice(1)), [['Inspect','s','sss'], ['Decide','ss','ss']]);
  assert(contract.includes('/org/buzz/HostApproval1')); assert(contract.includes('interface name="org.buzz.HostApproval1"'));
  assert(source.includes('unix:path=/run/dbus/system_bus_socket')); assert(source.includes('"system-bus-name"'));
  assert(!/\bmain\s*\(|getenv\s*\(|sd_bus_open_system_remote|system\s*\(|execve\s*\(|fork\s*\(/.test(source));
  assert(!/admission\.lock|store\.decide|store\.reserve|loadApprovedPrepared/.test(source));
});

test('fixed build flags and blocked prerequisite reporting have no compiler/env fallback', () => {
  assert(Object.isFrozen(approvalFlags)); assert.equal(approvalFlags[0], '-B/usr/bin/');
  for (const flag of ['-std=c17','-Werror','-Wconversion','-Wshadow','-Wformat=2','-fstack-protector-strong','-fPIC','-shared']) assert(approvalFlags.includes(flag));
  assert(approvalFlags.includes('-Wl,-z,defs,-z,relro,-z,now,-z,noexecstack'));
  assert(approvalPrerequisites().every(p => p.startsWith('/usr/')));
});

test('MANDATORY production native approval shared-library build and protected manifest', t => {
  const missing = approvalPrerequisites(); if (missing.length) t.diagnostic('BLOCKED native prerequisites: ' + missing.join(', '));
  const dir = scratch(t), built = buildHostApprovalDbus(dir), manifest = JSON.parse(fs.readFileSync(built.manifest, 'utf8'));
  assert.equal(manifest.library.digest, sha(built.library)); assert.equal(manifest.source.digest, sha(native));
  assert.equal(manifest.type, 'buzz.host-approval-dbus-library'); assert(manifest.elfInputs.some(p => /libsystemd[.-]/.test(path.basename(p.path))));
  assert(manifest.headers.some(h => h.path.endsWith('/systemd/sd-bus.h'))); assert(manifest.headers.some(h => h.path.endsWith('/systemd/sd-login.h')));
  assert(!manifest.argv.some(x => x.includes('HA_TEST'))); assert.equal(manifest.loader.digest.length, 64); assert.equal(manifest.runtime.digest.length, 64);
  const symbols = run('/usr/bin/readelf', ['-Ws', built.library], dir); assert(!/\bha_test_|\bmain\s*$/.test(symbols));
  assert.equal(fs.statSync(built.library).mode & 0o7777, 0o755);
});

for (const sanitizer of [false, true]) test('MANDATORY disposable broker/fake Polkit ' + (sanitizer ? 'ASan+UBSan lifetimes' : 'strict C17 warnings-as-errors'), async t => {
  const missing = [...approvalPrerequisites(), ...(!fs.existsSync('/usr/bin/dbus-daemon') ? ['/usr/bin/dbus-daemon'] : [])];
  assert.equal(missing.length, 0, 'BLOCKED native/broker prerequisites: ' + missing.join(', ')); assert.notEqual(process.getuid(), 0);
  const dir = scratch(t), executable = path.join(dir, 'approval-fixture');
  const packageFlags = run('/usr/bin/pkg-config', ['--cflags', '--libs', 'libsystemd'], dir).split(/\s+/).filter(Boolean);
  assert(packageFlags.every(f => f === '-lsystemd' || f === '-pthread' || /^-[IL]\/[A-Za-z0-9_./+-]+$/.test(f)));
  const flags = approvalFlags.filter(f => f !== '-shared' && f !== '-fPIC');
  const sanitizerFlags = sanitizer ? ['-O1', '-fsanitize=address,undefined', '-fno-omit-frame-pointer'] : [];
  run('/usr/bin/cc', [...flags, '-fPIE', '-pie', '-DHA_TEST', ...sanitizerFlags, native, harness, '-o', executable, ...packageFlags], dir);
  const address = await broker(t, dir);
  for (const scenario of scenarios) {
    const output = run(executable, [address, scenario], dir, sanitizer);
    assert(output.includes('NOT live Polkit/TTY/root/store acceptance'), scenario);
  }
  t.diagnostic(`${scenarios.length} synthetic broker scenarios; no host acceptance`);
});
