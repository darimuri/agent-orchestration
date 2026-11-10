// Trusted source-only composition. Import does not load an addon or open a bus.
import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
import { isMainThread } from 'node:worker_threads';
import { fileURLToPath } from 'node:url';
import { createAdmissionStore } from './admission-store.mjs';
import { canonical, data, digest, fixedPolicy, timestamp } from './intent.mjs';
const require = createRequire(import.meta.url);
const sourceRoot = fileURLToPath(new URL('./native/', import.meta.url));
const unavailable = () => { const e = Error('approval_unavailable'); e.code = e.message; throw e; };
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
let poisoned = false;
function protectedFile(file) {
  if (typeof file !== 'string' || !path.isAbsolute(file) || path.normalize(file) !== file || fs.realpathSync(file) !== file) unavailable();
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.uid !== 0 || stat.nlink !== 1 || (stat.mode & 0o7022)) unavailable();
  for (let parent = path.dirname(file); ; parent = path.dirname(parent)) {
    const s = fs.lstatSync(parent);
    if (!s.isDirectory() || s.isSymbolicLink() || s.uid !== 0 || (s.mode & 0o7022)) unavailable();
    if (parent === path.dirname(parent)) break;
  }
  const descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const opened = fs.fstatSync(descriptor), bytes = fs.readFileSync(descriptor), after = fs.fstatSync(descriptor), named = fs.lstatSync(file);
    const stamp = s => [s.dev, s.ino, s.uid, s.mode, s.nlink, s.size, s.mtimeMs, s.ctimeMs].join(':');
    if (stamp(stat) !== stamp(opened) || stamp(opened) !== stamp(after) || stamp(after) !== stamp(named) || bytes.length !== stat.size) unavailable();
    return bytes;
  } finally { fs.closeSync(descriptor); }
}
function loadArtifact(input) {
  const a = data(input, ['path', 'digest', 'manifestPath', 'manifestDigest']);
  if (!/^[a-f0-9]{64}$/.test(a.digest) || !/^[a-f0-9]{64}$/.test(a.manifestDigest) || !a.path.endsWith('.node')) unavailable();
  const bytes = protectedFile(a.path), manifestBytes = protectedFile(a.manifestPath);
  if (hash(bytes) !== a.digest || hash(manifestBytes) !== a.manifestDigest || manifestBytes.length > 1048576) unavailable();
  const m = JSON.parse(manifestBytes);
  if (m.version !== 1 || m.type !== 'buzz.host-approval-node' || m.test !== false || m.artifact.digest !== a.digest ||
      m.runtime.path !== fs.realpathSync(process.execPath) || m.runtime.version !== process.version || m.abi !== process.versions.modules ||
      m.platform !== process.platform || m.architecture !== process.arch || m.napi !== 8 || !Array.isArray(m.inputs) || m.inputs.length > 4096 ||
      !Array.isArray(m.imports) || !m.imports.length || !Array.isArray(m.argv) || m.argv.some(x => /HA_TEST|sanitize|NODE_OPTIONS/.test(x))) unavailable();
  for (const record of m.inputs) if (typeof record.path !== 'string' || hash(protectedFile(record.path)) !== record.digest) unavailable();
  for (const name of ['host-approval-node.c', 'host-approval-dbus.c', 'host-approval-dbus.h']) {
    const file = path.join(sourceRoot, name);
    if (!m.inputs.some(p => p.path === fs.realpathSync(file) && p.digest === hash(protectedFile(file)))) unavailable();
  }
  if (!m.inputs.some(p => p.path === m.runtime.path && p.digest === hash(protectedFile(process.execPath)))) unavailable();
  const native = require(a.path);
  if (typeof native.createServer !== 'function' || Reflect.ownKeys(native).length !== 1 || !Object.isFrozen(native)) unavailable();
  if (hash(protectedFile(a.path)) !== a.digest || hash(protectedFile(a.manifestPath)) !== a.manifestDigest) unavailable();
  return native;
}
export function createApprovalDecisionService(input) {
  let nativeServer;
  const calls = new Set();
  let closed = false, pumping = false, last = -1;
  function poison() {
    poisoned = true; closed = true;
    for (const entry of calls) { try { entry.call.cancel(); } catch {} }
    calls.clear();
    // During a native callback processOnce owns the native server frame. Close
    // at the end of that explicit turn rather than reentering native processing.
    if (!pumping && nativeServer) { try { nativeServer.close(); } catch {} }
  }
  try {
    if (poisoned || !isMainThread || process.platform !== 'linux' || process.getuid() !== 0 || process.geteuid() !== 0) unavailable();
    const options = data(input, ['directory', 'policy', 'ownerUid', 'clock', 'nativeArtifact']);
    const policy = fixedPolicy(options.policy), policyDigest = digest(policy);
    if (!Number.isSafeInteger(options.ownerUid) || options.ownerUid <= 0 || options.ownerUid === 10001 || options.ownerUid > 0xffffffff || typeof options.clock !== 'function') unavailable();
    const clock = () => {
      const n = options.clock();
      if (!Number.isSafeInteger(n) || n < 0 || n < last) { poison(); unavailable(); }
      last = n; return n;
    };
    clock();
    const native = loadArtifact(options.nativeArtifact);
    const inspectStore = createAdmissionStore({ directory: options.directory, policy, clock, decisionAuthority: () => unavailable() });
    const check = observation => {
      if (!observation || observation.phase === 'outcome_unknown') { poison(); unavailable(); }
      return observation;
    };
    const usable = () => { if (poisoned || closed) unavailable(); };
    const config = { ownerUid: options.ownerUid, ownerId: policy.ownerId, policyDigest, authorityTimeoutMs: policy.authorityTimeoutMs, clock };
    const callbacks = {
      inspect(call, id) {
        try {
          usable(); const observed = check(inspectStore.inspect(id));
          const summary = observed.intent ? canonical(observed.intent) : '';
          if (!summary.isWellFormed() || Buffer.byteLength(summary) > 16384) unavailable();
          call.reply({ intentDigest: observed.intentDigest ?? '', summary, phase: observed.phase });
        } catch { try { call.cancel(); } catch {} poison(); }
      },
      decide(call, id, decision) {
        const entry = { call }; calls.add(entry);
        // Each actual native call owns its own store/authority closure. Never
        // resolve authority from a global current-request or binding cache.
        void (async () => {
          try {
            usable();
            const before = check(inspectStore.inspect(id));
            const originalDeadline = before.intent ? Math.min(timestamp(before.intent.approvalExpiresAt), timestamp(before.intent.jobExpiresAt)) : 0;
            const attemptDeadline = Math.min(originalDeadline, clock() + policy.authorityTimeoutMs);
            const expected = { requestId: id, intentDigest: before.intentDigest, decision, ownerId: policy.ownerId, policyDigest };
            const decisionAuthority = async (binding, signal) => {
              usable();
              const exact = data(binding, Object.keys(expected));
              if (Object.entries(expected).some(([k, v]) => exact[k] !== v) || before.phase !== 'pending' ||
                  !(signal instanceof AbortSignal) || signal.aborted || clock() >= attemptDeadline) unavailable();
              const lease = await call.authorize(binding, attemptDeadline, signal);
              usable(); const authorizedAt = clock();
              if (!lease || lease.valid() !== true || authorizedAt >= attemptDeadline || signal.aborted) unavailable();
              const authorityId = randomBytes(16).toString('hex');
              return Object.freeze({ ...binding, authorityId, authorizedAt, validUntil: attemptDeadline,
                stillValid: () => !poisoned && !closed && !signal.aborted && clock() < attemptDeadline && lease.valid() === true });
            };
            const store = createAdmissionStore({ directory: options.directory, policy, clock, decisionAuthority });
            const result = check(await store.decide(id, decision));
            usable();
            const receiptId = ['approved', 'rejected', 'reserved'].includes(result.phase) ? result.decisionReceiptId : '';
            if (receiptId !== '' && (typeof receiptId !== 'string' || !/^[a-f0-9]{32}$/.test(receiptId))) unavailable();
            // Native reply consumes the call, then releases its retained lease.
            // A reply failure after durable publication poisons; never undo it.
            call.reply({ phase: result.phase, receiptId });
          } catch { poison(); }
          finally { try { call.cancel(); } catch { poison(); } calls.delete(entry); }
        })();
      },
    };
    nativeServer = native.createServer(config, callbacks);
    return Object.freeze({
      processOnce() {
        usable(); if (pumping) { poison(); unavailable(); }
        pumping = true;
        try { const result = nativeServer.processOnce(); usable(); return result; }
        catch { poison(); unavailable(); }
        finally { pumping = false; if (closed) { try { nativeServer.close(); } catch {} } }
      },
      close() { poison(); },
    });
  } catch { poison(); unavailable(); }
}
