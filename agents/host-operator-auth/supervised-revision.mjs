// Fixed source/fixture issuer. The owner-supplied supervisor is a trust boundary;
// there is deliberately no default process or simulated settlement backend.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { types } from 'node:util';
import { verifyOwnerEvent } from './owner-event.mjs';
import { createFileEventResolver } from './event-source.mjs';
import { createAuthorizationAdapter } from './authorization.mjs';
import { HostOperatorJournal } from '../scripts/host-operator-journal.mjs';
import { binding, descriptor, digest, exact, bounded, identifier, hexadecimal, timestamp } from '../scripts/host-operator-protocol.mjs';
import { ownData, evidenceData, evidencePins, canonicalEvidence, parseEvidence, terminalBoundary, protectedDirectory, createRevisionEvidenceStore } from './revision-evidence.mjs';

const denied = () => { const e = Error('supervised_revision_denied'); e.code = e.message; e.stack = e.message; throw e; };
const unknown = () => Object.freeze({ status: 'unknown', code: 'issue_unconfirmed' });
function freeze(v) { if (v && typeof v === 'object') { Object.values(v).forEach(freeze); Object.freeze(v); } return v; }
function rawBytes(raw) {
  if (typeof raw === 'string') { if (!raw.isWellFormed() || !Buffer.byteLength(raw) || Buffer.byteLength(raw) > 16384) denied(); return Buffer.from(raw); }
  if (!raw || types.isProxy(raw) || !Buffer.isBuffer(raw) || Object.getPrototypeOf(raw) !== Buffer.prototype) denied();
  const typed = Object.getPrototypeOf(Uint8Array.prototype), n = Object.getOwnPropertyDescriptor(typed, 'byteLength').get.call(raw);
  if (!n || n > 16384 || types.isSharedArrayBuffer(Object.getOwnPropertyDescriptor(typed, 'buffer').get.call(raw))) denied();
  const props = Object.getOwnPropertyDescriptors(raw), keys = Reflect.ownKeys(props);
  if (keys.length !== n || keys.some((k, i) => k !== String(i) || !Object.hasOwn(props[k], 'value'))) denied();
  return Buffer.from(keys.map(k => props[k].value));
}
const issuerFile = fileURLToPath(import.meta.url), workerFile = fileURLToPath(new URL('./supervised-revision-worker.mjs', import.meta.url));
function artifact(file, expected) {
  const s = fs.lstatSync(file); if (!s.isFile() || s.isSymbolicLink() || s.nlink !== 1 || s.size < 1 || s.size > 131072 || (s.mode & 0o7022)) denied();
  if (createHash('sha256').update(fs.readFileSync(file)).digest('hex') !== expected) denied();
}
export function createSupervisedRevisionIssuer(options) {
  try {
    const c = ownData(options), required = ['eventDirectory', 'journalDirectory', 'sourceDirectory', 'uid', 'ownerPubkey', 'requesterId', 'mentionPubkey', 'targetPubkey', 'channelId', 'threadId', 'source', 'currentJob', 'evidenceDirectory', 'authorityId', 'issuerArtifactDigest', 'workerArtifactDigest', 'clockId', 'supervisor', 'settlementWaitMs'];
    if (required.some(k => !Object.hasOwn(c, k)) || Object.keys(c).some(k => ![...required, 'clock', 'monotonic'].includes(k)) ||
        typeof c.currentJob !== 'function' || (c.clock !== undefined && typeof c.clock !== 'function') || (c.monotonic !== undefined && typeof c.monotonic !== 'function') ||
        process.platform !== 'linux' || !Number.isSafeInteger(c.uid) || c.uid <= 0 || c.uid !== process.getuid() || !Number.isSafeInteger(c.settlementWaitMs) || c.settlementWaitMs < 1 || c.settlementWaitMs > 60000) denied();
    c.source = freeze(binding(evidenceData(c.source)));
    const pins = evidencePins(Object.fromEntries(['source', 'authorityId', 'issuerArtifactDigest', 'workerArtifactDigest', 'clockId'].map(k => [k, c[k]])));
    const supervisor = ownData(c.supervisor); exact(supervisor, ['run']); if (typeof supervisor.run !== 'function') denied(); const run = supervisor.run;
    artifact(issuerFile, pins.issuerArtifactDigest); artifact(workerFile, pins.workerArtifactDigest);
    const roots = [c.eventDirectory, c.journalDirectory, c.sourceDirectory, c.evidenceDirectory];
    roots.forEach((p, i) => protectedDirectory(p, c.uid, i !== 2));
    if (new Set(roots).size !== 4) denied();
    for (const a of roots) for (const b of roots) if (a !== b && !path.relative(a, b).startsWith('..' + path.sep)) denied();
    const wall = c.clock ?? Date.now, mono = c.monotonic ?? (() => performance.now()); let lastWall = -1, lastMono = -1;
    function clock() { const n = wall(), m = mono(); timestamp(n); if (!Number.isFinite(m) || m < 0 || m < lastMono || n < lastWall) denied(); lastWall = n; lastMono = m; return n; }
    const context = freeze(Object.fromEntries(['ownerPubkey', 'requesterId', 'mentionPubkey', 'targetPubkey', 'channelId', 'threadId', 'source'].map(k => [k, c[k]])));
    const resolveEvent = createFileEventResolver({ directory: c.eventDirectory, uid: c.uid, clock, monotonic: mono });
    const authorize = createAuthorizationAdapter({ ...context, currentJob: c.currentJob, resolveEvent, clock });
    const journal = new HostOperatorJournal({ directory: c.journalDirectory, source: c.source, ownerPubkey: c.ownerPubkey, authorize, verifyReceipt: denied, clock });
    const store = createRevisionEvidenceStore({ directory: c.evidenceDirectory, uid: c.uid, ...pins });
    let inFlight = false;
    return Object.freeze({ async issue(raw, locator) {
      if (inFlight) denied(); inFlight = true; let stage = 'input';
      try {
        if (arguments.length !== 2) denied();
        const snapshot = rawBytes(raw), expected = evidenceData(locator); exact(expected, ['intentId', 'intentDigest']); identifier(expected.intentId); hexadecimal(expected.intentDigest);
        if (snapshot[0] === 0xef && snapshot[1] === 0xbb && snapshot[2] === 0xbf) denied(); stage = 'authorization';
        const r = verifyOwnerEvent(snapshot, { ...context, now: clock() }).request, d = descriptor(r, c.source);
        if (d.operationId !== 'status.revision') denied();
        function inspect() {
          const v = evidenceData(journal.inspectPendingExecution(r, expected)), i = v.intent; exact(v, ['intent', 'intentDigest']);
          if (v.intentDigest !== expected.intentDigest || digest(i) !== expected.intentDigest || i.intentId !== expected.intentId || i.requestHash !== digest(r) || i.descriptorDigest !== digest(d) || i.step !== 'execution' || i.deadline !== i.createdAt + 5000) denied();
          return i;
        }
        const first = inspect(), handle = store.reserveAttempt({ intentDigest: expected.intentDigest, requestHash: digest(r), descriptorDigest: digest(d), deadline: first.deadline });
        inspect(); const startedAt = clock(), startedMono = lastMono; if (startedAt >= first.deadline) denied();
        artifact(issuerFile, pins.issuerArtifactDigest); artifact(workerFile, pins.workerArtifactDigest);
        const spec = freeze({ executable: process.execPath, entry: workerFile,
          input: canonicalEvidence({ sourceDirectory: c.sourceDirectory, uid: c.uid, source: c.source, runId: handle.runId, requestHash: digest(r), intentDigest: expected.intentDigest, startedAt }),
          stdoutLimitBytes: 4096, stderrLimitBytes: 4096, inputLimitBytes: 8192,
          env: { LANG: 'C.UTF-8', TZ: 'UTC' }, runId: handle.runId, requestHash: digest(r), intentDigest: expected.intentDigest,
          workerArtifactDigest: pins.workerArtifactDigest, clockId: pins.clockId, startedAt, deadline: first.deadline, settlementWaitMs: c.settlementWaitMs });
        if (Buffer.byteLength(spec.input) > 8192) denied();
        let timer, answer;
        try { answer = await Promise.race([Promise.resolve().then(() => run(spec)), new Promise(resolve => { timer = setTimeout(() => resolve(null), c.settlementWaitMs); })]); }
        finally { clearTimeout(timer); }
        // Late settlement cannot attach a publication continuation to this call.
        if (!answer) return unknown();
        const a = evidenceData(answer); exact(a, ['status', 'boundary', 'stdout', 'stderr']);
        if (a.status !== 'settled' || typeof a.stdout !== 'string' || typeof a.stderr !== 'string') return unknown();
        const boundary = terminalBoundary(a.boundary, { runId: handle.runId, requestHash: digest(r), intentDigest: expected.intentDigest, workerArtifactDigest: pins.workerArtifactDigest, clockId: pins.clockId, startedAt });
        let finishedAt = clock(); if (boundary.settledAt > finishedAt || lastMono - startedMono > c.settlementWaitMs) return unknown();
        let result, code;
        if (Buffer.byteLength(a.stdout) > 4096 || Buffer.byteLength(a.stderr) > 4096) code = 'output_limit';
        else if (boundary.exitCode !== 0 || boundary.signal !== null) code = 'worker_failed';
        else {
          try {
            result = parseEvidence(a.stdout, 4096); exact(result, ['status', 'repository', 'workspaceId', 'expectedSha', 'observedSha', 'observedAt', 'runId', 'requestHash', 'intentDigest']); timestamp(result.observedAt);
            if (result.runId !== handle.runId || result.requestHash !== digest(r) || result.intentDigest !== expected.intentDigest) return unknown();
            if (result.repository !== c.source.repository || result.workspaceId !== c.source.workspaceId || result.expectedSha !== c.source.baseSha || !/^[a-f0-9]{40}$/.test(result.observedSha) || result.status !== (result.observedSha === c.source.baseSha ? 'observed' : 'mismatch') || result.observedAt < startedAt || result.observedAt > boundary.settledAt) code = 'worker_failed';
          } catch { code = 'worker_failed'; }
        }
        if (!code) {
          try { inspect(); } catch { code = 'postcondition_denied'; }
          finishedAt = clock(); if (finishedAt >= first.deadline || lastMono - startedMono >= first.deadline - startedAt) code = 'deadline_exceeded';
        }
        finishedAt = clock();
        if (!code && (finishedAt >= first.deadline || lastMono - startedMono >= first.deadline - startedAt)) code = 'deadline_exceeded';
        const outcome = code ? 'failed' : 'success';
        if (code) result = { status: 'failed', code, runId: handle.runId, requestHash: digest(r), intentDigest: expected.intentDigest };
        const proof = { version: 2, type: 'host-operator.revision-completion', authorityId: pins.authorityId, completionId: handle.runId,
          requestHash: digest(r), intentId: expected.intentId, intentDigest: expected.intentDigest, descriptorDigest: digest(d), startedAt, finishedAt, outcome,
          execution: { kind: 'supervised_process_v1', settled: true, descendants: 0, runId: handle.runId, boundaryId: boundary.boundaryId, boundaryDigest: digest(boundary), workerArtifactDigest: pins.workerArtifactDigest },
          resultDigest: digest(result), summary: { passed: 0, failed: 0, skipped: 0, exitCode: null, signal: null }, issuerArtifactDigest: pins.issuerArtifactDigest, clockId: pins.clockId };
        const evidence = store.publish(handle, { version: 1, proof, result, boundary });
        return freeze({ status: 'issued', outcome, evidence });
      } catch { if (stage === 'input') denied(); return unknown(); }
      finally { inFlight = false; }
    } });
  } catch { denied(); }
}
