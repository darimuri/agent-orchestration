// One explicit local call, DATA admission only. No transport, dispatch or receipt endpoint.
import fs from 'node:fs';
import path from 'node:path';
import { types } from 'node:util';
import { createFileEventPlacer } from './event-placement.mjs';
import { createFileEventResolver } from './event-source.mjs';
import { verifyOwnerEvent } from './owner-event.mjs';
import { createAuthorizationAdapter } from './authorization.mjs';
import { HostOperatorJournal } from '../scripts/host-operator-journal.mjs';
import { ProtocolError, binding, descriptor, digest, exact, bounded, identifier, hexadecimal, timestamp } from '../scripts/host-operator-protocol.mjs';

const deny = () => { const e = Error('ingress_denied'); e.code = 'ingress_denied'; e.stack = 'ingress_denied'; throw e; };
const fixed = (status, code = status) => Object.freeze({ status, code });
function protocolCode(error) {
  try {
    if (!error || types.isProxy(error) || !(error instanceof ProtocolError)) return null;
    const p = Object.getOwnPropertyDescriptor(error, 'code');
    return p && Object.hasOwn(p, 'value') && typeof p.value === 'string' ? p.value : null;
  } catch { return null; }
}
function own(value) {
  if (!value || typeof value !== 'object' || types.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) deny();
  const props = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(props).some(k => typeof k !== 'string' || !Object.hasOwn(props[k], 'value') || !props[k].enumerable)) deny();
  return Object.fromEntries(Object.entries(props).map(([k, p]) => [k, p.value]));
}
function rawBytes(raw) {
  if (typeof raw === 'string') {
    if (!raw.isWellFormed() || Buffer.byteLength(raw) < 1 || Buffer.byteLength(raw) > 16384) deny();
    return Buffer.from(raw);
  }
  if (!raw || typeof raw !== 'object' || types.isProxy(raw) || !Buffer.isBuffer(raw) || Object.getPrototypeOf(raw) !== Buffer.prototype) deny();
  const typed = Object.getPrototypeOf(Uint8Array.prototype);
  const length = Object.getOwnPropertyDescriptor(typed, 'byteLength').get.call(raw);
  const backing = Object.getOwnPropertyDescriptor(typed, 'buffer').get.call(raw);
  if (length < 1 || length > 16384 || types.isSharedArrayBuffer(backing)) deny();
  const props = Object.getOwnPropertyDescriptors(raw), keys = Reflect.ownKeys(props);
  if (keys.length !== length || keys.some((k, i) => k !== String(i) || !Object.hasOwn(props[k], 'value'))) deny();
  return Buffer.from(keys.map(k => props[k].value));
}
function namespace(directory, uid) {
  if (typeof directory !== 'string' || !directory.isWellFormed() || directory.includes('\0') || directory.endsWith('/') || !path.isAbsolute(directory) || path.normalize(directory) !== directory || Buffer.byteLength(directory) > 4000 || fs.realpathSync(directory) !== directory) deny();
  for (let p = directory; ; p = path.dirname(p)) {
    const s = fs.lstatSync(p), tmp = p === '/tmp' && (s.mode & 0o1000) && [0, uid].includes(s.uid);
    if (!s.isDirectory() || s.isSymbolicLink() || ![0, uid].includes(s.uid) || (!tmp && (s.mode & 0o022)) || (p === directory && (s.uid !== uid || (s.mode & 0o7777) !== 0o700))) deny();
    if (p === path.dirname(p)) break;
  }
}
function snapshot(value, depth = 0, budget = { nodes: 0, bytes: 0 }) {
  if (++budget.nodes > 4096 || depth > 16) deny();
  if (typeof value === 'string') { budget.bytes += Buffer.byteLength(value); if (budget.bytes > 8192) deny(); return value; }
  if (value === null || typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value))) return value;
  // Current journal DATA result shapes contain ordinary objects, never arrays/functions/promises.
  return Object.fromEntries(Object.entries(own(value)).map(([k, v]) => [k, snapshot(v, depth + 1, budget)]));
}
function execution(value) {
  if (value === null) return null;
  exact(value, ['version', 'receiptId', 'intentId', 'intentDigest', 'requestHash', 'step', 'outcome', 'finishedAt', 'evidenceRef', 'evidenceDigest', 'summary']);
  for (const k of ['receiptId', 'intentId', 'evidenceRef']) identifier(value[k]);
  for (const k of ['intentDigest', 'requestHash', 'evidenceDigest']) hexadecimal(value[k]);
  timestamp(value.finishedAt);
  if (value.version !== 1 || value.step !== 'execution' || !['success', 'failed', 'needs_user'].includes(value.outcome)) deny();
  exact(value.summary, ['passed', 'failed', 'skipped', 'exitCode', 'signal']);
  for (const k of ['passed', 'failed', 'skipped']) if (!Number.isSafeInteger(value.summary[k]) || value.summary[k] < 0 || value.summary[k] > 1000000) deny();
  if (value.summary.exitCode !== null && (!Number.isInteger(value.summary.exitCode) || value.summary.exitCode < 0 || value.summary.exitCode > 255)) deny();
  if (![null, 'SIGTERM', 'SIGKILL'].includes(value.summary.signal)) deny();
  return value;
}
// Public shape projection, not a replacement journal schema or receipt verifier.
function publicData(input, r, config) {
  const value = snapshot(input); bounded(value, 8192);
  const d = descriptor(r, config.source);
  const publicResult = result => {
    exact(result, ['version', 'requestId', 'taskId', 'jobId', 'repository', 'baseSha', 'operationId', 'registryVersion', 'workspaceId', 'requesterId', 'execution']);
    const expected = { version: 1, requestId: r.requestId, taskId: r.taskId, jobId: r.jobId, repository: r.repository, baseSha: r.baseSha,
      operationId: r.operationId, registryVersion: d.registryVersion, workspaceId: d.workspaceId, requesterId: config.requesterId };
    for (const [k, v] of Object.entries(expected)) if (result[k] !== v) deny();
    execution(result.execution); return result;
  };
  if (value.status === 'complete') { exact(value, ['status', 'result']); publicResult(value.result); }
  else if (value.status === 'outcome_unknown') {
    exact(value, ['status', 'code', 'intentId']); identifier(value.intentId);
    if (!['pending_effect', 'deadline_elapsed'].includes(value.code)) deny();
  } else if (value.status === 'blocked') {
    exact(value, ['status', 'code']); if (value.code !== 'host_preparation_required') deny();
  } else if (value.status === 'intent') {
    exact(value, ['status', 'intent', 'intentDigest']);
    const i = value.intent;
    exact(i, ['version', 'intentId', 'requestHash', 'descriptorDigest', 'step', 'sequence', 'createdAt', 'deadline', 'payload']);
    identifier(i.intentId); timestamp(i.createdAt); timestamp(i.deadline); hexadecimal(value.intentDigest);
    if (i.version !== 1 || i.requestHash !== digest(r) || i.descriptorDigest !== digest(d) || !Number.isSafeInteger(i.sequence) || i.sequence < 0 || i.sequence > 4 ||
        i.deadline !== i.createdAt + (i.step === 'execution' ? d.timeoutMs : 60000) || value.intentDigest !== digest(i)) deny();
    if (i.step === 'execution') { exact(i.payload, ['descriptor']); if (digest(i.payload.descriptor) !== digest(d)) deny(); }
    else if (i.step === 'kaneo') { exact(i.payload, ['taskId', 'result']); if (i.payload.taskId !== r.taskId) deny(); publicResult(i.payload.result); }
    else if (i.step === 'buzz') {
      exact(i.payload, ['channelId', 'threadId', 'mentionPubkey', 'result']);
      if (i.payload.channelId !== r.channelId || i.payload.threadId !== r.threadId || i.payload.mentionPubkey !== config.mentionPubkey) deny(); publicResult(i.payload.result);
    } else deny(); // A1 currently accepts status.revision only; no user action exists for it.
  } else deny();
  return value;
}

export function createLocalEventIngress(options) {
  try {
    const config = own(options), required = ['eventDirectory', 'journalDirectory', 'uid', 'ownerPubkey', 'requesterId', 'mentionPubkey', 'targetPubkey', 'channelId', 'threadId', 'source', 'currentJob', 'verifyReceipt'];
    if (Object.keys(config).some(k => ![...required, 'clock', 'monotonic'].includes(k)) || required.some(k => !Object.hasOwn(config, k))) deny();
    if (process.platform !== 'linux' || !Number.isSafeInteger(config.uid) || config.uid <= 0 || config.uid !== process.getuid() || typeof config.currentJob !== 'function' || typeof config.verifyReceipt !== 'function' ||
        (config.clock !== undefined && typeof config.clock !== 'function') || (config.monotonic !== undefined && typeof config.monotonic !== 'function')) deny();
    config.source = Object.freeze(binding(own(config.source)));
    namespace(config.eventDirectory, config.uid); namespace(config.journalDirectory, config.uid);
    const relative = path.relative(config.eventDirectory, config.journalDirectory), reverse = path.relative(config.journalDirectory, config.eventDirectory);
    if (!relative || !relative.startsWith('..' + path.sep) || !reverse.startsWith('..' + path.sep)) deny();
    const selectedClock = config.clock ?? Date.now;
    let previous = -1;
    const clock = () => { const now = selectedClock(); timestamp(now); if (now < previous) deny(); previous = now; return now; };
    const context = Object.freeze(Object.fromEntries(['ownerPubkey', 'requesterId', 'mentionPubkey', 'targetPubkey', 'channelId', 'threadId', 'source'].map(k => [k, config[k]])));
    const placer = createFileEventPlacer({ directory: config.eventDirectory, uid: config.uid, ...Object.fromEntries(['ownerPubkey', 'targetPubkey', 'channelId', 'threadId', 'source'].map(k => [k, context[k]])), clock });
    const resolveEvent = createFileEventResolver({ directory: config.eventDirectory, uid: config.uid, clock, ...(config.monotonic && { monotonic: config.monotonic }) });
    const authorize = createAuthorizationAdapter({ ...context, currentJob: config.currentJob, resolveEvent, clock });
    const journal = new HostOperatorJournal({ directory: config.journalDirectory, source: context.source, ownerPubkey: context.ownerPubkey, authorize, verifyReceipt: config.verifyReceipt, clock });
    return Object.freeze({ ingest(raw) {
      let stage = 'input';
      try {
        if (arguments.length !== 1) deny();
        const bytes = rawBytes(raw);
        // Keep the serialized input boundary strict; TextDecoder otherwise strips a UTF-8 BOM.
        if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) deny();
        const now = clock(); timestamp(now);
        const proof = verifyOwnerEvent(bytes, { ...context, now });
        stage = 'placement';
        const placed = own(placer.place(bytes));
        exact(placed, ['status', 'code', 'eventId']);
        if (placed.eventId !== proof.request.authorizationEventId) deny();
        if (placed.status === 'already_present' && placed.code === 'durability_unproven') return fixed('placement_unconfirmed');
        if (placed.status === 'conflict' && placed.code === 'conflict') return fixed('placement_conflict');
        if (placed.status === 'denied' && placed.code === 'denied') return fixed('placement_denied');
        if (placed.status === 'outcome_unknown' && placed.code === 'outcome_unknown') return fixed('placement_unconfirmed');
        if (placed.status !== 'confirmed' || placed.code !== 'durability_confirmed') deny();
        stage = 'journal';
        const value = journal.next(proof.request); // Exactly once, only this invocation's confirmed placement.
        stage = 'result'; return publicData(value, proof.request, context);
      } catch (e) {
        const code = protocolCode(e);
        if (stage === 'input') return fixed('ingress_denied');
        if (stage === 'placement') return fixed('placement_denied');
        if (stage === 'journal' && ['authorization_denied', 'scope_mismatch', 'operation_denied'].includes(code)) return fixed('admission_denied');
        if (stage === 'journal' && ['request_conflict', 'workspace_busy', 'journal_locked', 'journal_full', 'host_preparation_required'].includes(code)) return fixed('blocked', code);
        return fixed('outcome_unknown', 'journal_unconfirmed');
      }
    } });
  } catch { deny(); }
}
