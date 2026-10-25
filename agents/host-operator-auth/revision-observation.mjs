// Authorized pending observation only; never claims, consumes or completes execution.
import fs from 'node:fs';
import path from 'node:path';
import { types } from 'node:util';
import { verifyOwnerEvent } from './owner-event.mjs';
import { createFileEventResolver } from './event-source.mjs';
import { createAuthorizationAdapter } from './authorization.mjs';
import { createDetachedRevisionObserver } from './revision-source.mjs';
import { HostOperatorJournal } from '../scripts/host-operator-journal.mjs';
import { binding, descriptor, digest, exact, bounded, identifier, hexadecimal, timestamp } from '../scripts/host-operator-protocol.mjs';

const denied = () => { const e = Error('revision_observation_denied'); e.code = 'revision_observation_denied'; e.stack = 'revision_observation_denied'; throw e; };
function own(value) {
  if (!value || typeof value !== 'object' || types.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) denied();
  const props = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(props).some(k => typeof k !== 'string' || !Object.hasOwn(props[k], 'value') || !props[k].enumerable)) denied();
  return Object.fromEntries(Object.entries(props).map(([k, p]) => [k, p.value]));
}
function data(value, depth = 0, budget = { nodes: 0, bytes: 0 }) {
  if (++budget.nodes > 256 || depth > 8) denied();
  if (typeof value === 'string') { budget.bytes += Buffer.byteLength(value); if (budget.bytes > 4096) denied(); return value; }
  if (value === null || typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value))) return value;
  return Object.fromEntries(Object.entries(own(value)).map(([k, v]) => [k, data(v, depth + 1, budget)]));
}
function bytes(raw) {
  if (typeof raw === 'string') {
    if (!raw.isWellFormed() || Buffer.byteLength(raw) < 1 || Buffer.byteLength(raw) > 16384) denied();
    return Buffer.from(raw);
  }
  if (!raw || typeof raw !== 'object' || types.isProxy(raw) || !Buffer.isBuffer(raw) || Object.getPrototypeOf(raw) !== Buffer.prototype) denied();
  const typed = Object.getPrototypeOf(Uint8Array.prototype), length = Object.getOwnPropertyDescriptor(typed, 'byteLength').get.call(raw);
  if (length < 1 || length > 16384 || types.isSharedArrayBuffer(Object.getOwnPropertyDescriptor(typed, 'buffer').get.call(raw))) denied();
  const props = Object.getOwnPropertyDescriptors(raw), keys = Reflect.ownKeys(props);
  if (keys.length !== length || keys.some((k, i) => k !== String(i) || !Object.hasOwn(props[k], 'value'))) denied();
  return Buffer.from(keys.map(k => props[k].value));
}
function namespace(root, uid, privateRoot) {
  if (typeof root !== 'string' || !root.isWellFormed() || root.includes('\0') || root.endsWith('/') || !path.isAbsolute(root) || path.normalize(root) !== root || Buffer.byteLength(root) > 4000 || fs.realpathSync(root) !== root) denied();
  for (let p = root; ; p = path.dirname(p)) {
    const s = fs.lstatSync(p), tmp = p === '/tmp' && (s.mode & 0o1000) && [0, uid].includes(s.uid);
    if (!s.isDirectory() || s.isSymbolicLink() || ![0, uid].includes(s.uid) || (!tmp && (s.mode & 0o7022)) || (privateRoot && p === root && (s.uid !== uid || (s.mode & 0o7777) !== 0o700))) denied();
    if (p === path.dirname(p)) break;
  }
}
function pending(value, r, expected, source) {
  const result = data(value); bounded(result, 4096); exact(result, ['intent', 'intentDigest']);
  const i = result.intent, d = descriptor(r, source);
  exact(i, ['version', 'intentId', 'requestHash', 'descriptorDigest', 'step', 'sequence', 'createdAt', 'deadline', 'payload']);
  timestamp(i.createdAt); timestamp(i.deadline);
  if (result.intentDigest !== expected.intentDigest || i.intentId !== expected.intentId || digest(i) !== expected.intentDigest ||
      i.version !== 1 || i.step !== 'execution' || i.requestHash !== digest(r) || i.descriptorDigest !== digest(d) || !Number.isSafeInteger(i.sequence) || i.sequence < 0 || i.sequence > 4 || i.deadline !== i.createdAt + d.timeoutMs) denied();
  exact(i.payload, ['descriptor']); if (digest(i.payload.descriptor) !== digest(d)) denied(); return result;
}

export function createRevisionObservationBridge(options) {
  try {
    const config = own(options), required = ['eventDirectory', 'journalDirectory', 'sourceDirectory', 'uid', 'ownerPubkey', 'requesterId', 'mentionPubkey', 'targetPubkey', 'channelId', 'threadId', 'source', 'currentJob', 'verifyReceipt'];
    if (Object.keys(config).some(k => ![...required, 'clock', 'monotonic'].includes(k)) || required.some(k => !Object.hasOwn(config, k)) ||
        process.platform !== 'linux' || !Number.isSafeInteger(config.uid) || config.uid <= 0 || config.uid !== process.getuid() || typeof config.currentJob !== 'function' || typeof config.verifyReceipt !== 'function' ||
        (config.clock !== undefined && typeof config.clock !== 'function') || (config.monotonic !== undefined && typeof config.monotonic !== 'function')) denied();
    config.source = Object.freeze(binding(own(config.source)));
    const roots = [config.eventDirectory, config.journalDirectory, config.sourceDirectory];
    roots.forEach((p, i) => namespace(p, config.uid, i < 2));
    for (const a of roots) for (const b of roots) if (a !== b && !path.relative(a, b).startsWith('..' + path.sep)) denied();
    if (new Set(roots).size !== 3) denied();
    const selectedClock = config.clock ?? Date.now; let previous = -1;
    const clock = () => { const now = selectedClock(); timestamp(now); if (now < previous) denied(); previous = now; return now; };
    const context = Object.freeze(Object.fromEntries(['ownerPubkey', 'requesterId', 'mentionPubkey', 'targetPubkey', 'channelId', 'threadId', 'source'].map(k => [k, config[k]])));
    const timing = { clock, ...(config.monotonic && { monotonic: config.monotonic }) };
    const resolveEvent = createFileEventResolver({ directory: config.eventDirectory, uid: config.uid, ...timing });
    const authorize = createAuthorizationAdapter({ ...context, currentJob: config.currentJob, resolveEvent, clock });
    const journal = new HostOperatorJournal({ directory: config.journalDirectory, source: context.source, ownerPubkey: context.ownerPubkey, authorize, verifyReceipt: config.verifyReceipt, clock });
    const observer = createDetachedRevisionObserver({ sourceDirectory: config.sourceDirectory, uid: config.uid, source: context.source, ...timing });
    return Object.freeze({ observe(raw, input) {
      try {
        if (arguments.length !== 2) denied();
        const rawSnapshot = bytes(raw), expected = data(input); exact(expected, ['intentId', 'intentDigest']); identifier(expected.intentId); hexadecimal(expected.intentDigest);
        if (rawSnapshot[0] === 0xef && rawSnapshot[1] === 0xbb && rawSnapshot[2] === 0xbf) denied();
        const started = clock(), proof = verifyOwnerEvent(rawSnapshot, { ...context, now: started }), r = proof.request;
        const first = pending(journal.inspectPendingExecution(r, expected), r, expected, context.source);
        const observation = data(observer.observe());
        exact(observation, ['status', 'repository', 'workspaceId', 'expectedSha', 'observedSha', 'observedAt']);
        timestamp(observation.observedAt);
        if (observation.repository !== context.source.repository || observation.workspaceId !== context.source.workspaceId || observation.expectedSha !== context.source.baseSha ||
            typeof observation.observedSha !== 'string' || !/^[a-f0-9]{40}$/.test(observation.observedSha) || observation.status !== (observation.observedSha === context.source.baseSha ? 'observed' : 'mismatch') || observation.observedAt < started) denied();
        const last = pending(journal.inspectPendingExecution(r, expected), r, expected, context.source), now = clock();
        if (last.intentDigest !== first.intentDigest || observation.observedAt > now || now >= last.intent.deadline) denied();
        const result = { status: observation.status, intentId: expected.intentId, intentDigest: expected.intentDigest, requestHash: digest(r),
          descriptorDigest: digest(descriptor(r, context.source)), observation: Object.freeze(observation) };
        bounded(result, 4096); return Object.freeze(result);
      } catch { denied(); }
    } });
  } catch { denied(); }
}
