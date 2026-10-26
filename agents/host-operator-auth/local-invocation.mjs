// One new-event invocation; observation is non-consuming and never a receipt.
import { types } from 'node:util';
import { verifyOwnerEvent } from './owner-event.mjs';
import { createRevisionObservationBridge } from './revision-observation.mjs';
import { createLocalEventIngress } from './local-ingress.mjs';
import { binding, descriptor, digest, exact, bounded, identifier, hexadecimal, timestamp } from '../scripts/host-operator-protocol.mjs';

const denied = () => { const e = Error('local_invocation_denied'); e.code = 'local_invocation_denied'; e.stack = 'local_invocation_denied'; throw e; };
function own(value) {
  if (!value || typeof value !== 'object' || types.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) denied();
  const props = Object.getOwnPropertyDescriptors(value), keys = Reflect.ownKeys(props);
  if (keys.length > 32 || keys.some(k => typeof k !== 'string' || !Object.hasOwn(props[k], 'value') || !props[k].enumerable)) denied();
  return Object.fromEntries(keys.map(k => [k, props[k].value]));
}
function data(value, depth = 0, budget = { nodes: 0, bytes: 0 }) {
  if (++budget.nodes > 256 || depth > 8) denied();
  if (typeof value === 'string') { budget.bytes += Buffer.byteLength(value); if (budget.bytes > 8192) denied(); return value; }
  if (value === null || typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value))) return value;
  return Object.fromEntries(Object.entries(own(value)).map(([k, v]) => [k, data(v, depth + 1, budget)]));
}
function rawSnapshot(raw) {
  let bytes;
  if (typeof raw === 'string') {
    if (!raw.isWellFormed() || Buffer.byteLength(raw) < 1 || Buffer.byteLength(raw) > 16384) denied();
    bytes = Buffer.from(raw);
  } else {
    if (!raw || typeof raw !== 'object' || types.isProxy(raw) || !Buffer.isBuffer(raw) || Object.getPrototypeOf(raw) !== Buffer.prototype) denied();
    const typed = Object.getPrototypeOf(Uint8Array.prototype), length = Object.getOwnPropertyDescriptor(typed, 'byteLength').get.call(raw);
    if (length < 1 || length > 16384 || types.isSharedArrayBuffer(Object.getOwnPropertyDescriptor(typed, 'buffer').get.call(raw))) denied();
    const props = Object.getOwnPropertyDescriptors(raw), keys = Reflect.ownKeys(props);
    if (keys.length !== length || keys.some((k, i) => k !== String(i) || !Object.hasOwn(props[k], 'value'))) denied();
    bytes = Buffer.from(keys.map(k => props[k].value));
  }
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) denied();
  return bytes;
}
function frozen(value) { if (value && typeof value === 'object') { Object.values(value).forEach(frozen); Object.freeze(value); } return value; }
const stopped = (stage, code, admittedIntent) => frozen({ status: 'not_observed', stage, code, ...(admittedIntent && { admittedIntent }) });
function admission(input, operation) {
  const value = data(input); bounded(value, 8192);
  const fixed = ['ingress_denied', 'placement_unconfirmed', 'placement_conflict', 'placement_denied', 'admission_denied'];
  if (fixed.includes(value.status)) { exact(value, ['status', 'code']); if (value.code !== value.status) denied(); return { stop: value.status }; }
  if (value.status === 'blocked') {
    exact(value, ['status', 'code']); if (!['request_conflict', 'workspace_busy', 'journal_locked', 'journal_full', 'host_preparation_required'].includes(value.code)) denied();
    return { stop: value.code };
  }
  if (value.status === 'outcome_unknown') {
    if (value.code === 'journal_unconfirmed') exact(value, ['status', 'code']);
    else { exact(value, ['status', 'code', 'intentId']); identifier(value.intentId); if (!['pending_effect', 'deadline_elapsed'].includes(value.code)) denied(); }
    return { stop: value.code === 'journal_unconfirmed' ? 'admission_unconfirmed' : 'outcome_unknown' };
  }
  // Nonexecution results stop; neither public receipt nor report payload is projected.
  if (value.status === 'complete') { exact(value, ['status', 'result']); return { stop: 'complete' }; }
  if (value.status !== 'intent') denied();
  exact(value, ['status', 'intent', 'intentDigest']);
  const i = value.intent;
  exact(i, ['version', 'intentId', 'requestHash', 'descriptorDigest', 'step', 'sequence', 'createdAt', 'deadline', 'payload']);
  identifier(i.intentId); hexadecimal(value.intentDigest); hexadecimal(i.requestHash); hexadecimal(i.descriptorDigest); timestamp(i.createdAt); timestamp(i.deadline);
  if (i.version !== 1 || !Number.isSafeInteger(i.sequence) || i.sequence < 0 || i.sequence > 4 || digest(i) !== value.intentDigest) denied();
  if (['kaneo', 'buzz', 'user'].includes(i.step)) return { stop: 'nonexecution_intent' };
  if (i.step !== 'execution' || i.deadline !== i.createdAt + operation.timeoutMs || i.descriptorDigest !== digest(operation)) denied();
  exact(i.payload, ['descriptor']); if (digest(i.payload.descriptor) !== digest(operation)) denied();
  return { expected: { intentId: i.intentId, intentDigest: value.intentDigest }, requestHash: i.requestHash };
}
function observation(input, admitted, operation) {
  const value = data(input); bounded(value, 4096);
  exact(value, ['status', 'intentId', 'intentDigest', 'requestHash', 'descriptorDigest', 'observation']);
  const p = value.observation;
  exact(p, ['status', 'repository', 'workspaceId', 'expectedSha', 'observedSha', 'observedAt']); timestamp(p.observedAt);
  if (value.intentId !== admitted.expected.intentId || value.intentDigest !== admitted.expected.intentDigest || value.requestHash !== admitted.requestHash ||
      value.descriptorDigest !== digest(operation) || p.repository !== operation.repository || p.workspaceId !== operation.workspaceId || p.expectedSha !== operation.baseSha ||
      typeof p.observedSha !== 'string' || !/^[a-f0-9]{40}$/.test(p.observedSha) || p.status !== (p.observedSha === operation.baseSha ? 'observed' : 'mismatch') || value.status !== p.status) denied();
  return value;
}
export function createLocalRevisionInvocation(options) {
  try {
    const config = own(options), required = ['eventDirectory', 'journalDirectory', 'sourceDirectory', 'uid', 'ownerPubkey', 'requesterId', 'mentionPubkey', 'targetPubkey', 'channelId', 'threadId', 'source', 'currentJob', 'verifyReceipt'];
    if (Object.keys(config).some(k => ![...required, 'clock', 'monotonic'].includes(k)) || required.some(k => !Object.hasOwn(config, k)) ||
        (config.clock !== undefined && typeof config.clock !== 'function')) denied();
    config.source = Object.freeze(binding(own(config.source)));
    const selectedClock = config.clock ?? Date.now; let previous = -1;
    config.clock = () => { const now = selectedClock(); timestamp(now); if (now < previous) denied(); previous = now; return now; };
    const operation = descriptor({ ...config.source, operationId: 'status.revision' }, config.source);
    const bridge = createRevisionObservationBridge(config); // Source preflight BEFORE any admission.
    const ingress = createLocalEventIngress(Object.fromEntries([...required.filter(k => k !== 'sourceDirectory'), 'clock', ...(Object.hasOwn(config, 'monotonic') ? ['monotonic'] : [])].map(k => [k, config[k]])));
    const context = Object.freeze(Object.fromEntries(['ownerPubkey', 'requesterId', 'mentionPubkey', 'targetPubkey', 'channelId', 'threadId', 'source'].map(k => [k, config[k]])));
    let inFlight = false;
    return Object.freeze({ invoke(raw) {
      if (inFlight) denied();
      inFlight = true; let stage = 'input', admitted;
      try {
        if (arguments.length !== 1) denied();
        const snapshot = rawSnapshot(raw);
        stage = 'admission'; admitted = admission(ingress.ingest(snapshot), operation);
        if (admitted.stop) return stopped(stage, admitted.stop);
        stage = 'observation';
        const actual = observation(bridge.observe(snapshot, admitted.expected), admitted, operation);
        const result = { status: actual.status, admittedIntent: admitted.expected, observation: actual };
        bounded(result, 8192); return frozen(result);
      } catch {
        if (stage === 'input') denied();
        return stopped(stage, stage === 'observation' ? 'revision_observation_denied' : 'admission_unconfirmed', stage === 'observation' ? admitted.expected : undefined);
      } finally { inFlight = false; }
    }, resume(raw, locator) {
      if (inFlight) denied();
      inFlight = true; let stage = 'input';
      try {
        if (arguments.length !== 2) denied();
        // Detach BOTH untrusted inputs before the first trusted clock/provider call.
        const snapshot = rawSnapshot(raw), expected = data(locator);
        exact(expected, ['intentId', 'intentDigest']); identifier(expected.intentId); hexadecimal(expected.intentDigest);
        bounded(expected, 4096);
        stage = 'resume';
        const proof = verifyOwnerEvent(snapshot, { ...context, now: config.clock() });
        const actual = observation(bridge.observe(snapshot, expected), { expected, requestHash: digest(proof.request) }, operation);
        const result = { status: actual.status, admittedIntent: expected, observation: actual };
        bounded(result, 8192); return frozen(result);
      } catch {
        if (stage === 'input') denied();
        return stopped('resume', 'revision_observation_denied');
      } finally { inFlight = false; }
    } });
  } catch { denied(); }
}
