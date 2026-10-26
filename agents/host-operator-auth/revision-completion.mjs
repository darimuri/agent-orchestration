// Verifies independently resolved terminal evidence; never produces execution proof.
import { types } from 'node:util';
import { isSupervisedResolver } from './revision-evidence.mjs';
import { binding, request, identity, descriptor, receipt, digest, exact, bounded, identifier, hexadecimal, timestamp } from '../scripts/host-operator-protocol.mjs';

const denied = () => { const e = Error('revision_completion_denied'); e.code = 'revision_completion_denied'; e.stack = 'revision_completion_denied'; throw e; };
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
export function createRevisionCompletionVerifier(options) {
  try {
    const config = own(options); if (Object.keys(config).some(k => !['source', 'authorityId', 'resolveCompletion', 'clock', 'supervised'].includes(k)) ||
      ['source', 'authorityId', 'resolveCompletion'].some(k => !Object.hasOwn(config, k)) || typeof config.resolveCompletion !== 'function' ||
      (config.clock !== undefined && typeof config.clock !== 'function')) denied();
    const source = Object.freeze(binding(data(config.source))), authority = config.authorityId, resolve = config.resolveCompletion, selectedClock = config.clock ?? Date.now;
    let supervised;
    if (Object.hasOwn(config, 'supervised')) {
      supervised = data(config.supervised); exact(supervised, ['issuerArtifactDigest', 'workerArtifactDigest', 'clockId']);
      hexadecimal(supervised.issuerArtifactDigest); hexadecimal(supervised.workerArtifactDigest); identifier(supervised.clockId);
    }
    identifier(authority); let previous = -1;
    const clock = () => { const now = selectedClock(); timestamp(now); if (now < previous) denied(); previous = now; return now; };
    return function verify(evidence, intent, context) {
      try {
        if (arguments.length !== 3) denied();
        const locator = data(evidence), i = data(intent), ctx = data(context);
        exact(locator, ['ref', 'digest']); identifier(locator.ref); hexadecimal(locator.digest);
        exact(ctx, ['request', 'identity']); const r = request(ctx.request), who = identity(ctx.identity), d = descriptor(r, source);
        exact(i, ['version', 'intentId', 'requestHash', 'descriptorDigest', 'step', 'sequence', 'createdAt', 'deadline', 'payload']);
        identifier(i.intentId); timestamp(i.createdAt); timestamp(i.deadline); exact(i.payload, ['descriptor']);
        if (d.operationId !== 'status.revision' || d.privilege !== 'read_only' || d.userActionId !== null || who.eventId !== r.authorizationEventId ||
            i.version !== 1 || i.step !== 'execution' || i.sequence !== 0 || i.requestHash !== digest(r) || i.descriptorDigest !== digest(d) ||
            i.deadline !== i.createdAt + d.timeoutMs || digest(i.payload.descriptor) !== digest(d)) denied();
        clock(); // All caller data is detached before any trusted callback.
        const proof = data(resolve(locator.ref)), now = clock(); bounded(proof, 8192);
        const v2 = proof.version === 2;
        exact(proof, ['version', 'type', 'authorityId', 'completionId', 'requestHash', 'intentId', 'intentDigest', 'descriptorDigest', 'startedAt', 'finishedAt', 'outcome', 'execution', 'resultDigest', 'summary', ...(v2 ? ['issuerArtifactDigest', 'clockId'] : [])]);
        if (v2 && (!supervised || !isSupervisedResolver(resolve, { source, authorityId: authority, ...supervised }) || proof.issuerArtifactDigest !== supervised.issuerArtifactDigest || proof.clockId !== supervised.clockId)) denied();
        identifier(proof.completionId); hexadecimal(proof.resultDigest); timestamp(proof.startedAt); timestamp(proof.finishedAt);
        exact(proof.execution, ['kind', 'settled', 'descendants', ...(v2 ? ['runId', 'boundaryId', 'boundaryDigest', 'workerArtifactDigest'] : [])]);
        if (v2) { identifier(proof.execution.runId); identifier(proof.execution.boundaryId); hexadecimal(proof.execution.boundaryDigest);
          if (proof.completionId !== proof.execution.runId || proof.execution.workerArtifactDigest !== supervised.workerArtifactDigest) denied(); }
        exact(proof.summary, ['passed', 'failed', 'skipped', 'exitCode', 'signal']);
        if ((!v2 && proof.version !== 1) || proof.type !== 'host-operator.revision-completion' || proof.authorityId !== authority ||
            proof.requestHash !== digest(r) || proof.intentId !== i.intentId || proof.intentDigest !== digest(i) || proof.descriptorDigest !== digest(d) ||
            !['success', 'failed'].includes(proof.outcome) || proof.execution.kind !== (v2 ? 'supervised_process_v1' : 'in_process_read_only') || proof.execution.settled !== true || proof.execution.descendants !== 0 ||
            proof.startedAt < i.createdAt || proof.finishedAt < proof.startedAt || proof.finishedAt > now || (proof.outcome === 'success' && proof.finishedAt >= i.deadline) ||
            ['passed', 'failed', 'skipped'].some(k => proof.summary[k] !== 0) || proof.summary.exitCode !== null || proof.summary.signal !== null || digest(proof) !== locator.digest) denied();
        return receipt({ version: 1, receiptId: proof.completionId, intentId: i.intentId, intentDigest: digest(i), requestHash: digest(r), step: 'execution',
          outcome: proof.outcome, finishedAt: proof.finishedAt, evidenceRef: locator.ref, evidenceDigest: digest(proof), summary: proof.summary }, i, now);
      } catch { denied(); }
    };
  } catch { denied(); }
}
