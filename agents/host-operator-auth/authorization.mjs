// Host-selected synchronous seams only. No live/fallback policy or event reader.
import { deny, copy, exact, bounded, digest, identifier, hexadecimal, timestamp, binding,
  request, descriptor } from '../scripts/host-operator-protocol.mjs';
import { verifyOwnerEvent } from './owner-event.mjs';

// Normalize only ordinary own data; reject promises, prototypes, symbols and
// accessors before serialization. In-process malicious code is outside the boundary.
function data(value, depth = 0) {
  if (depth > 16) deny('authorization_denied');
  if (value === null || ['string', 'boolean'].includes(typeof value)) return value;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (!value || typeof value !== 'object' ||
      ![Object.prototype, Array.prototype].includes(Object.getPrototypeOf(value)) ||
      Object.getOwnPropertySymbols(value).length) deny('authorization_denied');
  const properties = Object.getOwnPropertyDescriptors(value);
  for (const [key, property] of Object.entries(properties)) {
    if (Array.isArray(value) && key === 'length') continue;
    if (!Object.hasOwn(property, 'value') || !property.enumerable) deny('authorization_denied');
  }
  if (Array.isArray(value)) {
    if (Object.keys(value).length !== value.length || Object.keys(value).some((k, i) => k !== String(i))) deny('authorization_denied');
    return value.map(v => data(v, depth + 1));
  }
  return Object.fromEntries(Object.entries(properties).map(([k, p]) => [k, data(p.value, depth + 1)]));
}

export function createAuthorizationAdapter({ ownerPubkey, requesterId, mentionPubkey, targetPubkey,
  channelId, threadId, source, resolveEvent, currentJob, clock = Date.now }) {
  try {
    for (const v of [ownerPubkey, mentionPubkey, targetPubkey, threadId]) hexadecimal(v);
    identifier(requesterId);
    if (typeof channelId !== 'string' || !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(channelId) ||
        typeof resolveEvent !== 'function' || typeof currentJob !== 'function' || typeof clock !== 'function') deny('authorization_denied');
    const trustedSource = binding(source);
    return (input, suppliedDescriptor) => {
      try {
        const now = clock(); timestamp(now);
        const r = request(data(input)), operation = descriptor(r, trustedSource);
        if (digest(data(suppliedDescriptor)) !== digest(operation)) deny('authorization_denied');
        const proof = verifyOwnerEvent(resolveEvent(r.authorizationEventId), {
          ownerPubkey, targetPubkey, channelId, threadId, source: trustedSource, now,
        });
        if (digest(proof.request) !== digest(r) || digest(proof.descriptor) !== digest(operation)) deny('authorization_denied');
        const who = { requesterId, role: 'owner', kind: 'owner_event', eventId: r.authorizationEventId,
          signerPubkey: proof.signerPubkey, ownerPubkey, mentionPubkey };
        const scope = Object.fromEntries(['taskId', 'jobId', 'repository', 'baseRef', 'baseSha',
          'operationId', 'channelId', 'threadId'].map(k => [k, r[k]]));
        const expected = { ...scope, requesterId, role: 'owner', ownerPubkey, mentionPubkey, targetPubkey,
          workspaceId: operation.workspaceId, sourceDigest: operation.sourceDigest,
          descriptorDigest: digest(operation), requestHash: digest(r),
          enabled: true, status: 'active', requesterMember: true, ownerAllowed: true,
          allowedOperations: ['status.revision'] };
        // DTO, not a Gateway ledger schema. Provider must derive these facts from
        // authoritative state. An echoed input/static assignment is not a provider.
        const facts = data(currentJob(copy(r), copy(who), copy(operation)));
        bounded(facts, 4096); exact(facts, [...Object.keys(expected), 'verifiedAt', 'expiresAt']);
        timestamp(facts.verifiedAt); timestamp(facts.expiresAt);
        if (facts.verifiedAt > now || now - facts.verifiedAt > 60000 || facts.expiresAt <= now ||
            digest(Object.fromEntries(Object.keys(expected).map(k => [k, facts[k]]))) !== digest(expected)) deny('authorization_denied');
        return { ...who, ...scope, requestHash: digest(r), descriptorDigest: digest(operation),
          enabled: true, status: 'active', verifiedAt: now, expiresAt: Math.min(proof.expiresAt, facts.expiresAt) };
      } catch { deny('authorization_denied'); }
    };
  } catch { deny('authorization_denied'); }
}
