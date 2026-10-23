// Offline protocol only. Trusted adapters are injected by the host, never by a request.
import { createHash } from 'node:crypto';

export class ProtocolError extends Error {
  constructor(code) { super(code); this.code = code; }
}
export const deny = code => { throw new ProtocolError(code); };
export const copy = value => JSON.parse(JSON.stringify(value));
export function exact(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join() !== [...keys].sort().join()) deny('schema');
}
export function bounded(value, bytes) {
  let encoded;
  try { encoded = JSON.stringify(value); } catch { deny('schema'); }
  if (typeof encoded !== 'string' || Buffer.byteLength(encoded) > bytes) deny('size_limit');
}
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(k => [k, canonical(value[k])]));
  return value;
}
export const digest = value => createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
const id = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const hex = /^[a-f0-9]{64}$/;
const patterns = {
  requestId: id, taskId: id, jobId: id,
  repository: /^[A-Za-z0-9][A-Za-z0-9_-]{0,99}\/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/,
  baseRef: /^[A-Za-z0-9][A-Za-z0-9/_.-]{0,127}$/,
  baseSha: /^[a-f0-9]{40}$/, operationId: /^[a-z]+\.[a-z-]{1,40}$/,
  channelId: /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/,
  threadId: hex, authorizationEventId: hex,
};
export function identifier(value) { if (typeof value !== 'string' || !id.test(value)) deny('schema'); }
export function hexadecimal(value) { if (typeof value !== 'string' || !hex.test(value)) deny('schema'); }
export function timestamp(value) { if (!Number.isSafeInteger(value) || value < 0) deny('schema'); }
export function request(input) {
  bounded(input, 4096);
  exact(input, ['version', ...Object.keys(patterns)]);
  if (input.version !== 1) deny('schema');
  for (const [k, p] of Object.entries(patterns)) if (typeof input[k] !== 'string' || !p.test(input[k])) deny('schema');
  if (input.repository.includes('..') || input.repository.endsWith('.git') ||
      input.baseRef.includes('..') || input.baseRef.includes('//') || input.baseRef.endsWith('/') ||
      input.baseRef.split('/').some(p => p.startsWith('.') || p.endsWith('.') || p.endsWith('.lock'))) deny('schema');
  return copy(input);
}

// Immutable names describe future reviewed operations. There are NO executable
// paths, shell snippets or runner functions in this registry or module.
const registry = Object.freeze({
  'status.revision': ['read_only', 5000, 4096, null],
  'validate.node': ['isolated_validation', 120000, 65536, null],
  'validate.resource-config': ['isolated_validation', 30000, 16384, 'prepare-host-fixture'],
  'validate.preflight': ['host_gate', 30000, 16384, 'prepare-host-fixture'],
  'validate.build-smoke': ['host_gate', 600000, 65536, 'prepare-host-fixture'],
  'validate.resources': ['host_gate', 120000, 65536, 'prepare-host-fixture'],
});
export function binding(value) {
  exact(value, ['repository', 'baseRef', 'baseSha', 'workspaceId', 'sourceDigest']);
  request({ version: 1, requestId: 'binding', taskId: 'binding', jobId: 'binding',
    ...Object.fromEntries(['repository', 'baseRef', 'baseSha'].map(k => [k, value[k]])),
    operationId: 'status.revision', channelId: '00000000-0000-0000-0000-000000000000',
    threadId: '0'.repeat(64), authorizationEventId: '0'.repeat(64) });
  identifier(value.workspaceId); hexadecimal(value.sourceDigest);
  return copy(value);
}
export function descriptor(r, source) {
  if (['repository', 'baseRef', 'baseSha'].some(k => r[k] !== source[k])) deny('scope_mismatch');
  if (!Object.hasOwn(registry, r.operationId)) deny('operation_denied');
  const [privilege, timeoutMs, outputBytes, userActionId] = registry[r.operationId];
  return { registryVersion: 'host-operator-offline-v1', operationId: r.operationId,
    ...source, privilege, timeoutMs, outputBytes, userActionId };
}
export function identity(value) {
  exact(value, ['requesterId', 'role', 'kind', 'eventId', 'signerPubkey', 'ownerPubkey', 'mentionPubkey']);
  identifier(value.requesterId);
  for (const k of ['eventId', 'signerPubkey', 'ownerPubkey', 'mentionPubkey']) hexadecimal(value[k]);
  if (!['owner_event', 'assignment'].includes(value.kind) ||
      !['owner', 'control', 'developer', 'reviewer'].includes(value.role) ||
      (value.kind === 'owner_event' && (value.role !== 'owner' || value.signerPubkey !== value.ownerPubkey)) ||
      (value.kind === 'assignment' && value.role === 'owner')) deny('authorization_denied');
  return copy(value);
}
export function authorize(adapter, r, operation, ownerPubkey, now) {
  let a;
  try {
    a = adapter(copy(r), copy(operation)); bounded(a, 4096);
    exact(a, ['requesterId', 'role', 'kind', 'eventId', 'signerPubkey', 'ownerPubkey', 'mentionPubkey',
      'requestHash', 'descriptorDigest', 'verifiedAt', 'expiresAt', 'enabled', 'status', 'taskId', 'jobId',
      'repository', 'baseRef', 'baseSha', 'operationId', 'channelId', 'threadId']);
    const who = identity(Object.fromEntries(['requesterId', 'role', 'kind', 'eventId', 'signerPubkey', 'ownerPubkey', 'mentionPubkey'].map(k => [k, a[k]])));
    timestamp(a.verifiedAt); timestamp(a.expiresAt);
    if (a.ownerPubkey !== ownerPubkey || a.eventId !== r.authorizationEventId ||
        a.requestHash !== digest(r) || a.descriptorDigest !== digest(operation) || a.enabled !== true || a.status !== 'active' ||
        a.verifiedAt > now || now - a.verifiedAt > 60000 || a.expiresAt <= now ||
        ['taskId', 'jobId', 'repository', 'baseRef', 'baseSha', 'operationId', 'channelId', 'threadId'].some(k => a[k] !== r[k])) deny('authorization_denied');
    return who;
  } catch { deny('authorization_denied'); }
}
export function userAction(actionId) {
  if (actionId !== 'prepare-host-fixture') deny('host_preparation_required');
  return { actionId, reason: 'host_preparation_required',
    command: ['HOST_OPERATOR_FIXTURE_ONLY', 'prepare-host'] };
}
export function receipt(value, intent, now) {
  bounded(value, 4096);
  exact(value, ['version', 'receiptId', 'intentId', 'intentDigest', 'requestHash', 'step',
    'outcome', 'finishedAt', 'evidenceRef', 'evidenceDigest', 'summary']);
  if (value.version !== 1) deny('receipt_invalid');
  for (const k of ['receiptId', 'intentId', 'evidenceRef']) identifier(value[k]);
  for (const k of ['intentDigest', 'requestHash', 'evidenceDigest']) hexadecimal(value[k]);
  timestamp(value.finishedAt);
  if (value.intentId !== intent.intentId || value.intentDigest !== digest(intent) ||
      value.requestHash !== intent.requestHash || value.step !== intent.step ||
      value.finishedAt < intent.createdAt || value.finishedAt > now) deny('receipt_invalid');
  const allowed = intent.step === 'execution' ? ['success', 'failed', 'needs_user', 'timeout', 'cancelled'] : ['success'];
  if (!allowed.includes(value.outcome)) deny('receipt_invalid');
  exact(value.summary, ['passed', 'failed', 'skipped', 'exitCode', 'signal']);
  for (const k of ['passed', 'failed', 'skipped']) if (!Number.isSafeInteger(value.summary[k]) || value.summary[k] < 0 || value.summary[k] > 1000000) deny('receipt_invalid');
  if (value.summary.exitCode !== null && (!Number.isInteger(value.summary.exitCode) || value.summary.exitCode < 0 || value.summary.exitCode > 255)) deny('receipt_invalid');
  if (![null, 'SIGTERM', 'SIGKILL'].includes(value.summary.signal)) deny('receipt_invalid');
  if (value.outcome === 'needs_user' && (value.summary.passed !== 0 || value.summary.failed !== 0 ||
      value.summary.skipped !== 0 || value.summary.exitCode !== null || value.summary.signal !== null)) deny('receipt_invalid');
  if (value.outcome === 'success' && (value.summary.failed !== 0 || value.summary.signal !== null || ![null, 0].includes(value.summary.exitCode))) deny('receipt_invalid');
  return copy(value);
}
export function publicReceipt(entry) {
  const executions = entry.effects.filter(e => e.intent.step === 'execution');
  return { version: 1, requestId: entry.request.requestId, taskId: entry.request.taskId,
    jobId: entry.request.jobId, repository: entry.request.repository, baseSha: entry.request.baseSha,
    operationId: entry.request.operationId, registryVersion: entry.descriptor.registryVersion,
    workspaceId: entry.descriptor.workspaceId, requesterId: entry.identity.requesterId,
    execution: executions.at(-1)?.receipt ?? null };
}
