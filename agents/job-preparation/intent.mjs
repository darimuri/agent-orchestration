// Source-only fixed admission policy. No request value is authority or a path.
import { createHash } from 'node:crypto';
import { types } from 'node:util';

export const deny = () => { const e = Error('admission_denied'); e.code = 'admission_denied'; throw e; };
export const canonical = value => JSON.stringify(value && typeof value === 'object'
  ? Array.isArray(value) ? value.map(v => JSON.parse(canonical(v)))
    : Object.fromEntries(Object.keys(value).sort().map(k => [k, JSON.parse(canonical(value[k]))])) : value);
export const digest = value => createHash('sha256').update(canonical(value)).digest('hex');
export function data(value, keys) {
  if (!value || types.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) deny();
  const descriptors = Object.getOwnPropertyDescriptors(value), names = Reflect.ownKeys(descriptors);
  if (names.length !== keys.length || names.some(k => typeof k !== 'string' || !keys.includes(k) || !descriptors[k].enumerable || !Object.hasOwn(descriptors[k], 'value'))) deny();
  return Object.fromEntries(names.map(k => [k, descriptors[k].value]));
}
export const identifier = value => { if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value)) deny(); return value; };
// Gateway src/jobs.ts jobSchema.id at reviewed tree24e0b0b79712d74d56a9231be056a2fef539370b.
export const jobId = value => { if (typeof value !== 'string' || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(value)) deny(); return value; };
export const requestId = value => { if (typeof value !== 'string' || !/^[a-f0-9]{32}$/.test(value)) deny(); return value; };
export const timestamp = value => {
  if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value) || !Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) deny();
  return Date.parse(value);
};
export const DEVELOPER_CAPABILITIES = Object.freeze([
  'repository:read', 'pull-request:read', 'branch-commit:create',
  'pull-request:create', 'pull-request:update', 'pull-request:ready',
  'issue:list', 'issue:search', 'issue:read', 'issue:create',
  'issue:update', 'issue:comment', 'issue:state',
]);
const policyKeys = ['version', 'ownerId', 'developerAgentId', 'repository', 'baseRef', 'baseSha', 'policyVersion', 'capabilityProfileVersion', 'capabilityProfileDigest', 'slotNamespace', 'approvalLifetimeMs', 'jobLifetimeMs', 'authorityTimeoutMs'];
export function fixedPolicy(input) {
  const p = data(input, policyKeys);
  for (const k of ['ownerId', 'policyVersion', 'capabilityProfileVersion', 'slotNamespace']) identifier(p[k]);
  jobId(p.developerAgentId);
  if (p.version !== 1 || typeof p.repository !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,99}\/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/.test(p.repository) || p.repository.includes('..') || p.repository.endsWith('.git') ||
      typeof p.baseRef !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9/_.-]{0,127}$/.test(p.baseRef) || p.baseRef.includes('..') || p.baseRef.includes('//') || p.baseRef.split('/').some(s => !s || s.startsWith('.') || s.endsWith('.') || s.endsWith('.lock')) ||
      typeof p.baseSha !== 'string' || !/^[a-f0-9]{40}$/.test(p.baseSha)) deny();
  for (const k of ['approvalLifetimeMs', 'jobLifetimeMs', 'authorityTimeoutMs']) if (!Number.isSafeInteger(p[k]) || p[k] < 1 || p[k] > (k === 'authorityTimeoutMs' ? 60000 : 604800000)) deny();
  if (p.approvalLifetimeMs > p.jobLifetimeMs || p.capabilityProfileDigest !== digest({ version: p.capabilityProfileVersion, role: 'developer', capabilities: DEVELOPER_CAPABILITIES })) deny();
  return Object.freeze(p);
}
const proposalKeys = ['version', 'requestId', 'jobId', 'repository', 'baseRef', 'baseSha', 'approvalExpiresAt', 'jobExpiresAt', 'taskId', 'assignmentId', 'channelId', 'threadId'];
// A depth-one JSON scanner detects duplicate *decoded* keys before JSON.parse.
export function parseProposal(raw) {
  try {
  let text;
  if (typeof raw === 'string') text = raw;
  else if (Buffer.isBuffer(raw) && raw.length <= 4096) text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(raw);
  else deny();
  if (Buffer.byteLength(text) > 4096 || !text.isWellFormed() || text.charCodeAt(0) === 0xfeff) deny();
  let i = 0; const seen = new Set(), ws = () => { while (/[\x20\t\r\n]/.test(text[i] ?? '') && i < text.length) i++; };
  const string = () => { const start = i++; while (i < text.length) { if (text[i] === '\\') { i += 2; continue; } if (text[i++] === '"') return JSON.parse(text.slice(start, i)); } deny(); };
  ws(); if (text[i++] !== '{') deny(); ws();
  while (text[i] !== '}') {
    if (text[i] !== '"') deny(); const key = string(); if (seen.has(key)) deny(); seen.add(key); ws(); if (text[i++] !== ':') deny(); ws();
    if (text[i] === '"') string(); else { const start = i; while (i < text.length && !/[,}\s]/.test(text[i])) i++; if (i === start || !/^(?:null|true|false|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)$/.test(text.slice(start, i))) deny(); }
    ws(); if (text[i] === '}') break; if (text[i++] !== ',') deny(); ws(); if (text[i] === '}') deny();
  }
  if (text[i++] !== '}') deny(); ws(); if (i !== text.length) deny();
  const p = data(JSON.parse(text), proposalKeys);
  if (p.version !== 1) deny(); requestId(p.requestId);
  jobId(p.jobId); for (const k of ['taskId', 'assignmentId']) identifier(p[k]);
  if (typeof p.channelId !== 'string' || !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(p.channelId) || typeof p.threadId !== 'string' || !/^[a-f0-9]{64}$/.test(p.threadId)) deny();
  timestamp(p.approvalExpiresAt); timestamp(p.jobExpiresAt);
  if (p.approvalExpiresAt > p.jobExpiresAt) deny(); return p;
  } catch { deny(); }
}
export function canonicalIntent(raw, inputPolicy) {
  const policy = fixedPolicy(inputPolicy), proposal = parseProposal(raw);
  if (['repository', 'baseRef', 'baseSha'].some(k => proposal[k] !== policy[k])) deny();
  const intent = { ...proposal, ownerId: policy.ownerId, agentId: policy.developerAgentId,
    role: 'developer', operation: 'prepare_developer_job_v1', policy,
    policyDigest: digest(policy), capabilityProfileVersion: policy.capabilityProfileVersion,
    capabilityProfileDigest: policy.capabilityProfileDigest, capabilities: [...DEVELOPER_CAPABILITIES],
    logicalSlot: `${policy.slotNamespace}:${proposal.requestId}`, proposerIdentity: 'unverified' };
  return JSON.parse(canonical(intent));
}
export function checkLifetime(intent, now) {
  if (!Number.isSafeInteger(now) || now < 0 || timestamp(intent.approvalExpiresAt) <= now || timestamp(intent.jobExpiresAt) <= now ||
      timestamp(intent.approvalExpiresAt) - now > intent.policy.approvalLifetimeMs || timestamp(intent.jobExpiresAt) - now > intent.policy.jobLifetimeMs) deny();
}
export function proposalFromIntent(intent) { return Object.fromEntries(proposalKeys.map(k => [k, intent[k]])); }
