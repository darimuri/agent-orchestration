import test from 'node:test';
import assert from 'node:assert/strict';
import { canonical, digest, DEVELOPER_CAPABILITIES, fixedPolicy, parseProposal, canonicalIntent, checkLifetime } from '../job-preparation/intent.mjs';

const epoch = Date.parse('2026-11-06T20:00:00.000Z');
const policy = () => ({ version: 1, ownerId: 'owner', developerAgentId: 'developer-a', repository: 'example/project', baseRef: 'main', baseSha: 'a'.repeat(40), policyVersion: 'p1', capabilityProfileVersion: 'developer-v1', capabilityProfileDigest: digest({ version: 'developer-v1', role: 'developer', capabilities: DEVELOPER_CAPABILITIES }), slotNamespace: 'managed-v1', approvalLifetimeMs: 10000, jobLifetimeMs: 20000, authorityTimeoutMs: 50 });
const proposal = () => ({ version: 1, requestId: '1'.repeat(32), jobId: 'age7-prejob', repository: 'example/project', baseRef: 'main', baseSha: 'a'.repeat(40), approvalExpiresAt: new Date(epoch + 10000).toISOString(), jobExpiresAt: new Date(epoch + 20000).toISOString(), taskId: 'task7', assignmentId: 'assignment7', channelId: '00000000-0000-0000-0000-000000000000', threadId: 'b'.repeat(64) });

test('canonical intent binds the complete fixed scope; context and proposer are non-authorizing', () => {
  const p = proposal(), c = policy(), intent = canonicalIntent(JSON.stringify(p), c);
  assert.equal(canonical(intent), canonical(canonicalIntent(JSON.stringify(Object.fromEntries(Object.entries(p).reverse())), c)));
  assert.equal(intent.role, 'developer'); assert.equal(intent.operation, 'prepare_developer_job_v1');
  assert.equal(intent.proposerIdentity, 'unverified'); assert.equal(intent.logicalSlot, `managed-v1:${p.requestId}`);
  assert.deepEqual(intent.capabilities, DEVELOPER_CAPABILITIES); assert(intent.capabilities.includes('pull-request:ready'));
  assert.equal(intent.policyDigest, digest(c)); checkLifetime(intent, epoch);
  for (const now of [epoch - 1, epoch + 10000, -1, NaN]) assert.throws(() => checkLifetime(intent, now));
  for (const key of ['taskId', 'assignmentId', 'threadId', 'jobId', 'channelId', 'approvalExpiresAt', 'jobExpiresAt']) {
    const changed = { ...p, [key]: key.includes('Expires') ? new Date(epoch + 9000).toISOString() : key === 'channelId' ? '11111111-0000-0000-0000-000000000000' : key === 'threadId' ? 'c'.repeat(64) : 'other' };
    if (key === 'jobExpiresAt') changed.approvalExpiresAt = changed.jobExpiresAt;
    assert.notEqual(digest(canonicalIntent(JSON.stringify(changed), c)), digest(intent));
  }
});

test('bounded UTF8 depth-one JSON rejects duplicates, encodings and authority/path injections', () => {
  const raw = JSON.stringify(proposal());
  assert.deepEqual(parseProposal(Buffer.from(raw)), proposal());
  assert.equal(parseProposal(JSON.stringify({ ...proposal(), jobId: 'age7.job_1-test' })).jobId, 'age7.job_1-test');
  const invalid = ['', '{}', raw + 'x', raw.replace('"version":1', '"version":1,"version":1'), raw.replace('"version":1', '"version":1,"\\u0076ersion":1'), '\ufeff' + raw, Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(raw)]), Buffer.from([0xff]), raw.replace('"version":1', '"version":{}'), raw.replace('"version":1', '"version":[]'), raw.replace('"version":1', '"version":01'), raw.replace('"version":1', '"version":NaN'), raw.slice(0, -1) + ',}', raw + ' '.repeat(4096), raw.replace('task7', '\\ud800')];
  for (const value of invalid) assert.throws(() => parseProposal(value));
  for (const field of ['authorized', 'subject', 'receipt', 'uid', 'role', 'ownerId', 'profile', 'capabilities', 'path', 'env', 'url', 'command', '__proto__']) assert.throws(() => parseProposal(raw.slice(0, -1) + `,${JSON.stringify(field)}:true}`));
  for (const [key, values] of Object.entries({ requestId: ['A'.repeat(32), '1'.repeat(31), '../x'], jobId: ['', '../job', 'a'.repeat(65), 'a b', 'Uppercase'], taskId: ['<script>', '\u001b'], threadId: ['b'.repeat(63)], channelId: ['not-a-channel'], approvalExpiresAt: ['2026-11-06T20:00:10Z', '2026-02-30T00:00:00.000Z', '2026-11-06T21:00:00.000+01:00', null], version: [true, 2, '1'] })) for (const value of values) assert.throws(() => parseProposal(JSON.stringify({ ...proposal(), [key]: value })));
});

test('fixed policy cannot silently narrow capabilities or select caller destinations', () => {
  for (const [key, value] of Object.entries({ ownerId: '', developerAgentId: '../agent', repository: 'example/../project', baseRef: 'refs/../main', baseSha: 'A'.repeat(40), version: 2, capabilityProfileDigest: 'f'.repeat(64), approvalLifetimeMs: 0, jobLifetimeMs: 999, authorityTimeoutMs: 60001, slotNamespace: '/absolute/path' })) assert.throws(() => fixedPolicy({ ...policy(), [key]: value }));
  for (const [key, value] of Object.entries({ repository: 'other/project', baseRef: 'other', baseSha: 'b'.repeat(40) })) assert.throws(() => canonicalIntent(JSON.stringify({ ...proposal(), [key]: value }), policy()));
  const getter = { ...policy() }; Object.defineProperty(getter, 'ownerId', { enumerable: true, get() { throw Error('must not execute'); } }); assert.throws(() => fixedPolicy(getter), /admission_denied/);
  assert.throws(() => fixedPolicy(new Proxy(policy(), {}))); assert.throws(() => fixedPolicy({ ...policy(), uid: 10001 }));
});
