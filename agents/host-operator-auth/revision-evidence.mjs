// Owner-controlled immutable evidence custody, not a raw/locator recovery store.
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { types } from 'node:util';
import { binding, digest, exact, bounded, identifier, hexadecimal, timestamp } from '../scripts/host-operator-protocol.mjs';

export const evidenceDenied = () => { const e = Error('revision_evidence_denied'); e.code = 'revision_evidence_denied'; e.stack = 'revision_evidence_denied'; throw e; };
export function ownData(value) {
  if (!value || typeof value !== 'object' || types.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) evidenceDenied();
  const p = Object.getOwnPropertyDescriptors(value), keys = Reflect.ownKeys(p);
  if (keys.length > 32 || keys.some(k => typeof k !== 'string' || !Object.hasOwn(p[k], 'value') || !p[k].enumerable)) evidenceDenied();
  return Object.fromEntries(keys.map(k => [k, p[k].value]));
}
export function evidenceData(value, depth = 0, budget = { nodes: 0, bytes: 0 }) {
  if (++budget.nodes > 512 || depth > 12) evidenceDenied();
  if (typeof value === 'string') { budget.bytes += Buffer.byteLength(value); if (budget.bytes > 32768 || !value.isWellFormed()) evidenceDenied(); return value; }
  if (value === null || typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value))) return value;
  return Object.fromEntries(Object.entries(ownData(value)).map(([k, v]) => [k, evidenceData(v, depth + 1, budget)]));
}
function ordered(value) { return value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(k => [k, ordered(value[k])])) : value; }
export const canonicalEvidence = value => JSON.stringify(ordered(value));
export function parseEvidence(text, limit = 32768) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > limit) evidenceDenied();
  const value = evidenceData(JSON.parse(text)); if (canonicalEvidence(value) !== text) evidenceDenied(); return value;
}
export function evidencePins(input) {
  const p = evidenceData(input); exact(p, ['source', 'authorityId', 'issuerArtifactDigest', 'workerArtifactDigest', 'clockId']);
  p.source = binding(p.source); identifier(p.authorityId); identifier(p.clockId); hexadecimal(p.issuerArtifactDigest); hexadecimal(p.workerArtifactDigest); return p;
}
export function terminalBoundary(input, binding) {
  const b = evidenceData(input); bounded(b, 8192);
  exact(b, ['version', 'runId', 'boundaryId', 'requestHash', 'intentDigest', 'workerArtifactDigest', 'clockId', 'startedAt', 'leaderExitedAt', 'settledAt', 'leaderReaped', 'noEscape', 'sealed', 'populated', 'exitCode', 'signal']);
  identifier(b.runId); identifier(b.boundaryId); for (const k of ['requestHash', 'intentDigest', 'workerArtifactDigest']) hexadecimal(b[k]); identifier(b.clockId);
  for (const k of ['startedAt', 'leaderExitedAt', 'settledAt']) timestamp(b[k]);
  if (b.version !== 1 || b.leaderReaped !== true || b.noEscape !== true || b.sealed !== true || b.populated !== 0 || b.startedAt > b.leaderExitedAt || b.leaderExitedAt > b.settledAt ||
      ![null, 'SIGTERM', 'SIGKILL'].includes(b.signal) || (b.exitCode !== null && (!Number.isInteger(b.exitCode) || b.exitCode < 0 || b.exitCode > 255)) || ((b.exitCode === null) === (b.signal === null)) ||
      Object.entries(binding).some(([k, v]) => b[k] !== v)) evidenceDenied(); return b;
}
export function validateSupervisedBundle(input, inputPins) {
  const pins = evidencePins(inputPins), bundle = evidenceData(input); bounded(bundle, 32768); exact(bundle, ['version', 'proof', 'result', 'boundary']);
  if (bundle.version !== 1) evidenceDenied(); const p = bundle.proof, r = bundle.result;
  bounded(p, 8192); bounded(r, 4096);
  exact(p, ['version', 'type', 'authorityId', 'completionId', 'requestHash', 'intentId', 'intentDigest', 'descriptorDigest', 'startedAt', 'finishedAt', 'outcome', 'execution', 'resultDigest', 'summary', 'issuerArtifactDigest', 'clockId']);
  const e = p.execution; exact(e, ['kind', 'settled', 'descendants', 'runId', 'boundaryId', 'boundaryDigest', 'workerArtifactDigest']);
  for (const k of ['completionId', 'intentId']) identifier(p[k]); for (const k of ['requestHash', 'intentDigest', 'descriptorDigest', 'resultDigest']) hexadecimal(p[k]); hexadecimal(e.boundaryDigest);
  timestamp(p.startedAt); timestamp(p.finishedAt); exact(p.summary, ['passed', 'failed', 'skipped', 'exitCode', 'signal']);
  if (p.version !== 2 || p.type !== 'host-operator.revision-completion' || p.authorityId !== pins.authorityId || p.issuerArtifactDigest !== pins.issuerArtifactDigest || p.clockId !== pins.clockId ||
      e.kind !== 'supervised_process_v1' || e.settled !== true || e.descendants !== 0 || e.workerArtifactDigest !== pins.workerArtifactDigest || e.runId !== p.completionId ||
      !['success', 'failed'].includes(p.outcome) || p.finishedAt < p.startedAt || ['passed', 'failed', 'skipped'].some(k => p.summary[k] !== 0) || p.summary.exitCode !== null || p.summary.signal !== null) evidenceDenied();
  const b = terminalBoundary(bundle.boundary, { runId: p.completionId, boundaryId: e.boundaryId, requestHash: p.requestHash, intentDigest: p.intentDigest, workerArtifactDigest: pins.workerArtifactDigest, clockId: pins.clockId, startedAt: p.startedAt });
  if (b.settledAt > p.finishedAt || digest(b) !== e.boundaryDigest || digest(r) !== p.resultDigest || r.runId !== p.completionId || r.requestHash !== p.requestHash || r.intentDigest !== p.intentDigest) evidenceDenied();
  if (p.outcome === 'success') {
    exact(r, ['status', 'repository', 'workspaceId', 'expectedSha', 'observedSha', 'observedAt', 'runId', 'requestHash', 'intentDigest']); timestamp(r.observedAt);
    if (b.exitCode !== 0 || b.signal !== null || r.repository !== pins.source.repository || r.workspaceId !== pins.source.workspaceId || r.expectedSha !== pins.source.baseSha ||
        typeof r.observedSha !== 'string' || !/^[a-f0-9]{40}$/.test(r.observedSha) || r.status !== (r.observedSha === pins.source.baseSha ? 'observed' : 'mismatch') || r.observedAt < p.startedAt || r.observedAt > b.settledAt) evidenceDenied();
  } else {
    exact(r, ['status', 'code', 'runId', 'requestHash', 'intentDigest']); if (r.status !== 'failed' || !['worker_failed', 'output_limit', 'deadline_exceeded', 'postcondition_denied'].includes(r.code)) evidenceDenied();
  }
  return bundle;
}
const resolverPins = new WeakMap();
export const isSupervisedResolver = (resolver, pins) => resolverPins.has(resolver) && digest(resolverPins.get(resolver)) === digest(evidencePins(pins));
const stable = s => [s.dev, s.ino, s.uid, s.mode, s.nlink, s.size, s.mtimeNs, s.ctimeNs].join(':');
export function protectedDirectory(root, uid, privateRoot = true) {
  if (typeof root !== 'string' || !root.isWellFormed() || root.includes('\0') || root.endsWith('/') || !path.isAbsolute(root) || path.normalize(root) !== root || Buffer.byteLength(root) > 3800 || fs.realpathSync(root) !== root) evidenceDenied();
  for (let p = root; ; p = path.dirname(p)) {
    const s = fs.lstatSync(p), tmp = p === '/tmp' && (s.mode & 0o1000) && [0, uid].includes(s.uid);
    if (!s.isDirectory() || s.isSymbolicLink() || ![0, uid].includes(s.uid) || (!tmp && (s.mode & 0o7022)) || (privateRoot && p === root && (s.uid !== uid || (s.mode & 0o7777) !== 0o700))) evidenceDenied();
    if (p === path.dirname(p)) break;
  }
}
function readSafe(file, uid, limit) {
  const before = fs.lstatSync(file, { bigint: true });
  const check = s => { if (!s.isFile() || s.uid !== BigInt(uid) || s.nlink !== 1n || (s.mode & 0o7777n) !== 0o600n || s.size < 1n || s.size > BigInt(limit)) evidenceDenied(); };
  check(before); const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try { const opened = fs.fstatSync(fd, { bigint: true }); check(opened); if (stable(before) !== stable(opened)) evidenceDenied(); const bytes = Buffer.alloc(limit + 1), n = fs.readSync(fd, bytes, 0, limit + 1, 0); if (n !== Number(opened.size) || stable(opened) !== stable(fs.fstatSync(fd, { bigint: true })) || stable(opened) !== stable(fs.lstatSync(file, { bigint: true }))) evidenceDenied(); return parseEvidence(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, n)), limit); } finally { fs.closeSync(fd); }
}
const missing = file => { try { fs.lstatSync(file); return false; } catch (e) { if (e.code !== 'ENOENT') throw e; return true; } };
function syncDir(dir) { const fd = fs.openSync(dir, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); } }
export function createRevisionEvidenceStore(options) {
  try {
    const c = ownData(options); exact(c, ['directory', 'uid', 'source', 'authorityId', 'issuerArtifactDigest', 'workerArtifactDigest', 'clockId']);
    if (process.platform !== 'linux' || !Number.isSafeInteger(c.uid) || c.uid <= 0 || c.uid !== process.getuid()) evidenceDenied();
    const pins = evidencePins(Object.fromEntries(['source', 'authorityId', 'issuerArtifactDigest', 'workerArtifactDigest', 'clockId'].map(k => [k, c[k]]))), root = c.directory, claims = path.join(root, 'claims'), objects = path.join(root, 'objects'), lock = path.join(root, 'evidence.lock');
    const anchors = new Map(); for (const p of [root, claims, objects]) { protectedDirectory(p, c.uid); const s = fs.lstatSync(p); anchors.set(p, [s.dev, s.ino, s.uid, s.mode].join(':')); }
    const guard = () => { for (const [p, anchor] of anchors) { protectedDirectory(p, c.uid); const s = fs.lstatSync(p); if ([s.dev, s.ino, s.uid, s.mode].join(':') !== anchor) evidenceDenied(); } };
    function validClaim(v) { exact(v, ['version', 'runId', 'intentDigest', 'requestHash', 'descriptorDigest', 'deadline', 'issuerArtifactDigest']); identifier(v.runId); for (const k of ['intentDigest', 'requestHash', 'descriptorDigest']) hexadecimal(v[k]); timestamp(v.deadline); if (v.version !== 1 || v.issuerArtifactDigest !== pins.issuerArtifactDigest) evidenceDenied(); return v; }
    function inventory() { let count = 0, size = 0; const counts = {}; for (const dir of [claims, objects]) { counts[dir] = 0; for (const name of fs.readdirSync(dir)) { if (!/^[a-f0-9]{64}\.json$/.test(name)) evidenceDenied(); const f = path.join(dir, name), value = readSafe(f, c.uid, dir === claims ? 8192 : 32768); if (dir === objects) { const b = validateSupervisedBundle(value, pins); if (digest(b.proof) + '.json' !== name) evidenceDenied(); size += fs.statSync(f).size; } else if (validClaim(value).intentDigest + '.json' !== name) evidenceDenied(); counts[dir]++; count++; } } if (count > 256 || counts[claims] > 128 || counts[objects] > 128 || size > 4194304) evidenceDenied(); return { counts, size }; }
    function locked(work) { let fd; try { guard(); fd = fs.openSync(lock, 'wx', 0o600); fs.fsyncSync(fd); syncDir(root); inventory(); const result = work(); guard(); fs.closeSync(fd); fd = undefined; fs.unlinkSync(lock); syncDir(root); return result; } catch { if (fd !== undefined) { try { fs.closeSync(fd); } catch {} } evidenceDenied(); } }
    function persist(file, value, limit) { if (!missing(file)) evidenceDenied(); const tmp = file + '.tmp', bytes = canonicalEvidence(value); if (Buffer.byteLength(bytes) > limit) evidenceDenied(); const fd = fs.openSync(tmp, 'wx', 0o600); try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); } fs.renameSync(tmp, file); syncDir(path.dirname(file)); syncDir(root); if (canonicalEvidence(readSafe(file, c.uid, limit)) !== bytes) evidenceDenied(); }
    const handles = new WeakMap();
    const api = Object.freeze({ reserveAttempt(input) {
      try { const value = evidenceData(input); exact(value, ['intentDigest', 'requestHash', 'descriptorDigest', 'deadline']); for (const k of ['intentDigest', 'requestHash', 'descriptorDigest']) hexadecimal(value[k]); timestamp(value.deadline);
        const claim = { version: 1, runId: randomUUID(), ...value, issuerArtifactDigest: pins.issuerArtifactDigest };
        const ok = locked(() => { const inv = inventory(); if (!missing(path.join(claims, value.intentDigest + '.json')) || inv.counts[claims] >= 128 || inv.counts[objects] >= 128 || inv.size >= 4194304) return false; persist(path.join(claims, value.intentDigest + '.json'), claim, 8192); return true; });
        if (!ok) evidenceDenied(); const handle = Object.freeze({ runId: claim.runId }); handles.set(handle, claim); return handle;
      } catch { evidenceDenied(); }
    }, publish(handle, input) {
      try { const claim = handles.get(handle); if (!claim) evidenceDenied(); const b = validateSupervisedBundle(input, pins), p = b.proof, ref = digest(p);
        if (p.completionId !== claim.runId || p.intentDigest !== claim.intentDigest || p.requestHash !== claim.requestHash || p.descriptorDigest !== claim.descriptorDigest || (p.outcome === 'success' && p.finishedAt >= claim.deadline)) evidenceDenied();
        const ok = locked(() => { if (digest(readSafe(path.join(claims, claim.intentDigest + '.json'), c.uid, 8192)) !== digest(claim)) evidenceDenied(); const file = path.join(objects, ref + '.json'), bytes = canonicalEvidence(b), inv = inventory(); for (const name of fs.readdirSync(objects)) { if (name !== ref + '.json' && readSafe(path.join(objects, name), c.uid, 32768).proof.intentDigest === claim.intentDigest) return false; } if (!missing(file)) return canonicalEvidence(readSafe(file, c.uid, 32768)) === bytes; if (inv.counts[objects] >= 128 || inv.size + Buffer.byteLength(bytes) > 4194304) return false; persist(file, b, 32768); return true; });
        if (!ok) evidenceDenied(); return Object.freeze({ ref, digest: ref });
      } catch { evidenceDenied(); }
    }, resolveCompletion(ref) {
      try { hexadecimal(ref); const proof = locked(() => { const file = path.join(objects, ref + '.json'); if (missing(file)) return null; const b = validateSupervisedBundle(readSafe(file, c.uid, 32768), pins); if (digest(b.proof) !== ref) evidenceDenied(); const claim = readSafe(path.join(claims, b.proof.intentDigest + '.json'), c.uid, 8192); exact(claim, ['version', 'runId', 'intentDigest', 'requestHash', 'descriptorDigest', 'deadline', 'issuerArtifactDigest']); if (claim.version !== 1 || claim.runId !== b.proof.completionId || claim.intentDigest !== b.proof.intentDigest || claim.requestHash !== b.proof.requestHash || claim.descriptorDigest !== b.proof.descriptorDigest || claim.issuerArtifactDigest !== pins.issuerArtifactDigest || (b.proof.outcome === 'success' && b.proof.finishedAt >= claim.deadline)) evidenceDenied(); return b.proof; }); if (!proof) evidenceDenied(); return proof;
      } catch { evidenceDenied(); }
    } });
    resolverPins.set(api.resolveCompletion, pins); return api;
  } catch { evidenceDenied(); }
}
