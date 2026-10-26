// Library-only intent gate: no CLI, subprocess, socket, runner or network publisher.
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { types } from 'node:util';
import { ProtocolError, deny, copy, exact, bounded, digest, identifier, hexadecimal, timestamp,
  request, binding, descriptor, identity, authorize, userAction, receipt, publicReceipt } from './host-operator-protocol.mjs';

function trust(directory) {
  if (typeof directory !== 'string' || !path.isAbsolute(directory) || directory === '/' || path.normalize(directory) !== directory) deny('journal_untrusted');
  for (let p = directory; ; p = path.dirname(p)) {
    const s = fs.lstatSync(p);
    const fixtureTmp = process.getuid() !== 0 && p === '/tmp' && [0, process.getuid()].includes(s.uid) && (s.mode & 0o1000);
    if (!s.isDirectory() || s.isSymbolicLink() ||
        (![0, process.getuid()].includes(s.uid)) || (!fixtureTmp && (s.mode & 0o022)) ||
        (p === directory && (s.uid !== process.getuid() || (s.mode & 0o077)))) deny('journal_untrusted');
    if (p === '/') break;
  }
}
function syncChain(directory) {
  for (let p = directory; ; p = path.dirname(p)) {
    const fd = fs.openSync(p, 'r');
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    if (p === '/') break;
  }
}
function read(file) {
  let s;
  try { s = fs.lstatSync(file); } catch (e) { if (e.code === 'ENOENT') return { version: 1, entries: {} }; throw e; }
  if (!s.isFile() || s.isSymbolicLink() || s.nlink !== 1 || s.uid !== process.getuid() || (s.mode & 0o077) || s.size > 1048576) deny('journal_untrusted');
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try { return JSON.parse(fs.readFileSync(fd, 'utf8')); } finally { fs.closeSync(fd); }
}
function save(directory, file, state) {
  bounded(state, 1048576);
  const fd = fs.openSync(`${file}.tmp`, 'wx', 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(state)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(`${file}.tmp`, file);
  syncChain(directory); // Same child-before-parent durability pattern as handoff.
}
const keyFor = r => digest([r.jobId, r.requestId]);
function complete(e) { return e.effects.at(-1)?.intent.step === 'buzz' && e.effects.at(-1).receipt !== null; }
function nextStep(e) {
  const last = e.effects.at(-1);
  if (!last || last.intent.step === 'user') return 'execution';
  if (last.intent.step === 'execution') return last.receipt.outcome === 'needs_user' ? 'user' : 'kaneo';
  return 'buzz';
}
function intentFor(e, step, now, intentId = randomUUID()) {
  let payload;
  if (step === 'execution') payload = { descriptor: e.descriptor };
  else if (step === 'user') payload = userAction(e.descriptor.userActionId);
  else {
    const result = publicReceipt(e);
    payload = step === 'kaneo' ? { taskId: e.request.taskId, result } :
      { channelId: e.request.channelId, threadId: e.request.threadId, mentionPubkey: e.identity.mentionPubkey, result };
  }
  return { version: 1, intentId, requestHash: e.requestHash,
    descriptorDigest: digest(e.descriptor), step, sequence: e.effects.length,
    createdAt: now, deadline: now + (step === 'execution' ? e.descriptor.timeoutMs : 60000), payload };
}
// Rebuild each stored intent's deterministic fields, not just its top-level shape.
function validateEntry(e, source, now) {
  exact(e, ['request', 'requestHash', 'descriptor', 'identity', 'effects']);
  const r = request(e.request), d = descriptor(r, source);
  identity(e.identity);
  if (e.requestHash !== digest(r) || digest(e.descriptor) !== digest(d) || !Array.isArray(e.effects) || e.effects.length > 5) deny('journal_invalid');
  const prefix = { ...e, effects: [] };
  for (const effect of e.effects) {
    exact(effect, ['intent', 'receipt']);
    const i = effect.intent;
    exact(i, ['version', 'intentId', 'requestHash', 'descriptorDigest', 'step', 'sequence', 'createdAt', 'deadline', 'payload']);
    identifier(i.intentId); timestamp(i.createdAt); timestamp(i.deadline);
    if (prefix.effects.at(-1)?.receipt === null || complete(prefix)) deny('journal_invalid');
    const step = nextStep(prefix);
    if (step === 'user' && prefix.effects.some(x => x.intent.step === 'user')) deny('journal_invalid');
    const expected = intentFor(prefix, step, i.createdAt, i.intentId);
    if (digest(i) !== digest(expected) || i.createdAt > now) deny('journal_invalid');
    if (effect.receipt !== null) receipt(effect.receipt, i, now);
    // Timeout/cancellation is ambiguous: never turn it into permission to run/report.
    if (['timeout', 'cancelled'].includes(effect.receipt?.outcome)) deny('journal_invalid');
    prefix.effects.push(effect);
  }
}

// Inspection inputs are data, never serialized authority or executable callbacks.
function inspectionData(value) {
  if (!value || typeof value !== 'object' || types.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) deny('pending_execution_denied');
  const props = Object.getOwnPropertyDescriptors(value), keys = Reflect.ownKeys(props);
  if (keys.length > 16 || keys.some(k => typeof k !== 'string' || !Object.hasOwn(props[k], 'value') || !props[k].enumerable)) deny('pending_execution_denied');
  const result = {};
  for (const k of keys) {
    const v = props[k].value;
    if (!((typeof v === 'string' && Buffer.byteLength(v) <= 512) || (typeof v === 'number' && Number.isSafeInteger(v)))) deny('pending_execution_denied');
    Object.defineProperty(result, k, { value: v, enumerable: true });
  }
  bounded(result, 4096); return result;
}

export class HostOperatorJournal {
  #directory; #source; #owner; #authorize; #verifyReceipt; #verifyRevisionCompletion; #clock;
  constructor({ directory, source, ownerPubkey, authorize: authorizationAdapter, verifyReceipt, verifyRevisionCompletion, clock = Date.now }) {
    if (typeof authorizationAdapter !== 'function' || typeof verifyReceipt !== 'function' || typeof clock !== 'function' || (verifyRevisionCompletion !== undefined && typeof verifyRevisionCompletion !== 'function')) deny('adapter_required');
    if (typeof directory !== 'string' || !path.isAbsolute(directory) || directory === '/' || path.normalize(directory) !== directory) deny('journal_untrusted');
    hexadecimal(ownerPubkey);
    this.#directory = directory; this.#source = binding(source); this.#owner = ownerPubkey;
    this.#authorize = authorizationAdapter; this.#verifyReceipt = verifyReceipt; this.#verifyRevisionCompletion = verifyRevisionCompletion; this.#clock = clock;
  }
  // Only competing NEW admissions use this predicate; reporting/replay stay unchanged.
  #reserved(e) {
    if (complete(e)) return false;
    if (!this.#verifyRevisionCompletion || e.descriptor.operationId !== 'status.revision' ||
        e.descriptor.privilege !== 'read_only' || e.descriptor.userActionId !== null) return true;
    const executions = e.effects.filter(x => x.intent.step === 'execution');
    if (executions.length !== 1 || !['success', 'failed'].includes(executions[0].receipt?.outcome)) return true;
    const effect = executions[0];
    try {
      const proof = { ref: effect.receipt.evidenceRef, digest: effect.receipt.evidenceDigest };
      const normalized = receipt(this.#verifyRevisionCompletion(proof, copy(effect.intent),
        { request: copy(e.request), identity: copy(e.identity) }), effect.intent, this.#now());
      return digest(normalized) !== digest(effect.receipt);
    } catch { return true; } // Unavailable/revoked/conflicting proof HOLDs reservation.
  }
  #now() {
    try { const now = this.#clock(); timestamp(now); return now; } catch { deny('clock_invalid'); }
  }
  #locked(work) {
    let fd, locked = false;
    const dir = this.#directory, lock = path.join(dir, 'journal.lock'), file = path.join(dir, 'state.json');
    try {
      trust(dir);
      try { fd = fs.openSync(lock, 'wx', 0o600); locked = true; } catch { deny('journal_locked'); }
      syncChain(dir);
      // Never adopt a previous interrupted atomic write.
      try { fs.lstatSync(`${file}.tmp`); deny('journal_unresolved'); } catch (e) { if (e.code !== 'ENOENT') throw e; }
      const state = read(file);
      exact(state, ['version', 'entries']);
      if (state.version !== 1 || !state.entries || typeof state.entries !== 'object' || Array.isArray(state.entries) || Object.keys(state.entries).length > 128) deny('journal_invalid');
      for (const [key, e] of Object.entries(state.entries)) {
        if (key !== keyFor(e.request)) deny('journal_invalid');
        validateEntry(e, this.#source, this.#now());
      }
      return copy(work(state, s => save(dir, file, s)));
    } catch (e) { throw new ProtocolError(e instanceof ProtocolError ? e.code : 'journal_io'); }
    finally {
      if (locked) {
        try { fs.closeSync(fd); fs.unlinkSync(lock); } catch { deny('journal_io'); }
      }
    }
  }
  // Non-consuming inspection: state.json is never persisted; the normal exclusive
  // lock is still created/synced/removed and may remain stale after process death.
  inspectPendingExecution(input, expected) {
    try {
      if (arguments.length !== 2) deny('pending_execution_denied');
      const r = request(inspectionData(input)), d = descriptor(r, this.#source), wanted = inspectionData(expected);
      exact(wanted, ['intentId', 'intentDigest']); identifier(wanted.intentId); hexadecimal(wanted.intentDigest);
      if (d.operationId !== 'status.revision' || d.privilege !== 'read_only' || d.userActionId !== null) deny('pending_execution_denied');
      let previous = -1;
      const inspectionNow = () => { const value = this.#now(); if (value < previous) deny('pending_execution_denied'); previous = value; return value; };
      authorize(this.#authorize, r, d, this.#owner, inspectionNow());
      return this.#locked(state => {
        const now = inspectionNow(), who = authorize(this.#authorize, r, d, this.#owner, now), e = state.entries[keyFor(r)];
        if (!e || e.requestHash !== digest(r) || digest(e.descriptor) !== digest(d) || digest(e.identity) !== digest(who)) deny('pending_execution_denied');
        const effect = e.effects.at(-1), intent = effect?.intent, checkedAt = inspectionNow();
        if (!intent || intent.step !== 'execution' || effect.receipt !== null || intent.intentId !== wanted.intentId ||
            digest(intent) !== wanted.intentDigest || checkedAt < intent.createdAt || checkedAt >= intent.deadline) deny('pending_execution_denied');
        const result = { intent, intentDigest: digest(intent) }; bounded(result, 4096); return result;
      });
    } catch {
      const error = new ProtocolError('pending_execution_denied'); error.stack = 'pending_execution_denied'; throw error;
    }
  }
  next(input) {
    const r = request(input), d = descriptor(r, this.#source);
    // Denied requests do not even create a lock or write an acceptance record.
    authorize(this.#authorize, r, d, this.#owner, this.#now());
    return this.#locked((state, persist) => {
      const now = this.#now(), who = authorize(this.#authorize, r, d, this.#owner, now), key = keyFor(r);
      let e = state.entries[key];
      if (e && (e.requestHash !== digest(r) || digest(e.identity) !== digest(who))) deny('request_conflict');
      if (e && complete(e)) return { status: 'complete', result: publicReceipt(e) };
      if (e?.effects.at(-1)?.receipt === null) {
        const pending = e.effects.at(-1).intent;
        return { status: 'outcome_unknown', code: now >= pending.deadline ? 'deadline_elapsed' : 'pending_effect', intentId: pending.intentId };
      }
      if (!e) {
        if (Object.values(state.entries).some(other => (other.request.jobId === r.jobId || other.descriptor.workspaceId === d.workspaceId) && this.#reserved(other))) deny('workspace_busy');
        if (Object.keys(state.entries).length >= 128) deny('journal_full');
        e = { request: r, requestHash: digest(r), descriptor: d, identity: who, effects: [] };
        state.entries[key] = e;
      }
      const step = nextStep(e);
      if (step === 'user' && (e.effects.some(x => x.intent.step === 'user') || !d.userActionId)) return { status: 'blocked', code: 'host_preparation_required' };
      const intent = intentFor(e, step, now);
      e.effects.push({ intent, receipt: null });
      persist(state); // No consumer can see an effect before durable intent.
      return { status: step === 'user' ? 'needs_user' : 'intent', intent, intentDigest: digest(intent) };
    });
  }
  // This is also the reconciliation entry point. The trusted adapter must prove
  // the exact past effect, even after expiry; no search-result absence or chat ack.
  record(input, evidence) {
    const r = request(input);
    bounded(evidence, 8192);
    return this.#locked((state, persist) => {
      const e = state.entries[keyFor(r)];
      if (!e || e.requestHash !== digest(r) || !e.effects.length) deny('receipt_invalid');
      const effect = e.effects.at(-1);
      let normalized;
      try { normalized = receipt(this.#verifyReceipt(copy(evidence), copy(effect.intent), { request: copy(r), identity: copy(e.identity) }), effect.intent, this.#now()); }
      catch { deny('receipt_invalid'); }
      if (effect.receipt !== null) {
        if (digest(effect.receipt) !== digest(normalized)) deny('receipt_conflict');
        return { status: complete(e) ? 'complete' : 'recorded' };
      }
      if (['timeout', 'cancelled'].includes(normalized.outcome)) return { status: 'outcome_unknown', code: 'termination_unproven', intentId: effect.intent.intentId };
      if (e.effects.some(x => x.receipt?.receiptId === normalized.receiptId)) deny('receipt_conflict');
      effect.receipt = normalized;
      persist(state);
      return { status: complete(e) ? 'complete' : 'recorded' };
    });
  }
}
