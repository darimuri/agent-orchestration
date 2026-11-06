// Private root-custodied journal only; no executor, Gateway or startup wiring.
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { canonical, digest, data, deny, fixedPolicy, requestId, canonicalIntent, checkLifetime, proposalFromIntent, timestamp } from './intent.mjs';

const MAX_INTENTS = 4096, MAX_RECORD = 8192;
const directoryIdentity = s => [s.dev, s.ino, s.uid, s.mode].join(':');
const identity = s => [s.dev, s.ino, s.uid, s.mode, s.nlink].join(':');
const stamp = s => [identity(s), s.size, s.mtimeNs, s.ctimeNs].join(':');
const unknown = () => Object.freeze({ phase: 'outcome_unknown' });
const missing = file => { try { fs.lstatSync(file); return false; } catch (e) { if (e.code !== 'ENOENT') throw e; return true; } };
function custody(directory) {
  if (typeof directory !== 'string' || !directory.isWellFormed() || !path.isAbsolute(directory) || directory.includes('\0') || directory.endsWith('/') || path.normalize(directory) !== directory || Buffer.byteLength(directory) > 3800 || fs.realpathSync(directory) !== directory) deny();
  for (let p = directory; ; p = path.dirname(p)) {
    const s = fs.lstatSync(p);
    if (!s.isDirectory() || s.isSymbolicLink() || s.uid !== 0 || (s.mode & 0o7022) || (p === directory && (s.mode & 0o7777) !== 0o700)) deny();
    if (p === path.dirname(p)) break;
  }
}
function read(file, limit = MAX_RECORD) {
  const before = fs.lstatSync(file, { bigint: true });
  const check = s => { if (!s.isFile() || s.uid !== 0n || s.nlink !== 1n || (s.mode & 0o7777n) !== 0o600n || s.size < 1n || s.size > BigInt(limit)) deny(); };
  check(before); const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const opened = fs.fstatSync(fd, { bigint: true }); check(opened); if (stamp(before) !== stamp(opened)) deny();
    const bytes = Buffer.alloc(limit + 1); let n = 0, count;
    while ((count = fs.readSync(fd, bytes, n, bytes.length - n, n)) > 0) { n += count; if (n > limit) deny(); }
    if (n !== Number(opened.size) || stamp(opened) !== stamp(fs.fstatSync(fd, { bigint: true })) || stamp(opened) !== stamp(fs.lstatSync(file, { bigint: true }))) deny();
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes.subarray(0, n));
    const parsed = JSON.parse(text); if (canonical(parsed) !== text) deny(); return { value: parsed, bytes: text, identity: identity(opened) };
  } finally { fs.closeSync(fd); }
}
function freeze(value) { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; }
function buildAdmissionStore(input) {
  const options = data(input, ['directory', 'policy', 'clock', 'decisionAuthority']);
  if (process.platform !== 'linux' || process.getuid() !== 0 || typeof options.clock !== 'function' || typeof options.decisionAuthority !== 'function') deny();
  const policy = fixedPolicy(options.policy), policyBytes = canonical(policy), root = options.directory;
  custody(root); const anchors = new Map();
  for (let p = root; ; p = path.dirname(p)) { anchors.set(p, directoryIdentity(fs.lstatSync(p))); if (p === path.dirname(p)) break; }
  let last = -1, poisoned = false, activeLock = null;
  const lock = path.join(root, 'admission.lock');
  function guard() {
    custody(root); for (const [p, id] of anchors) if (directoryIdentity(fs.lstatSync(p)) !== id) deny();
    const live = data(input, ['directory', 'policy', 'clock', 'decisionAuthority']);
    if (live.directory !== root || canonical(fixedPolicy(live.policy)) !== policyBytes || live.clock !== options.clock || live.decisionAuthority !== options.decisionAuthority) deny();
    if (activeLock && (identity(fs.fstatSync(activeLock.fd)) !== activeLock.id || read(lock).identity !== activeLock.id || read(lock).bytes !== activeLock.bytes)) deny();
  }
  function now() { const n = options.clock(); if (!Number.isSafeInteger(n) || n < 0 || n < last) deny(); last = n; return n; }
  function syncDirectory() {
    guard(); const fd = fs.openSync(root, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    try { if (directoryIdentity(fs.fstatSync(fd)) !== anchors.get(root)) deny(); fs.fsyncSync(fd); guard(); } finally { fs.closeSync(fd); }
  }
  const file = (id, kind, candidate = false) => path.join(root, `${id}.${kind}${candidate ? '.candidate' : '.json'}`);
  function validateRecord(record, id, kind, intentRecord) {
    const r = data(record, ['version', 'kind', 'requestId', 'intentDigest', 'receiptId', 'payload', 'checksum']);
    const { checksum, ...body } = r;
    if (r.version !== 1 || r.kind !== kind || r.requestId !== id || typeof r.receiptId !== 'string' || !/^[a-f0-9]{32}$/.test(r.receiptId) || digest(body) !== checksum) deny();
    if (kind === 'intent') {
      const expected = canonicalIntent(JSON.stringify(proposalFromIntent(r.payload)), policy);
      if (canonical(expected) !== canonical(r.payload) || r.intentDigest !== digest(expected)) deny();
    } else {
      if (!intentRecord || r.intentDigest !== intentRecord.intentDigest) deny();
      if (kind === 'decision') {
        const p = data(r.payload, ['phase', 'at', 'authorityId']);
        if (!['approved', 'rejected', 'expired'].includes(p.phase) || !Number.isSafeInteger(p.at) || p.at < 0 ||
            (p.phase === 'expired' ? p.authorityId !== null || p.at < Math.min(timestamp(intentRecord.payload.approvalExpiresAt), timestamp(intentRecord.payload.jobExpiresAt)) :
              typeof p.authorityId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(p.authorityId) || p.at >= Math.min(timestamp(intentRecord.payload.approvalExpiresAt), timestamp(intentRecord.payload.jobExpiresAt)))) deny();
      } else { const p = data(r.payload, ['phase', 'at', 'decisionReceiptId']); if (p.phase !== 'reserved' || !Number.isSafeInteger(p.at) || p.at < 0 || typeof p.decisionReceiptId !== 'string') deny(); }
    }
    return r;
  }
  // Full bounded inventory: unexplained/partial evidence disables all new authority.
  function inventory() {
    guard(); const names = fs.readdirSync(root); if (names.length > MAX_INTENTS * 6 + 1) deny();
    const records = new Map();
    for (const name of names) {
      if (name === 'admission.lock') continue;
      const m = /^([a-f0-9]{32})\.(intent|decision|reservation)\.(candidate|json)$/.exec(name); if (!m) deny();
      const [, id, kind, suffix] = m, key = `${id}.${kind}`;
      if (!records.has(key)) records.set(key, {}); records.get(key)[suffix] = read(path.join(root, name));
    }
    for (const pair of records.values()) if (!pair.json || !pair.candidate || pair.json.bytes !== pair.candidate.bytes) deny();
    const intents = new Map();
    for (const [key, pair] of records) if (key.endsWith('.intent')) { const id = key.slice(0, 32); intents.set(id, validateRecord(pair.json.value, id, 'intent')); }
    if (intents.size > MAX_INTENTS) deny();
    const states = new Map([...intents].map(([id, intent]) => [id, { intent }]));
    for (const [key, pair] of records) if (!key.endsWith('.intent')) { const id = key.slice(0, 32), kind = key.slice(33); if (!states.has(id)) deny(); states.get(id)[kind] = validateRecord(pair.json.value, id, kind, intents.get(id)); }
    for (const state of states.values()) if (state.reservation && (!state.decision || state.decision.payload.phase !== 'approved' || state.reservation.payload.decisionReceiptId !== state.decision.receiptId || state.reservation.payload.at < state.decision.payload.at || state.reservation.payload.at >= Math.min(timestamp(state.intent.payload.approvalExpiresAt), timestamp(state.intent.payload.jobExpiresAt)))) deny();
    guard(); return states;
  }
  function publish(id, kind, intentDigest, payload, check = () => {}) {
    const body = { version: 1, kind, requestId: id, intentDigest, receiptId: randomBytes(16).toString('hex'), payload };
    const record = { ...body, checksum: digest(body) }, bytes = Buffer.from(canonical(record)); if (bytes.length > MAX_RECORD) deny();
    for (const candidate of [true, false]) {
      check(); guard(); const target = file(id, kind, candidate), fd = fs.openSync(target, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
      let created;
      try { created = identity(fs.fstatSync(fd)); let offset = 0; while (offset < bytes.length) { const n = fs.writeSync(fd, bytes, offset, bytes.length - offset, offset); if (!Number.isInteger(n) || n <= 0 || n > bytes.length - offset) deny(); offset += n; } fs.fsyncSync(fd); if (identity(fs.fstatSync(fd)) !== created) deny(); }
      finally { fs.closeSync(fd); }
      syncDirectory(); const saved = read(target); if (saved.bytes !== bytes.toString() || saved.identity !== created) deny();
    }
    return record;
  }
  function locked(work) {
    if (poisoned) return unknown(); let fd, id, released = false;
    try {
      guard(); fd = fs.openSync(lock, fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
      id = identity(fs.fstatSync(fd)); const bytes = Buffer.from(canonical({ token: randomBytes(16).toString('hex') }));
      let offset = 0; while (offset < bytes.length) { const n = fs.writeSync(fd, bytes, offset, bytes.length - offset, offset); if (!Number.isInteger(n) || n <= 0 || n > bytes.length - offset) deny(); offset += n; }
      fs.fsyncSync(fd); activeLock = { fd, id, bytes: bytes.toString() }; syncDirectory(); if (read(lock).identity !== id) deny();
      const result = work(inventory()); guard();
      // Only the verified named/open lock from THIS live operation may be removed.
      if (identity(fs.fstatSync(fd)) !== id || read(lock).identity !== id || read(lock).bytes !== bytes.toString()) deny();
      fs.unlinkSync(lock); activeLock = null; released = true; syncDirectory(); fs.closeSync(fd); fd = undefined; return result;
    } catch (e) {
      if (fd !== undefined) poisoned = true; if (e.code !== 'EEXIST') poisoned = true;
      if (released) {
        // A failed release sync must not silently become restart authority.
        // Best-effort create-only quarantine preserves uncertainty; no repair.
        let quarantine;
        try {
          guard(); quarantine = fs.openSync(path.join(root, 'admission.uncertain'), fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
          const bytes = Buffer.from('{"phase":"outcome_unknown"}'); let offset = 0;
          while (offset < bytes.length) { const n = fs.writeSync(quarantine, bytes, offset, bytes.length - offset, offset); if (!Number.isInteger(n) || n <= 0 || n > bytes.length - offset) deny(); offset += n; }
          fs.fsyncSync(quarantine); syncDirectory();
        } catch {} finally { if (quarantine !== undefined) { try { fs.closeSync(quarantine); } catch {} } }
      }
      return unknown();
    }
    finally { activeLock = null; if (fd !== undefined) { try { fs.closeSync(fd); } catch { poisoned = true; } } }
  }
  function observation(state) {
    if (!state) return Object.freeze({ phase: 'absent' });
    return freeze({ phase: state.reservation ? 'reserved' : state.decision?.payload.phase ?? 'pending',
      intent: JSON.parse(canonical(state.intent.payload)), intentDigest: state.intent.intentDigest,
      intentReceiptId: state.intent.receiptId, decisionReceiptId: state.decision?.receiptId ?? null,
      reservationReceiptId: state.reservation?.receiptId ?? null });
  }
  function inspect(id) {
    try { requestId(id); guard(); now(); if (poisoned || !missing(lock)) return unknown(); const inv = inventory(); if (!missing(lock)) return unknown(); return observation(inv.get(id)); } catch { return unknown(); }
  }
  function expire(state, n) {
    if (!state.decision && n >= Math.min(timestamp(state.intent.payload.approvalExpiresAt), timestamp(state.intent.payload.jobExpiresAt))) state.decision = publish(state.intent.requestId, 'decision', state.intent.intentDigest, { phase: 'expired', at: n, authorityId: null });
    return state;
  }
  const submit = raw => {
    // Validate before acquiring anything: hostile input never creates files.
    const intent = canonicalIntent(raw, policy), id = intent.requestId;
    return locked(inv => {
      const n = now(), prior = inv.get(id);
      if (prior) { if (canonical(prior.intent.payload) !== canonical(intent)) return Object.freeze({ phase: 'conflict' }); return observation(prior); }
      checkLifetime(intent, n); if (inv.size >= MAX_INTENTS) return Object.freeze({ phase: 'capacity' });
      return observation({ intent: publish(id, 'intent', digest(intent), intent) });
    });
  };
  async function decide(id, decision) {
    requestId(id); if (!['approve', 'reject'].includes(decision)) deny();
    const before = inspect(id); if (before.phase !== 'pending') {
      if ((decision === 'approve' && ['approved', 'reserved'].includes(before.phase)) || (decision === 'reject' && before.phase === 'rejected')) return before;
      return ['outcome_unknown', 'absent', 'expired'].includes(before.phase) ? before : Object.freeze({ phase: 'conflict' });
    }
    let n; try { n = now(); } catch { return unknown(); }
    if (n >= Math.min(timestamp(before.intent.approvalExpiresAt), timestamp(before.intent.jobExpiresAt))) return locked(inv => observation(expire(inv.get(id), now())));
    const binding = freeze({ requestId: id, intentDigest: before.intentDigest, decision, ownerId: policy.ownerId, policyDigest: digest(policy) });
    const controller = new AbortController(); let timer, grant;
    try {
      grant = await Promise.race([Promise.resolve().then(() => options.decisionAuthority(binding, controller.signal)), new Promise((_, reject) => { timer = setTimeout(() => { controller.abort(); reject(Error('authority_timeout')); }, policy.authorityTimeoutMs); })]);
    } catch { controller.abort(); return Object.freeze({ phase: 'denied' }); }
    finally { clearTimeout(timer); }
    return locked(inv => {
      const state = inv.get(id), current = now(); if (!state || canonical(state.intent.payload) !== canonical(before.intent) || state.intent.intentDigest !== binding.intentDigest) deny();
      expire(state, current); if (state.decision) return state.decision.payload.phase === 'expired' || state.decision.payload.phase === (decision === 'approve' ? 'approved' : 'rejected') ? observation(state) : Object.freeze({ phase: 'conflict' });
      const g = data(grant, [...Object.keys(binding), 'authorityId', 'authorizedAt', 'validUntil', 'stillValid']);
      if (Object.entries(binding).some(([k, v]) => g[k] !== v) || typeof g.authorityId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(g.authorityId) || !Number.isSafeInteger(g.authorizedAt) || !Number.isSafeInteger(g.validUntil) || g.authorizedAt < n || g.authorizedAt > current || g.validUntil <= current || g.validUntil > Math.min(timestamp(before.intent.approvalExpiresAt), timestamp(before.intent.jobExpiresAt)) || typeof g.stillValid !== 'function' || g.stillValid() !== true) deny();
      // Recheck continuity and exact bytes again at each candidate/final create.
      const at = now(); guard(); if (at >= g.validUntil) deny(); checkLifetime(state.intent.payload, at);
      const fresh = inventory().get(id); if (!fresh || fresh.decision || canonical(fresh.intent) !== canonical(state.intent)) deny();
      state.decision = publish(id, 'decision', binding.intentDigest, { phase: decision === 'approve' ? 'approved' : 'rejected', at, authorityId: g.authorityId }, () => {
        if (g.stillValid() !== true) deny(); const t = now(); guard(); if (t >= g.validUntil) deny(); checkLifetime(state.intent.payload, t);
        if (read(file(id, 'intent')).bytes !== read(file(id, 'intent', true)).bytes || canonical(read(file(id, 'intent')).value) !== canonical(state.intent) || !missing(file(id, 'decision'))) deny();
      });
      return observation(state);
    });
  }
  // This object must remain inside a future trusted executor composition. Tokens
  // are opaque, instance-local, and deliberately absent from inspect/replay.
  function reserve(id) {
    requestId(id); let token;
    const result = locked(inv => {
      const state = inv.get(id); if (!state) return Object.freeze({ phase: 'absent' }); const n = now(); expire(state, n);
      if (state.reservation || state.decision?.payload.phase !== 'approved') return observation(state);
      checkLifetime(state.intent.payload, n);
      state.reservation = publish(id, 'reservation', state.intent.intentDigest, { phase: 'reserved', at: n, decisionReceiptId: state.decision.receiptId }, () => {
        const t = now(); guard(); checkLifetime(state.intent.payload, t);
        if (canonical(read(file(id, 'intent')).value) !== canonical(state.intent) || canonical(read(file(id, 'decision')).value) !== canonical(state.decision)) deny();
      });
      token = Object.freeze(Object.create(null)); return observation(state);
    });
    return result.phase === 'reserved' && token ? Object.freeze({ ...result, token }) : result;
  }
  return Object.freeze({ submit, inspect, decide, reserve });
}

export function createAdmissionStore(input) {
  try { return buildAdmissionStore(input); } catch { deny(); }
}
