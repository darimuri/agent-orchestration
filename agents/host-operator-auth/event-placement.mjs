// Local candidate publication only: A1 authenticates; A2 remains policy authority.
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { types } from 'node:util';
import { verifyOwnerEvent } from './owner-event.mjs';
import { binding, hexadecimal } from '../scripts/host-operator-protocol.mjs';

const deny = () => { const e = Error('event_placement_denied'); e.code = 'event_placement_denied'; e.stack = 'event_placement_denied'; throw e; };
const result = (status, eventId) => Object.freeze({ status, code: status === 'confirmed' ? 'durability_confirmed' : status === 'already_present' ? 'durability_unproven' : status, ...(eventId && { eventId }) });
const identity = s => `${s.dev}:${s.ino}`;
const fingerprint = s => [s.dev, s.ino, s.uid, s.gid, s.mode, s.nlink, s.size, s.mtimeNs, s.ctimeNs].join(':');
function data(value, allowed, required = allowed) {
  if (!value || typeof value !== 'object' || types.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) deny();
  const props = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(props).some(k => typeof k !== 'string' || !allowed.includes(k) || !Object.hasOwn(props[k], 'value') || !props[k].enumerable) || required.some(k => !Object.hasOwn(props, k))) deny();
  return Object.fromEntries(Object.entries(props).map(([k, p]) => [k, p.value]));
}
function bytes(raw) {
  if (typeof raw === 'string') {
    if (!raw.isWellFormed() || Buffer.byteLength(raw) < 1 || Buffer.byteLength(raw) > 16384) deny();
    return Buffer.from(raw);
  }
  if (!raw || typeof raw !== 'object' || types.isProxy(raw) || !Buffer.isBuffer(raw) || Object.getPrototypeOf(raw) !== Buffer.prototype) deny();
  const length = Reflect.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), 'byteLength').get.call(raw);
  if (length < 1 || length > 16384) deny();
  const backing = Reflect.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), 'buffer').get.call(raw);
  if (types.isSharedArrayBuffer(backing)) deny();
  const props = Object.getOwnPropertyDescriptors(raw), keys = Reflect.ownKeys(props);
  if (keys.length !== length || keys.some((k, i) => k !== String(i) || !Object.hasOwn(props[k], 'value'))) deny();
  // Copy only ordinary indexed data; no caller method/property lookup.
  return Buffer.from(keys.map(k => props[k].value));
}
function ancestors(directory, uid) {
  if (fs.realpathSync(directory) !== directory) deny();
  for (let dir = directory; ; dir = path.dirname(dir)) {
    const s = fs.lstatSync(dir, { bigint: true });
    const tmp = dir === '/tmp' && (s.mode & 0o1000n) && [0n, BigInt(uid)].includes(s.uid);
    if (!s.isDirectory() || s.isSymbolicLink() || ![0n, BigInt(uid)].includes(s.uid) || (!tmp && (s.mode & 0o022n))) deny();
    if (dir === path.dirname(dir)) break;
  }
}
function privateDir(s, uid) {
  if (!s.isDirectory() || s.uid !== BigInt(uid) || (s.mode & 0o7777n) !== 0o700n) deny();
}
function privateFile(s, uid, dev, size, links = 1n) {
  if (!s.isFile() || s.uid !== BigInt(uid) || s.dev !== dev || s.nlink !== links || (s.mode & 0o7777n) !== 0o600n || s.size !== BigInt(size)) deny();
}

export function createFileEventPlacer(options) {
  let config;
  try {
    config = data(options, ['directory', 'uid', 'ownerPubkey', 'targetPubkey', 'channelId', 'threadId', 'source', 'clock'], ['directory', 'uid', 'ownerPubkey', 'targetPubkey', 'channelId', 'threadId', 'source']);
    config.source = binding(data(config.source, ['repository', 'baseRef', 'baseSha', 'workspaceId', 'sourceDigest']));
    const { directory, uid, ownerPubkey, targetPubkey, channelId, threadId } = config;
    hexadecimal(ownerPubkey); hexadecimal(targetPubkey); hexadecimal(threadId);
    if (typeof channelId !== 'string' || !/^[a-f0-9-]{36}$/.test(channelId) || process.platform !== 'linux' || !Number.isSafeInteger(uid) || uid <= 0 || uid !== process.getuid() ||
        typeof directory !== 'string' || !directory.isWellFormed() || directory.includes('\0') || directory.endsWith('/') || !path.isAbsolute(directory) || path.normalize(directory) !== directory || Buffer.byteLength(directory) > 4000 ||
        (config.clock !== undefined && typeof config.clock !== 'function')) deny();
  } catch { deny(); }
  const { directory, uid, clock = Date.now } = config;
  return Object.freeze({ place(raw) {
    let parent, stageFd, attempted = false, eventId;
    try {
      if (arguments.length !== 1) deny();
      const input = bytes(raw);
      let previous = -1;
      const time = () => { const now = clock(); if (!Number.isSafeInteger(now) || now < 0 || now < previous) deny(); previous = now; return now; };
      const verify = () => verifyOwnerEvent(input, { ...config, now: time() });
      eventId = verify().request.authorizationEventId;
      const final = path.join(directory, eventId + '.json');
      ancestors(directory, uid);
      const named = fs.lstatSync(directory, { bigint: true }); privateDir(named, uid);
      parent = fs.openSync(directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
      const anchor = fs.fstatSync(parent, { bigint: true }); privateDir(anchor, uid);
      if (identity(named) !== identity(anchor)) deny();
      const guard = () => {
        ancestors(directory, uid);
        for (const s of [fs.lstatSync(directory, { bigint: true }), fs.fstatSync(parent, { bigint: true })]) {
          privateDir(s, uid); if (identity(s) !== identity(anchor)) deny();
        }
      };
      const read = (file, expected, links = 1n) => {
        guard(); const before = fs.lstatSync(file, { bigint: true });
        // Existing differing lengths are still conflicts, provided metadata is safe.
        if (before.size < 1n || before.size > 16384n) deny();
        privateFile(before, uid, anchor.dev, Number(before.size), links);
        if (expected && identity(before) !== identity(expected)) deny();
        const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
        try {
          const opened = fs.fstatSync(fd, { bigint: true }); if (fingerprint(before) !== fingerprint(opened)) deny();
          const buffer = Buffer.alloc(Number(opened.size) + 1), count = fs.readSync(fd, buffer, 0, buffer.length, 0);
          if (count !== Number(opened.size) || fingerprint(opened) !== fingerprint(fs.fstatSync(fd, { bigint: true })) || fingerprint(opened) !== fingerprint(fs.lstatSync(file, { bigint: true }))) deny();
          guard(); return buffer.subarray(0, count);
        } finally { fs.closeSync(fd); }
      };
      guard();
      try { const existing = read(final); return result(existing.equals(input) ? 'already_present' : 'conflict', eventId); }
      catch (error) { if (error.code !== 'ENOENT') throw error; }
      const stage = path.join(directory, '.event-' + randomBytes(24).toString('hex') + '.tmp');
      stageFd = fs.openSync(stage, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK, 0o600);
      const initial = fs.fstatSync(stageFd, { bigint: true }); privateFile(initial, uid, anchor.dev, 0);
      for (let offset = 0; offset < input.length;) {
        const count = fs.writeSync(stageFd, input, offset, input.length - offset, offset);
        if (!Number.isSafeInteger(count) || count <= 0 || count > input.length - offset) deny(); offset += count;
      }
      fs.fsyncSync(stageFd);
      const staged = fs.fstatSync(stageFd, { bigint: true }); privateFile(staged, uid, anchor.dev, input.length);
      if (identity(initial) !== identity(staged) || !read(stage, staged).equals(input)) deny();
      guard(); verify();
      attempted = true;
      fs.linkSync(stage, final); // Atomic create-only; NEVER overwrite-rename or copy fallback.
      privateFile(fs.fstatSync(stageFd, { bigint: true }), uid, anchor.dev, input.length, 2n);
      if (!read(stage, staged, 2n).equals(input) || !read(final, staged, 2n).equals(input)) deny();
      guard();
      const cleanup = fs.lstatSync(stage, { bigint: true }); privateFile(cleanup, uid, anchor.dev, input.length, 2n);
      if (identity(cleanup) !== identity(staged)) deny();
      fs.unlinkSync(stage); // Only this positively identified call-owned stage, on the success path.
      fs.fsyncSync(parent);
      if (!read(final, staged).equals(input)) deny();
      fs.closeSync(stageFd); stageFd = undefined; fs.closeSync(parent); parent = undefined;
      return result('confirmed', eventId);
    } catch { return result(attempted ? 'outcome_unknown' : 'denied', eventId); }
    finally { for (const fd of [stageFd, parent]) if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* No repair or retry. */ } } }
  } });
}
