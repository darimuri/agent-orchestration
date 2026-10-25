// Detached HEAD pointer observation only: no Git invocation or execution authority.
import fs from 'node:fs';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { types } from 'node:util';
import { binding } from '../scripts/host-operator-protocol.mjs';

const denied = () => {
  const e = Error('revision_source_denied'); e.code = 'revision_source_denied'; e.stack = 'revision_source_denied'; throw e;
};
const fingerprint = s => [s.dev, s.ino, s.uid, s.gid, s.mode, s.nlink, s.size, s.mtimeNs, s.ctimeNs].join(':');
function own(value) {
  if (!value || typeof value !== 'object' || types.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) denied();
  const props = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(props).some(k => typeof k !== 'string' || !Object.hasOwn(props[k], 'value') || !props[k].enumerable)) denied();
  return Object.fromEntries(Object.entries(props).map(([k, p]) => [k, p.value]));
}
function directory(s, uid) {
  if (!s.isDirectory() || s.isSymbolicLink() || ![0n, BigInt(uid)].includes(s.uid) || (s.mode & 0o7022n)) denied();
}
function ancestry(root, uid) {
  if (fs.realpathSync(root) !== root) denied();
  for (let p = root; ; p = path.dirname(p)) {
    const s = fs.lstatSync(p, { bigint: true });
    const fixtureTmp = p === '/tmp' && (s.mode & 0o1000n) && [0n, BigInt(uid)].includes(s.uid);
    if (!s.isDirectory() || s.isSymbolicLink() || ![0n, BigInt(uid)].includes(s.uid) || (!fixtureTmp && (s.mode & 0o7022n))) denied();
    if (p === path.dirname(p)) break;
  }
}
function headFile(s, uid, dev) {
  // The owner-approved handoff requires ordinary same-UID HEAD metadata. Unlike
  // secret event/ledger files, non-secret HEAD may be readable by group/others.
  if (!s.isFile() || s.uid !== BigInt(uid) || s.dev !== dev || s.nlink !== 1n || (s.mode & 0o7022n) || ![40n, 41n].includes(s.size)) denied();
}

export function createDetachedRevisionObserver(options) {
  try {
    const config = own(options), required = ['sourceDirectory', 'uid', 'source'];
    if (Object.keys(config).some(k => ![...required, 'clock', 'monotonic'].includes(k)) || required.some(k => !Object.hasOwn(config, k))) denied();
    const { sourceDirectory: root, uid, clock = Date.now, monotonic = () => performance.now() } = config;
    if (process.platform !== 'linux' || !Number.isSafeInteger(uid) || uid <= 0 || uid !== process.getuid() ||
        typeof root !== 'string' || !root.isWellFormed() || root.includes('\0') || root.endsWith('/') || !path.isAbsolute(root) || path.normalize(root) !== root ||
        Buffer.byteLength(root) > 4086 || typeof clock !== 'function' || typeof monotonic !== 'function') denied();
    const source = Object.freeze(binding(own(config.source))), metadata = path.join(root, '.git'), file = path.join(metadata, 'HEAD');
    if (Buffer.byteLength(file) > 4096) denied();
    return Object.freeze({ observe() {
      let rootFd, metadataFd, input;
      try {
        if (arguments.length !== 0) denied();
        let start, previous;
        const elapsed = () => {
          const wall = clock(), mono = monotonic();
          if (!Number.isSafeInteger(wall) || wall < 0 || !Number.isFinite(mono) || mono < 0 || (previous && (wall < previous.wall || mono < previous.mono))) denied();
          if (!start) start = { wall, mono };
          if (wall - start.wall > 100 || mono - start.mono > 100) denied();
          previous = { wall, mono }; return wall;
        };
        elapsed(); ancestry(root, uid);
        const namedRoot = fs.lstatSync(root, { bigint: true }); directory(namedRoot, uid);
        const flags = fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK;
        rootFd = fs.openSync(root, flags);
        const rootAnchor = fs.fstatSync(rootFd, { bigint: true }); directory(rootAnchor, uid);
        if (fingerprint(namedRoot) !== fingerprint(rootAnchor)) denied();
        const namedMetadata = fs.lstatSync(metadata, { bigint: true }); directory(namedMetadata, uid);
        if (fs.realpathSync(metadata) !== metadata) denied();
        metadataFd = fs.openSync(metadata, flags);
        const metadataAnchor = fs.fstatSync(metadataFd, { bigint: true }); directory(metadataAnchor, uid);
        if (fingerprint(namedMetadata) !== fingerprint(metadataAnchor)) denied();
        const guard = () => {
          ancestry(root, uid);
          if (fs.realpathSync(metadata) !== metadata) denied();
          for (const [name, fd, anchor] of [[root, rootFd, rootAnchor], [metadata, metadataFd, metadataAnchor]]) {
            for (const s of [fs.lstatSync(name, { bigint: true }), fs.fstatSync(fd, { bigint: true })]) {
              directory(s, uid); if (fingerprint(s) !== fingerprint(anchor)) denied();
            }
          }
        };
        elapsed(); guard();
        const before = fs.lstatSync(file, { bigint: true }); headFile(before, uid, metadataAnchor.dev);
        input = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
        const opened = fs.fstatSync(input, { bigint: true }); headFile(opened, uid, metadataAnchor.dev);
        if (fingerprint(before) !== fingerprint(opened)) denied();
        elapsed(); guard();
        const bytes = Buffer.alloc(42), count = fs.readSync(input, bytes, 0, 42, 0);
        const after = fs.fstatSync(input, { bigint: true }), named = fs.lstatSync(file, { bigint: true });
        headFile(after, uid, metadataAnchor.dev); headFile(named, uid, metadataAnchor.dev); guard();
        if (count !== Number(opened.size) || fingerprint(opened) !== fingerprint(after) || fingerprint(opened) !== fingerprint(named)) denied();
        const observedSha = bytes.subarray(0, 40).toString('utf8');
        if (!/^[a-f0-9]{40}$/.test(observedSha) || (count === 41 && bytes[40] !== 10)) denied();
        fs.closeSync(input); input = undefined; fs.closeSync(metadataFd); metadataFd = undefined; fs.closeSync(rootFd); rootFd = undefined;
        const observedAt = elapsed();
        return Object.freeze({ status: observedSha === source.baseSha ? 'observed' : 'mismatch', repository: source.repository,
          workspaceId: source.workspaceId, expectedSha: source.baseSha, observedSha, observedAt });
      } catch { denied(); }
      finally {
        for (const fd of [input, metadataFd, rootFd]) if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* Fixed denial; no fallback. */ } }
      }
    } });
  } catch { denied(); }
}
