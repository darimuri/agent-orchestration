// Candidate-byte source only. A1 authenticates every read; A2 authorizes policy.
import fs from 'node:fs';
import path from 'node:path';
import { performance } from 'node:perf_hooks';

const denied = () => {
  const error = new Error('event_source_denied');
  error.code = 'event_source_denied'; error.stack = 'event_source_denied';
  throw error;
};
const fingerprint = s => [s.dev, s.ino, s.uid, s.gid, s.mode, s.nlink, s.size, s.mtimeNs, s.ctimeNs].join(':');
function ancestors(directory, uid) {
  if (fs.realpathSync(directory) !== directory) denied();
  for (let dir = directory; ; dir = path.dirname(dir)) {
    const s = fs.lstatSync(dir, { bigint: true });
    const fixtureTmp = dir === '/tmp' && (s.mode & 0o1000n) && [0n, BigInt(uid)].includes(s.uid);
    if (!s.isDirectory() || s.isSymbolicLink() || ![0n, BigInt(uid)].includes(s.uid) ||
        (!fixtureTmp && (s.mode & 0o022n))) denied();
    if (dir === path.dirname(dir)) break;
  }
}
function privateDirectory(s, uid) {
  if (!s.isDirectory() || s.uid !== BigInt(uid) || (s.mode & 0o7777n) !== 0o700n) denied();
}
function privateFile(s, uid) {
  if (!s.isFile() || s.uid !== BigInt(uid) || s.nlink !== 1n ||
      (s.mode & 0o7777n) !== 0o600n || s.size < 1n || s.size > 16384n) denied();
}

export function createFileEventResolver(options) {
  try {
    if (!options || typeof options !== 'object' || Object.getPrototypeOf(options) !== Object.prototype) denied();
    const props = Object.getOwnPropertyDescriptors(options);
    if (Reflect.ownKeys(options).some(k => typeof k !== 'string' || !['directory', 'uid', 'clock', 'monotonic'].includes(k)) ||
        !Object.hasOwn(props, 'directory') || !Object.hasOwn(props, 'uid') ||
        Object.values(props).some(p => !Object.hasOwn(p, 'value') || !p.enumerable)) denied();
    const { directory, uid, clock = Date.now, monotonic = () => performance.now() } = options;
    if (process.platform !== 'linux' || typeof process.getuid !== 'function' ||
        !Number.isSafeInteger(uid) || uid <= 0 || uid !== process.getuid() ||
        typeof directory !== 'string' || !directory.isWellFormed() || directory.includes('\0') ||
        directory.endsWith('/') || !path.isAbsolute(directory) || path.normalize(directory) !== directory ||
        Buffer.byteLength(directory) > 4096 || typeof clock !== 'function' || typeof monotonic !== 'function') denied();
    return eventId => {
      let parent, input, result;
      try {
        if (typeof eventId !== 'string' || !/^[a-f0-9]{64}$/.test(eventId)) denied();
        const file = path.join(directory, eventId + '.json'); if (Buffer.byteLength(file) > 4096) denied();
        let start, previous;
        const elapsed = () => {
          const wall = clock(), mono = monotonic();
          if (!Number.isSafeInteger(wall) || wall < 0 || !Number.isFinite(mono) || mono < 0) denied();
          if (previous && (wall < previous.wall || mono < previous.mono)) denied();
          if (!start) start = { wall, mono };
          if (wall - start.wall > 100 || mono - start.mono > 100) denied();
          previous = { wall, mono };
        };
        elapsed(); ancestors(directory, uid);
        const namedParent = fs.lstatSync(directory, { bigint: true }); privateDirectory(namedParent, uid);
        parent = fs.openSync(directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
        const anchor = fs.fstatSync(parent, { bigint: true }); privateDirectory(anchor, uid);
        if (anchor.dev !== namedParent.dev || anchor.ino !== namedParent.ino) denied();
        const guard = () => {
          ancestors(directory, uid);
          const named = fs.lstatSync(directory, { bigint: true }), held = fs.fstatSync(parent, { bigint: true });
          privateDirectory(named, uid); privateDirectory(held, uid);
          if (named.dev !== anchor.dev || named.ino !== anchor.ino || held.dev !== anchor.dev || held.ino !== anchor.ino) denied();
        };
        elapsed(); guard();
        const before = fs.lstatSync(file, { bigint: true }); privateFile(before, uid);
        if (before.dev !== anchor.dev) denied();
        input = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
        const opened = fs.fstatSync(input, { bigint: true }); privateFile(opened, uid);
        if (fingerprint(before) !== fingerprint(opened)) denied();
        elapsed(); guard();
        const bytes = Buffer.alloc(Number(opened.size) + 1);
        const count = fs.readSync(input, bytes, 0, bytes.length, 0);
        const after = fs.fstatSync(input, { bigint: true }), named = fs.lstatSync(file, { bigint: true });
        privateFile(after, uid); privateFile(named, uid); guard();
        if (count !== Number(opened.size) || fingerprint(opened) !== fingerprint(after) || fingerprint(opened) !== fingerprint(named)) denied();
        result = Buffer.from(bytes.subarray(0, count));
        fs.closeSync(input); input = undefined; fs.closeSync(parent); parent = undefined;
        elapsed(); return result;
      } catch { denied(); }
      finally {
        for (const fd of [input, parent]) if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* denial is already fixed */ } }
      }
    };
  } catch { denied(); }
}
