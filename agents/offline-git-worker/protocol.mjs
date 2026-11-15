// OGW1 is a private FD protocol, not authorization or an executable locator.
import { types } from 'node:util';
export const LIMITS = Object.freeze({ control: 16384, frame: 65536, bundle: 33554432,
  machine: 268435456, diagnostics: 1048576, reads: 20000, frames: 65536,
  object: 8388608, wallMs: 30000, settlementMs: 2000, outerMs: 40000,
  cpuGuardUs: 8000000, cpuFinalUs: 10000000, memory: 536870912,
  scratch: 268435456, inodes: 65536, pids: 8 });
export const OP = Object.freeze({ OPEN: 1, INIT: 2, INDEX_PACK: 3, VERIFY_PACK: 4,
  FSCK: 5, OBJECT: 6, TREE: 7, SETTLE: 8, ADOPT: 9, OBSERVE: 10,
  DATA: 11, END: 12, DENIED: 13, UNKNOWN: 14 });
export const BINDINGS = Object.freeze(['nonce', 'intent', 'artifact', 'policy', 'capability', 'context']);
export const HEADER = 208;
const denied = () => { throw Object.assign(Error('offline_git_protocol_denied'), { code: 'offline_git_protocol_denied' }); };
export function exact(v, keys) {
  if (!v || typeof v !== 'object' || types.isProxy(v) || Object.getPrototypeOf(v) !== Object.prototype ||
      Object.getOwnPropertySymbols(v).length) denied();
  const d = Object.getOwnPropertyDescriptors(v);
  if (Object.keys(d).length !== keys.length || keys.some(k => !Object.hasOwn(d, k)) ||
      Object.values(d).some(p => !Object.hasOwn(p, 'value') || !p.enumerable)) denied();
}
export function binding(raw) {
  exact(raw, BINDINGS);
  const v = {};
  for (const k of BINDINGS) { if (typeof raw[k] !== 'string' || !/^[a-f0-9]{64}$/.test(raw[k]) || /^0+$/.test(raw[k])) denied(); v[k] = raw[k]; }
  return Object.freeze(v);
}
function payloadOK(op, b) {
  switch (op) {
    case OP.OPEN: return b.length === 32; // host-issued 256-bit inbox handle
    case OP.INDEX_PACK: return b.length === 16 && b.readBigUInt64BE(0) <= BigInt(LIMITS.bundle) &&
      b.readBigUInt64BE(8) > 0n && b.readBigUInt64BE(0) + b.readBigUInt64BE(8) <= BigInt(LIMITS.bundle);
    case OP.OBJECT: case OP.TREE: return b.length === 20;
    case OP.ADOPT: return b.length === 32; // exact sealed validator inventory digest
    case OP.INIT: case OP.VERIFY_PACK: case OP.FSCK: case OP.SETTLE: case OP.OBSERVE:
    case OP.END: case OP.DENIED: case OP.UNKNOWN: return b.length === 0;
    case OP.DATA: return b.length <= LIMITS.frame - HEADER;
    default: return false;
  }
}
export function encodeFrame(scope, sequence, op, payload = Buffer.alloc(0)) {
  const s = binding(scope);
  if (!Number.isInteger(sequence) || sequence < 1 || sequence > 0xffffffff || !Buffer.isBuffer(payload) ||
      !payloadOK(op, payload) || HEADER + payload.length > (op === OP.DATA ? LIMITS.frame : LIMITS.control)) denied();
  const b = Buffer.alloc(HEADER + payload.length);
  b.write('OGW1'); b.writeUInt16BE(1, 4); b.writeUInt16BE(op, 6);
  b.writeUInt32BE(sequence, 8); b.writeUInt32BE(payload.length, 12);
  BINDINGS.forEach((k, i) => Buffer.from(s[k], 'hex').copy(b, 16 + i * 32));
  payload.copy(b, HEADER); return b;
}
export function decodeFrame(bytes, scope, sequence) {
  if (!Buffer.isBuffer(bytes) || bytes.length < HEADER || bytes.length > LIMITS.frame ||
      bytes.toString('ascii', 0, 4) !== 'OGW1' || bytes.readUInt16BE(4) !== 1 ||
      bytes.readUInt32BE(8) !== sequence || !Number.isInteger(sequence) || sequence < 1 ||
      bytes.readUInt32BE(12) !== bytes.length - HEADER) denied();
  const op = bytes.readUInt16BE(6), payload = bytes.subarray(HEADER);
  if (!payloadOK(op, payload) || bytes.length > (op === OP.DATA ? LIMITS.frame : LIMITS.control)) denied();
  const s = binding(scope);
  BINDINGS.forEach((k, i) => { if (bytes.subarray(16 + i * 32, 48 + i * 32).toString('hex') !== s[k]) denied(); });
  return Object.freeze({ op, payload: Buffer.from(payload) });
}
// Shared finite state, including cumulative reads, bytes and frames. No reset API.
export function createSessionState() {
  let stage = 0, reads = 0, frames = 0, machine = 0, diagnostics = 0, dead = false;
  return Object.freeze({
    accept(op) {
      if (dead) denied();
      if (op === OP.SETTLE && stage >= 4) { stage = 5; return; }
      if (op === OP.ADOPT && stage === 5) { stage = 6; return; }
      if (stage < 4 && op === [OP.INIT, OP.INDEX_PACK, OP.VERIFY_PACK, OP.FSCK][stage]) { stage++; return; }
      if (stage === 4 && [OP.OBJECT, OP.TREE].includes(op) && ++reads <= LIMITS.reads) return;
      dead = true; denied();
    },
    charge(output, diagnostic = 0) {
      if (dead || !Number.isSafeInteger(output) || output < 0 || !Number.isSafeInteger(diagnostic) || diagnostic < 0 ||
          ++frames > LIMITS.frames || (machine += output) > LIMITS.machine || (diagnostics += diagnostic) > LIMITS.diagnostics) { dead = true; denied(); }
    },
    poison() { dead = true; },
    snapshot() { return Object.freeze({ stage, reads, frames, machine, diagnostics, dead }); }
  });
}
