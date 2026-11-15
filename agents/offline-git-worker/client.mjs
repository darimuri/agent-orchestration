// Trusted host/validator use ONLY. FD ownership comes from the qualified launcher.
// No process launcher, path option, injected transport, or operational test mode.
import fs from 'node:fs';
import { binding, exact, encodeFrame, decodeFrame, OP, LIMITS, HEADER } from './protocol.mjs';
const fail = () => { throw Error('offline_git_channel_unknown'); };
export function createOfflineGitClient(options) {
  exact(options, ['channelFd', 'binding']);
  const scope = binding(options.binding), fd = options.channelFd;
  if (!Number.isInteger(fd) || fd < 3 || !fs.fstatSync(fd).isSocket()) fail();
  let sequence = 0, dead = false, total = 0, packets = 0;
  // The launcher sets socket deadlines. EOF, partial packets and uncertainty poison
  // the capability; do not repeat a request or manufacture a successful replay.
  function request(op, payload) {
    if (dead || ++sequence > 0xffffffff) fail();
    try {
      const bytes = encodeFrame(scope, sequence, op, payload);
      if (fs.writeSync(fd, bytes) !== bytes.length) fail();
      const chunks = []; let size = 0;
      for (;;) {
        const b = Buffer.alloc(LIMITS.frame + 1), n = fs.readSync(fd, b, 0, b.length, null);
        if (n < HEADER || n > LIMITS.frame || ++packets > LIMITS.frames) fail();
        const result = decodeFrame(b.subarray(0, n), scope, sequence);
        if (result.op === OP.END) return Buffer.concat(chunks, size);
        if (result.op !== OP.DATA || (total += result.payload.length) > LIMITS.machine) fail();
        size += result.payload.length; chunks.push(result.payload);
      }
    } catch { dead = true; fail(); }
  }
  return Object.freeze({
    open(handle) { if (typeof handle !== 'string' || !/^[a-f0-9]{64}$/.test(handle)) fail(); return request(OP.OPEN, Buffer.from(handle, 'hex')); },
    step(op, payload = Buffer.alloc(0)) { if (![OP.INIT, OP.INDEX_PACK, OP.VERIFY_PACK, OP.FSCK, OP.OBJECT, OP.TREE].includes(op)) fail(); return request(op, payload); },
    settle() { return request(OP.SETTLE, Buffer.alloc(0)); },
    adopt(inventoryDigest) { if (typeof inventoryDigest !== 'string' || !/^[a-f0-9]{64}$/.test(inventoryDigest)) fail(); return request(OP.ADOPT, Buffer.from(inventoryDigest, 'hex')); },
    observe() { return request(OP.OBSERVE, Buffer.alloc(0)); }
  });
}
