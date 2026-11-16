// Fixed AGE30 SHA1 fixture validator, not AGE28 semantic importer logic.
// Runtime closure places this at /validator/entry.mjs, with the unmodified
// client.mjs and protocol.mjs alongside it. No caller module or profile selector.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
const fail = () => { throw Error('age30_validator_unknown'); };
const oid = (type, b) => createHash('sha1').update(Buffer.from(`${type} ${b.length}\0`)).update(b).digest('hex');
export function fixtureObjects() {
  const blob = Buffer.from('AGE30 fixture\n');
  const blobOid = oid('blob', blob);
  const tree = Buffer.concat([Buffer.from('100644 fixture.txt\0'), Buffer.from(blobOid,'hex')]);
  const treeOid = oid('tree',tree);
  const commit = Buffer.from(`tree ${treeOid}\nauthor AGE30 <fixture@example.invalid> 0 +0000\ncommitter AGE30 <fixture@example.invalid> 0 +0000\n\nAGE30 fixture\n`);
  return { blob, blobOid, tree, treeOid, commit, commitOid: oid('commit',commit) };
}
export function parseFixtureBundle(b) {
  if (!Buffer.isBuffer(b) || b.length > 33554432) fail();
  const f = fixtureObjects(), header = Buffer.from(`# v2 git bundle\n${f.commitOid} refs/heads/candidate\n\n`);
  if (b.length < header.length + 32 || !b.subarray(0,header.length).equals(header)) fail();
  const pack = b.subarray(header.length);
  if (pack.toString('ascii',0,4) !== 'PACK' || pack.readUInt32BE(4) !== 2 || pack.readUInt32BE(8) !== 3 ||
      !createHash('sha1').update(pack.subarray(0,-20)).digest().equals(pack.subarray(-20))) fail();
  return { offset: header.length, length: pack.length };
}
export function checkBatch(b, type, expectedOid, raw) {
  const header = Buffer.from(`${expectedOid} ${type} ${raw.length}\n`);
  if (!Buffer.isBuffer(b) || !b.equals(Buffer.concat([header, raw, Buffer.from('\n')]))) fail();
  if (oid(type,raw) !== expectedOid) fail();
}
function heldBytes(fd, maximum, exactSize) {
  const s = fs.fstatSync(fd); if (!s.isFile() || !Number.isSafeInteger(s.size) || s.size < 1 || s.size > maximum ||
    (exactSize !== undefined && s.size !== exactSize)) fail();
  const b = Buffer.alloc(s.size); let n = 0;
  while (n < b.length) { const got = fs.readSync(fd,b,n,b.length-n,n); if (!got) fail(); n += got; }
  return b;
}
async function main() {
  if (process.argv.length !== 2 || process.getuid() !== 10002 || process.geteuid() !== 10002) fail();
  const capsule = heldBytes(4,496,496), bundle = heldBytes(5,33554432);
  if (capsule.toString('ascii',0,4) !== 'OGC2' || capsule.readUInt32BE(4) !== 2) fail();
  const scope = {};
  ['nonce','intent','artifact','policy','capability','context'].forEach((key,i) => {
    scope[key] = capsule.subarray(8 + i * 32,40 + i * 32).toString('hex');
  });
  const { createOfflineGitClient } = await import('file:///validator/client.mjs');
  const { OP } = await import('file:///validator/protocol.mjs');
  const client = createOfflineGitClient({ channelFd:3, binding:scope });
  const range = parseFixtureBundle(bundle), payload = Buffer.alloc(16);
  payload.writeBigUInt64BE(BigInt(range.offset)); payload.writeBigUInt64BE(BigInt(range.length),8);
  client.step(OP.INIT); client.step(OP.INDEX_PACK,payload); client.step(OP.VERIFY_PACK); client.step(OP.FSCK);
  const f = fixtureObjects();
  checkBatch(client.step(OP.OBJECT,Buffer.from(f.commitOid,'hex')),'commit',f.commitOid,f.commit);
  checkBatch(client.step(OP.OBJECT,Buffer.from(f.blobOid,'hex')),'blob',f.blobOid,f.blob);
  const tree = client.step(OP.TREE,Buffer.from(f.treeOid,'hex')); if (!tree.equals(f.tree)) fail();
  client.settle(); // No external OPEN/ADOPT capability is forwarded to this process.
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(() => { process.stderr.write('age30_validator_unknown\n'); process.exitCode = 70; });
}
