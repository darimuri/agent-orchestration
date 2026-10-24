// Public-data verifier only: no transport, secrets, processes or policy provider.
import { createHash } from 'node:crypto';
import { schnorr } from '@noble/curves/secp256k1.js';
import { deny, exact, request, binding, descriptor, digest, hexadecimal, timestamp } from '../scripts/host-operator-protocol.mjs';

// JSON.parse alone silently accepts duplicate keys. Scan keys at every depth
// (including escaped spellings) before parsing; JSON.parse remains the grammar
// authority. Bounds are fixed, independent of any request-supplied limits.
function decode(raw, limit) {
  let text;
  if (typeof raw === 'string') text = raw;
  else if (Buffer.isBuffer(raw)) {
    if (raw.length > limit) deny('authorization_denied');
    text = new TextDecoder('utf-8', { fatal: true }).decode(raw);
  } else deny('authorization_denied');
  if (!text.isWellFormed() || Buffer.byteLength(text) > limit) deny('authorization_denied');
  let i = 0;
  const space = () => { while (/[\x20\t\r\n]/.test(text[i] ?? '') && i < text.length) i++; };
  function string() {
    const start = i++;
    while (i < text.length) {
      const c = text[i++];
      if (c === '\\') i++;
      else if (c === '"') {
        const value = JSON.parse(text.slice(start, i));
        if (!value.isWellFormed()) deny('authorization_denied');
        return value;
      }
    }
    deny('authorization_denied');
  }
  function value(depth) {
    if (depth > 16) deny('authorization_denied');
    space();
    const c = text[i];
    if (c === '"') { string(); return; }
    if (c === '{' || c === '[') {
      i++; space(); const end = c === '{' ? '}' : ']'; const keys = new Set();
      if (text[i] === end) { i++; return; }
      while (i < text.length) {
        if (c === '{') {
          if (text[i] !== '"') deny('authorization_denied');
          const key = string(); if (keys.has(key)) deny('authorization_denied'); keys.add(key);
          space(); if (text[i++] !== ':') deny('authorization_denied');
        }
        value(depth + 1); space();
        if (text[i] === end) { i++; return; }
        if (text[i++] !== ',') deny('authorization_denied'); space();
      }
      deny('authorization_denied');
    }
    const token = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(i));
    if (!token) deny('authorization_denied'); i += token[0].length;
  }
  value(0); space(); if (i !== text.length) deny('authorization_denied');
  return JSON.parse(text);
}

export function verifyOwnerEvent(raw, { ownerPubkey, targetPubkey, channelId, threadId, source, now }) {
  try {
    hexadecimal(ownerPubkey); hexadecimal(targetPubkey); hexadecimal(threadId); timestamp(now);
    const trustedSource = binding(source), event = decode(raw, 16384);
    exact(event, ['id', 'pubkey', 'created_at', 'kind', 'tags', 'content', 'sig']);
    hexadecimal(event.id); hexadecimal(event.pubkey);
    if (typeof event.sig !== 'string' || !/^[a-f0-9]{128}$/.test(event.sig) ||
        event.pubkey !== ownerPubkey || event.kind !== 9) deny('authorization_denied');
    timestamp(event.created_at);
    const createdAt = event.created_at * 1000;
    if (!Number.isSafeInteger(createdAt) || createdAt > now + 60000 || now - createdAt > 600000 ||
        typeof event.content !== 'string' || Buffer.byteLength(event.content) > 8192 ||
        !Array.isArray(event.tags) || event.tags.length > 32) deny('authorization_denied');
    for (const tag of event.tags) {
      if (!Array.isArray(tag) || tag.length < 1 || tag.length > 4 ||
          tag.some(v => typeof v !== 'string' || Buffer.byteLength(v) > 256)) deny('authorization_denied');
    }
    // One exact routing tag of each security kind; no competing reply/target.
    for (const [name, expected] of [['h', ['h', channelId]], ['p', ['p', targetPubkey]],
      ['e', ['e', threadId, '', 'root']]]) {
      const tags = event.tags.filter(t => t[0] === name);
      if (tags.length !== 1 || JSON.stringify(tags[0]) !== JSON.stringify(expected)) deny('authorization_denied');
    }
    const id = createHash('sha256').update(JSON.stringify([
      0, event.pubkey, event.created_at, event.kind, event.tags, event.content,
    ])).digest('hex');
    if (id !== event.id || !schnorr.verify(Buffer.from(event.sig, 'hex'), Buffer.from(id, 'hex'),
      Buffer.from(event.pubkey, 'hex'))) deny('authorization_denied');
    const envelope = decode(event.content, 8192);
    exact(envelope, ['type', 'version', 'request', 'descriptorDigest', 'expiresAt']);
    timestamp(envelope.expiresAt); hexadecimal(envelope.descriptorDigest);
    if (envelope.type !== 'host-operator.request' || envelope.version !== 1 ||
        envelope.expiresAt <= now || envelope.expiresAt <= createdAt ||
        envelope.expiresAt - createdAt > 600000) deny('authorization_denied');
    // Reject an embedded authorizationEventId instead of silently overwriting it.
    exact(envelope.request, ['version', 'requestId', 'taskId', 'jobId', 'repository', 'baseRef',
      'baseSha', 'operationId', 'channelId', 'threadId']);
    const r = request({ ...envelope.request, authorizationEventId: id });
    if (r.operationId !== 'status.revision' || r.channelId !== channelId || r.threadId !== threadId) deny('authorization_denied');
    const operation = descriptor(r, trustedSource);
    if (envelope.descriptorDigest !== digest(operation)) deny('authorization_denied');
    return { request: r, descriptor: operation, signerPubkey: event.pubkey, expiresAt: envelope.expiresAt };
  } catch { deny('authorization_denied'); }
}
