// Internal fixed worker protocol only. No public CLI, authority, shell or transport.
import { createDetachedRevisionObserver } from './revision-source.mjs';
import { parseEvidence, canonicalEvidence } from './revision-evidence.mjs';
import { exact, bounded, identifier, hexadecimal, timestamp } from '../scripts/host-operator-protocol.mjs';
try {
  let size = 0; const chunks = [];
  for await (const chunk of process.stdin) { size += chunk.length; if (size > 8192) throw Error('input'); chunks.push(chunk); }
  const c = parseEvidence(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)), 8192);
  exact(c, ['sourceDirectory', 'uid', 'source', 'runId', 'requestHash', 'intentDigest', 'startedAt']); identifier(c.runId); hexadecimal(c.requestHash); hexadecimal(c.intentDigest); timestamp(c.startedAt);
  // Parent-provided wall sample is result data, never completion-time authority.
  // A11's independent monotonic elapsed read budget remains active.
  const observation = createDetachedRevisionObserver({ sourceDirectory: c.sourceDirectory, uid: c.uid, source: c.source, clock: () => c.startedAt }).observe();
  const result = { ...observation, runId: c.runId, requestHash: c.requestHash, intentDigest: c.intentDigest }; bounded(result, 4096); process.stdout.write(canonicalEvidence(result));
} catch { process.stdout.write('{"code":"worker_failed","status":"failed"}'); process.exitCode = 1; }
