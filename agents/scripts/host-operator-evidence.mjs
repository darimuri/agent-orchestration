// Offline metadata lint only. No authority, evidence resolver, storage or host I/O.
import { pathToFileURL } from 'node:url';

const MAX_BYTES = 65536, MAX_REFERENCES = 108;
const typedArrayLength = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), 'length').get;
export const CONTRACT = Object.freeze({
  id: 'host-operator-host-acceptance-a4',
  repository: 'darimuri/agent-orchestration',
  sourceSha: '60d7f6e857c6139e4b776cf5296720f00c5ebc81',
  sourceTree: '500522c773e21c941244fc298fd4a2d28e55222a',
  contractBlob: '50cc24f45d9aef2f2422417d737b28c8202e6767',
  gatewaySha: '59fca5e863c99dd44b7d8d0ad762e00f03402517',
  gatewayTree: 'b1e1430793bcd26b02df9a77aa49a5b5ce16a24b',
});
// Fixed preparation identifiers map to the existing A4 H1-H9 rows, not host facts.
export const REQUIREMENTS = Object.freeze(Object.fromEntries(Object.entries({
  H1: ['installed_set', 'install_boundary', 'source_binding'],
  H2: ['reader_identity', 'private_access', 'agent_exclusion'],
  H3: ['ledger_custody', 'subject_scope', 'owner_mapping'],
  H4: ['writer_source', 'atomic_update', 'pair_recovery'],
  H5: ['namespace_storage', 'capacity_durability', 'restart_recovery'],
  H6: ['clock_latency', 'stall_acceptance', 'revocation_acceptance'],
  H7: ['raw_event_source', 'event_bounds', 'event_failure_replay'],
  H8: ['termination_authority', 'reporter_identity', 'receipt_reconciliation'],
  H9: ['status_scope', 'advisory_assessment', 'activation_decision'],
}).map(([gate, facts]) => [gate, Object.freeze(facts)])));
const revisionFacts = new Set(['installed_set', 'source_binding', 'writer_source', 'advisory_assessment']);
class LintError extends Error { constructor(code) { super(code); this.code = code; } }
const reject = code => { throw new LintError(code); };
function exact(v, keys) {
  if (!v || typeof v !== 'object' || Array.isArray(v) ||
      Object.keys(v).sort().join() !== [...keys].sort().join()) reject('schema');
}
const time = n => Number.isSafeInteger(n) && n >= 0;
const label = s => typeof s === 'string' && /^[a-z][a-z0-9_-]{0,31}$/.test(s);
function list(v, max) { if (!Array.isArray(v) || v.length > max) reject('bounds'); }

// Inspect duplicate keys and fixed structural bounds before JSON.parse loses them.
// No already-parsed objects, accessors, class instances or cached verdicts accepted.
function parse(raw) {
  let text;
  if (typeof raw === 'string') {
    if (raw.length > MAX_BYTES) reject('bounds');
    text = raw;
  } else {
    // Native brand/length inspection rejects proxies and accessors without invoking
    // caller-supplied length getters before checking the bounded byte container.
    let length;
    try { length = typedArrayLength.call(raw); } catch { reject('invalid_input'); }
    if (!Buffer.isBuffer(raw) || Object.getPrototypeOf(raw) !== Buffer.prototype) reject('invalid_input');
    if (length > MAX_BYTES) reject('bounds');
    if (Object.getOwnPropertySymbols(raw).length || Reflect.ownKeys(raw).length !== length) reject('invalid_input');
    try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(raw); }
    catch { reject('invalid_encoding'); }
  }
  if (!text.isWellFormed()) reject('invalid_encoding');
  if (Buffer.byteLength(text) > MAX_BYTES) reject('bounds');
  let i = 0;
  const space = () => { while (i < text.length && /[\x20\t\r\n]/.test(text[i])) i++; };
  function string() {
    const start = i++;
    while (i < text.length) {
      const c = text[i++];
      if (c === '\\') i++;
      else if (c === '"') {
        const s = JSON.parse(text.slice(start, i));
        if (!s.isWellFormed()) reject('invalid_encoding');
        if (Buffer.byteLength(s) > 128) reject('bounds');
        return s;
      }
    }
    reject('invalid_json');
  }
  function value(depth) {
    if (depth > 8) reject('bounds');
    space(); const c = text[i];
    if (c === '"') { string(); return; }
    if (c === '{' || c === '[') {
      i++; space(); const end = c === '{' ? '}' : ']', keys = new Set(); let count = 0;
      if (text[i] === end) { i++; return; }
      while (i < text.length) {
        if (++count > (c === '{' ? 32 : 108)) reject('bounds');
        if (c === '{') {
          if (text[i] !== '"') reject('invalid_json');
          const key = string(); if (keys.has(key)) reject('duplicate_key'); keys.add(key);
          space(); if (text[i++] !== ':') reject('invalid_json');
        }
        value(depth + 1); space();
        if (text[i] === end) { i++; return; }
        if (text[i++] !== ',') reject('invalid_json'); space();
      }
      reject('invalid_json');
    }
    const token = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(i));
    if (!token) reject('invalid_json'); i += token[0].length;
  }
  try { value(0); space(); if (i !== text.length) reject('invalid_json'); return JSON.parse(text); }
  catch (e) { if (e instanceof LintError) throw e; reject('invalid_json'); }
}
function result(structure, codes, gates = []) {
  // No caller strings, references, custodians, revisions, timestamps or errors escape.
  const output = { version: 1, contractId: CONTRACT.id, decision: 'NOT_READY',
    verification: 'INDEPENDENTLY_UNVERIFIED', structure, codes, gates };
  if (Buffer.byteLength(JSON.stringify(output)) > 4096) return result('INVALID', ['output_bound']);
  return output;
}

export function lintEvidenceIndex(raw, asOf) {
  try {
    if (!time(asOf)) reject('invalid_cutoff');
    const index = parse(raw);
    exact(index, ['version', 'contract', 'asOf', 'references', 'gates']);
    if (index.version !== 1) reject('schema');
    exact(index.contract, Object.keys(CONTRACT));
    if (Object.entries(CONTRACT).some(([k, v]) => index.contract[k] !== v)) reject('contract_mismatch');
    if (index.asOf !== asOf) reject('cutoff_mismatch');
    list(index.references, MAX_REFERENCES); list(index.gates, 9);
    if (index.gates.length !== 9) reject('gate_set');
    const references = new Map(), used = new Set(), gates = new Map();
    for (const ref of index.references) {
      exact(ref, ['id', 'custodian', 'revision', 'recordedAt', 'reviewBy']);
      if (!label(ref.id) || !label(ref.custodian) ||
          !(ref.revision === null || (typeof ref.revision === 'string' && /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(ref.revision)))) reject('reference_schema');
      if (!time(ref.recordedAt) || ref.recordedAt > asOf ||
          !(ref.reviewBy === null || (time(ref.reviewBy) && ref.reviewBy >= ref.recordedAt))) reject('reference_time');
      if (references.has(ref.id)) {
        const old = references.get(ref.id);
        reject(Object.keys(old).every(k => old[k] === ref[k]) ? 'duplicate_reference' : 'reference_conflict');
      }
      references.set(ref.id, ref);
    }
    for (const gate of index.gates) {
      exact(gate, ['id', 'facts']);
      if (typeof gate.id !== 'string' || !Object.hasOwn(REQUIREMENTS, gate.id) || gates.has(gate.id)) reject('gate_set');
      list(gate.facts, 3); if (gate.facts.length !== 3) reject('fact_set');
      const seen = new Set(), codes = new Set();
      for (const fact of gate.facts) {
        exact(fact, ['id', 'status', 'references']);
        if (!REQUIREMENTS[gate.id].includes(fact.id) || seen.has(fact.id)) reject('fact_set');
        seen.add(fact.id); list(fact.references, 4);
        if (!['UNRESOLVED', 'REFERENCES_SUPPLIED'].includes(fact.status)) reject('fact_status');
        if ((fact.status === 'UNRESOLVED') !== (fact.references.length === 0)) reject('fact_conflict');
        if (!fact.references.length) codes.add('missing_references');
        const refIds = new Set();
        for (const id of fact.references) {
          if (!label(id) || !references.has(id)) reject('unknown_reference');
          if (refIds.has(id)) reject('duplicate_reference');
          refIds.add(id); used.add(id); const ref = references.get(id);
          if (ref.reviewBy === null) codes.add('review_policy_missing');
          else if (ref.reviewBy <= asOf) codes.add('stale_reference');
          if (revisionFacts.has(fact.id) && ref.revision === null) codes.add('revision_missing');
        }
      }
      gates.set(gate.id, { id: gate.id, decision: 'NOT_READY', codes: [...codes].sort() });
    }
    if (used.size !== references.size) reject('unused_reference');
    const ordered = Object.keys(REQUIREMENTS).map(id => gates.get(id));
    return result(ordered.some(g => g.codes.length) ? 'INCOMPLETE' : 'COMPLETE', ['independently_unverified'], ordered);
  } catch (e) { return result('INVALID', [e instanceof LintError ? e.code : 'invalid_input']); }
}

// Stdin-only CLI: explicit reproducible cutoff; no file argument or ambient clock.
// Importing the pure module does not consume stdin or emit output.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  let finished = false, size = 0; const chunks = [];
  const emit = output => {
    if (finished) return; finished = true;
    process.stdout.write(JSON.stringify(output) + '\n');
    process.exitCode = output.structure === 'INVALID' ? 2 : output.structure === 'COMPLETE' ? 3 : 1;
  };
  const args = process.argv.slice(2);
  if (args.length !== 2 || args[0] !== '--as-of' || !/^(?:0|[1-9][0-9]{0,15})$/.test(args[1]) || !time(Number(args[1]))) {
    emit(result('INVALID', ['invalid_cutoff']));
  } else {
    process.stdin.on('data', chunk => {
      if (finished) return;
      size += chunk.length;
      if (size > MAX_BYTES) { emit(result('INVALID', ['bounds'])); process.stdin.destroy(); }
      else chunks.push(chunk);
    });
    process.stdin.on('end', () => { if (!finished) emit(lintEvidenceIndex(Buffer.concat(chunks, size), Number(args[1]))); });
    process.stdin.on('error', () => emit(result('INVALID', ['invalid_input'])));
  }
}
