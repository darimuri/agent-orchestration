import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import childProcess from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { lintEvidenceIndex, CONTRACT, REQUIREMENTS } from './host-operator-evidence.mjs';

const cutoff = 1800000000000;
const modulePath = fileURLToPath(new URL('./host-operator-evidence.mjs', import.meta.url));
const canary = 'SECRET_CANARY';
function index(complete = false) {
  let count = 0; const references = [];
  const gates = Object.entries(REQUIREMENTS).map(([id, facts]) => ({ id, facts: facts.map(id => {
    const ref = 'evidence-' + ++count;
    if (complete) references.push({ id: ref, custodian: 'custodian-one', revision: '1'.repeat(40),
      recordedAt: cutoff - 1000, reviewBy: cutoff + 1000 });
    return { id, status: complete ? 'REFERENCES_SUPPLIED' : 'UNRESOLVED', references: complete ? [ref] : [] };
  }) }));
  return { version: 1, contract: { ...CONTRACT }, asOf: cutoff, references, gates };
}
function lint(value, asOf = cutoff) { return lintEvidenceIndex(JSON.stringify(value), asOf); }
function safe(output) {
  const text = JSON.stringify(output);
  assert.equal(output.decision, 'NOT_READY'); assert.equal(output.verification, 'INDEPENDENTLY_UNVERIFIED');
  assert(Buffer.byteLength(text) <= 4096);
  for (const secret of [canary, '/private/', 'https://', 'custodian-one', 'evidence-', '1'.repeat(40)]) assert.equal(text.includes(secret), false);
  for (const gate of output.gates) assert.equal(gate.decision, 'NOT_READY');
  return output;
}
function invalid(value, code) {
  const output = safe(lint(value)); assert.equal(output.structure, 'INVALID');
  if (code) assert.deepEqual(output.codes, [code]);
}
function cli(input, args = ['--as-of', String(cutoff)]) {
  return childProcess.spawnSync(process.execPath, [modulePath, ...args], {
    input, encoding: 'utf8', env: {}, timeout: 5000, maxBuffer: 8192,
  });
}

test('canonical unresolved nine-gate index reports every missing gate, deterministic and bounded', () => {
  const output = safe(lint(index()));
  assert.equal(output.structure, 'INCOMPLETE'); assert.deepEqual(output.codes, ['independently_unverified']);
  assert.deepEqual(output.gates.map(g => g.id), Object.keys(REQUIREMENTS));
  for (const gate of output.gates) assert.deepEqual(gate.codes, ['missing_references']);
  assert.deepEqual(output, lintEvidenceIndex(Buffer.from(JSON.stringify(index())), cutoff));
});
test('forged complete metadata can ONLY be structurally complete, never operationally ready', () => {
  const input = index(true), output = safe(lint(input)); assert.equal(output.structure, 'COMPLETE');
  assert(output.gates.every(g => g.codes.length === 0));
  input.references.forEach(r => { r.custodian = 'forged-custodian'; r.revision = '2'.repeat(64); });
  assert.deepEqual(lint(input), output); // Identity/revision claims are not independently verified.
  assert.equal(cli(JSON.stringify(input)).status, 3); // Nonzero even for forged complete input.
});
test('incremental references affect missing diagnostics only; H7-H9 cannot be waived', () => {
  const input = index(true); const unresolved = index();
  input.gates.splice(6, 3, ...unresolved.gates.slice(6)); input.references.splice(18);
  const output = safe(lint(input)); assert.equal(output.structure, 'INCOMPLETE');
  assert(output.gates.slice(0, 6).every(g => g.codes.length === 0));
  assert(output.gates.slice(6).every(g => g.codes.includes('missing_references')));
  assert.equal(lint(index()).gates[0].decision, output.gates[0].decision);
});
test('input key/gate/fact/reference order changes do not change the fixed summary', () => {
  const input = index(true); input.gates.reverse(); input.references.reverse();
  input.gates.forEach(g => g.facts.reverse());
  const reordered = Object.fromEntries(Object.entries(input).reverse());
  assert.deepEqual(safe(lint(reordered)), lint(index(true)));
});
test('contract version and every source/contract pin must match exactly', () => {
  const input = index(); input.version = 2; invalid(input, 'schema');
  for (const key of Object.keys(CONTRACT)) { const changed = index(); changed.contract[key] = 'forged'; invalid(changed, 'contract_mismatch'); }
  const extra = index(); extra.contract.verified = true; invalid(extra, 'schema');
  const missing = index(); delete missing.contract.contractBlob; invalid(missing, 'schema');
});
test('missing, unknown or duplicate gate/fact and unknown status fail closed', () => {
  const changes = [s => s.gates.pop(), s => { s.gates[0].id = 'H10'; }, s => { s.gates[1].id = 'H1'; },
    s => s.gates[0].facts.pop(), s => { s.gates[0].facts[0].id = 'freeform'; },
    s => { s.gates[0].facts[1].id = s.gates[0].facts[0].id; }, s => { s.gates[0].facts[0].status = 'READY'; }];
  for (const change of changes) { const input = index(); change(input); invalid(input); }
});
test('dangerous/freeform fields at every layer are rejected without reflecting content', () => {
  for (const key of ['ready', 'verified', 'PASS', 'shell', 'path', 'url', 'env', 'argv', 'mount', 'attachment', '__proto__']) {
    for (const layer of ['root', 'gate', 'fact', 'reference']) {
      const input = index(true), target = layer === 'root' ? input : layer === 'gate' ? input.gates[0] :
        layer === 'fact' ? input.gates[0].facts[0] : input.references[0];
      Object.defineProperty(target, key, { value: canary + '/private/token https://private.invalid', enumerable: true }); invalid(input);
    }
  }
  for (const value of ['https://private.invalid', '/private/token', 'cat secret', 'x'.repeat(33), 'SECRET_CANARY']) {
    const input = index(true); input.references[0].id = value; invalid(input);
    const other = index(true); other.references[0].custodian = value; invalid(other);
  }
});
test('duplicate keys including escaped nested spellings are rejected before JSON.parse', () => {
  const raw = JSON.stringify(index(true));
  for (const changed of [raw.replace('{', '{"version":1,'), raw.replace('{', '{"\\u0076ersion":1,'),
    raw.replace('"contract":{', '"contract":{"id":"forged",'),
    raw.replace('"recordedAt":', '"\\u0072eviewBy":null,"recordedAt":')]) {
    const output = safe(lintEvidenceIndex(changed, cutoff)); assert.equal(output.structure, 'INVALID'); assert.deepEqual(output.codes, ['duplicate_key']);
  }
});
test('invalid UTF-8/JSON, lone surrogates and wrong pure-API input types return fixed codes', () => {
  let getterInvoked = false;
  const accessor = Object.defineProperty({}, 'raw', { get() { getterInvoked = true; throw Error(canary); } });
  const proxy = new Proxy({}, { getPrototypeOf() { throw Error(canary); } });
  const symbolBuffer = Buffer.from('{}'); symbolBuffer[Symbol('secret')] = canary;
  for (const raw of [null, index(), Promise.resolve(index()), Object.create(index()), new String('{}'), accessor, proxy, symbolBuffer,
    Buffer.from([0xc3, 0x28]), '\ud800', '"\\ud800"', '{', 'null', '{}', '[]', '[1,]', 'NaN', '{"a":01}', '{"a":"\n"}']) {
    assert.equal(safe(lintEvidenceIndex(raw, cutoff)).structure, 'INVALID');
  }
  assert.equal(getterInvoked, false);
});
test('byte limit is UTF-8 bytes and rejects one over the boundary including streaming input', () => {
  const raw = JSON.stringify(index());
  const atLimit = raw + ' '.repeat(65536 - Buffer.byteLength(raw));
  assert.equal(safe(lintEvidenceIndex(atLimit, cutoff)).structure, 'INCOMPLETE');
  assert.deepEqual(safe(lintEvidenceIndex(atLimit + ' ', cutoff)).codes, ['bounds']);
  assert.deepEqual(safe(lintEvidenceIndex(Buffer.alloc(65537), cutoff)).codes, ['bounds']);
  assert.deepEqual(safe(lintEvidenceIndex('é'.repeat(32769), cutoff)).codes, ['bounds']);
  const processResult = cli(atLimit + ' '); assert.equal(processResult.status, 2);
  assert.deepEqual(safe(JSON.parse(processResult.stdout)).codes, ['bounds']); assert.equal(processResult.stderr, '');
});
test('depth, string, array, reference and per-fact bounds cannot be caller-expanded', () => {
  for (const raw of ['['.repeat(10) + '0' + ']'.repeat(10), JSON.stringify({ extra: 'x'.repeat(129) }), JSON.stringify(Array(109).fill(null))]) {
    assert.deepEqual(safe(lintEvidenceIndex(raw, cutoff)).codes, ['bounds']);
  }
  const overRefs = index(true); overRefs.references = Array(109).fill(overRefs.references[0]); invalid(overRefs, 'bounds');
  const overFact = index(true); overFact.gates[0].facts[0].references = Array(5).fill('evidence-1'); invalid(overFact, 'bounds');
});
test('duplicate definitions, metadata conflicts, duplicate pointers and unresolved/reference conflicts reject', () => {
  for (const field of [null, 'custodian', 'revision', 'recordedAt', 'reviewBy']) {
    const input = index(true), copy = { ...input.references[0] };
    if (field) copy[field] = field === 'custodian' ? 'other-custodian' : field === 'revision' ? '2'.repeat(40) : cutoff;
    input.references.push(copy); invalid(input, field ? 'reference_conflict' : 'duplicate_reference');
  }
  const duplicate = index(true); duplicate.gates[0].facts[0].references.push('evidence-1'); invalid(duplicate, 'duplicate_reference');
  const conflict = index(true); conflict.gates[0].facts[0].status = 'UNRESOLVED'; invalid(conflict, 'fact_conflict');
  const empty = index(); empty.gates[0].facts[0].status = 'REFERENCES_SUPPLIED'; invalid(empty, 'fact_conflict');
});
test('unknown and unused evidence references reject; shared pointer is permitted, not opened', () => {
  const unknown = index(true); unknown.gates[0].facts[0].references = ['not-defined']; invalid(unknown, 'unknown_reference');
  const unused = index(); unused.references = index(true).references.slice(0, 1); invalid(unused, 'unused_reference');
  const shared = index(true); shared.references = shared.references.slice(0, 1);
  shared.gates.forEach(g => g.facts.forEach(f => { f.references = ['evidence-1']; }));
  assert.equal(safe(lint(shared)).structure, 'COMPLETE'); // One opaque document may cover multiple claims; never proof.
});
test('explicit cutoff, future/reversed/invalid times and cutoff mismatch reject without clock access', () => {
  for (const asOf of [undefined, null, '1800000000000', -1, Infinity, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    assert.deepEqual(safe(lintEvidenceIndex(JSON.stringify(index()), asOf)).codes, ['invalid_cutoff']);
  }
  invalid({ ...index(), asOf: cutoff - 1 }, 'cutoff_mismatch');
  for (const change of [{ recordedAt: cutoff + 1 }, { recordedAt: -1 }, { recordedAt: cutoff / 1000, reviewBy: 1 },
    { reviewBy: '1800000000' }, { recordedAt: null }, { reviewBy: Number.MAX_SAFE_INTEGER + 1 }]) {
    const input = index(true); Object.assign(input.references[0], change); invalid(input, 'reference_time');
  }
});
test('unknown review policy, stale references and missing applicable revision remain incomplete', () => {
  const input = index(true); input.references[0].reviewBy = null; input.references[0].revision = null;
  input.references[3].reviewBy = cutoff;
  const output = safe(lint(input)); assert.equal(output.structure, 'INCOMPLETE');
  assert.deepEqual(output.gates[0].codes, ['review_policy_missing', 'revision_missing']);
  assert.deepEqual(output.gates[1].codes, ['stale_reference']);
  // Advancing the explicitly supplied cutoff never renews a prior review date.
  const later = index(true); later.asOf = cutoff + 1001;
  assert(safe(lint(later, cutoff + 1001)).gates.every(g => g.codes.includes('stale_reference')));
});
test('pure calls perform no filesystem/network/subprocess/clock operations and never echo exceptions', () => {
  let calls = 0; const blocked = () => { calls++; throw Error(canary + '/private/path'); };
  const seams = [[fs, 'openSync'], [fs, 'readFileSync'], [fs, 'writeFileSync'], [fs, 'statSync'],
    [http, 'request'], [https, 'request'], [childProcess, 'spawnSync'], [globalThis, 'fetch'], [Date, 'now']];
  const originals = seams.map(([object, key]) => object[key]);
  try {
    seams.forEach(([object, key]) => { object[key] = blocked; });
    assert.equal(safe(lint(index(true))).structure, 'COMPLETE'); assert.equal(calls, 0);
    const object = Object.defineProperty({}, 'toJSON', { get: blocked });
    assert.equal(safe(lintEvidenceIndex(object, cutoff)).structure, 'INVALID'); assert.equal(calls, 0);
  } finally { seams.forEach(([object, key], i) => { object[key] = originals[i]; }); }
});
test('mutating output cannot change frozen contract/requirements or later lint decisions', () => {
  assert(Object.isFrozen(CONTRACT)); assert(Object.isFrozen(REQUIREMENTS)); assert(Object.values(REQUIREMENTS).every(Object.isFrozen));
  const output = lint(index(true)); output.decision = 'READY'; output.gates[0].decision = 'READY';
  assert.equal(safe(lint(index(true))).decision, 'NOT_READY');
});
test('stdin-only CLI has bounded fixed output and documented nonzero exit semantics', () => {
  for (const [input, code, structure] of [[JSON.stringify(index()), 1, 'INCOMPLETE'],
    [JSON.stringify(index(true)), 3, 'COMPLETE'], ['{SECRET_CANARY', 2, 'INVALID']]) {
    const result = cli(input); assert.equal(result.error, undefined); assert.equal(result.status, code); assert.equal(result.stderr, '');
    assert.equal(safe(JSON.parse(result.stdout)).structure, structure); assert.equal(result.stdout.trim().split('\n').length, 1);
  }
  for (const args of [[], ['--as-of', 'now'], ['--as-of', String(cutoff), '/private/SECRET_CANARY'], ['--file', '/private/SECRET_CANARY']]) {
    const result = cli('', args); assert.equal(result.status, 2); assert.deepEqual(safe(JSON.parse(result.stdout)).codes, ['invalid_cutoff']);
    assert.equal(result.stderr, '');
  }
});

test('UTF-8 BOM, Buffer subclass/extra properties and surrogate wire values cannot bypass strict input handling', () => {
  const raw = JSON.stringify(index());
  for (const input of ['\ufeff' + raw, Buffer.from('\ufeff' + raw), '{"x":"\\ud800"}']) {
    assert.equal(safe(lintEvidenceIndex(input, cutoff)).structure, 'INVALID');
  }
  const extra = Buffer.from(raw); extra.verified = true;
  const derived = Buffer.from(raw); Object.setPrototypeOf(derived, Object.create(Buffer.prototype));
  for (const input of [extra, derived]) assert.equal(safe(lintEvidenceIndex(input, cutoff)).structure, 'INVALID');
});
test('importing the module has no stdin consumer, output or CLI side effect', () => {
  const url = new URL('./host-operator-evidence.mjs', import.meta.url).href;
  const result = childProcess.spawnSync(process.execPath, ['--input-type=module', '-e', `await import(${JSON.stringify(url)})`], {
    input: canary, encoding: 'utf8', env: {}, timeout: 5000,
  });
  assert.equal(result.status, 0); assert.equal(result.stdout, ''); assert.equal(result.stderr, '');
});

test('Buffer length accessors and proxy traps cannot execute during raw-input validation', () => {
  let invoked = false;
  const buffer = Buffer.from('{}'); Object.defineProperty(buffer, 'length', { get() { invoked = true; throw Error(canary); } });
  const proxy = new Proxy(Buffer.from('{}'), { getPrototypeOf() { invoked = true; throw Error(canary); }, get() { invoked = true; throw Error(canary); } });
  for (const raw of [buffer, proxy]) assert.equal(safe(lintEvidenceIndex(raw, cutoff)).structure, 'INVALID');
  assert.equal(invoked, false);
});

test('complete-payload Buffer wrappers reject hidden data/accessors/symbols/proxies without invoking getters', () => {
  const complete = JSON.stringify(index(true));
  assert.equal(safe(lintEvidenceIndex(Buffer.from(complete), cutoff)).structure, 'COMPLETE');
  let invoked = false;
  for (const key of ['verified', 'length', 'byteLength', 'byteOffset', 'buffer']) {
    for (const descriptor of [{ value: true }, { get() { invoked = true; throw Error(canary + '/private/wrapper'); } }]) {
      const raw = Buffer.from(complete);
      Object.defineProperty(raw, key, descriptor); // non-enumerable by default
      const output = safe(lintEvidenceIndex(raw, cutoff));
      assert.equal(output.structure, 'INVALID'); assert.deepEqual(output.codes, ['invalid_input']);
    }
  }
  const symbol = Buffer.from(complete); Object.defineProperty(symbol, Symbol('verified'), { value: canary });
  const proxy = new Proxy(Buffer.from(complete), {
    getPrototypeOf() { invoked = true; throw Error(canary); },
    ownKeys() { invoked = true; throw Error(canary); },
    get() { invoked = true; throw Error(canary); },
  });
  // The documented API accepts ordinary Buffer, not a general Uint8Array or subclass.
  const uint8 = new Uint8Array(Buffer.from(complete));
  const subclass = Buffer.from(complete); Object.setPrototypeOf(subclass, Object.create(Buffer.prototype));
  for (const raw of [symbol, proxy, uint8, subclass]) {
    const output = safe(lintEvidenceIndex(raw, cutoff));
    assert.equal(output.structure, 'INVALID'); assert.deepEqual(output.codes, ['invalid_input']);
  }
  assert.equal(invoked, false);
});
