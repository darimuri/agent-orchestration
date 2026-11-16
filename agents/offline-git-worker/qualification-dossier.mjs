// Pure evidence packaging/accounting. No IO, process launcher, trust store or capsule issuer.
import { createHash } from 'node:crypto';
import { types, TextDecoder } from 'node:util';
export const MAX_BYTES = 16384;
const fail = () => { throw Error('age30_dossier_v2_denied'); };
const hash = b => createHash('sha256').update(b).digest('hex');
export const POLICY = Object.freeze({ quotaUs:20000, periodUs:100000, burstUs:0, pids:8,
  wallMs:30000, tailMs:2000, ownerMs:40000, guardUs:8000000, ceilingUs:10000000, memoryBytes:536870912, swapBytes:0,
  scratchBytes:268435456, inodes:65536, machineBytes:268435456, diagnosticBytes:1048576,
  readCount:20000, frameCount:65536, objectBytes:8388608, bundleBytes:33554432, controlBytes:16384, frameBytes:65536 });
export const PROBE = Object.freeze({ schema:'age30.nonadmitting-inspection', version:2,
  sha256:hash('age30.nonadmitting-inspection/v2:current-process-only;no-enforcement-proof\n') });
export const PRODUCTION = Object.freeze({ commit:'8bbc3a9d052d428e67eebd3b7cf56c43ffe4490a',
  tree:'8c5c76161e3e2580c463f644bff7f893a47bbb54', files:Object.freeze([
  ['agents/OFFLINE_GIT_WORKER.md','2bdbe9c011ba8e7acd134de99ffc48d683c9b3302dd9aa609e4763da036a4ecf'],
  ['agents/offline-git-worker/client.mjs','b47394c670f23a69cc9f7527a4b1ec05f00a96c2de724e5b8586a21660d3022c'],
  ['agents/offline-git-worker/native/custody.c','dfdec62d1d4aa8401931ee690b07e3fc01e427d5afdab6c7cf1f56a4bf2eb4b1'],
  ['agents/offline-git-worker/native/custody.h','f14a2e43af3ea99f8c759852907c7edcdb0d663539b3dd0eeaecac91f455ff3f'],
  ['agents/offline-git-worker/native/protocol.h','f184864d39fd4339e874da4e23eb30304fc6204cc3fb6255f6092c99c9e44a40'],
  ['agents/offline-git-worker/native/supervisor.c','ba37e482bede7203e98be447ab6d2d15b59a36c0680b4bd719608471db3e4a0e'],
  ['agents/offline-git-worker/native/worker.c','3a4b672202fbc6752ff8eb25a46b6d7914fdb3df5f4a51a6ad73873dcbbadc65'],
  ['agents/offline-git-worker/protocol.mjs','fca2e7b451fe30e247fdf29ceb1949580361198b108f1895f14a3d7c396a7745'],
  ['agents/scripts/build-offline-git-worker.mjs','30f2e689e85b52c03bca8364d4c2efe0f18148138520af9e46f9e0e8902edefd'],
  ['agents/scripts/offline-git-worker.test.mjs','b1b71d29d1a69f1ec27e7dfac6bbc5da79d9c779a58aab6bb219386a4840d842'],
  ['agents/tests/offline-git-worker/native.test.c','b13cf509ed62a47f0b9cb36409901d4b6de5de706003454ea798eacac98a63f4'],
  ['agents/tests/offline-git-worker/worker.test.c','eb5a1d7c9464c30d92c69f1e509abe8fcd93b0b7da263ffd886518efd9a72a4d']
].map(([path,sha256]) => Object.freeze({path,sha256}))) });
export const PREPARATION_FILES = Object.freeze(['agents/OFFLINE_GIT_HOST_ACCEPTANCE.md',
  'agents/offline-git-worker/qualification-dossier.mjs', 'agents/scripts/offline-git-host-acceptance.mjs',
  'agents/scripts/offline-git-host-acceptance.test.mjs','agents/tests/offline-git-worker/host-driver.c',
  'agents/tests/offline-git-worker/host-entry.c','agents/tests/offline-git-worker/host-validator.mjs']);
export const OBLIGATIONS = Object.freeze(['kernelQuotaBound','finiteRunnableLifetime','noEscapeMigration',
  'trustedCpuBound','uncertaintyReserve','intendedHostScope','independentContract']);
export const PROVENANCE = Object.freeze(['SOURCE_CLAIM','NONROOT_OBSERVATION','OWNER_OBSERVATION','INDEPENDENT_REVIEW_REFERENCE']);
const TERMS = Object.freeze(['parallelism','quotaSlackUs','maxRunnableUs','terminationBoundUs','trustedCpuUs','uncertaintyUs']);
const HOST_KEYS = ['scope','kernelRelease','kernelBuildSha256','kernelConfigSha256','arch','uidMapSha256',
  'gidMapSha256','namespaces','cgroupSha256'];
const NS_KEYS = ['ipc','mnt','net','pid','user','uts'];
function exact(v, keys) {
  if (!v || types.isProxy(v) || Object.getPrototypeOf(v) !== Object.prototype || Object.getOwnPropertySymbols(v).length) fail();
  const d = Object.getOwnPropertyDescriptors(v);
  if (Object.keys(d).length !== keys.length || keys.some(k => !Object.hasOwn(d,k)) ||
      Object.values(d).some(p => !Object.hasOwn(p,'value') || !p.enumerable)) fail();
}
// Restricted canonical JSON: sorted ASCII field names, no whitespace, integer
// decimal numbers, shortest JSON.stringify string escaping, finite bounded tree.
export function canonicalBytes(value) {
  let nodes = 0;
  function encode(v, depth) {
    if (++nodes > 2048 || depth > 12) fail();
    if (v === null || typeof v === 'boolean') return JSON.stringify(v);
    if (typeof v === 'number') { if (!Number.isSafeInteger(v) || v < 0 || Object.is(v,-0)) fail(); return String(v); }
    if (typeof v === 'string') {
      if (!v.isWellFormed() || Buffer.byteLength(v) > 512) fail(); return JSON.stringify(v);
    }
    if (!v || typeof v !== 'object' || types.isProxy(v) || Object.getOwnPropertySymbols(v).length) fail();
    if (Array.isArray(v)) {
      if (Object.getPrototypeOf(v) !== Array.prototype || v.length > 32 || Object.keys(v).length !== v.length) fail();
      const descriptors = Object.getOwnPropertyDescriptors(v);
      for (let i=0;i<v.length;i++) if (!Object.hasOwn(descriptors[i] ?? {},'value')) fail();
      return '[' + v.map(x => encode(x,depth+1)).join(',') + ']';
    }
    if (Object.getPrototypeOf(v) !== Object.prototype) fail();
    const d = Object.getOwnPropertyDescriptors(v), keys = Object.keys(d).sort();
    if (keys.length > 32 || keys.some(k => !/^[A-Za-z][A-Za-z0-9]*$/.test(k) || !Object.hasOwn(d[k],'value') || !d[k].enumerable)) fail();
    return '{' + keys.map(k => JSON.stringify(k)+':'+encode(d[k].value,depth+1)).join(',') + '}';
  }
  const result = Buffer.from(encode(value,0)); if (result.length > MAX_BYTES) fail(); return result;
}
function digest(v, width=64) { if (v !== null && (typeof v !== 'string' || !new RegExp('^[a-f0-9]{'+width+'}$').test(v) || /^0+$/.test(v))) fail(); }
function integer(v) { if (v !== null && (!Number.isSafeInteger(v) || v < 0)) fail(); }
function source(v, paths, preparation=false) {
  if (v === null) return;
  exact(v,preparation ? ['commit','tree','files','clean'] : ['commit','tree','files']);
  if (preparation && ![true,false,null].includes(v.clean)) fail(); digest(v.commit,40); digest(v.tree,40);
  if (v.files === null) return;
  if (!Array.isArray(v.files) || v.files.length !== paths.length) fail();
  v.files.forEach((f,i) => { exact(f,['path','sha256']); if (f.path !== paths[i]) fail(); digest(f.sha256); });
}
function context(v) {
  if (v === null) return;
  exact(v,['production','preparation','probe','host','policy']);
  source(v.production,PRODUCTION.files.map(f=>f.path)); source(v.preparation,PREPARATION_FILES,true);
  if (v.probe !== null) { exact(v.probe,['schema','version','sha256']);
    if (v.probe.schema !== null && v.probe.schema !== PROBE.schema) fail(); integer(v.probe.version); digest(v.probe.sha256); }
  if (v.policy !== null) { exact(v.policy,Object.keys(POLICY)); Object.values(v.policy).forEach(integer); }
  if (v.host !== null) {
    exact(v.host,HOST_KEYS);
    if (!['CURRENT_PROCESS_UNQUALIFIED','INTENDED_HOST_CLAIM',null].includes(v.host.scope) ||
      !['x64','arm64',null].includes(v.host.arch) ||
      (v.host.kernelRelease !== null && (typeof v.host.kernelRelease !== 'string' || !/^[a-zA-Z0-9._+-]{1,128}$/.test(v.host.kernelRelease)))) fail();
    for (const k of ['kernelBuildSha256','kernelConfigSha256','uidMapSha256','gidMapSha256','cgroupSha256']) digest(v.host[k]);
    if (v.host.namespaces !== null) { exact(v.host.namespaces,NS_KEYS);
      for (const k of NS_KEYS) if (v.host.namespaces[k] !== null &&
        (typeof v.host.namespaces[k] !== 'string' || !new RegExp('^'+k+':\\[[0-9]{1,20}\\]$').test(v.host.namespaces[k]))) fail(); }
  }
}
export function dossierTemplate() {
  return {version:2,expected:null,claimed:null,accounting:Object.fromEntries(TERMS.map(k=>[k,null])),evidence:[]};
}
export function decodeQualificationDossier(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > MAX_BYTES) fail();
  let d; try { d = JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)); } catch { fail(); }
  if (!canonicalBytes(d).equals(bytes)) fail(); // includes duplicate keys, trailing LF, exponent/escape aliases
  exact(d,['version','expected','claimed','accounting','evidence']); if (d.version !== 2) fail();
  context(d.expected); context(d.claimed);
  if (d.accounting !== null) { exact(d.accounting,TERMS); Object.values(d.accounting).forEach(integer); }
  if (!Array.isArray(d.evidence) || d.evidence.length > 16) fail();
  const seen = new Set();
  for (const e of d.evidence) {
    exact(e,['obligation','expectedContextSha256','evidenceSha256','evidenceId','provenance']);
    if (!OBLIGATIONS.includes(e.obligation) || !PROVENANCE.includes(e.provenance) ||
      typeof e.evidenceId !== 'string' || !/^[a-zA-Z0-9_.:-]{1,256}$/.test(e.evidenceId) || canonicalBytes(e).length > 512) fail();
    digest(e.expectedContextSha256); digest(e.evidenceSha256);
    if (e.expectedContextSha256 === null || e.evidenceSha256 === null) fail();
    const key = e.obligation+':'+e.provenance+':'+e.evidenceId;
    if (seen.has(key)) fail(); seen.add(key);
  }
  return d;
}
export function contextDigest(value) { const b = canonicalBytes(value); context(JSON.parse(b.toString())); return hash(b); }
export function assessQualificationDossier(bytes, observation = null) {
  const d = decodeQualificationDossier(bytes);
  // An in-memory observation is still unqualified. It never supplies independent proof.
  const observed = JSON.parse(canonicalBytes(observation).toString()); context(observed);
  const missing = new Set(), contradictions = new Set();
  function compare(a,b,label) {
    if (a === null || b === null) { missing.add(label); return; }
    if (typeof a !== 'object') { if (a !== b) contradictions.add(label); return; }
    for (const k of Object.keys(a)) compare(a[k],b[k],label+'.'+k);
  }
  compare(d.expected,d.claimed,'claimed'); compare(d.expected,observed,'observed');
  for (const [name,c] of [['expected',d.expected],['claimed',d.claimed],['observed',observed]]) {
    if (c === null) { missing.add(name); continue; }
    if (c.preparation?.clean === false) contradictions.add(name+'.preparation.dirty');
    compare(PRODUCTION,c.production,name+'.production'); compare(PROBE,c.probe,name+'.probe'); compare(POLICY,c.policy,name+'.policy');
  }
  if (observed?.host?.scope === 'INTENDED_HOST_CLAIM') contradictions.add('observation_is_not_host_attestation');
  if (d.expected?.host?.scope === 'INTENDED_HOST_CLAIM' || d.claimed?.host?.scope === 'INTENDED_HOST_CLAIM')
    contradictions.add('container_or_current_process_cannot_be_promoted_to_intended_host');
  const identityMissing = missing.size;
  const a = d.accounting;
  const absentTerms = TERMS.filter(k => a === null || a[k] === null);
  for (const k of absentTerms) missing.add('accounting.'+k);
  const badTerms = [];
  if (a !== null) {
    for (const [k,min,max] of [['parallelism',1,8],['maxRunnableUs',40000000,Number.MAX_SAFE_INTEGER],
      ['terminationBoundUs',2000000,Number.MAX_SAFE_INTEGER],['trustedCpuUs',1,Number.MAX_SAFE_INTEGER],['uncertaintyUs',1,Number.MAX_SAFE_INTEGER]])
      if (a[k] !== null && (a[k] < min || a[k] > max)) { contradictions.add('accounting.'+k); badTerms.push(k); }
  }
  let worker = null, total = null;
  if (!absentTerms.length && !badTerms.length) {
    const periods = (BigInt(a.maxRunnableUs)+BigInt(a.terminationBoundUs)+99999n)/100000n+1n;
    worker = periods*20000n+BigInt(a.parallelism)*BigInt(a.quotaSlackUs);
    total = worker+BigInt(a.trustedCpuUs)+BigInt(a.uncertaintyUs);
    if (total > 10000000n) contradictions.add('aggregate_cpu_ceiling_exceeded');
  }
  const expectedDigest = contextDigest(d.expected);
  const obligations = OBLIGATIONS.map(obligation => {
    const refs = d.evidence.filter(e=>e.obligation===obligation);
    const wrong = refs.some(e=>e.expectedContextSha256 !== expectedDigest);
    if (wrong) contradictions.add('evidence_context.'+obligation);
    const termsMissing = obligation === 'kernelQuotaBound' ? absentTerms.some(k=>['parallelism','quotaSlackUs'].includes(k)) :
      obligation === 'finiteRunnableLifetime' ? absentTerms.some(k=>['maxRunnableUs','terminationBoundUs'].includes(k)) :
      obligation === 'trustedCpuBound' ? absentTerms.includes('trustedCpuUs') :
      obligation === 'uncertaintyReserve' ? absentTerms.includes('uncertaintyUs') : false;
    const contextBad = [...contradictions].some(k=>!k.startsWith('accounting.') && !k.startsWith('evidence_context.') && k !== 'aggregate_cpu_ceiling_exceeded');
    const accountingBad = (badTerms.length || (total !== null && total > 10000000n)) && ['kernelQuotaBound','finiteRunnableLifetime','trustedCpuBound','uncertaintyReserve'].includes(obligation);
    return {obligation, state:wrong || contextBad || accountingBad ? 'CONTRADICTED' :
      !refs.length || identityMissing || termsMissing ? 'MISSING' :
      refs.some(e=>['OWNER_OBSERVATION','INDEPENDENT_REVIEW_REFERENCE'].includes(e.provenance)) ? 'REQUIRES_INDEPENDENT_REVIEW' : 'CLAIM_ONLY',
      references:refs.map(e=>({evidenceId:e.evidenceId,evidenceSha256:e.evidenceSha256,provenance:e.provenance}))};
  });
  const blockers = [...contradictions].sort();
  const unsupported = ['finite runnable lifetime under arbitrary owner/controller/guardian starvation or death',
    'trusted setup/hash/output/controller/guardian/owner/settlement CPU outside worker cpu.stat'];
  return {version:2,type:'age30.nonadmitting-dossier-assessment',status:'UNKNOWN',admission:false,qualified:false,assumptionsVerified:false,
    dossierSha256:hash(bytes),expectedContextSha256:expectedDigest,policy:POLICY,
    provenanceVerified:false,freshness:'UNVERIFIED',
    identityMatches:blockers.some(k=>!k.startsWith('accounting.') && k !== 'aggregate_cpu_ceiling_exceeded') ? false : identityMissing ? 'UNKNOWN' : true,
    arithmeticWithinCeiling:total === null ? 'UNKNOWN' : total <= 10000000n,
    workerUpperUs:worker?.toString() ?? null, aggregateUpperUs:total?.toString() ?? null,
    unprovedTerms:TERMS.map(term=>({term,value:a?.[term] ?? null,proven:false})),
    obligations, missing:[...missing].sort(), blockers, unsupported,
    handoff:blockers.length || (d.evidence.length && total !== null) ? 'PREVENTIVE_BOUND_UNSUPPORTED' :
      missing.size ? 'MISSING_PRIVILEGED_OBSERVATION' : 'SOURCE_CONTRACT_READY_FOR_REVIEW'};
}
