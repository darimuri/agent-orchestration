// Offline contract for the reviewed PublicationRecords API used by the host fixture.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
const fixture=fs.readFileSync(new URL('./test-gateway-publication-storage.sh',import.meta.url),'utf8');
function contract(source) {
 const calls=[...source.matchAll(/\bs\.([A-Za-z][A-Za-z0-9]*)\s*\(/g)].map(m=>m[1]);
 const supported=new Set(['reserve','recordCommit','load','reservePull','recordPull','pull']);
 assert(calls.length>0,'fixture PublicationRecords calls missing');
 for(const method of calls)assert(supported.has(method),'unsupported PublicationRecords method: '+method);
 for(const method of supported)assert(calls.includes(method),'missing fixture API coverage: '+method);
 assert.equal(calls.filter(m=>m==='reserve').length,3,'commit reservation and both duplicate-reservation probes required');
 assert.equal([...source.matchAll(/s\.reserve\(c,1,"2"\.repeat\(40\)\)/g)].length,3,'reserve(context, repositoryId, baseTree) signature drift');
}
test('host fixture uses reviewed reserve API and contract gate precedes privileged execution',()=>{
 contract(fixture);
 const gate=fixture.indexOf('node --test "$root_dir/scripts/gateway-publication-fixture-api.test.mjs"');
 assert(gate>=0 && gate<fixture.indexOf('(( EUID == 0 ))'));
});
test('contract rejects obsolete reserveCommit, unknown methods and reservation signature drift',()=>{
 for(const source of [fixture.replaceAll('s.reserve(','s.reserveCommit('),fixture.replace('s.recordCommit(','s.unknown('),fixture.replace('s.reserve(c,1,','s.reserve(c,2,')])assert.throws(()=>contract(source));
});
