// Mandatory native gate: a missing compiler is FAILURE, never a skipped PASS.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { buildHostOperatorSupervisor, supervisorFlags } from './build-host-operator-supervisor.mjs';
const hash=file=>createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const source=fileURLToPath(new URL('../tests/host-operator/native-supervisor.test.c',import.meta.url));
test('fixed compiler subordinate lookup is shared without PATH fallback',()=>{assert.equal(supervisorFlags[0],'-B/usr/bin/');assert(Object.isFrozen(supervisorFlags));assert.equal(supervisorFlags.filter(x=>x.startsWith('-B')).length,1);});
function run(file,args,cwd){const r=spawnSync(file,args,{cwd,env:{LANG:'C',LC_ALL:'C',TZ:'UTC'},encoding:'utf8',timeout:30000,maxBuffer:65536});assert.ifError(r.error);assert.equal(r.status,0,r.stderr);return r.stdout;}
test('mandatory production native build is pinned, protected and has no runtime fixture mode',t=>{const dir=fs.mkdtempSync(path.join(os.tmpdir(),'native-build-'));fs.chmodSync(dir,0o700);t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));const result=buildHostOperatorSupervisor(dir),manifest=JSON.parse(fs.readFileSync(result.manifest));assert.equal(result.digest,hash(result.binary));assert.equal(manifest.argv[0],'-B/usr/bin/');assert.deepEqual(manifest.argv.slice(0,supervisorFlags.length),[...supervisorFlags]);assert.equal(manifest.binary.digest,result.digest);assert.equal(manifest.source.digest,hash(fileURLToPath(new URL('../host-operator-auth/native/revision-supervisor.c',import.meta.url))));assert.equal(manifest.header.digest,hash(fileURLToPath(new URL('../host-operator-auth/native/revision-supervisor-protocol.h',import.meta.url))));assert.equal(fs.statSync(result.binary).mode&0o7777,0o755);assert(!manifest.argv.includes('-DRS_TEST'));assert(!manifest.argv.includes('-march=native'));if(process.env.HOST_OPERATOR_TEST_SUPERVISOR_BUILD){const root=process.env.HOST_OPERATOR_TEST_SUPERVISOR_BUILD,m=JSON.parse(fs.readFileSync(path.join(root,'revision-supervisor.build.json')));assert.equal(m.source.digest,manifest.source.digest);assert.equal(m.header.digest,manifest.header.digest);assert.equal(m.binary.digest,hash(path.join(root,'revision-supervisor')));assert.equal(m.compiler.digest,manifest.compiler.digest);}});
for(const sanitizer of [false,true])test('complete native synthetic syscall/pipe/state harness '+(sanitizer?'ASan+UBSan':'warnings-as-errors'),t=>{const dir=fs.mkdtempSync(path.join(process.env.TEST_EXECUTABLE_TMPDIR??os.tmpdir(),'native-test-'));fs.chmodSync(dir,0o700);t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));const binary=path.join(dir,'native-fixture'),flags=sanitizer?[...supervisorFlags,'-fsanitize=address,undefined','-fno-omit-frame-pointer']:supervisorFlags;run('/usr/bin/cc',[...flags,source,'-o',binary],dir);const output=run(binary,[],dir);assert(output.includes('NOT host acceptance'));});
