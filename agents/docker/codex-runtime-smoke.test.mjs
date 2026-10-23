import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const script = new URL('./codex-runtime-smoke.mjs', import.meta.url);
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'runtime-smoke-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const bin = path.join(root, 'bin');
  const adapter = path.join(root, 'node_modules/@agentclientprotocol/codex-acp');
  const codex = path.join(adapter, 'node_modules/@openai/codex');
  fs.mkdirSync(bin, { recursive: true });
  fs.mkdirSync(path.join(adapter, 'dist'), { recursive: true });
  fs.mkdirSync(path.join(codex, 'bin'), { recursive: true });
  fs.writeFileSync(path.join(adapter, 'package.json'), JSON.stringify({ version: '2.2.2' }));
  fs.writeFileSync(path.join(codex, 'package.json'), JSON.stringify({ version: '0.160.1' }));
  const program = output => `#!/usr/bin/env node\nif(process.env.GITHUB_GATEWAY_AGENT_TOKEN || process.env.OPENAI_API_KEY || process.env.APP_SERVER_LOGS) process.exit(9);\nconsole.log(${JSON.stringify(output)});\n`;
  fs.writeFileSync(path.join(codex, 'bin/codex.js'), program('codex-cli 0.160.1'));
  fs.writeFileSync(path.join(adapter, 'dist/index.js'), program('codex-cli 0.160.1'), { mode: 0o755 });
  fs.symlinkSync(path.join(adapter, 'dist/index.js'), path.join(bin, 'codex-acp'));
  fs.writeFileSync(path.join(bin, 'codex'), program('codex-cli 0.163.0'), { mode: 0o755 });
  return { bin, adapter };
}
function run(bin, overrides = {}, versions = ['0.163.0', '2.2.2', '0.160.1']) {
  return spawnSync(process.execPath, [script.pathname, ...versions, bin], {
    env: { PATH: process.env.PATH, ...overrides }, encoding: 'utf8', timeout: 20000,
  });
}
test('verifies both versions using a clean environment', t => {
  const { bin } = fixture(t);
  const r = run(bin, { OPENAI_API_KEY: 'fixture-secret', GITHUB_GATEWAY_AGENT_TOKEN: 'fixture-secret', APP_SERVER_LOGS: 'fixture-secret' });
  assert.equal(r.status, 0);
  assert.ok(r.stdout.includes('ACP Codex (CODEX_PATH unset): 0.160.1'));
  assert.ok(!(r.stdout + r.stderr).includes('fixture-secret'));
});
test('rejects override and unexpected package version without exposing values', t => {
  const { bin } = fixture(t);
  for (const r of [run(bin, { CODEX_PATH: 'fixture-secret' }), run(bin, {}, ['0.163.0', '2.2.3', '0.160.1'])]) {
    assert.equal(r.status, 1);
    assert.ok(!(r.stdout + r.stderr).includes('fixture-secret'));
  }
});
test('suppresses noisy failing child diagnostics and mismatched CLI output', t => {
  const { bin } = fixture(t);
  fs.writeFileSync(path.join(bin, 'codex'), '#!/usr/bin/env node\nconsole.error("fixture-secret"); console.log("wrong-version"); process.exit(1);\n');
  const r = run(bin);
  assert.equal(r.status, 1);
  assert.ok(!(r.stdout + r.stderr).includes('fixture-secret'));
  assert.ok(!r.stdout.includes('wrong-version'));
});
