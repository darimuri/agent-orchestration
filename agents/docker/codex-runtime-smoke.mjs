import { mkdtempSync, readFileSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';

// Deliberately suppress child output on failure: it may contain configuration.
// No credentials, existing HOME, MCP registrations or logging settings are inherited.
const [directVersion, adapterVersion, bundledVersion, binDir = '/usr/local/bin'] = process.argv.slice(2);
let scratch;
try {
  if (![directVersion, adapterVersion, bundledVersion].every(v => /^\d+\.\d+\.\d+$/.test(v ?? ''))) throw Error();
  if (process.env.CODEX_PATH) throw Error();
  const adapter = realpathSync(path.join(binDir, 'codex-acp'));
  const adapterPackage = JSON.parse(readFileSync(path.resolve(path.dirname(adapter), '../package.json'), 'utf8'));
  const bundled = createRequire(adapter).resolve('@openai/codex/bin/codex.js');
  const bundledPackage = JSON.parse(readFileSync(path.resolve(path.dirname(bundled), '../package.json'), 'utf8'));
  if (adapterPackage.version !== adapterVersion || bundledPackage.version !== bundledVersion) throw Error();
  scratch = mkdtempSync(path.join(tmpdir(), 'codex-runtime-smoke-'));
  const env = { PATH: `${binDir}:/usr/local/bin:/usr/bin:/bin`, HOME: scratch,
    CODEX_HOME: path.join(scratch, '.codex'), NO_BROWSER: '1' };
  const version = (command, args, expected) => {
    const result = spawnSync(command, args, { env, cwd: scratch, encoding: 'utf8', timeout: 15000, maxBuffer: 65536 });
    if (result.error || result.status !== 0 || result.stdout.trim() !== expected) throw Error();
  };
  version(process.execPath, [realpathSync(path.join(binDir, 'codex')), '--version'], `codex-cli ${directVersion}`);
  version(process.execPath, [bundled, '--version'], `codex-cli ${bundledVersion}`);
  // Use -V: adapter 2.2.2 intercepts --version even after the cli subcommand.
  version(process.execPath, [adapter, 'cli', '-V'], `codex-cli ${bundledVersion}`);
  console.log(`Direct Codex: ${directVersion}`);
  console.log(`codex-acp package.json: ${adapterVersion}`);
  console.log(`ACP Codex (CODEX_PATH unset): ${bundledVersion}`);
  console.log(`ACP bundled entrypoint: ${bundled}`);
} catch {
  console.error('Codex runtime smoke failed (versions, bundled path or CODEX_PATH); child output suppressed.');
  process.exitCode = 1;
} finally {
  if (scratch) rmSync(scratch, { recursive: true, force: true });
}
