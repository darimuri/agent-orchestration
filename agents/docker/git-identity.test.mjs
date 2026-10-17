import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { personas, validateManifest, loadManifest, render, install, check, applyIdentity } from './git-identity.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const example = path.join(here, '../git-identities.example.json');
const fixture = () => JSON.parse(fs.readFileSync(example, 'utf8'));
function setup(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'git-identity-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const directories = personas.map(id => path.join(root, id));
  return { root, directories, records: validateManifest(fixture()) };
}
function run(command, args, options = {}) {
  return spawnSync(command, args, { encoding: 'utf8', ...options });
}
function isolatedEnv(home) {
  // Only fixture environment enters child Git/entrypoint processes.
  return { PATH: process.env.PATH, HOME: home, XDG_CONFIG_HOME: path.join(home, '.config'),
    XDG_CACHE_HOME: path.join(home, '.cache'), CODEX_HOME: path.join(home, '.codex'),
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: path.join(home, '.gitconfig') };
}

test('complete, unique mapping is required; malformed input never leaks values', () => {
  assert.equal(loadManifest(example).length, 3);
  const mutations = [
    v => { v.identities.pop(); },
    v => { v.identities[1].agentId = v.identities[0].agentId; },
    v => { v.identities[1].name = v.identities[0].name.toUpperCase(); },
    v => { v.identities[1].email = v.identities[0].email.toUpperCase(); },
    v => { v.identities[0].name = ''; },
    v => { v.identities[0].name = '  '; },
    v => { v.identities[0].email = 'bad'; },
    v => { v.identities[0].name = 'private\nvalue'; },
    v => { v.identities[0].email = 'private\u0000@example.test'; },
    v => { v.identities[0].name = 'hidden\u202evalue'; },
    v => { v.identities[0].include = '/private'; },
    v => { v.identities[0].agentId = 'unknown'; },
  ];
  for (const mutate of mutations) { const v = fixture(); mutate(v); assert.throws(() => validateManifest(v)); }
});

test('install, repeat, apply and real local commits preserve three distinct identities', t => {
  const { root, directories, records } = setup(t);
  install(records, directories); check(records, directories);
  const before = directories.map(dir => fs.readFileSync(path.join(dir, 'gitconfig'), 'utf8'));
  install(records, directories); check(records, directories);
  assert.deepEqual(directories.map(dir => fs.readFileSync(path.join(dir, 'gitconfig'), 'utf8')), before);
  for (let i = 0; i < records.length; i++) {
    const home = path.join(root, 'home-' + i), repo = path.join(root, 'repo-' + i);
    fs.mkdirSync(home); fs.mkdirSync(repo);
    const target = path.join(home, '.gitconfig');
    fs.writeFileSync(target, '[user]\n name = stale\n email = stale@agents.example.test\n');
    applyIdentity(path.join(directories[i], 'gitconfig'), target, records[i].agentId);
    const stat = fs.statSync(target);
    assert.equal(stat.mode & 0o777, 0o600); assert.equal(stat.uid, 10001); assert.equal(stat.gid, 10001);
    const env = isolatedEnv(home);
    assert.equal(run('git', ['init', '-q', repo], { env }).status, 0);
    assert.equal(run('git', ['config', '--local', '--get', 'user.name'], { cwd: repo, env }).status, 1);
    assert.equal(run('git', ['config', '--global', '--get', 'user.useConfigOnly'], { env }).stdout.trim(), 'true');
    assert.equal(run('git', ['commit', '--allow-empty', '-qm', 'fixture'], { cwd: repo, env }).status, 0);
    assert.equal(run('git', ['log', '-1', '--format=%an|%ae|%cn|%ce'], { cwd: repo, env }).stdout.trim(),
      [records[i].name, records[i].email, records[i].name, records[i].email].join('|'));
    applyIdentity(path.join(directories[i], 'gitconfig'), target, records[i].agentId);
    assert.equal(fs.readFileSync(target, 'utf8'), before[i]);
  }
});

test('last-persona conflict aborts before writing other identities; unmanaged config is preserved', t => {
  const { directories, records } = setup(t);
  fs.mkdirSync(directories[2]);
  const conflict = path.join(directories[2], 'gitconfig');
  fs.writeFileSync(conflict, '[include]\n path = /do-not-read\n');
  assert.throws(() => install(records, directories));
  assert.equal(fs.existsSync(directories[0]), false);
  assert.equal(fs.readFileSync(conflict, 'utf8'), '[include]\n path = /do-not-read\n');
});

test('symlinks, hardlinks, nested directories and nonregular targets are rejected', t => {
  const { root, directories, records } = setup(t);
  fs.mkdirSync(directories[0]);
  const file = path.join(directories[0], 'gitconfig');
  fs.symlinkSync(path.join(root, 'missing'), file);
  assert.throws(() => install(records, directories)); fs.unlinkSync(file);
  fs.writeFileSync(path.join(root, 'shared'), render(records[0]));
  fs.linkSync(path.join(root, 'shared'), file);
  assert.throws(() => install(records, directories)); fs.unlinkSync(file);
  fs.mkdirSync(file); assert.throws(() => install(records, directories)); fs.rmdirSync(file);
  fs.symlinkSync(directories[0], path.join(root, 'link'));
  assert.throws(() => install(records, [path.join(root, 'link/child'), ...directories.slice(1)]));
  assert.throws(() => install(records, [directories[0], path.join(directories[0], 'child'), directories[2]]));
});

test('preflight validation rejects missing, wrong persona/value/useConfigOnly and permissions', t => {
  const { directories, records } = setup(t);
  install(records, directories);
  const file = path.join(directories[0], 'gitconfig');
  for (const content of [render(records[1]), render(records[0]).replace('true', 'false'),
    render(records[0]).replace(records[0].name, 'Wrong Fixture')]) {
    fs.writeFileSync(file, content);
    assert.throws(() => check(records, directories));
  }
  fs.writeFileSync(file, render(records[0]));
  fs.chmodSync(file, 0o644); assert.throws(() => check(records, directories));
  fs.chmodSync(file, 0o600);
  fs.chmodSync(directories[0], 0o755); assert.throws(() => check(records, directories));
  fs.chmodSync(directories[0], 0o700);
  fs.unlinkSync(file); assert.throws(() => check(records, directories));
});

test('entrypoint fails before credential loading despite stale HOME; valid identities start and restart', t => {
  const { root, directories, records } = setup(t);
  install(records, directories);
  const home = path.join(root, 'home'); fs.mkdirSync(home);
  const prompt = path.join(root, 'prompt'); fs.writeFileSync(prompt, 'fixture');
  const marker = path.join(root, 'started');
  const destination = path.join(home, '.gitconfig');
  fs.writeFileSync(destination, '[user]\n name = stale\n email = stale@agents.example.test\n');
  const env = { ...isolatedEnv(home), AGENT_ROLE: 'developer', AGENT_PROVIDER: 'codex',
    AGENT_CREDENTIALS_DIR: directories[1], AGENT_COMMON_PROMPT: prompt, AGENT_ROLE_PROMPT: prompt,
    BUZZ_RELAY_URL: 'wss://buzz.example.test', BUZZ_ACP_AGENT_OWNER: 'fixture' };
  const start = () => run('bash', [path.join(here, 'agent-entrypoint.sh'), 'touch', marker], { env });
  const source = path.join(directories[1], 'gitconfig');
  fs.unlinkSync(source);
  const missing = start(); assert.notEqual(missing.status, 0); assert.match(missing.stderr, /Git identity is required/);
  assert.equal(fs.existsSync(marker), false);
  install(records, directories);
  fs.writeFileSync(source, render(records[0]));
  assert.notEqual(start().status, 0); assert.equal(fs.existsSync(marker), false);
  fs.writeFileSync(source, render(records[1]));
  fs.writeFileSync(path.join(directories[1], 'buzz-private-key'), 'fixture');
  fs.writeFileSync(path.join(directories[1], 'codex-auth.json'), '{}');
  assert.equal(start().status, 0); assert.equal(fs.existsSync(marker), true);
  assert.equal(start().status, 0);
  assert.equal(fs.readFileSync(destination, 'utf8'), render(records[1]));
  fs.unlinkSync(destination); fs.symlinkSync(path.join(root, 'outside'), destination);
  assert.notEqual(start().status, 0); assert.equal(fs.existsSync(path.join(root, 'outside')), false);
});

test('quoted names roundtrip through Git without interpreting config directives', t => {
  const { root, directories, records } = setup(t);
  records[0].name = 'Fixture "Quoted" \\ Agent #1';
  install(records, directories);
  const target = path.join(root, '.gitconfig');
  applyIdentity(path.join(directories[0], 'gitconfig'), target, records[0].agentId);
  assert.equal(run('git', ['config', '--file', target, '--get', 'user.name']).stdout.trim(), records[0].name);
});

test('CLI rejects malformed JSON with value-free diagnostics', t => {
  const { root } = setup(t);
  const file = path.join(root, 'bad.json'); fs.writeFileSync(file, '{private-sentinel');
  const result = run('node', [path.join(here, 'git-identity.mjs'), 'validate', file]);
  assert.notEqual(result.status, 0); assert.equal(result.stdout, '');
  assert.ok(!result.stderr.includes('private-sentinel'));
});
