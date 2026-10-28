import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const personas = ['dispatcher-planner', 'developer-a', 'reviewer-a'];
// Library callers may inject fixture ownership. CLI callers always use this default.
const runtimeOwner = Object.freeze({ uid: 10001, gid: 10001 });
class IdentityError extends Error {}
const fail = (message) => { throw new IdentityError(message); };
const exactKeys = (value, keys) => value && typeof value === 'object'
  && !Array.isArray(value) && Object.keys(value).sort().join(',') === [...keys].sort().join(',');

function validateRecord(record, hostApply = false) {
  if (!exactKeys(record, ['agentId', 'name', 'email']) || !(personas.includes(record.agentId) || (hostApply && record.agentId === 'host-operator'))) {
    fail('invalid identity record or persona');
  }
  for (const key of ['name', 'email']) {
    const text = record[key];
    if (typeof text !== 'string' || !text.trim() || text !== text.trim()
        || /[\p{Cc}\p{Cf}<>]/u.test(text) || text.length > 254) fail('invalid identity name or email');
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(record.email)) fail('invalid identity email');
}

export function validateManifest(value) {
  if (!exactKeys(value, ['identities']) || !Array.isArray(value.identities)
      || value.identities.length !== personas.length) fail('manifest must contain exactly three identities');
  const ids = new Set(), names = new Set(), emails = new Set();
  for (const record of value.identities) {
    validateRecord(record);
    const name = record.name.toLowerCase(), email = record.email.toLowerCase();
    if (ids.has(record.agentId) || names.has(name) || emails.has(email)) fail('duplicate or shared identity');
    ids.add(record.agentId); names.add(name); emails.add(email);
  }
  return personas.map(id => value.identities.find(record => record.agentId === id));
}

export function loadManifest(file) {
  try {
    regular(file);
    return validateManifest(JSON.parse(fs.readFileSync(file, 'utf8')));
  }
  catch { fail('identity manifest missing or invalid; supply approved distinct identities (values suppressed)'); }
}

function quote(value) { return '"' + value.replaceAll('\\', '\\\\').replaceAll('"', '\\"') + '"'; }
export function render(record) {
  return `# Managed agent Git identity v1: ${record.agentId}\n[user]\n\tname = ${quote(record.name)}\n\temail = ${quote(record.email)}\n\tuseConfigOnly = true\n`;
}

// Never follow a symlink in any path component, including dangling links.
export function safePath(file) {
  if (!path.isAbsolute(file) || path.resolve(file) !== file) fail('identity path must be absolute and canonical');
  let current = path.parse(file).root;
  for (const part of file.slice(current.length).split('/').filter(Boolean)) {
    current = path.join(current, part);
    try {
      if (fs.lstatSync(current).isSymbolicLink()) fail('symlink in identity path');
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
}

function regular(file, optional = false) {
  safePath(file);
  let stat;
  try { stat = fs.lstatSync(file); }
  catch (error) { if (optional && error.code === 'ENOENT') return null; throw error; }
  if (!stat.isFile() || stat.nlink !== 1) fail('identity file must be regular with one link');
  return stat;
}
function privateFile(file, owner) {
  const stat = regular(file);
  if (stat.uid !== owner.uid || stat.gid !== owner.gid || (stat.mode & 0o777) !== 0o600) {
    fail('identity file requires 10001:10001 and mode 0600');
  }
}
function privateDirectory(dir, owner) {
  safePath(dir);
  const stat = fs.lstatSync(dir);
  if (!stat.isDirectory() || stat.uid !== owner.uid || stat.gid !== owner.gid || (stat.mode & 0o777) !== 0o700) {
    fail('identity directory requires 10001:10001 and mode 0700');
  }
}
function atomicWrite(file, content, owner) {
  safePath(file);
  regular(file, true);
  const temporary = fs.mkdtempSync(path.join(path.dirname(file), '.git-identity-'));
  const staged = path.join(temporary, 'gitconfig');
  try {
    fs.writeFileSync(staged, content, { flag: 'wx', mode: 0o600 });
    fs.chownSync(staged, owner.uid, owner.gid);
    fs.renameSync(staged, file);
  } finally { fs.rmSync(temporary, { recursive: true, force: true }); }
}

export function checkInstall(records, directories) {
  if (directories.length !== personas.length) fail('three credential directories are required');
  for (const dir of directories) safePath(dir);
  for (let i = 0; i < directories.length; i++) {
    for (let j = 0; j < i; j++) {
      if (directories[i] === directories[j] || directories[i].startsWith(directories[j] + '/')
          || directories[j].startsWith(directories[i] + '/')) fail('credential directories must be disjoint');
    }
    const file = path.join(directories[i], 'gitconfig');
    if (regular(file, true) && fs.readFileSync(file, 'utf8') !== render(records[i])) {
      fail('existing gitconfig conflicts; preserve it and follow the migration guide');
    }
  }
}
export function install(records, directories, owner = runtimeOwner) {
  // Check every destination before any write, including a conflict in the last persona.
  checkInstall(records, directories);
  for (let i = 0; i < directories.length; i++) {
    fs.mkdirSync(directories[i], { recursive: true, mode: 0o700 });
    fs.chownSync(directories[i], owner.uid, owner.gid);
    fs.chmodSync(directories[i], 0o700);
    atomicWrite(path.join(directories[i], 'gitconfig'), render(records[i]), owner);
  }
}
export function check(records, directories, owner = runtimeOwner) {
  checkInstall(records, directories);
  for (const dir of directories) {
    privateDirectory(dir, owner);
    privateFile(path.join(dir, 'gitconfig'), owner);
  }
}

export function applyIdentity(source, destination, role, owner = runtimeOwner) {
  const persona = ({ developer: 'developer-a', reviewer: 'reviewer-a' })[role] ?? role;
  if (!personas.includes(persona) && persona !== 'host-operator') fail('unknown identity persona');
  privateDirectory(path.dirname(source), owner);
  privateFile(source, owner);
  const content = fs.readFileSync(source, 'utf8');
  // Parse only our generated subset, never Git includes, helpers, or arbitrary config.
  const match = content.match(/^# Managed agent Git identity v1: ([a-z-]+)\n\[user\]\n\tname = ("(?:[^"\\\n]|\\["\\])*")\n\temail = ("(?:[^"\\\n]|\\["\\])*")\n\tuseConfigOnly = true\n$/);
  if (!match || match[1] !== persona) fail('missing, unmanaged, or wrong-persona gitconfig; run identity provisioning');
  let record;
  try { record = { agentId: persona, name: JSON.parse(match[2]), email: JSON.parse(match[3]) }; }
  catch { fail('invalid managed gitconfig'); }
  validateRecord(record, true);
  if (render(record) !== content) fail('invalid managed gitconfig');
  atomicWrite(destination, content, owner);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [command, input, ...args] = process.argv.slice(2);
    if (command === 'apply') {
      if (args.length !== 2) fail('apply requires source, destination, role');
      applyIdentity(input, ...args);
    } else {
      const records = loadManifest(input);
      if (command === 'validate' && args.length === 0) { /* validation only */ }
      else if (command === 'check-install') checkInstall(records, args);
      else if (command === 'install') install(records, args);
      else if (command === 'check') check(records, args);
      else fail('unknown identity command');
    }
  } catch (error) {
    const reason = error instanceof IdentityError ? error.message : 'file access or ownership operation failed';
    console.error('git-identity: ' + reason + ' (identity values suppressed)');
    process.exitCode = 1;
  }
}
