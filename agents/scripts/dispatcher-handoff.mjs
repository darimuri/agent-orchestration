#!/usr/bin/env node
// A durable gate around native MCP/Buzz calls, not an authorization service.
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const id = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const hex = /^[a-f0-9]{64}$/;
const fields = {
  taskId: id, workspaceId: id, agentId: id, assigneeId: id, jobId: id,
  repository: /^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/,
  baseRef: /^[A-Za-z0-9][A-Za-z0-9/_.-]{0,127}$/,
  baseSha: /^[a-f0-9]{40}$/,
  expiresAt: /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{3})?Z$/,
  channelId: /^[a-f0-9-]{36}$/, threadId: hex, mentionPubkey: hex,
  displayName: /^[\p{L}\p{N}][\p{L}\p{N} ._-]{0,79}$/u,
  trustedEventId: hex,
};
const operations = new Set(["repository:read", "issue:read", "issue:write", "branch:write", "pull-request:read", "pull-request:write"]);
const stages = ["assign", "comment", "notify"];
const codes = new Set(["permission_denied", "missing_member", "expired", "invalid_assignment", "scope_mismatch", "outcome_unknown"]);
function reject() { throw new Error("invalid_request"); }
function exact(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).sort().join() !== [...keys].sort().join()) reject();
}
export function validateAssignment(input) {
  exact(input, [...Object.keys(fields), "allowedOperations"]);
  const result = {};
  for (const [key, pattern] of Object.entries(fields)) {
    if (typeof input[key] !== "string" || !pattern.test(input[key])) reject();
    result[key] = input[key];
  }
  if (!Number.isFinite(Date.parse(result.expiresAt)) ||
      new Date(result.expiresAt).toISOString() !== result.expiresAt.replace(/Z$/, result.expiresAt.includes(".") ? "Z" : ".000Z")) reject();
  if (result.baseRef.includes("..") || result.baseRef.includes("//") ||
      result.baseRef.endsWith("/") || result.baseRef.endsWith(".") ||
      result.baseRef.split("/").some(part => part.endsWith(".lock") || part.startsWith("."))) reject();
  if (!Array.isArray(input.allowedOperations) || input.allowedOperations.length === 0 ||
      input.allowedOperations.some(op => !operations.has(op)) ||
      new Set(input.allowedOperations).size !== input.allowedOperations.length) reject();
  result.allowedOperations = [...input.allowedOperations].sort();
  return result;
}
export function assignmentKey(a) {
  // One job cannot silently acquire a different task, recipient, or payload.
  return createHash("sha256").update(a.jobId).digest("hex");
}
function payload(a, key) {
  return `Assignment: ${key}\nTask: ${a.taskId}\nAssignee: ${a.agentId}\nRepository: ${a.repository}\njobId: ${a.jobId}\nbaseRef: ${a.baseRef}\nbaseSha: ${a.baseSha}\nexpiresAt: ${a.expiresAt}\nAllowed operations: ${a.allowedOperations.join(", ")}\nOwner evidence: ${a.trustedEventId}`;
}
function operation(a, key, step) {
  const content = payload(a, key);
  if (step === "assign") return { tool: "kaneo.update_task_assignee", arguments: { taskId: a.taskId, userId: a.assigneeId } };
  if (step === "comment") return { tool: "kaneo.create_task_comment", arguments: { taskId: a.taskId, content } };
  return { tool: "buzz.messages.send", arguments: {
    channel: a.channelId, replyTo: a.threadId, mention: a.mentionPubkey,
    content: `@${a.displayName}\n${content}\nAssignment recorded. Verify your Gateway access and checkout SHA before resuming this task.`,
  } };
}
function verifyPreflight(a, p, now) {
  exact(p, ["taskId", "workspaceId", "agentId", "assigneeId", "mentionPubkey", "displayName", "channelId", "verifiedAt"]);
  for (const key of Object.keys(p).filter(k => k !== "verifiedAt")) {
    if (p[key] !== a[key]) throw new Error("scope_mismatch");
  }
  if (!Number.isSafeInteger(p.verifiedAt) || p.verifiedAt > now || now - p.verifiedAt > 60_000) reject();
}
function validateReceipt(a, step, receipt) {
  if (step === "assign") {
    exact(receipt, ["taskId", "assigneeId"]);
    if (receipt.taskId !== a.taskId || receipt.assigneeId !== a.assigneeId) reject();
  } else if (step === "comment") {
    exact(receipt, ["taskId", "commentId", "content"]);
    if (receipt.taskId !== a.taskId || typeof receipt.commentId !== "string" || !id.test(receipt.commentId) || receipt.content !== payload(a, assignmentKey(a))) reject();
  } else {
    exact(receipt, ["accepted", "eventId", "mentionPubkeys"]);
    if (receipt.accepted !== true || typeof receipt.eventId !== "string" || !hex.test(receipt.eventId) || !Array.isArray(receipt.mentionPubkeys) ||
        receipt.mentionPubkeys.length !== 1 || receipt.mentionPubkeys[0] !== a.mentionPubkey) reject();
  }
}
function blocked(a, code) {
  return { status: "blocked", code, report: { taskId: a.taskId, channelId: a.channelId, threadId: a.threadId,
    content: `Outcome: blocked\nTask: ${a.taskId}\nReason: ${code}\nNo automatic retry. Reconcile authoritative evidence before continuing.` } };
}
function save(directory, file, state) {
  const temporary = `${file}.tmp`;
  const fd = fs.openSync(temporary, "wx", 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(state)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(temporary, file);
  const dir = fs.openSync(directory, "r");
  try { fs.fsyncSync(dir); } finally { fs.closeSync(dir); }
}

// Sync the whole ancestry even when mkdir created nothing: an earlier failed
// attempt or a concurrent creator may have left an unpersisted directory entry.
// Child-before-parent reaches the root before any execution intent is issued.
function syncDirectoryChain(directory) {
  let current = path.resolve(directory);
  while (true) {
    const fd = fs.openSync(current, "r");
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
}

// Every command holds the same lock. A killed process leaves a lock, deliberately
// requiring operator reconciliation rather than guessing whether an effect happened.
export function dispatch(directory, request, now = Date.now()) {
  if (!Number.isSafeInteger(now)) reject();
  const a = validateAssignment(request.assignment);
  const key = assignmentKey(a);
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const stat = fs.lstatSync(directory);
  if (fs.realpathSync(directory) !== path.resolve(directory) || !stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o077)) reject();
  syncDirectoryChain(directory);
  const file = path.join(directory, `${key}.json`);
  const lock = path.join(directory, `${key}.lock`);
  let fd;
  try { fd = fs.openSync(lock, "wx", 0o600); } catch { return blocked(a, "journal_locked"); }
  try {
    let state;
    if (fs.existsSync(file)) {
      const journalStat = fs.lstatSync(file);
      if (!journalStat.isFile() || journalStat.isSymbolicLink() || journalStat.uid !== process.getuid() || (journalStat.mode & 0o077)) reject();
      state = JSON.parse(fs.readFileSync(file, "utf8"));
      exact(state, ["assignment", "completed", "pending", "receipts", "blocked"]);
      if (state.blocked !== null && !codes.has(state.blocked)) reject();
      if (JSON.stringify(state.assignment) !== JSON.stringify(a)) return blocked(a, "assignment_conflict");
      if (!Number.isInteger(state.completed) || state.completed < 0 || state.completed > 3 ||
          typeof state.pending !== "boolean" || !Array.isArray(state.receipts) || state.receipts.length !== state.completed ||
          state.receipts.some(receipt => typeof receipt !== "string" || !id.test(receipt)) ||
          (state.completed === 3 && state.pending)) reject();
    } else {
      state = { assignment: a, completed: 0, pending: false, receipts: [], blocked: null };
    }
    if (request.action === "record") {
      exact(request, ["action", "assignment", "step", "receipt"]);
      if (state.blocked || !state.pending || stages[state.completed] !== request.step) reject();
      validateReceipt(a, request.step, request.receipt);
      // Keep only validated, non-secret identifiers in the journal.
      state.receipts.push(request.receipt.commentId ?? request.receipt.eventId ?? a.taskId);
      state.completed += 1;
      state.pending = false;
      save(directory, file, state);
      return { status: state.completed === 3 ? "complete" : "recorded", key, receipts: state.receipts };
    }
    if (request.action === "fail") {
      exact(request, ["action", "assignment", "code"]);
      if (!codes.has(request.code)) reject();
      state.blocked = request.code;
      save(directory, file, state);
      return blocked(a, request.code);
    }
    exact(request, ["action", "assignment", "preflight"]);
    if (request.action !== "next") reject();
    if (state.blocked) return blocked(a, state.blocked);
    if (state.completed === 3) return { status: "complete", key, receipts: state.receipts };
    if (state.pending) return blocked(a, "outcome_unknown");
    if (Date.parse(a.expiresAt) <= now) return blocked(a, "expired");
    verifyPreflight(a, request.preflight, now);
    state.pending = true;
    save(directory, file, state); // Intent reaches durable storage BEFORE caller sees it.
    return { status: "execute_once", key, step: stages[state.completed], operation: operation(a, key, stages[state.completed]) };
  } finally {
    fs.closeSync(fd);
    fs.unlinkSync(lock);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 3) reject();
    const input = fs.readFileSync(0, "utf8");
    if (Buffer.byteLength(input) > 16384) reject();
    const result = dispatch(process.argv[2], JSON.parse(input));
    process.stdout.write(`${JSON.stringify(result)}\n`);
    if (result.status === "blocked") process.exitCode = 1;
  } catch {
    // Never echo input, filesystem paths, upstream errors, or credentials.
    process.stdout.write('{"status":"blocked","code":"invalid_request_or_journal"}\n');
    process.exitCode = 1;
  }
}
