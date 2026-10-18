import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync, spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { assignmentKey, dispatch, validateAssignment } from "./dispatcher-handoff.mjs";

const now = Date.parse("2026-10-18T03:00:00Z");
const assignment = {
  taskId: "task-4", workspaceId: "workspace", agentId: "developer-a",
  assigneeId: "member-a", jobId: "age4-test", repository: "example/orchestration",
  baseRef: "main", baseSha: "a".repeat(40), expiresAt: "2026-10-25T03:00:00Z",
  channelId: "e04d48c5-f100-4e75-9362-aaac11094227", threadId: "b".repeat(64),
  mentionPubkey: "c".repeat(64), displayName: "Developer A", trustedEventId: "d".repeat(64),
  allowedOperations: ["repository:read", "branch:write", "pull-request:write"],
};
const preflight = Object.fromEntries(["taskId", "workspaceId", "agentId", "assigneeId", "mentionPubkey", "displayName", "channelId"].map(k => [k, assignment[k]]));
preflight.verifiedAt = now;
const script = fileURLToPath(new URL("./dispatcher-handoff.mjs", import.meta.url));
function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "handoff-test-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}
function next(directory, a = assignment, p = preflight, time = now) {
  return dispatch(directory, { action: "next", assignment: a, preflight: p }, time);
}
function record(directory, result) {
  const { step, operation: op } = result;
  const receipt = step === "assign" ? { taskId: assignment.taskId, assigneeId: assignment.assigneeId }
    : step === "comment" ? { taskId: assignment.taskId, commentId: "comment-1", content: op.arguments.content }
    : { accepted: true, eventId: "e".repeat(64), mentionPubkeys: [assignment.mentionPubkey] };
  return dispatch(directory, { action: "record", assignment, step, receipt }, now);
}

test("native operation sequence preserves assignment and posts once; replay does nothing", t => {
  const dir = fixture(t), calls = [];
  for (const step of ["assign", "comment", "notify"]) {
    const plan = next(dir);
    assert.equal(plan.status, "execute_once");
    assert.equal(plan.step, step);
    calls.push(plan.operation);
    record(dir, plan);
  }
  assert.equal(next(dir).status, "complete");
  assert.equal(next(dir).status, "complete");
  assert.deepEqual(calls.map(c => c.tool), ["kaneo.update_task_assignee", "kaneo.create_task_comment", "buzz.messages.send"]);
  const comment = calls[1].arguments.content;
  for (const k of ["repository", "baseRef", "baseSha", "jobId", "expiresAt"]) assert.ok(comment.includes(assignment[k]));
  assert.equal(calls[2].arguments.replyTo, assignment.threadId);
  assert.equal(calls[2].arguments.channel, assignment.channelId);
  assert.equal(calls[2].arguments.mention, assignment.mentionPubkey);
  assert.ok(calls[2].arguments.content.startsWith("@Developer A\n"));
});

for (const crashStep of ["assign", "comment", "notify"]) test(`crash after ${crashStep} effect, before receipt: no duplicate; verified receipt resumes`, t => {
  const dir = fixture(t);
  let plan;
  for (const step of ["assign", "comment", "notify"]) {
    plan = next(dir);
    if (step === crashStep) break;
    record(dir, plan);
  }
  // A fresh invocation sees only durable state; an effect may already have happened.
  assert.equal(next(dir).code, "outcome_unknown");
  assert.equal(next(dir).code, "outcome_unknown");
  record(dir, plan); // Reconciled from authoritative read-back, never re-executed.
  while (true) {
    const result = next(dir);
    if (result.status === "complete") break;
    record(dir, result);
  }
  assert.equal(next(dir).status, "complete");
});

test("expiry, missing or mismatched membership, and stale evidence produce no operation", t => {
  const dir = fixture(t);
  assert.equal(next(dir, { ...assignment, expiresAt: "2026-10-18T02:59:59Z" }).code, "expired");
  assert.throws(() => next(dir, assignment, { ...preflight, assigneeId: "missing" }), /scope_mismatch/);
  assert.throws(() => next(dir, assignment, { ...preflight, mentionPubkey: "f".repeat(64) }), /scope_mismatch/);
  assert.throws(() => next(dir, assignment, { ...preflight, verifiedAt: now - 60001 }));
  assert.throws(() => next(dir, assignment, { ...preflight, verifiedAt: now + 1 }));
  assert.equal(fs.readdirSync(dir).length, 0);
});

test("expiry between steps prevents further calls, but allows recording known past success", t => {
  const dir = fixture(t);
  const plan = next(dir);
  record(dir, plan);
  assert.equal(next(dir, assignment, preflight, Date.parse(assignment.expiresAt)).code, "expired");
});

for (const code of ["permission_denied", "missing_member"]) test(`${code} blocks every later step`, t => {
  const dir = fixture(t);
  if (code === "permission_denied") next(dir);
  const result = dispatch(dir, { action: "fail", assignment, code }, now);
  assert.equal(result.report.channelId, assignment.channelId);
  assert.equal(result.report.taskId, assignment.taskId);
  assert.equal(next(dir).code, code);
  assert.equal(next(dir).code, code);
});

test("same job cannot be reused for another task, SHA or recipient", t => {
  const dir = fixture(t);
  next(dir);
  for (const change of [{ taskId: "other" }, { baseSha: "f".repeat(40) }, { mentionPubkey: "f".repeat(64) }, { jobId: assignment.jobId, expiresAt: "2027-01-01T00:00:00Z" }]) {
    assert.equal(next(dir, { ...assignment, ...change }).code, "assignment_conflict");
  }
});

test("bad receipts never unlock a pending write", t => {
  const dir = fixture(t);
  next(dir);
  assert.throws(() => dispatch(dir, { action: "record", assignment, step: "assign", receipt: { taskId: assignment.taskId, assigneeId: "other" } }, now));
  assert.equal(next(dir).code, "outcome_unknown");
});

test("missing mention or rejected Buzz response never completes", t => {
  const dir = fixture(t);
  record(dir, next(dir)); record(dir, next(dir)); next(dir);
  for (const receipt of [
    { accepted: false, eventId: "e".repeat(64), mentionPubkeys: [assignment.mentionPubkey] },
    { accepted: true, eventId: "e".repeat(64), mentionPubkeys: [] },
  ]) assert.throws(() => dispatch(dir, { action: "record", assignment, step: "notify", receipt }, now));
  assert.equal(next(dir).code, "outcome_unknown");
});

test("exclusive lock, leftover temp and malformed state fail closed", t => {
  const dir = fixture(t), key = assignmentKey(assignment);
  fs.writeFileSync(path.join(dir, `${key}.lock`), "");
  assert.equal(next(dir).code, "journal_locked");
  fs.unlinkSync(path.join(dir, `${key}.lock`));
  fs.writeFileSync(path.join(dir, `${key}.json.tmp`), "partial");
  assert.throws(() => next(dir));
  fs.unlinkSync(path.join(dir, `${key}.json.tmp`));
  fs.writeFileSync(path.join(dir, `${key}.json`), "broken");
  assert.throws(() => next(dir));
});

test("CLI restart and concurrent processes issue at most one intent", async t => {
  const dir = fixture(t);
  const a = { ...assignment, expiresAt: new Date(Date.now() + 3600000).toISOString() };
  const input = JSON.stringify({ action: "next", assignment: a, preflight: { ...preflight, verifiedAt: Date.now() } });
  const invoke = () => new Promise(resolve => {
    const child = spawn(process.execPath, [script, dir]);
    let stdout = "";
    child.stdout.on("data", chunk => { stdout += chunk; });
    child.on("close", () => resolve(JSON.parse(stdout)));
    child.stdin.end(input);
  });
  const results = await Promise.all([invoke(), invoke()]);
  assert.equal(results.filter(r => r.status === "execute_once").length, 1);
  assert.equal(results.filter(r => r.status === "blocked").length, 1);
  assert.equal((await invoke()).code, "outcome_unknown");
});

test("unknown fields, credential-shaped payloads, and errors do not leak to stdout, stderr or journal", t => {
  const dir = fixture(t), secret = "NEVER_PRINT_THIS_FIXTURE_SECRET";
  for (const request of [
    { action: "next", assignment: { ...assignment, token: secret }, preflight },
    { action: "fail", assignment, code: secret },
    { action: "next", assignment: { ...assignment, displayName: `@bad\n${secret}` }, preflight },
  ]) {
    const result = spawnSync(process.execPath, [script, dir], { input: JSON.stringify(request), encoding: "utf8" });
    assert.equal(result.status, 1);
    assert.equal(result.stderr, "");
    assert.ok(!result.stdout.includes(secret));
    for (const file of fs.readdirSync(dir)) assert.ok(!fs.readFileSync(path.join(dir, file), "utf8").includes(secret));
  }
  assert.throws(() => validateAssignment({ ...assignment, allowedOperations: ["merge"] }));
});

test("invalid dates, refs, privileges and non-private journal paths are rejected", t => {
  const dir = fixture(t);
  for (const change of [
    { expiresAt: "2026-02-30T00:00:00Z" }, { baseRef: "../main" },
    { baseRef: "main.lock" }, { repository: "../repo" },
    { allowedOperations: ["repository:read", "repository:read"] },
  ]) assert.throws(() => validateAssignment({ ...assignment, ...change }));
  fs.chmodSync(dir, 0o755);
  assert.throws(() => next(dir));
  fs.chmodSync(dir, 0o700);
  const link = `${dir}-link`;
  fs.symlinkSync(dir, link);
  t.after(() => fs.unlinkSync(link));
  assert.throws(() => next(link));
});

test("receipt can be reconciled after expiry without issuing another effect", t => {
  const dir = fixture(t);
  next(dir);
  const afterExpiry = Date.parse(assignment.expiresAt) + 1;
  const result = dispatch(dir, { action: "record", assignment, step: "assign", receipt: {
    taskId: assignment.taskId, assigneeId: assignment.assigneeId,
  } }, afterExpiry);
  assert.equal(result.status, "recorded");
  assert.equal(next(dir, assignment, preflight, afterExpiry).code, "expired");
});
