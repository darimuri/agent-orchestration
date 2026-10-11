import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import path from "node:path";
import readline from "node:readline";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  filterServerMessage,
  inspectClientMessage,
} from "./kaneo-mcp-safe-proxy.mjs";

const proxy = path.join(path.dirname(fileURLToPath(import.meta.url)), "kaneo-mcp-safe-proxy.mjs");

function waitForClose(child, timeoutMs = 1000) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      child.kill();
      reject(new Error("timed out waiting for proxy to exit"));
    }, timeoutMs);
    child.once("close", (code, signal) => {
      clearTimeout(timeout);
      resolve({ code, signal });
    });
  });
}

test("removes whoami from tools/list responses", () => {
  const pending = new Set();
  const request = { jsonrpc: "2.0", id: 7, method: "tools/list", params: {} };

  assert.equal(inspectClientMessage(request, pending).forward, true);
  const response = filterServerMessage({
    jsonrpc: "2.0",
    id: 7,
    result: {
      tools: [
        { name: "whoami", description: "returns a session" },
        { name: "list_projects", description: "lists projects" },
      ],
    },
  }, pending);

  assert.deepEqual(response.result.tools, [
    { name: "list_projects", description: "lists projects" },
  ]);
  assert.equal(pending.size, 0);
});

test("rejects direct whoami calls without forwarding them", () => {
  const pending = new Set();
  const decision = inspectClientMessage({
    jsonrpc: "2.0",
    id: "call-1",
    method: "tools/call",
    params: { name: "whoami", arguments: {} },
  }, pending);

  assert.equal(decision.forward, false);
  assert.equal(decision.response.id, "call-1");
  assert.equal(decision.response.error.code, -32602);
  assert.doesNotMatch(JSON.stringify(decision.response), /session|token/i);
});

test("filters whoami from JSON-RPC batches", () => {
  const pending = new Set();
  const decision = inspectClientMessage([
    { jsonrpc: "2.0", id: 1, method: "tools/list" },
    { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "whoami" } },
    { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "list_projects" } },
  ], pending);

  assert.deepEqual(decision.message.map((message) => message.id), [1, 3]);
  assert.deepEqual(decision.response.map((response) => response.id), [2]);
  assert.deepEqual(filterServerMessage([{
    jsonrpc: "2.0",
    id: 1,
    result: { tools: [{ name: "whoami" }, { name: "list_projects" }] },
  }], pending)[0].result.tools, [{ name: "list_projects" }]);
});

test("passes allowed calls and unrelated responses through unchanged", () => {
  const pending = new Set();
  const request = {
    jsonrpc: "2.0",
    id: 9,
    method: "tools/call",
    params: { name: "list_projects", arguments: {} },
  };
  const response = { jsonrpc: "2.0", id: 9, result: { content: [{ type: "text", text: "ok" }] } };

  assert.equal(inspectClientMessage(request, pending).forward, true);
  assert.equal(filterServerMessage(response, pending), response);
});

test("matches tools/list responses by JSON-RPC id", () => {
  const pending = new Set();
  inspectClientMessage({ jsonrpc: "2.0", id: "list-2", method: "tools/list" }, pending);

  const unrelated = { jsonrpc: "2.0", id: "other", result: { tools: [{ name: "whoami" }] } };
  assert.equal(filterServerMessage(unrelated, pending), unrelated);
  assert.equal(pending.size, 1);

  const error = { jsonrpc: "2.0", id: "list-2", error: { code: -32000, message: "failed" } };
  assert.equal(filterServerMessage(error, pending), error);
  assert.equal(pending.size, 0);
});

test("filters an upstream server end to end without logging its diagnostics", async (context) => {
  const secret = "raw-session-token-must-not-escape";
  const fakeUpstream = `
    import readline from "node:readline";
    const calls = [];
    process.stderr.write(${JSON.stringify(secret)} + "\\n");
    const lines = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
    lines.on("line", (line) => {
      const message = JSON.parse(line);
      if (message.method === "tools/list") {
        process.stdout.write(JSON.stringify({
          jsonrpc: "2.0",
          id: message.id,
          result: { tools: [{ name: "whoami" }, { name: "list_projects" }] },
        }) + "\\n");
      } else if (message.method === "tools/call") {
        calls.push(message.params.name);
        process.stdout.write(JSON.stringify({
          jsonrpc: "2.0",
          id: message.id,
          result: message.params.name === "whoami"
            ? { structuredContent: { session: { token: ${JSON.stringify(secret)} } } }
            : { structuredContent: { calls } },
        }) + "\\n");
      }
    });
  `;
  const child = spawn(process.execPath, [
    proxy,
    process.execPath,
    "--input-type=module",
    "-e",
    fakeUpstream,
  ], { stdio: ["pipe", "pipe", "pipe"] });
  context.after(() => child.kill());

  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => { stderr += chunk; });

  const responses = [];
  const responseLines = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });
  const received = new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("timed out waiting for proxy responses")), 2000);
    responseLines.on("line", (line) => {
      responses.push(JSON.parse(line));
      if (responses.length === 3) {
        clearTimeout(timeout);
        resolve();
      }
    });
  });

  for (const message of [
    { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} },
    { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "whoami", arguments: {} } },
    { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "list_projects", arguments: {} } },
  ]) {
    child.stdin.write(`${JSON.stringify(message)}\n`);
  }
  await received;

  const byId = Object.fromEntries(responses.map((response) => [response.id, response]));
  assert.deepEqual(byId[1].result.tools, [{ name: "list_projects" }]);
  assert.equal(byId[2].error.code, -32602);
  assert.deepEqual(byId[3].result.structuredContent.calls, ["list_projects"]);
  assert.doesNotMatch(JSON.stringify(responses), /session-token/);
  assert.doesNotMatch(stderr, /session-token/);
});

test("exits when the upstream server stops while client input remains open", async (context) => {
  const child = spawn(process.execPath, [
    proxy,
    process.execPath,
    "-e",
    "process.exit(0)",
  ], { stdio: ["pipe", "pipe", "pipe"] });
  context.after(() => child.kill());

  const result = await waitForClose(child);
  assert.equal(result.signal, null);
  assert.equal(result.code, 1);
});

test("exits when the upstream command cannot be spawned", async (context) => {
  const child = spawn(process.execPath, [
    proxy,
    `missing-kaneo-upstream-${process.pid}`,
  ], { stdio: ["pipe", "pipe", "pipe"] });
  context.after(() => child.kill());

  const result = await waitForClose(child);
  assert.equal(result.signal, null);
  assert.equal(result.code, 1);
});
