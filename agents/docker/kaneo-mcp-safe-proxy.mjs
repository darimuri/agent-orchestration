#!/usr/bin/env node

import { spawn } from "node:child_process";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import readline from "node:readline";

const blockedTools = new Set(["whoami"]);

function idKey(id) {
  return JSON.stringify(id);
}

export function inspectClientMessage(message, pendingToolLists) {
  if (Array.isArray(message)) {
    const decisions = message.map((item) => inspectClientMessage(item, pendingToolLists));
    const forwarded = decisions.filter((decision) => decision.forward).map((decision) => decision.message);
    const responses = decisions.flatMap((decision) => decision.response ? [decision.response] : []);
    return {
      forward: forwarded.length > 0,
      message: forwarded,
      response: responses.length > 0 ? responses : undefined,
    };
  }

  if (message?.method === "tools/call" && blockedTools.has(message.params?.name)) {
    return {
      forward: false,
      response: {
        jsonrpc: "2.0",
        id: message.id,
        error: {
          code: -32602,
          message: "Tool is disabled by agent security policy",
        },
      },
    };
  }

  if (message?.method === "tools/list" && message.id !== undefined) {
    pendingToolLists.add(idKey(message.id));
  }
  return { forward: true, message };
}

export function filterServerMessage(message, pendingToolLists) {
  if (Array.isArray(message)) {
    return message.map((item) => filterServerMessage(item, pendingToolLists));
  }
  if (message?.id === undefined) return message;

  const key = idKey(message.id);
  if (!pendingToolLists.delete(key)) return message;
  if (!Array.isArray(message.result?.tools)) return message;

  return {
    ...message,
    result: {
      ...message.result,
      tools: message.result.tools.filter((tool) => !blockedTools.has(tool?.name)),
    },
  };
}

function writeMessage(stream, message) {
  stream.write(`${JSON.stringify(message)}\n`);
}

function main() {
  const upstreamCommand = process.argv[2] ?? "kaneo-mcp";
  const upstreamArgs = process.argv.length > 2 ? process.argv.slice(3) : ["serve"];
  const child = spawn(upstreamCommand, upstreamArgs, {
    env: process.env,
    stdio: ["pipe", "pipe", "ignore"],
  });
  const pendingToolLists = new Set();
  let clientInputClosed = false;
  let shuttingDown = false;
  let clientLines;
  let serverLines;

  function shutdown(message, exitCode) {
    if (shuttingDown) return;
    shuttingDown = true;
    if (message) process.stderr.write(`kaneo-mcp-safe-proxy: ${message}\n`);
    clientLines?.close();
    serverLines?.close();
    process.stdin.pause();
    child.stdin?.destroy();
    child.stdout?.destroy();
    if (child.exitCode === null && child.signalCode === null) child.kill();
    process.exitCode = exitCode;
  }

  child.on("error", () => shutdown("failed to start upstream server", 1));
  child.on("close", (code, signal) => {
    const expected = clientInputClosed && code === 0 && signal === null;
    shutdown(expected ? undefined : "upstream server exited unexpectedly", expected ? 0 : 1);
  });
  child.stdin.on("error", () => shutdown("upstream input failed", 1));

  clientLines = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  clientLines.on("line", (line) => {
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      shutdown("invalid client JSON", 1);
      return;
    }

    const decision = inspectClientMessage(message, pendingToolLists);
    if (decision.forward) writeMessage(child.stdin, decision.message);
    if (decision.response) writeMessage(process.stdout, decision.response);
  });
  clientLines.on("close", () => {
    if (shuttingDown) return;
    clientInputClosed = true;
    child.stdin.end();
  });

  serverLines = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });
  serverLines.on("line", (line) => {
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      shutdown("invalid upstream JSON", 1);
      return;
    }
    writeMessage(process.stdout, filterServerMessage(message, pendingToolLists));
  });
}

if (process.argv[1] && fileURLToPath(import.meta.url) === realpathSync(process.argv[1])) main();
