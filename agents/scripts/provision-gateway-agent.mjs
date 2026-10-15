#!/usr/bin/env node

import { createHash, randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { chmod, chown, readFile, rename, rm, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const [agentId, role, credentialDirectory, runtimeDirectory] = process.argv.slice(2);
if (!agentId || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(agentId)) {
  throw new Error("agent ID must match [a-z0-9][a-z0-9._-]{0,63}");
}
if (role !== "control" && role !== "developer" && role !== "reviewer") {
  throw new Error("role must be control, developer, or reviewer");
}
if (!credentialDirectory || !runtimeDirectory) {
  throw new Error("usage: provision-gateway-agent.mjs <agent-id> <role> <credential-dir> <gateway-runtime-dir>");
}
if (typeof process.getuid === "function" && process.getuid() !== 0) {
  throw new Error("run as root so files can be assigned to container UIDs 10001 and 1000");
}

const ttlInput = process.env.GATEWAY_AGENT_TOKEN_TTL_DAYS ?? "30";
if (!/^[1-9][0-9]*$/.test(ttlInput)) {
  throw new Error("GATEWAY_AGENT_TOKEN_TTL_DAYS must be a decimal integer from 1 to 365");
}
const ttlDays = Number(ttlInput);
if (!Number.isInteger(ttlDays) || ttlDays < 1 || ttlDays > 365) {
  throw new Error("GATEWAY_AGENT_TOKEN_TTL_DAYS must be an integer from 1 to 365");
}

const lockEnvironment = "GATEWAY_AGENT_PROVISION_LOCK_HELD";
if (process.env[lockEnvironment] !== "1") {
  const lockFile = path.resolve(runtimeDirectory, ".provision-gateway-agent.lock");
  const result = spawnSync(
    "flock",
    [
      "--exclusive",
      lockFile,
      process.execPath,
      fileURLToPath(import.meta.url),
      ...process.argv.slice(2),
    ],
    {
      env: { ...process.env, [lockEnvironment]: "1" },
      stdio: "inherit",
    },
  );
  if (result.error?.code === "ENOENT") {
    throw new Error("flock is required to serialize gateway agent provisioning");
  }
  if (result.error) throw result.error;
  if (result.signal) throw new Error(`provisioning lock process ended from signal ${result.signal}`);
  process.exit(result.status ?? 1);
}

const token = `gag_${randomBytes(32).toString("base64url")}`;
const tokenSha256 = createHash("sha256").update(token).digest("hex");
const expiresAt = new Date(Date.now() + ttlDays * 24 * 60 * 60 * 1000).toISOString();
const agentsFile = path.resolve(runtimeDirectory, "agents.json");
const tokenFile = path.resolve(credentialDirectory, "github-gateway-agent-token");

const agentsConfig = JSON.parse(await readFile(agentsFile, "utf8"));
if (!Array.isArray(agentsConfig.agents)) throw new Error("agents.json must contain an agents array");
const nextAgent = { id: agentId, role, tokenSha256, expiresAt, disabled: false };
const existingAgents = agentsConfig.agents.filter((agent) => agent?.id === agentId);
const otherAgents = agentsConfig.agents.filter((agent) => agent?.id !== agentId);

let currentToken;
try {
  currentToken = await readFile(tokenFile, "utf8");
} catch (error) {
  if (error?.code !== "ENOENT") throw error;
}
let currentAgent;
if (currentToken !== undefined) {
  const currentHash = createHash("sha256").update(currentToken).digest("hex");
  currentAgent = existingAgents.find((agent) => agent?.tokenSha256 === currentHash);
  if (!currentAgent) {
    throw new Error("existing agent token does not match any agents.json record; refusing unsafe rotation");
  }
} else if (existingAgents.length > 0) {
  throw new Error("agents.json contains the agent but its existing token file is missing");
}

const finalConfig = { ...agentsConfig, agents: [...otherAgents, nextAgent] };
const transitionConfig = currentAgent
  ? { ...agentsConfig, agents: [...otherAgents, currentAgent, nextAgent] }
  : finalConfig;
const suffix = `${process.pid}-${randomBytes(6).toString("hex")}`;
const tokenTemporary = `${tokenFile}.${suffix}.next`;
const transitionTemporary = `${agentsFile}.${suffix}.transition`;
const finalTemporary = `${agentsFile}.${suffix}.final`;
const rollbackTemporary = `${agentsFile}.${suffix}.rollback`;
const temporaryFiles = [tokenTemporary, transitionTemporary, finalTemporary, rollbackTemporary];

async function writeOwnedFile(file, contents, uid) {
  await writeFile(file, contents, { mode: 0o600 });
  await chmod(file, 0o600);
  await chown(file, uid, uid);
}

try {
  await writeOwnedFile(tokenTemporary, token, 10001);
  await writeOwnedFile(
    transitionTemporary,
    `${JSON.stringify(transitionConfig, null, 2)}\n`,
    1000,
  );
  await writeOwnedFile(finalTemporary, `${JSON.stringify(finalConfig, null, 2)}\n`, 1000);
  await writeOwnedFile(rollbackTemporary, `${JSON.stringify(agentsConfig, null, 2)}\n`, 1000);

  // During rotation the gateway temporarily accepts both token hashes. This keeps
  // the old token usable until the new token file has been installed atomically.
  await rename(transitionTemporary, agentsFile);
  try {
    await rename(tokenTemporary, tokenFile);
  } catch (tokenError) {
    try {
      await rename(rollbackTemporary, agentsFile);
    } catch (rollbackError) {
      throw new AggregateError(
        [tokenError, rollbackError],
        "token install failed; transition config still accepts the previous token",
      );
    }
    throw tokenError;
  }

  try {
    await rename(finalTemporary, agentsFile);
  } catch (error) {
    throw new Error(
      "new token is installed and remains valid in the transition config; rerun provisioning to finish cleanup",
      { cause: error },
    );
  }
} finally {
  await Promise.all(temporaryFiles.map((file) => rm(file, { force: true }).catch(() => {})));
}

process.stdout.write(`Provisioned ${agentId} (${role}); expires ${expiresAt}. Token value was not printed.\n`);
