#!/usr/bin/env node

import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";

const provider = process.argv[2];
const definitionFile = process.env.AGENT_MCP_DEFINITION ?? "/etc/buzz-agent/mcp-servers.json";
const home = process.env.HOME;
const codexHome = process.env.CODEX_HOME;
const gatewayEnabled = process.env.ENABLE_GITHUB_GATEWAY_MCP === "true";

if (!home) throw new Error("HOME is required");
if (provider !== "codex" && provider !== "claude") {
  throw new Error(`unsupported provider: ${provider ?? "<unset>"}`);
}

const definitions = JSON.parse(await readFile(definitionFile, "utf8"));
const selected = [definitions.kaneo];
if (gatewayEnabled) selected.push(definitions.github_gateway);

for (const definition of selected) {
  if (!definition || (definition.type !== "stdio" && definition.type !== "http")) {
    throw new Error("invalid MCP server definition");
  }
}

function requiredEnvironment(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function quote(value) {
  return JSON.stringify(value);
}

async function writePrivateJson(file, value) {
  await mkdir(path.dirname(file), { recursive: true });
  const temporary = `${file}.tmp`;
  await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  await chmod(temporary, 0o600);
  await rename(temporary, file);
}

async function generateCodexConfig() {
  if (!codexHome) throw new Error("CODEX_HOME is required for Codex");
  const file = path.join(codexHome, "config.toml");
  await mkdir(codexHome, { recursive: true });
  let current = "";
  try {
    current = await readFile(file, "utf8");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }

  const begin = "# BEGIN buzz-agent managed MCP servers";
  const end = "# END buzz-agent managed MCP servers";
  const managedPattern = new RegExp(`(?:^|\\n)${begin}\\n[\\s\\S]*?\\n${end}(?:\\n|$)`, "m");
  const unmanaged = current.replace(managedPattern, "\n").trimEnd();
  for (const name of ["kaneo", "github_gateway"]) {
    if (new RegExp(`^\\[mcp_servers\\.${name}\\]$`, "m").test(unmanaged)) {
      throw new Error(`unmanaged Codex MCP server conflicts with managed server: ${name}`);
    }
  }

  const lines = [begin];
  const kaneo = definitions.kaneo;
  lines.push(
    "[mcp_servers.kaneo]",
    `command = ${quote(kaneo.command)}`,
    `args = [${kaneo.args.map(quote).join(", ")}]`,
    "required = true",
    "",
    "[mcp_servers.kaneo.env]",
  );
  for (const environmentName of kaneo.env) {
    lines.push(`${environmentName} = ${quote(requiredEnvironment(environmentName))}`);
  }

  if (gatewayEnabled) {
    const gateway = definitions.github_gateway;
    lines.push(
      "",
      "[mcp_servers.github_gateway]",
      `url = ${quote(requiredEnvironment(gateway.urlEnv))}`,
      `bearer_token_env_var = ${quote(gateway.bearerTokenEnv)}`,
      "required = true",
      "startup_timeout_sec = 15",
    );
    requiredEnvironment(gateway.bearerTokenEnv);
  }
  lines.push(end);

  const output = `${unmanaged ? `${unmanaged}\n\n` : ""}${lines.join("\n")}\n`;
  const temporary = `${file}.tmp`;
  await writeFile(temporary, output, { mode: 0o600 });
  await chmod(temporary, 0o600);
  await rename(temporary, file);
}

async function generateClaudeConfig() {
  const file = path.join(home, ".claude.json");
  let config = {};
  try {
    config = JSON.parse(await readFile(file, "utf8"));
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  if (!config || typeof config !== "object" || Array.isArray(config)) {
    throw new Error("Claude user configuration must be a JSON object");
  }
  if (!config.mcpServers || typeof config.mcpServers !== "object" || Array.isArray(config.mcpServers)) {
    config.mcpServers = {};
  }

  const kaneo = definitions.kaneo;
  config.mcpServers.kaneo = {
    type: "stdio",
    command: kaneo.command,
    args: kaneo.args,
    env: Object.fromEntries(kaneo.env.map((name) => [name, requiredEnvironment(name)])),
  };

  if (gatewayEnabled) {
    const gateway = definitions.github_gateway;
    requiredEnvironment(gateway.bearerTokenEnv);
    config.mcpServers.github_gateway = {
      type: "http",
      url: requiredEnvironment(gateway.urlEnv),
      headers: {
        Authorization: `Bearer \${${gateway.bearerTokenEnv}}`,
      },
    };
  } else {
    delete config.mcpServers.github_gateway;
  }
  await writePrivateJson(file, config);
}

if (provider === "codex") await generateCodexConfig();
else await generateClaudeConfig();

process.stderr.write(
  `Generated native MCP configuration for ${provider}: kaneo${gatewayEnabled ? ", github_gateway" : ""}.\n`,
);
