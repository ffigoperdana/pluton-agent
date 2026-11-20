#!/usr/bin/env node
import {
  configFromEnvironment,
  createAgentConfig,
  parseBoolean,
} from "./config.js";
import { AgentClient } from "./client.js";
import { readEnrollmentToken } from "./enrollmentToken.js";
import { atAgentStage, formatAgentFailure } from "./errors.js";
import { lockEnrollment, saveEnrollmentIdentity } from "./identity.js";
import { collectInventory } from "./inventory.js";
import {
  preflightSource,
  resolveAllowedRoots,
  safeSourceDiagnosticPath,
  SourceAccessError,
} from "./filesystemPolicy.js";
import { checkConnection, run, runOnce } from "./runtime.js";
import { UPGRADE_PROTOCOL } from "./upgradeGuard.js";
import { lstat } from "node:fs/promises";
import { loadIdentity } from "./identity.js";
import { networkPreflight } from "./networkPreflight.js";
import {
  SourceAccessPolicy,
  readSourceAccessEnvironment,
} from "./sourceAccessPolicy.js";
import {
  RestorePolicyError,
  changeRestoreRoots,
  knownSourceRoots,
  restoreAccessReport,
} from "./restorePolicy.js";
import type { AgentConfig } from "./types.js";

function readOption(args: string[], name: string): string | undefined {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
}

function configFromArgs(args: string[]) {
  const envConfig = process.env;
  const allowInsecureHttp =
    args.includes("--allow-insecure-http") ||
    parseBoolean(envConfig.PLUTON_AGENT_ALLOW_INSECURE_HTTP) ||
    parseBoolean(envConfig.ALLOW_INSECURE_HTTP);
  return createAgentConfig({
    serverUrl: readOption(args, "--server") || envConfig.PLUTON_SERVER_URL,
    dataDir: readOption(args, "--data-dir") || envConfig.PLUTON_AGENT_DATA_DIR,
    allowedRoots:
      readOption(args, "--allowed-roots") ||
      envConfig.PLUTON_AGENT_ALLOWED_ROOTS,
    binDir: readOption(args, "--bin-dir") || envConfig.PLUTON_AGENT_BIN_DIR,
    allowInsecureHttp,
    caFile: readOption(args, "--ca-file") || envConfig.PLUTON_AGENT_CA_FILE,
    clientCertFile: envConfig.PLUTON_AGENT_CLIENT_CERT_FILE,
    clientKeyFile: envConfig.PLUTON_AGENT_CLIENT_KEY_FILE,
    hookRoot: envConfig.PLUTON_AGENT_HOOK_ROOT,
    databaseBinDirs: envConfig.PLUTON_AGENT_DATABASE_BIN_DIRS,
    sourcePolicyFile: envConfig.PLUTON_AGENT_SOURCE_POLICY_FILE,
    storageCaFile: envConfig.PLUTON_AGENT_STORAGE_CA_FILE,
  });
}

function usage(): void {
  console.log("       pluton-agent network-check --server <https://origin> [--ca-file <PEM>] (read-only unauthenticated health GET; no identity/token)");
  console.log(
    "Usage: pluton-agent enroll --server <url> (--token-stdin | --token <token>) [--data-dir <dir>]",
  );
  console.log(
    "       pluton-agent run [--once] [--server <url>] [--data-dir <dir>]",
  );
  console.log(
    "       pluton-agent check [--server <url>] [--data-dir <dir>] (heartbeat only; no command execution)",
  );
  console.log(
    "       pluton-agent preflight --source <absolute-path> --allowed-roots <comma-separated-paths> [--scan] [--exclude <relative-pattern> ...] (local, read-only; run as pluton-agent)",
  );
  console.log(
    "       pluton-agent source-access <approve|revoke|recover-selection|delegate|host-approved> --config-file /etc/pluton-agent.env --agent-id <id> --expected-host-policy-revision <sha256> [--root <canonical-directory> ... | --request-id <id>] [--confirm-drained] [--confirm-delegation] (explicit local host operator only)",
  );
  console.log(
    "       pluton-agent restore-roots <list|approve|revoke> --config-file /etc/pluton-agent.env --agent-id <id> [--root <existing 0700 directory owned by pluton-agent> ...] (explicit local host operator only)",
  );
}

/** Host administrator only: list, approve or revoke host-approved restore roots. */
async function restoreRootsCommand(args: string[]): Promise<void> {
  const [action, ...options] = args;
  if (!["list", "approve", "revoke"].includes(action))
    throw new Error("A narrow restore-roots operation is required.");
  const allowed = new Set(["--config-file", "--agent-id", "--root"]);
  for (let index = 0; index < options.length; index++) {
    if (
      !allowed.has(options[index]) ||
      !options[index + 1] ||
      options[index + 1].startsWith("--")
    )
      throw new Error("Invalid restore-roots options.");
    index++;
  }
  for (const name of ["--config-file", "--agent-id"])
    if (options.filter((value) => value === name).length > 1)
      throw new Error("Repeated restore-roots option.");
  const roots = options.flatMap((value, index) =>
    value === "--root" ? [options[index + 1]] : [],
  );
  if (action === "list" ? roots.length > 0 : roots.length === 0)
    throw new Error(
      action === "list"
        ? "Listing does not take --root."
        : "At least one --root is required.",
    );
  const localConfig = await readSourceAccessEnvironment(
    readOption(options, "--config-file") || "/etc/pluton-agent.env",
  );
  const identity = await loadIdentity(localConfig.dataDir);
  const agentId = readOption(options, "--agent-id") || "";
  if (agentId !== identity.agentId)
    throw new Error("Agent identity must match the enrolled Agent.");
  // This operation is local only; it never connects to this placeholder origin.
  const config = {
    ...localConfig,
    serverUrl: new URL("https://example.invalid"),
    allowInsecureHttp: false,
  } as AgentConfig;
  const uid = (await lstat(localConfig.dataDir)).uid;
  const sourceReport = await new SourceAccessPolicy({
    config,
    agentId,
    uid,
  }).report();
  const context = {
    config,
    agentId,
    uid,
    sourceRoots: knownSourceRoots(config, sourceReport),
  };
  if (action === "list") {
    console.log(JSON.stringify(await restoreAccessReport(context)));
    return;
  }
  if (sourceReport.policyError)
    throw new Error(
      `Source policy is unavailable (${sourceReport.policyError}); restore roots cannot be checked against source roots.`,
    );
  try {
    const result = await changeRestoreRoots(context, {
      action: action as "approve" | "revoke",
      roots,
    });
    console.log(
      JSON.stringify({
        ...result,
        advice:
          "Pluton sees the change at the next heartbeat. Restores create a new folder inside an approved root; files are owned by pluton-agent and are never moved, chowned or deleted by Pluton.",
      }),
    );
  } catch (error) {
    if (!(error instanceof RestorePolicyError)) throw error;
    console.error(
      JSON.stringify({
        code: error.code,
        advice:
          "Create the root first: install -d -o pluton-agent -g pluton-agent -m 0700 <path>, below root-owned directories, outside every source root and system tree. No permissions were changed.",
      }),
    );
    process.exitCode = 1;
  }
}

async function main(): Promise<void> {
  const [command, ...args] = process.argv.slice(2);
  if (command === "--upgrade-info" && !args.length) {
    console.log(JSON.stringify(UPGRADE_PROTOCOL));
    return;
  }
  if (!command || command === "--help" || command === "-h") {
    usage();
    return;
  }
  if (command === "source-access") {
    const [action, ...options] = args;
    if (
      ![
        "approve",
        "revoke",
        "recover-selection",
        "delegate",
        "host-approved",
      ].includes(action)
    )
      throw new Error("A narrow source-access operation is required.");
    const allowed = new Set([
      "--config-file",
      "--agent-id",
      "--expected-host-policy-revision",
      "--root",
      "--request-id",
      "--confirm-drained",
      "--confirm-delegation",
    ]);
    const booleanOptions = new Set([
      "--confirm-drained",
      "--confirm-delegation",
    ]);
    for (let index = 0; index < options.length; index++) {
      if (booleanOptions.has(options[index])) continue;
      if (
        !allowed.has(options[index]) ||
        !options[index + 1] ||
        options[index + 1].startsWith("--")
      )
        throw new Error("Invalid source-access options.");
      index++;
    }
    for (const name of [...allowed].filter((name) => name !== "--root"))
      if (options.filter((value) => value === name).length > 1)
        throw new Error("Repeated source-access option.");
    const configFile =
      readOption(options, "--config-file") || "/etc/pluton-agent.env";
    const localConfig = await readSourceAccessEnvironment(configFile);
    const identity = await loadIdentity(localConfig.dataDir);
    const agentId = readOption(options, "--agent-id") || "";
    const expectedRevision =
      readOption(options, "--expected-host-policy-revision") || "";
    if (
      agentId !== identity.agentId ||
      !/^[a-f0-9]{64}$/.test(expectedRevision)
    )
      throw new Error(
        "Agent identity and current source policy revision must match.",
      );
    const policy = new SourceAccessPolicy({
      // This operation is local only; it never connects to this placeholder origin.
      config: {
        ...localConfig,
        serverUrl: new URL("https://example.invalid"),
        allowInsecureHttp: false,
      },
      agentId,
      uid: (await lstat(localConfig.dataDir)).uid,
    });
    if (action === "delegate" || action === "host-approved") {
      const roots = options.flatMap((value, index) =>
        value === "--root" ? [options[index + 1]] : [],
      );
      const result = await policy.changeAuthorizationMode({
        agentId,
        expectedRevision,
        requestId: readOption(options, "--request-id") || "",
        authorizationMode:
          action === "delegate" ? "server-managed" : "host-approved",
        roots,
        secret: identity.secret,
        confirmDrained: options.includes("--confirm-drained"),
        confirmDelegation: options.includes("--confirm-delegation"),
      });
      console.log(
        JSON.stringify({
          ...result,
          selectionChanged: false,
          advice:
            "Host authority changed. Refresh Pluton and explicitly apply enabled directories. Delegation trusts Pluton administrators only within these prefixes; Linux permissions and private-directory exclusions remain enforced.",
        }),
      );
    } else if (action === "recover-selection") {
      if (options.includes("--root"))
        throw new Error("Recovery cannot change roots.");
      await policy.recoverSelection({
        agentId,
        expectedRevision,
        requestId: readOption(options, "--request-id") || "",
      });
      console.log(
        "Existing explicit source selection durability verified; no new selection was authorized.",
      );
    } else {
      if (options.includes("--request-id"))
        throw new Error("Host approval does not apply a server request.");
      const roots = options.flatMap((value, index) =>
        value === "--root" ? [options[index + 1]] : [],
      );
      const result = await policy.changeHostApproval({
        action: action as "approve" | "revoke",
        agentId,
        expectedRevision,
        roots,
      });
      console.log(
        JSON.stringify({
          ...result,
          selectionChanged: false,
          advice:
            "Refresh Source Access in Pluton, then explicitly enable the approved canonical roots. No identity or permissions were changed.",
        }),
      );
    }
    return;
  }
  if (command === "restore-roots") {
    await restoreRootsCommand(args);
    return;
  }
  if (command === "preflight") {
    const source = readOption(args, "--source") || "";
    const roots = (
      readOption(args, "--allowed-roots") ||
      process.env.PLUTON_AGENT_ALLOWED_ROOTS ||
      ""
    )
      .split(",")
      .filter(Boolean);
    try {
      const result = await preflightSource(source, roots, {
        scan: args.includes("--scan"),
        exclusions: args.flatMap((value, index) =>
          value === "--exclude" ? [args[index + 1]] : [],
        ),
      });
      console.log(
        JSON.stringify({
          ...result,
          requestedPath: safeSourceDiagnosticPath(result.requestedPath),
          resolvedPath: safeSourceDiagnosticPath(result.resolvedPath),
        }),
      );
    } catch (error) {
      if (!(error instanceof SourceAccessError))
        throw new Error("Source preflight could not complete.");
      console.error(
        JSON.stringify({
          code: error.code,
          requestedPath: safeSourceDiagnosticPath(error.requestedPath),
          resolvedPath: safeSourceDiagnosticPath(error.resolvedPath),
          blockedPath: safeSourceDiagnosticPath(error.blockedPath),
          advice:
            "Review read-only access and canonical allowed roots. No permissions were changed.",
        }),
      );
      process.exitCode = 1;
    }
    return;
  }
  const config = await atAgentStage("load-configuration", () =>
    args.length > 0 ? configFromArgs(args) : configFromEnvironment(),
  );
  if (command === "network-check") {
    for (let index = 0; index < args.length; index += 2) {
      if (!["--server", "--ca-file"].includes(args[index]) || !args[index + 1] || args[index + 1].startsWith("--"))
        throw new Error("Network preflight does not accept credentials or identity options.");
    }
    if (!(await networkPreflight(config))) process.exitCode = 1;
    return;
  }
  if (command === "enroll") {
    const release = await atAgentStage("load-identity", () => lockEnrollment(config.dataDir));
    try {
    const token = await atAgentStage("read-enrollment-token", () =>
      readEnrollmentToken(args),
    );
    const roots = await atAgentStage("resolve-allowed-roots", () =>
      resolveAllowedRoots(config.allowedRoots),
    );
    const client = new AgentClient(config);
    const result = await atAgentStage("enroll", () =>
      client.enroll(
        token,
        collectInventory({
          filesystemRootsConfigured: roots.length > 0,
          binDir: config.binDir,
          hookRoot: config.hookRoot,
          databaseBinDirs: config.databaseBinDirs,
        }),
      ),
    );
    await atAgentStage("save-identity", () =>
      saveEnrollmentIdentity(config.dataDir, { ...result, completedCommands: [] }),
    );
    console.log(`Agent enrolled successfully: ${result.agentId}`);
    } finally { await release(); }
    return;
  }
  if (command === "run") {
    if (args.includes("--once")) await runOnce(config);
    else await run(config);
    return;
  }
  if (command === "check") {
    await checkConnection(config);
    console.log(
      "Agent authenticated heartbeat succeeded; no command was polled or executed.",
    );
    return;
  }
  usage();
  throw new Error("Unknown command.");
}

main().catch((error) => {
  console.error(`[pluton-agent] ${formatAgentFailure(error)}`);
  process.exitCode = 1;
});
