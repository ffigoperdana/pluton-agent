import type { SourceDiagnostics } from "./sourceDiagnostics.js";
import crypto from "node:crypto";
import { AgentOperationError } from "./errors.js";
import { AgentTransport, AgentHttpError } from "./transport.js";
import { AgentNetworkError } from "./network.js";
import { CommandStatusError, type CommandStatusCode } from "./commandStatus.js";
import { signRequest, verifyCommandDetailed } from "./protocol.js";
import type {
  AgentCommandEnvelope,
  AgentConfig,
  AgentInventory,
  StoredAgentIdentity,
} from "./types.js";

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function success(value: unknown, rejection: "REQUEST_REJECTED" | "ENROLLMENT_REJECTED"): Record<string, unknown> {
  if (!object(value) || typeof value.success !== "boolean") throw new AgentNetworkError("INVALID_RESPONSE");
  if (!value.success) throw new AgentNetworkError(rejection);
  return value;
}

function resultObject(value: unknown): Record<string, unknown> {
  if (!object(value)) throw new AgentNetworkError("INVALID_RESPONSE");
  return value;
}

function commandEnvelope(value: unknown): value is AgentCommandEnvelope {
  if (!object(value) || !object(value.payload)) return false;
  for (const field of ["id", "type", "idempotencyKey", "leaseToken", "signatureTimestamp", "signature"]) {
    if (typeof value[field] !== "string" || !value[field] || value[field].length > 4096) return false;
  }
  return typeof value.leaseExpiresAt === "string" && Number.isFinite(Date.parse(value.leaseExpiresAt)) &&
    /^[A-Za-z0-9_-]{32,128}$/.test(value.leaseToken as string) &&
    /^\d+$/.test(value.signatureTimestamp as string);
}

export class AgentClient {
  private readonly transport: AgentTransport;
  private readonly statusInFlight = new Map<string, Promise<{ cancelled: boolean }>>();
  private readonly leaseDeadlines = new Map<string, number>();

  constructor(
    private readonly config: AgentConfig,
    private readonly identity?: StoredAgentIdentity,
    transport?: AgentTransport,
  ) {
    this.transport = transport || new AgentTransport(config);
  }

  async enroll(
    token: string,
    inventory: AgentInventory,
  ): Promise<{
    deviceId: string;
    agentId: string;
    secret: string;
    pollIntervalSeconds: number;
  }> {
    const result = await this.postUnsigned<{
      deviceId: string; agentId: string; secret: string; pollIntervalSeconds: number;
    }>("/api/agent/enroll", { token, inventory });
    if (!result || typeof result.deviceId !== "string" || !result.deviceId || result.deviceId.length > 1024 ||
        typeof result.agentId !== "string" || !result.agentId || result.agentId.length > 1024 ||
        typeof result.secret !== "string" || !result.secret || result.secret.length > 4096 ||
        !Number.isInteger(result.pollIntervalSeconds) || result.pollIntervalSeconds < 1) {
      throw new AgentNetworkError("INVALID_RESPONSE");
    }
    return result;
  }

  async heartbeat(inventory: AgentInventory): Promise<void> {
    resultObject(await this.postSigned("/api/agent/heartbeat", inventory, "result"));
  }

  async poll(): Promise<AgentCommandEnvelope | null> {
    const result = resultObject(await this.postSigned("/api/agent/poll", {}, "result"));
    if (result.command === null) return null;
    if (!commandEnvelope(result.command)) throw new AgentNetworkError("INVALID_RESPONSE");
    if (!this.identity) {
      throw new AgentOperationError(
        "verify-command",
        "agent identity is unavailable",
      );
    }
    const verification = verifyCommandDetailed(
      this.identity.secret,
      result.command,
    );
    if (!verification.valid) {
      throw new AgentOperationError("verify-command", verification.reason);
    }
    this.leaseDeadlines.set(
      result.command.id + ":" + result.command.leaseToken,
      Date.parse(result.command.leaseExpiresAt!),
    );
    return result.command;
  }

  async acknowledge(commandId: string, leaseToken: string): Promise<void> {
    await this.postSigned(
      `/api/agent/commands/${encodeURIComponent(commandId)}/ack`,
      { leaseToken },
      "void",
    );
  }

  async event(
    commandId: string,
    leaseToken: string,
    sequence: number,
    event?: Record<string, unknown>,
  ): Promise<void> {
    await this.postSigned(
      `/api/agent/commands/${encodeURIComponent(commandId)}/events`,
      {
        leaseToken,
        sequence,
        ...(event ? { event } : {}),
      },
      "void",
    );
  }

  async complete(
    commandId: string,
    leaseToken: string,
    completion: {
      sequence: number;
      success: boolean;
      error?: string;
      failureStage?: string;
      failureCode?: string;
      sourceDiagnostics?: SourceDiagnostics;
      databaseId?: string;
      engine?: "mysql" | "mariadb" | "postgresql";
      result?: Record<string, unknown>;
      cancelled?: boolean;
    },
  ): Promise<void> {
    const {
      sequence,
      success,
      error,
      failureStage,
      failureCode,
      sourceDiagnostics,
      databaseId,
      engine,
      result,
      cancelled,
    } = completion;
    await this.postSigned(
      `/api/agent/commands/${encodeURIComponent(commandId)}/complete`,
      {
        leaseToken,
        sequence,
        success,
        ...(error ? { error } : {}),
        ...(failureStage ? { failureStage } : {}),
        ...(failureCode ? { failureCode } : {}),
        ...(sourceDiagnostics ? { sourceDiagnostics } : {}),
        ...(databaseId ? { databaseId, engine } : {}),
        ...(result ? { result } : {}),
        ...(cancelled ? { cancelled: true } : {}),
      },
      "void",
    );
  }

  commandStatus(
    commandId: string,
    leaseToken: string,
  ): Promise<{ cancelled: boolean }> {
    const key = commandId + ":" + leaseToken;
    const pending = this.statusInFlight.get(key);
    if (pending) return pending;
    const check = this.readCommandStatus(commandId, leaseToken, key).finally(() =>
      this.statusInFlight.delete(key),
    );
    this.statusInFlight.set(key, check);
    return check;
  }

  private async readCommandStatus(commandId: string, leaseToken: string, key: string): Promise<{ cancelled: boolean }> {
    // Only this authenticated, idempotent status operation retries. Enrollment,
    // poll, ACK, events and completion retain their standalone response contracts.
    const budget = Date.now() + 15_000;
    for (let attempt = 0; attempt < 3; attempt++) {
      const lease = this.leaseDeadlines.get(key);
      if (lease !== undefined && (!Number.isFinite(lease) || lease <= Date.now()))
        throw new CommandStatusError("command-lease-unavailable");
      const timeout = Math.min(5000, budget - Date.now(), (lease ?? Infinity) - Date.now());
      if (timeout <= 0) throw new CommandStatusError("control-plane-timeout");
      const started = Date.now();
      try {
        const result = resultObject(await this.postSigned(
          `/api/agent/commands/${encodeURIComponent(commandId)}/status`,
          { leaseToken }, "result", timeout,
        ));
        if (typeof result.cancelled !== "boolean")
          throw new CommandStatusError("control-plane-response-invalid");
        const expires = result.leaseExpiresAt;
        if (expires !== undefined && (typeof expires !== "string" || !Number.isFinite(Date.parse(expires))))
          throw new CommandStatusError("control-plane-response-invalid");
        if (!result.cancelled && expires !== undefined && Date.parse(expires as string) <= Date.now())
          throw new CommandStatusError("command-lease-unavailable");
        // Legacy boolean-only servers renew for 60s at SQLite second precision.
        // Request start is the conservative lower bound, never response arrival.
        this.leaseDeadlines.set(key, expires !== undefined
          ? Date.parse(expires as string) : Math.floor(started / 1000) * 1000 + 60_000);
        return { cancelled: result.cancelled };
      } catch (error) {
        const code = commandStatusCode(error);
        if (attempt === 2 || ![
          "control-plane-rate-limited", "control-plane-unavailable",
          "control-plane-timeout", "control-plane-network-failed",
        ].includes(code)) throw new CommandStatusError(code);
        const delay = attempt === 0 ? 250 : 750;
        if (Date.now() + delay >= Math.min(budget, lease ?? Infinity))
          throw new CommandStatusError(code);
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }
    throw new CommandStatusError("control-plane-unexpected");
  }

  private async postUnsigned<T>(
    pathname: string,
    body: Record<string, unknown>,
  ): Promise<T> {
    const raw = JSON.stringify(body);
    const response = success(await this.transport.post<unknown>(pathname, raw), "ENROLLMENT_REJECTED");
    return resultObject(response.result) as T;
  }

  private async postSigned(
    pathname: string,
    body: Record<string, unknown>,
    contract: "void" | "result",
    timeoutMs?: number,
  ): Promise<unknown> {
    if (!this.identity)
      throw new Error("Agent identity is required. Enroll this agent first.");
    const raw = JSON.stringify(body);
    const timestamp = Date.now().toString();
    const nonce = crypto.randomBytes(24).toString("base64url");
    const signature = signRequest(
      this.identity.secret,
      timestamp,
      nonce,
      "POST",
      pathname,
      raw,
    );
    const response = success(await this.transport.post<unknown>(pathname, raw, {
      "x-pluton-agent-id": this.identity.agentId,
      "x-pluton-agent-timestamp": timestamp,
      "x-pluton-agent-nonce": nonce,
      "x-pluton-agent-signature": signature,
    }, timeoutMs), "REQUEST_REJECTED");
    // ACK/events/complete are void; heartbeat/poll/status require structured data.
    // No retry here: a rejected/ambiguous response may already have been applied.
    if (contract === "void") return;
    return resultObject(response.result);
  }
}

/** Keep standalone network/TLS categories intact; translate only at status checks. */
function commandStatusCode(error: unknown): CommandStatusCode {
  if (error instanceof CommandStatusError) return error.code;
  if (error instanceof AgentHttpError) {
    if (error.statusCode === 429) return "control-plane-rate-limited";
    if (error.statusCode >= 500 && error.statusCode <= 599) return "control-plane-unavailable";
    if ([401, 403].includes(error.statusCode)) return "command-authorization-rejected";
    if ([404, 409, 410].includes(error.statusCode)) return "command-lease-unavailable";
    return "control-plane-response-invalid";
  }
  if (error instanceof AgentNetworkError) {
    switch (error.code) {
      case "REQUEST_TIMEOUT": case "DNS_TIMEOUT": case "CONNECT_TIMEOUT":
        return "control-plane-timeout";
      case "DNS_FAILURE": case "CONNECT_FAILURE": case "CONNECTION_INTERRUPTED":
        return "control-plane-network-failed";
      case "TLS_VERIFICATION_FAILED": case "REQUEST_REJECTED": case "ENROLLMENT_REJECTED":
        return "command-authorization-rejected";
      case "INVALID_RESPONSE": case "RESPONSE_TOO_LARGE":
        return "control-plane-response-invalid";
    }
  }
  return "control-plane-unexpected";
}
