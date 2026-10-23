import crypto from "node:crypto";
import { AgentOperationError } from "./errors.js";
import { AgentTransport } from "./transport.js";
import { AgentNetworkError } from "./network.js";
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

  constructor(
    private readonly config: AgentConfig,
    private readonly identity?: StoredAgentIdentity,
  ) {
    this.transport = new AgentTransport(config);
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
        ...(databaseId ? { databaseId, engine } : {}),
        ...(result ? { result } : {}),
        ...(cancelled ? { cancelled: true } : {}),
      },
      "void",
    );
  }

  async commandStatus(
    commandId: string,
    leaseToken: string,
  ): Promise<{ cancelled: boolean }> {
    const result = resultObject(await this.postSigned(
      `/api/agent/commands/${encodeURIComponent(commandId)}/status`,
      { leaseToken },
      "result",
    ));
    if (typeof result.cancelled !== "boolean") throw new AgentNetworkError("INVALID_RESPONSE");
    return { cancelled: result.cancelled };
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
    }), "REQUEST_REJECTED");
    // ACK/events/complete are void; heartbeat/poll/status require structured data.
    // No retry here: a rejected/ambiguous response may already have been applied.
    if (contract === "void") return;
    return resultObject(response.result);
  }
}
