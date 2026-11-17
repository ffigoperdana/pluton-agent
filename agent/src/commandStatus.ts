/** Closed control-plane diagnostics. Never retain provider text or signed inputs. */
export type CommandStatusCode =
  | "command-lease-unavailable"
  | "command-authorization-rejected"
  | "control-plane-rate-limited"
  | "control-plane-unavailable"
  | "control-plane-timeout"
  | "control-plane-network-failed"
  | "control-plane-response-invalid"
  | "control-plane-unexpected";
export class CommandStatusError extends Error {
  constructor(readonly code: CommandStatusCode) {
    super(`Command status could not be established (${code}).`);
    this.name = "CommandStatusError";
  }
}

/** Outages of the server or the network path, not a refusal. While the lease the
 * server last granted is running, a backup may outlive them; it never outlives
 * the lease itself. */
export const TRANSIENT_COMMAND_STATUS_CODES: ReadonlySet<CommandStatusCode> =
  new Set<CommandStatusCode>([
    "control-plane-rate-limited",
    "control-plane-unavailable",
    "control-plane-timeout",
    "control-plane-network-failed",
  ]);

/**
 * The cancellation check of a running command. A transient status failure does
 * not stop the work while the lease the server last granted is still running;
 * a refusal, a lost lease or an ended lease does, exactly as before. Logs one
 * line when the outage starts and one when the server answers again.
 */
export function leaseBoundCancellationCheck(input: {
  status: () => Promise<{ cancelled: boolean }>;
  leaseDeadline: () => number | undefined;
  aborted: () => boolean;
  now?: () => number;
  log?: Pick<Console, "info" | "warn">;
}): () => Promise<boolean> {
  const now = input.now || Date.now;
  const log = input.log || console;
  let outage: CommandStatusCode | undefined;
  return async () => {
    if (input.aborted()) return true;
    try {
      const status = await input.status();
      if (outage) {
        log.info(
          "[pluton-agent] control plane answered again; command continues.",
        );
        outage = undefined;
      }
      return input.aborted() || status.cancelled;
    } catch (error) {
      const lease = input.leaseDeadline();
      if (
        !(error instanceof CommandStatusError) ||
        !TRANSIENT_COMMAND_STATUS_CODES.has(error.code) ||
        lease === undefined ||
        lease <= now()
      )
        throw error;
      if (!outage)
        log.warn(
          `[pluton-agent] control plane unavailable (${error.code}); command continues until its lease ends at ${new Date(lease).toISOString()}.`,
        );
      outage = error.code;
      return input.aborted();
    }
  };
}
