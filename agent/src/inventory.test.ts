import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  AGENT_VERSION,
  collectInventory,
  commandTypesForInventory,
} from "./inventory.js";

test("does not advertise BACKUP_FILESYSTEM when a private backup binary is unavailable", () => {
  assert.deepEqual(
    commandTypesForInventory({
      filesystemRootsConfigured: true,
      resticVersion: "restic 0.19.1 compiled with go1.25.1 on linux/amd64",
    }),
    ["PING", "INVENTORY_REFRESH"],
  );
});

test("advertises BACKUP_FILESYSTEM only with roots and both private tools", () => {
  assert.deepEqual(
    commandTypesForInventory({
      filesystemRootsConfigured: true,
      resticVersion: "restic 0.19.1 compiled with go1.25.1 on linux/amd64",
      rcloneVersion: "rclone v1.75.1",
    }),
    ["PING", "INVENTORY_REFRESH", "BACKUP_FILESYSTEM"],
  );
  assert.deepEqual(
    commandTypesForInventory({
      filesystemRootsConfigured: false,
      resticVersion: "restic 0.19.1",
      rcloneVersion: "rclone v1.75.1",
    }),
    ["PING", "INVENTORY_REFRESH"],
  );
});

test("advertises S3 repositories and backup payload version 5 as Agent 0.8.0", () => {
  const inventory = collectInventory({
    filesystemRootsConfigured: false,
    binDir: path.join(os.tmpdir(), "pluton-agent-absent-private-tools"),
  });
  assert.equal(AGENT_VERSION, "0.8.0");
  assert.equal(inventory.agentVersion, "0.8.0");
  assert.deepEqual(inventory.capabilities.repositoryBackends, ["sftp", "s3"]);
  assert.equal(inventory.capabilities.backupPayloadVersion, 5);
});
