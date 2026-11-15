import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import {
  COMMAND_SECRETS_LABEL,
  SealedSecretsError,
  commandSecretsAdditionalData,
  deriveCommandSecretsKey,
  openSealedCommandSecrets,
} from "./sealedSecrets.js";

/** S3 design section 10.4 test vector, verbatim. */
const vector = {
  secret: "synthetic-agent-secret-0123456789abcdef",
  commandId: "cmd-synthetic-01",
  leaseToken: "0123456789abcdef0123456789abcdef0123456789abcdef",
  derivedKeyHex:
    "1f35dc3e9cf013165a2353883369bbfa7edd62b56072b3413c8074e2ffb93fac",
  nonce: "AAECAwQFBgcICQoL",
  plaintext:
    '{"repositoryPassword":"synthetic-repository-password-01","rclone":{"access_key_id":"SYNTHETICKEY01","secret_access_key":"synthetic-secret-key-01"}}',
  ciphertext:
    "jh0qetVE17GJz08s3DXhomumBqDIVOhzX3A4LgVFJeiH9JSKr4qR7OowvN0duifn639ReyzbjXGWiSEWAaymlLJKNnxwbrP+vLmuRdk9vI+wuUG8cJhENnxGV0LXHElNyPLQME0jaSjTfM7T0n9LTBr7V76enQuphACHq53aFDwiyFLa5p/2ML2748FcdivP43U+",
  tag: "pUKJ+stiEzlyVi8BFN6biQ==",
};
const context = {
  secret: vector.secret,
  commandId: vector.commandId,
  leaseToken: vector.leaseToken,
};
const sealed = {
  alg: "A256GCM",
  kid: "pluton-agent-command-secrets-v1",
  nonce: vector.nonce,
  ciphertext: vector.ciphertext,
  tag: vector.tag,
};

function flipByte(value: string, index: number): string {
  const bytes = Buffer.from(value, "base64");
  bytes[index] ^= 0x01;
  return bytes.toString("base64");
}

function changeCharacter(value: string, index: number): string {
  return (
    value.slice(0, index) +
    (value[index] === "0" ? "1" : "0") +
    value.slice(index + 1)
  );
}

/** Independent sealer built only from node:crypto; the Agent itself only opens. */
function sealForTest(
  plaintext: string | Buffer,
  nonce: Buffer = Buffer.from(vector.nonce, "base64"),
) {
  const key = Buffer.from(
    crypto.hkdfSync(
      "sha256",
      Buffer.from(vector.secret, "utf8"),
      Buffer.alloc(0),
      Buffer.from("pluton-agent-command-secrets-v1", "utf8"),
      32,
    ),
  );
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce, {
    authTagLength: 16,
  });
  cipher.setAAD(
    Buffer.from(
      `pluton-agent-command-secrets-v1\n${vector.commandId}\n${vector.leaseToken}`,
      "utf8",
    ),
  );
  const ciphertext = Buffer.concat([
    cipher.update(
      typeof plaintext === "string" ? Buffer.from(plaintext, "utf8") : plaintext,
    ),
    cipher.final(),
  ]);
  return {
    alg: "A256GCM",
    kid: "pluton-agent-command-secrets-v1",
    nonce: nonce.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
  };
}

test("sealed: derives the 10.4 key with HKDF-SHA256 and the command-secrets label", () => {
  assert.equal(COMMAND_SECRETS_LABEL, "pluton-agent-command-secrets-v1");
  assert.equal(
    deriveCommandSecretsKey(vector.secret).toString("hex"),
    vector.derivedKeyHex,
  );
  assert.equal(
    commandSecretsAdditionalData(vector.commandId, vector.leaseToken).toString(
      "utf8",
    ),
    `pluton-agent-command-secrets-v1\n${vector.commandId}\n${vector.leaseToken}`,
  );
  // The command HMAC is keyed by the raw secret; the sealing key never equals it.
  assert.notEqual(
    deriveCommandSecretsKey(vector.secret).toString("hex"),
    Buffer.from(vector.secret, "utf8").toString("hex"),
  );
});

test("sealed: opens the 10.4 vector to the exact plaintext", () => {
  assert.deepEqual(
    openSealedCommandSecrets(sealed, context),
    JSON.parse(vector.plaintext),
  );
});

test("sealed: an independent sealer with the 10.4 inputs reproduces the vector ciphertext and tag", () => {
  const result = sealForTest(vector.plaintext);
  assert.equal(result.ciphertext, vector.ciphertext);
  assert.equal(result.tag, vector.tag);
});

test("sealed: changing any byte of ciphertext, tag or nonce, or any character of the command ID or lease token, refuses", () => {
  for (const field of ["ciphertext", "tag", "nonce"] as const) {
    const length = Buffer.from(sealed[field], "base64").length;
    for (let index = 0; index < length; index++)
      assert.throws(
        () =>
          openSealedCommandSecrets(
            { ...sealed, [field]: flipByte(sealed[field], index) },
            context,
          ),
        SealedSecretsError,
        `${field} byte ${index}`,
      );
  }
  for (const field of ["commandId", "leaseToken"] as const)
    for (let index = 0; index < context[field].length; index++)
      assert.throws(
        () =>
          openSealedCommandSecrets(sealed, {
            ...context,
            [field]: changeCharacter(context[field], index),
          }),
        SealedSecretsError,
        `${field} character ${index}`,
      );
  assert.throws(
    () =>
      openSealedCommandSecrets(sealed, {
        ...context,
        secret: "synthetic-agent-secret-0123456789abcdeF",
      }),
    SealedSecretsError,
  );
});

test("sealed: refuses envelope fields, algorithms, key IDs and non-canonical encodings outside the contract", () => {
  for (const candidate of [
    undefined,
    null,
    [],
    "sealed",
    { ...sealed, alg: "A128GCM" },
    { ...sealed, kid: "pluton-agent-command-secrets-v2" },
    { ...sealed, extra: true },
    {
      alg: sealed.alg,
      kid: sealed.kid,
      nonce: sealed.nonce,
      ciphertext: sealed.ciphertext,
    },
    { ...sealed, nonce: "AAECAwQFBgcICQo=" },
    { ...sealed, tag: "pUKJ+stiEzlyVi8BFN6b" },
    { ...sealed, nonce: "AAECAwQFBgcICQoL\n" },
    { ...sealed, ciphertext: sealed.ciphertext.replace(/\+/g, "-") },
    { ...sealed, ciphertext: "" },
  ])
    assert.throws(
      () => openSealedCommandSecrets(candidate, context),
      SealedSecretsError,
    );
  for (const bad of [
    { ...context, commandId: "" },
    { ...context, leaseToken: "lease\ninjected" },
    { ...context, secret: "" },
  ])
    assert.throws(
      () => openSealedCommandSecrets(sealed, bad),
      SealedSecretsError,
    );
});

test("sealed: refuses plaintext outside the closed secret shape", () => {
  for (const plaintext of [
    "not json",
    "[]",
    '{"repositoryPassword":"synthetic-repository-password-01"}',
    '{"repositoryPassword":"synthetic-repository-password-01","rclone":{},"extra":true}',
    '{"repositoryPassword":"synthetic-repository-password-01","rclone":{"session_token":"x"}}',
    '{"repositoryPassword":"synthetic-repository-password-01","rclone":{"pass":""}}',
    '{"repositoryPassword":"bad\\nvalue","rclone":{"pass":"synthetic"}}',
    '{"repositoryPassword":7,"rclone":{"pass":"synthetic"}}',
  ])
    assert.throws(
      () =>
        openSealedCommandSecrets(
          sealForTest(plaintext, crypto.randomBytes(12)),
          context,
        ),
      SealedSecretsError,
      plaintext,
    );
  assert.throws(
    () =>
      openSealedCommandSecrets(
        sealForTest(Buffer.from([0xff, 0xfe]), crypto.randomBytes(12)),
        context,
      ),
    SealedSecretsError,
  );
  assert.deepEqual(
    openSealedCommandSecrets(
      sealForTest(
        '{"repositoryPassword":"synthetic-repository-password-01","rclone":{"pass":"synthetic-sftp-password-01"}}',
        crypto.randomBytes(12),
      ),
      context,
    ),
    {
      repositoryPassword: "synthetic-repository-password-01",
      rclone: { pass: "synthetic-sftp-password-01" },
    },
  );
});

test("sealed: opens optional database passwords for both lifecycle shapes and refuses malformed ones", () => {
  const base = {
    repositoryPassword: "synthetic-repository-password-01",
    rclone: { pass: "synthetic-sftp-password-01" },
  };
  const open = (lifecycle: unknown) =>
    openSealedCommandSecrets(
      sealForTest(JSON.stringify({ ...base, lifecycle }), crypto.randomBytes(12)),
      context,
    );
  assert.deepEqual(open({ database: "synthetic-db-password-01" }).lifecycle, {
    database: "synthetic-db-password-01",
  });
  // MySQL/MariaDB passwords may contain tabs and newlines; only NUL is refused.
  assert.deepEqual(
    open({
      databases: {
        db_one: "synthetic-db-password-01",
        db_two: "synthetic-db\tpassword\n02",
      },
    }).lifecycle,
    {
      databases: {
        db_one: "synthetic-db-password-01",
        db_two: "synthetic-db\tpassword\n02",
      },
    },
  );
  assert.equal(
    openSealedCommandSecrets(sealed, context).lifecycle,
    undefined,
    "The 10.4 vector carries no lifecycle.",
  );
  for (const lifecycle of [
    {},
    "synthetic-db-password-01",
    [],
    { databases: {} },
    { databases: ["synthetic-db-password-01"] },
    { databases: { "not-a-database-id": "synthetic-db-password-01" } },
    { databases: { db_one: "" } },
    { databases: { db_one: 7 } },
    { database: "" },
    { database: "synthetic\u0000password" },
    { database: "x".repeat(1025) },
    { database: null },
    { password: "synthetic-db-password-01" },
    {
      databases: Object.fromEntries(
        Array.from({ length: 9 }, (_, index) => [
          `db_entry${index}`,
          "synthetic-db-password-01",
        ]),
      ),
    },
  ])
    assert.throws(
      () => open(lifecycle),
      SealedSecretsError,
      JSON.stringify(lifecycle),
    );
});
