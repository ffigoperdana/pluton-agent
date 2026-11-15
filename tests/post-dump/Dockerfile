# Native Linux test runner only; never an Agent deployment artifact.
ARG TOOL_IMAGE=pluton-agent-validation:ci-22.04
FROM ${TOOL_IMAGE} AS standalone-tools
# Disposable private CA and HTTPS S3 fixture certificate for this test image only.
# The CA key never leaves this stage. The runner receives the CA certificate
# root-owned (as the Agent requires for PLUTON_AGENT_STORAGE_CA_FILE) and the
# server pair owned by the unprivileged runner account.
FROM ${TOOL_IMAGE} AS fixture-tls
RUN set -eu; umask 022; mkdir /tmp/fixture-tls; cd /tmp/fixture-tls; \
    openssl req -x509 -newkey rsa:2048 -nodes -days 30 -keyout ca-key.pem -out ca.pem \
      -subj '/CN=Synthetic Pluton Agent Lab CA' \
      -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign'; \
    openssl req -newkey rsa:2048 -nodes -keyout server-key.pem -out server.csr -subj '/CN=s3.example.internal'; \
    printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature,keyEncipherment' \
      'extendedKeyUsage=serverAuth' 'subjectAltName=DNS:s3.example.internal,IP:127.0.0.1' > server.ext; \
    openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -set_serial 1 -days 30 -sha256 \
      -extfile server.ext -out server.pem; \
    openssl verify -CAfile ca.pem server.pem; \
    chmod 0644 ca.pem server.pem; chmod 0600 server-key.pem
FROM mysql@sha256:24989179f58856db763f418010c1169fecc944e3ec1ea7e921572d83eb070f70
COPY --from=standalone-tools /opt/pluton-agent/runtime /opt/test-node
COPY --from=standalone-tools /opt/pluton-agent/bin/restic /usr/local/bin/restic
COPY --from=standalone-tools /opt/pluton-agent/bin/rclone /usr/local/bin/rclone
COPY --from=standalone-tools /workspace/agent/dist /app/agent/dist
COPY --from=standalone-tools /workspace/agent/package.json /app/agent/package.json
# The Agent refuses a storage CA file that is not root-owned, so the lab CA stays root-owned.
COPY --from=fixture-tls --chown=0:0 /tmp/fixture-tls/ca.pem /app/fixture-tls/ca.pem
COPY --from=fixture-tls --chown=10001:10001 /tmp/fixture-tls/server.pem /tmp/fixture-tls/server-key.pem /app/fixture-tls-server/
COPY tests/post-dump /app/tests/post-dump
ENV PATH=/opt/test-node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
USER 10001:10001
ENTRYPOINT ["node", "--experimental-strip-types", "/app/tests/post-dump/native.lab.ts"]
