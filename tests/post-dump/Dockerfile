# Native Linux test runner only; never an Agent deployment artifact.
ARG TOOL_IMAGE=pluton-agent-validation:ci-22.04
FROM ${TOOL_IMAGE} AS standalone-tools
FROM mysql@sha256:24989179f58856db763f418010c1169fecc944e3ec1ea7e921572d83eb070f70
COPY --from=standalone-tools /opt/pluton-agent/runtime /opt/test-node
COPY --from=standalone-tools /opt/pluton-agent/bin/restic /usr/local/bin/restic
COPY --from=standalone-tools /opt/pluton-agent/bin/rclone /usr/local/bin/rclone
COPY --from=standalone-tools /workspace/agent/dist /app/agent/dist
COPY --from=standalone-tools /workspace/agent/package.json /app/agent/package.json
COPY tests/post-dump /app/tests/post-dump
ENV PATH=/opt/test-node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
USER 10001:10001
ENTRYPOINT ["node", "--experimental-strip-types", "/app/tests/post-dump/native.lab.ts"]
