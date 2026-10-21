FROM ubuntu:22.04@sha256:0a9887931b0e38af2e3487ed39e29436b0535c4f3f52e57745baaf79d1898956 AS validation
LABEL io.pluton.test.scope="standalone-agent-ubuntu2204"
RUN apt-get update --error-on=any && apt-get install -y --no-install-recommends \
    ca-certificates curl git xz-utils bzip2 unzip locales python3 openssl systemd \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/* \
    && mkdir -p /opt/test-locales \
    && localedef --no-archive --inputfile en_US --charmap UTF-8 /opt/test-locales/en_US.UTF-8
ENV LOCPATH=/opt/test-locales PLUTON_REQUIRE_LOCALE_TESTS=1 PLUTON_DISPOSABLE_INSTALL_TEST=1
WORKDIR /workspace
COPY . .
RUN touch /opt/pluton-disposable-ubuntu-test && chmod 0600 /opt/pluton-disposable-ubuntu-test \
    && find . -name '*.sh' -type f -exec chmod 0755 {} + \
    && install -m 0755 tests/ubuntu/systemctl-fixture.sh /usr/local/bin/systemctl \
    && bash tests/ubuntu/fresh-install.sh && bash tests/ubuntu/legacy-refusal.sh /workspace
ENV PATH=/opt/pluton-agent/runtime/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
RUN ln -s /opt/pluton-agent/runtime/bin/node /usr/local/bin/node \
    && printf '#!/bin/sh\nexec /opt/pluton-agent/runtime/bin/node /opt/pluton-agent/runtime/lib/node_modules/corepack/dist/corepack.js pnpm "$@"\n' > /usr/local/bin/pnpm \
    && chmod 0755 /usr/local/bin/pnpm \
    && useradd -m -u 1000 tester \
    && bash tests/ubuntu/provision-phase5.sh \
    && git init && git config user.name 'Synthetic Test' && git config user.email 'test@example.invalid' \
    && git add -- . && git commit -m 'Synthetic isolated extraction test' \
    && mkdir -p /opt/test-corepack && chown tester:tester /opt/test-corepack \
    && chown -R tester:tester /workspace
ENV COREPACK_HOME=/opt/test-corepack COREPACK_ENABLE_DOWNLOAD_PROMPT=0
ENV PLUTON_PHASE5_TEST_TOOLS=/opt/pluton-phase5-tools PLUTON_EXCLUSIONS_RESTIC=/opt/pluton-agent/bin/restic
USER tester
RUN pnpm install --frozen-lockfile --ignore-scripts && pnpm typecheck && pnpm test && pnpm test:contracts \
    && pnpm test:installers && bash -n install-agent.sh upgrade-agent.sh installers/*.sh tests/ubuntu/*.sh \
    && pnpm package:release && cp release/release-manifest.json /tmp/first-release.json \
    && pnpm package:release && cmp release/release-manifest.json /tmp/first-release.json \
    && (cd release && sha256sum -c SHA256SUMS)
