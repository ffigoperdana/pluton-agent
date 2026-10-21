#!/usr/bin/env bash
set -Eeuo pipefail
[[ -f /opt/pluton-disposable-ubuntu-test && $EUID == 0 && ${PLUTON_DISPOSABLE_INSTALL_TEST:-} == 1 ]] || exit 90
tools=/opt/pluton-phase5-tools
mkdir -p "$tools/bin" "$tools/hooks" "$tools/mysql-only" /usr/lib/postgresql/17/bin
fixtures=agent/test-fixtures/phase5
for binary in mysqldump mariadb-dump pg_dump; do cp "$fixtures/database-client.mjs" "$tools/bin/$binary"; done
cp "$fixtures/database-client.mjs" /usr/lib/postgresql/17/bin/pg_dump
cp "$fixtures/database-client.mjs" "$tools/mysql-only/mariadb-dump"
cp "$fixtures/restic.mjs" "$tools/bin/restic"
cp "$fixtures/rclone.mjs" "$tools/bin/rclone"
for name in prepare cleanup fail slow noisy dirty child not-executable writable setuid; do cp "$fixtures/hook.mjs" "$tools/hooks/$name"; done
chown -R root:root "$tools" /usr/lib/postgresql/17
chmod -R a+rX,u+w,go-w "$tools" /usr/lib/postgresql
chmod 0755 "$tools/bin/"* "$tools/hooks/"* "$tools/mysql-only/"* /usr/lib/postgresql/17/bin/pg_dump
chmod 0644 "$tools/hooks/not-executable"
chmod 0775 "$tools/hooks/writable"
chmod 4755 "$tools/hooks/setuid"
ln -s "$tools/hooks/prepare" "$tools/hooks/link"
