param(
    # A clean, separately reviewed Pluton Server checkout (read-only use).
    [Parameter(Mandatory = $true)][string]$MonorepoCheckout,
    # The exact monorepo commit whose installer produced the Agent to migrate.
    [Parameter(Mandatory = $true)][ValidatePattern('^[a-f0-9]{40}$')][string]$MonorepoCommit,
    [ValidateSet('22.04', '24.04')][string]$UbuntuVersion = '22.04'
)
# Disposable Ubuntu container only: no host mounts, ports, Docker socket or live Agent.
# Exports only the monorepo installer/Agent source paths at the pinned commit.
$ErrorActionPreference = 'Stop'
$repository = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$checkout = (Resolve-Path -LiteralPath $MonorepoCheckout).Path
& git -C $checkout cat-file -e "$MonorepoCommit^{commit}"
if ($LASTEXITCODE -ne 0) { throw 'The pinned monorepo commit is not available in that checkout.' }
& git -C $checkout cat-file -e "${MonorepoCommit}:installers/install-agent.sh"
if ($LASTEXITCODE -ne 0) { throw 'That commit has no monorepo Agent installer.' }
$id = [Guid]::NewGuid().ToString('N')
$snapshot = Join-Path $repository "tmp/monorepo-snapshot-$id"
$archive = Join-Path $repository "tmp/monorepo-snapshot-$id.tar"
$image = "pluton-agent-monorepo-migration:$id"
New-Item -ItemType Directory -Path $snapshot | Out-Null
try {
    & git -C $checkout archive --format=tar "--output=$archive" $MonorepoCommit package.json pnpm-lock.yaml pnpm-workspace.yaml agent installers
    if ($LASTEXITCODE -ne 0) { throw 'Monorepo source export failed.' }
    # Windows bsdtar: a Git-for-Windows tar on PATH treats "C:" as a remote host.
    $tar = if ($env:OS -eq 'Windows_NT') { Join-Path $env:SystemRoot 'System32\tar.exe' } else { 'tar' }
    & $tar -xf $archive -C $snapshot
    if ($LASTEXITCODE -ne 0) { throw 'Monorepo source extraction failed.' }
    & docker build --progress=plain --file (Join-Path $repository 'tests/ubuntu/Dockerfile') `
        --build-arg "UBUNTU_VERSION=$UbuntuVersion" --build-context "monorepo=$snapshot" `
        --target monorepo-migration --tag $image $repository
    if ($LASTEXITCODE -ne 0) { throw 'Disposable monorepo migration validation failed.' }
    Write-Output "PASS monorepo $MonorepoCommit -> standalone migration on Ubuntu $UbuntuVersion; see the systemd adapter limitation in test output."
} finally {
    if ($image -notmatch '^pluton-agent-monorepo-migration:[a-f0-9]{32}$') { throw 'Unsafe fixture identity.' }
    # `docker images -q` is empty (exit 0) when the build never produced the image.
    if (& docker images -q $image) { & docker image rm $image | Out-Null }
    Remove-Item -LiteralPath $archive -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $snapshot -Recurse -Force -ErrorAction SilentlyContinue
}
