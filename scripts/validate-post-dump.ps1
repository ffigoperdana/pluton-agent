param(
    [string]$RuntimeImage = 'pluton-agent-post-dump-port:local',
    [string]$DatabaseImage = 'mysql@sha256:24989179f58856db763f418010c1169fecc944e3ec1ea7e921572d83eb070f70',
    [switch]$Baseline
)
# All state belongs to disposable containers. No host ports/volumes or live Agent.
$ErrorActionPreference = 'Stop'
$id = [Guid]::NewGuid().ToString('N')
$network = "pluton-agent-post-dump-$id"
$database = "$network-db"
$runner = "$network-runner"
$password = [Guid]::NewGuid().ToString('N')
try {
    docker network create --internal $network | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Disposable network unavailable.' }
    docker run -d --rm --name $database --network $network --memory 768m --memory-swap 768m --pids-limit 128 --tmpfs /var/lib/mysql:rw,nosuid,nodev,size=512m -e "MYSQL_ROOT_PASSWORD=$password" -e MYSQL_ROOT_HOST=% $DatabaseImage | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Disposable MySQL unavailable.' }
    $arguments = @('run', '--rm', '--init', '--name', $runner, '--network', "container:$database", '--read-only', '--user', '10001:10001', '--cpus', '2', '--memory', '3g', '--memory-swap', '3g', '--pids-limit', '192', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--tmpfs', '/tmp:rw,exec,nosuid,nodev,size=512m', '-e', "FIXTURE_MYSQL_PASSWORD=$password", $RuntimeImage)
    if ($Baseline) { $arguments += '--baseline' }
    & docker @arguments
    if ($LASTEXITCODE -ne 0) { throw 'Disposable native post-dump regression failed.' }
} finally {
    if ($runner -notmatch '^pluton-agent-post-dump-[a-f0-9]{32}-runner$' -or $database -ne "$network-db") { throw 'Unsafe fixture identity.' }
    docker rm -f $runner $database 2>$null | Out-Null
    docker network rm $network | Out-Null
}
