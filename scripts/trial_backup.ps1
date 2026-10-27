param(
    [switch]$WritersPaused
)

$ErrorActionPreference = 'Stop'
if (-not $WritersPaused) {
    throw 'Stop web, worker, and beat for a consistent database + artifact backup, then pass -WritersPaused.'
}
$running = @(docker compose -f compose.yaml -f compose.trial.yaml ps --status running --services)
if ($LASTEXITCODE -ne 0) { throw 'Docker Compose status failed.' }
if ($running | Where-Object { $_ -in @('web', 'worker', 'beat') }) {
    throw 'A writer is still running. Stop web, worker, and beat before backup.'
}
if ($running -notcontains 'db') { throw 'The database must be running.' }

$backupDirectory = Join-Path $PSScriptRoot '..\trial_backups'
New-Item -ItemType Directory -Force -Path $backupDirectory | Out-Null
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$databaseName = "$stamp-db.dump"
$artifactsName = "$stamp-artifacts.tar.gz"

docker compose -f compose.yaml -f compose.trial.yaml exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc --file="/backups/$1"' sh $databaseName
if ($LASTEXITCODE -ne 0) { throw 'Database dump failed.' }
docker compose -f compose.yaml -f compose.trial.yaml --profile backup run --rm --no-deps backup sh -c 'tar -C /source -czf "/backups/$1" .' sh $artifactsName
if ($LASTEXITCODE -ne 0) { throw 'Artifact archive failed; discard this backup set.' }

$databasePath = Join-Path $backupDirectory $databaseName
$artifactsPath = Join-Path $backupDirectory $artifactsName
if ((Get-Item $databasePath).Length -eq 0 -or (Get-Item $artifactsPath).Length -eq 0) {
    throw 'A backup file is empty.'
}
$manifest = @(
    "$( (Get-FileHash -Algorithm SHA256 -Path $databasePath).Hash.ToLowerInvariant() )  $databaseName"
    "$( (Get-FileHash -Algorithm SHA256 -Path $artifactsPath).Hash.ToLowerInvariant() )  $artifactsName"
)
$manifest | Set-Content -Encoding ascii (Join-Path $backupDirectory "$stamp-sha256.txt")
Write-Output "Backup set $stamp created. Encrypt and copy it to access-controlled off-host storage."
