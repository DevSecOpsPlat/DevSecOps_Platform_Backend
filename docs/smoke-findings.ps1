param(
  [Parameter(Mandatory = $true)]
  [string]$BaseUrl,

  [Parameter(Mandatory = $true)]
  [string]$JwtToken,

  [Parameter(Mandatory = $true)]
  [string]$AppId,

  [string]$Branch = "main"
)

$ErrorActionPreference = "Stop"

$headers = @{
  Authorization = "Bearer $JwtToken"
}

function Invoke-JsonGet {
  param(
    [Parameter(Mandatory = $true)][string]$Label,
    [Parameter(Mandatory = $true)][string]$Url
  )
  Write-Host ""
  Write-Host "=== $Label ===" -ForegroundColor Cyan
  Write-Host $Url -ForegroundColor DarkGray
  $resp = Invoke-RestMethod -Method GET -Uri $Url -Headers $headers
  $resp | ConvertTo-Json -Depth 12
}

$base = $BaseUrl.TrimEnd("/")

# 1) Stats locales (tables findings/finding_occurrences)
Invoke-JsonGet -Label "Local findings stats by application" `
  -Url "$base/api/findings/stats/by-application/$AppId?status=OPEN"

# 2) Liste locale des findings (fallback front)
Invoke-JsonGet -Label "Local findings list by application" `
  -Url "$base/api/findings/by-application/$AppId?page=0&size=10&branch=$Branch&status=OPEN"

# 3) Dashboard DefectDojo (scan only)
Invoke-JsonGet -Label "DefectDojo dashboard (scan only)" `
  -Url "$base/api/defectdojo/dashboard2?applicationId=$AppId&branch=$Branch&scanOnly=true"

# 4) Liste pipelines (doit contenir executionKind SCAN/DEPLOY)
$pipelines = Invoke-RestMethod -Method GET -Uri "$base/api/pipelines?page=0&size=20" -Headers $headers
Write-Host ""
Write-Host "=== Pipelines (top 20) ===" -ForegroundColor Cyan
$pipelines |
  Select-Object pipelineId, executionKind, gitBranch, environmentId, pipelineStatus, createdAt |
  Format-Table -AutoSize

$scanPipe = $pipelines | Where-Object { $_.executionKind -eq "SCAN" -and $_.pipelineId } | Select-Object -First 1
if ($null -ne $scanPipe) {
  $pid = $scanPipe.pipelineId
  Invoke-JsonGet -Label "DefectDojo dashboard filtered by pipelineId=$pid" `
    -Url "$base/api/defectdojo/dashboard2?applicationId=$AppId&branch=$Branch&pipelineId=$pid&scanOnly=true"
} else {
  Write-Host ""
  Write-Host "No SCAN pipeline found in /api/pipelines (run one scan first)." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Smoke test done." -ForegroundColor Green

