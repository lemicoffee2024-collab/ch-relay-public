# Restores the Codex config changed by __BASE__/install.ps1.
& {
  $ErrorActionPreference = 'Stop'
  try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}
  $Marker = '__MARKER__'
  $Off = '__OFF__'
  $CodexHome = if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $HOME '.codex' }
  $CfgPath = Join-Path $CodexHome 'config.toml'
  $CatPath = Join-Path $CodexHome 'code-hole-remote-catalog.json'
  $Utf8 = New-Object System.Text.UTF8Encoding $false

  if (Test-Path $CfgPath) {
    $raw = [IO.File]::ReadAllText($CfgPath)
    $crlf = $raw.Contains("`r`n")
    $lines = ($raw -replace "`r`n", "`n") -split "`n"
    $kept = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $lines.Length; $i++) {
      if ($lines[$i].Trim() -eq $Marker) { $i++; continue }
      if ($lines[$i].StartsWith($Off)) { $kept.Add($lines[$i].Substring($Off.Length)); continue }
      $kept.Add($lines[$i])
    }
    $text = $kept -join "`n"
    if ($crlf) { $text = $text -replace "`n", "`r`n" }
    [IO.File]::WriteAllText($CfgPath, $text, $Utf8)
  }
  if (Test-Path $CatPath) { Remove-Item $CatPath -Force }
  Write-Host 'Đã gỡ. Codex trở lại cấu hình cũ.' -ForegroundColor Green
}
