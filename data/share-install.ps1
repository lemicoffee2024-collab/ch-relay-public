# Points Codex at __BASE__ using your own ChatGPT login. Undo: irm "__BASE__/uninstall.ps1__KQ__" | iex
& {
  $ErrorActionPreference = 'Stop'
  try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}
  $Base = '__BASE__'
  $Marker = '__MARKER__'
  $Off = '__OFF__'
  $CodexHome = if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $HOME '.codex' }
  $AuthPath = Join-Path $CodexHome 'auth.json'
  $CfgPath = Join-Path $CodexHome 'config.toml'
  $CatPath = Join-Path $CodexHome 'code-hole-remote-catalog.json'
  $Utf8 = New-Object System.Text.UTF8Encoding $false

  if (-not (Test-Path $AuthPath)) {
    Write-Host 'Chưa thấy đăng nhập Codex. Chạy "codex login", chọn "Sign in with ChatGPT", rồi chạy lại lệnh này.' -ForegroundColor Red
    return
  }
  $auth = [IO.File]::ReadAllText($AuthPath) | ConvertFrom-Json
  $tok = $null
  if ($auth.tokens) { $tok = $auth.tokens.access_token }
  if (-not $tok) {
    Write-Host 'Codex đang đăng nhập bằng API key. Chạy "codex login" và chọn "Sign in with ChatGPT".' -ForegroundColor Red
    return
  }

  try {
    $res = Invoke-WebRequest -UseBasicParsing -Uri "$Base/client/catalog__KQ__" -Headers @{ Authorization = "Bearer $tok" }
  } catch {
    $code = 0
    if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
    if ($code -eq 403) {
      Write-Host 'License key không hợp lệ, hoặc tài khoản ChatGPT này chưa được cấp quyền. Kiểm tra lại key / liên hệ người bán.' -ForegroundColor Red
    } elseif ($code -eq 401) {
      Write-Host 'Phiên đăng nhập Codex đã hết hạn. Mở Codex dùng thử một lần rồi chạy lại lệnh này.' -ForegroundColor Red
    } else {
      Write-Host "Không kết nối được máy chủ ($Base): $($_.Exception.Message)" -ForegroundColor Red
    }
    return
  }
  $defaultModel = @($res.Headers['X-Default-Model'])[0]

  New-Item -ItemType Directory -Force -Path $CodexHome | Out-Null
  [IO.File]::WriteAllText($CatPath, [string]$res.Content, $Utf8)

  $raw = ''
  if (Test-Path $CfgPath) {
    $raw = [IO.File]::ReadAllText($CfgPath)
    Copy-Item $CfgPath ($CfgPath + '.bak-remote-' + (Get-Date -Format 'yyyyMMddHHmmss'))
  }
  $crlf = $raw.Contains("`r`n")
  $lines = ($raw -replace "`r`n", "`n") -split "`n"

  # Drop our previous lines (marker + the line under it).
  $kept = New-Object System.Collections.Generic.List[string]
  for ($i = 0; $i -lt $lines.Length; $i++) {
    if ($lines[$i].Trim() -eq $Marker) { $i++; continue }
    $kept.Add($lines[$i])
  }

  # Root keys we take over are commented out (restored by uninstall), not deleted.
  $rootEnd = $kept.Count
  for ($i = 0; $i -lt $kept.Count; $i++) { if ($kept[$i] -match '^\s*\[') { $rootEnd = $i; break } }
  $owned = @('openai_base_url', 'model_catalog_json', 'model', 'model_provider')
  for ($i = 0; $i -lt $rootEnd; $i++) {
    $key = ($kept[$i] -split '=', 2)[0].Trim()
    if ($owned -contains $key) { $kept[$i] = $Off + $kept[$i] }
  }

  $catToml = $CatPath -replace '\\', '/'
  $managed = @($Marker, "openai_base_url = `"$Base/v1`"", $Marker, "model_catalog_json = `"$catToml`"")
  if ($defaultModel) { $managed += @($Marker, "model = `"$defaultModel`"") }
  $text = (@($managed) + @($kept)) -join "`n"
  if ($crlf) { $text = $text -replace "`n", "`r`n" }
  [IO.File]::WriteAllText($CfgPath, $text, $Utf8)

  Write-Host 'Xong! Mở lại Codex, model mặc định là GPT-6 Astra.' -ForegroundColor Green
  Write-Host "Gỡ cài đặt: irm `"$Base/uninstall.ps1__KQ__`" | iex"
}
