Set-Location 'D:\Code\research\rv-maltrace'
$ErrorActionPreference = 'Continue'
$log = 'D:\Code\research\rv-maltrace\results\board\genesys2_trace_validation\20260608-1104-trace-export-packed104\00_trace_build\command.log'
'RVMT_COMMAND=uv run rvmt bitstream:build-trace' | Out-File -LiteralPath $log -Encoding utf8
'RVMT_STARTED=' + (Get-Date -Format o) | Add-Content -LiteralPath $log -Encoding utf8
& uv run rvmt bitstream:build-trace 2>&1 | ForEach-Object {
  $line = $_.ToString()
  Add-Content -LiteralPath $log -Value $line -Encoding utf8
}
$code = $LASTEXITCODE
'RVMT_COMMAND_EXIT=' + $code | Add-Content -LiteralPath $log -Encoding utf8
'RVMT_FINISHED=' + (Get-Date -Format o) | Add-Content -LiteralPath $log -Encoding utf8
$code | Out-File -LiteralPath 'D:\Code\research\rv-maltrace\results\board\genesys2_trace_validation\20260608-1104-trace-export-packed104\00_trace_build\command.exit' -Encoding ascii
exit $code
