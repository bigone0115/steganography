@echo off
rem Rewrites HostFolder in sandbox.wsb to this folder's path, then launches it. (see sandbox.wsb comment)
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$d='%~dp0'.TrimEnd('\'); $w=Join-Path $d 'sandbox.wsb';" ^
  "(Get-Content -Raw -Encoding UTF8 $w) -replace '<HostFolder>.*?</HostFolder>', ('<HostFolder>'+$d.Replace('$','$$')+'</HostFolder>') | Set-Content -Encoding UTF8 -NoNewline $w;" ^
  "Start-Process $w"
