$csc = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
& $csc /nologo /target:winexe /out:(Join-Path $here "healthmon.exe") (Join-Path $here "HealthMon.cs")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Output (Join-Path $here "healthmon.exe")
