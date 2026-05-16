param(
    [string]$BaseUrl = "http://127.0.0.1:8080",
    [string]$Out = "recon-output",
    [string]$Config = "config.example.json",
    [switch]$Dynamic,
    [switch]$InstallPlaywright,
    [switch]$NoStatic
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

$PythonBin = "python"
if (Test-Path ".\.venv\Scripts\python.exe") {
    $PythonBin = ".\.venv\Scripts\python.exe"
} else {
    Write-Host "[*] Creating virtualenv .venv"
    try {
        python -m venv .venv
        if (Test-Path ".\.venv\Scripts\python.exe") {
            $PythonBin = ".\.venv\Scripts\python.exe"
        }
    } catch {
        Write-Host "[!] Could not create .venv; falling back to system python"
        $PythonBin = "python"
    }
}

if ($InstallPlaywright) {
    Write-Host "[*] Installing optional Playwright dependency"
    & $PythonBin -m pip install --upgrade pip
    & $PythonBin -m pip install -r requirements.txt
    & $PythonBin -m playwright install chromium
}

$cmd = @("-B", "-m", "recontool", "-c", $Config, "--base-url", $BaseUrl, "--out", $Out)

if ($Dynamic) {
    $cmd += "--dynamic"
}

if ($NoStatic) {
    $cmd += "--no-static"
}

Write-Host "[*] Running: $PythonBin $($cmd -join ' ')"
& $PythonBin @cmd

Write-Host ""
Write-Host "[+] Done"
Write-Host "[+] JSON:     $Out/inventory.json"
Write-Host "[+] Markdown: $Out/inventory.md"
Write-Host "[+] Params:   $Out/params.txt"
