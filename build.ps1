<#
.SYNOPSIS
    Builds deep-defense.exe.

.DESCRIPTION
    The project targets x86_64-pc-windows-gnu, which needs two things on PATH
    that a bare rustup install does not put there:

      * dlltool.exe - ships inside the toolchain, under
        <sysroot>/lib/rustlib/x86_64-pc-windows-gnu/bin/self-contained
      * as.exe      - the GNU assembler dlltool shells out to. It is NOT part
                      of rustup; it comes from MinGW-w64.

    This script locates both and runs cargo with them in scope, so you do not
    have to touch your global PATH.

.PARAMETER Dev
    Build the unoptimised profile (fast to compile, keeps a console window).
    Not named -Debug: CmdletBinding already reserves that as a common parameter.

.PARAMETER Test
    Run the test suite instead of building.
#>
[CmdletBinding()]
param(
    [switch]$Dev,
    [switch]$Test
)

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

# --- cargo -----------------------------------------------------------------
$cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
if (Test-Path (Join-Path $cargoBin 'cargo.exe')) {
    $env:PATH = "$cargoBin;$env:PATH"
}
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Error @'
cargo was not found.

Install the Rust toolchain first:
  1. Download https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-gnu/rustup-init.exe
  2. Run: .\rustup-init.exe -y --default-host x86_64-pc-windows-gnu --profile minimal
No administrator rights are needed; it installs into your user profile.
'@
}

# --- dlltool (ships with the toolchain) ------------------------------------
$sysroot = (& rustc --print sysroot).Trim()
$selfContained = Join-Path $sysroot 'lib\rustlib\x86_64-pc-windows-gnu\bin\self-contained'
if (Test-Path (Join-Path $selfContained 'dlltool.exe')) {
    $env:PATH = "$selfContained;$env:PATH"
}

# --- MinGW-w64 (provides as.exe) -------------------------------------------
$mingwCandidates = @(
    (Join-Path $env:USERPROFILE '.mingw-toolchain\mingw64\bin'),
    'C:\mingw64\bin',
    'C:\msys64\mingw64\bin'
)
$mingw = $mingwCandidates | Where-Object { Test-Path (Join-Path $_ 'as.exe') } | Select-Object -First 1

if ($mingw) {
    $env:PATH = "$mingw;$env:PATH"
} elseif (-not (Get-Command as -ErrorAction SilentlyContinue)) {
    Write-Error @'
The GNU assembler (as.exe) was not found, and the build will fail without it.

Get a portable MinGW-w64 (no installer, no administrator rights):
  1. Download the x86_64 UCRT zip from
     https://github.com/brechtsanders/winlibs_mingw/releases
  2. Extract it so that this path exists:
     %USERPROFILE%\.mingw-toolchain\mingw64\bin\as.exe
  3. Re-run this script.
'@
}

# --- go --------------------------------------------------------------------
if ($Test) {
    & cargo test
    exit $LASTEXITCODE
}

# Spelled out rather than splatted: in Windows PowerShell 5.1, `@array`
# splatting into a native executable mangles the arguments.
if ($Dev) {
    & cargo build
} else {
    & cargo build --release
}
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$outDir = if ($Dev) { 'debug' } else { 'release' }
$exe = Join-Path $PSScriptRoot "target\$outDir\deep-defense.exe"
if (Test-Path $exe) {
    $sizeMb = [math]::Round((Get-Item $exe).Length / 1MB, 1)
    Write-Host ''
    Write-Host "Built: $exe  ($sizeMb MB)" -ForegroundColor Green
    Write-Host 'It is a single self-contained file - copy it anywhere.'

    # A swapped executable is the end of everything this program protects: it
    # would simply read the password as it is typed. There is no signing
    # certificate here, so the next best thing is a fingerprint recorded at
    # build time, which turns "is this the file I built?" into a question with
    # an answer.
    $hash = (Get-FileHash -Algorithm SHA256 $exe).Hash.ToLower()
    $sums = Join-Path $PSScriptRoot 'SHA256SUMS.txt'
    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    @(
        "# Deep Defense - fingerprint of the built executable",
        "# Written by build.ps1 on $stamp",
        "#",
        "# Check it before running a copy you did not build yourself:",
        "#   (Get-FileHash -Algorithm SHA256 .\deep-defense.exe).Hash",
        "# and compare with the line below, ignoring case.",
        "",
        "$hash  deep-defense.exe"
    ) | Out-File -FilePath $sums -Encoding utf8

    Write-Host ''
    Write-Host "SHA-256: $hash" -ForegroundColor Cyan
    Write-Host "Recorded in $sums"
}
