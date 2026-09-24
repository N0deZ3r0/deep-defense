<#
.SYNOPSIS
    Prints the directory holding the GNU binutils this build needs.

.DESCRIPTION
    The project targets x86_64-pc-windows-gnu, and two separate things need
    tools rustup does not ship: the linker driver is gcc, and build.rs calls
    windres and ar directly to turn the icon into an object file.

    Where those live depends entirely on how MinGW arrived on the machine — a
    hand-placed portable toolchain, MSYS2, Chocolatey, or Strawberry Perl, which
    carries a complete one almost by accident. There is no single right answer,
    so this looks in all of them and demands the whole set from one directory:
    a gcc from one install and an ar from another is how a link fails with a
    message about a symbol nobody can explain.

    Prints the directory and exits 0, or prints nothing and exits 1. It exists
    so that build.ps1 and the CI workflows share one list instead of three that
    drift apart.
#>

$required = @('as.exe', 'ar.exe', 'windres.exe', 'gcc.exe')

$candidates = @(
    # Where this project's own README tells people to put a portable toolchain.
    (Join-Path $env:USERPROFILE '.mingw-toolchain\mingw64\bin'),
    # GitHub's windows runner images.
    'C:\ProgramData\mingw64\mingw64\bin',
    'C:\ProgramData\chocolatey\lib\mingw\tools\install\mingw64\bin',
    # MSYS2, whichever environment was installed.
    'C:\msys64\mingw64\bin',
    'C:\msys64\ucrt64\bin',
    # A plain unzipped toolchain.
    'C:\mingw64\bin',
    # Strawberry Perl ships a complete MinGW, and is often already there.
    'C:\Strawberry\c\bin'
)

foreach ($dir in $candidates) {
    if ([string]::IsNullOrWhiteSpace($dir)) { continue }
    $missing = $required | Where-Object { -not (Test-Path (Join-Path $dir $_)) }
    if (-not $missing) {
        Write-Output $dir
        exit 0
    }
}

# Nothing on disk. Say what was looked for, not just that it failed: the next
# person to read this is looking at a build that stopped for no visible reason.
Write-Error @"
None of these holds the full set ($($required -join ', ')):
$($candidates | ForEach-Object { "  $_" } | Out-String)
"@
exit 1
