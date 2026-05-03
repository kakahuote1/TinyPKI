param(
    [switch]$Fix
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$clangFormatVersion = "18.1.8"
$clangFormatPackage = "clang-format==$clangFormatVersion"

function Test-ExpectedClangFormat {
    param([string[]]$Command)

    $exe = $Command[0]
    $prefixArgs = @()
    if ($Command.Count -gt 1) {
        $prefixArgs = $Command[1..($Command.Count - 1)]
    }

    try {
        $version = & $exe @prefixArgs --version 2>$null
    } catch {
        return $false
    }

    return $version -match "version $([regex]::Escape($clangFormatVersion))"
}

function Get-ClangFormatCommand {
    if ($env:CLANG_FORMAT) {
        $command = @($env:CLANG_FORMAT)
        if (Test-ExpectedClangFormat $command) {
            return $command
        }
        throw "CLANG_FORMAT must point to clang-format $clangFormatVersion."
    }

    if (Get-Command "uvx" -ErrorAction SilentlyContinue) {
        return @("uvx", "--from", $clangFormatPackage, "clang-format")
    }

    foreach ($name in @("clang-format-18", "clang-format")) {
        if (Get-Command $name -ErrorAction SilentlyContinue) {
            $command = @($name)
            if (Test-ExpectedClangFormat $command) {
                return $command
            }
        }
    }

    throw "clang-format $clangFormatVersion was not found. Install uvx or set CLANG_FORMAT to the exact version."
}

function Invoke-ClangFormat {
    param(
        [string[]]$Command,
        [string[]]$Arguments
    )

    $exe = $Command[0]
    $prefixArgs = @()
    if ($Command.Count -gt 1) {
        $prefixArgs = $Command[1..($Command.Count - 1)]
    }

    & $exe @prefixArgs @Arguments
}

Push-Location $repoRoot
try {
    $files = Get-ChildItem -Path "include", "src", "tests" -Recurse -File |
        Where-Object { $_.Extension -in ".h", ".c" } |
        Sort-Object FullName |
        ForEach-Object { Resolve-Path -Relative $_.FullName }

    if (-not $files) {
        Write-Host "No C headers or sources found."
        exit 0
    }

    $clangFormat = Get-ClangFormatCommand
    $version = Invoke-ClangFormat $clangFormat @("--version")
    Write-Host "Using $version"

    if ($Fix) {
        $args = @("-i", "-style=file") + $files
    } else {
        $args = @("--dry-run", "-Werror", "-style=file") + $files
    }

    Invoke-ClangFormat $clangFormat $args
} finally {
    Pop-Location
}
