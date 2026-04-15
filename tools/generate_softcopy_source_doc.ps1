param(
    [Parameter(Mandatory = $true)]
    [string]$TemplatePath,
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$wdStatisticPages = 2
$wdHeaderFooterPrimary = 1
$wdFindContinue = 1
$wdReplaceAll = 2
$wdLineSpaceExactly = 4
$wdGoToPage = 1
$wdGoToAbsolute = 1
$wdDoNotSaveChanges = 0

$sourceFiles = @(
    "src/ecqv/ecqv.c",
    "src/auth/auth.c",
    "src/revoke/revoke.c",
    "src/pki/client.c"
)

function Read-SourceBundle {
    param(
        [string]$Root,
        [string[]]$Files
    )

    $builder = New-Object System.Text.StringBuilder
    foreach ($rel in $Files) {
        $full = Join-Path $Root $rel
        if (-not (Test-Path -LiteralPath $full)) {
            throw "Source file not found: $full"
        }

        [void]$builder.AppendLine("/* ============================================================ */")
        [void]$builder.AppendLine("/* FILE: $rel */")
        [void]$builder.AppendLine("/* ============================================================ */")
        $content = Get-Content -LiteralPath $full -Raw -Encoding UTF8
        [void]$builder.AppendLine($content.TrimEnd("`r", "`n"))
        [void]$builder.AppendLine()
        [void]$builder.AppendLine()
    }

    return $builder.ToString()
}

function Apply-BodyFormat {
    param(
        $Range,
        [double]$FontSize,
        [double]$LineSpacing
    )

    $Range.Font.Name = "Consolas"
    $Range.Font.Size = $FontSize
    $Range.ParagraphFormat.LineSpacingRule = $wdLineSpaceExactly
    $Range.ParagraphFormat.LineSpacing = $LineSpacing
    $Range.ParagraphFormat.SpaceBefore = 0
    $Range.ParagraphFormat.SpaceAfter = 0
}

function Replace-InRange {
    param(
        $Range,
        [string]$FindText,
        [string]$ReplaceText
    )

    $find = $Range.Find
    $find.ClearFormatting()
    $find.Replacement.ClearFormatting()
    $find.Text = $FindText
    $find.Replacement.Text = $ReplaceText
    [void]$find.Execute($FindText, $false, $false, $false, $false, $false, $true, $wdFindContinue, $false, $ReplaceText, $wdReplaceAll)
}

function Get-PageCount {
    param($Document)
    return $Document.ComputeStatistics($wdStatisticPages)
}

function Trim-ToFrontBack60Pages {
    param($Document)

    $pageCount = Get-PageCount -Document $Document
    if ($pageCount -le 60) {
        return
    }

    $page31 = $Document.GoTo($wdGoToPage, $wdGoToAbsolute, 31)
    $pageBeforeLast30 = $Document.GoTo($wdGoToPage, $wdGoToAbsolute, $pageCount - 29)
    $start = $page31.Start
    $end = $pageBeforeLast30.Start

    if ($end -gt $start) {
        $midRange = $Document.Range($start, $end)
        $midRange.Text = "`r`n/* Middle pages omitted to keep only the first 30 and last 30 pages for copyright filing. */`r`n"
    }
}

$bundle = Read-SourceBundle -Root $RepoRoot -Files $sourceFiles

Copy-Item -LiteralPath $TemplatePath -Destination $OutputPath -Force
$outputItem = Get-Item -LiteralPath $OutputPath
$outputItem.IsReadOnly = $false

$word = New-Object -ComObject Word.Application
$word.Visible = $false
$word.DisplayAlerts = 0

try {
    $doc = $word.Documents.Open($OutputPath)
    try {
        foreach ($section in $doc.Sections) {
            Replace-InRange -Range $section.Headers($wdHeaderFooterPrimary).Range -FindText "********" -ReplaceText "TinyPKI"
            $section.Footers($wdHeaderFooterPrimary).Range.Text = "TinyPKI Team"
        }

        $doc.Content.Text = $bundle

        $formatCandidates = @(
            @{ FontSize = 7.5; LineSpacing = 8.0 },
            @{ FontSize = 7.0; LineSpacing = 7.5 },
            @{ FontSize = 6.5; LineSpacing = 7.0 }
        )

        foreach ($candidate in $formatCandidates) {
            Apply-BodyFormat -Range $doc.Content -FontSize $candidate.FontSize -LineSpacing $candidate.LineSpacing
            $doc.Repaginate()
            if ((Get-PageCount -Document $doc) -le 60) {
                break
            }
        }

        $doc.Repaginate()
        Trim-ToFrontBack60Pages -Document $doc
        $doc.Repaginate()

        $pages = Get-PageCount -Document $doc
        $doc.Save()
        Write-Output ("OUTPUT=" + $OutputPath)
        Write-Output ("PAGES=" + $pages)
    }
    finally {
        $doc.Close([ref]$wdDoNotSaveChanges)
    }
}
finally {
    $word.Quit([ref]$wdDoNotSaveChanges) | Out-Null
}
