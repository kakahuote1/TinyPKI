param(
    [Parameter(Mandatory = $true)]
    [string]$TemplatePath,
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,
    [string]$BodyPath = (Join-Path $PSScriptRoot "softcopy_design_doc_body.md")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$wdHeaderFooterPrimary = 1
$wdFindContinue = 1
$wdReplaceAll = 2
$wdAlignCenter = 1
$wdAlignLeft = 0
$wdLineSpaceSingle = 0
$wdStatisticPages = 2
$wdPageBreak = 7
$wdInformationActiveEndPageNumber = 3
$wdAlignTabRight = 2
$wdTabLeaderSpaces = 0
$tocTitleText = ([string]([char]30446) + [char]24405)

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

function Normalize-HeadingText {
    param([string]$Text)

    return ([regex]::Replace($Text, '^((?:\d+(?:\.\d+)*)\.?)[ ]+', '$1'))
}

function Parse-BodyBlocks {
    param([string]$Path)

    $lines = Get-Content -LiteralPath $Path -Encoding UTF8
    $blocks = New-Object System.Collections.Generic.List[object]
    $i = 0
    $skipManualToc = $false

    while ($i -lt $lines.Count) {
        $line = $lines[$i].TrimEnd()

        if ($skipManualToc) {
            if ($line.StartsWith("# ") -and $line.Substring(2).Trim() -match '^\d') {
                $skipManualToc = $false
            }
            else {
                $i++
                continue
            }
        }

        if ($line -eq "") {
            $blocks.Add([PSCustomObject]@{ Type = "blank"; Text = "" })
            $i++
            continue
        }

        if ($line.StartsWith("TABLE:")) {
            $title = $line.Substring(6).Trim()
            $rows = New-Object System.Collections.Generic.List[object]
            $i++
            while ($i -lt $lines.Count) {
                $rowLine = $lines[$i].Trim()
                if (-not $rowLine.StartsWith("|")) {
                    break
                }

                $cells = @()
                foreach ($cell in ($rowLine.Trim("|").Split("|"))) {
                    $cells += $cell.Trim()
                }
                $rows.Add($cells)
                $i++
            }

            $blocks.Add([PSCustomObject]@{
                Type  = "table"
                Title = $title
                Rows  = $rows
            })
            continue
        }

        if ($line.StartsWith("TITLE:")) {
            $blocks.Add([PSCustomObject]@{ Type = "title"; Text = $line.Substring(6).Trim() })
        }
        elseif ($line.StartsWith("SUBTITLE:")) {
            $blocks.Add([PSCustomObject]@{ Type = "subtitle"; Text = $line.Substring(9).Trim() })
        }
        elseif ($line.StartsWith("ORG:")) {
            $blocks.Add([PSCustomObject]@{ Type = "org"; Text = $line.Substring(4).Trim() })
        }
        elseif ($line.StartsWith("META:")) {
            $blocks.Add([PSCustomObject]@{ Type = "meta"; Text = $line.Substring(5).Trim() })
        }
        elseif ($line.StartsWith("## ")) {
            $blocks.Add([PSCustomObject]@{
                Type = "h2"
                Text = (Normalize-HeadingText -Text $line.Substring(3).Trim())
            })
        }
        elseif ($line.StartsWith("# ")) {
            $headingText = $line.Substring(2).Trim()
            if ($headingText -eq $tocTitleText) {
                $skipManualToc = $true
                $i++
                continue
            }

            $blocks.Add([PSCustomObject]@{
                Type = "h1"
                Text = (Normalize-HeadingText -Text $headingText)
            })
        }
        else {
            $blocks.Add([PSCustomObject]@{ Type = "body"; Text = $line })
        }

        $i++
    }

    return $blocks
}

function Split-DocumentBlocks {
    param([System.Collections.Generic.List[object]]$Blocks)

    $coverBlocks = New-Object System.Collections.Generic.List[object]
    $contentBlocks = New-Object System.Collections.Generic.List[object]
    $contentStarted = $false

    foreach ($block in $Blocks) {
        if (-not $contentStarted -and $block.Type -in @("title", "subtitle", "org", "meta", "blank")) {
            $coverBlocks.Add($block)
            continue
        }

        $contentStarted = $true
        if ($block.Type -in @("title", "subtitle", "org", "meta")) {
            continue
        }
        $contentBlocks.Add($block)
    }

    return [PSCustomObject]@{
        Cover   = $coverBlocks
        Content = $contentBlocks
    }
}

function New-TocEntries {
    param([System.Collections.Generic.List[object]]$ContentBlocks)

    $entries = New-Object System.Collections.Generic.List[object]
    foreach ($block in $ContentBlocks) {
        if ($block.Type -in @("h1", "h2")) {
            $entries.Add([PSCustomObject]@{
                Level            = $block.Type
                Text             = $block.Text
                TocParagraph     = $null
                HeadingParagraph = $null
            })
        }
    }
    return $entries
}

function Set-TocTabStop {
    param($Paragraph)

    $document = $Paragraph.Range.Document
    $position = $document.PageSetup.PageWidth - $document.PageSetup.LeftMargin - $document.PageSetup.RightMargin
    $tabStops = $Paragraph.Range.ParagraphFormat.TabStops
    if ($tabStops.Count -gt 0) {
        $tabStops.ClearAll()
    }
    [void]$tabStops.Add([single]$position, $wdAlignTabRight, $wdTabLeaderSpaces)
}

function Apply-ParagraphStyle {
    param(
        $Paragraph,
        [string]$Type
    )

    $range = $Paragraph.Range
    $range.Font.Name = "SimSun"
    $range.Font.NameFarEast = "SimSun"
    $range.Font.Size = 11
    $range.Font.Bold = 0
    $range.ParagraphFormat.SpaceBefore = 0
    $range.ParagraphFormat.SpaceAfter = 0
    $range.ParagraphFormat.LineSpacingRule = $wdLineSpaceSingle
    $range.ParagraphFormat.FirstLineIndent = 0
    $range.ParagraphFormat.Alignment = $wdAlignLeft

    switch ($Type) {
        "title" {
            $range.Font.Name = "SimHei"
            $range.Font.NameFarEast = "SimHei"
            $range.Font.Size = 20
            $range.Font.Bold = 1
            $range.ParagraphFormat.Alignment = $wdAlignCenter
            $range.ParagraphFormat.SpaceAfter = 12
        }
        "subtitle" {
            $range.Font.Name = "SimHei"
            $range.Font.NameFarEast = "SimHei"
            $range.Font.Size = 16
            $range.Font.Bold = 1
            $range.ParagraphFormat.Alignment = $wdAlignCenter
            $range.ParagraphFormat.SpaceAfter = 8
        }
        "org" {
            $range.Font.Size = 12
            $range.ParagraphFormat.Alignment = $wdAlignCenter
            $range.ParagraphFormat.SpaceAfter = 4
        }
        "meta" {
            $range.Font.Size = 12
            $range.ParagraphFormat.Alignment = $wdAlignCenter
            $range.ParagraphFormat.SpaceAfter = 16
        }
        "toctitle" {
            $range.Font.Name = "SimHei"
            $range.Font.NameFarEast = "SimHei"
            $range.Font.Size = 15
            $range.Font.Bold = 1
            $range.ParagraphFormat.Alignment = $wdAlignCenter
            $range.ParagraphFormat.SpaceAfter = 8
        }
        "toc1" {
            try { $range.Style = "TOC 1" } catch {}
            $range.Font.Name = "SimSun"
            $range.Font.NameFarEast = "SimSun"
            $range.Font.Size = 12
            $range.ParagraphFormat.Alignment = $wdAlignLeft
            Set-TocTabStop -Paragraph $Paragraph
        }
        "toc2" {
            try { $range.Style = "TOC 2" } catch {}
            $range.Font.Name = "SimSun"
            $range.Font.NameFarEast = "SimSun"
            $range.Font.Size = 12
            $range.ParagraphFormat.Alignment = $wdAlignLeft
            Set-TocTabStop -Paragraph $Paragraph
        }
        "h1" {
            $range.Font.Name = "SimHei"
            $range.Font.NameFarEast = "SimHei"
            $range.Font.Size = 14
            $range.Font.Bold = 1
            $range.ParagraphFormat.SpaceBefore = 8
            $range.ParagraphFormat.SpaceAfter = 4
        }
        "h2" {
            $range.Font.Name = "SimHei"
            $range.Font.NameFarEast = "SimHei"
            $range.Font.Size = 12
            $range.Font.Bold = 1
            $range.ParagraphFormat.SpaceBefore = 6
            $range.ParagraphFormat.SpaceAfter = 2
        }
        "tabletitle" {
            $range.Font.Name = "SimHei"
            $range.Font.NameFarEast = "SimHei"
            $range.Font.Size = 11
            $range.Font.Bold = 1
            $range.ParagraphFormat.SpaceBefore = 4
            $range.ParagraphFormat.SpaceAfter = 2
        }
        "blank" {
            $range.Font.Size = 11
        }
        default {
            $range.Font.Size = 11
            $range.ParagraphFormat.FirstLineIndent = 21
        }
    }
}

function Insert-Paragraph {
    param(
        $Selection,
        [string]$Text,
        [string]$Type
    )

    $Selection.TypeText($Text)
    $Selection.TypeParagraph()
    $paragraph = $Selection.Paragraphs.Item(1).Previous()
    Apply-ParagraphStyle -Paragraph $paragraph -Type $Type
    return $paragraph
}

function Insert-TableBlock {
    param(
        $Document,
        $Selection,
        [string]$Title,
        [System.Collections.Generic.List[object]]$Rows
    )

    [void](Insert-Paragraph -Selection $Selection -Text $Title -Type "tabletitle")

    if ($Rows.Count -eq 0) {
        return
    }

    $rowCount = $Rows.Count
    $columnCount = $Rows[0].Count
    $table = $Document.Tables.Add($Selection.Range, $rowCount, $columnCount)
    $table.Borders.Enable = 1
    $table.Range.Font.Name = "SimSun"
    $table.Range.Font.NameFarEast = "SimSun"
    $table.Range.Font.Size = 10.5
    $table.Rows.Alignment = 0

    for ($r = 1; $r -le $rowCount; $r++) {
        $cells = $Rows[$r - 1]
        for ($c = 1; $c -le $columnCount; $c++) {
            $cellText = ""
            if ($c -le $cells.Count) {
                $cellText = [string]$cells[$c - 1]
            }

            $table.Cell($r, $c).Range.Text = $cellText
            if ($r -eq 1) {
                $table.Cell($r, $c).Range.Bold = 1
            }
        }
    }

    $Selection.SetRange($table.Range.End, $table.Range.End)
    $Selection.TypeParagraph()
}

function Insert-PageBreak {
    param($Selection)

    [void]$Selection.InsertBreak($wdPageBreak)
}

function Update-TocEntries {
    param([System.Collections.Generic.List[object]]$Entries)

    foreach ($entry in $Entries) {
        if ($null -eq $entry.TocParagraph -or $null -eq $entry.HeadingParagraph) {
            continue
        }

        $page = $entry.HeadingParagraph.Range.Information($wdInformationActiveEndPageNumber)
        $textRange = $entry.TocParagraph.Range.Duplicate
        $textRange.SetRange($entry.TocParagraph.Range.Start, $entry.TocParagraph.Range.End - 1)
        $textRange.Text = ($entry.Text + "`t" + $page)
        $styleType = if ($entry.Level -eq "h1") { "toc1" } else { "toc2" }
        Apply-ParagraphStyle -Paragraph $entry.TocParagraph -Type $styleType
    }
}

if (-not (Test-Path -LiteralPath $BodyPath)) {
    throw "Design body file not found: $BodyPath"
}

$blocks = Parse-BodyBlocks -Path $BodyPath
$parts = Split-DocumentBlocks -Blocks $blocks
$tocEntries = New-TocEntries -ContentBlocks $parts.Content

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
            Replace-InRange -Range $section.Headers($wdHeaderFooterPrimary).Range -FindText "***" -ReplaceText "TinyPKI"
            $section.Footers($wdHeaderFooterPrimary).Range.Text = "TinyPKI Team"
        }

        $doc.Content.Text = ""
        $selection = $word.Selection
        $selection.SetRange(0, 0)

        foreach ($block in $parts.Cover) {
            switch ($block.Type) {
                "blank" {
                    $selection.TypeParagraph()
                }
                default {
                    [void](Insert-Paragraph -Selection $selection -Text $block.Text -Type $block.Type)
                }
            }
        }

        Insert-PageBreak -Selection $selection
        [void](Insert-Paragraph -Selection $selection -Text $tocTitleText -Type "toctitle")
        foreach ($entry in $tocEntries) {
            $tocType = if ($entry.Level -eq "h1") { "toc1" } else { "toc2" }
            $entry.TocParagraph = Insert-Paragraph -Selection $selection -Text ($entry.Text + "`t") -Type $tocType
        }

        Insert-PageBreak -Selection $selection
        $headingIndex = 0
        foreach ($block in $parts.Content) {
            switch ($block.Type) {
                "table" {
                    Insert-TableBlock -Document $doc -Selection $selection -Title $block.Title -Rows $block.Rows
                }
                "blank" {
                    $selection.TypeParagraph()
                }
                "h1" {
                    $paragraph = Insert-Paragraph -Selection $selection -Text $block.Text -Type "h1"
                    $tocEntries[$headingIndex].HeadingParagraph = $paragraph
                    $headingIndex++
                }
                "h2" {
                    $paragraph = Insert-Paragraph -Selection $selection -Text $block.Text -Type "h2"
                    $tocEntries[$headingIndex].HeadingParagraph = $paragraph
                    $headingIndex++
                }
                default {
                    [void](Insert-Paragraph -Selection $selection -Text $block.Text -Type "body")
                }
            }
        }

        $doc.Repaginate()
        Update-TocEntries -Entries $tocEntries
        $doc.Repaginate()

        $pages = $doc.ComputeStatistics($wdStatisticPages)
        $doc.Save()
        Write-Output ("OUTPUT=" + $OutputPath)
        Write-Output ("PAGES=" + $pages)
        Write-Output ("TOC_ENTRIES=" + $tocEntries.Count)
    }
    finally {
        $doc.Close([ref]0)
    }
}
finally {
    $word.Quit([ref]0) | Out-Null
}
