param(
    [Parameter(Mandatory = $true)]
    [string]$TemplatePath,
    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Set-ParagraphText {
    param(
        $Document,
        [int]$Index,
        [string]$Text
    )

    $paragraph = $Document.Paragraphs.Item($Index)
    $range = $paragraph.Range.Duplicate
    $range.End = $range.End - 1
    $range.Text = $Text
}

$values = @{
    42  = "基于隐式证书与离线吊销验证的轻量级公开密钥基础设施软件"
    46  = "TinyPKI"
    49  = "V1.0"
    52  = "☑原创         □ 修改（含翻译软件、合成软件）"
    55  = "□应用软件     □嵌入式软件     ☑中间件     □操作系统"
    58  = "2026/4/11"
    60  = "未发表"
    63  = "1931年"
    65  = "未发表"
    68  = "☑事业单位       □营业执照      □身份证     □其他"
    71  = "☑独立开发     □合作开发       □委托开发      □下达任务开发"
    75  = "西安电子科技大学"
    79  = "121000004352307294"
    83  = "陕西省西安市西沣路兴隆段266号"
    87  = "710071"
    91  = "李毅刚"
    95  = "17792268841"
    99  = "764925453@qq.com"
    104 = "☑原始取得    □继受取得 ( □ 受让   □承受   □继承 )"
    110 = "☑全部"
    117 = "☑一般交存"
    120 = "☑一种文档    □      种文档"
    132 = "x86_64 开发机、边缘网关测试节点"
    135 = "x86_64 主机、边缘网关、资源受限终端"
    138 = "Windows 11、Ubuntu 20.04"
    141 = "C11、CMake、OpenSSL 3、VS Code"
    144 = "Linux、Windows、macOS"
    147 = "OpenSSL 3.0 及以上"
    153 = "□Assembly language      ☑C        □C#       □C++                 □Delphi/Object Pascal   □Go       □HTML     □Java    □JavaScript             □MATLAB   □Objective-C        □PHP                    □PL/SQL   □Perl     □Python"
    154 = "□R                      □Ruby     □SQL      □Swift     □Visual Basic           □Visual Basic .Net"
    157 = "15889行"
    161 = "为弱网与受限设备提供轻量、离线可验证的 PKI 能力。"
    164 = "物联网安全、边缘计算安全、工业互联网身份认证"
    167 = "本软件面向物联网与边缘场景，提供 ECQV 隐式证书签发、终端密钥重构、CA 签名 Merkle 根记录发布、携带式非吊销证明生成与离线验证、双向身份认证、会话密钥协商及 SM4-GCM/CCM 安全会话保护，并支持撤销状态同步与高层 PKI service/client 接口。"
    170 = "□APP           □游戏软件      □教育软件    □金融软件      □医疗软件      □地理信息软件  □云计算软件    ☑信息安全软件  □大数据软件     □人工智能软件  □VR软件        □5G软件       □小程序        ☑物联网软件    □ 智慧城市软件"
    173 = "基于 ECQV 隐式证书与 CA 签名 Merkle 根记录，采用携带式非吊销证明实现离线精确吊销验证，并将认证、密钥协商与 AEAD 会话保护整合为轻量主链路。"
}

Copy-Item -LiteralPath $TemplatePath -Destination $OutputPath -Force
$outputItem = Get-Item -LiteralPath $OutputPath
$outputItem.IsReadOnly = $false

$word = New-Object -ComObject Word.Application
$word.Visible = $false
$word.DisplayAlerts = 0

try {
    $doc = $word.Documents.Open($OutputPath)
    try {
        foreach ($key in ($values.Keys | Sort-Object)) {
            Set-ParagraphText -Document $doc -Index $key -Text $values[$key]
        }

        $doc.Save()

        Write-Output ("OUTPUT=" + $OutputPath)
        foreach ($key in 42,46,49,58,60,65,75,91,132,135,157,167,173) {
            $text = $doc.Paragraphs.Item($key).Range.Text -replace '[\r\a]', ''
            Write-Output ("P{0}={1}" -f $key, $text)
        }
    }
    finally {
        $doc.Close([ref]0)
    }
}
finally {
    $word.Quit([ref]0) | Out-Null
}
