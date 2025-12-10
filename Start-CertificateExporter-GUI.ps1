<#
.SYNOPSIS
    CertStoreExporter - GUI tool to export a certificate (User/Computer Personal) to PFX
    and optionally generate Linux-ready files using OpenSSL.
    Also supports converting an existing PFX to Linux files.

.DESCRIPTION
    This WinForms tool:
      1) Enumerates certificates from:
         - Cert:\CurrentUser\My
         - Cert:\LocalMachine\My
      2) Lets you select a certificate with a private key
      3) Exports it to PFX using Export-PfxCertificate
      4) Optional: Uses OpenSSL to create Linux-ready files:
         - <name>-cert.pem
         - <name>-privkey.key
         - <name>-chain.cer
         - <name>-fullchain.cer
      5) Can also convert an existing PFX to the same set

.VERSION
    1.14 - Added UI label explaining output naming rules.
           Removed duplicate OpenSSL Browse click handler.
           Preserves:
             - CN-based export folder naming (.\<CN>\)
             - Robust overwrite/timestamp prompt (Yes/No/Cancel)
             - Progress + verbose logging
             - OpenSSL arg concatenation fix
             - Required extensions:
                 cert = .pem, key = .key, chain/fullchain = .cer

.AUTHOR
    Peter

.LAST UPDATED
    2025-12-10
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ----------------------------
# Configuration
# ----------------------------
$ScriptName    = "CertStoreExporter"
$ScriptVersion = "1.14"
$LogFile       = ".\CertStoreExporter.log"

# ----------------------------
# Logging
# ----------------------------
function Initialize-Log {
    try {
        if (Test-Path $LogFile) {
            $stamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
            $arch  = [IO.Path]::ChangeExtension($LogFile, "$stamp.log")
            Move-Item $LogFile $arch -Force -ErrorAction SilentlyContinue
        }

        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $ScriptName v$ScriptVersion starting." |
            Out-File -FilePath $LogFile -Encoding utf8
    } catch {}
}

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("INFO","WARN","ERROR","DEBUG")][string]$Level = "INFO"
    )
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    try { $line | Out-File -FilePath $LogFile -Append -Encoding utf8 } catch {}
}

Initialize-Log

# ----------------------------
# Helpers: CN + safe names
# ----------------------------
function Get-CommonNameFromSubject {
    param([string]$Subject)

    if ([string]::IsNullOrWhiteSpace($Subject)) { return $null }

    $m = [regex]::Match($Subject, '(?i)\bCN\s*=\s*([^,]+)')
    if ($m.Success) {
        return $m.Groups[1].Value.Trim()
    }
    return $null
}

function Remove-InvalidFileNameChars {
    param([Parameter(Mandatory)][string]$Name)

    $invalid = [IO.Path]::GetInvalidFileNameChars()
    $safe = $Name
    foreach ($ch in $invalid) { $safe = $safe.Replace($ch, "_") }

    $safe = $safe.Trim().TrimEnd(".")
    if ([string]::IsNullOrWhiteSpace($safe)) { return $null }

    return $safe
}

function Get-FolderNameForCert {
    param(
        [object]$CertObject,
        [string]$FallbackName
    )

    $cn = $null
    try {
        if ($CertObject -and $CertObject.Subject) {
            $cn = Get-CommonNameFromSubject -Subject $CertObject.Subject
        }
    } catch {}

    if ([string]::IsNullOrWhiteSpace($cn)) { $cn = $FallbackName }

    if ([string]::IsNullOrWhiteSpace($cn)) {
        try { if ($CertObject -and $CertObject.Thumbprint) { $cn = $CertObject.Thumbprint } } catch {}
    }

    $cn = Remove-InvalidFileNameChars -Name $cn
    if ([string]::IsNullOrWhiteSpace($cn)) { $cn = "CertExport" }

    return $cn
}

function Ensure-ExportFolder {
    param([Parameter(Mandatory)][string]$FolderName)

    $path = Join-Path (Get-Location).Path $FolderName
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
    return $path
}

# ----------------------------
# Timestamp helper
# ----------------------------
function Add-TimestampToPath {
    param([Parameter(Mandatory)][string]$Path)

    $dir  = Split-Path $Path -Parent
    $name = [IO.Path]::GetFileNameWithoutExtension($Path)
    $ext  = [IO.Path]::GetExtension($Path)
    $ts   = (Get-Date).ToString("yyyyMMdd-HHmmss")

    $newName = "$name-$ts$ext"
    if ([string]::IsNullOrWhiteSpace($dir)) { return $newName }
    return (Join-Path $dir $newName)
}

# ----------------------------
# Overwrite / Timestamp / Cancel (robust MessageBox)
# ----------------------------
function Ask-OverwriteOrTimestamp {
    param(
        [Parameter(Mandatory)][string]$TargetLabel,
        [Parameter(Mandatory)][string]$ExistingPath
    )

    $msg =
        "$TargetLabel already exists:`r`n" +
        "$ExistingPath`r`n`r`n" +
        "Choose:`r`n" +
        "Yes    = Overwrite`r`n" +
        "No     = Add timestamp`r`n" +
        "Cancel = Cancel"

    $res = [System.Windows.Forms.MessageBox]::Show(
        $msg,
        "Export file exists",
        [System.Windows.Forms.MessageBoxButtons]::YesNoCancel,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )

    switch ($res) {
        'Yes'    { return "Overwrite" }
        'No'     { return "Timestamp" }
        default  { return "Cancel" }
    }
}

# ----------------------------
# Ensure safe file path for single-file exports (PFX)
# ----------------------------
function Get-SafeExportPath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Label
    )

    if (-not (Test-Path $Path)) { return $Path }

    $choice = Ask-OverwriteOrTimestamp -TargetLabel $Label -ExistingPath $Path
    Write-Log "User choice for existing $($Label): $choice" "DEBUG"

    switch ($choice) {
        "Overwrite" { return $Path }
        "Timestamp" { return (Add-TimestampToPath -Path $Path) }
        default     { return $null }
    }
}

# ----------------------------
# PEM set collision handling (REQUIRED EXTENSIONS)
# ----------------------------
function Resolve-PemSetPaths {
    param(
        [Parameter(Mandatory)][string]$OutputDir,
        [Parameter(Mandatory)][string]$BaseName
    )

    # Required output extensions:
    # leaf cert = .pem
    # private key = .key
    # chain = .cer
    # fullchain = .cer
    $certPem      = Join-Path $OutputDir "$BaseName-cert.pem"
    $keyPem       = Join-Path $OutputDir "$BaseName-privkey.key"
    $chainPem     = Join-Path $OutputDir "$BaseName-chain.cer"
    $fullchainPem = Join-Path $OutputDir "$BaseName-fullchain.cer"

    $existing = @($certPem, $keyPem, $chainPem, $fullchainPem) | Where-Object { Test-Path $_ }

    if ($existing.Count -gt 0) {
        $choice = Ask-OverwriteOrTimestamp -TargetLabel "Certificate export set" -ExistingPath $OutputDir
        Write-Log "User choice for existing certificate export set: $choice" "DEBUG"

        if ($choice -eq "Cancel" -or -not $choice) { return $null }

        if ($choice -eq "Timestamp") {
            $ts = (Get-Date).ToString("yyyyMMdd-HHmmss")
            $BaseName = "$BaseName-$ts"

            $certPem      = Join-Path $OutputDir "$BaseName-cert.pem"
            $keyPem       = Join-Path $OutputDir "$BaseName-privkey.key"
            $chainPem     = Join-Path $OutputDir "$BaseName-chain.cer"
            $fullchainPem = Join-Path $OutputDir "$BaseName-fullchain.cer"
        }
    }

    return [pscustomobject]@{
        BaseName     = $BaseName
        CertPem      = $certPem
        KeyPem       = $keyPem
        ChainPem     = $chainPem
        FullchainPem = $fullchainPem
    }
}

# ----------------------------
# GUI Password Dialog (with confirm)
# ----------------------------
function Get-PfxPasswordDialog {
    param(
        [string]$Title = "PFX Password Required",
        [string]$Prompt = "Enter and confirm the password:",
        [bool]$RequireConfirm = $true
    )

    $dialog = New-Object System.Windows.Forms.Form
    $dialog.Text = $Title
    $dialog.Size = New-Object System.Drawing.Size(430, 260)
    $dialog.StartPosition = "CenterParent"
    $dialog.FormBorderStyle = "FixedDialog"
    $dialog.MaximizeBox = $false
    $dialog.MinimizeBox = $false
    $dialog.TopMost = $true
    $dialog.ShowInTaskbar = $false

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = $Prompt
    $lbl.AutoSize = $true
    $lbl.Location = New-Object System.Drawing.Point(12, 15)
    $dialog.Controls.Add($lbl)

    $lbl1 = New-Object System.Windows.Forms.Label
    $lbl1.Text = "Password:"
    $lbl1.AutoSize = $true
    $lbl1.Location = New-Object System.Drawing.Point(15, 55)
    $dialog.Controls.Add($lbl1)

    $txt1 = New-Object System.Windows.Forms.TextBox
    $txt1.Location = New-Object System.Drawing.Point(110, 52)
    $txt1.Size = New-Object System.Drawing.Size(280, 24)
    $txt1.UseSystemPasswordChar = $true
    $dialog.Controls.Add($txt1)

    $lbl2 = New-Object System.Windows.Forms.Label
    $lbl2.Text = "Confirm:"
    $lbl2.AutoSize = $true
    $lbl2.Location = New-Object System.Drawing.Point(15, 92)
    $dialog.Controls.Add($lbl2)

    $txt2 = New-Object System.Windows.Forms.TextBox
    $txt2.Location = New-Object System.Drawing.Point(110, 89)
    $txt2.Size = New-Object System.Drawing.Size(280, 24)
    $txt2.UseSystemPasswordChar = $true
    $dialog.Controls.Add($txt2)

    if (-not $RequireConfirm) {
        $lbl2.Visible = $false
        $txt2.Visible = $false
    }

    $chkShow = New-Object System.Windows.Forms.CheckBox
    $chkShow.Text = "Show password"
    $chkShow.AutoSize = $true
    $chkShow.Location = New-Object System.Drawing.Point(15, 125)
    $chkShow.Add_CheckedChanged({
        $txt1.UseSystemPasswordChar = -not $chkShow.Checked
        if ($RequireConfirm) { $txt2.UseSystemPasswordChar = -not $chkShow.Checked }
    })
    $dialog.Controls.Add($chkShow)

    $lblError = New-Object System.Windows.Forms.Label
    $lblError.Text = ""
    $lblError.ForeColor = [System.Drawing.Color]::DarkRed
    $lblError.AutoSize = $true
    $lblError.Location = New-Object System.Drawing.Point(15, 150)
    $dialog.Controls.Add($lblError)

    $btnOk = New-Object System.Windows.Forms.Button
    $btnOk.Text = "OK"
    $btnOk.Location = New-Object System.Drawing.Point(234, 180)
    $btnOk.Size = New-Object System.Drawing.Size(75, 28)
    $btnOk.DialogResult = [System.Windows.Forms.DialogResult]::None
    $dialog.Controls.Add($btnOk)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Cancel"
    $btnCancel.Location = New-Object System.Drawing.Point(315, 180)
    $btnCancel.Size = New-Object System.Drawing.Size(75, 28)
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $dialog.CancelButton = $btnCancel
    $dialog.Controls.Add($btnCancel)

    $btnOk.Add_Click({
        $p1 = $txt1.Text
        $p2 = if ($RequireConfirm) { $txt2.Text } else { $txt1.Text }

        if ([string]::IsNullOrWhiteSpace($p1)) {
            $lblError.Text = "Password cannot be empty."
            return
        }
        if ($RequireConfirm -and $p1 -ne $p2) {
            $lblError.Text = "Passwords do not match."
            return
        }

        $dialog.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $dialog.Close()
    })

    $dialog.Add_Shown({ $txt1.Focus() })

    $result = $dialog.ShowDialog()
    if ($result -ne [System.Windows.Forms.DialogResult]::OK) { return $null }

    $secure = ConvertTo-SecureString -String $txt1.Text -AsPlainText -Force
    $txt1.Text = ""
    $txt2.Text = ""
    return $secure
}

# ----------------------------
# Find OpenSSL
# ----------------------------
function Get-OpenSslPath {
    Write-Log "Attempting to locate openssl.exe via PATH and known locations." "DEBUG"

    $cmd = Get-Command openssl.exe -ErrorAction SilentlyContinue
    if ($cmd) {
        Write-Log "Found OpenSSL via PATH: $($cmd.Source)" "INFO"
        return $cmd.Source
    }

    $candidates = @(
        "$env:ProgramFiles\Git\usr\bin\openssl.exe",
        "$env:ProgramFiles(x86)\Git\usr\bin\openssl.exe",
        "$env:LOCALAPPDATA\Programs\Git\usr\bin\openssl.exe",
        "C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
    )

    foreach ($c in $candidates) {
        if (Test-Path $c) {
            Write-Log "Found OpenSSL candidate: $c" "INFO"
            return $c
        }
    }

    Write-Log "OpenSSL was not found automatically." "WARN"
    return $null
}

# ----------------------------
# Load certs
# ----------------------------
function Get-PersonalStoreCerts {
    $stores = @(
        @{ Name = "CurrentUser";  Path = "Cert:\CurrentUser\My" },
        @{ Name = "LocalMachine"; Path = "Cert:\LocalMachine\My" }
    )

    $result = New-Object System.Collections.Generic.List[object]

    foreach ($s in $stores) {
        Write-Log "Reading certificates from $($s.Path)" "DEBUG"
        try {
            $certs = Get-ChildItem -Path $s.Path -ErrorAction Stop
            foreach ($c in $certs) {
                $result.Add([pscustomobject]@{
                    Store          = $s.Name
                    Path           = "$($s.Path)\$($c.Thumbprint)"
                    Subject        = $c.Subject
                    FriendlyName   = $c.FriendlyName
                    Thumbprint     = $c.Thumbprint
                    NotAfter       = $c.NotAfter
                    HasPrivateKey  = $c.HasPrivateKey
                })
            }
        } catch {
            Write-Log "Failed to read $($s.Path): $($_.Exception.Message)" "WARN"
        }
    }

    return $result
}

# ----------------------------
# Export PFX
# ----------------------------
function Export-SelectedCertToPfx {
    param(
        [Parameter(Mandatory)][string]$CertPath,
        [Parameter(Mandatory)][string]$PfxFilePath,
        [Parameter(Mandatory)][securestring]$Password
    )

    Write-Log "Export-PfxCertificate start. CertPath=$CertPath PfxFilePath=$PfxFilePath" "INFO"

    Export-PfxCertificate -Cert $CertPath `
        -FilePath $PfxFilePath `
        -Password $Password `
        -ChainOption BuildChain `
        -Force | Out-Null

    Write-Log "Export-PfxCertificate completed successfully." "INFO"
}

# ----------------------------
# Run OpenSSL with capture
# ----------------------------
function Invoke-OpenSsl {
    param(
        [Parameter(Mandatory)][string]$OpenSsl,
        [Parameter(Mandatory)][string[]]$Args
    )

    Write-Log ("OpenSSL command: `"$OpenSsl`" " + ($Args -join " ")) "DEBUG"

    $output = & $OpenSsl @Args 2>&1
    if ($LASTEXITCODE -ne 0) {
        $msg = "OpenSSL failed (exit $LASTEXITCODE). Output: $output"
        Write-Log $msg "ERROR"
        throw $msg
    }

    if ($output) {
        Write-Log ("OpenSSL output: " + ($output -join " | ")) "DEBUG"
    }

    return $output
}

# ----------------------------
# Convert PFX -> Linux files
# ----------------------------
function Convert-PfxToLinuxPem {
    param(
        [Parameter(Mandatory)][string]$OpenSsl,
        [Parameter(Mandatory)][string]$PfxFile,
        [Parameter(Mandatory)][securestring]$Password,
        [Parameter(Mandatory)][string]$OutputDir,
        [Parameter(Mandatory)][string]$BaseName
    )

    Write-Log "Convert-PfxToLinuxPem start. PfxFile=$PfxFile OutputDir=$OutputDir BaseName=$BaseName" "INFO"

    if (!(Test-Path $OpenSsl)) { throw "OpenSSL not found at: $OpenSsl" }
    if (!(Test-Path $PfxFile)) { throw "PFX file not found: $PfxFile" }

    if (!(Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    $resolved = Resolve-PemSetPaths -OutputDir $OutputDir -BaseName $BaseName
    if (-not $resolved) { throw "Certificate export cancelled by user." }

    $certFile      = $resolved.CertPem
    $keyFile       = $resolved.KeyPem
    $chainFile     = $resolved.ChainPem
    $fullchainFile = $resolved.FullchainPem

    # Convert SecureString password for -passin usage
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    try { $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }

    $passArgs = @("-passin", "pass:$plain")

    # 1) Leaf cert -> .pem
    $args = @("pkcs12","-in",$PfxFile,"-clcerts","-nokeys","-out",$certFile)
    $args += $passArgs
    Invoke-OpenSsl -OpenSsl $OpenSsl -Args $args | Out-Null

    # 2) Private key -> .key (PEM-encoded content)
    $args = @("pkcs12","-in",$PfxFile,"-nocerts","-nodes","-out",$keyFile)
    $args += $passArgs
    Invoke-OpenSsl -OpenSsl $OpenSsl -Args $args | Out-Null

    # 3) Chain -> .cer
    $args = @("pkcs12","-in",$PfxFile,"-cacerts","-nokeys","-out",$chainFile)
    $args += $passArgs
    Invoke-OpenSsl -OpenSsl $OpenSsl -Args $args | Out-Null

    # 4) Full chain -> .cer (leaf + chain)
    $certContent  = Get-Content -Path $certFile  -ErrorAction SilentlyContinue
    $chainContent = Get-Content -Path $chainFile -ErrorAction SilentlyContinue
    @($certContent + $chainContent) | Set-Content -Path $fullchainFile -Encoding ascii

    $chainLikelyMissing = $false
    try {
        if (-not (Test-Path $chainFile) -or (Get-Item $chainFile).Length -lt 50) {
            $chainLikelyMissing = $true
            Write-Log "chain.cer seems empty/small. PFX may not include intermediates." "WARN"
        }
    } catch {}

    Write-Log "Linux file generation completed: cert=$certFile key=$keyFile chain=$chainFile fullchain=$fullchainFile" "INFO"

    return [pscustomobject]@{
        CertPem            = $certFile
        PrivateKey         = $keyFile
        ChainPem           = $chainFile
        FullchainPem       = $fullchainFile
        OutputDir          = $OutputDir
        ChainLikelyMissing = $chainLikelyMissing
    }
}

# ----------------------------
# Load PFX cert to extract CN (Convert Existing flow)
# ----------------------------
function Get-CertFromPfxFile {
    param(
        [Parameter(Mandatory)][string]$PfxFile,
        [Parameter(Mandatory)][securestring]$Password
    )

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    try { $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }

    try {
        $x = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $x.Import(
            $PfxFile,
            $plain,
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet
        )
        return $x
    } catch {
        Write-Log "Failed to load cert from PFX for CN extraction: $($_.Exception.Message)" "WARN"
        return $null
    }
}

# ----------------------------
# UI Construction
# ----------------------------
$form = New-Object System.Windows.Forms.Form
$form.Text = "$ScriptName v$ScriptVersion"
$form.Size = New-Object System.Drawing.Size(950, 800)
$form.StartPosition = "CenterScreen"

$lblInfo = New-Object System.Windows.Forms.Label
$lblInfo.Text = "Select a certificate from Personal stores (User/Computer). Only certs with private keys can be exported to PFX."
$lblInfo.AutoSize = $true
$lblInfo.Location = New-Object System.Drawing.Point(12, 12)
$form.Controls.Add($lblInfo)

# ListView
$list = New-Object System.Windows.Forms.ListView
$list.View = "Details"
$list.FullRowSelect = $true
$list.GridLines = $true
$list.Location = New-Object System.Drawing.Point(12, 40)
$list.Size = New-Object System.Drawing.Size(910, 380)

@("Store","FriendlyName","Subject","Thumbprint","Expires","HasPrivateKey") | ForEach-Object {
    $col = New-Object System.Windows.Forms.ColumnHeader
    $col.Text = $_
    $col.Width = switch ($_) {
        "Store" { 110 }
        "FriendlyName" { 170 }
        "Subject" { 230 }
        "Thumbprint" { 240 }
        "Expires" { 110 }
        "HasPrivateKey" { 90 }
        default { 120 }
    }
    $list.Columns.Add($col) | Out-Null
}
$form.Controls.Add($list)

# OpenSSL path controls
$lblOpenSsl = New-Object System.Windows.Forms.Label
$lblOpenSsl.Text = "OpenSSL path:"
$lblOpenSsl.AutoSize = $true
$lblOpenSsl.Location = New-Object System.Drawing.Point(12, 435)
$form.Controls.Add($lblOpenSsl)

$txtOpenSsl = New-Object System.Windows.Forms.TextBox
$txtOpenSsl.Location = New-Object System.Drawing.Point(110, 432)
$txtOpenSsl.Size = New-Object System.Drawing.Size(650, 25)
$form.Controls.Add($txtOpenSsl)

$btnBrowseOpenSsl = New-Object System.Windows.Forms.Button
$btnBrowseOpenSsl.Text = "Browse..."
$btnBrowseOpenSsl.Location = New-Object System.Drawing.Point(770, 430)
$btnBrowseOpenSsl.Size = New-Object System.Drawing.Size(75, 28)
$form.Controls.Add($btnBrowseOpenSsl)

# Buttons
$btnRefresh = New-Object System.Windows.Forms.Button
$btnRefresh.Text = "Refresh List"
$btnRefresh.Location = New-Object System.Drawing.Point(12, 475)
$btnRefresh.Size = New-Object System.Drawing.Size(120, 35)
$form.Controls.Add($btnRefresh)

$btnExportPfxOnly = New-Object System.Windows.Forms.Button
$btnExportPfxOnly.Text = "Export Selected → PFX only"
$btnExportPfxOnly.Location = New-Object System.Drawing.Point(140, 475)
$btnExportPfxOnly.Size = New-Object System.Drawing.Size(200, 35)
$form.Controls.Add($btnExportPfxOnly)

$btnExport = New-Object System.Windows.Forms.Button
$btnExport.Text = "Export Selected → PFX → Linux files"
$btnExport.Location = New-Object System.Drawing.Point(350, 475)
$btnExport.Size = New-Object System.Drawing.Size(270, 35)
$form.Controls.Add($btnExport)

$btnConvertExisting = New-Object System.Windows.Forms.Button
$btnConvertExisting.Text = "Convert Existing PFX → Linux files"
$btnConvertExisting.Location = New-Object System.Drawing.Point(630, 475)
$btnConvertExisting.Size = New-Object System.Drawing.Size(292, 35)
$form.Controls.Add($btnConvertExisting)

# NEW: Naming rules info label
$lblNamingRules = New-Object System.Windows.Forms.Label
$lblNamingRules.AutoSize = $false
$lblNamingRules.Size = New-Object System.Drawing.Size(910, 50)
$lblNamingRules.Location = New-Object System.Drawing.Point(12, 515)
$lblNamingRules.ForeColor = [System.Drawing.Color]::DimGray
$lblNamingRules.Text =
    "Linux export naming rules: Folder = Common Name (CN). " +
    "Files: <name>-cert.pem (leaf cert), <name>-privkey.key (private key), " +
    "<name>-chain.cer (intermediates), <name>-fullchain.cer (leaf+intermediates)."
$form.Controls.Add($lblNamingRules)

# Progress bar
$progress = New-Object System.Windows.Forms.ProgressBar
$progress.Location = New-Object System.Drawing.Point(12, 570)
$progress.Size = New-Object System.Drawing.Size(910, 18)
$progress.Minimum = 0
$progress.Maximum = 100
$progress.Value = 0
$form.Controls.Add($progress)

$lblProgress = New-Object System.Windows.Forms.Label
$lblProgress.Text = "Idle."
$lblProgress.AutoSize = $true
$lblProgress.Location = New-Object System.Drawing.Point(12, 592)
$form.Controls.Add($lblProgress)

# Status box
$txtStatus = New-Object System.Windows.Forms.TextBox
$txtStatus.Multiline = $true
$txtStatus.ReadOnly = $true
$txtStatus.ScrollBars = "Vertical"
$txtStatus.Location = New-Object System.Drawing.Point(12, 615)
$txtStatus.Size = New-Object System.Drawing.Size(910, 110)
$form.Controls.Add($txtStatus)

# Footer with version
$lblFooter = New-Object System.Windows.Forms.Label
$lblFooter.Text = "$ScriptName v$ScriptVersion"
$lblFooter.AutoSize = $true
$lblFooter.ForeColor = [System.Drawing.Color]::Gray
$lblFooter.Location = New-Object System.Drawing.Point(12, 735)
$form.Controls.Add($lblFooter)

# ----------------------------
# UI Helper functions
# ----------------------------
function Write-Status {
    param([string]$msg)
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $txtStatus.AppendText("[$timestamp] $msg`r`n")
    Write-Log $msg "INFO"
}

function Set-Progress {
    param([int]$Value, [string]$Text)
    if ($Value -lt 0) { $Value = 0 }
    if ($Value -gt 100) { $Value = 100 }
    $progress.Value = $Value
    if ($Text) { $lblProgress.Text = $Text }
    $form.Refresh()
}

function Set-UiBusy {
    param([bool]$Busy)
    $btnRefresh.Enabled          = -not $Busy
    $btnExport.Enabled           = -not $Busy
    $btnExportPfxOnly.Enabled    = -not $Busy
    $btnConvertExisting.Enabled  = -not $Busy
    $btnBrowseOpenSsl.Enabled    = -not $Busy
}

function Warn-IfChainMissingUI {
    param($ResultObject)
    if ($ResultObject -and $ResultObject.ChainLikelyMissing) {
        [System.Windows.Forms.MessageBox]::Show(
            "Warning: The generated chain.cer looks empty or very small.`r`n`r`n" +
            "This often means your PFX does not include intermediate certificates.`r`n" +
            "If your Linux service needs a full chain, download the intermediates from your CA " +
            "and append them to build a complete fullchain.cer.",
            "Chain may be missing",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        ) | Out-Null
    }
}

# ----------------------------
# Auto-detect OpenSSL
# ----------------------------
$autoOpenSsl = Get-OpenSslPath
if ($autoOpenSsl) { $txtOpenSsl.Text = $autoOpenSsl }

# ----------------------------
# Load cert list
# ----------------------------
function Load-CertList {
    Set-Progress -Value 5 -Text "Loading certificates..."
    $list.Items.Clear()

    $certs = Get-PersonalStoreCerts | Sort-Object Store, Subject
    foreach ($c in $certs) {
        $item = New-Object System.Windows.Forms.ListViewItem($c.Store)
        $item.SubItems.Add($c.FriendlyName) | Out-Null
        $item.SubItems.Add($c.Subject) | Out-Null
        $item.SubItems.Add($c.Thumbprint) | Out-Null
        $item.SubItems.Add(($c.NotAfter.ToString("yyyy-MM-dd"))) | Out-Null
        $item.SubItems.Add([string]$c.HasPrivateKey) | Out-Null
        $item.Tag = $c
        $list.Items.Add($item) | Out-Null
    }

    Write-Status "Loaded $($certs.Count) certificates from User/Computer Personal stores."
    Set-Progress -Value 0 -Text "Idle."
}

# ----------------------------
# Browse OpenSSL (single handler)
# ----------------------------
$btnBrowseOpenSsl.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = "OpenSSL (openssl.exe)|openssl.exe|All files (*.*)|*.*"
    $dlg.InitialDirectory = (Get-Location).Path
    if ($dlg.ShowDialog() -eq "OK") {
        $txtOpenSsl.Text = $dlg.FileName
        Write-Status "OpenSSL path set to: $($dlg.FileName)"
    }
})

# Refresh
$btnRefresh.Add_Click({ Load-CertList })

# ----------------------------
# Selection validation
# ----------------------------
function Get-SelectedCertOrWarn {
    if ($list.SelectedItems.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "Select a certificate first.",
            "No selection",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
        return $null
    }

    $selected = $list.SelectedItems[0].Tag
    Write-Log "Selected cert: Store=$($selected.Store) Subject=$($selected.Subject) Thumbprint=$($selected.Thumbprint) HasPrivateKey=$($selected.HasPrivateKey)" "DEBUG"

    if (-not $selected.HasPrivateKey) {
        [System.Windows.Forms.MessageBox]::Show(
            "The selected certificate does not have a private key. Cannot export to PFX.",
            "No private key",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        ) | Out-Null
        return $null
    }

    return $selected
}

# ----------------------------
# Button: Export Selected → PFX only
# ----------------------------
$btnExportPfxOnly.Add_Click({
    Set-UiBusy -Busy $true

    try {
        Set-Progress -Value 0 -Text "Starting PFX export..."

        $selected = Get-SelectedCertOrWarn
        if (-not $selected) { return }

        Set-Progress -Value 20 -Text "Choosing PFX output..."

        $save = New-Object System.Windows.Forms.SaveFileDialog
        $save.Filter = "PFX files (*.pfx)|*.pfx|All files (*.*)|*.*"
        $save.InitialDirectory = (Get-Location).Path

        $safeName = ($selected.Subject -replace '[^\w\.-]+','_')
        if ([string]::IsNullOrWhiteSpace($safeName)) { $safeName = $selected.Thumbprint }
        $save.FileName = "$safeName.pfx"

        if ($save.ShowDialog() -ne "OK") { return }

        $pfxPath = $save.FileName

        $pfxPath = Get-SafeExportPath -Path $pfxPath -Label "PFX file"
        if (-not $pfxPath) {
            Write-Status "PFX export cancelled by user."
            return
        }

        Set-Progress -Value 40 -Text "Waiting for password input..."

        $pwd = Get-PfxPasswordDialog `
            -Title "PFX Export Password" `
            -Prompt "Create and confirm a password to protect the exported PFX:" `
            -RequireConfirm $true

        if (-not $pwd) {
            Write-Status "Password prompt cancelled or invalid."
            return
        }

        Set-Progress -Value 70 -Text "Exporting certificate to PFX..."
        Write-Status "Exporting certificate from $($selected.Store) store..."
        Export-SelectedCertToPfx -CertPath $selected.Path -PfxFilePath $pfxPath -Password $pwd
        Write-Status "PFX exported to: $pfxPath"

        Set-Progress -Value 100 -Text "Done."

        [System.Windows.Forms.MessageBox]::Show(
            "PFX export complete.`r`n`r`nFile:`r`n$pfxPath`r`n`r`nLog:`r`n$LogFile",
            "Done",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
    } catch {
        $err = $_.Exception.Message
        Write-Status "ERROR: $err"
        Write-Log $err "ERROR"
        [System.Windows.Forms.MessageBox]::Show(
            $err, "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
    } finally {
        Set-Progress -Value 0 -Text "Idle."
        Set-UiBusy -Busy $false
    }
})

# ----------------------------
# Button: Export Selected → PFX → Linux files
# ----------------------------
$btnExport.Add_Click({
    Set-UiBusy -Busy $true

    try {
        Set-Progress -Value 0 -Text "Starting export..."

        $selected = Get-SelectedCertOrWarn
        if (-not $selected) { return }

        $openSslPath = $txtOpenSsl.Text
        if ([string]::IsNullOrWhiteSpace($openSslPath) -or -not (Test-Path $openSslPath)) {
            [System.Windows.Forms.MessageBox]::Show(
                "OpenSSL.exe not found. Please set the OpenSSL path.",
                "OpenSSL missing",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            ) | Out-Null
            return
        }

        Set-Progress -Value 20 -Text "Choosing PFX output..."

        $save = New-Object System.Windows.Forms.SaveFileDialog
        $save.Filter = "PFX files (*.pfx)|*.pfx|All files (*.*)|*.*"
        $save.InitialDirectory = (Get-Location).Path

        $safeName = ($selected.Subject -replace '[^\w\.-]+','_')
        if ([string]::IsNullOrWhiteSpace($safeName)) { $safeName = $selected.Thumbprint }
        $save.FileName = "$safeName.pfx"

        if ($save.ShowDialog() -ne "OK") { return }

        $pfxPath = $save.FileName

        $pfxPath = Get-SafeExportPath -Path $pfxPath -Label "PFX file"
        if (-not $pfxPath) {
            Write-Status "PFX export cancelled by user."
            return
        }

        Set-Progress -Value 35 -Text "Waiting for password input..."

        $pwd = Get-PfxPasswordDialog `
            -Title "PFX Export Password" `
            -Prompt "Create and confirm a password to protect the exported PFX:`r`n(This will also be used to generate Linux files.)" `
            -RequireConfirm $true

        if (-not $pwd) {
            Write-Status "Password prompt cancelled or invalid."
            return
        }

        Set-Progress -Value 50 -Text "Exporting certificate to PFX..."
        Write-Status "Exporting certificate from $($selected.Store) store..."
        Export-SelectedCertToPfx -CertPath $selected.Path -PfxFilePath $pfxPath -Password $pwd
        Write-Status "PFX exported to: $pfxPath"

        # Folder based on CN
        $fallback = if ($selected.FriendlyName) { $selected.FriendlyName } else { $selected.Thumbprint }
        $folderName = Get-FolderNameForCert -CertObject $selected -FallbackName $fallback
        $exportDir = Ensure-ExportFolder -FolderName $folderName
        Write-Status "Linux export folder: $exportDir"

        # Base name for files = PFX base name
        $baseName = [IO.Path]::GetFileNameWithoutExtension($pfxPath)
        $baseName = Remove-InvalidFileNameChars -Name $baseName
        if (-not $baseName) { $baseName = "export" }

        Set-Progress -Value 75 -Text "Generating Linux files..."
        $result = Convert-PfxToLinuxPem -OpenSsl $openSslPath -PfxFile $pfxPath -Password $pwd -OutputDir $exportDir -BaseName $baseName

        Set-Progress -Value 90 -Text "Finalizing outputs..."
        Write-Status "Created:"
        Write-Status "  cert:      $($result.CertPem)"
        Write-Status "  privkey:   $($result.PrivateKey)"
        Write-Status "  chain:     $($result.ChainPem)"
        Write-Status "  fullchain: $($result.FullchainPem)"

        Set-Progress -Value 100 -Text "Done."
        Warn-IfChainMissingUI -ResultObject $result

        [System.Windows.Forms.MessageBox]::Show(
            "Export complete.`r`n`r`nFolder:`r`n$($result.OutputDir)`r`n`r`nLog:`r`n$LogFile",
            "Done",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
    } catch {
        $err = $_.Exception.Message
        Write-Status "ERROR: $err"
        Write-Log $err "ERROR"
        [System.Windows.Forms.MessageBox]::Show(
            $err, "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
    } finally {
        Set-Progress -Value 0 -Text "Idle."
        Set-UiBusy -Busy $false
    }
})

# ----------------------------
# Button: Convert Existing PFX → Linux files
# ----------------------------
$btnConvertExisting.Add_Click({
    Set-UiBusy -Busy $true

    try {
        Set-Progress -Value 0 -Text "Starting PFX conversion..."

        $openSslPath = $txtOpenSsl.Text
        if ([string]::IsNullOrWhiteSpace($openSslPath) -or -not (Test-Path $openSslPath)) {
            [System.Windows.Forms.MessageBox]::Show(
                "OpenSSL.exe not found. Please set the OpenSSL path.",
                "OpenSSL missing",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            ) | Out-Null
            return
        }

        Set-Progress -Value 20 -Text "Selecting PFX file..."
        $open = New-Object System.Windows.Forms.OpenFileDialog
        $open.Filter = "PFX files (*.pfx)|*.pfx|All files (*.*)|*.*"
        $open.InitialDirectory = (Get-Location).Path

        if ($open.ShowDialog() -ne "OK") { return }
        $pfxPath = $open.FileName

        Set-Progress -Value 35 -Text "Waiting for password input..."
        $pwd = Get-PfxPasswordDialog `
            -Title "PFX Password" `
            -Prompt "Enter and confirm the password for this PFX:`r`n(Needed to extract Linux files.)" `
            -RequireConfirm $true

        if (-not $pwd) {
            Write-Status "Password prompt cancelled or invalid."
            return
        }

        # Load cert for CN extraction
        $pfxCert = Get-CertFromPfxFile -PfxFile $pfxPath -Password $pwd
        $fallback = [IO.Path]::GetFileNameWithoutExtension($pfxPath)

        $folderName = Get-FolderNameForCert -CertObject $pfxCert -FallbackName $fallback
        $exportDir = Ensure-ExportFolder -FolderName $folderName
        Write-Status "Linux export folder: $exportDir"

        $baseName = Remove-InvalidFileNameChars -Name $fallback
        if (-not $baseName) { $baseName = "export" }

        Set-Progress -Value 75 -Text "Generating Linux files..."
        $result = Convert-PfxToLinuxPem -OpenSsl $openSslPath -PfxFile $pfxPath -Password $pwd -OutputDir $exportDir -BaseName $baseName

        Set-Progress -Value 90 -Text "Finalizing outputs..."
        Write-Status "Created:"
        Write-Status "  cert:      $($result.CertPem)"
        Write-Status "  privkey:   $($result.PrivateKey)"
        Write-Status "  chain:     $($result.ChainPem)"
        Write-Status "  fullchain: $($result.FullchainPem)"

        Set-Progress -Value 100 -Text "Done."
        Warn-IfChainMissingUI -ResultObject $result

        [System.Windows.Forms.MessageBox]::Show(
            "Conversion complete.`r`n`r`nFolder:`r`n$($result.OutputDir)`r`n`r`nLog:`r`n$LogFile",
            "Done",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
    } catch {
        $err = $_.Exception.Message
        Write-Status "ERROR: $err"
        Write-Log $err "ERROR"
        [System.Windows.Forms.MessageBox]::Show(
            $err, "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
    } finally {
        Set-Progress -Value 0 -Text "Idle."
        Set-UiBusy -Busy $false
    }
})

# ----------------------------
# OpenSSL Browse button already defined above
# ----------------------------

# ----------------------------
# Auto-detect OpenSSL path into UI
# ----------------------------
if ($autoOpenSsl) { $txtOpenSsl.Text = $autoOpenSsl }

# ----------------------------
# Initial load + show UI
# ----------------------------
Load-CertList
[void]$form.ShowDialog()
