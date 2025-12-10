<#
.SYNOPSIS
    CertStoreExporter - GUI tool to export a certificate (User/Computer Personal) to PFX
    and optionally generate Linux-ready PEM files using OpenSSL.
    Also supports converting an existing PFX to Linux PEM files.

.DESCRIPTION
    This WinForms tool:
      1) Enumerates certificates from:
         - Cert:\CurrentUser\My
         - Cert:\LocalMachine\My
      2) Lets you select a certificate with a private key
      3) Exports it to PFX using Export-PfxCertificate
      4) Optional: Uses OpenSSL to create:
         - cert.pem
         - privkey.pem
         - chain.pem
         - fullchain.pem
      5) Can also convert an existing PFX to the same PEM set

.VERSION
    1.5 - Renamed tool to CertStoreExporter (UI + log + internal name).
          Includes:
          - Export Selected → PFX only
          - Export Selected → PFX → Linux PEMs
          - Convert Existing PFX → Linux PEMs
          - GUI password confirmation
          - Verbose file logging
          - Progress indicator
          - OpenSSL auto-detect incl. C:\Program Files\OpenSSL-Win64\bin\openssl.exe
          - UI warning when chain appears missing/small

.AUTHOR
    Peter

.LAST UPDATED
    2025-12-10

.NOTES
    - The PFX password is used to feed OpenSSL when PEM generation is selected.
    - Output files are named based on the PFX filename to avoid collisions.
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ----------------------------
# Configuration
# ----------------------------
$ScriptName    = "CertStoreExporter"
$ScriptVersion = "1.5"
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
    } catch {
        # Logging failure shouldn't block UI
    }
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
# Helper: GUI Password Dialog (with confirm)
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
        if ($RequireConfirm) {
            $txt2.UseSystemPasswordChar = -not $chkShow.Checked
        }
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

    # Best-effort cleanup of plaintext UI buffers
    $txt1.Text = ""
    $txt2.Text = ""

    return $secure
}

# ----------------------------
# Helper: Find OpenSSL
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
# Helper: Load certs
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
# Helper: Export PFX
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
# Helper: Run OpenSSL with capture
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
# Helper: Convert PFX -> PEM set
# ----------------------------
function Convert-PfxToLinuxPem {
    param(
        [Parameter(Mandatory)][string]$OpenSsl,
        [Parameter(Mandatory)][string]$PfxFile,
        [Parameter(Mandatory)][securestring]$Password,
        [Parameter(Mandatory)][string]$OutputDir
    )

    Write-Log "Convert-PfxToLinuxPem start. PfxFile=$PfxFile OutputDir=$OutputDir" "INFO"

    if (!(Test-Path $OpenSsl)) { throw "OpenSSL not found at: $OpenSsl" }
    if (!(Test-Path $PfxFile)) { throw "PFX file not found: $PfxFile" }

    if (!(Test-Path $OutputDir)) {
        Write-Log "OutputDir does not exist. Creating: $OutputDir" "DEBUG"
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    $base = [IO.Path]::GetFileNameWithoutExtension($PfxFile)

    $certPem      = Join-Path $OutputDir "$base-cert.pem"
    $keyPem       = Join-Path $OutputDir "$base-privkey.pem"
    $chainPem     = Join-Path $OutputDir "$base-chain.pem"
    $fullchainPem = Join-Path $OutputDir "$base-fullchain.pem"

    # Convert SecureString password for -passin usage
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    try { $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }

    $passArgs = @("-passin", "pass:$plain")

    # 1) cert.pem (leaf)
    Invoke-OpenSsl -OpenSsl $OpenSsl -Args @(
        "pkcs12","-in",$PfxFile,"-clcerts","-nokeys","-out",$certPem
    ) + $passArgs | Out-Null

    # 2) privkey.pem
    Invoke-OpenSsl -OpenSsl $OpenSsl -Args @(
        "pkcs12","-in",$PfxFile,"-nocerts","-nodes","-out",$keyPem
    ) + $passArgs | Out-Null

    # 3) chain.pem
    Invoke-OpenSsl -OpenSsl $OpenSsl -Args @(
        "pkcs12","-in",$PfxFile,"-cacerts","-nokeys","-out",$chainPem
    ) + $passArgs | Out-Null

    # 4) fullchain.pem
    $certContent  = Get-Content -Path $certPem  -ErrorAction SilentlyContinue
    $chainContent = Get-Content -Path $chainPem -ErrorAction SilentlyContinue
    @($certContent + $chainContent) | Set-Content -Path $fullchainPem -Encoding ascii

    $chainLikelyMissing = $false
    try {
        if (-not (Test-Path $chainPem) -or (Get-Item $chainPem).Length -lt 50) {
            $chainLikelyMissing = $true
            Write-Log "chain.pem seems empty/small. PFX may not include intermediates." "WARN"
        }
    } catch {}

    Write-Log "PEM generation completed: cert=$certPem key=$keyPem chain=$chainPem fullchain=$fullchainPem" "INFO"

    return [pscustomobject]@{
        CertPem            = $certPem
        PrivateKey         = $keyPem
        ChainPem           = $chainPem
        FullchainPem       = $fullchainPem
        OutputDir          = $OutputDir
        ChainLikelyMissing = $chainLikelyMissing
    }
}

# ----------------------------
# UI Construction
# ----------------------------
$form = New-Object System.Windows.Forms.Form
$form.Text = "$ScriptName v$ScriptVersion"
$form.Size = New-Object System.Drawing.Size(950, 730)
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
$btnExport.Text = "Export Selected → PFX → Linux PEMs"
$btnExport.Location = New-Object System.Drawing.Point(350, 475)
$btnExport.Size = New-Object System.Drawing.Size(270, 35)
$form.Controls.Add($btnExport)

$btnConvertExisting = New-Object System.Windows.Forms.Button
$btnConvertExisting.Text = "Convert Existing PFX → Linux PEMs"
$btnConvertExisting.Location = New-Object System.Drawing.Point(630, 475)
$btnConvertExisting.Size = New-Object System.Drawing.Size(292, 35)
$form.Controls.Add($btnConvertExisting)

# Progress bar
$progress = New-Object System.Windows.Forms.ProgressBar
$progress.Location = New-Object System.Drawing.Point(12, 520)
$progress.Size = New-Object System.Drawing.Size(910, 18)
$progress.Minimum = 0
$progress.Maximum = 100
$progress.Value = 0
$form.Controls.Add($progress)

# Progress label
$lblProgress = New-Object System.Windows.Forms.Label
$lblProgress.Text = "Idle."
$lblProgress.AutoSize = $true
$lblProgress.Location = New-Object System.Drawing.Point(12, 542)
$form.Controls.Add($lblProgress)

# Status box
$txtStatus = New-Object System.Windows.Forms.TextBox
$txtStatus.Multiline = $true
$txtStatus.ReadOnly = $true
$txtStatus.ScrollBars = "Vertical"
$txtStatus.Location = New-Object System.Drawing.Point(12, 565)
$txtStatus.Size = New-Object System.Drawing.Size(910, 105)
$form.Controls.Add($txtStatus)

function Write-Status {
    param([string]$msg)
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "[$timestamp] $msg"
    $txtStatus.AppendText("$line`r`n")
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
    $btnRefresh.Enabled         = -not $Busy
    $btnExport.Enabled          = -not $Busy
    $btnExportPfxOnly.Enabled   = -not $Busy
    $btnConvertExisting.Enabled = -not $Busy
    $btnBrowseOpenSsl.Enabled   = -not $Busy
}

function Warn-IfChainMissingUI {
    param($ResultObject)
    if ($ResultObject -and $ResultObject.ChainLikelyMissing) {
        [System.Windows.Forms.MessageBox]::Show(
            "Warning: The generated chain.pem looks empty or very small.`r`n`r`n" +
            "This often means your PFX does not include intermediate certificates.`r`n" +
            "If your Linux service needs a full chain, download the intermediates from your CA " +
            "and append them to build a complete fullchain.pem.",
            "Chain may be missing",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        ) | Out-Null
    }
}

# Auto-detect OpenSSL
$autoOpenSsl = Get-OpenSslPath
if ($autoOpenSsl) { $txtOpenSsl.Text = $autoOpenSsl }

# Load certs
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

# Browse OpenSSL
$btnBrowseOpenSsl.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = "OpenSSL (openssl.exe)|openssl.exe|All files (*.*)|*.*"
    $dlg.InitialDirectory = (Get-Location).Path
    if ($dlg.ShowDialog() -eq "OK") {
        $txtOpenSsl.Text = $dlg.FileName
        Write-Status "OpenSSL path set to: $($dlg.FileName)"
    }
})

# Refresh click
$btnRefresh.Add_Click({ Load-CertList })

# Shared selection validation
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
# Button: PFX only export
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

        Set-Progress -Value 40 -Text "Waiting for password input..."

        $pwd1 = Get-PfxPasswordDialog `
            -Title "PFX Export Password" `
            -Prompt "Create and confirm a password to protect the exported PFX:" `
            -RequireConfirm $true

        if (-not $pwd1) {
            Write-Status "Password prompt cancelled or invalid."
            [System.Windows.Forms.MessageBox]::Show(
                "Password was cancelled or invalid. Aborting.",
                "Password required",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            ) | Out-Null
            return
        }

        Set-Progress -Value 70 -Text "Exporting certificate to PFX..."
        Write-Status "Exporting certificate from $($selected.Store) store..."
        Export-SelectedCertToPfx -CertPath $selected.Path -PfxFilePath $pfxPath -Password $pwd1
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
            $err,
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null

    } finally {
        Set-Progress -Value 0 -Text "Idle."
        Set-UiBusy -Busy $false
    }
})

# ----------------------------
# Button: Selected cert → PFX → Linux PEMs
# ----------------------------
$btnExport.Add_Click({
    Set-UiBusy -Busy $true

    try {
        Set-Progress -Value 0 -Text "Starting export..."

        $selected = Get-SelectedCertOrWarn
        if (-not $selected) { return }

        Set-Progress -Value 10 -Text "Validating OpenSSL..."

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

        Set-Progress -Value 30 -Text "Waiting for password input..."

        $pwd1 = Get-PfxPasswordDialog `
            -Title "PFX Export Password" `
            -Prompt "Create and confirm a password to protect the exported PFX:`r`n(This will also be used to generate Linux PEM files.)" `
            -RequireConfirm $true

        if (-not $pwd1) {
            Write-Status "Password prompt cancelled or invalid."
            [System.Windows.Forms.MessageBox]::Show(
                "Password was cancelled or invalid. Aborting.",
                "Password required",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            ) | Out-Null
            return
        }

        Set-Progress -Value 45 -Text "Exporting certificate to PFX..."
        Write-Status "Exporting certificate from $($selected.Store) store..."
        Export-SelectedCertToPfx -CertPath $selected.Path -PfxFilePath $pfxPath -Password $pwd1
        Write-Status "PFX exported to: $pfxPath"

        $outputDir = Split-Path $pfxPath -Parent
        if ([string]::IsNullOrWhiteSpace($outputDir)) { $outputDir = (Get-Location).Path }

        Set-Progress -Value 70 -Text "Running OpenSSL conversions..."
        Write-Status "Generating Linux PEM files..."
        $result = Convert-PfxToLinuxPem -OpenSsl $openSslPath -PfxFile $pfxPath -Password $pwd1 -OutputDir $outputDir

        Set-Progress -Value 90 -Text "Finalizing outputs..."
        Write-Status "Created:"
        Write-Status "  cert.pem:      $($result.CertPem)"
        Write-Status "  privkey.pem:   $($result.PrivateKey)"
        Write-Status "  chain.pem:     $($result.ChainPem)"
        Write-Status "  fullchain.pem: $($result.FullchainPem)"

        Set-Progress -Value 100 -Text "Done."

        Warn-IfChainMissingUI -ResultObject $result

        [System.Windows.Forms.MessageBox]::Show(
            "Export complete.`r`n`r`ncert.pem`r`nprivkey.pem`r`nchain.pem`r`nfullchain.pem`r`n`r`nFolder:`r`n$($result.OutputDir)`r`n`r`nLog:`r`n$LogFile",
            "Done",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null

    } catch {
        $err = $_.Exception.Message
        Write-Status "ERROR: $err"
        Write-Log $err "ERROR"

        [System.Windows.Forms.MessageBox]::Show(
            $err,
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null

    } finally {
        Set-Progress -Value 0 -Text "Idle."
        Set-UiBusy -Busy $false
    }
})

# ----------------------------
# Button: Convert Existing PFX → Linux PEMs
# ----------------------------
$btnConvertExisting.Add_Click({
    Set-UiBusy -Busy $true

    try {
        Set-Progress -Value 0 -Text "Starting PFX conversion..."

        Set-Progress -Value 10 -Text "Validating OpenSSL..."
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

        Set-Progress -Value 30 -Text "Waiting for password input..."

        $pwd1 = Get-PfxPasswordDialog `
            -Title "PFX Password" `
            -Prompt "Enter and confirm the password for this PFX:`r`n(Needed to extract Linux PEM files.)" `
            -RequireConfirm $true

        if (-not $pwd1) {
            Write-Status "Password prompt cancelled or invalid."
            [System.Windows.Forms.MessageBox]::Show(
                "Password was cancelled or invalid. Aborting.",
                "Password required",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            ) | Out-Null
            return
        }

        $outputDir = Split-Path $pfxPath -Parent
        if ([string]::IsNullOrWhiteSpace($outputDir)) { $outputDir = (Get-Location).Path }

        Set-Progress -Value 70 -Text "Running OpenSSL conversions..."
        Write-Status "Converting existing PFX to Linux PEM files..."
        $result = Convert-PfxToLinuxPem -OpenSsl $openSslPath -PfxFile $pfxPath -Password $pwd1 -OutputDir $outputDir

        Set-Progress -Value 90 -Text "Finalizing outputs..."
        Write-Status "Created:"
        Write-Status "  cert.pem:      $($result.CertPem)"
        Write-Status "  privkey.pem:   $($result.PrivateKey)"
        Write-Status "  chain.pem:     $($result.ChainPem)"
        Write-Status "  fullchain.pem: $($result.FullchainPem)"

        Set-Progress -Value 100 -Text "Done."

        Warn-IfChainMissingUI -ResultObject $result

        [System.Windows.Forms.MessageBox]::Show(
            "Conversion complete.`r`n`r`ncert.pem`r`nprivkey.pem`r`nchain.pem`r`nfullchain.pem`r`n`r`nFolder:`r`n$($result.OutputDir)`r`n`r`nLog:`r`n$LogFile",
            "Done",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null

    } catch {
        $err = $_.Exception.Message
        Write-Status "ERROR: $err"
        Write-Log $err "ERROR"

        [System.Windows.Forms.MessageBox]::Show(
            $err,
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null

    } finally {
        Set-Progress -Value 0 -Text "Idle."
        Set-UiBusy -Busy $false
    }
})

# Initial load
Load-CertList

# Show UI
[void]$form.ShowDialog()
