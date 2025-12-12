## CertificateExporter — Copilot / AI agent instructions

Short summary
- This repository is a single-file Windows PowerShell GUI tool (`Start-CertificateExporter-GUI.ps1`) that enumerates certificates from the Windows Personal stores, exports PFX files and optionally converts PFX to Linux-ready certificate/key files using OpenSSL.

What to know up front
- Primary entrypoint: `Start-CertificateExporter-GUI.ps1` (WinForms + helper functions). Treat this as the authoritative implementation rather than searching for build artifacts.
- Runtime: Windows PowerShell 5.1 (recommended for WinForms). PowerShell 7+ on Windows may work but assume WinForms behaviors target Windows PowerShell unless a change is explicitly added.
- OpenSSL: The script auto-detects `openssl.exe` via `Get-OpenSslPath`. If not found, the UI exposes an `OpenSSL path` field used by `Convert-PfxToLinuxFiles`.

High-level architecture & important flows
- Single-script UI app (no separate backend): UI elements, event wiring, helpers and CLI-like functions live in `Start-CertificateExporter-GUI.ps1`.
- Data flow: UI selects certificate -> `Export-SelectedCertToPfx` creates PFX using `Export-PfxCertificate` -> optional `Convert-PfxToLinuxFiles` calls OpenSSL to produce Linux files -> results logged and displayed.
- Logging: All runs write to `./Logs/$ScriptName.log`. Older logs are archived with timestamps via `Initialize-Log`.

Key implementation patterns to follow
- Use existing helper functions whenever possible: `Get-FolderNameForCert`, `Remove-InvalidFileNameChars`, `Ensure-ExportFolder`, `Get-PfxPasswordDialog`, `Get-OpenSslPath`, `Convert-PfxToLinuxFiles`.
- Error handling uses try/catch with `Write-Log` and user dialogs in UI event handlers — preserve that pattern and log with `Write-Log` for traceability.
- User-interactive flows use WinForms dialogs (MessageBox/SaveFileDialog/OpenFileDialog). When adding automated paths for CI or headless runs, provide non-interactive alternatives (e.g., parameters or environment vars) and keep UI code untouched unless adding a clear feature flag.
- OpenSSL invocation is wrapped by `Invoke-OpenSsl`, which checks `$LASTEXITCODE` and throws on failures — use it for any OpenSSL calls.

Naming and file conventions
- Export folder naming: computed by `Get-FolderNameForCert` (prefers CN from the cert subject, falls back to FriendlyName or Thumbprint). Keep this logic consistent if adding new export modes.
- Linux output filenames: `<name>-cert.pem`, `<name>-privkey.key`, `<name>-chain.cer`, `<name>-fullchain.cer` — created by `Resolve-LinuxSetPaths` and `Convert-PfxToLinuxFiles`.
- Log location: `./Logs` relative to the working directory.

Running & testing locally (developer workflow)
- Run interactively (recommended):
  ```powershell
  # Ensure script execution allowed for the session
  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process

  # Run with default PowerShell (recommended on Windows)
  pwsh -File .\Start-CertificateExporter-GUI.ps1
  ```
- Permissions: To access `LocalMachine\My` store or private keys with ACLs, run PowerShell as Administrator.
- OpenSSL: If OpenSSL is not on PATH, set the path in the UI or install OpenSSL to `C:\Program Files\OpenSSL-Win64\bin` (one of the script's detection paths).

What to avoid changing without tests
- Avoid modifying UI layout code unless user-facing behavior is well validated manually — the script is a desktop utility and visual regressions are easy to introduce.
- Avoid changing CN extraction / filename sanitization logic (`Get-CommonNameFromSubject`, `Remove-InvalidFileNameChars`) without validating on a set of real certificate subjects.

Examples of targeted changes an AI can safely perform
- Small refactor: extract repeated OpenSSL candidate list into a constant near configuration and update `Get-OpenSslPath` to use it.
- Add a non-interactive CLI mode: add a `-Headless` parameter that accepts `-InputPfx`, `-OutputDir`, `-OpenSslPath`, and `-Password` then call `Convert-PfxToLinuxFiles` directly (ensure secure handling of password strings and clearly document the mode in `README.md`).

Files to inspect for deeper context
- `Start-CertificateExporter-GUI.ps1` — entire app and logic.
- `README.md` — user-facing requirements and assumptions (OpenSSL, PowerShell versions, admin guidance).
- `LICENSE` — rights for copying/modifying.

If you modify code
- Preserve `Write-Log` usage and log file behavior. Add new log lines for major state transitions.
- Keep UI dialogs intact for user flows; if adding headless features, provide clear opt-in parameters and minimal changes to the main UI flow.

Questions for repository owner
- Do you want a headless / CI-friendly conversion mode added? If so, specify the preferred secure password input (file, env var, or protected store).
- Any preferred OpenSSL version constraints to validate new behavior against?

End of agent instructions
