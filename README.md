# CertificateExporter

**CertificateExporter** is a lightweight Windows GUI tool that helps you export certificates from the Windows Certificate Store and prepare Linux-ready PEM files with consistent naming and safe export handling.

> Entry point script: **`Start-CertificateExporter-GUI.ps1`**

---

## Quick start

1. Install **OpenSSL for Windows (Win64)** (see Requirements below).
2. Clone or download this repository.
3. Run **`Start-CertificateExporter-GUI.ps1`** in PowerShell.
4. Select a certificate → choose an export workflow → follow the prompts.

---

## Who it's for

Targets IT Pros and admins who need a fast, repeatable way to move certificates from Windows environments to Linux-based services such as:

- NGINX  
- Apache  
- HAProxy  
- Other TLS-terminating services on Linux

---

## Key capabilities

### Certificate sources

Reads certificates from:

- **CurrentUser\Personal** (`Cert:\CurrentUser\My`)
- **LocalMachine\Personal** (`Cert:\LocalMachine\My`)

### Validation

- Filters for **certificates with private keys** (required for PFX export).

### Export workflows

- **Export Selected → PFX only**
- **Export Selected → PFX → Linux files**
- **Convert Existing PFX → Linux files**

### Linux output (via OpenSSL)

Generates the classic web-server file set:

- `<name>-cert.pem` – *leaf certificate*
- `<name>-privkey.key` – *private key*
- `<name>-chain.cer` – *intermediate certificate chain*
- `<name>-fullchain.cer` – *leaf + intermediate chain*

These are suitable for many common Linux-based reverse proxies and web servers.

### Folder naming

- Export folder naming is based on the certificate **SSL Common Name (CN)** to keep files organized and human-readable.
- Example: a cert with CN `bts.domain.com` will export into a folder:  
  `.\bts.domain.com\`

### Safe overwrite behavior

- Prompts if export files already exist.
- Allows:
  - **Overwrite** – replace existing files.
  - **Add timestamp** – keep existing files, write new ones with a timestamp suffix.
- Supports canceling without partial or inconsistent exports.

### User experience

- **Progress indicator** built in for clear feedback during export and conversion steps.
- **Password prompts are GUI-based** (no console prompts), with:
  - Password + confirmation
  - Optional *show/hide* toggle

### Logging

Verbose logging runs behind the scenes:

- Logs are automatically stored in `.\Logs`
- Each new run archives the previous log with a timestamped filename

Example log folder:

```text
.\Logs\
  CertificateExporter.log
  CertificateExporter-20251210-153202.log
