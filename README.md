## CertificateExporter

**CertificateExporter** is a lightweight Windows GUI tool that helps you export certificates from the Windows Certificate Store and prepare Linux-ready TLS files with consistent naming and safe export handling.

### Who it's for
Targets IT Pros and admins who need a fast, repeatable way to move certificates from Windows environments to Linux-based services (NGINX, Apache, HAProxy, etc.) or just export a certificate to a .pfx file.

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
Generates:

- `<name>-cert.pem` *(leaf certificate)*
- `<name>-privkey.key` *(private key)*
- `<name>-chain.cer` *(intermediate chain)*
- `<name>-fullchain.cer` *(leaf + intermediates)*

### Folder naming
- Export folder naming is based on the certificate **SSL Common Name (CN)** to keep files organized and human-readable.

### Safe overwrite behavior
- Prompts if export files exist.
- Allows:
  - **Overwrite**
  - **Add timestamp**
- Supports canceling without partial exports.

### User experience
- **Progress indicator** built-in for clear feedback during export/conversion steps.
- **Password prompts are GUI-based** (no console prompts), with confirmation and optional show/hide.

### Logging
Verbose logging runs behind the scenes:

- Logs are automatically stored in `.\Logs`
- New runs archive older logs with timestamps

### OpenSSL detection
- Tries system **PATH** first.
- Falls back to common install locations including:
  - `C:\Program Files\OpenSSL-Win64\bin`

### Minimal footprint
- Single PowerShell script
- Uses WinForms (no additional UI frameworks required)

### Best practice
- Running as **Admin** is recommended if you plan to export from the **LocalMachine** store to avoid access issues.
