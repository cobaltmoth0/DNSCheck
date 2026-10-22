DNSCheck 1.0

Run DNSCheck.exe. Type a domain or URL, press Check (or Enter).
No installer, no admin rights, no files or registry writes, no dependencies.

Build from source (Linux or Windows, Go 1.22+, no third-party modules):
  windres -O coff -i app.rc -o rsrc_windows_amd64.syso
  GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -H=windowsgui" -o DNSCheck.exe .

To change the icon: replace assets/app.ico (16/32/48/256 px recommended) and rebuild.

Privacy and network behavior
----------------------------
DNSCheck performs DNS lookups through the computer's configured resolver and
also queries Cloudflare (1.1.1.1) and Google Public DNS (8.8.8.8) over HTTPS.
The external reachability check sends the entered hostname, as an HTTPS URL,
to check-host.net so remote nodes can test it. These requests disclose the
hostname to those third parties. Do not use this tool with sensitive internal
hostnames if that disclosure is not acceptable. The application currently
does not provide a switch to disable the public DNS or external checks.

