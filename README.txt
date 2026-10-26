DNSCheck 1.0

Run DNSCheck.exe. Type a domain or URL, press Check (or Enter).
No installer, no admin rights, no files or registry writes, no dependencies.

Build from source (Linux or Windows, Go 1.22+, no third-party modules):
  windres -O coff -i app.rc -o rsrc_windows_amd64.syso
  GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -H=windowsgui" -o DNSCheck.exe .

To change the icon: replace assets/app.ico (16/32/48/256 px recommended) and rebuild.

Release signing
---------------
Windows releases should be Authenticode-signed with a certificate issued by a
trusted code-signing provider and timestamped before distribution. A SHA-256
checksum does not establish publisher identity and does not replace a
signature. The checked-in workflow builds and checksums the executable; signing
requires a protected certificate and private-key secret that is not stored in
this repository.

Privacy and network behavior
----------------------------
DNSCheck performs DNS lookups through the computer's configured resolver and
also queries Cloudflare (1.1.1.1) and Google Public DNS (8.8.8.8) over HTTPS.
The external reachability check sends the entered hostname to Globalping's
HTTPS API, which schedules HTTPS probes from a small number of remote locations.
This discloses the hostname to Globalping and its probe operators. Do not use
sensitive internal hostnames. DNSCheck only initiates outbound requests; it does
not listen for network connections. Before making local TCP connections, it
rejects private, loopback, link-local, multicast, and other non-unicast IPs,
including unsafe addresses in mixed DNS responses. Public DNS and external
checks currently cannot be disabled.

