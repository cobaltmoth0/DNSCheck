DNSCheck 1.0

Run DNSCheck.exe. Type a domain or URL, press Check (or Enter).
No installer, no admin rights, no files or registry writes, no dependencies.

Build from source (Linux or Windows, Go 1.22+, no third-party modules):
  windres -O coff -i app.rc -o rsrc_windows_amd64.syso
  GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -H=windowsgui" -o DNSCheck.exe .

To change the icon: replace assets/app.ico (16/32/48/256 px recommended) and rebuild.
