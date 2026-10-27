# DNSCheck
<img width="446" height="410" alt="image" src="https://github.com/user-attachments/assets/329e692d-b375-4ee5-8701-1adbf56380e0" />

A lightweight Windows utility that checks where a network block is happening.

Enter a domain or URL and DNSCheck runs a series of checks to work out whether the site is accessible or blocked, and which layer is responsible: the DNS filter, the firewall, or the destination itself.

## Features

- Classic Windows 95 style interface
- Checks DNS, DNS over HTTPS, TCP, TLS and HTTP
- Per-check status with response times
- Path graphic (PC, DNS, firewall, web) showing where the connection breaks
- Remote reachability test to tell a local block from a site that is down
- Single portable `.exe`, no installer

## Usage

 -Download the latest build from the **[Releases](https://github.com/pcktdrp/DNSCheck/releases)**.\
 -Type a domain or URL and press **Check**.

## Privacy

Domain names are sent to Cloudflare and Google for public DNS comparison, and to Globalping to test reachability from remote probes. 
**Do not enter sensitive internal hostnames.**

## Disclaimer

Results may be affected by filters, caches, proxies and CDNs. Treat them as diagnostic guidance, not a definitive answer.\
This network troubleshooting utility was built with AI collaboration to assist with network diagnostics. Please keep the following in mind before downloading:

  -**Unsigned Executable**: This tool does not currently have an expensive code-signing certificate attached.

  -**No Software Reputation**: Security software relies heavily on binary popularity metrics. Newer or niche tools naturally trigger automated alerts.
    
  -**False Positives**: Most antivirus programs will flag or block this program upon download.

