# Python Port Scanner

A multithreaded TCP connect scanner written in Python using only the standard library. Built to learn how port scanning works at the socket level.

## Features
- TCP connect scan with configurable port ranges (`22,80,443` or `1-1024`)
- Multithreaded for speed (default 100 threads)
- Service name lookup for common ports
- Basic banner grabbing
- Optional results file output

## Usage
```bash
python3 portscanner.py scanme.nmap.org
python3 portscanner.py 192.168.1.1 -p 1-65535 -t 200
python3 portscanner.py localhost -p 22,80,443,8080 -o results.txt
```

| Option | Description | Default |
|--------|-------------|---------|
| `-p, --ports` | Ports to scan | `1-1024` |
| `-t, --threads` | Worker threads | `100` |
| `--timeout` | Connection timeout (seconds) | `0.5` |
| `-o, --output` | Save results to file | none |

## Example output
(Paste a screenshot or real output from your own scan here.)

## How it works
For each port, the scanner calls `connect_ex()` on a TCP socket. A return value of 0 means the three-way handshake completed, so the port is open. For open ports it tries to read a short banner and look up the service name.

## Limitations
- TCP connect scans only (no SYN/stealth scanning, no UDP)
- Full connect scans are easy for firewalls and IDS to detect
- Banner grabbing only works on services that speak first (SSH, FTP, SMTP)

## Ideas for next steps
- Add UDP scanning
- Add host discovery for a subnet
- Export to JSON or CSV
- Add service version detection

## Legal and ethical use
Only scan systems you own or have written permission to test. Unauthorized scanning may be illegal. `scanme.nmap.org` is provided by the Nmap project for practice; scan it lightly.
