# WebReconSnipe

`WebReconSnipe` is a Bash-based reconnaissance tool designed to extract and analyze archived URLs from the Wayback Machine for one or multiple target domains. It filters for sensitive files, extracts potential vulnerabilities (secrets, SQLi, XSS, IDOR) using `gf`, validates live endpoints with `httpx-toolkit`, and optionally scans content for secrets using TruffleHog. Results are saved to a customizable output directory.

## Features
- Supports single domain or file-based multiple domains input.
- Fetches archived URLs via `waybackurls`.
- Filters for sensitive file extensions and keywords.
- Extracts secrets and vulnerabilities with `gf` patterns.
- Validates live URLs with `httpx-toolkit`.
- Optional secret scanning with TruffleHog.
- Customizable output directory.

## Prerequisites
- **Bash**: Compatible shell (Linux, macOS, WSL).
- **curl**: For fetching URLs.
- **waybackurls**: Fetch archived URLs.
- **gf**: Extract vulnerability patterns.
- **httpx-toolkit**: Validate live endpoints.
- **trufflehog**: Optional secret scanning.

## Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/webreconsnipe.git
   cd webreconsnipe
   chmod +x webreconsnipe

# Commands

Single Domain
./webreconsnipe -d https://www.tataplay.com -o my_output

Multiple Domains from File
./webreconsnipe -f domains.txt -o my_output

Skip TruffleHog
./webreconsnipe -d https://www.tataplay.com --skip-trufflehog

# Output
Results are saved in the specified output directory:

all_urls.txt: All archived URLs.
clean_urls.txt: Deduplicated URLs.
filtered_urls.txt: Sensitive files/keywords.
secrets_urls.txt, sqli_urls.txt, xss_urls.txt, idor.txt: Vulnerability-specific URLs.
live_urls.txt: Live endpoints (HTTP 200).
secrets_found.txt: TruffleHog findings (if enabled).
final_report.txt: Combined unique results.
