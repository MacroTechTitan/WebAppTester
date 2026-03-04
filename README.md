# WebAppTester

  **PrivSec Site Tester v1.0** by [Macro Tech Titan](https://macrotechtitan.com)

  A comprehensive website security and performance testing tool. Crawls your website and checks for security issues, exposed API keys, slow pages, broken links, open ports, missing security headers, SSL problems, and more.

  ## Installation

  ```bash
  pip install requests beautifulsoup4
  ```

  ## Usage

  ```bash
  python privsec-site-tester.py https://yoursite.com
  ```

  ### Options

  | Flag | Description |
  |------|-------------|
  | `--max-pages N` | Maximum pages to crawl (default: 100) |
  | `--timeout N` | Request timeout in seconds (default: 10) |
  | `--no-port-scan` | Skip port scanning |

  ## Tests Included

  - **SSL/TLS Certificate** — validity, expiration, protocol version
  - **Security Headers** — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
  - **API Key Exposure** — scans page source and JS files for leaked AWS, Stripe, GitHub tokens, JWTs, database URIs
  - **Sensitive File Exposure** — probes for `.env`, `.git`, config files, database dumps, admin panels
  - **Open Port Scan** — checks 24 common ports (MySQL, PostgreSQL, Redis, SSH, RDP, etc.)
  - **Broken Links** — crawls entire site, reports internal links returning 4xx/5xx
  - **Performance Analysis** — response time per page, flags slow pages (>3s)
  - **Cookie Security** — Secure, HttpOnly, SameSite flag checks
  - **Technology Detection** — identifies frameworks, CDNs, third-party services
  - **Full Site Crawl** — up to 100 pages (configurable)

  ## Output

  - Color-coded terminal output with severity ratings (Critical / High / Medium / Low / Info / Pass)
  - Overall letter grade (A through F)
  - JSON report file saved automatically

  ## License

  MIT License - Macro Tech Titan
  