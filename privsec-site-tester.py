#!/usr/bin/env python3
"""
PrivSec Site Tester v1.0
========================
Comprehensive website testing tool by Macro Tech Titan.
Tests security, performance, broken links, open ports, API key exposure, and more.

Usage:
    python privsec-site-tester.py https://yoursite.com

Requirements:
    pip install requests beautifulsoup4
"""

import sys
import os
import re
import json
import time
import socket
import ssl
import hashlib
import argparse
import urllib.parse
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    print("Missing dependencies. Install with:")
    print("  pip install requests beautifulsoup4")
    sys.exit(1)


VERSION = "1.0.0"
BANNER = f"""
╔══════════════════════════════════════════════════════════╗
║           PrivSec Site Tester v{VERSION}                    ║
║           by Macro Tech Titan                            ║
║           https://privsec.macrotechtitan.com              ║
╚══════════════════════════════════════════════════════════╝
"""

API_KEY_PATTERNS = [
    (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "API Key"),
    (r'(?:secret|password|passwd|pwd)\s*[:=]\s*["\']([^\s"\']{8,})["\']', "Secret/Password"),
    (r'(?:aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*["\']?(AKIA[0-9A-Z]{16})["\']?', "AWS Access Key"),
    (r'(?:aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?', "AWS Secret Key"),
    (r'sk[_-]live[_-][a-zA-Z0-9]{24,}', "Stripe Live Secret Key"),
    (r'sk[_-]test[_-][a-zA-Z0-9]{24,}', "Stripe Test Secret Key"),
    (r'pk[_-]live[_-][a-zA-Z0-9]{24,}', "Stripe Live Publishable Key"),
    (r'ghp_[a-zA-Z0-9]{36,}', "GitHub Personal Access Token"),
    (r'github_pat_[a-zA-Z0-9_]{22,}', "GitHub Fine-Grained Token"),
    (r'Bearer\s+[a-zA-Z0-9\-._~+/]+=*', "Bearer Token"),
    (r'(?:mongodb(?:\+srv)?://)[^\s<>"]+', "MongoDB Connection String"),
    (r'postgres(?:ql)?://[^\s<>"]+', "PostgreSQL Connection String"),
    (r'(?:PRIVATE KEY-----)', "Private Key"),
    (r'xox[baprs]-[a-zA-Z0-9-]+', "Slack Token"),
    (r'hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[a-zA-Z0-9]+', "Slack Webhook"),
    (r'(?:eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+)', "JWT Token"),
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9090, 27017]

SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD", "/wp-config.php", "/config.php",
    "/phpinfo.php", "/.htaccess", "/server-status", "/server-info",
    "/.well-known/security.txt", "/robots.txt", "/sitemap.xml",
    "/admin", "/administrator", "/wp-admin", "/wp-login.php",
    "/phpmyadmin", "/adminer.php", "/.DS_Store", "/backup.sql",
    "/database.sql", "/dump.sql", "/.svn/entries", "/web.config",
    "/.dockerenv", "/Dockerfile", "/docker-compose.yml",
    "/api/debug", "/api/test", "/graphql", "/_debug",
    "/swagger.json", "/api-docs", "/openapi.json",
]


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @staticmethod
    def disable():
        Colors.RED = Colors.GREEN = Colors.YELLOW = Colors.BLUE = ""
        Colors.MAGENTA = Colors.CYAN = Colors.WHITE = ""
        Colors.BOLD = Colors.DIM = Colors.RESET = ""


class Finding:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    PASS = "PASS"

    def __init__(self, category, severity, title, detail="", url=""):
        self.category = category
        self.severity = severity
        self.title = title
        self.detail = detail
        self.url = url

    def color(self):
        return {
            "CRITICAL": Colors.RED,
            "HIGH": Colors.RED,
            "MEDIUM": Colors.YELLOW,
            "LOW": Colors.CYAN,
            "INFO": Colors.BLUE,
            "PASS": Colors.GREEN,
        }.get(self.severity, Colors.WHITE)

    def __str__(self):
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "ℹ️ ", "PASS": "✅"}.get(self.severity, "")
        return f"{icon} [{self.severity}] {self.title}" + (f"\n   {self.detail}" if self.detail else "")


class SiteTester:
    def __init__(self, base_url, max_pages=100, timeout=10, threads=10, verbose=False):
        self.base_url = base_url.rstrip("/")
        self.parsed = urllib.parse.urlparse(self.base_url)
        self.domain = self.parsed.hostname
        self.max_pages = max_pages
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": f"PrivSec-SiteTester/{VERSION} (+https://privsec.macrotechtitan.com)"
        })
        self.visited = set()
        self.to_visit = set()
        self.findings = []
        self.page_times = []
        self.broken_links = []
        self.external_links = set()
        self.resources = defaultdict(list)
        self.start_time = None

    def log(self, msg, color=Colors.WHITE):
        if self.verbose:
            print(f"  {color}{msg}{Colors.RESET}")

    def add_finding(self, category, severity, title, detail="", url=""):
        self.findings.append(Finding(category, severity, title, detail, url))

    def run(self):
        self.start_time = time.time()
        print(BANNER)
        print(f"{Colors.BOLD}Target:{Colors.RESET} {self.base_url}")
        print(f"{Colors.BOLD}Domain:{Colors.RESET} {self.domain}")
        print(f"{Colors.BOLD}Started:{Colors.RESET} {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"{Colors.BOLD}Max pages:{Colors.RESET} {self.max_pages}")
        print()

        tests = [
            ("DNS & Connectivity", self.test_connectivity),
            ("SSL/TLS Certificate", self.test_ssl),
            ("Security Headers", self.test_security_headers),
            ("Sensitive File Exposure", self.test_sensitive_files),
            ("Port Scan", self.test_open_ports),
            ("Crawling Site", self.crawl_site),
            ("API Key Exposure", self.test_api_key_exposure),
            ("Performance Analysis", self.test_performance),
            ("Technology Detection", self.detect_technologies),
            ("Cookie Security", self.test_cookies),
        ]

        for name, test_fn in tests:
            print(f"\n{Colors.BOLD}{Colors.CYAN}━━━ {name} ━━━{Colors.RESET}")
            try:
                test_fn()
            except Exception as e:
                print(f"  {Colors.RED}Error: {e}{Colors.RESET}")
                self.add_finding(name, Finding.LOW, f"{name} test failed", str(e))

        elapsed = time.time() - self.start_time
        self.print_report(elapsed)
        self.save_report(elapsed)

    def test_connectivity(self):
        try:
            ip = socket.gethostbyname(self.domain)
            print(f"  {Colors.GREEN}✓{Colors.RESET} DNS resolves to {ip}")
            self.add_finding("DNS", Finding.PASS, "DNS resolution successful", f"Resolves to {ip}")
        except socket.gaierror:
            print(f"  {Colors.RED}✗{Colors.RESET} DNS resolution failed")
            self.add_finding("DNS", Finding.CRITICAL, "DNS resolution failed", "Domain does not resolve")
            return

        try:
            start = time.time()
            resp = self.session.get(self.base_url, timeout=self.timeout, allow_redirects=True)
            elapsed = time.time() - start
            print(f"  {Colors.GREEN}✓{Colors.RESET} HTTP {resp.status_code} in {elapsed:.2f}s")

            if elapsed > 5:
                self.add_finding("Performance", Finding.HIGH, "Slow initial response", f"Homepage took {elapsed:.2f}s")
            elif elapsed > 2:
                self.add_finding("Performance", Finding.MEDIUM, "Moderate response time", f"Homepage took {elapsed:.2f}s")
            else:
                self.add_finding("Performance", Finding.PASS, "Good response time", f"Homepage loaded in {elapsed:.2f}s")

            if resp.history:
                chain = " → ".join([f"{r.status_code} {r.url}" for r in resp.history])
                print(f"  {Colors.BLUE}ℹ{Colors.RESET} Redirect chain: {chain} → {resp.status_code} {resp.url}")

            if resp.url.startswith("http://") and self.base_url.startswith("https://"):
                self.add_finding("Security", Finding.HIGH, "HTTPS downgraded to HTTP", f"Redirected to {resp.url}")

        except requests.exceptions.Timeout:
            print(f"  {Colors.RED}✗{Colors.RESET} Connection timed out ({self.timeout}s)")
            self.add_finding("Connectivity", Finding.CRITICAL, "Connection timeout", f"No response within {self.timeout}s")
        except requests.exceptions.ConnectionError as e:
            print(f"  {Colors.RED}✗{Colors.RESET} Connection failed: {e}")
            self.add_finding("Connectivity", Finding.CRITICAL, "Connection failed", str(e))

    def test_ssl(self):
        if self.parsed.scheme != "https":
            print(f"  {Colors.YELLOW}⚠{Colors.RESET} Site not using HTTPS")
            self.add_finding("SSL", Finding.HIGH, "No HTTPS", "Site is served over plain HTTP")
            return

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    not_after = ssl.cert_time_to_seconds(cert["notAfter"])
                    days_left = (not_after - time.time()) / 86400

                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    subject = dict(x[0] for x in cert.get("subject", []))
                    cn = subject.get("commonName", "N/A")
                    org = issuer.get("organizationName", "N/A")
                    proto = ssock.version()

                    print(f"  {Colors.GREEN}✓{Colors.RESET} Valid SSL certificate")
                    print(f"    CN: {cn}")
                    print(f"    Issuer: {org}")
                    print(f"    Protocol: {proto}")
                    print(f"    Expires in: {int(days_left)} days")

                    if days_left < 7:
                        self.add_finding("SSL", Finding.CRITICAL, "SSL certificate expiring in <7 days", f"{int(days_left)} days remaining")
                    elif days_left < 30:
                        self.add_finding("SSL", Finding.HIGH, "SSL certificate expiring soon", f"{int(days_left)} days remaining")
                    else:
                        self.add_finding("SSL", Finding.PASS, "SSL certificate valid", f"{int(days_left)} days remaining, issued by {org}")

                    if proto in ("TLSv1", "TLSv1.1"):
                        self.add_finding("SSL", Finding.HIGH, f"Outdated TLS version: {proto}", "Upgrade to TLS 1.2 or 1.3")
                    elif proto == "TLSv1.2":
                        self.add_finding("SSL", Finding.PASS, f"TLS version: {proto}")
                    elif proto == "TLSv1.3":
                        self.add_finding("SSL", Finding.PASS, f"TLS version: {proto} (latest)")

                    san = cert.get("subjectAltName", [])
                    san_names = [x[1] for x in san if x[0] == "DNS"]
                    if san_names:
                        print(f"    SANs: {', '.join(san_names[:5])}{'...' if len(san_names) > 5 else ''}")

        except ssl.SSLCertVerificationError as e:
            print(f"  {Colors.RED}✗{Colors.RESET} SSL verification failed: {e}")
            self.add_finding("SSL", Finding.CRITICAL, "SSL certificate verification failed", str(e))
        except Exception as e:
            print(f"  {Colors.YELLOW}⚠{Colors.RESET} SSL check error: {e}")
            self.add_finding("SSL", Finding.MEDIUM, "SSL check encountered an error", str(e))

    def test_security_headers(self):
        try:
            resp = self.session.get(self.base_url, timeout=self.timeout)
            headers = resp.headers

            for header in SECURITY_HEADERS:
                val = headers.get(header)
                if val:
                    print(f"  {Colors.GREEN}✓{Colors.RESET} {header}: {val[:80]}")
                    self.add_finding("Headers", Finding.PASS, f"{header} present", val[:120])
                else:
                    severity = Finding.MEDIUM
                    if header in ("Strict-Transport-Security", "Content-Security-Policy"):
                        severity = Finding.HIGH
                    print(f"  {Colors.YELLOW}✗{Colors.RESET} {header}: missing")
                    self.add_finding("Headers", severity, f"Missing {header}", f"Add {header} header for better security")

            server = headers.get("Server", "")
            if server:
                print(f"  {Colors.BLUE}ℹ{Colors.RESET} Server: {server}")
                if any(v in server.lower() for v in ["apache/", "nginx/", "iis/", "php/"]):
                    self.add_finding("Headers", Finding.LOW, "Server version disclosed", f"Server: {server}. Consider hiding version info.")

            powered = headers.get("X-Powered-By", "")
            if powered:
                print(f"  {Colors.YELLOW}⚠{Colors.RESET} X-Powered-By: {powered}")
                self.add_finding("Headers", Finding.LOW, "X-Powered-By header present", f"Value: {powered}. Remove to reduce fingerprinting.")

        except Exception as e:
            print(f"  {Colors.RED}Error checking headers: {e}{Colors.RESET}")

    def test_sensitive_files(self):
        found_count = 0

        def check_path(path):
            url = f"{self.base_url}{path}"
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                return (path, resp.status_code, len(resp.content), resp)
            except:
                return (path, None, 0, None)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_path, p): p for p in SENSITIVE_PATHS}
            for future in as_completed(futures):
                path, status, size, resp = future.result()
                if status and status == 200 and size > 0:
                    content = resp.text[:500].lower() if resp else ""
                    is_custom_404 = any(x in content for x in ["not found", "404", "page not found", "does not exist"])
                    if is_custom_404:
                        continue

                    found_count += 1
                    severity = Finding.CRITICAL if any(s in path for s in [".env", ".git", "config.php", "wp-config", "backup.sql", "database.sql", "dump.sql", "PRIVATE"]) else Finding.MEDIUM
                    if path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
                        severity = Finding.INFO

                    icon = "🔴" if severity in (Finding.CRITICAL, Finding.HIGH) else "🟡" if severity == Finding.MEDIUM else "ℹ️ "
                    col = Colors.RED if severity in (Finding.CRITICAL, Finding.HIGH) else Colors.YELLOW if severity == Finding.MEDIUM else Colors.BLUE
                    print(f"  {col}{icon}{Colors.RESET} {path} → {status} ({size} bytes)")
                    self.add_finding("Exposure", severity, f"Accessible: {path}", f"HTTP {status}, {size} bytes", f"{self.base_url}{path}")

        if found_count == 0:
            print(f"  {Colors.GREEN}✓{Colors.RESET} No sensitive files exposed")
            self.add_finding("Exposure", Finding.PASS, "No sensitive files found")

    def test_open_ports(self):
        print(f"  Scanning {len(COMMON_PORTS)} common ports on {self.domain}...")
        open_ports = []

        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.domain, port))
                sock.close()
                return port if result == 0 else None
            except:
                return None

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(scan_port, p): p for p in COMMON_PORTS}
            for future in as_completed(futures):
                port = future.result()
                if port:
                    open_ports.append(port)

        port_names = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            587: "SMTP/TLS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
            1521: "Oracle", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
            9090: "Proxy", 27017: "MongoDB",
        }

        open_ports.sort()
        risky_ports = {21, 23, 25, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017}

        for port in open_ports:
            name = port_names.get(port, "Unknown")
            is_risky = port in risky_ports
            col = Colors.RED if is_risky else Colors.GREEN
            icon = "⚠" if is_risky else "✓"
            print(f"  {col}{icon}{Colors.RESET} Port {port} ({name}) — open")

            if is_risky:
                self.add_finding("Ports", Finding.HIGH, f"Risky port open: {port} ({name})", "This service should not be publicly accessible", self.domain)
            else:
                self.add_finding("Ports", Finding.INFO, f"Port {port} ({name}) open")

        if not open_ports:
            print(f"  {Colors.GREEN}✓{Colors.RESET} No common ports open (filtered or closed)")
            self.add_finding("Ports", Finding.PASS, "No common ports exposed")

    def crawl_site(self):
        self.to_visit.add(self.base_url)
        crawled = 0

        while self.to_visit and crawled < self.max_pages:
            url = self.to_visit.pop()
            if url in self.visited:
                continue

            self.visited.add(url)
            crawled += 1

            if crawled % 10 == 0 or crawled == 1:
                print(f"  {Colors.BLUE}ℹ{Colors.RESET} Crawled {crawled}/{self.max_pages} pages...")

            try:
                start = time.time()
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                elapsed = time.time() - start
                self.page_times.append((url, elapsed, resp.status_code))

                if resp.status_code >= 400:
                    self.broken_links.append((url, resp.status_code))

                content_type = resp.headers.get("Content-Type", "")
                if "text/html" not in content_type:
                    continue

                soup = BeautifulSoup(resp.text, "html.parser")

                for tag in soup.find_all("a", href=True):
                    href = tag["href"]
                    full_url = urllib.parse.urljoin(url, href)
                    parsed = urllib.parse.urlparse(full_url)

                    if parsed.fragment:
                        full_url = urllib.parse.urldefrag(full_url)[0]

                    if parsed.hostname == self.domain:
                        if full_url not in self.visited and full_url.startswith(("http://", "https://")):
                            clean = full_url.split("?")[0].split("#")[0]
                            if not any(clean.endswith(ext) for ext in (".pdf", ".zip", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".js", ".woff", ".woff2", ".ttf", ".ico", ".mp4", ".webm")):
                                self.to_visit.add(full_url)
                    elif parsed.scheme in ("http", "https"):
                        self.external_links.add(full_url)

                for tag in soup.find_all(["img", "script", "link"]):
                    src = tag.get("src") or tag.get("href")
                    if src:
                        self.resources[tag.name].append(urllib.parse.urljoin(url, src))

                page_text = resp.text
                for pattern, name in API_KEY_PATTERNS:
                    matches = re.findall(pattern, page_text)
                    if matches:
                        for match in matches[:3]:
                            masked = match[:6] + "..." + match[-4:] if len(match) > 12 else match[:4] + "..."
                            self.add_finding("API Keys", Finding.CRITICAL, f"Possible {name} exposed", f"Found in page source: {masked}", url)

            except requests.exceptions.Timeout:
                self.page_times.append((url, self.timeout, 0))
                self.add_finding("Performance", Finding.MEDIUM, "Page timeout", f"Timed out after {self.timeout}s", url)
            except Exception as e:
                self.log(f"Crawl error on {url}: {e}", Colors.RED)

        print(f"  {Colors.GREEN}✓{Colors.RESET} Crawled {crawled} pages, found {len(self.external_links)} external links")

        if self.broken_links:
            print(f"  {Colors.YELLOW}⚠{Colors.RESET} Found {len(self.broken_links)} broken links:")
            for link, status in self.broken_links[:20]:
                print(f"    {Colors.RED}✗{Colors.RESET} [{status}] {link}")
                self.add_finding("Links", Finding.MEDIUM, f"Broken link (HTTP {status})", "", link)
        else:
            self.add_finding("Links", Finding.PASS, "No broken internal links found")

    def test_api_key_exposure(self):
        exposed = [f for f in self.findings if f.category == "API Keys"]
        if exposed:
            print(f"  {Colors.RED}⚠ Found {len(exposed)} potential API key/secret exposures!{Colors.RESET}")
            for f in exposed:
                print(f"    {Colors.RED}✗{Colors.RESET} {f.title}: {f.detail}")
        else:
            print(f"  {Colors.GREEN}✓{Colors.RESET} No API keys or secrets found in page source")
            self.add_finding("API Keys", Finding.PASS, "No API keys exposed in crawled pages")

        js_urls = self.resources.get("script", [])[:30]
        checked = 0
        found = 0

        def check_js(url):
            try:
                resp = self.session.get(url, timeout=self.timeout)
                results = []
                for pattern, name in API_KEY_PATTERNS:
                    matches = re.findall(pattern, resp.text)
                    if matches:
                        for m in matches[:2]:
                            masked = m[:6] + "..." + m[-4:] if len(m) > 12 else m[:4] + "..."
                            results.append((name, masked, url))
                return results
            except:
                return []

        if js_urls:
            print(f"  Scanning {len(js_urls)} JavaScript files...")
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(check_js, u): u for u in js_urls}
                for future in as_completed(futures):
                    results = future.result()
                    checked += 1
                    for name, masked, url in results:
                        found += 1
                        print(f"    {Colors.RED}✗{Colors.RESET} {name} in JS: {masked}")
                        self.add_finding("API Keys", Finding.CRITICAL, f"Possible {name} in JavaScript", f"Found: {masked}", url)

            if found == 0:
                print(f"  {Colors.GREEN}✓{Colors.RESET} No secrets found in {checked} JavaScript files")

    def test_performance(self):
        if not self.page_times:
            print(f"  {Colors.YELLOW}⚠{Colors.RESET} No pages crawled for performance analysis")
            return

        times = [t for _, t, s in self.page_times if s > 0]
        if not times:
            return

        avg_time = sum(times) / len(times)
        max_time = max(times)
        min_time = min(times)
        slow_pages = [(u, t) for u, t, s in self.page_times if t > 3 and s > 0]

        print(f"  {Colors.BLUE}ℹ{Colors.RESET} Pages analyzed: {len(times)}")
        print(f"  {Colors.BLUE}ℹ{Colors.RESET} Avg response time: {avg_time:.2f}s")
        print(f"  {Colors.BLUE}ℹ{Colors.RESET} Fastest: {min_time:.2f}s")
        print(f"  {Colors.BLUE}ℹ{Colors.RESET} Slowest: {max_time:.2f}s")

        if avg_time > 3:
            self.add_finding("Performance", Finding.HIGH, "Very slow average response time", f"Average: {avg_time:.2f}s across {len(times)} pages")
        elif avg_time > 1.5:
            self.add_finding("Performance", Finding.MEDIUM, "Moderate average response time", f"Average: {avg_time:.2f}s across {len(times)} pages")
        else:
            self.add_finding("Performance", Finding.PASS, "Good average response time", f"Average: {avg_time:.2f}s across {len(times)} pages")

        if slow_pages:
            print(f"  {Colors.YELLOW}⚠{Colors.RESET} {len(slow_pages)} slow pages (>3s):")
            for url, t in sorted(slow_pages, key=lambda x: -x[1])[:10]:
                print(f"    {Colors.YELLOW}⏱{Colors.RESET}  {t:.2f}s — {url}")
                self.add_finding("Performance", Finding.MEDIUM, f"Slow page ({t:.2f}s)", "", url)

    def detect_technologies(self):
        try:
            resp = self.session.get(self.base_url, timeout=self.timeout)
            html = resp.text.lower()
            headers = {k.lower(): v for k, v in resp.headers.items()}
            detected = []

            tech_signatures = {
                "React": [("react", html), ("__react", html), ("_reactroot", html)],
                "Vue.js": [("vue.js", html), ("__vue__", html), ("v-app", html)],
                "Angular": [("ng-app", html), ("ng-version", html), ("angular", html)],
                "Next.js": [("__next", html), ("_next/", html)],
                "Nuxt.js": [("__nuxt", html), ("_nuxt/", html)],
                "jQuery": [("jquery", html)],
                "WordPress": [("wp-content", html), ("wp-includes", html)],
                "Tailwind CSS": [("tailwindcss", html)],
                "Bootstrap": [("bootstrap", html)],
                "Vite": [("vite", html), ("/@vite", html)],
                "Webpack": [("webpack", html)],
                "Node.js/Express": [("x-powered-by", headers.get("x-powered-by", "").lower())],
                "Cloudflare": [("cloudflare", headers.get("server", "").lower()), ("cf-ray", str(headers))],
                "Nginx": [("nginx", headers.get("server", "").lower())],
                "Apache": [("apache", headers.get("server", "").lower())],
                "Vercel": [("vercel", headers.get("server", "").lower()), ("x-vercel", str(headers))],
                "Netlify": [("netlify", headers.get("server", "").lower())],
                "Google Analytics": [("google-analytics", html), ("gtag", html), ("ga.js", html)],
                "Stripe": [("stripe.com", html), ("stripe.js", html)],
                "Sentry": [("sentry", html), ("sentry.io", html)],
                "Hotjar": [("hotjar", html)],
                "Intercom": [("intercom", html)],
            }

            for tech, checks in tech_signatures.items():
                for sig, source in checks:
                    if sig in source:
                        detected.append(tech)
                        break

            if detected:
                for tech in sorted(set(detected)):
                    print(f"  {Colors.BLUE}ℹ{Colors.RESET} {tech}")
                    self.add_finding("Technology", Finding.INFO, f"Detected: {tech}")
            else:
                print(f"  {Colors.BLUE}ℹ{Colors.RESET} No common technologies detected")

        except Exception as e:
            print(f"  {Colors.YELLOW}⚠{Colors.RESET} Tech detection error: {e}")

    def test_cookies(self):
        try:
            resp = self.session.get(self.base_url, timeout=self.timeout)
            cookies = resp.cookies

            if not cookies:
                print(f"  {Colors.GREEN}✓{Colors.RESET} No cookies set on initial page load")
                self.add_finding("Cookies", Finding.PASS, "No cookies on initial load")
                return

            for cookie in cookies:
                flags = []
                issues = []

                if cookie.secure:
                    flags.append(f"{Colors.GREEN}Secure{Colors.RESET}")
                else:
                    flags.append(f"{Colors.RED}No Secure{Colors.RESET}")
                    issues.append("Missing Secure flag")

                if "httponly" in str(cookie._rest).lower() or cookie.has_nonstandard_attr("HttpOnly"):
                    flags.append(f"{Colors.GREEN}HttpOnly{Colors.RESET}")
                else:
                    flags.append(f"{Colors.YELLOW}No HttpOnly{Colors.RESET}")
                    issues.append("Missing HttpOnly flag")

                samesite = cookie.get_nonstandard_attr("SameSite") or "Not set"
                flags.append(f"SameSite={samesite}")

                print(f"  {Colors.BLUE}🍪{Colors.RESET} {cookie.name}: {', '.join(flags)}")

                if issues:
                    self.add_finding("Cookies", Finding.MEDIUM, f"Cookie '{cookie.name}' security issues", "; ".join(issues))
                else:
                    self.add_finding("Cookies", Finding.PASS, f"Cookie '{cookie.name}' properly secured")

        except Exception as e:
            print(f"  {Colors.YELLOW}⚠{Colors.RESET} Cookie check error: {e}")

    def print_report(self, elapsed):
        print(f"\n\n{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}                    SCAN SUMMARY{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}\n")

        print(f"  Target:       {self.base_url}")
        print(f"  Pages crawled: {len(self.visited)}")
        print(f"  External links: {len(self.external_links)}")
        print(f"  Scan duration: {elapsed:.1f}s")
        print()

        severity_counts = defaultdict(int)
        for f in self.findings:
            severity_counts[f.severity] += 1

        print(f"  {Colors.RED}🔴 Critical: {severity_counts.get(Finding.CRITICAL, 0)}{Colors.RESET}")
        print(f"  {Colors.RED}🟠 High:     {severity_counts.get(Finding.HIGH, 0)}{Colors.RESET}")
        print(f"  {Colors.YELLOW}🟡 Medium:   {severity_counts.get(Finding.MEDIUM, 0)}{Colors.RESET}")
        print(f"  {Colors.CYAN}🔵 Low:      {severity_counts.get(Finding.LOW, 0)}{Colors.RESET}")
        print(f"  {Colors.BLUE}ℹ️  Info:     {severity_counts.get(Finding.INFO, 0)}{Colors.RESET}")
        print(f"  {Colors.GREEN}✅ Pass:     {severity_counts.get(Finding.PASS, 0)}{Colors.RESET}")

        total_issues = severity_counts.get(Finding.CRITICAL, 0) + severity_counts.get(Finding.HIGH, 0) + severity_counts.get(Finding.MEDIUM, 0)

        print()
        if severity_counts.get(Finding.CRITICAL, 0) > 0:
            score = "F"
            color = Colors.RED
        elif severity_counts.get(Finding.HIGH, 0) > 2:
            score = "D"
            color = Colors.RED
        elif severity_counts.get(Finding.HIGH, 0) > 0:
            score = "C"
            color = Colors.YELLOW
        elif severity_counts.get(Finding.MEDIUM, 0) > 3:
            score = "C"
            color = Colors.YELLOW
        elif severity_counts.get(Finding.MEDIUM, 0) > 0:
            score = "B"
            color = Colors.CYAN
        else:
            score = "A"
            color = Colors.GREEN

        print(f"  {Colors.BOLD}Overall Grade: {color}{score}{Colors.RESET}")

        actionable = [f for f in self.findings if f.severity in (Finding.CRITICAL, Finding.HIGH, Finding.MEDIUM)]
        if actionable:
            print(f"\n{Colors.BOLD}  Priority Issues:{Colors.RESET}")
            for f in sorted(actionable, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(x.severity, 3)):
                print(f"  {f}")
        print()

    def save_report(self, elapsed):
        report_name = f"privsec-scan-{self.domain}-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"

        report = {
            "tool": "PrivSec Site Tester",
            "version": VERSION,
            "target": self.base_url,
            "domain": self.domain,
            "scan_date": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": round(elapsed, 1),
            "pages_crawled": len(self.visited),
            "external_links": len(self.external_links),
            "broken_links": len(self.broken_links),
            "findings": [
                {
                    "category": f.category,
                    "severity": f.severity,
                    "title": f.title,
                    "detail": f.detail,
                    "url": f.url,
                }
                for f in self.findings
            ],
            "summary": {
                "critical": len([f for f in self.findings if f.severity == Finding.CRITICAL]),
                "high": len([f for f in self.findings if f.severity == Finding.HIGH]),
                "medium": len([f for f in self.findings if f.severity == Finding.MEDIUM]),
                "low": len([f for f in self.findings if f.severity == Finding.LOW]),
                "info": len([f for f in self.findings if f.severity == Finding.INFO]),
                "pass": len([f for f in self.findings if f.severity == Finding.PASS]),
            },
            "slow_pages": [
                {"url": url, "time": round(t, 2)}
                for url, t, s in self.page_times if t > 3 and s > 0
            ],
            "broken_link_details": [
                {"url": url, "status": status}
                for url, status in self.broken_links
            ],
        }

        with open(report_name, "w") as f:
            json.dump(report, f, indent=2)

        print(f"  {Colors.GREEN}📄 Report saved to: {report_name}{Colors.RESET}\n")


def main():
    parser = argparse.ArgumentParser(
        description="PrivSec Site Tester — Comprehensive website security and performance scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python privsec-site-tester.py https://example.com
  python privsec-site-tester.py https://example.com --max-pages 200
  python privsec-site-tester.py https://example.com --timeout 15 --threads 20
  python privsec-site-tester.py https://example.com --verbose --no-color
        """,
    )
    parser.add_argument("url", help="Target URL to scan (e.g., https://example.com)")
    parser.add_argument("--max-pages", type=int, default=100, help="Maximum pages to crawl (default: 100)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent threads (default: 10)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")

    args = parser.parse_args()

    if args.no_color:
        Colors.disable()

    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    tester = SiteTester(
        base_url=url,
        max_pages=args.max_pages,
        timeout=args.timeout,
        threads=args.threads,
        verbose=args.verbose,
    )
    tester.run()


if __name__ == "__main__":
    main()
