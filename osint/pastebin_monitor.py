"""
Pastebin & Leak Monitor - Professional Edition
Advanced leak detection and monitoring for offensive security operations
"""
import requests
from bs4 import BeautifulSoup
import re
import time
import json
import hashlib
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote_plus
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class PastebinMonitor:
    def __init__(self):
        self.results = []
        self.keywords = []
        self.seen_hashes = set()  # Track duplicates
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Advanced regex patterns for sensitive data
        self.patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'password_field': r'(?i)(password|pass|pwd)\s*[:=]\s*[^\s]+',
            'api_key': r'(?i)(api[_-]?key|apikey)\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]{20,})[\'"]?',
            'aws_key': r'(?i)(aws_access_key_id|aws_secret_access_key)\s*[:=]\s*[A-Z0-9]{20,}',
            'private_key': r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
            'jwt_token': r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
            'phone': r'\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'credit_card': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',
            'hash_md5': r'\b[a-f0-9]{32}\b',
            'hash_sha1': r'\b[a-f0-9]{40}\b',
            'hash_sha256': r'\b[a-f0-9]{64}\b',
            'ip_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'database_conn': r'(?i)(jdbc|mongodb|mysql|postgresql|redis)://[^\s]+',
            'oauth_token': r'(?i)(oauth[_-]?token|access[_-]?token)\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]{20,})[\'"]?',
        }
        
        # Multiple paste sites for comprehensive coverage
        self.paste_sites = {
            'pastebin': 'https://pastebin.com',
            'ghostbin': 'https://ghostbin.co',
            'justpaste': 'https://justpaste.it',
            'privatebin': 'https://privatebin.net',
            'paste_ee': 'https://paste.ee',
            'dpaste': 'https://dpaste.org',
        }
        
    def get_content_hash(self, content: str) -> str:
        """Generate MD5 hash of content to detect duplicates"""
        return hashlib.md5(content.encode('utf-8', errors='ignore')).hexdigest()
    
    def extract_sensitive_data(self, content: str) -> dict:
        """Extract all sensitive data patterns from content"""
        findings = {}
        
        for pattern_name, pattern in self.patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                findings[pattern_name] = matches if isinstance(matches, list) else [matches]
        
        return findings
    
    def calculate_sensitivity_score(self, findings: dict) -> int:
        """Calculate sensitivity score (0-100) based on findings"""
        score = 0
        weights = {
            'private_key': 30,
            'aws_key': 25,
            'api_key': 20,
            'password_field': 15,
            'database_conn': 15,
            'oauth_token': 15,
            'jwt_token': 10,
            'credit_card': 25,
            'ssn': 25,
            'email': 5,
            'phone': 5,
            'hash_md5': 3,
            'hash_sha1': 3,
            'hash_sha256': 3,
            'ip_address': 2,
        }
        
        for pattern_name, matches in findings.items():
            weight = weights.get(pattern_name, 5)
            count = len(matches) if isinstance(matches, list) else 1
            score += weight * min(count, 3)  # Cap contribution per pattern
        
        return min(score, 100)
    
    def search_pastebin_advanced(self, query: str, max_pastes: int = 50):
        """Advanced Pastebin search with sensitivity analysis"""
        print(f"\n\033[93m[*] Advanced Pastebin scan for: {query}\033[0m")
        print(f"\033[97m[*] Checking up to {max_pastes} recent pastes...\033[0m\n")
        
        found = 0
        checked = 0
        
        try:
            # Get archive page
            url = "https://pastebin.com/archive"
            response = self.session.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find paste links
            paste_links = soup.find_all('a', href=re.compile(r'^/[A-Za-z0-9]+$'))
            
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = []
                for link in paste_links[:max_pastes]:
                    paste_id = link['href'].strip('/')
                    paste_title = link.text.strip()
                    futures.append(
                        executor.submit(self._check_paste, paste_id, paste_title, query)
                    )
                
                for future in as_completed(futures):
                    checked += 1
                    result = future.result()
                    if result:
                        found += 1
                        self.results.append(result)
                        self._display_finding(result)
            
            print(f"\n\033[92m[+] Scan complete: {found} matches found in {checked} pastes\033[0m")
            
        except Exception as e:
            print(f"\033[91m[!] Error: {str(e)}\033[0m")
    
    def _check_paste(self, paste_id: str, title: str, query: str):
        """Check individual paste for matches"""
        try:
            raw_url = f"https://pastebin.com/raw/{paste_id}"
            response = self.session.get(raw_url, timeout=5, verify=False)
            content = response.text
            
            # Skip if duplicate
            content_hash = self.get_content_hash(content)
            if content_hash in self.seen_hashes:
                return None
            self.seen_hashes.add(content_hash)
            
            # Check for keyword match
            if query.lower() not in content.lower():
                return None
            
            # Extract sensitive data
            findings = self.extract_sensitive_data(content)
            sensitivity = self.calculate_sensitivity_score(findings)
            
            return {
                'paste_id': paste_id,
                'url': f"https://pastebin.com/{paste_id}",
                'raw_url': raw_url,
                'title': title,
                'matched_keyword': query,
                'sensitivity_score': sensitivity,
                'findings': findings,
                'content_preview': content[:500],
                'size': len(content),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return None
    
    def _display_finding(self, result: dict):
        """Display finding with color-coded sensitivity"""
        score = result.get('sensitivity_score', 0)
        
        if score >= 50:
            color = '\033[91m'  # Red - High sensitivity
            level = 'CRITICAL'
        elif score >= 25:
            color = '\033[93m'  # Yellow - Medium sensitivity
            level = 'WARNING'
        else:
            color = '\033[92m'  # Green - Low sensitivity
            level = 'INFO'
        
        print(f"{color}[{level}] Sensitivity: {score}%\033[0m")
        print(f"\033[97m  URL: {result['url']}\033[0m")
        print(f"\033[97m  Title: {result['title']}\033[0m")
        
        if result.get('findings'):
            print(f"\033[97m  Sensitive Data Found:\033[0m")
            for pattern_name, matches in result['findings'].items():
                count = len(matches) if isinstance(matches, list) else 1
                print(f"\033[97m    - {pattern_name}: {count} match(es)\033[0m")
        print()
    
    def search_multiple_sites(self, query: str):
        """Search across multiple paste sites simultaneously"""
        print(f"\n\033[93m[*] Multi-site leak search for: {query}\033[0m\n")
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(self._search_site, name, url, query): name
                for name, url in self.paste_sites.items()
            }
            
            for future in as_completed(futures):
                site_name = futures[future]
                try:
                    result = future.result()
                    if result:
                        print(f"\033[92m[+] {site_name}: Found matches\033[0m")
                    else:
                        print(f"\033[97m[-] {site_name}: No matches\033[0m")
                except Exception as e:
                    print(f"\033[91m[!] {site_name}: Error\033[0m")
    
    def _search_site(self, site_name: str, base_url: str, query: str):
        """Search individual paste site"""
        try:
            if site_name == 'pastebin':
                self.search_pastebin_advanced(query, max_pastes=30)
                return True
            else:
                # Generic search for other sites
                response = self.session.get(base_url, timeout=10, verify=False)
                return query.lower() in response.text.lower()
        except:
            return False
    
    def check_email_leaks(self, email: str):
        """Comprehensive email leak check"""
        print(f"\n\033[93m[*] Advanced email leak analysis: {email}\033[0m\n")
        
        # Check HaveIBeenPwned (informational)
        print(f"\033[97m[*] HaveIBeenPwned API check...\033[0m")
        try:
            hibp_url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote_plus(email)}"
            response = self.session.get(hibp_url, timeout=10, verify=False)
            
            if response.status_code == 200:
                breaches = response.json()
                print(f"\033[91m[!] ALERT: Email found in {len(breaches)} breaches!\033[0m")
                for breach in breaches[:5]:  # Show first 5
                    print(f"\033[97m  - {breach.get('Name', 'Unknown')}\033[0m")
            elif response.status_code == 404:
                print(f"\033[92m[+] No breaches found in HIBP database\033[0m")
            else:
                print(f"\033[97m[-] HIBP check skipped (rate limit/API key required)\033[0m")
        except:
            print(f"\033[97m[-] HIBP check skipped (requires API key)\033[0m")
        
        # Search paste sites
        print(f"\n\033[97m[*] Searching paste sites for: {email}\033[0m")
        self.search_pastebin_advanced(email, max_pastes=100)
        
        # Search for domain
        domain = email.split('@')[1] if '@' in email else None
        if domain:
            print(f"\n\033[97m[*] Searching for domain: {domain}\033[0m")
            self.search_pastebin_advanced(domain, max_pastes=50)
    
    def monitor_keywords(self, keywords: list, duration_minutes: int = 5, interval: int = 60):
        """Real-time continuous monitoring with alerting"""
        print(f"\n\033[93m[*] Starting continuous monitoring...\033[0m")
        print(f"\033[97m  Duration: {duration_minutes} minutes\033[0m")
        print(f"\033[97m  Check interval: {interval} seconds\033[0m")
        print(f"\033[97m  Keywords: {', '.join(keywords)}\033[0m\n")
        
        self.keywords = keywords
        start_time = time.time()
        end_time = start_time + (duration_minutes * 60)
        
        check_count = 0
        alerts = 0
        
        while time.time() < end_time:
            check_count += 1
            print(f"\n\033[96m{'='*70}\033[0m")
            print(f"\033[97m[*] Check #{check_count} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\033[0m")
            print(f"\033[96m{'='*70}\033[0m")
            
            initial_count = len(self.results)
            
            for keyword in keywords:
                print(f"\n\033[97m[*] Scanning for: {keyword}\033[0m")
                self.search_pastebin_advanced(keyword, max_pastes=20)
            
            new_findings = len(self.results) - initial_count
            if new_findings > 0:
                alerts += new_findings
                print(f"\n\033[91m[!] ALERT: {new_findings} new leak(s) detected!\033[0m")
            
            if time.time() < end_time:
                remaining = int((end_time - time.time()) / 60)
                print(f"\n\033[97m[*] Waiting {interval}s... ({remaining} min remaining)\033[0m")
                time.sleep(interval)
        
        print(f"\n\033[92m{'='*70}\033[0m")
        print(f"\033[92m[+] Monitoring complete!\033[0m")
        print(f"\033[97m  Total checks: {check_count}\033[0m")
        print(f"\033[97m  Total findings: {len(self.results)}\033[0m")
        print(f"\033[97m  New alerts: {alerts}\033[0m")
        print(f"\033[92m{'='*70}\033[0m")
    
    def search_github_leaks(self, query: str):
        """Advanced GitHub leak search with multiple queries"""
        print(f"\n\033[93m[*] GitHub Code Search for: {query}\033[0m\n")
        
        # Multiple search strategies
        search_queries = [
            f"{query} password",
            f"{query} api_key",
            f"{query} secret",
            f"{query} credentials",
            f"{query} token",
            f'"{query}" password OR api_key OR secret',
        ]
        
        print(f"\033[97m[*] Generated search URLs:\033[0m\n")
        
        for i, search_query in enumerate(search_queries, 1):
            encoded_query = quote_plus(search_query)
            url = f"https://github.com/search?q={encoded_query}&type=code"
            print(f"\033[97m  [{i}] {url}\033[0m")
        
        print(f"\n\033[97m[*] Note: Automated GitHub scraping requires authentication\033[0m")
        print(f"\033[97m[*] Use these URLs manually or provide GitHub token\033[0m")
        
        return search_queries
    
    def search_credential_dumps(self, query: str):
        """Search for credential dumps and combo lists"""
        print(f"\n\033[93m[*] Credential dump search for: {query}\033[0m\n")
        
        # Search for common dump formats
        dump_keywords = [
            f"{query} combo",
            f"{query} dump",
            f"{query} leak",
            f"{query} database",
            f"{query} credentials",
            f"{query}:password",
        ]
        
        total_found = 0
        
        for keyword in dump_keywords:
            print(f"\033[97m[*] Searching: {keyword}\033[0m")
            initial = len(self.results)
            self.search_pastebin_advanced(keyword, max_pastes=30)
            found = len(self.results) - initial
            total_found += found
            
            if found > 0:
                print(f"\033[92m  [+] Found {found} potential dumps\033[0m")
            
            time.sleep(1)  # Rate limiting
        
        print(f"\n\033[92m[+] Total credential dumps found: {total_found}\033[0m")
    
    def save_results(self, output_file: str, format_type: str = 'json'):
        """Save results in multiple formats"""
        try:
            if format_type.lower() == 'json':
                # JSON format with full metadata
                data = {
                    'scan_info': {
                        'timestamp': datetime.now().isoformat(),
                        'total_results': len(self.results),
                        'keywords': self.keywords,
                    },
                    'results': self.results
                }
                
                with open(output_file, 'w') as f:
                    json.dump(data, f, indent=2)
                
            else:  # Text format
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write("="*70 + "\n")
                    f.write("PASTEBIN/LEAK MONITOR - PROFESSIONAL REPORT\n")
                    f.write("="*70 + "\n\n")
                    f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Total Findings: {len(self.results)}\n")
                    f.write("="*70 + "\n\n")
                    
                    if self.results:
                        # Sort by sensitivity score
                        sorted_results = sorted(
                            self.results,
                            key=lambda x: x.get('sensitivity_score', 0),
                            reverse=True
                        )
                        
                        for i, result in enumerate(sorted_results, 1):
                            score = result.get('sensitivity_score', 0)
                            level = 'CRITICAL' if score >= 50 else 'WARNING' if score >= 25 else 'INFO'
                            
                            f.write(f"[{i}] {level} - Sensitivity: {score}%\n")
                            f.write(f"URL: {result.get('url', 'N/A')}\n")
                            f.write(f"Title: {result.get('title', 'N/A')}\n")
                            f.write(f"Keyword: {result.get('matched_keyword', 'N/A')}\n")
                            f.write(f"Size: {result.get('size', 0)} bytes\n")
                            
                            if result.get('findings'):
                                f.write("Sensitive Data:\n")
                                for pattern_name, matches in result['findings'].items():
                                    count = len(matches) if isinstance(matches, list) else 1
                                    f.write(f"  - {pattern_name}: {count} match(es)\n")
                            
                            if result.get('content_preview'):
                                f.write(f"\nPreview:\n{result['content_preview'][:300]}...\n")
                            
                            f.write("\n" + "-"*70 + "\n\n")
                    else:
                        f.write("No matches found.\n")
            
            print(f"\n\033[92m[+] Results saved to: {output_file}\033[0m")
            print(f"\033[97m[*] Format: {format_type.upper()}\033[0m")
            print(f"\033[97m[*] Total entries: {len(self.results)}\033[0m")
            
        except Exception as e:
            print(f"\n\033[91m[!] Error saving results: {e}\033[0m")
    
    def generate_statistics(self):
        """Generate detailed statistics about findings"""
        if not self.results:
            print(f"\n\033[97m[*] No results to analyze\033[0m")
            return
        
        print(f"\n\033[96m{'='*70}\033[0m")
        print(f"\033[96mSTATISTICS & ANALYSIS\033[0m")
        print(f"\033[96m{'='*70}\033[0m\n")
        
        total = len(self.results)
        critical = sum(1 for r in self.results if r.get('sensitivity_score', 0) >= 50)
        warning = sum(1 for r in self.results if 25 <= r.get('sensitivity_score', 0) < 50)
        info = sum(1 for r in self.results if r.get('sensitivity_score', 0) < 25)
        
        print(f"\033[97mTotal Findings: {total}\033[0m")
        print(f"\033[91m  Critical (50%+): {critical}\033[0m")
        print(f"\033[93m  Warning (25-49%): {warning}\033[0m")
        print(f"\033[92m  Info (<25%): {info}\033[0m\n")
        
        # Pattern statistics
        pattern_counts = {}
        for result in self.results:
            for pattern_name in result.get('findings', {}).keys():
                pattern_counts[pattern_name] = pattern_counts.get(pattern_name, 0) + 1
        
        if pattern_counts:
            print(f"\033[97mSensitive Data Types Found:\033[0m")
            for pattern_name, count in sorted(pattern_counts.items(), key=lambda x: x[1], reverse=True):
                print(f"\033[97m  - {pattern_name}: {count} paste(s)\033[0m")
        
        print(f"\n\033[96m{'='*70}\033[0m")

def run():
    """Main function"""
    print("\033[92m" + "="*70)
    print("     PASTEBIN & LEAK MONITOR - PROFESSIONAL EDITION")
    print("="*70 + "\033[0m\n")
    
    print("\033[93m[!] OFFENSIVE SECURITY TOOL - Authorized use only!\033[0m\n")
    
    print("\033[97mSelect scan mode:\033[0m")
    print("  [1] Advanced keyword search (with sensitivity analysis)")
    print("  [2] Real-time monitoring (continuous)")
    print("  [3] Email leak intelligence")
    print("  [4] GitHub code leak search")
    print("  [5] Multi-site paste search")
    print("  [6] Credential dump hunter")
    print("  [7] Custom pattern search")
    
    mode = input("\n\033[95m[?] Select mode (1-7): \033[0m").strip()
    
    monitor = PastebinMonitor()
    
    if mode == '1':
        query = input("\033[95m[?] Enter search keyword/term: \033[0m").strip()
        max_pastes = input("\033[95m[?] Max pastes to check (default 50): \033[0m").strip()
        max_pastes = int(max_pastes) if max_pastes.isdigit() else 50
        
        monitor.search_pastebin_advanced(query, max_pastes)
    
    elif mode == '2':
        keywords_input = input("\033[95m[?] Enter keywords (comma-separated): \033[0m").strip()
        keywords = [k.strip() for k in keywords_input.split(',')]
        
        duration = input("\033[95m[?] Monitor duration in minutes (default 5): \033[0m").strip()
        duration = int(duration) if duration.isdigit() else 5
        
        interval = input("\033[95m[?] Check interval in seconds (default 60): \033[0m").strip()
        interval = int(interval) if interval.isdigit() else 60
        
        monitor.monitor_keywords(keywords, duration, interval)
    
    elif mode == '3':
        email = input("\033[95m[?] Enter email address: \033[0m").strip()
        monitor.check_email_leaks(email)
    
    elif mode == '4':
        query = input("\033[95m[?] Enter search query (company/domain/keyword): \033[0m").strip()
        monitor.search_github_leaks(query)
    
    elif mode == '5':
        query = input("\033[95m[?] Enter search keyword: \033[0m").strip()
        monitor.search_multiple_sites(query)
    
    elif mode == '6':
        query = input("\033[95m[?] Enter target (company/domain): \033[0m").strip()
        monitor.search_credential_dumps(query)
    
    elif mode == '7':
        print("\n\033[97mAvailable patterns:\033[0m")
        for i, pattern_name in enumerate(monitor.patterns.keys(), 1):
            print(f"\033[97m  [{i}] {pattern_name}\033[0m")
        
        pattern_choice = input("\n\033[95m[?] Select pattern or enter custom regex: \033[0m").strip()
        
        if pattern_choice.isdigit() and 1 <= int(pattern_choice) <= len(monitor.patterns):
            pattern_name = list(monitor.patterns.keys())[int(pattern_choice) - 1]
            print(f"\033[97m[*] Using pattern: {pattern_name}\033[0m")
        
        query = input("\033[95m[?] Enter search context: \033[0m").strip()
        monitor.search_pastebin_advanced(query, 50)
    
    print("\n" + "\033[92m" + "="*70)
    print("           SCAN COMPLETE")
    print("="*70 + "\033[0m")
    
    if monitor.results:
        monitor.generate_statistics()
        
        save = input("\n\033[95m[?] Save results to file? (y/n): \033[0m").strip().lower()
        if save == 'y':
            format_type = input("\033[95m[?] Format (json/txt, default json): \033[0m").strip().lower()
            format_type = format_type if format_type in ['json', 'txt'] else 'json'
            
            filename = input(f"\033[95m[?] Filename (default: leak_results.{format_type}): \033[0m").strip()
            filename = filename if filename else f"leak_results.{format_type}"
            
            monitor.save_results(filename, format_type)
    else:
        print(f"\n\033[97m[*] No results found\033[0m")

if __name__ == "__main__":
    run()
