"""
Email Address Harvester
Finds email addresses using web scraping and pattern matching
"""
import re
import socket
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from typing import Set
import time

class EmailHarvester:
    def __init__(self):
        self.emails = set()
        self.visited_urls = set()
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        
    def extract_emails_from_text(self, text: str) -> Set[str]:
        """Extract email addresses from text using regex"""
        return set(self.email_pattern.findall(text))
    
    def scrape_website(self, url: str, max_depth: int = 2, current_depth: int = 0):
        """Scrape website for email addresses"""
        if current_depth > max_depth or url in self.visited_urls:
            return
        
        try:
            self.visited_urls.add(url)
            print(f"\033[93m[*] Scanning: {url}\033[0m")
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            response.raise_for_status()
            
            # Extract emails from page content
            page_emails = self.extract_emails_from_text(response.text)
            
            for email in page_emails:
                if email not in self.emails:
                    self.emails.add(email)
                    print(f"\033[92m[+] Found: {email}\033[0m")
            
            # Parse HTML for more links
            if current_depth < max_depth:
                soup = BeautifulSoup(response.text, 'html.parser')
                base_domain = urlparse(url).netloc
                
                for link in soup.find_all('a', href=True):
                    next_url = urljoin(url, link['href'])
                    next_domain = urlparse(next_url).netloc
                    
                    # Stay on same domain
                    if next_domain == base_domain and next_url not in self.visited_urls:
                        time.sleep(0.5)  # Be polite
                        self.scrape_website(next_url, max_depth, current_depth + 1)
                        
        except requests.RequestException as e:
            print(f"\033[91m[!] Error accessing {url}: {str(e)[:50]}\033[0m")
        except Exception as e:
            print(f"\033[91m[!] Unexpected error: {str(e)[:50]}\033[0m")
    
    def check_common_pages(self, domain: str) -> Set[str]:
        """Check common pages for emails"""
        common_pages = [
            '', '/contact', '/about', '/team', '/staff', '/contact-us',
            '/about-us', '/people', '/support', '/privacy', '/terms'
        ]
        
        emails = set()
        base_url = f"https://{domain}" if not domain.startswith('http') else domain
        
        for page in common_pages:
            url = base_url + page
            try:
                headers = {'User-Agent': 'Mozilla/5.0'}
                response = requests.get(url, headers=headers, timeout=5, verify=False)
                page_emails = self.extract_emails_from_text(response.text)
                emails.update(page_emails)
            except:
                pass
        
        return emails
    
    def search_dns_records(self, domain: str):
        """Extract emails from DNS TXT records (SPF, DMARC)"""
        print(f"\n\033[93m[*] Checking DNS records for {domain}...\033[0m")
        
        try:
            # This is a simplified version - full implementation would use dnspython
            import dns.resolver
            
            for record_type in ['TXT', 'MX']:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    for rdata in answers:
                        text = str(rdata)
                        emails = self.extract_emails_from_text(text)
                        for email in emails:
                            if email not in self.emails:
                                self.emails.add(email)
                                print(f"\033[92m[+] Found in DNS: {email}\033[0m")
                except:
                    pass
        except ImportError:
            print("\033[91m[!] dnspython not installed, skipping DNS lookup\033[0m")
        except Exception as e:
            print(f"\033[91m[!] DNS lookup error: {str(e)[:50]}\033[0m")
    
    def generate_common_emails(self, domain: str, names: list = None) -> Set[str]:
        """Generate common email patterns"""
        common_patterns = [
            'info', 'contact', 'admin', 'support', 'sales', 'hello',
            'webmaster', 'mail', 'help', 'service', 'team', 'office'
        ]
        
        emails = set()
        
        for pattern in common_patterns:
            emails.add(f"{pattern}@{domain}")
        
        if names:
            for name in names:
                parts = name.lower().split()
                if len(parts) >= 2:
                    fname, lname = parts[0], parts[-1]
                    emails.add(f"{fname}@{domain}")
                    emails.add(f"{lname}@{domain}")
                    emails.add(f"{fname}.{lname}@{domain}")
                    emails.add(f"{fname[0]}{lname}@{domain}")
        
        return emails
    
    def save_results(self, output_file: str):
        """Save found emails to file"""
        try:
            with open(output_file, 'w') as f:
                f.write("Email Address\n")
                for email in sorted(self.emails):
                    f.write(f"{email}\n")
            print(f"\n\033[92m[+] Results saved to: {output_file}\033[0m")
        except Exception as e:
            print(f"\n\033[91m[!] Error saving results: {e}\033[0m")

def run():
    """Main function to run email harvester"""
    print("\033[92m" + "="*70)
    print("           EMAIL ADDRESS HARVESTER")
    print("="*70 + "\033[0m\n")
    
    print("\033[93m[!] Warning: Only use on authorized targets!\033[0m\n")
    
    domain = input("\033[95m[?] Enter target domain (e.g., example.com): \033[0m").strip()
    
    if not domain:
        print("\033[91m[!] Domain cannot be empty!\033[0m")
        return
    
    # Remove http/https if present
    domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
    
    print("\n\033[97m[*] Harvesting Methods:\033[0m")
    print("  [1] Web Scraping (crawl website)")
    print("  [2] Common Email Patterns")
    print("  [3] Both methods")
    
    method = input("\n\033[95m[?] Select method (1-3): \033[0m").strip()
    
    harvester = EmailHarvester()
    
    if method in ['1', '3']:
        max_depth = input("\033[95m[?] Crawl depth (0-3, default 2): \033[0m").strip()
        max_depth = int(max_depth) if max_depth.isdigit() else 2
        
        url = f"https://{domain}"
        print(f"\n\033[93m[*] Starting web scraping from {url}...\033[0m\n")
        
        # Disable SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        harvester.scrape_website(url, max_depth)
    
    if method in ['2', '3']:
        print(f"\n\033[93m[*] Generating common email patterns...\033[0m\n")
        common_emails = harvester.generate_common_emails(domain)
        
        for email in common_emails:
            harvester.emails.add(email)
            print(f"\033[92m[+] Generated: {email}\033[0m")
    
    # Try DNS records
    try:
        harvester.search_dns_records(domain)
    except:
        pass
    
    print("\n" + "\033[92m" + "="*70)
    print(f"           HARVEST COMPLETE - Found {len(harvester.emails)} emails")
    print("="*70 + "\033[0m\n")
    
    if harvester.emails:
        print("\033[93mDiscovered Email Addresses:\033[0m")
        for email in sorted(harvester.emails):
            print(f"  \033[97m{email}\033[0m")
        
        save = input("\n\033[95m[?] Save results to file? (y/n): \033[0m").strip().lower()
        if save == 'y':
            filename = input("\033[95m[?] Enter filename (default: emails.txt): \033[0m").strip()
            filename = filename if filename else "emails.txt"
            harvester.save_results(filename)
    else:
        print("\033[91m[!] No email addresses found\033[0m")

if __name__ == "__main__":
    run()
