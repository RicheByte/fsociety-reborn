"""
Subdomain Discovery Tool
Discovers subdomains using DNS brute force and common subdomain wordlists
"""
import os
import socket
import concurrent.futures
from typing import List, Set

class SubdomainDiscovery:
    def __init__(self):
        self.found_subdomains = set()
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'webdisk', 'ns', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mx', 'm',
            'imap', 'test', 'vpn', 'beta', 'dev', 'development', 'staging', 'admin',
            'portal', 'api', 'app', 'blog', 'shop', 'store', 'cdn', 'static', 'assets',
            'img', 'images', 'wiki', 'forum', 'support', 'help', 'docs', 'download',
            'mysql', 'db', 'database', 'news', 'media', 'git', 'svn', 'backup', 'old',
            'new', 'mobile', 'server', 'ns3', 'ns4', 'mail2', 'email', 'direct', 'ssh',
            'secure', 'web', 'web1', 'web2', 'vpn1', 'vpn2', 'remote', 'cloud', 'host'
        ]
    
    def check_subdomain(self, subdomain: str, domain: str) -> bool:
        """Check if a subdomain exists using DNS resolution"""
        try:
            full_domain = f"{subdomain}.{domain}"
            socket.gethostbyname(full_domain)
            return True
        except socket.gaierror:
            return False
        except Exception:
            return False
    
    def scan_subdomain(self, subdomain: str, domain: str):
        """Scan a single subdomain"""
        if self.check_subdomain(subdomain, domain):
            full_domain = f"{subdomain}.{domain}"
            try:
                ip = socket.gethostbyname(full_domain)
                self.found_subdomains.add((full_domain, ip))
                print(f"\033[92m[+] Found: {full_domain} -> {ip}\033[0m")
            except:
                pass
    
    def discover_subdomains(self, domain: str, custom_wordlist: str = None, threads: int = 10):
        """Main subdomain discovery function"""
        print(f"\n\033[93m[*] Starting subdomain enumeration for: {domain}\033[0m")
        print(f"\033[93m[*] Using {threads} threads\033[0m\n")
        
        wordlist = self.common_subdomains
        
        # Load custom wordlist if provided
        if custom_wordlist and os.path.exists(custom_wordlist):
            try:
                with open(custom_wordlist, 'r') as f:
                    custom_words = [line.strip() for line in f if line.strip()]
                    wordlist.extend(custom_words)
                    print(f"\033[92m[+] Loaded {len(custom_words)} entries from custom wordlist\033[0m\n")
            except Exception as e:
                print(f"\033[91m[!] Error loading wordlist: {e}\033[0m\n")
        
        # Remove duplicates
        wordlist = list(set(wordlist))
        print(f"\033[93m[*] Testing {len(wordlist)} potential subdomains...\033[0m\n")
        
        # Multi-threaded scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(self.scan_subdomain, sub, domain) for sub in wordlist]
            concurrent.futures.wait(futures)
        
        return self.found_subdomains
    
    def save_results(self, output_file: str):
        """Save discovered subdomains to a file"""
        try:
            with open(output_file, 'w') as f:
                f.write("Subdomain,IP Address\n")
                for subdomain, ip in sorted(self.found_subdomains):
                    f.write(f"{subdomain},{ip}\n")
            print(f"\n\033[92m[+] Results saved to: {output_file}\033[0m")
        except Exception as e:
            print(f"\n\033[91m[!] Error saving results: {e}\033[0m")

def run():
    """Main function to run the subdomain discovery tool"""
    print("\033[92m" + "="*70)
    print("           SUBDOMAIN DISCOVERY TOOL")
    print("="*70 + "\033[0m\n")
    
    domain = input("\033[95m[?] Enter target domain (e.g., example.com): \033[0m").strip()
    
    if not domain:
        print("\033[91m[!] Domain cannot be empty!\033[0m")
        return
    
    # Remove http/https if present
    domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
    
    wordlist_choice = input("\033[95m[?] Use custom wordlist? (y/n): \033[0m").strip().lower()
    custom_wordlist = None
    
    if wordlist_choice == 'y':
        wordlist_path = input("\033[95m[?] Enter wordlist path: \033[0m").strip()
        if os.path.exists(wordlist_path):
            custom_wordlist = wordlist_path
        else:
            print("\033[91m[!] Wordlist not found, using default list\033[0m")
    
    threads = input("\033[95m[?] Number of threads (default 10): \033[0m").strip()
    threads = int(threads) if threads.isdigit() else 10
    
    scanner = SubdomainDiscovery()
    results = scanner.discover_subdomains(domain, custom_wordlist, threads)
    
    print("\n" + "\033[92m" + "="*70)
    print(f"           SCAN COMPLETE - Found {len(results)} subdomains")
    print("="*70 + "\033[0m\n")
    
    if results:
        print("\033[93mDiscovered Subdomains:\033[0m")
        for subdomain, ip in sorted(results):
            print(f"  \033[97m{subdomain:<40} {ip}\033[0m")
        
        save = input("\n\033[95m[?] Save results to file? (y/n): \033[0m").strip().lower()
        if save == 'y':
            filename = input("\033[95m[?] Enter filename (default: subdomains.csv): \033[0m").strip()
            filename = filename if filename else "subdomains.csv"
            scanner.save_results(filename)
    else:
        print("\033[91m[!] No subdomains discovered\033[0m")

if __name__ == "__main__":
    run()
