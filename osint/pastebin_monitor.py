"""
Pastebin & Leak Monitor
Scans paste sites for exposed credentials and sensitive data
"""
import requests
from bs4 import BeautifulSoup
import re
import time
from datetime import datetime

class PastebinMonitor:
    def __init__(self):
        self.results = []
        self.keywords = []
        
    def search_pastebin(self, query: str):
        """Search Pastebin for query (public pastes only)"""
        print(f"\n\033[93m[*] Searching Pastebin for: {query}\033[0m\n")
        
        try:
            # Scrape recent public pastes
            url = "https://pastebin.com/archive"
            headers = {'User-Agent': 'Mozilla/5.0'}
            
            response = requests.get(url, headers=headers, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find paste links
            paste_links = soup.find_all('a', href=re.compile(r'^/[A-Za-z0-9]+$'))
            
            print(f"\033[97m[*] Found {len(paste_links)} recent pastes to check\033[0m\n")
            
            for link in paste_links[:20]:  # Check first 20
                paste_id = link['href'].strip('/')
                paste_url = f"https://pastebin.com/raw/{paste_id}"
                
                try:
                    paste_response = requests.get(paste_url, headers=headers, timeout=5)
                    paste_content = paste_response.text.lower()
                    
                    if query.lower() in paste_content:
                        print(f"\033[92m[+] Match found in paste: {link['href']}\033[0m")
                        self.results.append({
                            'url': f"https://pastebin.com{link['href']}",
                            'title': link.text.strip(),
                            'matched_keyword': query
                        })
                    
                    time.sleep(0.5)  # Rate limiting
                    
                except Exception as e:
                    continue
                    
        except Exception as e:
            print(f"\033[91m[!] Error searching Pastebin: {str(e)[:50]}\033[0m")
    
    def search_paste_site(self, site_url: str, query: str):
        """Generic paste site searcher"""
        print(f"\n\033[93m[*] Searching {site_url} for: {query}\033[0m")
        
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(site_url, headers=headers, timeout=10)
            
            if query.lower() in response.text.lower():
                print(f"\033[92m[+] Keyword found on {site_url}\033[0m")
                return True
            else:
                print(f"\033[97m[-] No matches found\033[0m")
                return False
                
        except Exception as e:
            print(f"\033[91m[!] Error: {str(e)[:50]}\033[0m")
            return False
    
    def check_email_leaks(self, email: str):
        """Check if email appears in known breaches (simulated)"""
        print(f"\n\033[93m[*] Checking for email leaks: {email}\033[0m\n")
        
        # This is a simulation - in real scenario, you'd check against breach databases
        print(f"\033[97m[*] Note: This is a basic check. For comprehensive results,\033[0m")
        print(f"\033[97m[*] use services like HaveIBeenPwned.com\033[0m\n")
        
        # Search in pastes
        self.search_pastebin(email)
    
    def monitor_keywords(self, keywords: list, duration_minutes: int = 5):
        """Monitor paste sites for keywords over time"""
        print(f"\n\033[93m[*] Starting monitoring for {duration_minutes} minutes...\033[0m")
        print(f"\033[93m[*] Keywords: {', '.join(keywords)}\033[0m\n")
        
        self.keywords = keywords
        start_time = time.time()
        end_time = start_time + (duration_minutes * 60)
        
        check_count = 0
        
        while time.time() < end_time:
            check_count += 1
            print(f"\n\033[97m[*] Check #{check_count} - {datetime.now().strftime('%H:%M:%S')}\033[0m")
            
            for keyword in keywords:
                self.search_pastebin(keyword)
            
            if time.time() < end_time:
                wait_time = 60  # Check every minute
                print(f"\n\033[97m[*] Waiting {wait_time} seconds before next check...\033[0m")
                time.sleep(wait_time)
        
        print(f"\n\033[92m[+] Monitoring complete. Found {len(self.results)} matches.\033[0m")
    
    def search_github_leaks(self, query: str):
        """Search GitHub for potential leaks (code search)"""
        print(f"\n\033[93m[*] Searching GitHub for: {query}\033[0m\n")
        
        search_url = f"https://github.com/search?q={query}+password+OR+api_key+OR+secret&type=code"
        
        print(f"\033[92m[+] GitHub Search URL:\033[0m")
        print(f"\033[97m    {search_url}\033[0m")
        print(f"\033[97m    (GitHub requires authentication for API access)\033[0m")
        
        return search_url
    
    def check_paste_sites(self, query: str):
        """Check multiple paste sites"""
        paste_sites = [
            "https://pastebin.com/archive",
            "https://ghostbin.com/",
            "https://paste.ee/",
        ]
        
        print(f"\n\033[93m[*] Checking multiple paste sites for: {query}\033[0m\n")
        
        for site in paste_sites:
            print(f"\033[97m[*] Checking {site}...\033[0m")
            self.search_paste_site(site, query)
            time.sleep(1)
    
    def save_results(self, output_file: str):
        """Save found results to file"""
        try:
            with open(output_file, 'w') as f:
                f.write("Pastebin/Leak Monitor Results\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*70 + "\n\n")
                
                if self.results:
                    for result in self.results:
                        f.write(f"URL: {result['url']}\n")
                        f.write(f"Title: {result['title']}\n")
                        f.write(f"Matched Keyword: {result['matched_keyword']}\n")
                        f.write("-"*70 + "\n")
                else:
                    f.write("No matches found.\n")
            
            print(f"\n\033[92m[+] Results saved to: {output_file}\033[0m")
        except Exception as e:
            print(f"\n\033[91m[!] Error saving results: {e}\033[0m")

def run():
    """Main function"""
    print("\033[92m" + "="*70)
    print("           PASTEBIN & LEAK MONITOR")
    print("="*70 + "\033[0m\n")
    
    print("\033[93m[!] Use responsibly and only for authorized targets!\033[0m\n")
    
    print("\033[97mSelect mode:\033[0m")
    print("  [1] Search for specific keyword/email")
    print("  [2] Monitor keywords over time")
    print("  [3] Check email for leaks")
    print("  [4] Search GitHub for leaks")
    print("  [5] Check multiple paste sites")
    
    mode = input("\n\033[95m[?] Select mode (1-5): \033[0m").strip()
    
    monitor = PastebinMonitor()
    
    if mode == '1':
        query = input("\033[95m[?] Enter search keyword: \033[0m").strip()
        monitor.search_pastebin(query)
    
    elif mode == '2':
        keywords_input = input("\033[95m[?] Enter keywords (comma-separated): \033[0m").strip()
        keywords = [k.strip() for k in keywords_input.split(',')]
        
        duration = input("\033[95m[?] Monitor duration in minutes (default 5): \033[0m").strip()
        duration = int(duration) if duration.isdigit() else 5
        
        monitor.monitor_keywords(keywords, duration)
    
    elif mode == '3':
        email = input("\033[95m[?] Enter email address: \033[0m").strip()
        monitor.check_email_leaks(email)
    
    elif mode == '4':
        query = input("\033[95m[?] Enter search query (company/domain): \033[0m").strip()
        url = monitor.search_github_leaks(query)
    
    elif mode == '5':
        query = input("\033[95m[?] Enter search keyword: \033[0m").strip()
        monitor.check_paste_sites(query)
    
    print("\n" + "\033[92m" + "="*70)
    print("           SCAN COMPLETE")
    print("="*70 + "\033[0m")
    
    if monitor.results:
        print(f"\n\033[92m[+] Found {len(monitor.results)} matches:\033[0m\n")
        for result in monitor.results:
            print(f"\033[97m  URL: {result['url']}\033[0m")
            print(f"\033[97m  Title: {result['title']}\033[0m")
            print()
        
        save = input("\n\033[95m[?] Save results to file? (y/n): \033[0m").strip().lower()
        if save == 'y':
            filename = input("\033[95m[?] Enter filename (default: leak_results.txt): \033[0m").strip()
            filename = filename if filename else "leak_results.txt"
            monitor.save_results(filename)

if __name__ == "__main__":
    run()
