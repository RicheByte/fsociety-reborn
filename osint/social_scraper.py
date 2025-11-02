"""
Social Media Scraper
Collects public information from social media profiles
"""
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import quote
import json
import time

class SocialMediaScraper:
    def __init__(self):
        self.results = {}
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
    
    def search_twitter(self, username: str):
        """Search for Twitter/X profile information"""
        print(f"\n\033[93m[*] Searching Twitter for: @{username}\033[0m")
        
        profile_url = f"https://twitter.com/{username}"
        
        try:
            response = requests.get(profile_url, headers=self.headers, timeout=10, verify=False)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract basic info (this is simplified - Twitter uses dynamic loading)
                print(f"\033[92m[+] Profile URL: {profile_url}\033[0m")
                
                # Look for meta tags
                description = soup.find('meta', {'name': 'description'})
                if description:
                    print(f"\033[97m    Description: {description.get('content', '')[:100]}\033[0m")
                
                self.results['twitter'] = {
                    'username': username,
                    'url': profile_url,
                    'status': 'Found'
                }
            else:
                print(f"\033[91m[!] Profile not found or private\033[0m")
                self.results['twitter'] = {'status': 'Not found'}
                
        except requests.exceptions.SSLError:
            print(f"\033[91m[!] SSL Error - Twitter may be blocking automated requests\033[0m")
            print(f"\033[97m[*] Try accessing manually: {profile_url}\033[0m")
            self.results['twitter'] = {'status': 'SSL Error'}
        except requests.exceptions.ConnectionError:
            print(f"\033[91m[!] Connection Error - Check your internet connection\033[0m")
            self.results['twitter'] = {'status': 'Connection Error'}
        except Exception as e:
            print(f"\033[91m[!] Error: {str(e)[:80]}\033[0m")
            self.results['twitter'] = {'status': 'Error'}
    
    def search_linkedin(self, name: str):
        """Search for LinkedIn profiles"""
        print(f"\n\033[93m[*] Searching LinkedIn for: {name}\033[0m")
        
        search_url = f"https://www.linkedin.com/search/results/people/?keywords={quote(name)}"
        
        try:
            print(f"\033[92m[+] Search URL: {search_url}\033[0m")
            print(f"\033[97m    (LinkedIn requires login for full access)\033[0m")
            
            self.results['linkedin'] = {
                'name': name,
                'search_url': search_url,
                'status': 'Search URL generated'
            }
            
        except Exception as e:
            print(f"\033[91m[!] Error: {str(e)[:50]}\033[0m")
    
    def search_github(self, username: str):
        """Search GitHub for user profile"""
        print(f"\n\033[93m[*] Searching GitHub for: {username}\033[0m")
        
        api_url = f"https://api.github.com/users/{username}"
        profile_url = f"https://github.com/{username}"
        
        try:
            response = requests.get(api_url, headers=self.headers, timeout=10, verify=False)
            
            if response.status_code == 200:
                data = response.json()
                
                print(f"\033[92m[+] Profile found!\033[0m")
                print(f"\033[97m    Name: {data.get('name', 'N/A')}\033[0m")
                print(f"\033[97m    Bio: {data.get('bio', 'N/A')}\033[0m")
                print(f"\033[97m    Location: {data.get('location', 'N/A')}\033[0m")
                print(f"\033[97m    Company: {data.get('company', 'N/A')}\033[0m")
                print(f"\033[97m    Public Repos: {data.get('public_repos', 0)}\033[0m")
                print(f"\033[97m    Followers: {data.get('followers', 0)}\033[0m")
                print(f"\033[97m    Following: {data.get('following', 0)}\033[0m")
                print(f"\033[97m    Profile URL: {profile_url}\033[0m")
                
                if data.get('email'):
                    print(f"\033[92m[+] Email: {data.get('email')}\033[0m")
                if data.get('blog'):
                    print(f"\033[92m[+] Website: {data.get('blog')}\033[0m")
                
                self.results['github'] = {
                    'username': username,
                    'name': data.get('name'),
                    'bio': data.get('bio'),
                    'location': data.get('location'),
                    'company': data.get('company'),
                    'email': data.get('email'),
                    'website': data.get('blog'),
                    'repos': data.get('public_repos'),
                    'followers': data.get('followers'),
                    'url': profile_url
                }
            else:
                print(f"\033[91m[!] Profile not found\033[0m")
                self.results['github'] = {'status': 'Not found'}
                
        except requests.exceptions.SSLError:
            print(f"\033[91m[!] SSL Error\033[0m")
            self.results['github'] = {'status': 'SSL Error'}
        except requests.exceptions.ConnectionError:
            print(f"\033[91m[!] Connection Error - Check your internet connection\033[0m")
            self.results['github'] = {'status': 'Connection Error'}
        except Exception as e:
            print(f"\033[91m[!] Error: {str(e)[:80]}\033[0m")
            self.results['github'] = {'status': 'Error'}
    
    def search_instagram(self, username: str):
        """Search for Instagram profile"""
        print(f"\n\033[93m[*] Searching Instagram for: @{username}\033[0m")
        
        profile_url = f"https://www.instagram.com/{username}/"
        
        try:
            # Disable SSL warnings for Instagram
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            response = requests.get(profile_url, headers=self.headers, timeout=10, verify=False)
            
            if response.status_code == 200:
                print(f"\033[92m[+] Profile URL: {profile_url}\033[0m")
                
                # Try to extract data from page source (Instagram uses dynamic loading)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Look for JSON data in script tags
                scripts = soup.find_all('script', type='text/javascript')
                for script in scripts:
                    if script.string and 'window._sharedData' in script.string:
                        print(f"\033[97m    Profile data found (requires parsing)\033[0m")
                        break
                
                self.results['instagram'] = {
                    'username': username,
                    'url': profile_url,
                    'status': 'Found'
                }
            else:
                print(f"\033[91m[!] Profile not found or private\033[0m")
                self.results['instagram'] = {'status': 'Not found'}
                
        except requests.exceptions.SSLError:
            print(f"\033[91m[!] SSL Error - Instagram may be blocking automated requests\033[0m")
            print(f"\033[97m[*] Try accessing manually: {profile_url}\033[0m")
            self.results['instagram'] = {'status': 'SSL Error'}
        except requests.exceptions.ConnectionError:
            print(f"\033[91m[!] Connection Error - Check your internet connection\033[0m")
            self.results['instagram'] = {'status': 'Connection Error'}
        except Exception as e:
            print(f"\033[91m[!] Error: {str(e)[:80]}\033[0m")
            print(f"\033[97m[*] Instagram restricts automated access. Try: {profile_url}\033[0m")
            self.results['instagram'] = {'status': 'Error'}
    
    def search_reddit(self, username: str):
        """Search for Reddit user profile"""
        print(f"\n\033[93m[*] Searching Reddit for: u/{username}\033[0m")
        
        profile_url = f"https://www.reddit.com/user/{username}/about.json"
        public_url = f"https://www.reddit.com/user/{username}"
        
        try:
            response = requests.get(profile_url, headers=self.headers, timeout=10, verify=False)
            
            if response.status_code == 200:
                data = response.json()
                user_data = data.get('data', {})
                
                print(f"\033[92m[+] Profile found!\033[0m")
                print(f"\033[97m    Karma: {user_data.get('total_karma', 0)}\033[0m")
                print(f"\033[97m    Created: {time.strftime('%Y-%m-%d', time.localtime(user_data.get('created_utc', 0)))}\033[0m")
                print(f"\033[97m    Profile URL: {public_url}\033[0m")
                
                self.results['reddit'] = {
                    'username': username,
                    'karma': user_data.get('total_karma'),
                    'created': user_data.get('created_utc'),
                    'url': public_url
                }
            else:
                print(f"\033[91m[!] Profile not found\033[0m")
                self.results['reddit'] = {'status': 'Not found'}
                
        except requests.exceptions.SSLError:
            print(f"\033[91m[!] SSL Error\033[0m")
            self.results['reddit'] = {'status': 'SSL Error'}
        except requests.exceptions.ConnectionError:
            print(f"\033[91m[!] Connection Error - Check your internet connection\033[0m")
            self.results['reddit'] = {'status': 'Connection Error'}
        except Exception as e:
            print(f"\033[91m[!] Error: {str(e)[:80]}\033[0m")
            self.results['reddit'] = {'status': 'Error'}
    
    def search_youtube(self, channel_name: str):
        """Search for YouTube channel"""
        print(f"\n\033[93m[*] Searching YouTube for: {channel_name}\033[0m")
        
        search_url = f"https://www.youtube.com/results?search_query={quote(channel_name)}"
        
        try:
            print(f"\033[92m[+] Search URL: {search_url}\033[0m")
            print(f"\033[97m    (YouTube requires API key for detailed info)\033[0m")
            
            self.results['youtube'] = {
                'channel_name': channel_name,
                'search_url': search_url,
                'status': 'Search URL generated'
            }
            
        except Exception as e:
            print(f"\033[91m[!] Error: {str(e)[:50]}\033[0m")
    
    def save_results(self, output_file: str):
        """Save results to JSON file"""
        try:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=4)
            print(f"\n\033[92m[+] Results saved to: {output_file}\033[0m")
        except Exception as e:
            print(f"\n\033[91m[!] Error saving results: {e}\033[0m")

def run():
    """Main function to run social media scraper"""
    print("\033[92m" + "="*70)
    print("           SOCIAL MEDIA SCRAPER")
    print("="*70 + "\033[0m\n")
    
    print("\033[93m[!] Only scrapes publicly available information!\033[0m\n")
    
    print("\033[97mSelect platform:\033[0m")
    print("  [1] Twitter/X")
    print("  [2] LinkedIn")
    print("  [3] GitHub")
    print("  [4] Instagram")
    print("  [5] Reddit")
    print("  [6] YouTube")
    print("  [7] All platforms")
    
    platform = input("\n\033[95m[?] Select platform (1-7): \033[0m").strip()
    
    scraper = SocialMediaScraper()
    
    if platform == '1':
        username = input("\033[95m[?] Enter Twitter username: \033[0m").strip()
        scraper.search_twitter(username)
    
    elif platform == '2':
        name = input("\033[95m[?] Enter name to search: \033[0m").strip()
        scraper.search_linkedin(name)
    
    elif platform == '3':
        username = input("\033[95m[?] Enter GitHub username: \033[0m").strip()
        scraper.search_github(username)
    
    elif platform == '4':
        username = input("\033[95m[?] Enter Instagram username: \033[0m").strip()
        scraper.search_instagram(username)
    
    elif platform == '5':
        username = input("\033[95m[?] Enter Reddit username: \033[0m").strip()
        scraper.search_reddit(username)
    
    elif platform == '6':
        channel = input("\033[95m[?] Enter YouTube channel name: \033[0m").strip()
        scraper.search_youtube(channel)
    
    elif platform == '7':
        username = input("\033[95m[?] Enter username/name: \033[0m").strip()
        scraper.search_twitter(username)
        scraper.search_github(username)
        scraper.search_instagram(username)
        scraper.search_reddit(username)
        scraper.search_linkedin(username)
        scraper.search_youtube(username)
    
    print("\n" + "\033[92m" + "="*70)
    print("           SCAN COMPLETE")
    print("="*70 + "\033[0m")
    
    if scraper.results:
        save = input("\n\033[95m[?] Save results to file? (y/n): \033[0m").strip().lower()
        if save == 'y':
            filename = input("\033[95m[?] Enter filename (default: social_results.json): \033[0m").strip()
            filename = filename if filename else "social_results.json"
            scraper.save_results(filename)

if __name__ == "__main__":
    run()
