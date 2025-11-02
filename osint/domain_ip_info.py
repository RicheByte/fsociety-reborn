"""
Domain & IP Information Tool
WHOIS lookups and IP geolocation without external APIs
"""
import socket
import struct
import requests
from datetime import datetime
import re

class DomainIPInfo:
    def __init__(self):
        self.results = {}
        
    def get_ip_from_domain(self, domain: str) -> str:
        """Resolve domain to IP address"""
        try:
            ip = socket.gethostbyname(domain)
            print(f"\033[92m[+] IP Address: {ip}\033[0m")
            return ip
        except socket.gaierror:
            print(f"\033[91m[!] Failed to resolve domain\033[0m")
            return None
        except Exception as e:
            print(f"\033[91m[!] Error: {str(e)}\033[0m")
            return None
    
    def get_hostname_from_ip(self, ip: str) -> str:
        """Reverse DNS lookup"""
        try:
            hostname = socket.gethostbyaddr(ip)
            print(f"\033[92m[+] Hostname: {hostname[0]}\033[0m")
            return hostname[0]
        except socket.herror:
            print(f"\033[91m[!] No hostname found\033[0m")
            return None
        except Exception as e:
            print(f"\033[91m[!] Error: {str(e)}\033[0m")
            return None
    
    def get_whois_info(self, domain: str):
        """Basic WHOIS lookup using TCP connection"""
        print(f"\n\033[93m[*] Performing WHOIS lookup for: {domain}\033[0m\n")
        
        # Remove protocol and path
        domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        
        whois_servers = {
            'com': 'whois.verisign-grs.com',
            'net': 'whois.verisign-grs.com',
            'org': 'whois.pir.org',
            'info': 'whois.afilias.net',
            'biz': 'whois.biz',
            'io': 'whois.nic.io',
            'co': 'whois.nic.co',
            'me': 'whois.nic.me',
            'tv': 'whois.nic.tv',
            'default': 'whois.iana.org'
        }
        
        # Get TLD
        tld = domain.split('.')[-1]
        whois_server = whois_servers.get(tld, whois_servers['default'])
        
        try:
            # Connect to WHOIS server
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((whois_server, 43))
            s.send(f"{domain}\r\n".encode())
            
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            
            s.close()
            
            whois_data = response.decode('utf-8', errors='ignore')
            
            # Parse important fields
            self.parse_whois(whois_data)
            
            return whois_data
            
        except Exception as e:
            print(f"\033[91m[!] WHOIS lookup failed: {str(e)}\033[0m")
            return None
    
    def parse_whois(self, whois_data: str):
        """Parse WHOIS data for important information"""
        patterns = {
            'registrar': r'Registrar:\s*(.+)',
            'creation_date': r'Creation Date:\s*(.+)',
            'expiration_date': r'Registry Expiry Date:\s*(.+)',
            'updated_date': r'Updated Date:\s*(.+)',
            'name_servers': r'Name Server:\s*(.+)',
            'status': r'Status:\s*(.+)',
            'org': r'Registrant Organization:\s*(.+)',
            'country': r'Registrant Country:\s*(.+)',
        }
        
        for key, pattern in patterns.items():
            matches = re.findall(pattern, whois_data, re.IGNORECASE)
            if matches:
                if key == 'name_servers':
                    print(f"\033[97m  {key.replace('_', ' ').title()}:\033[0m")
                    for ns in set(matches):
                        print(f"\033[97m    - {ns.strip()}\033[0m")
                else:
                    print(f"\033[97m  {key.replace('_', ' ').title()}: {matches[0].strip()}\033[0m")
    
    def get_ip_info(self, ip: str):
        """Get IP information using free geolocation service"""
        print(f"\n\033[93m[*] Getting IP information for: {ip}\033[0m\n")
        
        try:
            # Using ip-api.com (free, no API key required)
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'success':
                    print(f"\033[97m  Country: {data.get('country', 'N/A')}\033[0m")
                    print(f"\033[97m  Country Code: {data.get('countryCode', 'N/A')}\033[0m")
                    print(f"\033[97m  Region: {data.get('regionName', 'N/A')}\033[0m")
                    print(f"\033[97m  City: {data.get('city', 'N/A')}\033[0m")
                    print(f"\033[97m  ZIP: {data.get('zip', 'N/A')}\033[0m")
                    print(f"\033[97m  Latitude: {data.get('lat', 'N/A')}\033[0m")
                    print(f"\033[97m  Longitude: {data.get('lon', 'N/A')}\033[0m")
                    print(f"\033[97m  Timezone: {data.get('timezone', 'N/A')}\033[0m")
                    print(f"\033[97m  ISP: {data.get('isp', 'N/A')}\033[0m")
                    print(f"\033[97m  Organization: {data.get('org', 'N/A')}\033[0m")
                    print(f"\033[97m  AS: {data.get('as', 'N/A')}\033[0m")
                    
                    self.results['ip_info'] = data
                else:
                    print(f"\033[91m[!] Failed to get IP information\033[0m")
            else:
                print(f"\033[91m[!] API request failed\033[0m")
                
        except Exception as e:
            print(f"\033[91m[!] Error: {str(e)}\033[0m")
    
    def get_dns_records(self, domain: str):
        """Get various DNS records"""
        print(f"\n\033[93m[*] Fetching DNS records for: {domain}\033[0m\n")
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
        
        try:
            import dns.resolver
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    print(f"\033[92m[+] {record_type} Records:\033[0m")
                    for rdata in answers:
                        print(f"\033[97m    {rdata}\033[0m")
                    print()
                except dns.resolver.NoAnswer:
                    pass
                except dns.resolver.NXDOMAIN:
                    print(f"\033[91m[!] Domain does not exist\033[0m")
                    break
                except Exception:
                    pass
                    
        except ImportError:
            print("\033[91m[!] dnspython not installed\033[0m")
            print("\033[93m[*] Install with: pip install dnspython\033[0m")
            
            # Fallback to basic lookup
            print(f"\n\033[93m[*] Using basic DNS lookup...\033[0m\n")
            try:
                ip = socket.gethostbyname(domain)
                print(f"\033[92m[+] A Record: {ip}\033[0m")
            except:
                print(f"\033[91m[!] DNS lookup failed\033[0m")
    
    def check_port_status(self, ip: str, ports: list):
        """Check common ports"""
        print(f"\n\033[93m[*] Checking common ports...\033[0m\n")
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                
                if result == 0:
                    print(f"\033[92m[+] Port {port} is OPEN\033[0m")
                else:
                    print(f"\033[97m[-] Port {port} is CLOSED\033[0m")
                
                sock.close()
            except Exception as e:
                print(f"\033[91m[!] Error checking port {port}: {str(e)[:30]}\033[0m")
    
    def save_results(self, output_file: str, domain: str, whois_data: str):
        """Save results to file"""
        try:
            with open(output_file, 'w') as f:
                f.write(f"Domain/IP Information Report\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Target: {domain}\n")
                f.write("="*70 + "\n\n")
                
                if whois_data:
                    f.write("WHOIS Information:\n")
                    f.write("-"*70 + "\n")
                    f.write(whois_data)
                    f.write("\n\n")
                
                if self.results.get('ip_info'):
                    f.write("IP Geolocation:\n")
                    f.write("-"*70 + "\n")
                    for key, value in self.results['ip_info'].items():
                        f.write(f"{key}: {value}\n")
            
            print(f"\n\033[92m[+] Results saved to: {output_file}\033[0m")
        except Exception as e:
            print(f"\n\033[91m[!] Error saving results: {e}\033[0m")

def run():
    """Main function"""
    print("\033[92m" + "="*70)
    print("           DOMAIN & IP INFORMATION TOOL")
    print("="*70 + "\033[0m\n")
    
    target = input("\033[95m[?] Enter domain or IP address: \033[0m").strip()
    
    if not target:
        print("\033[91m[!] Target cannot be empty!\033[0m")
        return
    
    tool = DomainIPInfo()
    
    # Detect if input is IP or domain
    is_ip = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target)
    
    if is_ip:
        # IP address provided
        print(f"\n\033[93m[*] Target is an IP address\033[0m")
        tool.get_hostname_from_ip(target)
        tool.get_ip_info(target)
        
        # Port scan
        port_scan = input("\n\033[95m[?] Scan common ports? (y/n): \033[0m").strip().lower()
        if port_scan == 'y':
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080]
            tool.check_port_status(target, common_ports)
    else:
        # Domain provided
        print(f"\n\033[93m[*] Target is a domain\033[0m")
        
        # Remove protocol if present
        target = target.replace('http://', '').replace('https://', '').split('/')[0]
        
        # Get IP
        ip = tool.get_ip_from_domain(target)
        
        # WHOIS lookup
        whois_data = tool.get_whois_info(target)
        
        # DNS records
        tool.get_dns_records(target)
        
        # IP info if resolved
        if ip:
            tool.get_ip_info(ip)
            
            # Port scan
            port_scan = input("\n\033[95m[?] Scan common ports? (y/n): \033[0m").strip().lower()
            if port_scan == 'y':
                common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080]
                tool.check_port_status(ip, common_ports)
    
    print("\n" + "\033[92m" + "="*70)
    print("           SCAN COMPLETE")
    print("="*70 + "\033[0m")
    
    # Save results
    save = input("\n\033[95m[?] Save results to file? (y/n): \033[0m").strip().lower()
    if save == 'y':
        filename = input("\033[95m[?] Enter filename (default: domain_info.txt): \033[0m").strip()
        filename = filename if filename else "domain_info.txt"
        tool.save_results(filename, target, whois_data if not is_ip else "")

if __name__ == "__main__":
    run()
