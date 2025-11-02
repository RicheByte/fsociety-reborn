"""
Recon-ng Automation Script
Automated host discovery and data collection
"""
import socket
import subprocess
import os
import json
from datetime import datetime

class ReconNGAutomation:
    def __init__(self):
        self.results = {
            'hosts': [],
            'domains': [],
            'emails': [],
            'ports': [],
            'metadata': {}
        }
        
    def dns_enumeration(self, domain: str):
        """Perform DNS enumeration"""
        print(f"\n\033[93m[*] DNS Enumeration for: {domain}\033[0m\n")
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        
        for record_type in record_types:
            try:
                import dns.resolver
                answers = dns.resolver.resolve(domain, record_type)
                
                print(f"\033[92m[+] {record_type} Records:\033[0m")
                for rdata in answers:
                    print(f"\033[97m    {rdata}\033[0m")
                    
                    if record_type == 'A':
                        self.results['hosts'].append(str(rdata))
                
            except ImportError:
                print(f"\033[91m[!] dnspython not installed\033[0m")
                break
            except Exception:
                pass
    
    def reverse_dns_sweep(self, ip_range: str):
        """Perform reverse DNS on IP range"""
        print(f"\n\033[93m[*] Reverse DNS sweep: {ip_range}\033[0m\n")
        
        # Parse IP range (e.g., 192.168.1.0/24)
        base = '.'.join(ip_range.split('.')[0:3])
        
        found = 0
        for i in range(1, 255):
            ip = f"{base}.{i}"
            try:
                hostname = socket.gethostbyaddr(ip)
                print(f"\033[92m[+] {ip} -> {hostname[0]}\033[0m")
                self.results['hosts'].append({'ip': ip, 'hostname': hostname[0]})
                found += 1
            except:
                pass
        
        print(f"\n\033[97m[*] Found {found} hosts with reverse DNS\033[0m")
    
    def whois_lookup(self, domain: str):
        """WHOIS lookup"""
        print(f"\n\033[93m[*] WHOIS Lookup: {domain}\033[0m\n")
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect(('whois.iana.org', 43))
            s.send(f"{domain}\r\n".encode())
            
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            
            s.close()
            
            whois_data = response.decode('utf-8', errors='ignore')
            
            # Extract emails from WHOIS
            import re
            emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', whois_data)
            
            if emails:
                print(f"\033[92m[+] Found {len(emails)} emails in WHOIS:\033[0m")
                for email in set(emails):
                    print(f"\033[97m    {email}\033[0m")
                    self.results['emails'].append(email)
            
            self.results['metadata']['whois'] = whois_data
            
        except Exception as e:
            print(f"\033[91m[!] WHOIS failed: {str(e)}\033[0m")
    
    def port_discovery(self, target: str, ports: list = None):
        """Discover open ports"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 8080, 8443]
        
        print(f"\n\033[93m[*] Port Discovery: {target}\033[0m\n")
        
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                
                if result == 0:
                    print(f"\033[92m[+] Port {port} is OPEN\033[0m")
                    open_ports.append(port)
                
                sock.close()
            except:
                pass
        
        self.results['ports'] = open_ports
        print(f"\n\033[97m[*] Found {len(open_ports)} open ports\033[0m")
    
    def subdomain_brute_force(self, domain: str, wordlist: list = None):
        """Brute force subdomains"""
        if wordlist is None:
            wordlist = [
                'www', 'mail', 'ftp', 'admin', 'vpn', 'api', 'dev', 'test',
                'staging', 'blog', 'shop', 'portal', 'cdn', 'secure', 'mobile'
            ]
        
        print(f"\n\033[93m[*] Subdomain Brute Force: {domain}\033[0m\n")
        print(f"\033[97m[*] Testing {len(wordlist)} subdomains...\033[0m\n")
        
        found = 0
        for sub in wordlist:
            full_domain = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(full_domain)
                print(f"\033[92m[+] {full_domain} -> {ip}\033[0m")
                self.results['domains'].append({'domain': full_domain, 'ip': ip})
                found += 1
            except:
                pass
        
        print(f"\n\033[97m[*] Found {found} subdomains\033[0m")
    
    def geo_ip_lookup(self, ip: str):
        """Geolocation lookup"""
        print(f"\n\033[93m[*] Geo IP Lookup: {ip}\033[0m\n")
        
        try:
            import requests
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'success':
                    print(f"\033[92m[+] Location Information:\033[0m")
                    print(f"\033[97m    Country: {data.get('country')}\033[0m")
                    print(f"\033[97m    Region: {data.get('regionName')}\033[0m")
                    print(f"\033[97m    City: {data.get('city')}\033[0m")
                    print(f"\033[97m    ISP: {data.get('isp')}\033[0m")
                    print(f"\033[97m    Coordinates: {data.get('lat')}, {data.get('lon')}\033[0m")
                    
                    self.results['metadata']['geolocation'] = data
        except:
            print(f"\033[91m[!] Geolocation lookup failed\033[0m")
    
    def full_reconnaissance(self, target: str, target_type: str = 'domain'):
        """Perform full reconnaissance"""
        print("\n\033[92m" + "="*70)
        print("           FULL RECONNAISSANCE")
        print("="*70 + "\033[0m")
        
        if target_type == 'domain':
            # Domain recon
            self.whois_lookup(target)
            self.dns_enumeration(target)
            self.subdomain_brute_force(target)
            
            # Get IP and scan ports
            try:
                ip = socket.gethostbyname(target)
                print(f"\n\033[92m[+] Resolved {target} to {ip}\033[0m")
                self.port_discovery(ip)
                self.geo_ip_lookup(ip)
            except:
                pass
        
        elif target_type == 'ip':
            # IP recon
            self.port_discovery(target)
            self.geo_ip_lookup(target)
            
            # Reverse DNS
            try:
                hostname = socket.gethostbyaddr(target)
                print(f"\n\033[92m[+] Reverse DNS: {hostname[0]}\033[0m")
                self.results['metadata']['hostname'] = hostname[0]
            except:
                pass
    
    def generate_report(self):
        """Generate comprehensive report"""
        print("\n\n" + "\033[92m" + "="*70)
        print("           RECONNAISSANCE REPORT")
        print("="*70 + "\033[0m\n")
        
        print(f"\033[93mHosts Discovered: {len(self.results['hosts'])}\033[0m")
        if self.results['hosts']:
            for host in self.results['hosts'][:10]:  # Show first 10
                if isinstance(host, dict):
                    print(f"\033[97m  {host.get('ip', 'N/A')} -> {host.get('hostname', 'N/A')}\033[0m")
                else:
                    print(f"\033[97m  {host}\033[0m")
        
        print(f"\n\033[93mDomains Found: {len(self.results['domains'])}\033[0m")
        if self.results['domains']:
            for domain in self.results['domains'][:10]:
                print(f"\033[97m  {domain.get('domain', 'N/A')} -> {domain.get('ip', 'N/A')}\033[0m")
        
        print(f"\n\033[93mEmails Found: {len(self.results['emails'])}\033[0m")
        if self.results['emails']:
            for email in self.results['emails'][:10]:
                print(f"\033[97m  {email}\033[0m")
        
        print(f"\n\033[93mOpen Ports: {len(self.results['ports'])}\033[0m")
        if self.results['ports']:
            print(f"\033[97m  {', '.join(map(str, self.results['ports']))}\033[0m")
    
    def save_results(self, filename: str):
        """Save results to JSON"""
        try:
            self.results['generated'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=4)
            
            print(f"\n\033[92m[+] Results saved to: {filename}\033[0m")
        except Exception as e:
            print(f"\n\033[91m[!] Error saving: {str(e)}\033[0m")

def run():
    """Main function"""
    print("\033[92m" + "="*70)
    print("           RECON-NG AUTOMATION SCRIPT")
    print("="*70 + "\033[0m\n")
    
    print("\033[97mSelect reconnaissance mode:\033[0m")
    print("  [1] Full reconnaissance (domain)")
    print("  [2] Full reconnaissance (IP)")
    print("  [3] DNS enumeration only")
    print("  [4] Subdomain discovery only")
    print("  [5] Port scan only")
    print("  [6] WHOIS lookup only")
    
    mode = input("\n\033[95m[?] Select mode (1-6): \033[0m").strip()
    
    recon = ReconNGAutomation()
    
    if mode == '1':
        target = input("\033[95m[?] Enter target domain: \033[0m").strip()
        recon.full_reconnaissance(target, 'domain')
    
    elif mode == '2':
        target = input("\033[95m[?] Enter target IP: \033[0m").strip()
        recon.full_reconnaissance(target, 'ip')
    
    elif mode == '3':
        target = input("\033[95m[?] Enter domain: \033[0m").strip()
        recon.dns_enumeration(target)
    
    elif mode == '4':
        target = input("\033[95m[?] Enter domain: \033[0m").strip()
        recon.subdomain_brute_force(target)
    
    elif mode == '5':
        target = input("\033[95m[?] Enter target (IP/domain): \033[0m").strip()
        recon.port_discovery(target)
    
    elif mode == '6':
        target = input("\033[95m[?] Enter domain: \033[0m").strip()
        recon.whois_lookup(target)
    
    # Generate report
    recon.generate_report()
    
    # Save results
    save = input("\n\033[95m[?] Save results to file? (y/n): \033[0m").strip().lower()
    if save == 'y':
        filename = input("\033[95m[?] Filename (default: recon_results.json): \033[0m").strip()
        filename = filename if filename else "recon_results.json"
        recon.save_results(filename)
    
    print("\n" + "\033[92m" + "="*70)
    print("           RECONNAISSANCE COMPLETE")
    print("="*70 + "\033[0m")

if __name__ == "__main__":
    run()
