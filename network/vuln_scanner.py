#!/usr/bin/env python3
import socket
import subprocess
import concurrent.futures
import re
import time
from datetime import datetime
import json
import ssl
import requests
from collections import defaultdict
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class AdvancedVulnerabilityScanner:
    def __init__(self):
        self.vulnerabilities = []
        self.services = {}
        self.scan_results = defaultdict(list)
        
        self.vuln_signatures = {
            'SSH': {
                'ports': [22],
                'checks': ['weak_version', 'weak_auth'],
                'versions': {
                    'vulnerable': ['OpenSSH 7.2', 'OpenSSH 6.', 'OpenSSH 5.'],
                    'check_cve': True
                }
            },
            'HTTP': {
                'ports': [80, 8080, 8000, 8888],
                'checks': ['headers', 'methods', 'directory_listing', 'ssl'],
                'vulnerable_headers': ['Server', 'X-Powered-By', 'X-AspNet-Version']
            },
            'HTTPS': {
                'ports': [443, 8443],
                'checks': ['ssl_version', 'ssl_cipher', 'certificate'],
                'weak_ssl': ['SSLv2', 'SSLv3', 'TLSv1.0']
            },
            'FTP': {
                'ports': [21],
                'checks': ['anonymous', 'version'],
                'vulnerable': ['vsftpd 2.3.4', 'ProFTPD 1.3.3']
            },
            'SMB': {
                'ports': [139, 445],
                'checks': ['eternalblue', 'null_session', 'version'],
                'cves': ['MS17-010', 'CVE-2017-0144']
            },
            'MySQL': {
                'ports': [3306],
                'checks': ['anonymous', 'version', 'weak_auth'],
                'vulnerable': ['MySQL 5.5', 'MySQL 5.6']
            },
            'PostgreSQL': {
                'ports': [5432],
                'checks': ['version', 'weak_auth'],
                'vulnerable': ['PostgreSQL 9.']
            },
            'RDP': {
                'ports': [3389],
                'checks': ['bluekeep', 'version'],
                'cves': ['CVE-2019-0708']
            },
            'Telnet': {
                'ports': [23],
                'checks': ['exposed'],
                'severity': 'HIGH'
            },
            'MongoDB': {
                'ports': [27017],
                'checks': ['anonymous', 'version']
            },
            'Redis': {
                'ports': [6379],
                'checks': ['anonymous', 'version']
            },
            'Elasticsearch': {
                'ports': [9200],
                'checks': ['anonymous', 'version']
            }
        }
    
    def port_scan(self, target, ports):
        print(f"\033[93m[*] Scanning {target}...\033[0m\n")
        
        open_ports = []
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    service = self.identify_service(target, port)
                    return (port, service)
            except:
                pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(check_port, port) for port in ports]
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    port, service = result
                    open_ports.append((port, service))
                    print(f"\033[92m[+] Port {port}: {service}\033[0m")
        
        return open_ports
    
    def identify_service(self, target, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target, port))
            
            banner = ''
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
            except:
                pass
            
            if not banner:
                try:
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                except:
                    pass
            
            sock.close()
            
            if 'SSH' in banner:
                return f"SSH: {banner.strip()}"
            elif 'HTTP' in banner or 'HTML' in banner:
                return f"HTTP: {banner.split(chr(10))[0]}"
            elif 'FTP' in banner:
                return f"FTP: {banner.strip()}"
            elif 'MySQL' in banner:
                return "MySQL"
            elif 'PostgreSQL' in banner:
                return "PostgreSQL"
            else:
                return banner.strip()[:50] if banner else "Unknown"
        
        except:
            port_services = {
                22: 'SSH', 80: 'HTTP', 443: 'HTTPS', 21: 'FTP',
                23: 'Telnet', 25: 'SMTP', 3306: 'MySQL', 5432: 'PostgreSQL',
                139: 'NetBIOS', 445: 'SMB', 3389: 'RDP', 6379: 'Redis',
                27017: 'MongoDB', 9200: 'Elasticsearch', 8080: 'HTTP-Alt'
            }
            return port_services.get(port, 'Unknown')
    
    def check_ssh_vulns(self, target, port):
        print(f"\n\033[96m[*] Testing SSH vulnerabilities...\033[0m")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            print(f"\033[97m  Version: {banner}\033[0m")
            
            for vuln_version in self.vuln_signatures['SSH']['versions']['vulnerable']:
                if vuln_version in banner:
                    self.vulnerabilities.append({
                        'target': target,
                        'port': port,
                        'service': 'SSH',
                        'severity': 'HIGH',
                        'vulnerability': f'Vulnerable SSH version: {banner}',
                        'recommendation': 'Update SSH to latest version'
                    })
                    print(f"\033[91m  [!] Vulnerable version detected\033[0m")
            
            if 'OpenSSH' in banner:
                version_match = re.search(r'OpenSSH[_\s](\d+\.\d+)', banner)
                if version_match:
                    version = float(version_match.group(1))
                    if version < 7.4:
                        self.vulnerabilities.append({
                            'target': target,
                            'port': port,
                            'service': 'SSH',
                            'severity': 'MEDIUM',
                            'vulnerability': 'SSH version < 7.4 (user enumeration possible)',
                            'cve': 'CVE-2018-15473',
                            'recommendation': 'Update to OpenSSH 7.4 or later'
                        })
        
        except Exception as e:
            pass
    
    def check_http_vulns(self, target, port):
        print(f"\n\033[96m[*] Testing HTTP vulnerabilities...\033[0m")
        
        protocol = 'https' if port in [443, 8443] else 'http'
        url = f"{protocol}://{target}:{port}"
        
        try:
            response = requests.get(url, timeout=5, verify=False, allow_redirects=True)
            
            print(f"\033[97m  Status: {response.status_code}\033[0m")
            
            for header in self.vuln_signatures['HTTP']['vulnerable_headers']:
                if header in response.headers:
                    value = response.headers[header]
                    print(f"\033[93m  {header}: {value}\033[0m")
                    
                    self.vulnerabilities.append({
                        'target': target,
                        'port': port,
                        'service': 'HTTP',
                        'severity': 'LOW',
                        'vulnerability': f'Information disclosure: {header} header exposed',
                        'details': value,
                        'recommendation': f'Remove or obfuscate {header} header'
                    })
            
            dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
            for method in dangerous_methods:
                try:
                    test_response = requests.request(method, url, timeout=3, verify=False)
                    if test_response.status_code not in [405, 501]:
                        self.vulnerabilities.append({
                            'target': target,
                            'port': port,
                            'service': 'HTTP',
                            'severity': 'MEDIUM',
                            'vulnerability': f'Dangerous HTTP method enabled: {method}',
                            'recommendation': f'Disable {method} method'
                        })
                        print(f"\033[91m  [!] {method} method enabled\033[0m")
                except:
                    pass
            
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME-sniffing protection',
                'Content-Security-Policy': 'XSS protection',
                'Strict-Transport-Security': 'HTTPS enforcement',
                'X-XSS-Protection': 'XSS filter'
            }
            
            missing_headers = []
            for header, purpose in security_headers.items():
                if header not in response.headers:
                    missing_headers.append(f"{header} ({purpose})")
            
            if missing_headers:
                self.vulnerabilities.append({
                    'target': target,
                    'port': port,
                    'service': 'HTTP',
                    'severity': 'MEDIUM',
                    'vulnerability': 'Missing security headers',
                    'details': ', '.join(missing_headers),
                    'recommendation': 'Implement recommended security headers'
                })
                print(f"\033[93m  [!] Missing {len(missing_headers)} security headers\033[0m")
        
        except Exception as e:
            pass
    
    def check_ssl_vulns(self, target, port):
        print(f"\n\033[96m[*] Testing SSL/TLS vulnerabilities...\033[0m")
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    protocol = ssock.version()
                    cipher = ssock.cipher()
                    
                    print(f"\033[97m  Protocol: {protocol}\033[0m")
                    print(f"\033[97m  Cipher: {cipher[0]}\033[0m")
                    
                    if protocol in self.vuln_signatures['HTTPS']['weak_ssl']:
                        self.vulnerabilities.append({
                            'target': target,
                            'port': port,
                            'service': 'HTTPS',
                            'severity': 'HIGH',
                            'vulnerability': f'Weak SSL/TLS protocol: {protocol}',
                            'recommendation': 'Disable SSLv2, SSLv3, and TLSv1.0'
                        })
                        print(f"\033[91m  [!] Weak protocol: {protocol}\033[0m")
                    
                    cert = ssock.getpeercert()
                    if cert:
                        not_after = cert.get('notAfter')
                        if not_after:
                            print(f"\033[97m  Certificate expires: {not_after}\033[0m")
        
        except ssl.SSLError as e:
            print(f"\033[91m  SSL Error: {str(e)}\033[0m")
        except Exception as e:
            pass
    
    def check_smb_vulns(self, target, port):
        print(f"\n\033[96m[*] Testing SMB vulnerabilities (EternalBlue)...\033[0m")
        
        try:
            result = subprocess.run(
                ['nmap', '-p', str(port), '--script', 'smb-vuln-ms17-010', target],
                capture_output=True, text=True, timeout=30
            )
            
            if 'VULNERABLE' in result.stdout:
                self.vulnerabilities.append({
                    'target': target,
                    'port': port,
                    'service': 'SMB',
                    'severity': 'CRITICAL',
                    'vulnerability': 'EternalBlue (MS17-010)',
                    'cve': 'CVE-2017-0144',
                    'recommendation': 'Apply MS17-010 security patch immediately'
                })
                print(f"\033[91m  [!] VULNERABLE TO ETERNALBLUE\033[0m")
            else:
                print(f"\033[92m  [+] Not vulnerable to EternalBlue\033[0m")
        
        except FileNotFoundError:
            print(f"\033[93m  [!] Nmap not found (install for advanced checks)\033[0m")
        except Exception as e:
            pass
    
    def check_database_vulns(self, target, port, db_type):
        print(f"\n\033[96m[*] Testing {db_type} vulnerabilities...\033[0m")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                self.vulnerabilities.append({
                    'target': target,
                    'port': port,
                    'service': db_type,
                    'severity': 'HIGH',
                    'vulnerability': f'{db_type} exposed to internet',
                    'recommendation': f'Restrict {db_type} access to localhost or trusted IPs'
                })
                print(f"\033[91m  [!] {db_type} accessible from internet\033[0m")
        
        except Exception as e:
            pass
    
    def generate_report(self):
        print(f"\n\n\033[92m{'='*70}\033[0m")
        print(f"\033[92m[*] VULNERABILITY SCAN REPORT\033[0m")
        print(f"\033[92m{'='*70}\033[0m\n")
        
        if not self.vulnerabilities:
            print(f"\033[92m[+] No major vulnerabilities detected\033[0m")
            return
        
        severity_counts = defaultdict(int)
        for vuln in self.vulnerabilities:
            severity_counts[vuln['severity']] += 1
        
        print(f"\033[91mCRITICAL: {severity_counts['CRITICAL']}\033[0m")
        print(f"\033[93mHIGH: {severity_counts['HIGH']}\033[0m")
        print(f"\033[93mMEDIUM: {severity_counts['MEDIUM']}\033[0m")
        print(f"\033[97mLOW: {severity_counts['LOW']}\033[0m\n")
        
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_vulns = sorted(self.vulnerabilities, key=lambda x: severity_order.get(x['severity'], 4))
        
        for i, vuln in enumerate(sorted_vulns, 1):
            severity_color = {
                'CRITICAL': '\033[91m',
                'HIGH': '\033[91m',
                'MEDIUM': '\033[93m',
                'LOW': '\033[97m'
            }.get(vuln['severity'], '\033[97m')
            
            print(f"{severity_color}[{vuln['severity']}] Vulnerability #{i}\033[0m")
            print(f"\033[97m  Target: {vuln['target']}:{vuln['port']}\033[0m")
            print(f"\033[97m  Service: {vuln['service']}\033[0m")
            print(f"\033[97m  Issue: {vuln['vulnerability']}\033[0m")
            
            if vuln.get('cve'):
                print(f"\033[93m  CVE: {vuln['cve']}\033[0m")
            if vuln.get('details'):
                print(f"\033[97m  Details: {vuln['details']}\033[0m")
            
            print(f"\033[96m  Recommendation: {vuln['recommendation']}\033[0m")
            print()
    
    def save_report(self, filename='vuln_report.json'):
        try:
            report = {
                'scan_date': datetime.now().isoformat(),
                'total_vulnerabilities': len(self.vulnerabilities),
                'severity_summary': {
                    'critical': len([v for v in self.vulnerabilities if v['severity'] == 'CRITICAL']),
                    'high': len([v for v in self.vulnerabilities if v['severity'] == 'HIGH']),
                    'medium': len([v for v in self.vulnerabilities if v['severity'] == 'MEDIUM']),
                    'low': len([v for v in self.vulnerabilities if v['severity'] == 'LOW'])
                },
                'vulnerabilities': self.vulnerabilities
            }
            
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            
            print(f"\033[92m[+] Report saved: {filename}\033[0m")
        
        except Exception as e:
            print(f"\033[91m[!] Error saving: {e}\033[0m")

def run():
    print("\033[92m" + "="*70)
    print("     ADVANCED VULNERABILITY SCANNER")
    print("="*70 + "\033[0m\n")
    
    print("\033[91m[!] WARNING: Only scan targets you own or have permission to test\033[0m\n")
    
    target = input("\033[95m[?] Target IP/hostname: \033[0m").strip()
    if not target:
        print("\033[91m[!] No target specified\033[0m")
        return
    
    print("\n\033[97mScan mode:\033[0m")
    print("  [1] Quick scan (common ports)")
    print("  [2] Standard scan (top 1000 ports)")
    print("  [3] Full scan (all ports)")
    print("  [4] Custom port range")
    
    mode = input("\n\033[95m[?] Select: \033[0m").strip()
    
    if mode == '1':
        ports = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432, 6379, 8080, 27017, 9200]
    elif mode == '2':
        ports = range(1, 1001)
    elif mode == '3':
        confirm = input("\033[91m[!] Full scan takes time. Continue? (yes/no): \033[0m").strip().lower()
        if confirm != 'yes':
            return
        ports = range(1, 65536)
    elif mode == '4':
        start = int(input("\033[95m[?] Start port: \033[0m").strip() or "1")
        end = int(input("\033[95m[?] End port: \033[0m").strip() or "1000")
        ports = range(start, end + 1)
    else:
        ports = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432, 8080]
    
    scanner = AdvancedVulnerabilityScanner()
    
    print(f"\n\033[92m{'='*70}\033[0m")
    print(f"\033[92m[*] PHASE 1: PORT SCANNING\033[0m")
    print(f"\033[92m{'='*70}\033[0m")
    
    open_ports = scanner.port_scan(target, ports)
    
    if not open_ports:
        print(f"\n\033[93m[!] No open ports found\033[0m")
        return
    
    print(f"\n\033[92m[+] Found {len(open_ports)} open ports\033[0m")
    
    print(f"\n\033[92m{'='*70}\033[0m")
    print(f"\033[92m[*] PHASE 2: VULNERABILITY TESTING\033[0m")
    print(f"\033[92m{'='*70}\033[0m")
    
    for port, service in open_ports:
        if port == 22 or 'SSH' in service:
            scanner.check_ssh_vulns(target, port)
        elif port in [80, 8080, 8000, 8888] or 'HTTP' in service:
            scanner.check_http_vulns(target, port)
        elif port in [443, 8443] or 'HTTPS' in service:
            scanner.check_http_vulns(target, port)
            scanner.check_ssl_vulns(target, port)
        elif port in [139, 445] or 'SMB' in service:
            scanner.check_smb_vulns(target, port)
        elif port == 3306 or 'MySQL' in service:
            scanner.check_database_vulns(target, port, 'MySQL')
        elif port == 5432 or 'PostgreSQL' in service:
            scanner.check_database_vulns(target, port, 'PostgreSQL')
        elif port == 6379 or 'Redis' in service:
            scanner.check_database_vulns(target, port, 'Redis')
        elif port == 27017 or 'MongoDB' in service:
            scanner.check_database_vulns(target, port, 'MongoDB')
        elif port == 9200 or 'Elasticsearch' in service:
            scanner.check_database_vulns(target, port, 'Elasticsearch')
        elif port == 23:
            scanner.vulnerabilities.append({
                'target': target,
                'port': port,
                'service': 'Telnet',
                'severity': 'HIGH',
                'vulnerability': 'Telnet service exposed (cleartext protocol)',
                'recommendation': 'Disable Telnet and use SSH instead'
            })
    
    scanner.generate_report()
    
    save = input("\n\033[95m[?] Save report? (y/n): \033[0m").strip().lower()
    if save == 'y':
        filename = input("\033[95m[?] Filename (default vuln_report.json): \033[0m").strip() or 'vuln_report.json'
        scanner.save_report(filename)
    
    print(f"\n\033[92m[+] Done\033[0m")

if __name__ == "__main__":
    run()
