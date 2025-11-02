"""
Shodan IoT Device Finder
Discovers exposed IoT devices using network scanning (no API)
"""
import socket
import concurrent.futures
from typing import List, Tuple
import struct

class ShodanIoTFinder:
    def __init__(self):
        self.discovered_devices = []
        
        # Common IoT device ports
        self.iot_ports = {
            80: 'HTTP (Web Interface)',
            443: 'HTTPS (Secure Web)',
            8080: 'HTTP Alt (Web)',
            8443: 'HTTPS Alt',
            23: 'Telnet',
            22: 'SSH',
            21: 'FTP',
            554: 'RTSP (Camera Stream)',
            8554: 'RTSP Alt',
            5000: 'UPnP',
            1900: 'SSDP (UPnP)',
            37777: 'DVR/Camera',
            9000: 'Camera/DVR',
            8000: 'IP Camera',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            6379: 'Redis',
            9200: 'Elasticsearch',
            8089: 'Splunk',
            502: 'Modbus (Industrial)',
            102: 'Siemens S7',
            1883: 'MQTT (IoT)',
            5683: 'CoAP (IoT)',
        }
    
    def scan_port(self, ip: str, port: int, timeout: float = 1.0) -> Tuple[bool, str]:
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                service = self.iot_ports.get(port, 'Unknown')
                return True, service
            return False, ""
        except:
            return False, ""
    
    def scan_device(self, ip: str):
        """Scan all IoT ports on a single IP"""
        open_ports = []
        
        print(f"\033[93m[*] Scanning {ip}...\033[0m", end='\r')
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self.scan_port, ip, port): port 
                      for port in self.iot_ports.keys()}
            
            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                try:
                    is_open, service = future.result()
                    if is_open:
                        open_ports.append((port, service))
                except:
                    pass
        
        if open_ports:
            device_info = {
                'ip': ip,
                'open_ports': open_ports
            }
            self.discovered_devices.append(device_info)
            
            print(f"\033[92m[+] Device found: {ip}\033[0m")
            for port, service in open_ports:
                print(f"\033[97m    Port {port}: {service}\033[0m")
            print()
    
    def scan_network(self, network_prefix: str, start: int = 1, end: int = 254):
        """Scan a network range"""
        print(f"\n\033[93m[*] Scanning network: {network_prefix}.{start}-{end}\033[0m")
        print(f"\033[93m[*] This may take several minutes...\033[0m\n")
        
        for i in range(start, end + 1):
            ip = f"{network_prefix}.{i}"
            self.scan_device(ip)
    
    def grab_banner(self, ip: str, port: int) -> str:
        """Attempt to grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            
            # Send HTTP request for web services
            if port in [80, 8080, 8000]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            return banner
        except:
            return ""
    
    def identify_device_type(self, ip: str, open_ports: List[Tuple[int, str]]) -> str:
        """Try to identify device type based on open ports"""
        port_numbers = [p[0] for p in open_ports]
        
        # Camera detection
        if any(p in port_numbers for p in [554, 8554, 37777, 8000]):
            return "IP Camera/DVR"
        
        # Router/Network device
        elif 80 in port_numbers and 23 in port_numbers:
            return "Router/Network Device"
        
        # IoT device
        elif any(p in port_numbers for p in [1883, 5683]):
            return "IoT Device (MQTT/CoAP)"
        
        # Industrial device
        elif any(p in port_numbers for p in [502, 102]):
            return "Industrial Control System"
        
        # Database
        elif any(p in port_numbers for p in [3306, 5432, 6379, 9200]):
            return "Database Server"
        
        # Generic web device
        elif 80 in port_numbers or 443 in port_numbers:
            return "Web Server/Device"
        
        return "Unknown Device"
    
    def detect_vulnerabilities(self, device_info: dict):
        """Basic vulnerability checks"""
        vulnerabilities = []
        
        open_ports = [p[0] for p in device_info['open_ports']]
        
        # Telnet exposed
        if 23 in open_ports:
            vulnerabilities.append("Telnet exposed (insecure)")
        
        # FTP exposed
        if 21 in open_ports:
            vulnerabilities.append("FTP exposed (potentially insecure)")
        
        # Database exposed
        if any(p in open_ports for p in [3306, 5432, 6379, 9200]):
            vulnerabilities.append("Database port exposed to internet")
        
        # Common vulnerable ports
        if 37777 in open_ports:
            vulnerabilities.append("DVR port 37777 (known vulnerabilities)")
        
        # No encryption
        if 80 in open_ports and 443 not in open_ports:
            vulnerabilities.append("HTTP without HTTPS")
        
        return vulnerabilities
    
    def generate_report(self):
        """Generate scan report"""
        print("\n" + "\033[92m" + "="*70)
        print("           SCAN REPORT")
        print("="*70 + "\033[0m\n")
        
        print(f"\033[93m[*] Total devices found: {len(self.discovered_devices)}\033[0m\n")
        
        for device in self.discovered_devices:
            ip = device['ip']
            device_type = self.identify_device_type(ip, device['open_ports'])
            
            print(f"\033[92m[+] Device: {ip}\033[0m")
            print(f"\033[97m    Type: {device_type}\033[0m")
            print(f"\033[97m    Open Ports:\033[0m")
            
            for port, service in device['open_ports']:
                print(f"\033[97m      {port}: {service}\033[0m")
            
            # Check vulnerabilities
            vulns = self.detect_vulnerabilities(device)
            if vulns:
                print(f"\033[91m    Potential Vulnerabilities:\033[0m")
                for vuln in vulns:
                    print(f"\033[91m      - {vuln}\033[0m")
            
            print()
    
    def save_results(self, filename: str):
        """Save results to file"""
        try:
            with open(filename, 'w') as f:
                f.write("IoT Device Scan Results\n")
                f.write("="*70 + "\n\n")
                
                for device in self.discovered_devices:
                    ip = device['ip']
                    device_type = self.identify_device_type(ip, device['open_ports'])
                    
                    f.write(f"Device: {ip}\n")
                    f.write(f"Type: {device_type}\n")
                    f.write(f"Open Ports:\n")
                    
                    for port, service in device['open_ports']:
                        f.write(f"  {port}: {service}\n")
                    
                    vulns = self.detect_vulnerabilities(device)
                    if vulns:
                        f.write("Vulnerabilities:\n")
                        for vuln in vulns:
                            f.write(f"  - {vuln}\n")
                    
                    f.write("\n" + "-"*70 + "\n\n")
            
            print(f"\033[92m[+] Results saved to: {filename}\033[0m")
        except Exception as e:
            print(f"\033[91m[!] Error saving: {str(e)}\033[0m")

def run():
    """Main function"""
    print("\033[92m" + "="*70)
    print("           SHODAN IoT DEVICE FINDER")
    print("="*70 + "\033[0m\n")
    
    print("\033[91m[!] WARNING: Only scan networks you own or have permission to scan!\033[0m\n")
    
    print("\033[97mSelect scan mode:\033[0m")
    print("  [1] Scan single IP")
    print("  [2] Scan network range")
    print("  [3] Scan custom IP list")
    
    mode = input("\n\033[95m[?] Select mode (1-3): \033[0m").strip()
    
    scanner = ShodanIoTFinder()
    
    if mode == '1':
        ip = input("\033[95m[?] Enter IP address: \033[0m").strip()
        scanner.scan_device(ip)
    
    elif mode == '2':
        network = input("\033[95m[?] Enter network prefix (e.g., 192.168.1): \033[0m").strip()
        start = int(input("\033[95m[?] Start IP (default 1): \033[0m").strip() or "1")
        end = int(input("\033[95m[?] End IP (default 254): \033[0m").strip() or "254")
        
        scanner.scan_network(network, start, end)
    
    elif mode == '3':
        print("\033[97m[*] Enter IP addresses (one per line, empty line to finish):\033[0m")
        ips = []
        while True:
            ip = input("\033[95m    > \033[0m").strip()
            if not ip:
                break
            ips.append(ip)
        
        for ip in ips:
            scanner.scan_device(ip)
    
    # Generate report
    scanner.generate_report()
    
    # Save results
    if scanner.discovered_devices:
        save = input("\n\033[95m[?] Save results to file? (y/n): \033[0m").strip().lower()
        if save == 'y':
            filename = input("\033[95m[?] Filename (default: iot_scan.txt): \033[0m").strip()
            filename = filename if filename else "iot_scan.txt"
            scanner.save_results(filename)
    
    print("\n" + "\033[92m" + "="*70)
    print("           SCAN COMPLETE")
    print("="*70 + "\033[0m")

if __name__ == "__main__":
    run()
