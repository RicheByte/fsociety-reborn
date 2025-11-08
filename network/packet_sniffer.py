#!/usr/bin/env python3
import socket
import struct
import sys
import platform
import time
import threading
from collections import defaultdict
from datetime import datetime
import json
import subprocess

class AdvancedPacketSniffer:
    def __init__(self):
        self.packets = []
        self.stats = defaultdict(int)
        self.connections = defaultdict(list)
        self.suspicious_patterns = []
        self.running = False
        self.packet_count = 0
        self.start_time = None
        
    def detect_scapy(self):
        try:
            from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw, DNS, conf, get_if_list
            self.scapy_modules = {
                'sniff': sniff, 'IP': IP, 'TCP': TCP, 'UDP': UDP,
                'ICMP': ICMP, 'ARP': ARP, 'Raw': Raw, 'DNS': DNS,
                'conf': conf, 'get_if_list': get_if_list
            }
            return True
        except ImportError:
            return False
    
    def get_interfaces(self):
        interfaces = []
        try:
            if self.detect_scapy():
                interfaces = self.scapy_modules['get_if_list']()
            else:
                if platform.system() == "Windows":
                    result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True)
                    for line in result.stdout.split('\n'):
                        if 'adapter' in line.lower():
                            interfaces.append(line.split(':')[0].strip())
                else:
                    result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
                    for line in result.stdout.split('\n'):
                        if ':' in line and not line.startswith(' '):
                            parts = line.split(':')
                            if len(parts) >= 2:
                                interfaces.append(parts[1].strip())
        except:
            pass
        return interfaces if interfaces else ['default']
    
    def analyze_packet(self, packet):
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'size': 0,
            'protocol': 'Unknown',
            'src': 'N/A',
            'dst': 'N/A',
            'src_port': 'N/A',
            'dst_port': 'N/A',
            'flags': None,
            'payload_preview': None
        }
        
        IP = self.scapy_modules['IP']
        TCP = self.scapy_modules['TCP']
        UDP = self.scapy_modules['UDP']
        ICMP = self.scapy_modules['ICMP']
        ARP = self.scapy_modules['ARP']
        DNS = self.scapy_modules['DNS']
        Raw = self.scapy_modules['Raw']
        
        if ARP in packet:
            analysis['protocol'] = 'ARP'
            analysis['src'] = packet[ARP].psrc
            analysis['dst'] = packet[ARP].pdst
            analysis['operation'] = 'Request' if packet[ARP].op == 1 else 'Reply'
            self.stats['ARP'] += 1
        
        elif IP in packet:
            analysis['src'] = packet[IP].src
            analysis['dst'] = packet[IP].dst
            analysis['size'] = len(packet)
            
            if TCP in packet:
                analysis['protocol'] = 'TCP'
                analysis['src_port'] = packet[TCP].sport
                analysis['dst_port'] = packet[TCP].dport
                analysis['flags'] = str(packet[TCP].flags)
                analysis['seq'] = packet[TCP].seq
                analysis['ack'] = packet[TCP].ack
                self.stats['TCP'] += 1
                
                if packet[TCP].dport in [80, 8080]:
                    self.stats['HTTP'] += 1
                elif packet[TCP].dport in [443, 8443]:
                    self.stats['HTTPS'] += 1
                elif packet[TCP].dport == 21:
                    self.stats['FTP'] += 1
                elif packet[TCP].dport == 22:
                    self.stats['SSH'] += 1
                elif packet[TCP].dport == 23:
                    self.stats['Telnet'] += 1
                elif packet[TCP].dport == 25:
                    self.stats['SMTP'] += 1
                
                conn_key = f"{analysis['src']}:{analysis['src_port']}->{analysis['dst']}:{analysis['dst_port']}"
                self.connections[conn_key].append(analysis['flags'])
            
            elif UDP in packet:
                analysis['protocol'] = 'UDP'
                analysis['src_port'] = packet[UDP].sport
                analysis['dst_port'] = packet[UDP].dport
                analysis['length'] = packet[UDP].len
                self.stats['UDP'] += 1
                
                if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                    self.stats['DNS'] += 1
                    if DNS in packet:
                        analysis['dns_query'] = packet[DNS].qd.qname.decode() if packet[DNS].qd else 'N/A'
                elif packet[UDP].dport == 67 or packet[UDP].dport == 68:
                    self.stats['DHCP'] += 1
            
            elif ICMP in packet:
                analysis['protocol'] = 'ICMP'
                analysis['type'] = packet[ICMP].type
                analysis['code'] = packet[ICMP].code
                self.stats['ICMP'] += 1
        
        if Raw in packet:
            payload = bytes(packet[Raw].load)
            analysis['payload_size'] = len(payload)
            try:
                decoded = payload.decode('utf-8', errors='ignore')
                analysis['payload_preview'] = decoded[:200]
                
                if 'password' in decoded.lower() or 'user' in decoded.lower():
                    self.suspicious_patterns.append({
                        'timestamp': analysis['timestamp'],
                        'pattern': 'Possible credentials in clear text',
                        'src': analysis['src'],
                        'dst': analysis['dst']
                    })
            except:
                analysis['payload_preview'] = str(payload[:100])
        
        return analysis
    
    def display_packet(self, packet_data):
        protocol_colors = {
            'TCP': '\033[94m',
            'UDP': '\033[95m',
            'ICMP': '\033[97m',
            'ARP': '\033[93m',
            'DNS': '\033[96m'
        }
        
        color = protocol_colors.get(packet_data['protocol'], '\033[97m')
        
        print(f"\n{color}[{packet_data['protocol']}] #{self.packet_count}\033[0m")
        print(f"\033[97m  {packet_data['src']}:{packet_data['src_port']} -> {packet_data['dst']}:{packet_data['dst_port']}\033[0m")
        
        if packet_data.get('flags'):
            print(f"\033[97m  Flags: {packet_data['flags']}\033[0m")
        
        if packet_data.get('dns_query'):
            print(f"\033[96m  DNS Query: {packet_data['dns_query']}\033[0m")
        
        if packet_data.get('payload_preview'):
            preview = packet_data['payload_preview'][:80]
            if 'password' in preview.lower():
                print(f"\033[91m  Payload: {preview}\033[0m")
            else:
                print(f"\033[90m  Payload: {preview}\033[0m")
    
    def packet_callback(self, packet):
        self.packet_count += 1
        analysis = self.analyze_packet(packet)
        self.packets.append(analysis)
        
        if self.verbose:
            self.display_packet(analysis)
        else:
            if self.packet_count % 10 == 0:
                elapsed = time.time() - self.start_time
                rate = self.packet_count / elapsed if elapsed > 0 else 0
                print(f"\r\033[92m[*] Packets: {self.packet_count} | Rate: {rate:.1f} pkt/s\033[0m", end='', flush=True)
    
    def display_statistics(self):
        print(f"\n\n\033[92m{'='*70}\033[0m")
        print(f"\033[92m[*] CAPTURE STATISTICS\033[0m")
        print(f"\033[92m{'='*70}\033[0m\n")
        
        elapsed = time.time() - self.start_time
        print(f"\033[97mTotal Packets: {self.packet_count}\033[0m")
        print(f"\033[97mCapture Time: {elapsed:.2f} seconds\033[0m")
        print(f"\033[97mAverage Rate: {self.packet_count/elapsed:.2f} packets/second\033[0m\n")
        
        print(f"\033[93m[*] Protocol Distribution:\033[0m")
        total_proto = sum(self.stats.values())
        for proto, count in sorted(self.stats.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_proto * 100) if total_proto > 0 else 0
            bar_length = int(percentage / 2)
            bar = '█' * bar_length
            print(f"\033[97m  {proto:10s}: {count:6d} ({percentage:5.1f}%) {bar}\033[0m")
        
        if self.connections:
            print(f"\n\033[93m[*] Top 10 TCP Connections:\033[0m")
            sorted_conns = sorted(self.connections.items(), key=lambda x: len(x[1]), reverse=True)[:10]
            for conn, flags in sorted_conns:
                print(f"\033[97m  {conn:50s} | Packets: {len(flags)}\033[0m")
        
        if self.suspicious_patterns:
            print(f"\n\033[91m[!] SUSPICIOUS PATTERNS DETECTED:\033[0m")
            for pattern in self.suspicious_patterns[:10]:
                print(f"\033[91m  [{pattern['timestamp']}] {pattern['pattern']}\033[0m")
                print(f"\033[91m    {pattern['src']} -> {pattern['dst']}\033[0m")
    
    def save_capture(self, filename='capture.json'):
        try:
            data = {
                'metadata': {
                    'total_packets': self.packet_count,
                    'start_time': self.start_time,
                    'capture_duration': time.time() - self.start_time,
                    'statistics': dict(self.stats)
                },
                'packets': self.packets[:1000],
                'suspicious_patterns': self.suspicious_patterns
            }
            
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
            
            print(f"\n\033[92m[+] Capture saved: {filename}\033[0m")
        except Exception as e:
            print(f"\033[91m[!] Error saving: {e}\033[0m")
    
    def start_capture(self, filter_str='', interface=None, packet_count=0, verbose=False):
        self.start_time = time.time()
        self.verbose = verbose
        self.running = True
        
        print(f"\n\033[92m[*] Starting advanced packet capture...\033[0m")
        if filter_str:
            print(f"\033[97m[*] Filter: {filter_str}\033[0m")
        if interface:
            print(f"\033[97m[*] Interface: {interface}\033[0m")
        print(f"\033[93m[*] Press Ctrl+C to stop\033[0m\n")
        
        try:
            sniff = self.scapy_modules['sniff']
            
            kwargs = {
                'prn': self.packet_callback,
                'store': False
            }
            
            if filter_str:
                kwargs['filter'] = filter_str
            if interface and interface != 'default':
                kwargs['iface'] = interface
            if packet_count > 0:
                kwargs['count'] = packet_count
            
            sniff(**kwargs)
            
        except KeyboardInterrupt:
            self.running = False
            print(f"\n\n\033[93m[*] Capture stopped\033[0m")
        except PermissionError:
            print(f"\033[91m[!] Permission denied. Run as root/administrator\033[0m")
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")

def run():
    print("\033[92m" + "="*70)
    print("     ADVANCED PACKET SNIFFER - PROFESSIONAL EDITION")
    print("="*70 + "\033[0m\n")
    
    print("\033[93m[!] WARNING: Requires root/administrator privileges\033[0m\n")
    
    sniffer = AdvancedPacketSniffer()
    
    if not sniffer.detect_scapy():
        print("\033[91m[!] Scapy not installed\033[0m")
        print("\033[97m[*] Install: pip install scapy\033[0m")
        return
    
    print("\033[97mCapture mode:\033[0m")
    print("  [1] All traffic")
    print("  [2] TCP only")
    print("  [3] UDP only")
    print("  [4] ICMP only")
    print("  [5] ARP only")
    print("  [6] HTTP/HTTPS (ports 80/443)")
    print("  [7] DNS queries")
    print("  [8] SSH/Telnet")
    print("  [9] Custom BPF filter")
    
    choice = input("\n\033[95m[?] Select: \033[0m").strip()
    
    filter_map = {
        '2': 'tcp',
        '3': 'udp',
        '4': 'icmp',
        '5': 'arp',
        '6': 'tcp port 80 or tcp port 443',
        '7': 'udp port 53',
        '8': 'tcp port 22 or tcp port 23'
    }
    
    filter_str = ''
    if choice == '9':
        filter_str = input("\033[95m[?] Enter BPF filter: \033[0m").strip()
    else:
        filter_str = filter_map.get(choice, '')
    
    interfaces = sniffer.get_interfaces()
    if len(interfaces) > 1:
        print(f"\n\033[97mInterfaces:\033[0m")
        for i, iface in enumerate(interfaces[:10], 1):
            print(f"  [{i}] {iface}")
        
        iface_choice = input("\n\033[95m[?] Select interface (Enter for default): \033[0m").strip()
        try:
            interface = interfaces[int(iface_choice) - 1] if iface_choice else None
        except:
            interface = None
    else:
        interface = None
    
    count = input("\n\033[95m[?] Packet limit (0 for unlimited): \033[0m").strip()
    count = int(count) if count.isdigit() else 0
    
    verbose = input("\033[95m[?] Verbose mode? (y/n): \033[0m").strip().lower() == 'y'
    
    try:
        sniffer.start_capture(filter_str, interface, count, verbose)
        sniffer.display_statistics()
        
        save = input("\n\033[95m[?] Save capture? (y/n): \033[0m").strip().lower()
        if save == 'y':
            filename = input("\033[95m[?] Filename (default capture.json): \033[0m").strip() or 'capture.json'
            sniffer.save_capture(filename)
    
    except KeyboardInterrupt:
        sniffer.running = False
        sniffer.display_statistics()
    
    print(f"\n\033[92m[+] Done\033[0m")

if __name__ == "__main__":
    run()
