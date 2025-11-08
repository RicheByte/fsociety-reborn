#!/usr/bin/env python3
import subprocess
import os
import time
import re
import signal
import sys
import hashlib
from datetime import datetime
from collections import defaultdict

class RogueAPDetector:
    def __init__(self):
        self.interface = None
        self.monitor_interface = None
        self.known_aps = {}
        self.suspicious_aps = []
        self.baseline_scan = {}
        self.processes = []
        
    def check_requirements(self):
        required = ['airmon-ng', 'airodump-ng', 'iwlist']
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
    
    def scan_networks(self, duration=30):
        print(f"\033[93m[*] Scanning ({duration}s)...\033[0m\n")
        
        scan_file = f"/tmp/rogue_scan_{int(time.time())}"
        cmd = ['airodump-ng', self.monitor_interface, '-w', scan_file, '--output-format', 'csv']
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.processes.append(proc)
        
        time.sleep(duration)
        proc.terminate()
        proc.wait(timeout=5)
        
        networks = {}
        
        try:
            csv_file = f"{scan_file}-01.csv"
            if os.path.exists(csv_file):
                with open(csv_file, 'r', encoding='latin-1') as f:
                    content = f.read()
                
                lines = content.split('\n')
                in_ap_section = False
                
                for line in lines:
                    if 'BSSID' in line and 'PWR' in line:
                        in_ap_section = True
                        continue
                    elif 'Station MAC' in line:
                        break
                    
                    if in_ap_section and line.strip():
                        parts = [p.strip() for p in line.split(',')]
                        if len(parts) >= 14 and ':' in parts[0]:
                            bssid = parts[0]
                            first_seen = parts[1]
                            last_seen = parts[2]
                            channel = parts[3]
                            speed = parts[4]
                            privacy = parts[5]
                            cipher = parts[6]
                            auth = parts[7]
                            power = parts[8]
                            beacons = parts[9]
                            essid = parts[13]
                            
                            if bssid and channel.isdigit():
                                networks[bssid] = {
                                    'bssid': bssid,
                                    'essid': essid,
                                    'channel': channel,
                                    'privacy': privacy,
                                    'cipher': cipher,
                                    'auth': auth,
                                    'power': power,
                                    'beacons': beacons,
                                    'first_seen': first_seen,
                                    'last_seen': last_seen
                                }
                
                for f in [f"{scan_file}-01.csv", f"{scan_file}-01.cap"]:
                    if os.path.exists(f):
                        os.remove(f)
        except:
            pass
        
        return networks
    
    def create_baseline(self, duration=60):
        print(f"\033[93m[*] Creating baseline scan ({duration}s)...\033[0m")
        print(f"\033[97m[*] This establishes legitimate APs\033[0m\n")
        
        self.baseline_scan = self.scan_networks(duration)
        
        print(f"\033[92m[+] Baseline: {len(self.baseline_scan)} APs\033[0m")
        
        for bssid, data in self.baseline_scan.items():
            print(f"\033[97m  {data['essid'][:20]:20s} | {bssid} | Ch: {data['channel']}\033[0m")
    
    def detect_rogues(self, duration=30):
        print(f"\n\033[93m[*] Detecting rogue APs ({duration}s)...\033[0m\n")
        
        current_scan = self.scan_networks(duration)
        
        for bssid, data in current_scan.items():
            risk_score = 0
            indicators = []
            
            if bssid not in self.baseline_scan:
                risk_score += 30
                indicators.append("New AP detected")
            
            essid = data['essid']
            for known_bssid, known_data in self.baseline_scan.items():
                if known_data['essid'] == essid and known_bssid != bssid:
                    risk_score += 50
                    indicators.append(f"Duplicate ESSID: {essid}")
                    break
            
            if data['privacy'] == 'OPN' or data['privacy'] == '':
                risk_score += 20
                indicators.append("Open network")
            
            try:
                power_level = int(data['power'])
                if power_level > -30:
                    risk_score += 15
                    indicators.append("Unusually strong signal")
            except:
                pass
            
            if risk_score >= 40:
                self.suspicious_aps.append({
                    'bssid': bssid,
                    'data': data,
                    'risk_score': risk_score,
                    'indicators': indicators
                })
    
    def continuous_monitoring(self, duration=300, interval=30):
        print(f"\n\033[93m[*] Continuous monitoring ({duration}s)\033[0m")
        print(f"\033[97m[*] Scan interval: {interval}s\033[0m")
        print(f"\033[97m[*] Press Ctrl+C to stop\033[0m\n")
        
        start_time = time.time()
        scan_count = 0
        
        while time.time() - start_time < duration:
            scan_count += 1
            print(f"\n\033[96m[*] Scan #{scan_count} - {datetime.now().strftime('%H:%M:%S')}\033[0m")
            
            self.suspicious_aps = []
            self.detect_rogues(interval)
            
            if self.suspicious_aps:
                print(f"\n\033[91m[!] ALERT: {len(self.suspicious_aps)} suspicious AP(s) detected!\033[0m\n")
                for ap in self.suspicious_aps:
                    self.display_suspicious_ap(ap)
            else:
                print(f"\n\033[92m[+] No suspicious APs detected\033[0m")
            
            if time.time() - start_time < duration:
                remaining = int((duration - (time.time() - start_time)) / 60)
                print(f"\n\033[97m[*] Next scan in {interval}s ({remaining} min remaining)...\033[0m")
                time.sleep(interval)
    
    def display_suspicious_ap(self, ap):
        data = ap['data']
        risk_score = ap['risk_score']
        indicators = ap['indicators']
        
        if risk_score >= 70:
            color = '\033[91m'
            level = 'CRITICAL'
        elif risk_score >= 50:
            color = '\033[93m'
            level = 'HIGH'
        else:
            color = '\033[96m'
            level = 'MEDIUM'
        
        print(f"{color}[{level}] Risk Score: {risk_score}%\033[0m")
        print(f"\033[97m  ESSID: {data['essid']}\033[0m")
        print(f"\033[97m  BSSID: {data['bssid']}\033[0m")
        print(f"\033[97m  Channel: {data['channel']}\033[0m")
        print(f"\033[97m  Security: {data['privacy']}\033[0m")
        print(f"\033[97m  Power: {data['power']} dBm\033[0m")
        print(f"\033[97m  Indicators:\033[0m")
        for indicator in indicators:
            print(f"\033[97m    - {indicator}\033[0m")
        print()
    
    def analyze_encryption(self, networks):
        print(f"\n\033[93m[*] Encryption analysis\033[0m\n")
        
        encryption_count = defaultdict(int)
        
        for bssid, data in networks.items():
            encryption_count[data['privacy']] += 1
        
        for enc_type, count in sorted(encryption_count.items(), key=lambda x: x[1], reverse=True):
            print(f"\033[97m  {enc_type:15s}: {count:3d} network(s)\033[0m")
        
        open_nets = [data for bssid, data in networks.items() if data['privacy'] in ['OPN', '']]
        
        if open_nets:
            print(f"\n\033[91m[!] WARNING: {len(open_nets)} open network(s) detected!\033[0m")
            for net in open_nets[:10]:
                print(f"\033[97m    {net['essid'][:20]:20s} | {net['bssid']} | Ch: {net['channel']}\033[0m")
    
    def channel_overlap_analysis(self, networks):
        print(f"\n\033[93m[*] Channel overlap analysis\033[0m\n")
        
        channels = defaultdict(list)
        
        for bssid, data in networks.items():
            channels[data['channel']].append(data['essid'])
        
        for channel in sorted(channels.keys(), key=lambda x: int(x) if x.isdigit() else 0):
            count = len(channels[channel])
            if count > 3:
                print(f"\033[91m  Channel {channel:2s}: {count:2d} APs (High congestion)\033[0m")
            elif count > 1:
                print(f"\033[93m  Channel {channel:2s}: {count:2d} APs\033[0m")
            else:
                print(f"\033[92m  Channel {channel:2s}: {count:2d} AP\033[0m")
    
    def save_report(self, filename='rogue_ap_report.txt'):
        try:
            with open(filename, 'w') as f:
                f.write("="*70 + "\n")
                f.write("ROGUE AP DETECTION REPORT\n")
                f.write("="*70 + "\n\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                f.write(f"Baseline APs: {len(self.baseline_scan)}\n")
                f.write(f"Suspicious APs: {len(self.suspicious_aps)}\n\n")
                
                if self.suspicious_aps:
                    f.write("SUSPICIOUS ACCESS POINTS:\n")
                    f.write("-"*70 + "\n\n")
                    
                    for ap in sorted(self.suspicious_aps, key=lambda x: x['risk_score'], reverse=True):
                        data = ap['data']
                        f.write(f"Risk Score: {ap['risk_score']}%\n")
                        f.write(f"ESSID: {data['essid']}\n")
                        f.write(f"BSSID: {data['bssid']}\n")
                        f.write(f"Channel: {data['channel']}\n")
                        f.write(f"Security: {data['privacy']}\n")
                        f.write(f"Power: {data['power']} dBm\n")
                        f.write("Indicators:\n")
                        for indicator in ap['indicators']:
                            f.write(f"  - {indicator}\n")
                        f.write("\n" + "-"*70 + "\n\n")
            
            print(f"\n\033[92m[+] Report saved: {filename}\033[0m")
        except Exception as e:
            print(f"\033[91m[!] Error saving: {e}\033[0m")
    
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
    print("     ROGUE ACCESS POINT DETECTOR")
    print("="*70 + "\033[0m\n")
    
    detector = RogueAPDetector()
    
    def signal_handler(sig, frame):
        print("\n\n\033[93m[!] Stopping...\033[0m")
        detector.cleanup()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    missing = detector.check_requirements()
    if missing:
        print(f"\033[91m[!] Missing: {', '.join(missing)}\033[0m")
        return
    
    interfaces = detector.get_interfaces()
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
    if not detector.enable_monitor_mode(selected):
        print("\033[91m[!] Failed\033[0m")
        return
    
    print(f"\033[92m[+] Monitor: {detector.monitor_interface}\033[0m\n")
    
    print("\033[97mDetection mode:\033[0m")
    print("  [1] Baseline + Single scan")
    print("  [2] Continuous monitoring")
    print("  [3] Quick scan (no baseline)")
    print("  [4] Network analysis")
    
    mode = input("\n\033[95m[?] Select: \033[0m").strip()
    
    if mode == '1':
        baseline_time = input("\033[95m[?] Baseline duration (default 60s): \033[0m").strip()
        baseline_time = int(baseline_time) if baseline_time.isdigit() else 60
        
        detector.create_baseline(baseline_time)
        detector.detect_rogues(30)
        
        if detector.suspicious_aps:
            print(f"\n\033[91m[!] Found {len(detector.suspicious_aps)} suspicious AP(s)!\033[0m\n")
            for ap in detector.suspicious_aps:
                detector.display_suspicious_ap(ap)
        else:
            print(f"\n\033[92m[+] No suspicious APs detected\033[0m")
    
    elif mode == '2':
        baseline_time = input("\033[95m[?] Baseline duration (default 60s): \033[0m").strip()
        baseline_time = int(baseline_time) if baseline_time.isdigit() else 60
        
        detector.create_baseline(baseline_time)
        
        monitor_time = input("\033[95m[?] Monitor duration (default 300s): \033[0m").strip()
        monitor_time = int(monitor_time) if monitor_time.isdigit() else 300
        
        interval = input("\033[95m[?] Scan interval (default 30s): \033[0m").strip()
        interval = int(interval) if interval.isdigit() else 30
        
        detector.continuous_monitoring(monitor_time, interval)
    
    elif mode == '3':
        networks = detector.scan_networks(30)
        
        print(f"\n\033[92m[+] Found {len(networks)} network(s)\033[0m\n")
        
        for bssid, data in networks.items():
            print(f"\033[97m{data['essid'][:20]:20s} | {bssid} | Ch: {data['channel']:2s} | "
                  f"{data['privacy']:10s} | {data['power']:4s} dBm\033[0m")
    
    elif mode == '4':
        networks = detector.scan_networks(60)
        detector.analyze_encryption(networks)
        detector.channel_overlap_analysis(networks)
    
    if detector.suspicious_aps:
        save = input("\n\033[95m[?] Save report? (y/n): \033[0m").strip().lower()
        if save == 'y':
            detector.save_report()
    
    detector.cleanup()
    print(f"\n\033[92m[+] Done\033[0m")

if __name__ == "__main__":
    run()
