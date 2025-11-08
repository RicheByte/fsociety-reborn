#!/usr/bin/env python3
import subprocess
import time
import re
import os
import json
from datetime import datetime
import sys

class BluetoothScanner:
    def __init__(self):
        self.devices = []
        self.detailed_info = {}
        
    def check_requirements(self):
        required = ['hcitool', 'bluetoothctl', 'sdptool', 'l2ping']
        missing = []
        for tool in required:
            try:
                subprocess.run([tool, '--help'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            except:
                if tool not in ['sdptool', 'l2ping']:
                    missing.append(tool)
        return missing
    
    def get_adapters(self):
        try:
            result = subprocess.run(['hciconfig'], capture_output=True, text=True, timeout=5)
            adapters = []
            for line in result.stdout.split('\n'):
                if 'hci' in line:
                    match = re.search(r'(hci\d+)', line)
                    if match:
                        adapters.append(match.group(1))
            return adapters
        except:
            return []
    
    def enable_adapter(self, adapter='hci0'):
        try:
            subprocess.run(['hciconfig', adapter, 'up'], timeout=5, check=True)
            subprocess.run(['hciconfig', adapter, 'piscan'], timeout=5, check=True)
            return True
        except:
            return False
    
    def quick_scan(self, duration=10):
        print(f"\033[93m[*] Quick scan ({duration}s)...\033[0m\n")
        
        try:
            proc = subprocess.Popen(['hcitool', 'scan', '--flush'], 
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            time.sleep(duration)
            proc.terminate()
            
            output = proc.stdout.read()
            
            for line in output.split('\n'):
                if ':' in line and len(line.split()) >= 2:
                    parts = line.split(maxsplit=1)
                    if len(parts[0]) == 17:
                        addr = parts[0]
                        name = parts[1] if len(parts) > 1 else 'Unknown'
                        
                        if addr not in [d['address'] for d in self.devices]:
                            self.devices.append({
                                'address': addr,
                                'name': name,
                                'type': 'Unknown',
                                'class': 'Unknown',
                                'rssi': 'N/A'
                            })
                            print(f"\033[92m[+] {addr} - {name}\033[0m")
        except:
            pass
    
    def ble_scan(self, duration=10):
        print(f"\n\033[93m[*] BLE scan ({duration}s)...\033[0m\n")
        
        try:
            proc = subprocess.Popen(['hcitool', 'lescan', '--duplicates'], 
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            seen = set()
            start = time.time()
            
            while time.time() - start < duration:
                line = proc.stdout.readline()
                if ':' in line:
                    parts = line.strip().split(maxsplit=1)
                    if len(parts) >= 1 and len(parts[0]) == 17:
                        addr = parts[0]
                        name = parts[1] if len(parts) > 1 else 'Unknown'
                        
                        if addr not in seen:
                            seen.add(addr)
                            self.devices.append({
                                'address': addr,
                                'name': name,
                                'type': 'BLE',
                                'class': 'Unknown',
                                'rssi': 'N/A'
                            })
                            print(f"\033[96m[+] BLE: {addr} - {name}\033[0m")
            
            proc.terminate()
            proc.wait(timeout=2)
        except:
            pass
    
    def get_device_info(self, address):
        info = {'address': address, 'services': [], 'manufacturer': 'Unknown', 'class': 'Unknown'}
        
        try:
            result = subprocess.run(['hcitool', 'info', address], 
                                  capture_output=True, text=True, timeout=10)
            
            for line in result.stdout.split('\n'):
                if 'Device Name:' in line:
                    info['name'] = line.split(':', 1)[1].strip()
                elif 'Class:' in line:
                    info['class'] = line.split(':', 1)[1].strip()
                elif 'Manufacturer:' in line:
                    info['manufacturer'] = line.split(':', 1)[1].strip()
        except:
            pass
        
        try:
            result = subprocess.run(['sdptool', 'browse', address], 
                                  capture_output=True, text=True, timeout=15)
            
            services = []
            current_service = None
            
            for line in result.stdout.split('\n'):
                if 'Service Name:' in line:
                    current_service = line.split(':', 1)[1].strip()
                elif 'Service RecHandle:' in line and current_service:
                    services.append(current_service)
                    current_service = None
            
            info['services'] = services
        except:
            pass
        
        try:
            result = subprocess.run(['l2ping', '-c', '1', address], 
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'bytes from' in line:
                        match = re.search(r'time=(\S+)', line)
                        if match:
                            info['latency'] = match.group(1)
        except:
            pass
        
        return info
    
    def enumerate_services(self, address):
        print(f"\n\033[93m[*] Enumerating services for {address}...\033[0m\n")
        
        try:
            result = subprocess.run(['sdptool', 'records', address], 
                                  capture_output=True, text=True, timeout=20)
            
            print(result.stdout)
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
    
    def device_class_lookup(self, class_code):
        major_classes = {
            '0x100': 'Computer',
            '0x200': 'Phone',
            '0x300': 'LAN/Network',
            '0x400': 'Audio/Video',
            '0x500': 'Peripheral',
            '0x600': 'Imaging',
            '0x700': 'Wearable',
            '0x800': 'Toy',
            '0x900': 'Health'
        }
        
        if class_code:
            major = class_code[:5] + '00'
            return major_classes.get(major, 'Unknown')
        return 'Unknown'
    
    def aggressive_scan(self, duration=30):
        print(f"\n\033[93m[*] Aggressive scan ({duration}s)...\033[0m")
        print(f"\033[97m[*] Scanning Classic + BLE...\033[0m\n")
        
        import threading
        
        t1 = threading.Thread(target=self.quick_scan, args=(duration,))
        t2 = threading.Thread(target=self.ble_scan, args=(duration,))
        
        t1.start()
        time.sleep(2)
        t2.start()
        
        t1.join()
        t2.join()
    
    def save_results(self, filename='bluetooth_scan.json'):
        data = {
            'scan_time': datetime.now().isoformat(),
            'devices': self.devices,
            'detailed_info': self.detailed_info
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"\n\033[92m[+] Saved to {filename}\033[0m")
        except Exception as e:
            print(f"\033[91m[!] Error saving: {e}\033[0m")

def run():
    print("\033[92m" + "="*70)
    print("     BLUETOOTH DEVICE SCANNER")
    print("="*70 + "\033[0m\n")
    
    scanner = BluetoothScanner()
    
    missing = scanner.check_requirements()
    if missing:
        print(f"\033[91m[!] Missing: {', '.join(missing)}\033[0m")
        print(f"\033[97m[*] Install: apt install bluez bluez-tools\033[0m")
        return
    
    adapters = scanner.get_adapters()
    if not adapters:
        print("\033[91m[!] No Bluetooth adapters found\033[0m")
        return
    
    print(f"\033[97mAdapter: {adapters[0]}\033[0m")
    
    if not scanner.enable_adapter(adapters[0]):
        print("\033[91m[!] Failed to enable adapter\033[0m")
        return
    
    print(f"\033[92m[+] Adapter enabled\033[0m\n")
    
    print("\033[97mScan mode:\033[0m")
    print("  [1] Quick scan (Classic Bluetooth)")
    print("  [2] BLE scan")
    print("  [3] Aggressive (Classic + BLE)")
    print("  [4] Continuous monitoring")
    
    mode = input("\n\033[95m[?] Select: \033[0m").strip()
    
    if mode == '1':
        duration = input("\033[95m[?] Duration (default 10s): \033[0m").strip()
        duration = int(duration) if duration.isdigit() else 10
        scanner.quick_scan(duration)
    
    elif mode == '2':
        duration = input("\033[95m[?] Duration (default 10s): \033[0m").strip()
        duration = int(duration) if duration.isdigit() else 10
        scanner.ble_scan(duration)
    
    elif mode == '3':
        duration = input("\033[95m[?] Duration (default 30s): \033[0m").strip()
        duration = int(duration) if duration.isdigit() else 30
        scanner.aggressive_scan(duration)
    
    elif mode == '4':
        duration = input("\033[95m[?] Duration (default 60s): \033[0m").strip()
        duration = int(duration) if duration.isdigit() else 60
        
        intervals = duration // 15
        for i in range(intervals):
            print(f"\n\033[96m[*] Scan {i+1}/{intervals}\033[0m")
            scanner.quick_scan(15)
    
    if scanner.devices:
        print(f"\n\033[92m{'='*70}\033[0m")
        print(f"\033[92m[+] Found {len(scanner.devices)} device(s)\033[0m")
        print(f"\033[92m{'='*70}\033[0m\n")
        
        for i, dev in enumerate(scanner.devices, 1):
            print(f"\033[97m[{i}] {dev['address']:17s} | {dev['name'][:30]:30s} | {dev['type']}\033[0m")
        
        detail = input("\n\033[95m[?] Get detailed info for device # (or 'n'): \033[0m").strip()
        
        if detail.isdigit():
            try:
                idx = int(detail) - 1
                if 0 <= idx < len(scanner.devices):
                    addr = scanner.devices[idx]['address']
                    print(f"\n\033[93m[*] Gathering detailed info...\033[0m")
                    info = scanner.get_device_info(addr)
                    scanner.detailed_info[addr] = info
                    
                    print(f"\n\033[92m{'='*70}\033[0m")
                    print(f"\033[97mAddress: {info['address']}\033[0m")
                    print(f"\033[97mName: {info.get('name', 'Unknown')}\033[0m")
                    print(f"\033[97mClass: {info['class']}\033[0m")
                    print(f"\033[97mManufacturer: {info['manufacturer']}\033[0m")
                    
                    if info.get('latency'):
                        print(f"\033[97mLatency: {info['latency']}\033[0m")
                    
                    if info['services']:
                        print(f"\033[97m\nServices:\033[0m")
                        for svc in info['services']:
                            print(f"\033[97m  - {svc}\033[0m")
                    
                    print(f"\033[92m{'='*70}\033[0m")
                    
                    enum = input("\n\033[95m[?] Enumerate all services? (y/n): \033[0m").strip().lower()
                    if enum == 'y':
                        scanner.enumerate_services(addr)
            except:
                pass
        
        save = input("\n\033[95m[?] Save results? (y/n): \033[0m").strip().lower()
        if save == 'y':
            scanner.save_results()

if __name__ == "__main__":
    run()
