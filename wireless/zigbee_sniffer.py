#!/usr/bin/env python3
import subprocess
import time
import struct
import binascii
from datetime import datetime
import sys

class ZigbeeSniffer:
    def __init__(self):
        self.interface = None
        self.channel = 11
        self.packets = []
        self.device_addresses = set()
        
    def check_requirements(self):
        required = ['killerbee', 'zbwireshark', 'zbdump', 'zbid']
        missing = []
        for tool in required:
            try:
                result = subprocess.run(['which', tool], capture_output=True, text=True, timeout=2)
                if not result.stdout.strip():
                    missing.append(tool)
            except:
                missing.append(tool)
        return missing
    
    def get_interfaces(self):
        print("\033[93m[*] Detecting KillerBee-compatible interfaces...\033[0m\n")
        
        try:
            result = subprocess.run(['zbid'], capture_output=True, text=True, timeout=10)
            
            interfaces = []
            lines = result.stdout.split('\n')
            
            for line in lines:
                if 'Dev' in line and ('/dev/' in line or 'USB' in line):
                    parts = line.split()
                    if parts:
                        dev_id = parts[0]
                        interfaces.append(dev_id)
            
            if not interfaces:
                print("\033[97m[*] No KillerBee interfaces detected\033[0m")
                print("\033[97m[*] Supported: ApiMote, RZUSBstick, Freakduino\033[0m")
                print("\033[97m[*] Attempting generic approach...\033[0m\n")
                
                for dev in ['/dev/ttyUSB0', '/dev/ttyUSB1', '/dev/ttyACM0']:
                    import os
                    if os.path.exists(dev):
                        interfaces.append(dev)
            
            return interfaces
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return []
    
    def start_capture(self, interface, channel, duration=60):
        print(f"\033[93m[*] Starting Zigbee capture\033[0m")
        print(f"\033[97m  Interface: {interface}\033[0m")
        print(f"\033[97m  Channel: {channel}\033[0m")
        print(f"\033[97m  Duration: {duration}s\033[0m\n")
        
        pcap_file = f"zigbee_capture_{int(time.time())}.pcap"
        
        try:
            cmd = ['zbdump', '-f', pcap_file, '-c', str(channel), '-i', interface]
            
            print(f"\033[92m[+] Capturing to {pcap_file}...\033[0m")
            print(f"\033[97m[*] Press Ctrl+C to stop\033[0m\n")
            
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            
            start_time = time.time()
            packet_count = 0
            
            try:
                while time.time() - start_time < duration:
                    line = proc.stdout.readline()
                    if line:
                        if 'packet' in line.lower():
                            packet_count += 1
                            print(f"\r\033[92m[*] Packets captured: {packet_count}\033[0m", end='', flush=True)
                    time.sleep(0.1)
            except KeyboardInterrupt:
                pass
            
            proc.terminate()
            proc.wait(timeout=5)
            
            print(f"\n\n\033[92m[+] Capture complete: {packet_count} packets\033[0m")
            print(f"\033[97m[*] Saved to: {pcap_file}\033[0m")
            
            return pcap_file, packet_count
            
        except FileNotFoundError:
            print(f"\033[91m[!] zbdump not found\033[0m")
            print(f"\033[97m[*] Trying alternative method...\033[0m\n")
            return self.alternative_capture(interface, channel, duration)
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return None, 0
    
    def alternative_capture(self, interface, channel, duration):
        print(f"\033[93m[*] Alternative Zigbee capture method\033[0m\n")
        
        pcap_file = f"zigbee_alt_{int(time.time())}.pcap"
        
        try:
            import serial
            ser = serial.Serial(interface, 115200, timeout=1)
            
            ser.write(b'AT+CHANNEL=' + str(channel).encode() + b'\r\n')
            time.sleep(0.5)
            ser.write(b'AT+PROMISCUOUS=1\r\n')
            time.sleep(0.5)
            
            print(f"\033[92m[+] Capturing...\033[0m\n")
            
            packet_count = 0
            start_time = time.time()
            
            with open(pcap_file, 'wb') as f:
                f.write(b'\xa1\xb2\xc3\xd4')
                f.write(struct.pack('H', 2))
                f.write(struct.pack('H', 4))
                f.write(struct.pack('I', 0))
                f.write(struct.pack('I', 0))
                f.write(struct.pack('I', 65535))
                f.write(struct.pack('I', 195))
                
                while time.time() - start_time < duration:
                    try:
                        data = ser.read(256)
                        if data:
                            packet_count += 1
                            
                            ts = int(time.time())
                            f.write(struct.pack('I', ts))
                            f.write(struct.pack('I', 0))
                            f.write(struct.pack('I', len(data)))
                            f.write(struct.pack('I', len(data)))
                            f.write(data)
                            
                            print(f"\r\033[92m[*] Packets: {packet_count}\033[0m", end='', flush=True)
                    except KeyboardInterrupt:
                        break
                    except:
                        pass
            
            ser.close()
            
            print(f"\n\n\033[92m[+] Capture complete: {packet_count} packets\033[0m")
            return pcap_file, packet_count
            
        except ImportError:
            print(f"\033[91m[!] pyserial not installed\033[0m")
            print(f"\033[97m[*] Install: pip install pyserial\033[0m")
            return None, 0
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return None, 0
    
    def analyze_pcap(self, pcap_file):
        print(f"\n\033[93m[*] Analyzing capture...\033[0m\n")
        
        try:
            result = subprocess.run(['tshark', '-r', pcap_file, '-Y', 'wpan', '-T', 'fields', 
                                   '-e', 'wpan.src64', '-e', 'wpan.dst64', '-e', 'frame.len'],
                                  capture_output=True, text=True, timeout=30)
            
            devices = set()
            total_packets = 0
            
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        src = parts[0].strip()
                        dst = parts[1].strip()
                        
                        if src and src != '0x0000000000000000':
                            devices.add(src)
                        if dst and dst != '0x0000000000000000':
                            devices.add(dst)
                        
                        total_packets += 1
            
            print(f"\033[92m[+] Total packets: {total_packets}\033[0m")
            print(f"\033[92m[+] Unique devices: {len(devices)}\033[0m\n")
            
            if devices:
                print(f"\033[97mDetected devices:\033[0m")
                for i, device in enumerate(sorted(devices), 1):
                    print(f"\033[97m  [{i}] {device}\033[0m")
            
        except FileNotFoundError:
            print(f"\033[91m[!] tshark not found\033[0m")
            print(f"\033[97m[*] Install: apt install tshark\033[0m")
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
    
    def channel_scan(self, interface, channels=range(11, 27)):
        print(f"\033[93m[*] Scanning Zigbee channels\033[0m\n")
        
        results = {}
        
        for channel in channels:
            print(f"\033[97m[*] Scanning channel {channel}...\033[0m", end=' ', flush=True)
            
            try:
                pcap_file, packet_count = self.start_capture(interface, channel, 5)
                results[channel] = packet_count
                print(f"\033[92m{packet_count} packets\033[0m")
            except:
                results[channel] = 0
                print(f"\033[91m0 packets\033[0m")
        
        print(f"\n\033[92m{'='*50}\033[0m")
        print(f"\033[92mChannel Activity Summary:\033[0m")
        print(f"\033[92m{'='*50}\033[0m\n")
        
        sorted_channels = sorted(results.items(), key=lambda x: x[1], reverse=True)
        
        for channel, count in sorted_channels:
            if count > 10:
                print(f"\033[92m  Channel {channel:2d}: {count:5d} packets (Active)\033[0m")
            elif count > 0:
                print(f"\033[93m  Channel {channel:2d}: {count:5d} packets\033[0m")
            else:
                print(f"\033[97m  Channel {channel:2d}: {count:5d} packets\033[0m")
        
        return sorted_channels
    
    def jamming_test(self, interface, channel):
        print(f"\n\033[93m[*] Jamming test on channel {channel}\033[0m")
        print(f"\033[97m[*] This will transmit noise to test interference\033[0m")
        print(f"\033[91m[!] WARNING: May disrupt Zigbee networks\033[0m\n")
        
        confirm = input("\033[95m[?] Continue? (yes/no): \033[0m").strip().lower()
        
        if confirm != 'yes':
            print("\033[97m[*] Cancelled\033[0m")
            return
        
        try:
            duration = input("\033[95m[?] Duration (default 10s): \033[0m").strip()
            duration = int(duration) if duration.isdigit() else 10
            
            cmd = ['zbjammer', '-c', str(channel), '-i', interface, '-t', str(duration)]
            
            print(f"\n\033[93m[*] Jamming channel {channel}...\033[0m\n")
            
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            
            for line in iter(proc.stdout.readline, ''):
                if line:
                    print(line.rstrip())
            
            proc.wait()
            
            print(f"\n\033[92m[+] Jamming test complete\033[0m")
            
        except FileNotFoundError:
            print(f"\033[91m[!] zbjammer not found in KillerBee suite\033[0m")
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")

def run():
    print("\033[92m" + "="*70)
    print("     ZIGBEE PACKET SNIFFER")
    print("="*70 + "\033[0m\n")
    
    sniffer = ZigbeeSniffer()
    
    missing = sniffer.check_requirements()
    if missing and len(missing) >= 4:
        print(f"\033[91m[!] KillerBee framework not installed\033[0m")
        print(f"\033[97m[*] Install: pip install killerbee\033[0m")
        print(f"\033[97m[*] Requires: ApiMote, RZUSBstick, or compatible hardware\033[0m")
        return
    
    interfaces = sniffer.get_interfaces()
    if not interfaces:
        print("\033[91m[!] No Zigbee interfaces found\033[0m")
        print(f"\033[97m[*] Supported hardware: ApiMote, RZUSBstick, Freakduino\033[0m")
        return
    
    print(f"\033[97mInterfaces:\033[0m")
    for i, iface in enumerate(interfaces, 1):
        print(f"  [{i}] {iface}")
    
    choice = input("\n\033[95m[?] Select: \033[0m").strip()
    try:
        idx = int(choice) - 1
        selected = interfaces[idx]
    except:
        print("\033[91m[!] Invalid\033[0m")
        return
    
    sniffer.interface = selected
    
    print("\n\033[97mOperation mode:\033[0m")
    print("  [1] Single channel capture")
    print("  [2] Channel scan")
    print("  [3] Continuous monitoring")
    print("  [4] Jamming test")
    
    mode = input("\n\033[95m[?] Select: \033[0m").strip()
    
    if mode == '1':
        channel = input("\033[95m[?] Channel (11-26, default 11): \033[0m").strip()
        channel = int(channel) if channel.isdigit() and 11 <= int(channel) <= 26 else 11
        
        duration = input("\033[95m[?] Duration (default 60s): \033[0m").strip()
        duration = int(duration) if duration.isdigit() else 60
        
        pcap_file, packet_count = sniffer.start_capture(selected, channel, duration)
        
        if pcap_file and packet_count > 0:
            analyze = input("\n\033[95m[?] Analyze capture? (y/n): \033[0m").strip().lower()
            if analyze == 'y':
                sniffer.analyze_pcap(pcap_file)
    
    elif mode == '2':
        channels = input("\033[95m[?] Channel range (default 11-26): \033[0m").strip()
        if '-' in channels:
            try:
                start, end = map(int, channels.split('-'))
                channel_range = range(start, end + 1)
            except:
                channel_range = range(11, 27)
        else:
            channel_range = range(11, 27)
        
        sniffer.channel_scan(selected, channel_range)
    
    elif mode == '3':
        channel = input("\033[95m[?] Channel (11-26, default 11): \033[0m").strip()
        channel = int(channel) if channel.isdigit() and 11 <= int(channel) <= 26 else 11
        
        duration = input("\033[95m[?] Duration (default 300s): \033[0m").strip()
        duration = int(duration) if duration.isdigit() else 300
        
        pcap_file, packet_count = sniffer.start_capture(selected, channel, duration)
        
        if pcap_file:
            sniffer.analyze_pcap(pcap_file)
    
    elif mode == '4':
        channel = input("\033[95m[?] Channel (11-26): \033[0m").strip()
        channel = int(channel) if channel.isdigit() and 11 <= int(channel) <= 26 else 11
        
        sniffer.jamming_test(selected, channel)
    
    print(f"\n\033[92m[+] Done\033[0m")

if __name__ == "__main__":
    run()
