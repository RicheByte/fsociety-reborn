#!/usr/bin/env python3
import subprocess
import time
import binascii
import struct
from datetime import datetime
import sys
import os

class RFIDNFCCloner:
    def __init__(self):
        self.device = None
        self.card_data = {}
        self.cloned_cards = []
        
    def check_requirements(self):
        required = ['proxmark3', 'libnfc-bin', 'mfoc', 'mfcuk', 'nfc-list', 'nfc-mfclassic']
        missing = []
        for tool in required:
            try:
                result = subprocess.run(['which', tool], capture_output=True, text=True, timeout=2)
                if not result.stdout.strip():
                    missing.append(tool)
            except:
                pass
        return missing
    
    def detect_readers(self):
        print("\033[93m[*] Detecting NFC/RFID readers...\033[0m\n")
        
        readers = []
        
        try:
            result = subprocess.run(['nfc-list'], capture_output=True, text=True, timeout=10)
            
            if 'NFC device' in result.stdout or 'opened' in result.stdout:
                for line in result.stdout.split('\n'):
                    if 'NFC device' in line or 'tty' in line.lower():
                        readers.append({'type': 'libnfc', 'name': line.strip()})
                        print(f"\033[92m[+] Found: {line.strip()}\033[0m")
        except:
            pass
        
        try:
            result = subprocess.run(['proxmark3', '--help'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0 or 'proxmark' in result.stdout.lower():
                readers.append({'type': 'proxmark3', 'name': 'Proxmark3'})
                print(f"\033[92m[+] Found: Proxmark3\033[0m")
        except:
            pass
        
        if not readers:
            print(f"\033[93m[!] No readers detected\033[0m")
            print(f"\033[97m[*] Supported: ACR122U, Proxmark3, PN532\033[0m")
        
        return readers
    
    def scan_card(self, reader_type='libnfc'):
        print(f"\n\033[93m[*] Scanning for card...\033[0m")
        print(f"\033[97m[*] Place card on reader\033[0m\n")
        
        if reader_type == 'libnfc':
            return self.scan_with_libnfc()
        elif reader_type == 'proxmark3':
            return self.scan_with_proxmark()
        else:
            return None
    
    def scan_with_libnfc(self):
        try:
            result = subprocess.run(['nfc-list'], capture_output=True, text=True, timeout=10)
            
            card_data = {}
            
            for line in result.stdout.split('\n'):
                if 'UID' in line or 'uid' in line.lower():
                    parts = line.split(':')
                    if len(parts) >= 2:
                        uid = parts[1].strip().replace(' ', '')
                        card_data['uid'] = uid
                        print(f"\033[92m[+] UID: {uid}\033[0m")
                
                if 'ATQA' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        card_data['atqa'] = parts[1].strip()
                        print(f"\033[97m[*] ATQA: {parts[1].strip()}\033[0m")
                
                if 'SAK' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        card_data['sak'] = parts[1].strip()
                        print(f"\033[97m[*] SAK: {parts[1].strip()}\033[0m")
                
                if 'Mifare' in line:
                    card_data['type'] = 'Mifare'
                    print(f"\033[97m[*] Type: Mifare\033[0m")
            
            if card_data.get('uid'):
                return card_data
            else:
                print(f"\033[91m[!] No card detected\033[0m")
                return None
                
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return None
    
    def scan_with_proxmark(self):
        print(f"\033[93m[*] Using Proxmark3...\033[0m\n")
        
        try:
            cmd = "hf search"
            result = subprocess.run(['proxmark3', '/dev/ttyACM0', '-c', cmd],
                                  capture_output=True, text=True, timeout=15)
            
            card_data = {}
            
            for line in result.stdout.split('\n'):
                if 'UID' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        uid = parts[1].strip().replace(' ', '')
                        card_data['uid'] = uid
                        print(f"\033[92m[+] UID: {uid}\033[0m")
                
                if 'TYPE' in line or 'Type' in line:
                    card_data['type'] = line.strip()
                    print(f"\033[97m[*] {line.strip()}\033[0m")
            
            return card_data if card_data else None
            
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return None
    
    def dump_mifare_classic(self, uid):
        print(f"\n\033[93m[*] Dumping Mifare Classic card...\033[0m")
        print(f"\033[97m[*] This may take several minutes\033[0m\n")
        
        dump_file = f"card_dump_{uid}.mfd"
        key_file = f"card_keys_{uid}.txt"
        
        try:
            print(f"\033[97m[*] Recovering keys with mfoc...\033[0m")
            result = subprocess.run(['mfoc', '-O', dump_file], 
                                  capture_output=True, text=True, timeout=300)
            
            if os.path.exists(dump_file):
                print(f"\033[92m[+] Dump saved to: {dump_file}\033[0m")
                
                size = os.path.getsize(dump_file)
                print(f"\033[97m[*] Size: {size} bytes\033[0m")
                
                return dump_file
            else:
                print(f"\033[93m[!] mfoc failed, trying mfcuk...\033[0m")
                return self.dump_with_mfcuk(uid)
                
        except subprocess.TimeoutExpired:
            print(f"\033[91m[!] Timeout\033[0m")
            return None
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return None
    
    def dump_with_mfcuk(self, uid):
        try:
            print(f"\033[97m[*] Using mfcuk (this takes longer)...\033[0m")
            
            dump_file = f"card_dump_{uid}.mfd"
            
            result = subprocess.run(['mfcuk', '-C', '-R', '0:A', '-s', '250', '-S', '250'],
                                  capture_output=True, text=True, timeout=600)
            
            if 'key' in result.stdout.lower():
                print(f"\033[92m[+] Keys recovered!\033[0m")
            
            if os.path.exists(dump_file):
                print(f"\033[92m[+] Dump saved: {dump_file}\033[0m")
                return dump_file
            
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
        
        return None
    
    def clone_card(self, dump_file, uid):
        print(f"\n\033[93m[*] Cloning card...\033[0m")
        print(f"\033[91m[!] Place blank writable card on reader\033[0m\n")
        
        ready = input("\033[95m[?] Ready? (y/n): \033[0m").strip().lower()
        if ready != 'y':
            print("\033[97m[*] Cancelled\033[0m")
            return False
        
        try:
            result = subprocess.run(['nfc-mfclassic', 'w', 'A', dump_file],
                                  capture_output=True, text=True, timeout=30)
            
            if 'Done' in result.stdout or result.returncode == 0:
                print(f"\033[92m[+] Card cloned successfully!\033[0m")
                
                self.cloned_cards.append({
                    'uid': uid,
                    'timestamp': datetime.now().isoformat(),
                    'dump_file': dump_file
                })
                
                return True
            else:
                print(f"\033[91m[!] Clone failed\033[0m")
                print(f"\033[97m{result.stdout}\033[0m")
                return False
                
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return False
    
    def emulate_card(self, dump_file):
        print(f"\n\033[93m[*] Emulating card...\033[0m")
        print(f"\033[97m[*] Press Ctrl+C to stop\033[0m\n")
        
        try:
            result = subprocess.run(['nfc-mfclassic', 'e', 'A', dump_file],
                                  capture_output=True, text=True, timeout=300)
            
            print(result.stdout)
            
        except KeyboardInterrupt:
            print(f"\n\033[93m[*] Stopped\033[0m")
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
    
    def analyze_dump(self, dump_file):
        print(f"\n\033[93m[*] Analyzing dump...\033[0m\n")
        
        try:
            with open(dump_file, 'rb') as f:
                data = f.read()
            
            print(f"\033[97mFile: {dump_file}\033[0m")
            print(f"\033[97mSize: {len(data)} bytes\033[0m")
            print(f"\033[97mSectors: {len(data) // 64}\033[0m\n")
            
            print(f"\033[97mFirst sector (hex):\033[0m")
            hex_data = binascii.hexlify(data[:64]).decode()
            for i in range(0, len(hex_data), 32):
                print(f"\033[97m{hex_data[i:i+32]}\033[0m")
            
            uid_bytes = data[0:4]
            uid = binascii.hexlify(uid_bytes).decode().upper()
            print(f"\n\033[92m[+] UID: {uid}\033[0m")
            
            checksum = data[4]
            print(f"\033[97m[*] BCC: {checksum:02X}\033[0m")
            
            print(f"\n\033[97mAccess conditions:\033[0m")
            for sector in range(min(16, len(data) // 64)):
                trailer_offset = sector * 64 + 48
                if trailer_offset + 16 <= len(data):
                    trailer = data[trailer_offset:trailer_offset+16]
                    key_a = binascii.hexlify(trailer[0:6]).decode()
                    access = binascii.hexlify(trailer[6:10]).decode()
                    key_b = binascii.hexlify(trailer[10:16]).decode()
                    
                    print(f"\033[97m  Sector {sector:2d}: KeyA={key_a} Access={access} KeyB={key_b}\033[0m")
            
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
    
    def uid_changer(self, new_uid):
        print(f"\n\033[93m[*] Changing UID to: {new_uid}\033[0m")
        print(f"\033[91m[!] Only works with special cards (Chinese Magic Cards)\033[0m\n")
        
        try:
            uid_bytes = bytes.fromhex(new_uid)
            
            cmd = f"hf mf csetuid {new_uid}"
            result = subprocess.run(['proxmark3', '/dev/ttyACM0', '-c', cmd],
                                  capture_output=True, text=True, timeout=15)
            
            if 'Done' in result.stdout or 'success' in result.stdout.lower():
                print(f"\033[92m[+] UID changed!\033[0m")
                return True
            else:
                print(f"\033[91m[!] Failed\033[0m")
                print(f"\033[97m{result.stdout}\033[0m")
                return False
                
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return False

def run():
    print("\033[92m" + "="*70)
    print("     RFID/NFC CLONER SIMULATOR")
    print("="*70 + "\033[0m\n")
    
    cloner = RFIDNFCCloner()
    
    missing = cloner.check_requirements()
    if len(missing) >= 5:
        print(f"\033[91m[!] Required tools not installed\033[0m")
        print(f"\033[97m[*] Install: apt install libnfc-bin mfoc mfcuk\033[0m")
        print(f"\033[97m[*] Hardware: ACR122U, Proxmark3, PN532\033[0m")
        return
    
    readers = cloner.detect_readers()
    if not readers:
        print(f"\n\033[93m[!] No readers detected, continuing in simulation mode\033[0m")
        reader_type = 'libnfc'
    else:
        reader_type = readers[0]['type']
    
    print("\n\033[97mOperation mode:\033[0m")
    print("  [1] Scan & Dump card")
    print("  [2] Clone card")
    print("  [3] Analyze dump file")
    print("  [4] Emulate card")
    print("  [5] Change UID (Magic cards)")
    print("  [6] Full workflow (Scan → Dump → Clone)")
    
    mode = input("\n\033[95m[?] Select: \033[0m").strip()
    
    if mode == '1':
        card_data = cloner.scan_card(reader_type)
        
        if card_data and 'Mifare' in card_data.get('type', ''):
            dump = input("\n\033[95m[?] Dump card data? (y/n): \033[0m").strip().lower()
            if dump == 'y':
                dump_file = cloner.dump_mifare_classic(card_data['uid'])
                if dump_file:
                    cloner.analyze_dump(dump_file)
    
    elif mode == '2':
        dump_file = input("\033[95m[?] Dump file path: \033[0m").strip()
        
        if os.path.exists(dump_file):
            with open(dump_file, 'rb') as f:
                data = f.read()
                uid = binascii.hexlify(data[0:4]).decode().upper()
            
            cloner.clone_card(dump_file, uid)
        else:
            print(f"\033[91m[!] File not found\033[0m")
    
    elif mode == '3':
        dump_file = input("\033[95m[?] Dump file path: \033[0m").strip()
        
        if os.path.exists(dump_file):
            cloner.analyze_dump(dump_file)
        else:
            print(f"\033[91m[!] File not found\033[0m")
    
    elif mode == '4':
        dump_file = input("\033[95m[?] Dump file path: \033[0m").strip()
        
        if os.path.exists(dump_file):
            cloner.emulate_card(dump_file)
        else:
            print(f"\033[91m[!] File not found\033[0m")
    
    elif mode == '5':
        new_uid = input("\033[95m[?] New UID (hex, e.g., 11223344): \033[0m").strip()
        
        if len(new_uid) == 8:
            cloner.uid_changer(new_uid)
        else:
            print(f"\033[91m[!] Invalid UID format\033[0m")
    
    elif mode == '6':
        print(f"\033[92m[*] Full workflow\033[0m\n")
        
        card_data = cloner.scan_card(reader_type)
        
        if not card_data:
            print(f"\033[91m[!] No card detected\033[0m")
            return
        
        if 'Mifare' in card_data.get('type', ''):
            dump_file = cloner.dump_mifare_classic(card_data['uid'])
            
            if dump_file:
                cloner.analyze_dump(dump_file)
                
                clone = input("\n\033[95m[?] Clone to new card? (y/n): \033[0m").strip().lower()
                if clone == 'y':
                    cloner.clone_card(dump_file, card_data['uid'])
    
    if cloner.cloned_cards:
        print(f"\n\033[92m{'='*70}\033[0m")
        print(f"\033[92m[+] Cloned {len(cloner.cloned_cards)} card(s)\033[0m")
        for i, card in enumerate(cloner.cloned_cards, 1):
            print(f"\033[97m  [{i}] UID: {card['uid']} | {card['timestamp']}\033[0m")
        print(f"\033[92m{'='*70}\033[0m")
    
    print(f"\n\033[92m[+] Done\033[0m")

if __name__ == "__main__":
    run()
