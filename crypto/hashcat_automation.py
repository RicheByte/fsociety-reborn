#!/usr/bin/env python3
import os
import subprocess
import json
import hashlib
import time
from datetime import datetime
from collections import defaultdict

class HashcatAutomation:
    def __init__(self):
        self.hash_types = {
            '0': 'MD5',
            '100': 'SHA1',
            '1400': 'SHA256',
            '1700': 'SHA512',
            '900': 'MD4',
            '1000': 'NTLM',
            '3000': 'LM',
            '5600': 'NetNTLMv2',
            '1800': 'sha512crypt',
            '500': 'md5crypt',
            '3200': 'bcrypt',
            '7500': 'Kerberos 5 AS-REQ',
            '13100': 'Kerberos 5 TGS-REP',
            '2500': 'WPA/WPA2',
            '16800': 'WPA-PMKID-PBKDF2',
            '22000': 'WPA-PBKDF2-PMKID+EAPOL',
            '1100': 'Domain Cached Credentials',
            '2100': 'Domain Cached Credentials 2',
            '99999': 'Plaintext'
        }
        
        self.attack_modes = {
            '0': 'Straight',
            '1': 'Combination',
            '3': 'Brute-force',
            '6': 'Hybrid Wordlist + Mask',
            '7': 'Hybrid Mask + Wordlist'
        }
        
        self.workload_profiles = {
            '1': 'Low',
            '2': 'Default',
            '3': 'High',
            '4': 'Nightmare'
        }
        
        self.output_dir = f"hashcat_session_{int(datetime.now().timestamp())}"
        self.results = defaultdict(list)
        
    def detect_hash_type(self, hash_value):
        hash_len = len(hash_value)
        
        if hash_len == 32 and all(c in '0123456789abcdefABCDEF' for c in hash_value):
            return '0', 'MD5'
        elif hash_len == 40 and all(c in '0123456789abcdefABCDEF' for c in hash_value):
            return '100', 'SHA1'
        elif hash_len == 64 and all(c in '0123456789abcdefABCDEF' for c in hash_value):
            return '1400', 'SHA256'
        elif hash_len == 128 and all(c in '0123456789abcdefABCDEF' for c in hash_value):
            return '1700', 'SHA512'
        elif hash_value.startswith('$2a$') or hash_value.startswith('$2b$') or hash_value.startswith('$2y$'):
            return '3200', 'bcrypt'
        elif hash_value.startswith('$6$'):
            return '1800', 'sha512crypt'
        elif hash_value.startswith('$5$'):
            return '7400', 'sha256crypt'
        elif hash_value.startswith('$1$'):
            return '500', 'md5crypt'
        elif ':' in hash_value and len(hash_value.split(':')) >= 2:
            return '1000', 'NTLM'
        else:
            return None, 'Unknown'
    
    def generate_mask_attack(self, min_len=8, max_len=12):
        masks = []
        
        charsets = {
            '?l': 'lowercase',
            '?u': 'uppercase',
            '?d': 'digits',
            '?s': 'special',
            '?a': 'all'
        }
        
        for length in range(min_len, max_len + 1):
            masks.append('?a' * length)
            
            if length >= 8:
                masks.append('?u' + '?l' * (length - 2) + '?d')
                masks.append('?l' * (length - 2) + '?d' + '?s')
                masks.append('?u' + '?l' * (length - 3) + '?d' + '?s')
        
        return masks
    
    def create_rule_file(self):
        os.makedirs(self.output_dir, exist_ok=True)
        
        rule_file = os.path.join(self.output_dir, 'custom.rule')
        
        rules = [
            ':',
            'l',
            'u',
            'c',
            't',
            '$0', '$1', '$2', '$3', '$!', '$@',
            '^0', '^1', '^2', '^3',
            'r',
            'd',
            '$1$2$3',
            '$!$@$#',
            '$2$0$2$0', '$2$0$2$1', '$2$0$2$2',
            'l $1', 'l $2', 'l $3',
            'u $1', 'u $2', 'u $3',
            'c $0', 'c $1', 'c $2',
            't $!', 't $@', 't $#',
            'l $1$2$3',
            'c $1$2$3',
            'l r $1',
            'c r $1',
            'l $1 $2 $3',
            'T0', 'T1', 'T2', 'T3',
            'so0', 'so1', 'se3', 'si1', 'ss5',
            'l so0 $1',
            'c se3 $!',
            'l si1 ss5 $0',
            'd $1$2$3',
            'f $1$2$3',
            'l r d $1',
            'c so0 se3 $1$2$3'
        ]
        
        with open(rule_file, 'w') as f:
            f.write('\n'.join(rules))
        
        return rule_file
    
    def run_dictionary_attack(self, hash_file, wordlist, hash_type='0'):
        print(f"\033[93m[*] Running dictionary attack...\033[0m")
        
        os.makedirs(self.output_dir, exist_ok=True)
        
        output_file = os.path.join(self.output_dir, 'cracked.txt')
        potfile = os.path.join(self.output_dir, 'hashcat.potfile')
        
        cmd = [
            'hashcat',
            '-m', hash_type,
            '-a', '0',
            hash_file,
            wordlist,
            '-o', output_file,
            '--potfile-path', potfile,
            '--force'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    cracked = f.readlines()
                
                print(f"\033[92m[+] Cracked {len(cracked)} hashes\033[0m")
                
                self.results['dictionary'].extend(cracked)
                
                return cracked
            else:
                print(f"\033[91m[!] No hashes cracked\033[0m")
                return []
        
        except subprocess.TimeoutExpired:
            print(f"\033[91m[!] Attack timeout\033[0m")
            return []
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return []
    
    def run_rule_based_attack(self, hash_file, wordlist, hash_type='0'):
        print(f"\033[93m[*] Running rule-based attack...\033[0m")
        
        rule_file = self.create_rule_file()
        output_file = os.path.join(self.output_dir, 'cracked_rules.txt')
        potfile = os.path.join(self.output_dir, 'hashcat.potfile')
        
        cmd = [
            'hashcat',
            '-m', hash_type,
            '-a', '0',
            hash_file,
            wordlist,
            '-r', rule_file,
            '-o', output_file,
            '--potfile-path', potfile,
            '--force'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)
            
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    cracked = f.readlines()
                
                print(f"\033[92m[+] Cracked {len(cracked)} hashes with rules\033[0m")
                
                self.results['rule_based'].extend(cracked)
                
                return cracked
            else:
                print(f"\033[91m[!] No hashes cracked\033[0m")
                return []
        
        except subprocess.TimeoutExpired:
            print(f"\033[91m[!] Attack timeout\033[0m")
            return []
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return []
    
    def run_mask_attack(self, hash_file, mask, hash_type='0'):
        print(f"\033[93m[*] Running mask attack: {mask}\033[0m")
        
        output_file = os.path.join(self.output_dir, 'cracked_mask.txt')
        potfile = os.path.join(self.output_dir, 'hashcat.potfile')
        
        cmd = [
            'hashcat',
            '-m', hash_type,
            '-a', '3',
            hash_file,
            mask,
            '-o', output_file,
            '--potfile-path', potfile,
            '--force'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)
            
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    cracked = f.readlines()
                
                print(f"\033[92m[+] Cracked {len(cracked)} hashes with mask\033[0m")
                
                self.results['mask_attack'].extend(cracked)
                
                return cracked
            else:
                print(f"\033[91m[!] No hashes cracked\033[0m")
                return []
        
        except subprocess.TimeoutExpired:
            print(f"\033[91m[!] Attack timeout\033[0m")
            return []
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return []
    
    def run_hybrid_attack(self, hash_file, wordlist, mask, hash_type='0'):
        print(f"\033[93m[*] Running hybrid attack...\033[0m")
        
        output_file = os.path.join(self.output_dir, 'cracked_hybrid.txt')
        potfile = os.path.join(self.output_dir, 'hashcat.potfile')
        
        cmd = [
            'hashcat',
            '-m', hash_type,
            '-a', '6',
            hash_file,
            wordlist,
            mask,
            '-o', output_file,
            '--potfile-path', potfile,
            '--force'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)
            
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    cracked = f.readlines()
                
                print(f"\033[92m[+] Cracked {len(cracked)} hashes with hybrid\033[0m")
                
                self.results['hybrid'].extend(cracked)
                
                return cracked
            else:
                print(f"\033[91m[!] No hashes cracked\033[0m")
                return []
        
        except subprocess.TimeoutExpired:
            print(f"\033[91m[!] Attack timeout\033[0m")
            return []
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return []
    
    def run_combinator_attack(self, hash_file, wordlist1, wordlist2, hash_type='0'):
        print(f"\033[93m[*] Running combinator attack...\033[0m")
        
        output_file = os.path.join(self.output_dir, 'cracked_combo.txt')
        potfile = os.path.join(self.output_dir, 'hashcat.potfile')
        
        cmd = [
            'hashcat',
            '-m', hash_type,
            '-a', '1',
            hash_file,
            wordlist1,
            wordlist2,
            '-o', output_file,
            '--potfile-path', potfile,
            '--force'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    cracked = f.readlines()
                
                print(f"\033[92m[+] Cracked {len(cracked)} hashes with combinator\033[0m")
                
                self.results['combinator'].extend(cracked)
                
                return cracked
            else:
                print(f"\033[91m[!] No hashes cracked\033[0m")
                return []
        
        except subprocess.TimeoutExpired:
            print(f"\033[91m[!] Attack timeout\033[0m")
            return []
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return []
    
    def benchmark_gpu(self):
        print(f"\033[93m[*] Running GPU benchmark...\033[0m")
        
        cmd = ['hashcat', '-b', '--force']
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            print(f"\033[92m[+] Benchmark complete\033[0m")
            print(result.stdout[:500])
            
            return result.stdout
        
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return ''
    
    def show_devices(self):
        print(f"\033[93m[*] Detecting GPU devices...\033[0m")
        
        cmd = ['hashcat', '-I', '--force']
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            print(result.stdout)
            
            return result.stdout
        
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return ''
    
    def automated_smart_attack(self, hash_file, wordlist, hash_type='0'):
        print(f"\033[93m[*] Running automated smart attack sequence...\033[0m")
        
        all_cracked = []
        
        print(f"\n\033[97m[1/5] Dictionary attack\033[0m")
        cracked = self.run_dictionary_attack(hash_file, wordlist, hash_type)
        all_cracked.extend(cracked)
        
        print(f"\n\033[97m[2/5] Rule-based attack\033[0m")
        cracked = self.run_rule_based_attack(hash_file, wordlist, hash_type)
        all_cracked.extend(cracked)
        
        print(f"\n\033[97m[3/5] Hybrid wordlist+mask attack\033[0m")
        cracked = self.run_hybrid_attack(hash_file, wordlist, '?d?d?d', hash_type)
        all_cracked.extend(cracked)
        
        print(f"\n\033[97m[4/5] Combinator attack\033[0m")
        cracked = self.run_combinator_attack(hash_file, wordlist, wordlist, hash_type)
        all_cracked.extend(cracked)
        
        print(f"\n\033[97m[5/5] Mask attack (common patterns)\033[0m")
        masks = ['?u?l?l?l?l?l?d?d', '?u?l?l?l?l?d?d?d', '?l?l?l?l?d?d?d?d']
        for mask in masks:
            cracked = self.run_mask_attack(hash_file, mask, hash_type)
            all_cracked.extend(cracked)
        
        print(f"\n\033[92m[+] Total cracked: {len(all_cracked)}\033[0m")
        
        return all_cracked
    
    def generate_report(self):
        os.makedirs(self.output_dir, exist_ok=True)
        
        report_file = os.path.join(self.output_dir, 'hashcat_report.json')
        
        total_cracked = sum(len(results) for results in self.results.values())
        
        report = {
            'session_date': datetime.now().isoformat(),
            'output_directory': self.output_dir,
            'total_cracked': total_cracked,
            'attack_results': {
                attack: len(results) for attack, results in self.results.items()
            },
            'cracked_passwords': dict(self.results)
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n\033[92m[+] Report saved: {report_file}\033[0m")

def run():
    print("\033[92m" + "="*70)
    print("     HASHCAT AUTOMATION WRAPPER")
    print("="*70 + "\033[0m\n")
    
    hashcat = HashcatAutomation()
    
    print("\033[97mHashcat Options:\033[0m")
    print("\033[97m  [1] Dictionary attack\033[0m")
    print("\033[97m  [2] Rule-based attack\033[0m")
    print("\033[97m  [3] Mask attack\033[0m")
    print("\033[97m  [4] Hybrid attack\033[0m")
    print("\033[97m  [5] Combinator attack\033[0m")
    print("\033[97m  [6] Automated smart attack (all methods)\033[0m")
    print("\033[97m  [7] GPU benchmark\033[0m")
    print("\033[97m  [8] Show GPU devices\033[0m")
    
    choice = input(f"\n\033[95m[?] Select option: \033[0m").strip()
    
    if choice in ['1', '2', '3', '4', '5', '6']:
        hash_file = input("\033[95m[?] Hash file path: \033[0m").strip()
        
        if not os.path.exists(hash_file):
            print(f"\033[91m[!] File not found\033[0m")
            return
        
        with open(hash_file, 'r') as f:
            sample_hash = f.readline().strip()
        
        hash_type_id, hash_type_name = hashcat.detect_hash_type(sample_hash)
        
        if hash_type_id:
            print(f"\033[92m[+] Detected hash type: {hash_type_name} (mode {hash_type_id})\033[0m")
            
            confirm = input(f"\033[95m[?] Use detected type? (y/n): \033[0m").strip().lower()
            
            if confirm != 'y':
                hash_type_id = input("\033[95m[?] Enter hash type mode: \033[0m").strip()
        else:
            hash_type_id = input("\033[95m[?] Enter hash type mode: \033[0m").strip()
        
        if choice == '6':
            wordlist = input("\033[95m[?] Wordlist path: \033[0m").strip()
            
            if not os.path.exists(wordlist):
                print(f"\033[91m[!] Wordlist not found\033[0m")
                return
            
            hashcat.automated_smart_attack(hash_file, wordlist, hash_type_id)
            hashcat.generate_report()
        
        elif choice == '1':
            wordlist = input("\033[95m[?] Wordlist path: \033[0m").strip()
            
            if not os.path.exists(wordlist):
                print(f"\033[91m[!] Wordlist not found\033[0m")
                return
            
            hashcat.run_dictionary_attack(hash_file, wordlist, hash_type_id)
            hashcat.generate_report()
        
        elif choice == '2':
            wordlist = input("\033[95m[?] Wordlist path: \033[0m").strip()
            
            if not os.path.exists(wordlist):
                print(f"\033[91m[!] Wordlist not found\033[0m")
                return
            
            hashcat.run_rule_based_attack(hash_file, wordlist, hash_type_id)
            hashcat.generate_report()
        
        elif choice == '3':
            mask = input("\033[95m[?] Mask pattern (e.g., ?u?l?l?l?l?d?d): \033[0m").strip()
            
            hashcat.run_mask_attack(hash_file, mask, hash_type_id)
            hashcat.generate_report()
        
        elif choice == '4':
            wordlist = input("\033[95m[?] Wordlist path: \033[0m").strip()
            mask = input("\033[95m[?] Mask pattern: \033[0m").strip()
            
            if not os.path.exists(wordlist):
                print(f"\033[91m[!] Wordlist not found\033[0m")
                return
            
            hashcat.run_hybrid_attack(hash_file, wordlist, mask, hash_type_id)
            hashcat.generate_report()
        
        elif choice == '5':
            wordlist1 = input("\033[95m[?] Wordlist 1 path: \033[0m").strip()
            wordlist2 = input("\033[95m[?] Wordlist 2 path: \033[0m").strip()
            
            if not os.path.exists(wordlist1) or not os.path.exists(wordlist2):
                print(f"\033[91m[!] Wordlist not found\033[0m")
                return
            
            hashcat.run_combinator_attack(hash_file, wordlist1, wordlist2, hash_type_id)
            hashcat.generate_report()
    
    elif choice == '7':
        hashcat.benchmark_gpu()
    
    elif choice == '8':
        hashcat.show_devices()
    
    print(f"\n\033[92m[+] Done\033[0m")

if __name__ == "__main__":
    run()
