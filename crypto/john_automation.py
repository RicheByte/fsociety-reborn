#!/usr/bin/env python3
import os
import subprocess
import json
import time
from datetime import datetime
from collections import defaultdict

class JohnAutomation:
    def __init__(self):
        self.formats = {
            'md5crypt': 'MD5 (Unix)',
            'bcrypt': 'bcrypt',
            'sha512crypt': 'SHA-512 (Unix)',
            'sha256crypt': 'SHA-256 (Unix)',
            'descrypt': 'DES (Unix)',
            'bsdicrypt': 'BSDI crypt',
            'md5': 'Raw MD5',
            'raw-sha1': 'Raw SHA1',
            'raw-sha256': 'Raw SHA-256',
            'raw-sha512': 'Raw SHA-512',
            'nt': 'NT (NTLM)',
            'lm': 'LM',
            'netlm': 'NetLM',
            'netntlm': 'NetNTLM',
            'netntlmv2': 'NetNTLMv2',
            'mscash': 'MS Cache Hash',
            'mscash2': 'MS Cache Hash 2',
            'krb5': 'Kerberos 5',
            'zip': 'ZIP',
            'rar': 'RAR',
            '7z': '7-Zip',
            'office': 'MS Office',
            'pdf': 'PDF',
            'pkzip': 'PKZIP',
            'wpa-psk': 'WPA-PSK'
        }
        
        self.crack_modes = {
            'single': 'Single crack mode',
            'wordlist': 'Wordlist mode',
            'incremental': 'Incremental mode',
            'external': 'External mode',
            'mask': 'Mask mode',
            'prince': 'PRINCE mode',
            'markov': 'Markov mode'
        }
        
        self.output_dir = f"john_session_{int(datetime.now().timestamp())}"
        self.results = defaultdict(list)
        
    def detect_hash_format(self, hash_file):
        print(f"\033[93m[*] Detecting hash format...\033[0m")
        
        cmd = ['john', '--list=formats', hash_file]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.stdout:
                formats = result.stdout.strip().split('\n')
                
                if formats:
                    print(f"\033[92m[+] Detected possible formats: {', '.join(formats[:5])}\033[0m")
                    return formats[0]
            
            return None
        
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return None
    
    def run_single_mode(self, hash_file, format_type=None):
        print(f"\033[93m[*] Running single crack mode...\033[0m")
        
        os.makedirs(self.output_dir, exist_ok=True)
        
        session_name = f"single_{int(time.time())}"
        
        cmd = ['john', '--single', hash_file]
        
        if format_type:
            cmd.extend(['--format=' + format_type])
        
        cmd.extend(['--session=' + session_name])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
            
            cracked = self.show_cracked(hash_file)
            
            self.results['single_mode'] = cracked
            
            print(f"\033[92m[+] Single mode complete: {len(cracked)} cracked\033[0m")
            
            return cracked
        
        except subprocess.TimeoutExpired:
            print(f"\033[91m[!] Timeout - checking progress\033[0m")
            return self.show_cracked(hash_file)
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return []
    
    def run_wordlist_mode(self, hash_file, wordlist, format_type=None, rules=None):
        print(f"\033[93m[*] Running wordlist mode...\033[0m")
        
        session_name = f"wordlist_{int(time.time())}"
        
        cmd = ['john', '--wordlist=' + wordlist, hash_file]
        
        if format_type:
            cmd.extend(['--format=' + format_type])
        
        if rules:
            cmd.extend(['--rules=' + rules])
        
        cmd.extend(['--session=' + session_name])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            cracked = self.show_cracked(hash_file)
            
            self.results['wordlist_mode'] = cracked
            
            print(f"\033[92m[+] Wordlist mode complete: {len(cracked)} cracked\033[0m")
            
            return cracked
        
        except subprocess.TimeoutExpired:
            print(f"\033[91m[!] Timeout - checking progress\033[0m")
            return self.show_cracked(hash_file)
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return []
    
    def run_incremental_mode(self, hash_file, charset='ASCII', format_type=None):
        print(f"\033[93m[*] Running incremental mode with {charset} charset...\033[0m")
        
        session_name = f"incremental_{int(time.time())}"
        
        cmd = ['john', '--incremental=' + charset, hash_file]
        
        if format_type:
            cmd.extend(['--format=' + format_type])
        
        cmd.extend(['--session=' + session_name])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)
            
            cracked = self.show_cracked(hash_file)
            
            self.results['incremental_mode'] = cracked
            
            print(f"\033[92m[+] Incremental mode complete: {len(cracked)} cracked\033[0m")
            
            return cracked
        
        except subprocess.TimeoutExpired:
            print(f"\033[91m[!] Timeout - checking progress\033[0m")
            return self.show_cracked(hash_file)
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return []
    
    def run_mask_mode(self, hash_file, mask, format_type=None):
        print(f"\033[93m[*] Running mask mode: {mask}\033[0m")
        
        session_name = f"mask_{int(time.time())}"
        
        cmd = ['john', '--mask=' + mask, hash_file]
        
        if format_type:
            cmd.extend(['--format=' + format_type])
        
        cmd.extend(['--session=' + session_name])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)
            
            cracked = self.show_cracked(hash_file)
            
            self.results['mask_mode'] = cracked
            
            print(f"\033[92m[+] Mask mode complete: {len(cracked)} cracked\033[0m")
            
            return cracked
        
        except subprocess.TimeoutExpired:
            print(f"\033[91m[!] Timeout - checking progress\033[0m")
            return self.show_cracked(hash_file)
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return []
    
    def run_prince_mode(self, hash_file, wordlist, format_type=None):
        print(f"\033[93m[*] Running PRINCE mode...\033[0m")
        
        session_name = f"prince_{int(time.time())}"
        
        cmd = ['john', '--prince=' + wordlist, hash_file]
        
        if format_type:
            cmd.extend(['--format=' + format_type])
        
        cmd.extend(['--session=' + session_name])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            cracked = self.show_cracked(hash_file)
            
            self.results['prince_mode'] = cracked
            
            print(f"\033[92m[+] PRINCE mode complete: {len(cracked)} cracked\033[0m")
            
            return cracked
        
        except subprocess.TimeoutExpired:
            print(f"\033[91m[!] Timeout - checking progress\033[0m")
            return self.show_cracked(hash_file)
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return []
    
    def run_markov_mode(self, hash_file, format_type=None):
        print(f"\033[93m[*] Running Markov mode...\033[0m")
        
        session_name = f"markov_{int(time.time())}"
        
        cmd = ['john', '--markov', hash_file]
        
        if format_type:
            cmd.extend(['--format=' + format_type])
        
        cmd.extend(['--session=' + session_name])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)
            
            cracked = self.show_cracked(hash_file)
            
            self.results['markov_mode'] = cracked
            
            print(f"\033[92m[+] Markov mode complete: {len(cracked)} cracked\033[0m")
            
            return cracked
        
        except subprocess.TimeoutExpired:
            print(f"\033[91m[!] Timeout - checking progress\033[0m")
            return self.show_cracked(hash_file)
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return []
    
    def show_cracked(self, hash_file):
        cmd = ['john', '--show', hash_file]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            cracked = []
            
            for line in result.stdout.split('\n'):
                if line.strip() and ':' in line:
                    cracked.append(line.strip())
            
            return cracked
        
        except Exception as e:
            return []
    
    def show_status(self, session_name):
        print(f"\033[93m[*] Checking session status: {session_name}\033[0m")
        
        cmd = ['john', '--status=' + session_name]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            print(result.stdout)
            
            return result.stdout
        
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return ''
    
    def restore_session(self, session_name):
        print(f"\033[93m[*] Restoring session: {session_name}\033[0m")
        
        cmd = ['john', '--restore=' + session_name]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            print(f"\033[92m[+] Session restored\033[0m")
            
            return result.stdout
        
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return ''
    
    def list_formats(self):
        print(f"\033[93m[*] Listing supported formats...\033[0m")
        
        cmd = ['john', '--list=formats']
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            formats = result.stdout.strip().split('\n')
            
            for i, fmt in enumerate(formats[:50], 1):
                print(f"\033[97m  {i}. {fmt}\033[0m")
            
            print(f"\033[97m  ... and {len(formats) - 50} more\033[0m")
            
            return formats
        
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return []
    
    def list_rules(self):
        print(f"\033[93m[*] Listing available rules...\033[0m")
        
        cmd = ['john', '--list=rules']
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            print(result.stdout)
            
            return result.stdout
        
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return ''
    
    def automated_attack(self, hash_file, wordlist, format_type=None):
        print(f"\033[93m[*] Running automated attack sequence...\033[0m")
        
        all_cracked = []
        
        print(f"\n\033[97m[1/6] Single crack mode\033[0m")
        cracked = self.run_single_mode(hash_file, format_type)
        all_cracked.extend(cracked)
        
        print(f"\n\033[97m[2/6] Wordlist mode (no rules)\033[0m")
        cracked = self.run_wordlist_mode(hash_file, wordlist, format_type)
        all_cracked.extend(cracked)
        
        print(f"\n\033[97m[3/6] Wordlist mode (with rules)\033[0m")
        cracked = self.run_wordlist_mode(hash_file, wordlist, format_type, 'All')
        all_cracked.extend(cracked)
        
        print(f"\n\033[97m[4/6] PRINCE mode\033[0m")
        cracked = self.run_prince_mode(hash_file, wordlist, format_type)
        all_cracked.extend(cracked)
        
        print(f"\n\033[97m[5/6] Markov mode\033[0m")
        cracked = self.run_markov_mode(hash_file, format_type)
        all_cracked.extend(cracked)
        
        print(f"\n\033[97m[6/6] Mask mode (common patterns)\033[0m")
        masks = ['?u?l?l?l?l?l?d?d', '?u?l?l?l?l?d?d?d', '?l?l?l?l?d?d?d?d']
        for mask in masks:
            cracked = self.run_mask_mode(hash_file, mask, format_type)
            all_cracked.extend(cracked)
        
        unique_cracked = list(set(all_cracked))
        
        print(f"\n\033[92m[+] Total unique cracked: {len(unique_cracked)}\033[0m")
        
        return unique_cracked
    
    def generate_custom_wordlist(self, input_wordlist, output_file):
        print(f"\033[93m[*] Generating custom wordlist with mutations...\033[0m")
        
        os.makedirs(self.output_dir, exist_ok=True)
        
        output_path = os.path.join(self.output_dir, output_file)
        
        mutations = []
        
        with open(input_wordlist, 'r', encoding='utf-8', errors='ignore') as f:
            words = [line.strip() for line in f if line.strip()][:10000]
        
        for word in words:
            mutations.append(word)
            mutations.append(word.lower())
            mutations.append(word.upper())
            mutations.append(word.capitalize())
            mutations.append(word + '123')
            mutations.append(word + '!')
            mutations.append(word + '@')
            mutations.append('1' + word)
            mutations.append(word[::-1])
            
            if len(word) > 3:
                mutations.append(word[:-1] + word[-1].upper())
        
        with open(output_path, 'w', encoding='utf-8') as f:
            for mutation in set(mutations):
                f.write(mutation + '\n')
        
        print(f"\033[92m[+] Generated {len(set(mutations))} mutations\033[0m")
        print(f"\033[92m[+] Saved: {output_path}\033[0m")
        
        return output_path
    
    def generate_report(self):
        os.makedirs(self.output_dir, exist_ok=True)
        
        report_file = os.path.join(self.output_dir, 'john_report.json')
        
        total_cracked = sum(len(results) for results in self.results.values())
        
        report = {
            'session_date': datetime.now().isoformat(),
            'output_directory': self.output_dir,
            'total_cracked': total_cracked,
            'mode_results': {
                mode: len(results) for mode, results in self.results.items()
            },
            'cracked_passwords': dict(self.results)
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n\033[92m[+] Report saved: {report_file}\033[0m")

def run():
    print("\033[92m" + "="*70)
    print("     JOHN THE RIPPER AUTOMATION WRAPPER")
    print("="*70 + "\033[0m\n")
    
    john = JohnAutomation()
    
    print("\033[97mJohn the Ripper Options:\033[0m")
    print("\033[97m  [1] Single crack mode\033[0m")
    print("\033[97m  [2] Wordlist mode\033[0m")
    print("\033[97m  [3] Wordlist mode with rules\033[0m")
    print("\033[97m  [4] Incremental mode\033[0m")
    print("\033[97m  [5] Mask mode\033[0m")
    print("\033[97m  [6] PRINCE mode\033[0m")
    print("\033[97m  [7] Markov mode\033[0m")
    print("\033[97m  [8] Automated attack (all modes)\033[0m")
    print("\033[97m  [9] List supported formats\033[0m")
    print("\033[97m  [10] Show cracked passwords\033[0m")
    
    choice = input(f"\n\033[95m[?] Select option: \033[0m").strip()
    
    if choice in ['1', '2', '3', '4', '5', '6', '7', '8', '10']:
        hash_file = input("\033[95m[?] Hash file path: \033[0m").strip()
        
        if not os.path.exists(hash_file):
            print(f"\033[91m[!] File not found\033[0m")
            return
        
        if choice != '10':
            format_type = input("\033[95m[?] Hash format (press Enter for auto-detect): \033[0m").strip()
            
            if not format_type:
                format_type = john.detect_hash_format(hash_file)
        
        if choice == '1':
            john.run_single_mode(hash_file, format_type)
            john.generate_report()
        
        elif choice == '2':
            wordlist = input("\033[95m[?] Wordlist path: \033[0m").strip()
            
            if not os.path.exists(wordlist):
                print(f"\033[91m[!] Wordlist not found\033[0m")
                return
            
            john.run_wordlist_mode(hash_file, wordlist, format_type)
            john.generate_report()
        
        elif choice == '3':
            wordlist = input("\033[95m[?] Wordlist path: \033[0m").strip()
            rules = input("\033[95m[?] Rule name (e.g., All, Jumbo): \033[0m").strip()
            
            if not os.path.exists(wordlist):
                print(f"\033[91m[!] Wordlist not found\033[0m")
                return
            
            john.run_wordlist_mode(hash_file, wordlist, format_type, rules)
            john.generate_report()
        
        elif choice == '4':
            charset = input("\033[95m[?] Charset (ASCII/Digits/LowerNum): \033[0m").strip() or 'ASCII'
            
            john.run_incremental_mode(hash_file, charset, format_type)
            john.generate_report()
        
        elif choice == '5':
            mask = input("\033[95m[?] Mask pattern (e.g., ?u?l?l?l?l?d?d): \033[0m").strip()
            
            john.run_mask_mode(hash_file, mask, format_type)
            john.generate_report()
        
        elif choice == '6':
            wordlist = input("\033[95m[?] Wordlist path: \033[0m").strip()
            
            if not os.path.exists(wordlist):
                print(f"\033[91m[!] Wordlist not found\033[0m")
                return
            
            john.run_prince_mode(hash_file, wordlist, format_type)
            john.generate_report()
        
        elif choice == '7':
            john.run_markov_mode(hash_file, format_type)
            john.generate_report()
        
        elif choice == '8':
            wordlist = input("\033[95m[?] Wordlist path: \033[0m").strip()
            
            if not os.path.exists(wordlist):
                print(f"\033[91m[!] Wordlist not found\033[0m")
                return
            
            john.automated_attack(hash_file, wordlist, format_type)
            john.generate_report()
        
        elif choice == '10':
            cracked = john.show_cracked(hash_file)
            
            print(f"\n\033[92m[+] Cracked passwords:\033[0m")
            for pwd in cracked:
                print(f"\033[97m  {pwd}\033[0m")
    
    elif choice == '9':
        john.list_formats()
    
    print(f"\n\033[92m[+] Done\033[0m")

if __name__ == "__main__":
    run()
