#!/usr/bin/env python3
import os
import subprocess
import json
import hashlib
import re
from datetime import datetime
from collections import defaultdict

class VolatilityAutomation:
    def __init__(self, memory_dump):
        self.memory_dump = memory_dump
        self.profile = None
        self.results = defaultdict(dict)
        self.output_dir = f"volatility_analysis_{int(datetime.now().timestamp())}"
        
        self.plugins = {
            'imageinfo': 'Identify memory dump profile',
            'pslist': 'List running processes',
            'psscan': 'Scan for process objects',
            'pstree': 'Display process tree',
            'psxview': 'Find hidden processes',
            'dlllist': 'List loaded DLLs',
            'handles': 'Display open handles',
            'cmdline': 'Extract command line arguments',
            'netscan': 'Scan for network artifacts',
            'connections': 'List network connections',
            'connscan': 'Scan for connection objects',
            'sockets': 'Display socket information',
            'filescan': 'Scan for file objects',
            'malfind': 'Find injected code',
            'ldrmodules': 'Detect unlinked DLLs',
            'apihooks': 'Detect API hooks',
            'ssdt': 'Display SSDT',
            'idt': 'Display IDT',
            'gdt': 'Display GDT',
            'hivelist': 'List registry hives',
            'hashdump': 'Dump password hashes',
            'cachedump': 'Dump cached credentials',
            'lsadump': 'Dump LSA secrets',
            'envars': 'Display environment variables',
            'cmdscan': 'Scan for command history',
            'consoles': 'Extract console information',
            'clipboard': 'Extract clipboard contents',
            'iehistory': 'Extract IE history',
            'timeliner': 'Create timeline',
            'mftparser': 'Parse MFT records',
            'svcscan': 'Scan for services',
            'mutantscan': 'Scan for mutexes',
            'shimcache': 'Parse shimcache'
        }
    
    def execute_volatility(self, plugin, extra_args=''):
        if not self.profile and plugin != 'imageinfo':
            print(f"\033[91m[!] Profile not identified\033[0m")
            return None
        
        profile_arg = f"--profile={self.profile}" if self.profile else ""
        cmd = f"volatility -f {self.memory_dump} {profile_arg} {plugin} {extra_args}"
        
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            return None
        except Exception as e:
            return None
    
    def identify_profile(self):
        print(f"\033[93m[*] Identifying memory dump profile...\033[0m")
        
        output = self.execute_volatility('imageinfo')
        
        if output:
            profile_match = re.search(r'Suggested Profile\(s\)\s*:\s*([^,\n]+)', output)
            
            if profile_match:
                self.profile = profile_match.group(1).strip()
                print(f"\033[92m[+] Profile identified: {self.profile}\033[0m")
                
                self.results['imageinfo']['profile'] = self.profile
                self.results['imageinfo']['raw_output'] = output[:500]
                
                return True
        
        print(f"\033[91m[!] Could not identify profile\033[0m")
        return False
    
    def analyze_processes(self):
        print(f"\033[93m[*] Analyzing processes...\033[0m")
        
        pslist_output = self.execute_volatility('pslist')
        psscan_output = self.execute_volatility('psscan')
        pstree_output = self.execute_volatility('pstree')
        psxview_output = self.execute_volatility('psxview')
        
        processes = []
        hidden_processes = []
        
        if pslist_output:
            for line in pslist_output.split('\n')[2:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 4:
                        try:
                            processes.append({
                                'name': parts[0],
                                'pid': parts[1],
                                'ppid': parts[2],
                                'threads': parts[3]
                            })
                        except:
                            pass
        
        if psxview_output:
            for line in psxview_output.split('\n'):
                if 'False' in line:
                    parts = line.split()
                    if parts:
                        hidden_processes.append({
                            'name': parts[0],
                            'pid': parts[1] if len(parts) > 1 else 'Unknown'
                        })
        
        self.results['processes']['running'] = processes[:50]
        self.results['processes']['hidden'] = hidden_processes
        self.results['processes']['tree'] = pstree_output[:1000] if pstree_output else ''
        
        print(f"\033[92m[+] Found {len(processes)} processes\033[0m")
        print(f"\033[92m[+] Found {len(hidden_processes)} hidden processes\033[0m")
    
    def analyze_network(self):
        print(f"\033[93m[*] Analyzing network connections...\033[0m")
        
        netscan_output = self.execute_volatility('netscan')
        
        connections = []
        
        if netscan_output:
            for line in netscan_output.split('\n')[2:]:
                if line.strip():
                    if any(proto in line for proto in ['TCP', 'UDP']):
                        parts = line.split()
                        if len(parts) >= 5:
                            connections.append({
                                'protocol': parts[0],
                                'local_addr': parts[1] if len(parts) > 1 else '',
                                'foreign_addr': parts[2] if len(parts) > 2 else '',
                                'state': parts[3] if len(parts) > 3 else '',
                                'pid': parts[4] if len(parts) > 4 else ''
                            })
        
        self.results['network']['connections'] = connections[:50]
        self.results['network']['raw_output'] = netscan_output[:1000] if netscan_output else ''
        
        print(f"\033[92m[+] Found {len(connections)} network connections\033[0m")
    
    def detect_malware(self):
        print(f"\033[93m[*] Detecting malware indicators...\033[0m")
        
        malfind_output = self.execute_volatility('malfind')
        ldrmodules_output = self.execute_volatility('ldrmodules')
        apihooks_output = self.execute_volatility('apihooks')
        
        injections = []
        unlinked_dlls = []
        hooks = []
        
        if malfind_output:
            current_process = None
            for line in malfind_output.split('\n'):
                if 'Process:' in line:
                    current_process = line.split('Process:')[1].strip().split()[0]
                elif 'Pid:' in line and current_process:
                    pid = re.search(r'Pid:\s*(\d+)', line)
                    if pid:
                        injections.append({
                            'process': current_process,
                            'pid': pid.group(1)
                        })
        
        if ldrmodules_output:
            for line in ldrmodules_output.split('\n'):
                if 'False' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        unlinked_dlls.append({
                            'pid': parts[0],
                            'dll': parts[-1] if parts else ''
                        })
        
        self.results['malware']['injections'] = injections[:20]
        self.results['malware']['unlinked_dlls'] = unlinked_dlls[:20]
        self.results['malware']['malfind_output'] = malfind_output[:2000] if malfind_output else ''
        
        print(f"\033[92m[+] Found {len(injections)} potential injections\033[0m")
        print(f"\033[92m[+] Found {len(unlinked_dlls)} unlinked DLLs\033[0m")
    
    def extract_credentials(self):
        print(f"\033[93m[*] Extracting credentials...\033[0m")
        
        hashdump_output = self.execute_volatility('hashdump')
        cachedump_output = self.execute_volatility('cachedump')
        lsadump_output = self.execute_volatility('lsadump')
        
        hashes = []
        
        if hashdump_output:
            for line in hashdump_output.split('\n'):
                if ':' in line and len(line) > 20:
                    parts = line.split(':')
                    if len(parts) >= 4:
                        hashes.append({
                            'username': parts[0],
                            'rid': parts[1],
                            'lm_hash': parts[2][:20] + '...',
                            'ntlm_hash': parts[3][:20] + '...'
                        })
        
        self.results['credentials']['hashes'] = hashes
        self.results['credentials']['cached'] = cachedump_output[:500] if cachedump_output else ''
        self.results['credentials']['lsa'] = lsadump_output[:500] if lsadump_output else ''
        
        print(f"\033[92m[+] Extracted {len(hashes)} password hashes\033[0m")
    
    def analyze_registry(self):
        print(f"\033[93m[*] Analyzing registry...\033[0m")
        
        hivelist_output = self.execute_volatility('hivelist')
        
        hives = []
        
        if hivelist_output:
            for line in hivelist_output.split('\n')[2:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        hives.append({
                            'virtual_addr': parts[0],
                            'name': ' '.join(parts[1:])
                        })
        
        self.results['registry']['hives'] = hives
        
        print(f"\033[92m[+] Found {len(hives)} registry hives\033[0m")
    
    def scan_files(self):
        print(f"\033[93m[*] Scanning file objects...\033[0m")
        
        filescan_output = self.execute_volatility('filescan')
        
        files = []
        suspicious_files = []
        
        suspicious_keywords = [
            'tmp', 'temp', 'appdata', 'startup', 'run', 'download',
            'desktop', 'recent', 'cache', 'cookie'
        ]
        
        if filescan_output:
            for line in filescan_output.split('\n')[2:]:
                if line.strip():
                    parts = line.split(None, 2)
                    if len(parts) >= 3:
                        file_path = parts[2]
                        files.append(file_path)
                        
                        if any(keyword in file_path.lower() for keyword in suspicious_keywords):
                            suspicious_files.append(file_path)
        
        self.results['files']['total_count'] = len(files)
        self.results['files']['suspicious'] = suspicious_files[:50]
        
        print(f"\033[92m[+] Found {len(files)} file objects\033[0m")
        print(f"\033[92m[+] Found {len(suspicious_files)} suspicious files\033[0m")
    
    def extract_command_history(self):
        print(f"\033[93m[*] Extracting command history...\033[0m")
        
        cmdline_output = self.execute_volatility('cmdline')
        cmdscan_output = self.execute_volatility('cmdscan')
        consoles_output = self.execute_volatility('consoles')
        
        commands = []
        
        if cmdline_output:
            for line in cmdline_output.split('\n'):
                if line.strip() and not line.startswith('*'):
                    commands.append(line.strip())
        
        self.results['commands']['cmdline'] = commands[:50]
        self.results['commands']['console'] = consoles_output[:1000] if consoles_output else ''
        
        print(f"\033[92m[+] Extracted {len(commands)} command lines\033[0m")
    
    def create_timeline(self):
        print(f"\033[93m[*] Creating forensic timeline...\033[0m")
        
        timeliner_output = self.execute_volatility('timeliner', '--output=body')
        
        if timeliner_output:
            timeline_file = os.path.join(self.output_dir, 'timeline.txt')
            
            os.makedirs(self.output_dir, exist_ok=True)
            
            with open(timeline_file, 'w') as f:
                f.write(timeliner_output)
            
            print(f"\033[92m[+] Timeline saved: {timeline_file}\033[0m")
    
    def dump_process_memory(self, pid):
        print(f"\033[93m[*] Dumping process memory for PID {pid}...\033[0m")
        
        os.makedirs(self.output_dir, exist_ok=True)
        
        output_file = os.path.join(self.output_dir, f'process_{pid}.dmp')
        
        self.execute_volatility('memdump', f'-p {pid} --dump-dir={self.output_dir}')
        
        if os.path.exists(output_file):
            print(f"\033[92m[+] Process dumped: {output_file}\033[0m")
        else:
            print(f"\033[91m[!] Failed to dump process\033[0m")
    
    def extract_artifacts(self):
        print(f"\033[93m[*] Extracting browser artifacts...\033[0m")
        
        iehistory_output = self.execute_volatility('iehistory')
        clipboard_output = self.execute_volatility('clipboard')
        
        self.results['artifacts']['iehistory'] = iehistory_output[:1000] if iehistory_output else ''
        self.results['artifacts']['clipboard'] = clipboard_output[:500] if clipboard_output else ''
        
        print(f"\033[92m[+] Artifacts extracted\033[0m")
    
    def run_full_analysis(self):
        print(f"\033[93m[*] Starting full memory analysis...\033[0m\n")
        
        os.makedirs(self.output_dir, exist_ok=True)
        
        if not self.identify_profile():
            return
        
        self.analyze_processes()
        self.analyze_network()
        self.detect_malware()
        self.extract_credentials()
        self.analyze_registry()
        self.scan_files()
        self.extract_command_history()
        self.extract_artifacts()
        
        self.generate_report()
    
    def generate_report(self):
        report_file = os.path.join(self.output_dir, 'volatility_report.json')
        
        report = {
            'memory_dump': self.memory_dump,
            'dump_hash': self.hash_file(self.memory_dump),
            'analysis_date': datetime.now().isoformat(),
            'profile': self.profile,
            'summary': {
                'processes': len(self.results['processes'].get('running', [])),
                'hidden_processes': len(self.results['processes'].get('hidden', [])),
                'network_connections': len(self.results['network'].get('connections', [])),
                'malware_injections': len(self.results['malware'].get('injections', [])),
                'unlinked_dlls': len(self.results['malware'].get('unlinked_dlls', [])),
                'password_hashes': len(self.results['credentials'].get('hashes', [])),
                'registry_hives': len(self.results['registry'].get('hives', [])),
                'suspicious_files': len(self.results['files'].get('suspicious', []))
            },
            'details': dict(self.results)
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n\033[92m[+] Report saved: {report_file}\033[0m")
        
        text_report = os.path.join(self.output_dir, 'volatility_report.txt')
        
        with open(text_report, 'w') as f:
            f.write("="*80 + "\n")
            f.write("VOLATILITY MEMORY FORENSICS ANALYSIS REPORT\n")
            f.write("="*80 + "\n\n")
            f.write(f"Memory Dump: {self.memory_dump}\n")
            f.write(f"Profile: {self.profile}\n")
            f.write(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("="*80 + "\n")
            f.write("SUMMARY\n")
            f.write("="*80 + "\n")
            for key, value in report['summary'].items():
                f.write(f"{key.replace('_', ' ').title()}: {value}\n")
            
            f.write("\n" + "="*80 + "\n")
            f.write("HIDDEN PROCESSES\n")
            f.write("="*80 + "\n")
            for proc in self.results['processes'].get('hidden', []):
                f.write(f"  {proc['name']} (PID: {proc['pid']})\n")
            
            f.write("\n" + "="*80 + "\n")
            f.write("MALWARE INDICATORS\n")
            f.write("="*80 + "\n")
            for inj in self.results['malware'].get('injections', [])[:10]:
                f.write(f"  {inj['process']} (PID: {inj['pid']})\n")
        
        print(f"\033[92m[+] Text report saved: {text_report}\033[0m")
    
    def hash_file(self, file_path):
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        
        return sha256.hexdigest()

def run():
    print("\033[92m" + "="*70)
    print("     VOLATILITY AUTOMATION WRAPPER")
    print("="*70 + "\033[0m\n")
    
    memory_dump = input("\033[95m[?] Enter memory dump path: \033[0m").strip()
    
    if not os.path.exists(memory_dump):
        print(f"\033[91m[!] File not found\033[0m")
        return
    
    volatility = VolatilityAutomation(memory_dump)
    
    print("\n\033[97mAnalysis Options:\033[0m")
    print("\033[97m  [1] Full automated analysis\033[0m")
    print("\033[97m  [2] Identify profile only\033[0m")
    print("\033[97m  [3] Analyze processes\033[0m")
    print("\033[97m  [4] Analyze network\033[0m")
    print("\033[97m  [5] Detect malware\033[0m")
    print("\033[97m  [6] Extract credentials\033[0m")
    print("\033[97m  [7] Dump specific process\033[0m")
    
    choice = input(f"\n\033[95m[?] Select option: \033[0m").strip()
    
    if choice == '1':
        volatility.run_full_analysis()
    
    elif choice == '2':
        volatility.identify_profile()
    
    elif choice == '3':
        if volatility.identify_profile():
            volatility.analyze_processes()
            volatility.generate_report()
    
    elif choice == '4':
        if volatility.identify_profile():
            volatility.analyze_network()
            volatility.generate_report()
    
    elif choice == '5':
        if volatility.identify_profile():
            volatility.detect_malware()
            volatility.generate_report()
    
    elif choice == '6':
        if volatility.identify_profile():
            volatility.extract_credentials()
            volatility.generate_report()
    
    elif choice == '7':
        if volatility.identify_profile():
            pid = input("\033[95m[?] Enter PID: \033[0m").strip()
            volatility.dump_process_memory(pid)
    
    print(f"\n\033[92m[+] Analysis complete\033[0m")

if __name__ == "__main__":
    run()
