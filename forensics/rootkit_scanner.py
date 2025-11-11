#!/usr/bin/env python3
import os
import subprocess
import json
import hashlib
import struct
from datetime import datetime
from collections import defaultdict

class RootkitScanner:
    def __init__(self):
        self.findings = defaultdict(list)
        self.output_dir = f"rootkit_scan_{int(datetime.now().timestamp())}"
        
        self.suspicious_paths = [
            '/dev/shm',
            '/tmp',
            '/var/tmp',
            '/dev/.hidden',
            '/usr/local/share/.hidden',
            '~/.ssh',
            '~/.config',
            '/lib/modules',
            '/usr/lib',
            '/usr/lib64'
        ]
        
        self.known_rootkits = {
            'azazel': [b'azazel', b'libselinux.so'],
            'diamorphine': [b'diamorphine', b'diamo'],
            'reptile': [b'reptile', b'khook'],
            'suterusu': [b'suterusu'],
            'hiddenwave': [b'hiddenwave'],
            'adore-ng': [b'adore'],
            'enyelkm': [b'enyelkm'],
            'mokes': [b'mokes'],
            'xnuxer': [b'xnuxer']
        }
        
        self.system_calls = [
            'open', 'read', 'write', 'getdents', 'getdents64',
            'kill', 'accept', 'recvfrom', 'stat', 'lstat'
        ]
    
    def check_kernel_modules(self):
        print(f"\033[93m[*] Checking kernel modules...\033[0m")
        
        try:
            result = subprocess.run(['lsmod'], capture_output=True, text=True, timeout=10)
            
            modules = []
            
            for line in result.stdout.split('\n')[1:]:
                if line.strip():
                    parts = line.split()
                    if parts:
                        module_name = parts[0]
                        size = parts[1] if len(parts) > 1 else '0'
                        used_by = parts[2] if len(parts) > 2 else '0'
                        
                        modules.append({
                            'name': module_name,
                            'size': size,
                            'used_by': used_by
                        })
                        
                        if any(rootkit in module_name.lower() for rootkit in self.known_rootkits.keys()):
                            self.findings['kernel_modules'].append({
                                'module': module_name,
                                'reason': 'Known rootkit name pattern'
                            })
                            print(f"\033[91m[!] Suspicious module: {module_name}\033[0m")
            
            hidden_modules = self.detect_hidden_modules()
            
            if hidden_modules:
                self.findings['hidden_modules'] = hidden_modules
            
            print(f"\033[92m[+] Scanned {len(modules)} kernel modules\033[0m")
            
            return modules
        
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return []
    
    def detect_hidden_modules(self):
        print(f"\033[93m[*] Detecting hidden kernel modules...\033[0m")
        
        hidden = []
        
        try:
            lsmod_result = subprocess.run(['lsmod'], capture_output=True, text=True, timeout=10)
            lsmod_modules = set()
            
            for line in lsmod_result.stdout.split('\n')[1:]:
                if line.strip():
                    parts = line.split()
                    if parts:
                        lsmod_modules.add(parts[0])
            
            if os.path.exists('/sys/module'):
                sys_modules = set(os.listdir('/sys/module'))
                
                hidden_mods = sys_modules - lsmod_modules
                
                for mod in hidden_mods:
                    if not mod.startswith('.'):
                        hidden.append(mod)
                        print(f"\033[91m[!] Hidden module detected: {mod}\033[0m")
            
        except Exception as e:
            pass
        
        return hidden
    
    def check_system_call_table(self):
        print(f"\033[93m[*] Checking system call table...\033[0m")
        
        try:
            if os.path.exists('/proc/kallsyms'):
                with open('/proc/kallsyms', 'r') as f:
                    kallsyms = f.read()
                
                sys_call_table_addr = None
                
                for line in kallsyms.split('\n'):
                    if 'sys_call_table' in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            sys_call_table_addr = parts[0]
                            print(f"\033[97m[*] sys_call_table at: 0x{sys_call_table_addr}\033[0m")
                            break
                
                hooked_calls = []
                
                for syscall in self.system_calls:
                    for line in kallsyms.split('\n'):
                        if f'sys_{syscall}' in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                addr = parts[0]
                                name = parts[2]
                                
                                if 'hook' in name.lower() or 'fake' in name.lower():
                                    hooked_calls.append({
                                        'syscall': syscall,
                                        'address': addr,
                                        'name': name
                                    })
                                    print(f"\033[91m[!] Possible hooked syscall: {name}\033[0m")
                
                if hooked_calls:
                    self.findings['hooked_syscalls'] = hooked_calls
                
                print(f"\033[92m[+] System call table check complete\033[0m")
            
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
    
    def check_process_hiding(self):
        print(f"\033[93m[*] Checking for hidden processes...\033[0m")
        
        try:
            ps_result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=10)
            ps_pids = set()
            
            for line in ps_result.stdout.split('\n')[1:]:
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        pid = int(parts[1])
                        ps_pids.add(pid)
                    except:
                        pass
            
            proc_pids = set()
            
            for entry in os.listdir('/proc'):
                if entry.isdigit():
                    proc_pids.add(int(entry))
            
            hidden_pids = proc_pids - ps_pids
            
            if hidden_pids:
                for pid in hidden_pids:
                    try:
                        cmdline_path = f'/proc/{pid}/cmdline'
                        if os.path.exists(cmdline_path):
                            with open(cmdline_path, 'r') as f:
                                cmdline = f.read().replace('\x00', ' ')
                            
                            self.findings['hidden_processes'].append({
                                'pid': pid,
                                'cmdline': cmdline[:200]
                            })
                            
                            print(f"\033[91m[!] Hidden process: PID {pid} - {cmdline[:50]}\033[0m")
                    except:
                        pass
            
            print(f"\033[92m[+] Found {len(hidden_pids)} hidden processes\033[0m")
        
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
    
    def check_file_hiding(self):
        print(f"\033[93m[*] Checking for hidden files...\033[0m")
        
        suspicious_files = []
        
        for path in self.suspicious_paths:
            expanded_path = os.path.expanduser(path)
            
            if os.path.exists(expanded_path):
                try:
                    for root, dirs, files in os.walk(expanded_path):
                        for file in files:
                            if file.startswith('.'):
                                file_path = os.path.join(root, file)
                                
                                try:
                                    stat_info = os.stat(file_path)
                                    
                                    if stat_info.st_size == 0 or stat_info.st_size > 10 * 1024 * 1024:
                                        suspicious_files.append({
                                            'path': file_path,
                                            'size': stat_info.st_size,
                                            'reason': 'Unusual size'
                                        })
                                except:
                                    pass
                        
                        if len(suspicious_files) > 100:
                            break
                
                except Exception as e:
                    pass
        
        if suspicious_files:
            self.findings['suspicious_files'] = suspicious_files[:50]
            print(f"\033[92m[+] Found {len(suspicious_files)} suspicious files\033[0m")
        else:
            print(f"\033[97m[*] No suspicious hidden files found\033[0m")
    
    def check_network_hiding(self):
        print(f"\033[93m[*] Checking for hidden network connections...\033[0m")
        
        try:
            netstat_result = subprocess.run(['netstat', '-anp'], capture_output=True, text=True, timeout=10)
            netstat_connections = set()
            
            for line in netstat_result.stdout.split('\n'):
                if 'ESTABLISHED' in line or 'LISTEN' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        local_addr = parts[3]
                        netstat_connections.add(local_addr)
            
            if os.path.exists('/proc/net/tcp'):
                with open('/proc/net/tcp', 'r') as f:
                    tcp_lines = f.readlines()[1:]
                
                proc_connections = set()
                
                for line in tcp_lines:
                    parts = line.split()
                    if len(parts) >= 2:
                        local_addr = parts[1]
                        proc_connections.add(local_addr)
                
                hidden_connections = proc_connections - netstat_connections
                
                if hidden_connections:
                    for conn in list(hidden_connections)[:20]:
                        self.findings['hidden_connections'].append(conn)
                        print(f"\033[91m[!] Hidden connection: {conn}\033[0m")
                    
                    print(f"\033[92m[+] Found {len(hidden_connections)} hidden connections\033[0m")
                else:
                    print(f"\033[97m[*] No hidden connections found\033[0m")
        
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
    
    def check_library_preloading(self):
        print(f"\033[93m[*] Checking LD_PRELOAD and library hijacking...\033[0m")
        
        preload_files = [
            '/etc/ld.so.preload',
            '~/.ld.so.preload'
        ]
        
        for preload_path in preload_files:
            expanded_path = os.path.expanduser(preload_path)
            
            if os.path.exists(expanded_path):
                try:
                    with open(expanded_path, 'r') as f:
                        content = f.read()
                    
                    if content.strip():
                        self.findings['ld_preload'].append({
                            'file': expanded_path,
                            'content': content[:500]
                        })
                        
                        print(f"\033[91m[!] LD_PRELOAD configured: {expanded_path}\033[0m")
                        print(f"\033[91m    Content: {content[:100]}\033[0m")
                except:
                    pass
        
        if os.getenv('LD_PRELOAD'):
            self.findings['ld_preload_env'] = os.getenv('LD_PRELOAD')
            print(f"\033[91m[!] LD_PRELOAD environment variable set\033[0m")
        
        print(f"\033[92m[+] Library preload check complete\033[0m")
    
    def scan_memory_signatures(self):
        print(f"\033[93m[*] Scanning memory for rootkit signatures...\033[0m")
        
        detected_rootkits = []
        
        try:
            for rootkit_name, signatures in self.known_rootkits.items():
                for signature in signatures:
                    try:
                        result = subprocess.run(
                            ['grep', '-r', signature.decode('utf-8', errors='ignore'), '/proc/'],
                            capture_output=True,
                            text=True,
                            timeout=30
                        )
                        
                        if result.returncode == 0 and result.stdout:
                            detected_rootkits.append({
                                'name': rootkit_name,
                                'signature': signature.decode('utf-8', errors='ignore'),
                                'matches': result.stdout[:200]
                            })
                            
                            print(f"\033[91m[!] Rootkit signature detected: {rootkit_name}\033[0m")
                    except:
                        pass
        
        except Exception as e:
            pass
        
        if detected_rootkits:
            self.findings['rootkit_signatures'] = detected_rootkits
        
        print(f"\033[92m[+] Memory signature scan complete\033[0m")
    
    def check_interrupt_descriptor_table(self):
        print(f"\033[93m[*] Checking Interrupt Descriptor Table (IDT)...\033[0m")
        
        try:
            if os.path.exists('/proc/kallsyms'):
                with open('/proc/kallsyms', 'r') as f:
                    kallsyms = f.read()
                
                idt_entries = []
                
                for line in kallsyms.split('\n'):
                    if 'idt' in line.lower() or 'interrupt' in line.lower():
                        parts = line.split()
                        if len(parts) >= 3:
                            idt_entries.append({
                                'address': parts[0],
                                'type': parts[1],
                                'name': parts[2]
                            })
                
                if idt_entries:
                    suspicious_idt = [e for e in idt_entries if 'hook' in e['name'].lower()]
                    
                    if suspicious_idt:
                        self.findings['idt_hooks'] = suspicious_idt
                        print(f"\033[91m[!] Suspicious IDT entries found\033[0m")
                
                print(f"\033[92m[+] IDT check complete\033[0m")
        
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
    
    def check_kernel_integrity(self):
        print(f"\033[93m[*] Checking kernel integrity...\033[0m")
        
        try:
            if os.path.exists('/boot/System.map'):
                print(f"\033[97m[*] System.map found\033[0m")
            
            if os.path.exists('/proc/kallsyms'):
                with open('/proc/kallsyms', 'r') as f:
                    symbols = f.readlines()
                
                text_symbols = [s for s in symbols if ' T ' in s or ' t ' in s]
                
                print(f"\033[97m[*] Kernel symbols: {len(symbols)}\033[0m")
                print(f"\033[97m[*] Text symbols: {len(text_symbols)}\033[0m")
                
                suspicious_symbols = []
                
                for symbol in text_symbols:
                    if any(keyword in symbol.lower() for keyword in ['hook', 'hide', 'fake', 'backdoor']):
                        suspicious_symbols.append(symbol.strip())
                
                if suspicious_symbols:
                    self.findings['suspicious_symbols'] = suspicious_symbols[:20]
                    print(f"\033[91m[!] Found {len(suspicious_symbols)} suspicious symbols\033[0m")
        
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
    
    def check_boot_integrity(self):
        print(f"\033[93m[*] Checking boot sector integrity...\033[0m")
        
        try:
            result = subprocess.run(['fdisk', '-l'], capture_output=True, text=True, timeout=10)
            
            if result.stdout:
                boot_devices = []
                
                for line in result.stdout.split('\n'):
                    if '/dev/' in line and '*' in line:
                        parts = line.split()
                        if parts:
                            boot_devices.append(parts[0])
                
                self.findings['boot_devices'] = boot_devices
                
                print(f"\033[92m[+] Found {len(boot_devices)} boot devices\033[0m")
        
        except Exception as e:
            pass
    
    def check_cron_backdoors(self):
        print(f"\033[93m[*] Checking for cron backdoors...\033[0m")
        
        cron_paths = [
            '/etc/crontab',
            '/etc/cron.d',
            '/var/spool/cron',
            '/var/spool/cron/crontabs'
        ]
        
        suspicious_crons = []
        
        for cron_path in cron_paths:
            if os.path.exists(cron_path):
                try:
                    if os.path.isfile(cron_path):
                        with open(cron_path, 'r') as f:
                            content = f.read()
                        
                        if any(keyword in content.lower() for keyword in ['nc ', 'netcat', 'bash -i', '/dev/tcp', 'curl ', 'wget ']):
                            suspicious_crons.append({
                                'file': cron_path,
                                'content': content[:200]
                            })
                            print(f"\033[91m[!] Suspicious cron: {cron_path}\033[0m")
                    
                    elif os.path.isdir(cron_path):
                        for file in os.listdir(cron_path):
                            file_path = os.path.join(cron_path, file)
                            try:
                                with open(file_path, 'r') as f:
                                    content = f.read()
                                
                                if any(keyword in content.lower() for keyword in ['nc ', 'netcat', 'bash -i', '/dev/tcp']):
                                    suspicious_crons.append({
                                        'file': file_path,
                                        'content': content[:200]
                                    })
                                    print(f"\033[91m[!] Suspicious cron: {file_path}\033[0m")
                            except:
                                pass
                except:
                    pass
        
        if suspicious_crons:
            self.findings['cron_backdoors'] = suspicious_crons
        
        print(f"\033[92m[+] Cron check complete\033[0m")
    
    def generate_report(self):
        os.makedirs(self.output_dir, exist_ok=True)
        
        report_file = os.path.join(self.output_dir, 'rootkit_scan_report.json')
        
        report = {
            'scan_date': datetime.now().isoformat(),
            'findings_summary': {
                category: len(findings) for category, findings in self.findings.items()
            },
            'detailed_findings': dict(self.findings)
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n\033[92m[+] Report saved: {report_file}\033[0m")
        
        text_report = os.path.join(self.output_dir, 'rootkit_scan_report.txt')
        
        with open(text_report, 'w') as f:
            f.write("="*80 + "\n")
            f.write("ROOTKIT DETECTION SCAN REPORT\n")
            f.write("="*80 + "\n\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("="*80 + "\n")
            f.write("SUMMARY\n")
            f.write("="*80 + "\n")
            for category, count in report['findings_summary'].items():
                f.write(f"{category}: {count}\n")
            
            f.write("\n" + "="*80 + "\n")
            f.write("DETAILED FINDINGS\n")
            f.write("="*80 + "\n")
            
            for category, findings in self.findings.items():
                f.write(f"\n{category.upper()}:\n")
                for finding in findings[:10]:
                    f.write(f"  {finding}\n")
        
        print(f"\033[92m[+] Text report saved: {text_report}\033[0m")

def run():
    print("\033[92m" + "="*70)
    print("     ROOTKIT DETECTION SCANNER")
    print("="*70 + "\033[0m\n")
    
    if os.geteuid() != 0:
        print(f"\033[91m[!] This scanner requires root privileges\033[0m")
        print(f"\033[97m[*] Some checks will be skipped\033[0m\n")
    
    scanner = RootkitScanner()
    
    scanner.check_kernel_modules()
    scanner.check_system_call_table()
    scanner.check_process_hiding()
    scanner.check_file_hiding()
    scanner.check_network_hiding()
    scanner.check_library_preloading()
    scanner.scan_memory_signatures()
    scanner.check_interrupt_descriptor_table()
    scanner.check_kernel_integrity()
    
    scanner.generate_report()
    
    total_findings = sum(len(findings) for findings in scanner.findings.values())
    
    print(f"\n\033[92m[+] Scan complete\033[0m")
    print(f"\033[97m[*] Total findings: {total_findings}\033[0m")
    
    if total_findings > 0:
        print(f"\033[91m[!] Suspicious activity detected - manual investigation recommended\033[0m")
    else:
        print(f"\033[92m[+] No obvious rootkit indicators found\033[0m")

if __name__ == "__main__":
    run()
