#!/usr/bin/env python3
import os
import subprocess
import json
import zipfile
import hashlib
import xml.etree.ElementTree as ET
import re
from collections import defaultdict
from datetime import datetime

class APKAnalyzer:
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.apk_name = os.path.basename(apk_path)
        self.work_dir = f"apk_analysis_{int(datetime.now().timestamp())}"
        self.results = defaultdict(list)
        
        self.dangerous_permissions = [
            'READ_CONTACTS', 'WRITE_CONTACTS', 'READ_CALENDAR', 'WRITE_CALENDAR',
            'SEND_SMS', 'RECEIVE_SMS', 'READ_SMS', 'RECEIVE_MMS',
            'READ_CALL_LOG', 'WRITE_CALL_LOG', 'CALL_PHONE', 'READ_PHONE_STATE',
            'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION', 'ACCESS_BACKGROUND_LOCATION',
            'CAMERA', 'RECORD_AUDIO', 'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE',
            'BODY_SENSORS', 'GET_ACCOUNTS', 'BLUETOOTH_SCAN', 'BLUETOOTH_CONNECT'
        ]
        
        self.vuln_patterns = {
            'hardcoded_secrets': [
                r'api[_-]?key[\s]*=[\s]*["\']([a-zA-Z0-9_\-]{20,})["\']',
                r'secret[\s]*=[\s]*["\']([a-zA-Z0-9_\-]{20,})["\']',
                r'password[\s]*=[\s]*["\']([^"\']{8,})["\']',
                r'token[\s]*=[\s]*["\']([a-zA-Z0-9_\-]{20,})["\']',
                r'aws[_-]?access[_-]?key[\s]*=[\s]*["\']([A-Z0-9]{20})["\']',
                r'private[_-]?key[\s]*=[\s]*["\']([^"\']{40,})["\']'
            ],
            'urls': [
                r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+',
                r'ws://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+',
                r'ftp://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+'
            ],
            'crypto_misuse': [
                r'DES["\']',
                r'MD5["\']',
                r'SHA1["\']',
                r'ECB["\']',
                r'Random\(\)',
                r'KeyGenerator\.getInstance\(["\']DES["\']',
                r'Cipher\.getInstance\(["\'].*ECB.*["\']'
            ],
            'webview_issues': [
                r'setJavaScriptEnabled\(true\)',
                r'addJavascriptInterface',
                r'setAllowFileAccess\(true\)',
                r'setAllowContentAccess\(true\)',
                r'setAllowUniversalAccessFromFileURLs\(true\)'
            ],
            'debug_flags': [
                r'android:debuggable[\s]*=[\s]*["\']true["\']',
                r'android:allowBackup[\s]*=[\s]*["\']true["\']',
                r'Log\.[dveiwDVEIW]\(',
                r'System\.out\.print',
                r'\.printStackTrace\(\)'
            ],
            'sql_injection': [
                r'execSQL\([^)]*\+',
                r'rawQuery\([^)]*\+',
                r'query\([^)]*\+[^)]*\)',
                r'SELECT.*WHERE.*=[\s]*["\'][\s]*\+',
                r'INSERT.*VALUES.*\+'
            ],
            'intent_issues': [
                r'setAction\(null\)',
                r'Intent\([^\)]*null[^\)]*\)',
                r'getIntent\(\)\.get[A-Z]',
                r'setComponent\(new ComponentName'
            ]
        }
    
    def extract_apk(self):
        os.makedirs(self.work_dir, exist_ok=True)
        
        print(f"\033[93m[*] Extracting APK...\033[0m")
        
        with zipfile.ZipFile(self.apk_path, 'r') as zip_ref:
            zip_ref.extractall(self.work_dir)
        
        print(f"\033[92m[+] Extracted to {self.work_dir}\033[0m")
    
    def parse_manifest(self):
        manifest_path = os.path.join(self.work_dir, 'AndroidManifest.xml')
        
        if not os.path.exists(manifest_path):
            self.results['manifest']['error'] = 'Manifest not found'
            return
        
        print(f"\033[93m[*] Parsing manifest...\033[0m")
        
        try:
            result = subprocess.run(['aapt', 'dump', 'badging', self.apk_path],
                                  capture_output=True, text=True, timeout=30)
            
            manifest_data = {}
            
            for line in result.stdout.split('\n'):
                if line.startswith('package:'):
                    package_match = re.search(r"name='([^']+)'", line)
                    version_match = re.search(r"versionCode='([^']+)'", line)
                    version_name_match = re.search(r"versionName='([^']+)'", line)
                    
                    if package_match:
                        manifest_data['package'] = package_match.group(1)
                    if version_match:
                        manifest_data['version_code'] = version_match.group(1)
                    if version_name_match:
                        manifest_data['version_name'] = version_name_match.group(1)
                
                elif line.startswith('sdkVersion:'):
                    sdk_match = re.search(r"'([^']+)'", line)
                    if sdk_match:
                        manifest_data['min_sdk'] = sdk_match.group(1)
                
                elif line.startswith('targetSdkVersion:'):
                    target_match = re.search(r"'([^']+)'", line)
                    if target_match:
                        manifest_data['target_sdk'] = target_match.group(1)
                
                elif line.startswith('uses-permission:'):
                    perm_match = re.search(r"name='([^']+)'", line)
                    if perm_match:
                        perm = perm_match.group(1).split('.')[-1]
                        manifest_data.setdefault('permissions', []).append(perm)
            
            self.results['manifest'] = manifest_data
            
            print(f"\033[92m[+] Package: {manifest_data.get('package', 'Unknown')}\033[0m")
            print(f"\033[92m[+] Version: {manifest_data.get('version_name', 'Unknown')}\033[0m")
            print(f"\033[92m[+] Permissions: {len(manifest_data.get('permissions', []))}\033[0m")
            
        except Exception as e:
            self.results['manifest']['error'] = str(e)
    
    def analyze_permissions(self):
        permissions = self.results.get('manifest', {}).get('permissions', [])
        
        dangerous = []
        for perm in permissions:
            for danger_perm in self.dangerous_permissions:
                if danger_perm in perm:
                    dangerous.append(perm)
        
        self.results['dangerous_permissions'] = dangerous
        
        print(f"\033[93m[*] Dangerous permissions: {len(dangerous)}\033[0m")
        for perm in dangerous:
            print(f"\033[91m  [!] {perm}\033[0m")
    
    def decompile_dex(self):
        dex_files = [f for f in os.listdir(self.work_dir) if f.endswith('.dex')]
        
        if not dex_files:
            return
        
        print(f"\033[93m[*] Found {len(dex_files)} DEX files\033[0m")
        
        smali_dir = os.path.join(self.work_dir, 'smali')
        os.makedirs(smali_dir, exist_ok=True)
        
        try:
            for dex in dex_files:
                dex_path = os.path.join(self.work_dir, dex)
                
                subprocess.run(['d2j-dex2jar', dex_path, '-o', dex_path.replace('.dex', '.jar')],
                             capture_output=True, timeout=60)
        except:
            pass
    
    def scan_code_patterns(self):
        print(f"\033[93m[*] Scanning for vulnerabilities...\033[0m")
        
        java_files = []
        for root, dirs, files in os.walk(self.work_dir):
            for file in files:
                if file.endswith(('.java', '.smali', '.xml')):
                    java_files.append(os.path.join(root, file))
        
        for file_path in java_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                for vuln_type, patterns in self.vuln_patterns.items():
                    for pattern in patterns:
                        matches = re.finditer(pattern, content, re.IGNORECASE)
                        
                        for match in matches:
                            rel_path = os.path.relpath(file_path, self.work_dir)
                            
                            self.results['vulnerabilities'].append({
                                'type': vuln_type,
                                'file': rel_path,
                                'match': match.group(0)[:100]
                            })
            except:
                pass
        
        vuln_count = len(self.results['vulnerabilities'])
        print(f"\033[92m[+] Found {vuln_count} potential issues\033[0m")
        
        vuln_types = defaultdict(int)
        for vuln in self.results['vulnerabilities']:
            vuln_types[vuln['type']] += 1
        
        for vuln_type, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True):
            print(f"\033[97m  {vuln_type}: {count}\033[0m")
    
    def extract_strings(self):
        print(f"\033[93m[*] Extracting strings...\033[0m")
        
        strings_data = {
            'urls': [],
            'emails': [],
            'ips': [],
            'base64': []
        }
        
        for root, dirs, files in os.walk(self.work_dir):
            for file in files:
                if file.endswith(('.xml', '.json', '.txt', '.smali')):
                    file_path = os.path.join(root, file)
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        urls = re.findall(r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+', content)
                        strings_data['urls'].extend(urls)
                        
                        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', content)
                        strings_data['emails'].extend(emails)
                        
                        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content)
                        strings_data['ips'].extend(ips)
                        
                        base64_matches = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', content)
                        strings_data['base64'].extend(base64_matches[:10])
                        
                    except:
                        pass
        
        strings_data['urls'] = list(set(strings_data['urls']))
        strings_data['emails'] = list(set(strings_data['emails']))
        strings_data['ips'] = list(set(strings_data['ips']))
        
        self.results['strings'] = strings_data
        
        print(f"\033[92m[+] URLs: {len(strings_data['urls'])}\033[0m")
        print(f"\033[92m[+] Emails: {len(strings_data['emails'])}\033[0m")
        print(f"\033[92m[+] IPs: {len(strings_data['ips'])}\033[0m")
    
    def analyze_native_libs(self):
        lib_dir = os.path.join(self.work_dir, 'lib')
        
        if not os.path.exists(lib_dir):
            return
        
        print(f"\033[93m[*] Analyzing native libraries...\033[0m")
        
        libs = []
        for root, dirs, files in os.walk(lib_dir):
            for file in files:
                if file.endswith('.so'):
                    lib_path = os.path.join(root, file)
                    
                    lib_info = {
                        'name': file,
                        'arch': os.path.basename(root),
                        'size': os.path.getsize(lib_path),
                        'hash': self.hash_file(lib_path)
                    }
                    
                    try:
                        result = subprocess.run(['strings', lib_path], 
                                              capture_output=True, text=True, timeout=10)
                        
                        interesting = []
                        for line in result.stdout.split('\n'):
                            if any(k in line.lower() for k in ['password', 'secret', 'key', 'token', 'api']):
                                interesting.append(line)
                        
                        lib_info['interesting_strings'] = interesting[:10]
                    except:
                        pass
                    
                    libs.append(lib_info)
        
        self.results['native_libraries'] = libs
        print(f"\033[92m[+] Found {len(libs)} native libraries\033[0m")
    
    def check_obfuscation(self):
        print(f"\033[93m[*] Checking obfuscation...\033[0m")
        
        obf_indicators = {
            'proguard': False,
            'dexguard': False,
            'r8': False,
            'class_name_obf': 0,
            'method_name_obf': 0
        }
        
        for root, dirs, files in os.walk(self.work_dir):
            for file in files:
                if file.endswith('.smali'):
                    try:
                        with open(os.path.join(root, file), 'r', errors='ignore') as f:
                            content = f.read()
                        
                        if re.search(r'\.class\s+[Ll][a-z]{1,2};', content):
                            obf_indicators['class_name_obf'] += 1
                        
                        if re.search(r'\.method\s+[a-z]{1,2}\(', content):
                            obf_indicators['method_name_obf'] += 1
                        
                        if 'proguard' in content.lower():
                            obf_indicators['proguard'] = True
                        if 'dexguard' in content.lower():
                            obf_indicators['dexguard'] = True
                        
                    except:
                        pass
        
        self.results['obfuscation'] = obf_indicators
        
        if obf_indicators['proguard']:
            print(f"\033[92m[+] ProGuard detected\033[0m")
        if obf_indicators['dexguard']:
            print(f"\033[92m[+] DexGuard detected\033[0m")
        if obf_indicators['class_name_obf'] > 10:
            print(f"\033[92m[+] Obfuscated class names: {obf_indicators['class_name_obf']}\033[0m")
    
    def generate_report(self):
        report_file = f"apk_analysis_report_{int(datetime.now().timestamp())}.json"
        
        report = {
            'apk_name': self.apk_name,
            'apk_hash': self.hash_file(self.apk_path),
            'analysis_date': datetime.now().isoformat(),
            'manifest': self.results.get('manifest', {}),
            'dangerous_permissions': self.results.get('dangerous_permissions', []),
            'vulnerabilities': self.results.get('vulnerabilities', []),
            'strings': self.results.get('strings', {}),
            'native_libraries': self.results.get('native_libraries', []),
            'obfuscation': self.results.get('obfuscation', {})
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n\033[92m[+] Report saved: {report_file}\033[0m")
        
        return report
    
    def hash_file(self, file_path):
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        
        return sha256.hexdigest()

def run():
    print("\033[92m" + "="*70)
    print("     APK DECOMPILATION & ANALYSIS TOOL")
    print("="*70 + "\033[0m\n")
    
    apk_path = input("\033[95m[?] Enter APK file path: \033[0m").strip()
    
    if not os.path.exists(apk_path):
        print(f"\033[91m[!] File not found\033[0m")
        return
    
    analyzer = APKAnalyzer(apk_path)
    
    analyzer.extract_apk()
    analyzer.parse_manifest()
    analyzer.analyze_permissions()
    analyzer.decompile_dex()
    analyzer.scan_code_patterns()
    analyzer.extract_strings()
    analyzer.analyze_native_libs()
    analyzer.check_obfuscation()
    
    report = analyzer.generate_report()
    
    print(f"\n\033[92m[+] Analysis complete\033[0m")

if __name__ == "__main__":
    run()
