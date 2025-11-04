#!/usr/bin/env python3
"""
Advanced Admin Interface Discovery Tool
Professional-grade offensive security tool for finding hidden admin panels
Features: Smart detection, fingerprinting, response analysis, wordlist support
"""

import requests
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
import time
import urllib3
import re
import json
import hashlib
from collections import defaultdict

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Realistic User-Agent to avoid detection
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
]

def run():
    print("\033[92m" + "="*70)
    print("       ADVANCED ADMIN INTERFACE DISCOVERY TOOL")
    print("="*70 + "\033[0m\n")
    
    print("\033[93m[!] WARNING: Only scan sites you own or have permission to test!\033[0m\n")
    
    # Extended and categorized admin paths
    ADMIN_PATHS = {
        'generic': [
            'admin', 'admin/', 'administrator', 'administrator/', 'administration',
            'admins', 'admins/', 'admin1', 'admin2', 'admin3', 'admin4', 'admin5',
            'adminarea', 'admin-area', 'admin_area', 'admincontrol', 'admin-control',
            'admincp', 'admin-cp', 'adminpanel', 'admin-panel', 'admin_panel',
            'adm', 'adm/', 'adminhome', 'admin_home', 'administracion', 'amministrazione',
            'administrateur', 'administrador', 'admin-console', 'admin_console'
        ],
        'login': [
            'login', 'login/', 'login.php', 'login.html', 'login.asp', 'login.aspx',
            'signin', 'sign-in', 'signin/', 'signin.php', 'sign_in', 'user/login',
            'users/login', 'account/login', 'auth', 'auth/', 'authenticate', 'authentication',
            'sso', 'session', 'session/new', 'oauth/authorize', 'saml/login',
            'admin/login', 'admin/signin', 'adminlogin', 'admin-login', 'admin_login',
            'user-login', 'userlogin', 'member-login', 'memberlogin', 'wp-login.php'
        ],
        'dashboard': [
            'dashboard', 'dashboard/', 'dashboard.php', 'panel', 'panel/', 'panel.php',
            'controlpanel', 'control-panel', 'control_panel', 'cp', 'cpanel', 'cPanel',
            'admin/dashboard', 'admin/panel', 'admin/controlpanel', 'admin/cp',
            'console', 'console/', 'webconsole', 'overview', 'home', 'portal'
        ],
        'cms': [
            # WordPress
            'wp-admin', 'wp-admin/', 'wp-login.php', 'wordpress/wp-admin', 'blog/wp-admin',
            'wp/wp-admin', 'wordpress/', 'wp-content/', 'wp-includes/',
            # Joomla
            'joomla/administrator', 'administrator/', 'administrator/index.php',
            'joomla/', 'components/', 'modules/',
            # Drupal
            'drupal/', 'drupal/admin', 'user/login', 'node/add', '?q=admin',
            # Others
            'typo3/', 'typo3/index.php', 'modx/', 'modx/manager', 'concrete5/',
            'umbraco/', 'umbraco/login', 'ghost/', 'ghost/ghost', 'admin.php'
        ],
        'database': [
            'phpmyadmin', 'phpMyAdmin', 'pma', 'PMA', 'myadmin', 'MyAdmin',
            'mysql', 'mysql/', 'mysqladmin', 'sql', 'db', 'database', 'dbadmin',
            'phppgadmin', 'phpPgAdmin', 'pgadmin', 'postgres', 'mongodb', 'mongo',
            'adminer', 'adminer.php', 'db_admin', 'database_admin', 'sqlmanager'
        ],
        'user_mgmt': [
            'user', 'users', 'user/', 'users/', 'user.php', 'users.php',
            'useradmin', 'user-admin', 'user_admin', 'usermanagement', 'userpanel',
            'account', 'accounts', 'account/', 'accounts/', 'myaccount', 'my-account',
            'profile', 'profiles', 'member', 'members', 'membership', 'moderator',
            'manage', 'management', 'manager', 'usermanager', 'accountmanager'
        ],
        'backend': [
            'backend', 'backend/', 'back-end', 'backend.php', 'backoffice', 'back-office',
            'sys', 'system', 'system/', 'sysadmin', 'sys-admin', 'systemadmin',
            'root', 'root/', 'root.php', 'superuser', 'supervisor', 'webadmin',
            'web-admin', 'web_admin', 'webmaster', 'master', 'intranet', 'internal'
        ],
        'api': [
            'api', 'api/', 'api/v1', 'api/v2', 'api/v3', 'api/admin', 'api/login',
            'rest', 'rest/', 'graphql', 'graphql/', 'swagger', 'swagger/',
            'api-docs', 'api/docs', 'docs', 'documentation', 'api/swagger',
            'v1/admin', 'v2/admin', 'api/auth', 'api/users', 'api/config'
        ],
        'config': [
            'config', 'config/', 'configuration', 'settings', 'preferences', 'options',
            'setup', 'install', 'installation', 'admin/config', 'admin/settings',
            'admin/setup', 'configure', 'siteadmin', 'site-admin', 'environment',
            'env', '.env', 'phpinfo.php', 'info.php', 'server-status', 'server-info'
        ],
        'framework': [
            # Laravel
            'laravel/admin', 'admin/laravel', 'horizon', 'horizon/dashboard', 'telescope',
            # Django
            'django/admin', 'admin/django', 'djadmin', '__debug__',
            # Rails
            'rails/admin', 'admin/rails', 'sidekiq', 'delayed_job',
            # Spring
            'spring/admin', 'actuator', 'actuator/health', 'actuator/env',
            # Others
            'symfony/admin', 'yii/admin', 'codeigniter/admin', 'zend/admin',
            'cake/admin', 'flask/admin', 'express/admin', 'nestjs/admin'
        ],
        'hidden': [
            'hidden', 'secret', 'private', 'restricted', 'secure', 'security',
            '_admin', '__admin', 'admin_', 'admin__', '.admin', 'admin.', '~admin',
            'backup', 'backups', 'old', 'temp', 'tmp', 'test', 'demo', 'dev',
            'development', 'staging', 'stage', 'beta', 'alpha', 'internal',
            '_private', '__private', '.private', 'confidential', 'classified'
        ],
        'filemanager': [
            'filemanager', 'file-manager', 'files', 'fileadmin', 'fm', 'elfinder',
            'ckfinder', 'filebrowser', 'browse', 'upload', 'uploads', 'uploader',
            'media', 'mediamanager', 'assets', 'content', 'downloads', 'attachments'
        ]
    }
    
    # Configuration
    target_url = input("\033[97m[?] Enter target URL (e.g., http://example.com): \033[0m").strip()
    if not target_url:
        print("\033[91m[!] No URL provided.\033[0m")
        return
    
    # Normalize URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    target_url = target_url.rstrip('/')
    
    # Scan mode selection
    print("\n\033[96m[?] Scan Mode:\033[0m")
    print("  [1] Quick Scan (Generic + Login + Dashboard)")
    print("  [2] Full Scan (All categories)")
    print("  [3] CMS Focused (CMS + Database)")
    print("  [4] Framework Focused (API + Framework)")
    print("  [5] Deep Scan (Everything + File variations)")
    
    mode = input("\033[97m[?] Select mode (1-5, default 2): \033[0m").strip()
    
    # Build path list based on mode
    paths_to_scan = []
    if mode == '1':
        paths_to_scan = ADMIN_PATHS['generic'] + ADMIN_PATHS['login'] + ADMIN_PATHS['dashboard']
    elif mode == '3':
        paths_to_scan = ADMIN_PATHS['cms'] + ADMIN_PATHS['database'] + ADMIN_PATHS['generic']
    elif mode == '4':
        paths_to_scan = ADMIN_PATHS['api'] + ADMIN_PATHS['framework'] + ADMIN_PATHS['backend']
    elif mode == '5':
        # Deep scan with file extensions
        for category in ADMIN_PATHS.values():
            paths_to_scan.extend(category)
        # Add file variations
        extensions = ['.php', '.asp', '.aspx', '.jsp', '.html', '.htm', '.do', '.action']
        base_paths = paths_to_scan.copy()
        for path in base_paths:
            if '.' not in path.split('/')[-1]:  # Only add extensions to paths without them
                for ext in extensions:
                    paths_to_scan.append(path.rstrip('/') + ext)
    else:  # mode == '2' or default
        for category in ADMIN_PATHS.values():
            paths_to_scan.extend(category)
    
    # Remove duplicates
    paths_to_scan = list(set(paths_to_scan))
    
    # Advanced options
    threads = input("\033[97m[?] Number of threads (default 50): \033[0m").strip()
    threads = int(threads) if threads.isdigit() and int(threads) > 0 else 50
    
    timeout = input("\033[97m[?] Request timeout in seconds (default 5): \033[0m").strip()
    timeout = int(timeout) if timeout.isdigit() and int(timeout) > 0 else 5
    
    follow_redirects = input("\033[97m[?] Follow redirects? (y/n, default y): \033[0m").strip().lower()
    follow_redirects = follow_redirects != 'n'
    
    smart_filter = input("\033[97m[?] Enable smart filtering (reduce false positives)? (y/n, default y): \033[0m").strip().lower()
    smart_filter = smart_filter != 'n'
    
    print(f"\n\033[92m[*] Starting Advanced Admin Panel Discovery...\033[0m")
    print(f"\033[97m[*] Target: {target_url}\033[0m")
    print(f"\033[97m[*] Paths to test: {len(paths_to_scan)}\033[0m")
    print(f"\033[97m[*] Threads: {threads}\033[0m")
    print(f"\033[97m[*] Timeout: {timeout}s\033[0m")
    print(f"\033[97m[*] Smart Filtering: {'Enabled' if smart_filter else 'Disabled'}\033[0m\n")
    
    found_panels = []
    tested = [0]
    errors = [0]
    lock = threading.Lock()
    response_hashes = set()  # Track response hashes to detect false positives
    
    def get_response_hash(content):
        """Generate hash of response content for duplicate detection"""
        return hashlib.md5(content.encode('utf-8', errors='ignore')).hexdigest()
    
    def extract_title(html):
        """Extract page title from HTML"""
        match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if match:
            title = match.group(1).strip()
            # Clean up title
            title = re.sub(r'\s+', ' ', title)
            return title[:100]
        return None
    
    def extract_forms(html):
        """Extract login forms from HTML"""
        forms = []
        form_pattern = r'<form[^>]*>(.*?)</form>'
        matches = re.finditer(form_pattern, html, re.IGNORECASE | re.DOTALL)
        
        for match in matches:
            form_content = match.group(1).lower()
            # Check if it's a login form
            if any(indicator in form_content for indicator in ['password', 'username', 'email', 'login', 'signin']):
                # Extract action
                action_match = re.search(r'action=["\']([^"\']+)["\']', match.group(0), re.IGNORECASE)
                action = action_match.group(1) if action_match else 'N/A'
                
                # Count input fields
                inputs = len(re.findall(r'<input', form_content, re.IGNORECASE))
                
                forms.append({
                    'action': action,
                    'inputs': inputs,
                    'has_password': 'password' in form_content,
                    'has_username': 'username' in form_content or 'email' in form_content
                })
        
        return forms
    
    def analyze_headers(headers):
        """Analyze response headers for fingerprinting"""
        info = {}
        
        # Server detection
        server = headers.get('Server', headers.get('server', ''))
        if server:
            info['server'] = server
        
        # Framework detection
        framework_headers = {
            'X-Powered-By': 'powered_by',
            'X-AspNet-Version': 'aspnet_version',
            'X-Framework': 'framework',
            'X-Generator': 'generator'
        }
        
        for header, key in framework_headers.items():
            value = headers.get(header, headers.get(header.lower(), ''))
            if value:
                info[key] = value
        
        # Security headers
        if 'X-Frame-Options' in headers or 'x-frame-options' in headers:
            info['has_security_headers'] = True
        
        # Cookie analysis
        set_cookie = headers.get('Set-Cookie', headers.get('set-cookie', ''))
        if set_cookie:
            if 'session' in set_cookie.lower() or 'auth' in set_cookie.lower():
                info['sets_session'] = True
        
        return info
    
    def calculate_confidence(response, url, html_content):
        """Calculate confidence score for admin panel detection"""
        score = 0
        reasons = []
        
        # Status code analysis
        if response.status_code == 200:
            score += 20
            reasons.append("HTTP 200")
        elif response.status_code in [401, 403]:
            score += 30
            reasons.append(f"Protected ({response.status_code})")
        elif response.status_code in [301, 302, 303, 307, 308]:
            location = response.headers.get('Location', '').lower()
            if any(word in location for word in ['login', 'signin', 'auth', 'admin']):
                score += 25
                reasons.append("Auth redirect")
        
        # Content analysis (only for 200 responses)
        if response.status_code == 200 and html_content:
            content_lower = html_content.lower()
            
            # High-value keywords
            high_value = ['dashboard', 'control panel', 'administrator', 'admin panel',
                         'welcome admin', 'admin login', 'management console']
            found_high = [kw for kw in high_value if kw in content_lower]
            score += len(found_high) * 10
            if found_high:
                reasons.append(f"Keywords: {', '.join(found_high[:2])}")
            
            # Form analysis
            forms = extract_forms(html_content)
            login_forms = [f for f in forms if f['has_password']]
            if login_forms:
                score += 15
                reasons.append(f"{len(login_forms)} login form(s)")
            
            # Title analysis
            title = extract_title(html_content)
            if title:
                title_lower = title.lower()
                if any(word in title_lower for word in ['admin', 'login', 'dashboard', 'panel', 'control']):
                    score += 15
                    reasons.append(f"Title: {title[:30]}")
            
            # Input field detection
            password_fields = len(re.findall(r'type=["\']password["\']', content_lower))
            if password_fields > 0:
                score += 10
                reasons.append(f"{password_fields} password field(s)")
            
            # Framework detection
            frameworks = {
                'wordpress': r'wp-content|wp-includes|wordpress',
                'joomla': r'joomla|com_content|option=com_',
                'drupal': r'drupal|sites/all|sites/default',
                'phpmyadmin': r'phpmyadmin|pma_|server_databases',
                'cpanel': r'cpanel|whm|webhost manager'
            }
            
            for fw_name, fw_pattern in frameworks.items():
                if re.search(fw_pattern, content_lower):
                    score += 20
                    reasons.append(f"Framework: {fw_name}")
                    break
        
        # Header analysis
        header_info = analyze_headers(response.headers)
        if header_info.get('sets_session'):
            score += 10
            reasons.append("Sets session")
        
        # URL pattern analysis
        url_lower = url.lower()
        admin_patterns = ['admin', 'login', 'auth', 'panel', 'dashboard', 'manage']
        if any(pattern in url_lower for pattern in admin_patterns):
            score += 5
        
        # Cap score at 100
        score = min(score, 100)
        
        return score, reasons
    
    def test_admin_path(path):
        """Test if admin path exists with advanced analysis"""
        try:
            url = urljoin(target_url, path)
            
            # Random user agent to avoid detection
            import random
            headers = {
                'User-Agent': random.choice(USER_AGENTS),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'close'
            }
            
            response = requests.get(
                url,
                timeout=timeout,
                verify=False,
                allow_redirects=follow_redirects,
                headers=headers
            )
            
            with lock:
                tested[0] += 1
                if tested[0] % 25 == 0:
                    print(f"\r\033[97m[*] Progress: {tested[0]}/{len(paths_to_scan)} | Found: {len(found_panels)} | Errors: {errors[0]}\033[0m", end='', flush=True)
            
            # Get response content
            html_content = None
            try:
                html_content = response.text
            except:
                html_content = response.content.decode('utf-8', errors='ignore')
            
            # Calculate confidence score
            confidence, reasons = calculate_confidence(response, url, html_content)
            
            # Smart filtering - skip if confidence too low
            if smart_filter and confidence < 15:
                return False
            
            # Check for duplicate responses (same content = error page)
            if smart_filter and response.status_code == 200 and html_content:
                content_hash = get_response_hash(html_content[:1000])  # Hash first 1KB
                
                with lock:
                    if content_hash in response_hashes and confidence < 40:
                        # Likely duplicate error page
                        return False
                    response_hashes.add(content_hash)
            
            # Determine if this is a valid find
            is_valid = False
            panel_type = 'unknown'
            
            if response.status_code in [200, 401, 403]:
                is_valid = True
                if response.status_code == 200:
                    panel_type = 'accessible'
                else:
                    panel_type = 'protected'
            elif response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '').lower()
                if any(word in location for word in ['login', 'signin', 'auth', 'admin']):
                    is_valid = True
                    panel_type = 'redirect'
            
            if is_valid:
                # Extract detailed information
                title = extract_title(html_content) if html_content else None
                forms = extract_forms(html_content) if html_content else []
                headers_info = analyze_headers(response.headers)
                
                panel_info = {
                    'url': url,
                    'status': response.status_code,
                    'type': panel_type,
                    'confidence': confidence,
                    'reasons': reasons,
                    'title': title,
                    'forms': len(forms),
                    'login_forms': len([f for f in forms if f['has_password']]),
                    'server': headers_info.get('server'),
                    'powered_by': headers_info.get('powered_by'),
                    'size': len(response.content),
                    'redirect': response.headers.get('Location') if panel_type == 'redirect' else None
                }
                
                with lock:
                    found_panels.append(panel_info)
                
                # Color-coded output based on confidence
                if confidence >= 70:
                    color = '\033[92m'  # Green - high confidence
                    prefix = '[+++]'
                elif confidence >= 40:
                    color = '\033[93m'  # Yellow - medium confidence
                    prefix = '[++]'
                else:
                    color = '\033[96m'  # Cyan - low confidence
                    prefix = '[+]'
                
                print(f"\n{color}{prefix} {url} [{response.status_code}] - Confidence: {confidence}%\033[0m")
                if reasons:
                    print(f"      \033[97m{' | '.join(reasons[:3])}\033[0m")
                
                return True
            
            return False
            
        except requests.exceptions.Timeout:
            with lock:
                errors[0] += 1
            return False
        except requests.exceptions.ConnectionError:
            with lock:
                errors[0] += 1
            return False
        except Exception as e:
            with lock:
                errors[0] += 1
            return False
    
    # Execute scan
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(test_admin_path, path): path for path in paths_to_scan}
        
        try:
            for future in as_completed(futures):
                future.result()
        except KeyboardInterrupt:
            print("\n\n\033[93m[!] Scan interrupted by user.\033[0m")
            executor.shutdown(wait=False, cancel_futures=True)
    
    elapsed = time.time() - start_time
    
    print("\n\n")
    
    # Sort results by confidence
    found_panels.sort(key=lambda x: x['confidence'], reverse=True)
    
    # Results summary
    print(f"\033[92m{'='*70}\033[0m")
    print(f"\033[92m[*] Admin Panel Discovery Complete\033[0m")
    print(f"\033[92m{'='*70}\033[0m\n")
    
    if found_panels:
        # Categorize by confidence
        high_conf = [p for p in found_panels if p['confidence'] >= 70]
        med_conf = [p for p in found_panels if 40 <= p['confidence'] < 70]
        low_conf = [p for p in found_panels if p['confidence'] < 40]
        
        print(f"\033[92m[+] Found {len(found_panels)} potential admin panels!\033[0m")
        print(f"\033[97m    High Confidence (70%+): {len(high_conf)}\033[0m")
        print(f"\033[97m    Medium Confidence (40-69%): {len(med_conf)}\033[0m")
        print(f"\033[97m    Low Confidence (<40%): {len(low_conf)}\033[0m\n")
        
        # Display detailed results
        for i, panel in enumerate(found_panels, 1):
            # Color based on confidence
            if panel['confidence'] >= 70:
                color = '\033[92m'  # Green
            elif panel['confidence'] >= 40:
                color = '\033[93m'  # Yellow
            else:
                color = '\033[96m'  # Cyan
            
            print(f"{color}{'='*70}\033[0m")
            print(f"{color}[{i}] {panel['url']}\033[0m")
            print(f"\033[97m    Status Code: {panel['status']}\033[0m")
            print(f"\033[97m    Confidence: {panel['confidence']}% ({panel['type']})\033[0m")
            
            if panel['reasons']:
                print(f"\033[97m    Detection: {' | '.join(panel['reasons'][:5])}\033[0m")
            
            if panel['title']:
                print(f"\033[97m    Page Title: {panel['title']}\033[0m")
            
            if panel.get('forms', 0) > 0:
                print(f"\033[97m    Forms: {panel['forms']} (Login: {panel['login_forms']})\033[0m")
            
            if panel.get('server'):
                print(f"\033[97m    Server: {panel['server']}\033[0m")
            
            if panel.get('powered_by'):
                print(f"\033[97m    Powered By: {panel['powered_by']}\033[0m")
            
            if panel.get('redirect'):
                print(f"\033[97m    Redirects To: {panel['redirect']}\033[0m")
            
            print(f"\033[97m    Response Size: {panel['size']} bytes\033[0m")
            print()
        
        # Save results
        print(f"\n\033[95m[?] Save results to file?\033[0m")
        print("  [1] Text format (.txt)")
        print("  [2] JSON format (.json)")
        print("  [3] Both formats")
        print("  [4] Don't save")
        
        save_choice = input("\033[97m[?] Choose option (1-4, default 4): \033[0m").strip()
        
        if save_choice in ['1', '2', '3']:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            domain = urlparse(target_url).netloc.replace(':', '_')
            
            # Text format
            if save_choice in ['1', '3']:
                txt_filename = f"admin_panels_{domain}_{timestamp}.txt"
                try:
                    with open(txt_filename, 'w', encoding='utf-8') as f:
                        f.write(f"Admin Panel Discovery Results\n")
                        f.write(f"{'='*70}\n")
                        f.write(f"Target: {target_url}\n")
                        f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write(f"Total Found: {len(found_panels)}\n")
                        f.write(f"High Confidence: {len(high_conf)}\n")
                        f.write(f"Medium Confidence: {len(med_conf)}\n")
                        f.write(f"Low Confidence: {len(low_conf)}\n")
                        f.write(f"{'='*70}\n\n")
                        
                        for i, panel in enumerate(found_panels, 1):
                            f.write(f"[{i}] {panel['url']}\n")
                            f.write(f"    Status: {panel['status']} | Confidence: {panel['confidence']}% | Type: {panel['type']}\n")
                            if panel['reasons']:
                                f.write(f"    Detection: {' | '.join(panel['reasons'])}\n")
                            if panel['title']:
                                f.write(f"    Title: {panel['title']}\n")
                            if panel.get('forms', 0) > 0:
                                f.write(f"    Forms: {panel['forms']} (Login: {panel['login_forms']})\n")
                            if panel.get('server'):
                                f.write(f"    Server: {panel['server']}\n")
                            if panel.get('powered_by'):
                                f.write(f"    Powered By: {panel['powered_by']}\n")
                            if panel.get('redirect'):
                                f.write(f"    Redirects To: {panel['redirect']}\n")
                            f.write(f"    Size: {panel['size']} bytes\n")
                            f.write("\n")
                    
                    print(f"\033[92m[+] Results saved to: {txt_filename}\033[0m")
                except Exception as e:
                    print(f"\033[91m[!] Error saving text file: {str(e)}\033[0m")
            
            # JSON format
            if save_choice in ['2', '3']:
                json_filename = f"admin_panels_{domain}_{timestamp}.json"
                try:
                    report = {
                        'target': target_url,
                        'scan_date': time.strftime('%Y-%m-%d %H:%M:%S'),
                        'scan_duration': f"{elapsed:.2f}s",
                        'paths_tested': tested[0],
                        'errors': errors[0],
                        'summary': {
                            'total_found': len(found_panels),
                            'high_confidence': len(high_conf),
                            'medium_confidence': len(med_conf),
                            'low_confidence': len(low_conf)
                        },
                        'results': found_panels
                    }
                    
                    with open(json_filename, 'w', encoding='utf-8') as f:
                        json.dump(report, f, indent=2, ensure_ascii=False)
                    
                    print(f"\033[92m[+] Results saved to: {json_filename}\033[0m")
                except Exception as e:
                    print(f"\033[91m[!] Error saving JSON file: {str(e)}\033[0m")
    
    else:
        print(f"\033[93m[!] No admin panels found.\033[0m")
        print(f"\033[97m[*] This could mean:\033[0m")
        print(f"\033[97m    - The site has no standard admin paths\033[0m")
        print(f"\033[97m    - Admin panel is on a different subdomain\033[0m")
        print(f"\033[97m    - Custom admin path not in wordlist\033[0m")
        print(f"\033[97m    - Rate limiting or WAF blocking requests\033[0m")
    
    # Statistics
    print(f"\n\033[96m{'='*70}\033[0m")
    print(f"\033[96m[*] Scan Statistics\033[0m")
    print(f"\033[96m{'='*70}\033[0m")
    print(f"\033[97m    Paths Tested: {tested[0]}/{len(paths_to_scan)}\033[0m")
    print(f"\033[97m    Errors: {errors[0]}\033[0m")
    print(f"\033[97m    Success Rate: {((tested[0]-errors[0])/tested[0]*100) if tested[0] > 0 else 0:.1f}%\033[0m")
    print(f"\033[97m    Scan Duration: {elapsed:.2f}s\033[0m")
    print(f"\033[97m    Requests/sec: {tested[0]/elapsed:.2f}\033[0m\n")

if __name__ == "__main__":
    run()
