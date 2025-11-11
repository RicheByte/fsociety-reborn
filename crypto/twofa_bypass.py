#!/usr/bin/env python3
import os
import time
import hmac
import hashlib
import struct
import json
import base64
from datetime import datetime
from collections import defaultdict

class TwoFABypass:
    def __init__(self):
        self.output_dir = f"2fa_test_{int(datetime.now().timestamp())}"
        self.results = defaultdict(list)
        
    def generate_totp(self, secret, time_step=30, digits=6, hash_algo='sha1'):
        try:
            secret = secret.replace(' ', '').upper()
            
            secret_bytes = base64.b32decode(secret + '=' * ((8 - len(secret) % 8) % 8))
            
            counter = int(time.time()) // time_step
            
            counter_bytes = struct.pack('>Q', counter)
            
            if hash_algo == 'sha1':
                hmac_hash = hmac.new(secret_bytes, counter_bytes, hashlib.sha1).digest()
            elif hash_algo == 'sha256':
                hmac_hash = hmac.new(secret_bytes, counter_bytes, hashlib.sha256).digest()
            elif hash_algo == 'sha512':
                hmac_hash = hmac.new(secret_bytes, counter_bytes, hashlib.sha512).digest()
            else:
                hmac_hash = hmac.new(secret_bytes, counter_bytes, hashlib.sha1).digest()
            
            offset = hmac_hash[-1] & 0x0F
            
            truncated = struct.unpack('>I', hmac_hash[offset:offset+4])[0] & 0x7FFFFFFF
            
            otp = truncated % (10 ** digits)
            
            return str(otp).zfill(digits)
        
        except Exception as e:
            print(f"\033[91m[!] Error generating TOTP: {e}\033[0m")
            return None
    
    def generate_hotp(self, secret, counter, digits=6):
        try:
            secret = secret.replace(' ', '').upper()
            
            secret_bytes = base64.b32decode(secret + '=' * ((8 - len(secret) % 8) % 8))
            
            counter_bytes = struct.pack('>Q', counter)
            
            hmac_hash = hmac.new(secret_bytes, counter_bytes, hashlib.sha1).digest()
            
            offset = hmac_hash[-1] & 0x0F
            
            truncated = struct.unpack('>I', hmac_hash[offset:offset+4])[0] & 0x7FFFFFFF
            
            otp = truncated % (10 ** digits)
            
            return str(otp).zfill(digits)
        
        except Exception as e:
            print(f"\033[91m[!] Error generating HOTP: {e}\033[0m")
            return None
    
    def brute_force_backup_codes(self, test_function, code_length=8, charset='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
        print(f"\033[93m[*] Brute forcing backup codes ({code_length} chars)...\033[0m")
        
        valid_codes = []
        attempts = 0
        max_attempts = 10000
        
        import itertools
        
        for attempt in itertools.product(charset, repeat=code_length):
            code = ''.join(attempt)
            attempts += 1
            
            if test_function(code):
                print(f"\033[92m[+] Valid code found: {code}\033[0m")
                valid_codes.append(code)
            
            if attempts >= max_attempts:
                break
            
            if attempts % 1000 == 0:
                print(f"\033[93m[*] Tested {attempts} codes...\033[0m")
        
        self.results['backup_codes'] = valid_codes
        
        print(f"\033[92m[+] Found {len(valid_codes)} valid backup codes\033[0m")
        
        return valid_codes
    
    def test_code_reuse(self, code, test_function, attempts=5):
        print(f"\033[93m[*] Testing code reuse for: {code}\033[0m")
        
        results = []
        
        for i in range(attempts):
            print(f"\033[93m[*] Attempt {i+1}/{attempts}\033[0m")
            
            result = test_function(code)
            results.append(result)
            
            if result:
                print(f"\033[92m[+] Code still valid\033[0m")
            else:
                print(f"\033[91m[-] Code invalid\033[0m")
            
            time.sleep(2)
        
        reuse_count = sum(results)
        
        if reuse_count > 1:
            print(f"\033[92m[+] Code reuse detected: {reuse_count} times\033[0m")
            self.results['code_reuse'].append({
                'code': code,
                'reuse_count': reuse_count
            })
            return True
        else:
            print(f"\033[91m[-] No code reuse detected\033[0m")
            return False
    
    def test_rate_limiting(self, test_function, codes, delay=0):
        print(f"\033[93m[*] Testing rate limiting...\033[0m")
        
        successful = 0
        blocked = 0
        
        for i, code in enumerate(codes, 1):
            print(f"\033[93m[*] Testing code {i}/{len(codes)}: {code}\033[0m")
            
            try:
                result = test_function(code)
                
                if result:
                    successful += 1
                    print(f"\033[92m[+] Code accepted\033[0m")
                else:
                    print(f"\033[91m[-] Code rejected\033[0m")
            
            except Exception as e:
                blocked += 1
                print(f"\033[91m[!] Request blocked: {e}\033[0m")
            
            if delay > 0:
                time.sleep(delay)
        
        if blocked == 0:
            print(f"\033[92m[+] No rate limiting detected\033[0m")
            self.results['rate_limiting'] = 'None'
        else:
            print(f"\033[91m[!] Rate limiting detected: {blocked}/{len(codes)} blocked\033[0m")
            self.results['rate_limiting'] = f"{blocked}/{len(codes)}"
        
        return blocked == 0
    
    def test_timing_attack(self, test_function, valid_code):
        print(f"\033[93m[*] Testing timing attack vulnerability...\033[0m")
        
        timings = []
        
        test_codes = [
            valid_code,
            valid_code[:-1] + '0',
            valid_code[:-2] + '00',
            '000000',
            '123456'
        ]
        
        for code in test_codes:
            times = []
            
            for _ in range(10):
                start = time.time()
                test_function(code)
                elapsed = time.time() - start
                times.append(elapsed)
                
                time.sleep(0.5)
            
            avg_time = sum(times) / len(times)
            timings.append((code, avg_time))
            
            print(f"\033[97m  {code}: {avg_time:.4f}s\033[0m")
        
        timings.sort(key=lambda x: x[1], reverse=True)
        
        if timings[0][1] - timings[-1][1] > 0.1:
            print(f"\033[92m[+] Timing attack possible (variance: {timings[0][1] - timings[-1][1]:.4f}s)\033[0m")
            self.results['timing_attack'] = 'Vulnerable'
            return True
        else:
            print(f"\033[91m[-] Timing attack unlikely\033[0m")
            self.results['timing_attack'] = 'Not vulnerable'
            return False
    
    def test_session_fixation(self, session_manager, username, password):
        print(f"\033[93m[*] Testing session fixation...\033[0m")
        
        session_before = session_manager.get_session()
        
        print(f"\033[97m  Session before login: {session_before}\033[0m")
        
        session_manager.login(username, password)
        
        session_after = session_manager.get_session()
        
        print(f"\033[97m  Session after login: {session_after}\033[0m")
        
        if session_before == session_after:
            print(f"\033[92m[+] Session fixation possible\033[0m")
            self.results['session_fixation'] = 'Vulnerable'
            return True
        else:
            print(f"\033[91m[-] Session regenerated correctly\033[0m")
            self.results['session_fixation'] = 'Not vulnerable'
            return False
    
    def test_mfa_fatigue(self, push_function, attempts=50):
        print(f"\033[93m[*] Testing MFA fatigue attack ({attempts} attempts)...\033[0m")
        
        approved = 0
        
        for i in range(attempts):
            print(f"\033[93m[*] Push notification {i+1}/{attempts}\033[0m")
            
            result = push_function()
            
            if result:
                approved += 1
                print(f"\033[92m[+] Approved\033[0m")
                break
            else:
                print(f"\033[91m[-] Denied\033[0m")
            
            time.sleep(10)
        
        if approved > 0:
            print(f"\033[92m[+] MFA fatigue successful after {i+1} attempts\033[0m")
            self.results['mfa_fatigue'] = f"Success after {i+1} attempts"
            return True
        else:
            print(f"\033[91m[-] MFA fatigue failed\033[0m")
            self.results['mfa_fatigue'] = 'Failed'
            return False
    
    def test_sms_interception(self, phone_number):
        print(f"\033[93m[*] Simulating SMS interception for: {phone_number}\033[0m")
        
        techniques = [
            'SS7 exploitation',
            'SIM swapping',
            'IMSI catcher',
            'Mobile malware',
            'Social engineering'
        ]
        
        print(f"\033[97m  Available techniques:\033[0m")
        for i, technique in enumerate(techniques, 1):
            print(f"\033[97m    {i}. {technique}\033[0m")
        
        self.results['sms_interception'] = {
            'target': phone_number,
            'techniques': techniques,
            'risk_level': 'High'
        }
        
        return techniques
    
    def test_qr_code_extraction(self, qr_image_path):
        print(f"\033[93m[*] Extracting TOTP secret from QR code...\033[0m")
        
        try:
            from PIL import Image
            import qrcode
            
            img = Image.open(qr_image_path)
            
            from pyzbar.pyzbar import decode
            
            decoded = decode(img)
            
            if decoded:
                data = decoded[0].data.decode('utf-8')
                
                print(f"\033[92m[+] QR code data: {data}\033[0m")
                
                if 'otpauth://' in data:
                    parts = data.split('?')
                    
                    if len(parts) > 1:
                        params = {}
                        
                        for param in parts[1].split('&'):
                            key, value = param.split('=')
                            params[key] = value
                        
                        if 'secret' in params:
                            secret = params['secret']
                            
                            print(f"\033[92m[+] Extracted secret: {secret}\033[0m")
                            
                            self.results['qr_extraction'] = {
                                'secret': secret,
                                'issuer': params.get('issuer', 'Unknown')
                            }
                            
                            return secret
                
                return data
            else:
                print(f"\033[91m[!] No QR code found\033[0m")
                return None
        
        except ImportError:
            print(f"\033[91m[!] Required libraries not installed (PIL, pyzbar)\033[0m")
            return None
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return None
    
    def test_backup_code_enumeration(self, test_function, format_pattern='[A-Z0-9]{8}'):
        print(f"\033[93m[*] Testing backup code enumeration...\033[0m")
        
        common_patterns = [
            '00000000', '11111111', '12345678', 'AAAAAAAA',
            'ABCD1234', '00000001', '99999999', 'ZZZZZZZZ'
        ]
        
        valid_codes = []
        
        for code in common_patterns:
            print(f"\033[93m[*] Testing: {code}\033[0m")
            
            if test_function(code):
                print(f"\033[92m[+] Valid code: {code}\033[0m")
                valid_codes.append(code)
            else:
                print(f"\033[91m[-] Invalid: {code}\033[0m")
        
        self.results['code_enumeration'] = valid_codes
        
        return valid_codes
    
    def test_oauth_token_theft(self, oauth_flow):
        print(f"\033[93m[*] Testing OAuth token theft vulnerabilities...\033[0m")
        
        vulnerabilities = []
        
        if not oauth_flow.get('state'):
            print(f"\033[92m[+] Missing state parameter (CSRF vulnerable)\033[0m")
            vulnerabilities.append('Missing state parameter')
        
        if oauth_flow.get('response_type') == 'token':
            print(f"\033[92m[+] Implicit flow (token in URL fragment)\033[0m")
            vulnerabilities.append('Implicit flow')
        
        if not oauth_flow.get('redirect_uri_validation'):
            print(f"\033[92m[+] Weak redirect URI validation\033[0m")
            vulnerabilities.append('Weak redirect URI')
        
        self.results['oauth_vulnerabilities'] = vulnerabilities
        
        return vulnerabilities
    
    def generate_totp_codes_batch(self, secret, count=10):
        print(f"\033[93m[*] Generating {count} TOTP codes...\033[0m")
        
        codes = []
        
        for i in range(count):
            code = self.generate_totp(secret)
            
            if code:
                codes.append(code)
                print(f"\033[97m  {i+1}. {code}\033[0m")
                
                time.sleep(30)
        
        return codes
    
    def generate_report(self):
        os.makedirs(self.output_dir, exist_ok=True)
        
        report_file = os.path.join(self.output_dir, '2fa_test_report.json')
        
        report = {
            'test_date': datetime.now().isoformat(),
            'output_directory': self.output_dir,
            'results': dict(self.results)
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n\033[92m[+] Report saved: {report_file}\033[0m")

def run():
    print("\033[92m" + "="*70)
    print("     2FA BYPASS TESTER")
    print("="*70 + "\033[0m\n")
    
    twofa = TwoFABypass()
    
    print("\033[97m2FA Testing Options:\033[0m")
    print("\033[97m  [1] Generate TOTP code\033[0m")
    print("\033[97m  [2] Generate HOTP code\033[0m")
    print("\033[97m  [3] Generate TOTP batch\033[0m")
    print("\033[97m  [4] Test code reuse\033[0m")
    print("\033[97m  [5] Test rate limiting\033[0m")
    print("\033[97m  [6] Extract QR code secret\033[0m")
    print("\033[97m  [7] SMS interception info\033[0m")
    
    choice = input(f"\n\033[95m[?] Select option: \033[0m").strip()
    
    if choice == '1':
        secret = input("\033[95m[?] TOTP secret: \033[0m").strip()
        
        code = twofa.generate_totp(secret)
        
        if code:
            print(f"\n\033[92m[+] TOTP Code: {code}\033[0m")
            print(f"\033[97m  (Valid for ~30 seconds)\033[0m")
    
    elif choice == '2':
        secret = input("\033[95m[?] HOTP secret: \033[0m").strip()
        counter = int(input("\033[95m[?] Counter value: \033[0m").strip())
        
        code = twofa.generate_hotp(secret, counter)
        
        if code:
            print(f"\n\033[92m[+] HOTP Code: {code}\033[0m")
    
    elif choice == '3':
        secret = input("\033[95m[?] TOTP secret: \033[0m").strip()
        count = int(input("\033[95m[?] Number of codes: \033[0m").strip())
        
        codes = twofa.generate_totp_codes_batch(secret, count)
        
        print(f"\n\033[92m[+] Generated {len(codes)} codes\033[0m")
    
    elif choice == '4':
        code = input("\033[95m[?] Code to test: \033[0m").strip()
        attempts = int(input("\033[95m[?] Number of attempts: \033[0m").strip())
        
        def mock_test(c):
            return True
        
        twofa.test_code_reuse(code, mock_test, attempts)
    
    elif choice == '5':
        test_codes = []
        
        for i in range(5):
            code = input(f"\033[95m[?] Test code {i+1}: \033[0m").strip()
            test_codes.append(code)
        
        def mock_test(c):
            return False
        
        twofa.test_rate_limiting(mock_test, test_codes)
    
    elif choice == '6':
        qr_path = input("\033[95m[?] QR code image path: \033[0m").strip()
        
        secret = twofa.test_qr_code_extraction(qr_path)
        
        if secret:
            print(f"\n\033[92m[+] Testing TOTP generation...\033[0m")
            
            code = twofa.generate_totp(secret)
            
            if code:
                print(f"\033[92m[+] Generated code: {code}\033[0m")
    
    elif choice == '7':
        phone = input("\033[95m[?] Target phone number: \033[0m").strip()
        
        twofa.test_sms_interception(phone)
    
    twofa.generate_report()
    
    print(f"\n\033[92m[+] Done\033[0m")

if __name__ == "__main__":
    run()
