#!/usr/bin/env python3
import os
import time
import json
import random
from datetime import datetime
import subprocess
import threading

class AutomatedVishing:
    def __init__(self):
        self.campaigns = []
        self.call_logs = []
        
        self.pretexts = {
            'tech_support': {
                'name': 'Tech Support Scam',
                'script': [
                    "Hello, this is {name} calling from {company} Technical Support.",
                    "We've detected suspicious activity on your account.",
                    "We need to verify your identity to secure your account.",
                    "Can you please confirm your email address?",
                    "And for security purposes, can you verify the last 4 digits of your payment method?",
                    "Thank you. We're now securing your account. You should receive a confirmation email shortly."
                ],
                'vars': ['name', 'company']
            },
            'bank_fraud': {
                'name': 'Bank Fraud Alert',
                'script': [
                    "This is {name} from {bank} Security Department.",
                    "We've detected unusual transactions on your account ending in {account_digits}.",
                    "Did you authorize a transaction of ${amount} to {merchant}?",
                    "For your security, we need to verify your identity.",
                    "Can you please confirm your full account number?",
                    "And the CVV code on the back of your card?",
                    "Thank you. We're placing a fraud alert on your account immediately."
                ],
                'vars': ['name', 'bank', 'account_digits', 'amount', 'merchant']
            },
            'irs_tax': {
                'name': 'IRS Tax Investigation',
                'script': [
                    "This is Agent {badge_number} from the Internal Revenue Service.",
                    "We're calling regarding case number {case_number} filed against you.",
                    "You have outstanding tax debt of ${amount}.",
                    "This is your final notice before legal action is taken.",
                    "To avoid arrest, you need to settle this debt immediately.",
                    "Can you provide a payment method to resolve this matter today?"
                ],
                'vars': ['badge_number', 'case_number', 'amount']
            },
            'delivery_package': {
                'name': 'Package Delivery',
                'script': [
                    "Hello, this is {name} from {courier} delivery service.",
                    "We have a package for you, tracking number {tracking}.",
                    "There's a customs fee of ${amount} that needs to be paid.",
                    "Can you provide payment information to release your package?",
                    "The package will be returned to sender if not claimed within 24 hours."
                ],
                'vars': ['name', 'courier', 'tracking', 'amount']
            },
            'prize_winner': {
                'name': 'Prize Winner Notification',
                'script': [
                    "Congratulations! This is {name} from {company}.",
                    "You've won ${prize_amount} in our {contest_name} sweepstakes!",
                    "To claim your prize, we need to verify your identity.",
                    "Can you confirm your full name and address?",
                    "There's a small processing fee of ${fee} to release the funds.",
                    "How would you like to pay the processing fee today?"
                ],
                'vars': ['name', 'company', 'prize_amount', 'contest_name', 'fee']
            },
            'hr_verification': {
                'name': 'HR Employment Verification',
                'script': [
                    "Hi, this is {name} from Human Resources at {company}.",
                    "We're updating our employee records and need to verify your information.",
                    "Can you confirm your employee ID number?",
                    "And your current home address?",
                    "For payroll purposes, can you verify your bank account details?",
                    "Thank you for your cooperation. Your records have been updated."
                ],
                'vars': ['name', 'company']
            },
            'it_password_reset': {
                'name': 'IT Password Reset',
                'script': [
                    "Hello, this is {name} from IT Support.",
                    "We're performing mandatory password resets for all accounts.",
                    "Your current password will expire in 15 minutes.",
                    "To avoid account lockout, please provide your current password.",
                    "I'll reset it to a temporary password that you can change later.",
                    "What is your current password?"
                ],
                'vars': ['name']
            },
            'microsoft_refund': {
                'name': 'Microsoft/Software Refund',
                'script': [
                    "This is {name} calling from {company} Customer Service.",
                    "You're eligible for a refund of ${amount} for your subscription.",
                    "To process the refund, I need to remote into your computer.",
                    "Can you go to {remote_site} and enter code {remote_code}?",
                    "I see your account. Let me process this refund for you.",
                    "Oh no, we accidentally refunded ${wrong_amount}. We need you to return the difference."
                ],
                'vars': ['name', 'company', 'amount', 'remote_site', 'remote_code', 'wrong_amount']
            }
        }
        
        self.voice_profiles = {
            'male_professional': {'gender': 'male', 'age': '35-45', 'accent': 'neutral'},
            'female_professional': {'gender': 'female', 'age': '30-40', 'accent': 'neutral'},
            'male_authority': {'gender': 'male', 'age': '40-55', 'accent': 'authoritative'},
            'female_friendly': {'gender': 'female', 'age': '25-35', 'accent': 'friendly'}
        }
    
    def generate_variables(self, pretext_name):
        pretext = self.pretexts.get(pretext_name, {})
        vars_needed = pretext.get('vars', [])
        
        auto_vars = {
            'name': random.choice(['John Smith', 'Sarah Johnson', 'Michael Brown', 'Jennifer Davis', 'David Wilson']),
            'company': random.choice(['Microsoft', 'Apple', 'Amazon', 'Google', 'Facebook']),
            'bank': random.choice(['Chase', 'Bank of America', 'Wells Fargo', 'Citibank', 'US Bank']),
            'account_digits': str(random.randint(1000, 9999)),
            'amount': str(random.randint(100, 9999)),
            'merchant': random.choice(['Amazon', 'Walmart', 'Best Buy', 'Target', 'Home Depot']),
            'badge_number': f"{random.randint(100000, 999999)}",
            'case_number': f"IRS-{random.randint(100000, 999999)}",
            'courier': random.choice(['FedEx', 'UPS', 'USPS', 'DHL']),
            'tracking': f"{random.randint(100000000000, 999999999999)}",
            'prize_amount': str(random.randint(5000, 50000)),
            'contest_name': random.choice(['Annual Sweepstakes', 'Customer Appreciation', 'Holiday Giveaway']),
            'fee': str(random.randint(50, 500)),
            'remote_site': random.choice(['anydesk.com', 'teamviewer.com', 'support-access.com']),
            'remote_code': str(random.randint(100000, 999999)),
            'wrong_amount': str(random.randint(10000, 99999))
        }
        
        return {var: auto_vars.get(var, 'Unknown') for var in vars_needed}
    
    def customize_script(self, pretext_name, custom_vars=None):
        if pretext_name not in self.pretexts:
            return None
        
        pretext = self.pretexts[pretext_name]
        script_lines = pretext['script'].copy()
        
        if custom_vars:
            vars_dict = custom_vars
        else:
            vars_dict = self.generate_variables(pretext_name)
        
        customized = []
        for line in script_lines:
            for var, value in vars_dict.items():
                line = line.replace('{' + var + '}', str(value))
            customized.append(line)
        
        return {
            'name': pretext['name'],
            'script': customized,
            'variables': vars_dict
        }
    
    def create_campaign(self, campaign_name, pretext_name, target_list, voice_profile='male_professional'):
        campaign = {
            'id': f"VISH-{random.randint(10000, 99999)}",
            'name': campaign_name,
            'pretext': pretext_name,
            'targets': target_list,
            'voice_profile': voice_profile,
            'created': datetime.now().isoformat(),
            'status': 'pending',
            'calls_made': 0,
            'successful': 0
        }
        
        self.campaigns.append(campaign)
        
        print(f"\033[92m[+] Campaign created: {campaign['id']}\033[0m")
        print(f"\033[97m    Name: {campaign_name}\033[0m")
        print(f"\033[97m    Pretext: {pretext_name}\033[0m")
        print(f"\033[97m    Targets: {len(target_list)}\033[0m")
        
        return campaign
    
    def simulate_call(self, phone, script_data, voice_profile):
        print(f"\n\033[93m[*] Initiating call to {phone}\033[0m")
        time.sleep(1)
        
        print(f"\033[97m[*] Using voice profile: {voice_profile}\033[0m")
        time.sleep(0.5)
        
        print(f"\n\033[96m{'='*60}\033[0m")
        print(f"\033[96mCALL SCRIPT - {script_data['name']}\033[0m")
        print(f"\033[96m{'='*60}\033[0m\n")
        
        for i, line in enumerate(script_data['script'], 1):
            print(f"\033[93m[Agent]: {line}\033[0m")
            time.sleep(2)
            
            if i % 2 == 0:
                responses = [
                    "[Target]: Yes, that's correct.",
                    "[Target]: I'm not sure...",
                    "[Target]: Okay, what do you need?",
                    "[Target]: Can you repeat that?",
                    "[Target]: Let me check..."
                ]
                print(f"\033[97m{random.choice(responses)}\033[0m")
                time.sleep(1.5)
        
        success = random.choice([True, True, True, False])
        
        call_log = {
            'timestamp': datetime.now().isoformat(),
            'phone': phone,
            'pretext': script_data['name'],
            'duration': len(script_data['script']) * 2,
            'success': success,
            'variables': script_data['variables']
        }
        
        self.call_logs.append(call_log)
        
        if success:
            print(f"\n\033[92m[+] Call successful - Target engaged\033[0m")
            print(f"\033[92m[+] Potential data obtained\033[0m")
        else:
            print(f"\n\033[91m[-] Call unsuccessful - Target suspicious\033[0m")
        
        print(f"\033[96m{'='*60}\033[0m\n")
        
        return success
    
    def run_campaign(self, campaign_id):
        campaign = None
        for c in self.campaigns:
            if c['id'] == campaign_id:
                campaign = c
                break
        
        if not campaign:
            print(f"\033[91m[!] Campaign not found\033[0m")
            return
        
        print(f"\033[92m[*] Starting campaign: {campaign['name']}\033[0m")
        
        script_data = self.customize_script(campaign['pretext'])
        
        if not script_data:
            print(f"\033[91m[!] Invalid pretext\033[0m")
            return
        
        for target in campaign['targets']:
            phone = target if isinstance(target, str) else target.get('phone', 'Unknown')
            
            success = self.simulate_call(phone, script_data, campaign['voice_profile'])
            
            campaign['calls_made'] += 1
            if success:
                campaign['successful'] += 1
            
            time.sleep(3)
        
        campaign['status'] = 'completed'
        
        print(f"\n\033[92m[+] Campaign completed\033[0m")
        print(f"\033[97m    Total calls: {campaign['calls_made']}\033[0m")
        print(f"\033[97m    Successful: {campaign['successful']}\033[0m")
        print(f"\033[97m    Success rate: {(campaign['successful']/campaign['calls_made']*100):.1f}%\033[0m")
    
    def generate_report(self, filename='vishing_report.json'):
        report = {
            'campaigns': self.campaigns,
            'call_logs': self.call_logs,
            'total_calls': len(self.call_logs),
            'successful_calls': sum(1 for log in self.call_logs if log['success']),
            'report_generated': datetime.now().isoformat()
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            
            print(f"\033[92m[+] Report saved: {filename}\033[0m")
        
        except Exception as e:
            print(f"\033[91m[!] Report generation failed: {e}\033[0m")
    
    def display_pretexts(self):
        print(f"\n\033[92m{'='*70}\033[0m")
        print(f"\033[92m[*] AVAILABLE PRETEXTS\033[0m")
        print(f"\033[92m{'='*70}\033[0m\n")
        
        for i, (key, pretext) in enumerate(self.pretexts.items(), 1):
            print(f"\033[93m[{i}] {pretext['name']}\033[0m")
            print(f"\033[97m    Key: {key}\033[0m")
            print(f"\033[97m    Variables: {', '.join(pretext['vars'])}\033[0m")
            print()

def run():
    print("\033[92m" + "="*70)
    print("     AUTOMATED VISHING SYSTEM")
    print("="*70 + "\033[0m\n")
    
    vishing = AutomatedVishing()
    
    print("\033[97mOperation mode:\033[0m")
    print("  [1] View pretexts")
    print("  [2] Test pretext script")
    print("  [3] Create campaign")
    print("  [4] Run campaign")
    print("  [5] View campaign stats")
    print("  [6] Generate report")
    
    mode = input("\n\033[95m[?] Select: \033[0m").strip()
    
    if mode == '1':
        vishing.display_pretexts()
    
    elif mode == '2':
        vishing.display_pretexts()
        
        pretext = input("\n\033[95m[?] Pretext key: \033[0m").strip()
        
        custom = input("\033[95m[?] Use custom variables? (y/n): \033[0m").strip().lower()
        
        if custom == 'y':
            if pretext in vishing.pretexts:
                vars_needed = vishing.pretexts[pretext]['vars']
                custom_vars = {}
                
                print(f"\n\033[97m[*] Enter custom values:\033[0m")
                for var in vars_needed:
                    value = input(f"\033[95m[?] {var}: \033[0m").strip()
                    custom_vars[var] = value
                
                script_data = vishing.customize_script(pretext, custom_vars)
            else:
                print(f"\033[91m[!] Invalid pretext\033[0m")
                return
        else:
            script_data = vishing.customize_script(pretext)
        
        if script_data:
            print(f"\n\033[92m[+] Generated script:\033[0m\n")
            for line in script_data['script']:
                print(f"\033[93m{line}\033[0m")
    
    elif mode == '3':
        name = input("\033[95m[?] Campaign name: \033[0m").strip()
        
        vishing.display_pretexts()
        pretext = input("\n\033[95m[?] Pretext key: \033[0m").strip()
        
        print(f"\n\033[97m[*] Enter target phone numbers (one per line, empty to finish):\033[0m")
        targets = []
        while True:
            phone = input("\033[95m> \033[0m").strip()
            if not phone:
                break
            targets.append(phone)
        
        if targets:
            voice = input(f"\n\033[95m[?] Voice profile (male_professional/female_professional/male_authority/female_friendly): \033[0m").strip()
            voice = voice if voice in vishing.voice_profiles else 'male_professional'
            
            vishing.create_campaign(name, pretext, targets, voice)
    
    elif mode == '4':
        if not vishing.campaigns:
            print(f"\033[91m[!] No campaigns created\033[0m")
        else:
            print(f"\n\033[97mAvailable campaigns:\033[0m")
            for campaign in vishing.campaigns:
                status_color = '\033[92m' if campaign['status'] == 'completed' else '\033[93m'
                print(f"\033[97m  {campaign['id']}: {campaign['name']} {status_color}[{campaign['status']}]\033[0m")
            
            campaign_id = input(f"\n\033[95m[?] Campaign ID: \033[0m").strip()
            vishing.run_campaign(campaign_id)
    
    elif mode == '5':
        if not vishing.campaigns:
            print(f"\033[91m[!] No campaigns\033[0m")
        else:
            for campaign in vishing.campaigns:
                print(f"\n\033[92m{campaign['name']} ({campaign['id']})\033[0m")
                print(f"\033[97m  Status: {campaign['status']}\033[0m")
                print(f"\033[97m  Pretext: {campaign['pretext']}\033[0m")
                print(f"\033[97m  Targets: {len(campaign['targets'])}\033[0m")
                print(f"\033[97m  Calls made: {campaign['calls_made']}\033[0m")
                print(f"\033[97m  Successful: {campaign['successful']}\033[0m")
    
    elif mode == '6':
        filename = input("\033[95m[?] Filename (vishing_report.json): \033[0m").strip()
        vishing.generate_report(filename if filename else 'vishing_report.json')
    
    print(f"\n\033[92m[+] Done\033[0m")

if __name__ == "__main__":
    run()
