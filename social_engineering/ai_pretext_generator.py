#!/usr/bin/env python3
import os
import json
import random
from datetime import datetime, timedelta

class AIPretextGenerator:
    def __init__(self):
        self.generated_pretexts = []
        
        self.personalities = {
            'authority': {
                'tone': 'commanding, confident, official',
                'language': 'formal, direct, technical',
                'keywords': ['regulation', 'compliance', 'mandatory', 'immediate', 'violation']
            },
            'friendly': {
                'tone': 'casual, helpful, approachable',
                'language': 'conversational, warm, relatable',
                'keywords': ['help', 'together', 'easy', 'simple', 'happy']
            },
            'urgent': {
                'tone': 'rushed, stressed, time-sensitive',
                'language': 'brief, pressured, critical',
                'keywords': ['urgent', 'deadline', 'immediately', 'critical', 'emergency']
            },
            'technical': {
                'tone': 'analytical, precise, expert',
                'language': 'jargon-heavy, detailed, specific',
                'keywords': ['protocol', 'system', 'configuration', 'authentication', 'database']
            },
            'empathetic': {
                'tone': 'understanding, caring, supportive',
                'language': 'emotional, comforting, patient',
                'keywords': ['understand', 'concern', 'care', 'support', 'help']
            }
        }
        
        self.scenarios = {
            'it_support': {
                'roles': ['IT Administrator', 'Help Desk Technician', 'System Administrator', 'Network Engineer'],
                'objectives': ['password reset', 'account verification', 'system maintenance', 'security update'],
                'backstories': [
                    'We detected suspicious activity on your account and need to verify your identity',
                    'Your system requires an urgent security patch that must be installed immediately',
                    'We\'re performing routine maintenance and need to verify your credentials',
                    'Your account will be locked in 24 hours unless we verify your information'
                ]
            },
            'executive': {
                'roles': ['CEO', 'CFO', 'Vice President', 'Director', 'Senior Manager'],
                'objectives': ['urgent transfer', 'confidential project', 'emergency approval', 'priority task'],
                'backstories': [
                    'I\'m in an important meeting and need you to process this wire transfer immediately',
                    'We have a time-sensitive acquisition and need these documents sent to legal',
                    'I\'m traveling and can\'t access my email - need you to send these files urgently',
                    'Board meeting in 30 minutes - need these financial reports prepared now'
                ]
            },
            'vendor': {
                'roles': ['Account Manager', 'Sales Representative', 'Support Specialist', 'Billing Department'],
                'objectives': ['payment update', 'invoice verification', 'account renewal', 'service upgrade'],
                'backstories': [
                    'Your payment method on file has expired and needs to be updated to avoid service interruption',
                    'We have a special discount available but need to verify your account information',
                    'Your subscription is about to expire - we can offer you a renewal at the current rate if you act now',
                    'There was an error processing your payment and we need updated billing information'
                ]
            },
            'hr': {
                'roles': ['HR Manager', 'Recruiter', 'Benefits Coordinator', 'Payroll Specialist'],
                'objectives': ['employee verification', 'benefits update', 'tax information', 'direct deposit'],
                'backstories': [
                    'We\'re updating our employee database and need you to verify your personal information',
                    'Your benefits enrollment is incomplete - please provide the missing information',
                    'There\'s an issue with your W-4 form that needs to be corrected immediately',
                    'Your direct deposit information appears to be incorrect - please verify your bank details'
                ]
            },
            'legal': {
                'roles': ['Attorney', 'Legal Counsel', 'Paralegal', 'Court Clerk'],
                'objectives': ['legal notice', 'document review', 'compliance issue', 'lawsuit threat'],
                'backstories': [
                    'You\'ve been named in a lawsuit and need to review these documents immediately',
                    'We have a legal notice that requires your immediate attention and response',
                    'There\'s a compliance issue with your account that could result in legal action',
                    'Court documents need to be reviewed and signed by end of business today'
                ]
            },
            'customer_service': {
                'roles': ['Customer Service Rep', 'Account Specialist', 'Support Agent', 'Service Manager'],
                'objectives': ['refund process', 'account issue', 'order problem', 'complaint resolution'],
                'backstories': [
                    'We\'re processing your refund but need to verify your payment information',
                    'There was an error with your recent order and we need to correct your billing information',
                    'Your complaint has been escalated and we need additional information to resolve it',
                    'You\'re eligible for a compensation package due to service issues - we need to verify your account'
                ]
            },
            'security': {
                'roles': ['Security Analyst', 'Incident Responder', 'Fraud Investigator', 'Risk Manager'],
                'objectives': ['breach notification', 'fraud alert', 'security verification', 'account compromise'],
                'backstories': [
                    'We detected unauthorized access to your account from an unknown location',
                    'Your account has been flagged for suspicious activity and needs immediate verification',
                    'We\'re investigating a security breach and need to verify that your account wasn\'t compromised',
                    'Multiple failed login attempts were detected - we need to secure your account immediately'
                ]
            }
        }
        
        self.urgency_amplifiers = [
            'within the next 24 hours',
            'by end of business today',
            'before 5 PM',
            'immediately',
            'as soon as possible',
            'within the hour',
            'before the deadline',
            'to avoid penalties',
            'to prevent account suspension',
            'to maintain compliance'
        ]
        
        self.credibility_builders = [
            'reference number {ref_num}',
            'case ID {case_id}',
            'ticket #{ticket}',
            'confirmation code {confirm}',
            'transaction ID {trans_id}',
            'account number ending in {digits}',
            'as per company policy',
            'according to our records',
            'per recent audit findings',
            'following security protocols'
        ]
        
        self.information_requests = {
            'credentials': ['username', 'password', 'email address', 'account credentials'],
            'financial': ['credit card number', 'bank account', 'routing number', 'payment information'],
            'personal': ['social security number', 'date of birth', 'home address', 'phone number'],
            'corporate': ['employee ID', 'department code', 'manager name', 'project details'],
            'access': ['VPN credentials', 'system access', 'network password', 'security token']
        }
    
    def generate_pretext(self, scenario, personality, target_info=None):
        if scenario not in self.scenarios:
            return None
        
        scenario_data = self.scenarios[scenario]
        personality_data = self.personalities.get(personality, self.personalities['authority'])
        
        role = random.choice(scenario_data['roles'])
        objective = random.choice(scenario_data['objectives'])
        backstory = random.choice(scenario_data['backstories'])
        urgency = random.choice(self.urgency_amplifiers)
        credibility = random.choice(self.credibility_builders)
        
        ref_num = f"{random.randint(100000, 999999)}"
        case_id = f"{random.choice(['CS', 'IT', 'HR', 'FN'])}-{random.randint(1000, 9999)}"
        ticket = str(random.randint(10000, 99999))
        confirm = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=8))
        trans_id = ''.join(random.choices('0123456789ABCDEF', k=16))
        digits = str(random.randint(1000, 9999))
        
        credibility = credibility.format(
            ref_num=ref_num,
            case_id=case_id,
            ticket=ticket,
            confirm=confirm,
            trans_id=trans_id,
            digits=digits
        )
        
        company_name = target_info.get('company', 'your organization') if target_info else 'your organization'
        target_name = target_info.get('name', 'there') if target_info else 'there'
        
        pretext = {
            'id': f"PRETEXT-{random.randint(10000, 99999)}",
            'scenario': scenario,
            'personality': personality,
            'role': role,
            'objective': objective,
            'opening': f"Hello {target_name}, this is {role} from {company_name}.",
            'backstory': backstory,
            'urgency': f"This needs to be resolved {urgency}.",
            'credibility': credibility,
            'tone': personality_data['tone'],
            'keywords': personality_data['keywords'],
            'created': datetime.now().isoformat()
        }
        
        self.generated_pretexts.append(pretext)
        
        return pretext
    
    def create_full_script(self, pretext, info_type='credentials'):
        if not pretext:
            return None
        
        info_requests = self.information_requests.get(info_type, self.information_requests['credentials'])
        info_needed = random.sample(info_requests, min(2, len(info_requests)))
        
        script_lines = [
            pretext['opening'],
            '',
            pretext['backstory'],
            '',
            f"[{pretext['credibility']}]",
            '',
            pretext['urgency'],
            '',
            f"To proceed, I'll need to verify your {info_needed[0]}.",
        ]
        
        if len(info_needed) > 1:
            script_lines.append(f"I'll also need your {info_needed[1]} for our records.")
        
        script_lines.extend([
            '',
            "Can you provide that information now?",
            '',
            "[LISTEN FOR RESPONSE]",
            '',
            "Thank you for your cooperation. This will be processed immediately.",
            '',
            "You should receive confirmation shortly.",
            '',
            "Is there anything else I can help you with today?"
        ])
        
        full_script = {
            'pretext_id': pretext['id'],
            'scenario': pretext['scenario'],
            'role': pretext['role'],
            'script': script_lines,
            'information_targets': info_needed,
            'tone_guidance': f"Deliver in a {pretext['tone']} manner",
            'keywords_to_use': pretext['keywords']
        }
        
        return full_script
    
    def generate_email_pretext(self, pretext):
        if not pretext:
            return None
        
        subject_templates = [
            f"[URGENT] Action Required - {pretext['objective'].title()}",
            f"[ATTENTION] {pretext['role']} - {pretext['objective'].title()}",
            f"Important: {pretext['objective'].title()} - Response Needed",
            f"Time Sensitive: {pretext['objective'].title()}",
            f"ALERT: {pretext['objective'].title()} Required"
        ]
        
        subject = random.choice(subject_templates)
        
        body = f"""Subject: {subject}

{pretext['opening']}

{pretext['backstory']}

{pretext['urgency']}

Reference: {pretext['credibility']}

Please click the link below to complete this process:
[PHISHING LINK HERE]

Alternatively, you can reply to this email with the requested information.

If you have any questions, please contact us immediately at the number below.

Thank you for your prompt attention to this matter.

Best regards,
{pretext['role']}
[Phone: +1-555-{random.randint(100, 999)}-{random.randint(1000, 9999)}]

---
This is an automated message. Please do not reply directly to this email.
"""
        
        email_pretext = {
            'pretext_id': pretext['id'],
            'subject': subject,
            'body': body,
            'sender_role': pretext['role'],
            'urgency_level': 'high' if any(word in pretext['urgency'].lower() for word in ['immediate', 'urgent', 'now']) else 'medium'
        }
        
        return email_pretext
    
    def create_multi_stage_attack(self, initial_scenario, followup_scenario):
        stage1 = self.generate_pretext(initial_scenario, 'friendly')
        stage2 = self.generate_pretext(followup_scenario, 'urgent')
        
        if not stage1 or not stage2:
            return None
        
        attack_plan = {
            'attack_id': f"MULTI-{random.randint(10000, 99999)}",
            'stage1': {
                'pretext': stage1,
                'objective': 'Build trust and establish relationship',
                'timing': 'Day 1',
                'success_metrics': ['Positive response', 'Information shared', 'Relationship established']
            },
            'stage2': {
                'pretext': stage2,
                'objective': 'Leverage trust to obtain sensitive information',
                'timing': 'Day 2-3',
                'success_metrics': ['Credentials obtained', 'Access granted', 'Sensitive data collected']
            },
            'notes': [
                'Wait 24-48 hours between stages',
                'Reference previous conversation in stage 2',
                'Increase urgency and authority in stage 2',
                'Use different communication channels if possible'
            ]
        }
        
        return attack_plan
    
    def adapt_pretext_to_target(self, base_pretext, target_profile):
        adapted = base_pretext.copy()
        
        if 'industry' in target_profile:
            industry = target_profile['industry']
            industry_terms = {
                'finance': ['compliance', 'audit', 'regulatory', 'SEC', 'financial controls'],
                'healthcare': ['HIPAA', 'patient records', 'medical compliance', 'privacy'],
                'technology': ['security patch', 'vulnerability', 'system update', 'network'],
                'retail': ['POS system', 'inventory', 'customer data', 'payment processing']
            }
            
            if industry in industry_terms:
                adapted['backstory'] += f" This is related to {random.choice(industry_terms[industry])}."
        
        if 'position' in target_profile:
            position = target_profile['position'].lower()
            if 'manager' in position or 'director' in position:
                adapted['opening'] = adapted['opening'].replace('Hello', 'Good morning/afternoon')
                adapted['tone'] = 'respectful, professional, acknowledging authority'
        
        if 'timezone' in target_profile:
            tz = target_profile['timezone']
            adapted['best_contact_time'] = f"Between 9 AM - 5 PM {tz}"
        
        return adapted
    
    def generate_report(self, filename='pretexts.json'):
        report = {
            'total_pretexts': len(self.generated_pretexts),
            'pretexts': self.generated_pretexts,
            'generated': datetime.now().isoformat()
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            
            print(f"\033[92m[+] Report saved: {filename}\033[0m")
        
        except Exception as e:
            print(f"\033[91m[!] Report generation failed: {e}\033[0m")
    
    def display_scenarios(self):
        print(f"\n\033[92m{'='*70}\033[0m")
        print(f"\033[92m[*] AVAILABLE SCENARIOS\033[0m")
        print(f"\033[92m{'='*70}\033[0m\n")
        
        for i, (key, scenario) in enumerate(self.scenarios.items(), 1):
            print(f"\033[93m[{i}] {key.upper().replace('_', ' ')}\033[0m")
            print(f"\033[97m    Roles: {', '.join(scenario['roles'][:3])}\033[0m")
            print(f"\033[97m    Objectives: {', '.join(scenario['objectives'][:3])}\033[0m")
            print()
    
    def display_personalities(self):
        print(f"\n\033[92m{'='*70}\033[0m")
        print(f"\033[92m[*] AVAILABLE PERSONALITIES\033[0m")
        print(f"\033[92m{'='*70}\033[0m\n")
        
        for i, (key, personality) in enumerate(self.personalities.items(), 1):
            print(f"\033[93m[{i}] {key.upper()}\033[0m")
            print(f"\033[97m    Tone: {personality['tone']}\033[0m")
            print(f"\033[97m    Language: {personality['language']}\033[0m")
            print()

def run():
    print("\033[92m" + "="*70)
    print("     AI-POWERED PRETEXT GENERATOR")
    print("="*70 + "\033[0m\n")
    
    generator = AIPretextGenerator()
    
    print("\033[97mOperation mode:\033[0m")
    print("  [1] Generate pretext")
    print("  [2] Create full script")
    print("  [3] Generate email pretext")
    print("  [4] Create multi-stage attack")
    print("  [5] View scenarios")
    print("  [6] View personalities")
    print("  [7] Generate report")
    
    mode = input("\n\033[95m[?] Select: \033[0m").strip()
    
    if mode == '1':
        generator.display_scenarios()
        
        scenario = input("\n\033[95m[?] Scenario key: \033[0m").strip()
        
        generator.display_personalities()
        
        personality = input("\n\033[95m[?] Personality: \033[0m").strip()
        
        target_name = input("\033[95m[?] Target name (optional): \033[0m").strip()
        company = input("\033[95m[?] Company name (optional): \033[0m").strip()
        
        target_info = {}
        if target_name:
            target_info['name'] = target_name
        if company:
            target_info['company'] = company
        
        pretext = generator.generate_pretext(scenario, personality, target_info if target_info else None)
        
        if pretext:
            print(f"\n\033[92m[+] Pretext generated: {pretext['id']}\033[0m\n")
            print(f"\033[93mRole: {pretext['role']}\033[0m")
            print(f"\033[93mObjective: {pretext['objective']}\033[0m")
            print(f"\n\033[97mOpening:\033[0m")
            print(f"\033[97m{pretext['opening']}\033[0m")
            print(f"\n\033[97mBackstory:\033[0m")
            print(f"\033[97m{pretext['backstory']}\033[0m")
            print(f"\n\033[97mUrgency:\033[0m")
            print(f"\033[97m{pretext['urgency']}\033[0m")
            print(f"\n\033[97mCredibility:\033[0m")
            print(f"\033[97m{pretext['credibility']}\033[0m")
            print(f"\n\033[97mTone: {pretext['tone']}\033[0m")
    
    elif mode == '2':
        scenario = input("\033[95m[?] Scenario: \033[0m").strip()
        personality = input("\033[95m[?] Personality: \033[0m").strip()
        
        pretext = generator.generate_pretext(scenario, personality)
        
        if pretext:
            print(f"\n\033[97mInformation type:\033[0m")
            print("  [1] credentials")
            print("  [2] financial")
            print("  [3] personal")
            print("  [4] corporate")
            print("  [5] access")
            
            info_choice = input(f"\n\033[95m[?] Select: \033[0m").strip()
            info_types = ['credentials', 'financial', 'personal', 'corporate', 'access']
            info_type = info_types[int(info_choice) - 1] if info_choice.isdigit() and 1 <= int(info_choice) <= 5 else 'credentials'
            
            script = generator.create_full_script(pretext, info_type)
            
            if script:
                print(f"\n\033[92m[+] Full script generated\033[0m\n")
                print(f"\033[93m{'='*60}\033[0m")
                print(f"\033[93m{script['role']} - {script['scenario'].upper()}\033[0m")
                print(f"\033[93m{'='*60}\033[0m\n")
                
                for line in script['script']:
                    if line.startswith('['):
                        print(f"\033[96m{line}\033[0m")
                    else:
                        print(f"\033[97m{line}\033[0m")
                
                print(f"\n\033[93m{'='*60}\033[0m")
                print(f"\033[97mTone Guidance: {script['tone_guidance']}\033[0m")
                print(f"\033[97mKeywords: {', '.join(script['keywords_to_use'])}\033[0m")
                print(f"\033[97mTargets: {', '.join(script['information_targets'])}\033[0m")
    
    elif mode == '3':
        scenario = input("\033[95m[?] Scenario: \033[0m").strip()
        personality = input("\033[95m[?] Personality: \033[0m").strip()
        
        pretext = generator.generate_pretext(scenario, personality)
        
        if pretext:
            email = generator.generate_email_pretext(pretext)
            
            if email:
                print(f"\n\033[92m[+] Email pretext:\033[0m\n")
                print("\033[93m" + email['body'] + "\033[0m")
    
    elif mode == '4':
        generator.display_scenarios()
        
        stage1_scenario = input("\n\033[95m[?] Stage 1 scenario: \033[0m").strip()
        stage2_scenario = input("\033[95m[?] Stage 2 scenario: \033[0m").strip()
        
        attack = generator.create_multi_stage_attack(stage1_scenario, stage2_scenario)
        
        if attack:
            print(f"\n\033[92m[+] Multi-stage attack plan: {attack['attack_id']}\033[0m\n")
            
            print(f"\033[93mSTAGE 1 - {attack['stage1']['timing']}\033[0m")
            print(f"\033[97m  Objective: {attack['stage1']['objective']}\033[0m")
            print(f"\033[97m  Pretext: {attack['stage1']['pretext']['backstory']}\033[0m")
            print(f"\033[97m  Success: {', '.join(attack['stage1']['success_metrics'])}\033[0m\n")
            
            print(f"\033[93mSTAGE 2 - {attack['stage2']['timing']}\033[0m")
            print(f"\033[97m  Objective: {attack['stage2']['objective']}\033[0m")
            print(f"\033[97m  Pretext: {attack['stage2']['pretext']['backstory']}\033[0m")
            print(f"\033[97m  Success: {', '.join(attack['stage2']['success_metrics'])}\033[0m\n")
            
            print(f"\033[93mNOTES:\033[0m")
            for note in attack['notes']:
                print(f"\033[97m  - {note}\033[0m")
    
    elif mode == '5':
        generator.display_scenarios()
    
    elif mode == '6':
        generator.display_personalities()
    
    elif mode == '7':
        filename = input("\033[95m[?] Filename (pretexts.json): \033[0m").strip()
        generator.generate_report(filename if filename else 'pretexts.json')
    
    print(f"\n\033[92m[+] Done\033[0m")

if __name__ == "__main__":
    run()
