#!/usr/bin/env python3
import os
import sqlite3
import plistlib
import hashlib
import json
from datetime import datetime
from collections import defaultdict

class iOSBackupAnalyzer:
    def __init__(self, backup_path):
        self.backup_path = backup_path
        self.manifest_db = os.path.join(backup_path, 'Manifest.db')
        self.status_plist = os.path.join(backup_path, 'Status.plist')
        self.info_plist = os.path.join(backup_path, 'Info.plist')
        self.results = defaultdict(dict)
        
        self.app_domains = {
            'AppDomain-com.apple.mobilesafari': 'Safari',
            'AppDomain-com.apple.mobilemail': 'Mail',
            'AppDomain-com.apple.MobileSMS': 'Messages',
            'AppDomain-com.apple.mobilephone': 'Phone',
            'AppDomain-com.apple.mobilenotes': 'Notes',
            'AppDomain-net.whatsapp.WhatsApp': 'WhatsApp',
            'AppDomain-com.facebook.Facebook': 'Facebook',
            'AppDomain-com.atebits.Tweetie2': 'Twitter',
            'AppDomain-com.google.chrome.ios': 'Chrome',
            'AppDomain-ph.telegra.Telegraph': 'Telegram'
        }
        
        self.db_patterns = {
            'sms': 'Library/SMS/sms.db',
            'contacts': 'Library/AddressBook/AddressBook.sqlitedb',
            'call_history': 'Library/CallHistoryDB/CallHistory.storedata',
            'safari_history': 'Library/Safari/History.db',
            'safari_cookies': 'Library/Cookies/Cookies.binarycookies',
            'calendar': 'Library/Calendar/Calendar.sqlitedb',
            'notes': 'Library/Notes/notes.sqlite',
            'voicemail': 'Library/Voicemail/voicemail.db',
            'photos': 'Media/DCIM',
            'health': 'Health/healthdb.sqlite'
        }
    
    def parse_manifest(self):
        if not os.path.exists(self.manifest_db):
            print(f"\033[91m[!] Manifest.db not found\033[0m")
            return
        
        print(f"\033[93m[*] Parsing Manifest.db...\033[0m")
        
        conn = sqlite3.connect(self.manifest_db)
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        if 'Files' in tables:
            cursor.execute("""
                SELECT fileID, domain, relativePath, flags, file 
                FROM Files 
                ORDER BY domain
            """)
            
            files = cursor.fetchall()
            
            for file_data in files:
                file_id, domain, rel_path, flags, file_blob = file_data
                
                if domain not in self.results['files']:
                    self.results['files'][domain] = []
                
                self.results['files'][domain].append({
                    'id': file_id,
                    'path': rel_path,
                    'flags': flags
                })
        
        conn.close()
        
        total_files = sum(len(files) for files in self.results['files'].values())
        print(f"\033[92m[+] Found {total_files} files in {len(self.results['files'])} domains\033[0m")
    
    def parse_info_plist(self):
        if not os.path.exists(self.info_plist):
            return
        
        print(f"\033[93m[*] Parsing Info.plist...\033[0m")
        
        with open(self.info_plist, 'rb') as f:
            info = plistlib.load(f)
        
        self.results['device_info'] = {
            'device_name': info.get('Device Name', 'Unknown'),
            'display_name': info.get('Display Name', 'Unknown'),
            'product_type': info.get('Product Type', 'Unknown'),
            'product_version': info.get('Product Version', 'Unknown'),
            'serial_number': info.get('Serial Number', 'Unknown'),
            'phone_number': info.get('Phone Number', 'Unknown'),
            'imei': info.get('IMEI', 'Unknown'),
            'last_backup': info.get('Last Backup Date', 'Unknown')
        }
        
        print(f"\033[92m[+] Device: {self.results['device_info']['device_name']}\033[0m")
        print(f"\033[92m[+] iOS Version: {self.results['device_info']['product_version']}\033[0m")
    
    def extract_sms_messages(self):
        print(f"\033[93m[*] Extracting SMS messages...\033[0m")
        
        sms_file = self.find_file_by_path('Library/SMS/sms.db')
        
        if not sms_file:
            print(f"\033[91m[!] SMS database not found\033[0m")
            return
        
        conn = sqlite3.connect(sms_file)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT 
                    handle.id as phone_number,
                    message.text,
                    message.date,
                    message.is_from_me,
                    message.service
                FROM message
                LEFT JOIN handle ON message.handle_id = handle.ROWID
                ORDER BY message.date DESC
                LIMIT 100
            """)
            
            messages = []
            for row in cursor.fetchall():
                phone, text, date, is_from_me, service = row
                
                messages.append({
                    'phone': phone,
                    'text': text[:200] if text else '',
                    'date': date,
                    'outgoing': bool(is_from_me),
                    'service': service
                })
            
            self.results['sms_messages'] = messages
            print(f"\033[92m[+] Extracted {len(messages)} SMS messages\033[0m")
            
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
        
        conn.close()
    
    def extract_contacts(self):
        print(f"\033[93m[*] Extracting contacts...\033[0m")
        
        contacts_file = self.find_file_by_path('Library/AddressBook/AddressBook.sqlitedb')
        
        if not contacts_file:
            print(f"\033[91m[!] Contacts database not found\033[0m")
            return
        
        conn = sqlite3.connect(contacts_file)
        cursor = conn.cursor()
        
        try:
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            contacts = []
            
            if 'ABPerson' in tables:
                cursor.execute("""
                    SELECT First, Last, Organization, Department, Note
                    FROM ABPerson
                """)
                
                for row in cursor.fetchall():
                    first, last, org, dept, note = row
                    
                    contacts.append({
                        'name': f"{first or ''} {last or ''}".strip(),
                        'organization': org,
                        'department': dept,
                        'note': note
                    })
            
            if 'ABMultiValue' in tables:
                cursor.execute("""
                    SELECT record_id, value, label
                    FROM ABMultiValue
                    WHERE property = 3 OR property = 4
                """)
                
                contact_details = defaultdict(list)
                for row in cursor.fetchall():
                    record_id, value, label = row
                    contact_details[record_id].append({
                        'value': value,
                        'label': label
                    })
                
                for i, contact in enumerate(contacts):
                    if i in contact_details:
                        contact['details'] = contact_details[i]
            
            self.results['contacts'] = contacts
            print(f"\033[92m[+] Extracted {len(contacts)} contacts\033[0m")
            
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
        
        conn.close()
    
    def extract_call_history(self):
        print(f"\033[93m[*] Extracting call history...\033[0m")
        
        call_file = self.find_file_by_path('Library/CallHistoryDB/CallHistory.storedata')
        
        if not call_file:
            print(f"\033[91m[!] Call history database not found\033[0m")
            return
        
        conn = sqlite3.connect(call_file)
        cursor = conn.cursor()
        
        try:
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            calls = []
            
            if 'ZCALLRECORD' in tables:
                cursor.execute("""
                    SELECT ZADDRESS, ZDATE, ZDURATION, ZANSWERED, ZORIGINATED
                    FROM ZCALLRECORD
                    ORDER BY ZDATE DESC
                    LIMIT 100
                """)
                
                for row in cursor.fetchall():
                    address, date, duration, answered, originated = row
                    
                    calls.append({
                        'number': address,
                        'date': date,
                        'duration': duration,
                        'answered': bool(answered),
                        'outgoing': bool(originated)
                    })
            
            self.results['call_history'] = calls
            print(f"\033[92m[+] Extracted {len(calls)} call records\033[0m")
            
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
        
        conn.close()
    
    def extract_safari_history(self):
        print(f"\033[93m[*] Extracting Safari history...\033[0m")
        
        safari_file = self.find_file_by_path('Library/Safari/History.db')
        
        if not safari_file:
            print(f"\033[91m[!] Safari history not found\033[0m")
            return
        
        conn = sqlite3.connect(safari_file)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT url, title, visit_count, visit_time
                FROM history_items
                LEFT JOIN history_visits ON history_items.id = history_visits.history_item
                ORDER BY visit_time DESC
                LIMIT 100
            """)
            
            history = []
            for row in cursor.fetchall():
                url, title, visit_count, visit_time = row
                
                history.append({
                    'url': url,
                    'title': title,
                    'visits': visit_count,
                    'last_visit': visit_time
                })
            
            self.results['safari_history'] = history
            print(f"\033[92m[+] Extracted {len(history)} history entries\033[0m")
            
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
        
        conn.close()
    
    def extract_notes(self):
        print(f"\033[93m[*] Extracting notes...\033[0m")
        
        notes_file = self.find_file_by_path('Library/Notes/notes.sqlite')
        
        if not notes_file:
            print(f"\033[91m[!] Notes database not found\033[0m")
            return
        
        conn = sqlite3.connect(notes_file)
        cursor = conn.cursor()
        
        try:
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            notes = []
            
            if 'ZNOTE' in tables:
                cursor.execute("""
                    SELECT ZTITLE, ZCONTENT, ZCREATIONDATE, ZMODIFICATIONDATE
                    FROM ZNOTE
                    ORDER BY ZMODIFICATIONDATE DESC
                    LIMIT 50
                """)
                
                for row in cursor.fetchall():
                    title, content, created, modified = row
                    
                    notes.append({
                        'title': title,
                        'content': content[:500] if content else '',
                        'created': created,
                        'modified': modified
                    })
            
            self.results['notes'] = notes
            print(f"\033[92m[+] Extracted {len(notes)} notes\033[0m")
            
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
        
        conn.close()
    
    def extract_app_data(self):
        print(f"\033[93m[*] Extracting app data...\033[0m")
        
        app_data = {}
        
        for domain, app_name in self.app_domains.items():
            if domain in self.results.get('files', {}):
                files = self.results['files'][domain]
                
                app_data[app_name] = {
                    'domain': domain,
                    'file_count': len(files),
                    'files': [f['path'] for f in files[:10]]
                }
        
        self.results['app_data'] = app_data
        print(f"\033[92m[+] Found data for {len(app_data)} apps\033[0m")
    
    def extract_photos_info(self):
        print(f"\033[93m[*] Analyzing photos...\033[0m")
        
        photo_files = []
        
        for root, dirs, files in os.walk(self.backup_path):
            for file in files:
                if file.lower().endswith(('.jpg', '.jpeg', '.png', '.heic', '.mov', '.mp4')):
                    file_path = os.path.join(root, file)
                    
                    photo_files.append({
                        'name': file,
                        'size': os.path.getsize(file_path),
                        'hash': self.hash_file(file_path)
                    })
        
        self.results['photos'] = photo_files
        print(f"\033[92m[+] Found {len(photo_files)} media files\033[0m")
    
    def extract_wifi_networks(self):
        print(f"\033[93m[*] Extracting WiFi networks...\033[0m")
        
        wifi_plist = self.find_file_by_path('Library/Preferences/com.apple.wifi.plist')
        
        if not wifi_plist:
            print(f"\033[91m[!] WiFi config not found\033[0m")
            return
        
        try:
            with open(wifi_plist, 'rb') as f:
                wifi_data = plistlib.load(f)
            
            networks = []
            
            if 'List of known networks' in wifi_data:
                for network in wifi_data['List of known networks']:
                    networks.append({
                        'ssid': network.get('SSID_STR', 'Unknown'),
                        'security': network.get('SecurityMode', 'Unknown'),
                        'last_joined': network.get('lastJoined', 'Unknown')
                    })
            
            self.results['wifi_networks'] = networks
            print(f"\033[92m[+] Found {len(networks)} WiFi networks\033[0m")
            
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
    
    def find_file_by_path(self, relative_path):
        for root, dirs, files in os.walk(self.backup_path):
            for file in files:
                file_path = os.path.join(root, file)
                
                domain_path = f"HomeDomain-{relative_path}"
                file_hash = hashlib.sha1(domain_path.encode()).hexdigest()
                
                if file == file_hash:
                    return file_path
        
        return None
    
    def hash_file(self, file_path):
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        
        return sha256.hexdigest()
    
    def generate_report(self):
        report_file = f"ios_backup_analysis_{int(datetime.now().timestamp())}.json"
        
        report = {
            'backup_path': self.backup_path,
            'analysis_date': datetime.now().isoformat(),
            'device_info': self.results.get('device_info', {}),
            'sms_messages': len(self.results.get('sms_messages', [])),
            'contacts': len(self.results.get('contacts', [])),
            'call_history': len(self.results.get('call_history', [])),
            'safari_history': len(self.results.get('safari_history', [])),
            'notes': len(self.results.get('notes', [])),
            'photos': len(self.results.get('photos', [])),
            'apps': list(self.results.get('app_data', {}).keys()),
            'wifi_networks': len(self.results.get('wifi_networks', []))
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n\033[92m[+] Report saved: {report_file}\033[0m")
        
        detailed_file = f"ios_backup_detailed_{int(datetime.now().timestamp())}.json"
        with open(detailed_file, 'w') as f:
            json.dump(dict(self.results), f, indent=2, default=str)
        
        print(f"\033[92m[+] Detailed data saved: {detailed_file}\033[0m")

def run():
    print("\033[92m" + "="*70)
    print("     iOS BACKUP ANALYZER")
    print("="*70 + "\033[0m\n")
    
    backup_path = input("\033[95m[?] Enter iOS backup directory path: \033[0m").strip()
    
    if not os.path.exists(backup_path):
        print(f"\033[91m[!] Directory not found\033[0m")
        return
    
    analyzer = iOSBackupAnalyzer(backup_path)
    
    analyzer.parse_manifest()
    analyzer.parse_info_plist()
    analyzer.extract_sms_messages()
    analyzer.extract_contacts()
    analyzer.extract_call_history()
    analyzer.extract_safari_history()
    analyzer.extract_notes()
    analyzer.extract_app_data()
    analyzer.extract_photos_info()
    analyzer.extract_wifi_networks()
    analyzer.generate_report()
    
    print(f"\n\033[92m[+] Analysis complete\033[0m")

if __name__ == "__main__":
    run()
