#!/usr/bin/env python3
import os
import re
import json
import hashlib
from datetime import datetime
from collections import defaultdict

class TimelineGenerator:
    def __init__(self):
        self.events = []
        self.output_dir = f"timeline_{int(datetime.now().timestamp())}"
        
        self.log_patterns = {
            'windows_event': {
                'pattern': r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(.+)',
                'timestamp_format': '%Y-%m-%d %H:%M:%S'
            },
            'syslog': {
                'pattern': r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.+)',
                'timestamp_format': '%b %d %H:%M:%S'
            },
            'apache': {
                'pattern': r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})\]',
                'timestamp_format': '%d/%b/%Y:%H:%M:%S %z'
            },
            'iis': {
                'pattern': r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',
                'timestamp_format': '%Y-%m-%d %H:%M:%S'
            },
            'firewall': {
                'pattern': r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})',
                'timestamp_format': '%Y-%m-%dT%H:%M:%S'
            }
        }
        
        self.artifact_sources = {
            'prefetch': {
                'path_patterns': ['*.pf', 'Prefetch/*.pf'],
                'description': 'Windows Prefetch'
            },
            'shimcache': {
                'path_patterns': ['SYSTEM'],
                'description': 'Application Compatibility Cache'
            },
            'amcache': {
                'path_patterns': ['Amcache.hve'],
                'description': 'Application Experience'
            },
            'mft': {
                'path_patterns': ['$MFT'],
                'description': 'Master File Table'
            },
            'usnjrnl': {
                'path_patterns': ['$UsnJrnl'],
                'description': 'USN Journal'
            },
            'registry': {
                'path_patterns': ['*.dat', 'SAM', 'SYSTEM', 'SOFTWARE', 'SECURITY'],
                'description': 'Registry Hives'
            },
            'browser_history': {
                'path_patterns': ['History', 'places.sqlite', 'WebCacheV*.dat'],
                'description': 'Browser History'
            },
            'lnk_files': {
                'path_patterns': ['*.lnk'],
                'description': 'Shortcut Files'
            },
            'recycle_bin': {
                'path_patterns': ['$I*', '$R*'],
                'description': 'Recycle Bin'
            }
        }
    
    def parse_windows_event_logs(self, log_path):
        print(f"\033[93m[*] Parsing Windows Event Logs from {log_path}...\033[0m")
        
        events_found = 0
        
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    match = re.search(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', line)
                    
                    if match:
                        timestamp_str = match.group(1)
                        
                        try:
                            timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                            
                            event_id = self.extract_event_id(line)
                            event_type = self.extract_event_type(line)
                            source = self.extract_source(line)
                            
                            self.events.append({
                                'timestamp': timestamp,
                                'source': 'Windows Event Log',
                                'event_type': event_type,
                                'event_id': event_id,
                                'source_name': source,
                                'description': line[:200],
                                'file': os.path.basename(log_path)
                            })
                            
                            events_found += 1
                        except:
                            pass
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
        
        print(f"\033[92m[+] Found {events_found} events\033[0m")
    
    def parse_syslog(self, log_path):
        print(f"\033[93m[*] Parsing Syslog from {log_path}...\033[0m")
        
        events_found = 0
        current_year = datetime.now().year
        
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    match = re.search(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.+)', line)
                    
                    if match:
                        timestamp_str = match.group(1)
                        hostname = match.group(2)
                        message = match.group(3)
                        
                        try:
                            timestamp = datetime.strptime(f"{current_year} {timestamp_str}", '%Y %b %d %H:%M:%S')
                            
                            self.events.append({
                                'timestamp': timestamp,
                                'source': 'Syslog',
                                'hostname': hostname,
                                'description': message[:200],
                                'file': os.path.basename(log_path)
                            })
                            
                            events_found += 1
                        except:
                            pass
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
        
        print(f"\033[92m[+] Found {events_found} events\033[0m")
    
    def parse_apache_logs(self, log_path):
        print(f"\033[93m[*] Parsing Apache logs from {log_path}...\033[0m")
        
        events_found = 0
        
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    match = re.search(r'(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\d+)', line)
                    
                    if match:
                        ip_addr = match.group(1)
                        timestamp_str = match.group(2)
                        request = match.group(3)
                        status = match.group(4)
                        size = match.group(5)
                        
                        try:
                            timestamp = datetime.strptime(timestamp_str.split()[0], '%d/%b/%Y:%H:%M:%S')
                            
                            self.events.append({
                                'timestamp': timestamp,
                                'source': 'Apache Access Log',
                                'ip_address': ip_addr,
                                'request': request[:100],
                                'status': status,
                                'size': size,
                                'file': os.path.basename(log_path)
                            })
                            
                            events_found += 1
                        except:
                            pass
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
        
        print(f"\033[92m[+] Found {events_found} events\033[0m")
    
    def parse_file_timestamps(self, directory):
        print(f"\033[93m[*] Extracting file timestamps from {directory}...\033[0m")
        
        files_found = 0
        
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    try:
                        stat_info = os.stat(file_path)
                        
                        self.events.append({
                            'timestamp': datetime.fromtimestamp(stat_info.st_mtime),
                            'source': 'File Modified',
                            'file_path': file_path,
                            'size': stat_info.st_size,
                            'description': f"File modified: {file}"
                        })
                        
                        self.events.append({
                            'timestamp': datetime.fromtimestamp(stat_info.st_ctime),
                            'source': 'File Created',
                            'file_path': file_path,
                            'size': stat_info.st_size,
                            'description': f"File created: {file}"
                        })
                        
                        self.events.append({
                            'timestamp': datetime.fromtimestamp(stat_info.st_atime),
                            'source': 'File Accessed',
                            'file_path': file_path,
                            'size': stat_info.st_size,
                            'description': f"File accessed: {file}"
                        })
                        
                        files_found += 1
                    except:
                        pass
                
                if files_found > 1000:
                    break
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
        
        print(f"\033[92m[+] Processed {files_found} files\033[0m")
    
    def parse_prefetch_files(self, prefetch_dir):
        print(f"\033[93m[*] Analyzing Prefetch files from {prefetch_dir}...\033[0m")
        
        prefetch_found = 0
        
        try:
            for file in os.listdir(prefetch_dir):
                if file.endswith('.pf'):
                    file_path = os.path.join(prefetch_dir, file)
                    
                    try:
                        stat_info = os.stat(file_path)
                        
                        app_name = file.replace('.pf', '').split('-')[0]
                        
                        self.events.append({
                            'timestamp': datetime.fromtimestamp(stat_info.st_mtime),
                            'source': 'Prefetch',
                            'application': app_name,
                            'file': file,
                            'description': f"Application executed: {app_name}"
                        })
                        
                        prefetch_found += 1
                    except:
                        pass
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
        
        print(f"\033[92m[+] Found {prefetch_found} prefetch files\033[0m")
    
    def parse_registry_timestamps(self, registry_path):
        print(f"\033[93m[*] Extracting registry timestamps from {registry_path}...\033[0m")
        
        try:
            stat_info = os.stat(registry_path)
            
            self.events.append({
                'timestamp': datetime.fromtimestamp(stat_info.st_mtime),
                'source': 'Registry Hive',
                'file': os.path.basename(registry_path),
                'description': f"Registry hive modified: {os.path.basename(registry_path)}"
            })
            
            print(f"\033[92m[+] Extracted registry timestamp\033[0m")
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
    
    def parse_browser_history(self, history_file):
        print(f"\033[93m[*] Parsing browser history from {history_file}...\033[0m")
        
        history_found = 0
        
        try:
            if history_file.endswith('.sqlite') or 'places' in history_file.lower():
                import sqlite3
                
                conn = sqlite3.connect(history_file)
                cursor = conn.cursor()
                
                try:
                    cursor.execute("""
                        SELECT url, title, visit_date, visit_count
                        FROM moz_places
                        JOIN moz_historyvisits ON moz_places.id = moz_historyvisits.place_id
                        ORDER BY visit_date DESC
                        LIMIT 1000
                    """)
                    
                    for row in cursor.fetchall():
                        url, title, visit_date, visit_count = row
                        
                        timestamp = datetime.fromtimestamp(visit_date / 1000000)
                        
                        self.events.append({
                            'timestamp': timestamp,
                            'source': 'Browser History',
                            'url': url[:200],
                            'title': title[:100] if title else '',
                            'visit_count': visit_count,
                            'description': f"Visited: {url[:100]}"
                        })
                        
                        history_found += 1
                except:
                    pass
                
                conn.close()
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
        
        print(f"\033[92m[+] Found {history_found} history entries\033[0m")
    
    def extract_event_id(self, line):
        match = re.search(r'EventID[:\s]+(\d+)', line, re.IGNORECASE)
        return match.group(1) if match else ''
    
    def extract_event_type(self, line):
        for event_type in ['Error', 'Warning', 'Information', 'Critical', 'Audit']:
            if event_type.lower() in line.lower():
                return event_type
        return 'Unknown'
    
    def extract_source(self, line):
        match = re.search(r'Source[:\s]+([^\s,]+)', line, re.IGNORECASE)
        return match.group(1) if match else 'Unknown'
    
    def sort_timeline(self):
        print(f"\033[93m[*] Sorting timeline chronologically...\033[0m")
        
        self.events.sort(key=lambda x: x['timestamp'])
        
        print(f"\033[92m[+] Sorted {len(self.events)} events\033[0m")
    
    def generate_timeline(self):
        os.makedirs(self.output_dir, exist_ok=True)
        
        timeline_file = os.path.join(self.output_dir, 'timeline.csv')
        
        print(f"\033[93m[*] Generating timeline...\033[0m")
        
        with open(timeline_file, 'w', encoding='utf-8') as f:
            f.write("Timestamp,Source,Description,Details\n")
            
            for event in self.events:
                timestamp = event['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                source = event.get('source', 'Unknown')
                description = event.get('description', '')
                
                details = '; '.join(f"{k}={v}" for k, v in event.items() 
                                   if k not in ['timestamp', 'source', 'description'])
                
                f.write(f'"{timestamp}","{source}","{description}","{details}"\n')
        
        print(f"\033[92m[+] Timeline saved: {timeline_file}\033[0m")
    
    def generate_report(self):
        report_file = os.path.join(self.output_dir, 'timeline_report.json')
        
        source_counts = defaultdict(int)
        for event in self.events:
            source_counts[event.get('source', 'Unknown')] += 1
        
        date_range = {
            'earliest': min(self.events, key=lambda x: x['timestamp'])['timestamp'].isoformat() if self.events else None,
            'latest': max(self.events, key=lambda x: x['timestamp'])['timestamp'].isoformat() if self.events else None
        }
        
        report = {
            'generation_date': datetime.now().isoformat(),
            'total_events': len(self.events),
            'date_range': date_range,
            'sources': dict(source_counts),
            'output_directory': self.output_dir
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\033[92m[+] Report saved: {report_file}\033[0m")
        
        text_report = os.path.join(self.output_dir, 'timeline_report.txt')
        
        with open(text_report, 'w') as f:
            f.write("="*80 + "\n")
            f.write("FORENSIC TIMELINE ANALYSIS REPORT\n")
            f.write("="*80 + "\n\n")
            f.write(f"Generation Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Events: {len(self.events)}\n\n")
            
            if date_range['earliest']:
                f.write(f"Date Range:\n")
                f.write(f"  Earliest: {date_range['earliest']}\n")
                f.write(f"  Latest: {date_range['latest']}\n\n")
            
            f.write("="*80 + "\n")
            f.write("EVENT SOURCES\n")
            f.write("="*80 + "\n")
            for source, count in sorted(source_counts.items(), key=lambda x: x[1], reverse=True):
                f.write(f"{source}: {count}\n")
            
            f.write("\n" + "="*80 + "\n")
            f.write("TIMELINE EVENTS (First 50)\n")
            f.write("="*80 + "\n")
            for event in self.events[:50]:
                f.write(f"\n{event['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"  Source: {event.get('source', 'Unknown')}\n")
                f.write(f"  Description: {event.get('description', '')}\n")
        
        print(f"\033[92m[+] Text report saved: {text_report}\033[0m")

def run():
    print("\033[92m" + "="*70)
    print("     TIMELINE GENERATOR")
    print("="*70 + "\033[0m\n")
    
    generator = TimelineGenerator()
    
    print("\033[97mTimeline Generation Options:\033[0m")
    print("\033[97m  [1] Parse Windows Event Logs\033[0m")
    print("\033[97m  [2] Parse Syslog\033[0m")
    print("\033[97m  [3] Parse Apache logs\033[0m")
    print("\033[97m  [4] Parse file timestamps from directory\033[0m")
    print("\033[97m  [5] Parse Prefetch files\033[0m")
    print("\033[97m  [6] Parse browser history\033[0m")
    print("\033[97m  [7] Generate timeline from parsed events\033[0m")
    
    while True:
        choice = input(f"\n\033[95m[?] Select option (or 7 to generate, 0 to exit): \033[0m").strip()
        
        if choice == '0':
            break
        
        elif choice == '1':
            log_path = input("\033[95m[?] Windows Event Log path: \033[0m").strip()
            if os.path.exists(log_path):
                generator.parse_windows_event_logs(log_path)
        
        elif choice == '2':
            log_path = input("\033[95m[?] Syslog path: \033[0m").strip()
            if os.path.exists(log_path):
                generator.parse_syslog(log_path)
        
        elif choice == '3':
            log_path = input("\033[95m[?] Apache log path: \033[0m").strip()
            if os.path.exists(log_path):
                generator.parse_apache_logs(log_path)
        
        elif choice == '4':
            directory = input("\033[95m[?] Directory path: \033[0m").strip()
            if os.path.exists(directory):
                generator.parse_file_timestamps(directory)
        
        elif choice == '5':
            prefetch_dir = input("\033[95m[?] Prefetch directory path: \033[0m").strip()
            if os.path.exists(prefetch_dir):
                generator.parse_prefetch_files(prefetch_dir)
        
        elif choice == '6':
            history_file = input("\033[95m[?] Browser history file path: \033[0m").strip()
            if os.path.exists(history_file):
                generator.parse_browser_history(history_file)
        
        elif choice == '7':
            if generator.events:
                generator.sort_timeline()
                generator.generate_timeline()
                generator.generate_report()
                print(f"\n\033[92m[+] Timeline generation complete\033[0m")
            else:
                print(f"\033[91m[!] No events to generate timeline\033[0m")
            break

if __name__ == "__main__":
    run()
