#!/usr/bin/env python3
import os
import struct
import hashlib
import json
from datetime import datetime
from collections import defaultdict

class FileCarving:
    def __init__(self, image_path):
        self.image_path = image_path
        self.carved_files = []
        self.output_dir = f"carved_files_{int(datetime.now().timestamp())}"
        
        self.file_signatures = {
            'jpeg': {
                'header': [b'\xFF\xD8\xFF\xE0', b'\xFF\xD8\xFF\xE1', b'\xFF\xD8\xFF\xE2'],
                'footer': [b'\xFF\xD9'],
                'ext': '.jpg',
                'name': 'JPEG Image'
            },
            'png': {
                'header': [b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'],
                'footer': [b'\x49\x45\x4E\x44\xAE\x42\x60\x82'],
                'ext': '.png',
                'name': 'PNG Image'
            },
            'gif': {
                'header': [b'GIF87a', b'GIF89a'],
                'footer': [b'\x00\x3B'],
                'ext': '.gif',
                'name': 'GIF Image'
            },
            'pdf': {
                'header': [b'%PDF-'],
                'footer': [b'%%EOF', b'%EOF'],
                'ext': '.pdf',
                'name': 'PDF Document'
            },
            'zip': {
                'header': [b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08'],
                'footer': [b'PK\x05\x06'],
                'ext': '.zip',
                'name': 'ZIP Archive'
            },
            'docx': {
                'header': [b'PK\x03\x04'],
                'footer': [b'PK\x05\x06'],
                'ext': '.docx',
                'name': 'Word Document'
            },
            'xlsx': {
                'header': [b'PK\x03\x04'],
                'footer': [b'PK\x05\x06'],
                'ext': '.xlsx',
                'name': 'Excel Spreadsheet'
            },
            'exe': {
                'header': [b'MZ'],
                'footer': [],
                'ext': '.exe',
                'name': 'Executable'
            },
            'dll': {
                'header': [b'MZ'],
                'footer': [],
                'ext': '.dll',
                'name': 'Dynamic Library'
            },
            'elf': {
                'header': [b'\x7FELF'],
                'footer': [],
                'ext': '.elf',
                'name': 'ELF Binary'
            },
            'mp3': {
                'header': [b'\xFF\xFB', b'\xFF\xF3', b'\xFF\xF2', b'ID3'],
                'footer': [],
                'ext': '.mp3',
                'name': 'MP3 Audio'
            },
            'mp4': {
                'header': [b'\x00\x00\x00\x18ftypmp4', b'\x00\x00\x00\x1Cftypmp42'],
                'footer': [],
                'ext': '.mp4',
                'name': 'MP4 Video'
            },
            'avi': {
                'header': [b'RIFF'],
                'footer': [],
                'ext': '.avi',
                'name': 'AVI Video'
            },
            'wav': {
                'header': [b'RIFF'],
                'footer': [],
                'ext': '.wav',
                'name': 'WAV Audio'
            },
            'pst': {
                'header': [b'!BDN'],
                'footer': [],
                'ext': '.pst',
                'name': 'Outlook PST'
            },
            'sqlite': {
                'header': [b'SQLite format 3\x00'],
                'footer': [],
                'ext': '.db',
                'name': 'SQLite Database'
            },
            'registry': {
                'header': [b'regf'],
                'footer': [],
                'ext': '.dat',
                'name': 'Windows Registry'
            },
            'evtx': {
                'header': [b'ElfFile\x00'],
                'footer': [],
                'ext': '.evtx',
                'name': 'Windows Event Log'
            },
            'prefetch': {
                'header': [b'SCCA'],
                'footer': [],
                'ext': '.pf',
                'name': 'Windows Prefetch'
            }
        }
        
        self.chunk_size = 1024 * 1024
    
    def carve_by_signature(self):
        print(f"\033[93m[*] Starting file carving from {self.image_path}...\033[0m")
        
        os.makedirs(self.output_dir, exist_ok=True)
        
        file_size = os.path.getsize(self.image_path)
        print(f"\033[97m[*] Image size: {file_size / (1024**3):.2f} GB\033[0m\n")
        
        with open(self.image_path, 'rb') as f:
            offset = 0
            buffer = b''
            
            while True:
                chunk = f.read(self.chunk_size)
                if not chunk:
                    break
                
                buffer += chunk
                
                for file_type, sig_info in self.file_signatures.items():
                    for header in sig_info['header']:
                        pos = 0
                        while True:
                            pos = buffer.find(header, pos)
                            if pos == -1:
                                break
                            
                            file_start = offset + pos
                            
                            if sig_info['footer']:
                                footer_pos = -1
                                for footer in sig_info['footer']:
                                    footer_search = buffer.find(footer, pos + len(header))
                                    if footer_search != -1:
                                        footer_pos = footer_search
                                        break
                                
                                if footer_pos != -1:
                                    file_data = buffer[pos:footer_pos + len(sig_info['footer'][0])]
                                    self.save_carved_file(file_type, file_data, file_start, sig_info)
                            else:
                                max_size = min(10 * 1024 * 1024, len(buffer) - pos)
                                file_data = buffer[pos:pos + max_size]
                                self.save_carved_file(file_type, file_data, file_start, sig_info)
                            
                            pos += 1
                
                offset += len(chunk)
                buffer = buffer[-self.chunk_size:]
                
                progress = (offset / file_size) * 100
                if offset % (100 * 1024 * 1024) == 0:
                    print(f"\033[97m[*] Progress: {progress:.1f}% - Carved: {len(self.carved_files)} files\033[0m")
        
        print(f"\n\033[92m[+] Carving complete. Found {len(self.carved_files)} files\033[0m")
    
    def save_carved_file(self, file_type, data, offset, sig_info):
        if len(data) < 100:
            return
        
        file_hash = hashlib.md5(data).hexdigest()[:8]
        filename = f"{file_type}_{offset}_{file_hash}{sig_info['ext']}"
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'wb') as f:
            f.write(data)
        
        self.carved_files.append({
            'type': sig_info['name'],
            'filename': filename,
            'offset': offset,
            'size': len(data),
            'md5': hashlib.md5(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest()
        })
    
    def carve_deleted_files(self):
        print(f"\033[93m[*] Searching for deleted file fragments...\033[0m")
        
        deleted_patterns = [
            b'\x00' * 512,
            b'\xFF' * 512
        ]
        
        with open(self.image_path, 'rb') as f:
            offset = 0
            
            while True:
                chunk = f.read(self.chunk_size)
                if not chunk:
                    break
                
                for pattern in deleted_patterns:
                    pos = chunk.find(pattern)
                    if pos != -1:
                        start = offset + pos + len(pattern)
                        
                        f.seek(start)
                        potential_data = f.read(4096)
                        
                        if self.is_valid_file_data(potential_data):
                            print(f"\033[92m[+] Found potential deleted file at offset {start}\033[0m")
                
                offset += len(chunk)
        
        print(f"\033[92m[+] Deleted file search complete\033[0m")
    
    def is_valid_file_data(self, data):
        if len(data) < 100:
            return False
        
        null_count = data.count(b'\x00')
        if null_count > len(data) * 0.9:
            return False
        
        printable_count = sum(1 for b in data if 32 <= b <= 126 or b in [9, 10, 13])
        if printable_count > len(data) * 0.3:
            return True
        
        return False
    
    def carve_strings(self, min_length=8):
        print(f"\033[93m[*] Extracting strings (min length: {min_length})...\033[0m")
        
        strings_file = os.path.join(self.output_dir, 'extracted_strings.txt')
        interesting_strings = []
        
        patterns = [
            b'http://',
            b'https://',
            b'ftp://',
            b'@',
            b'.com',
            b'.exe',
            b'.dll',
            b'password',
            b'username',
            b'admin',
            b'root',
            b'key',
            b'secret'
        ]
        
        with open(self.image_path, 'rb') as f:
            current_string = b''
            
            while True:
                chunk = f.read(self.chunk_size)
                if not chunk:
                    break
                
                for byte in chunk:
                    if 32 <= byte <= 126 or byte in [9, 10, 13]:
                        current_string += bytes([byte])
                    else:
                        if len(current_string) >= min_length:
                            try:
                                string_decoded = current_string.decode('utf-8', errors='ignore')
                                
                                if any(pattern.decode('utf-8', errors='ignore').lower() in string_decoded.lower() 
                                      for pattern in patterns):
                                    interesting_strings.append(string_decoded)
                            except:
                                pass
                        
                        current_string = b''
        
        with open(strings_file, 'w', encoding='utf-8') as f:
            for string in interesting_strings[:1000]:
                f.write(string + '\n')
        
        print(f"\033[92m[+] Extracted {len(interesting_strings)} interesting strings\033[0m")
        print(f"\033[92m[+] Strings saved: {strings_file}\033[0m")
    
    def carve_email_addresses(self):
        print(f"\033[93m[*] Extracting email addresses...\033[0m")
        
        emails = set()
        
        with open(self.image_path, 'rb') as f:
            buffer = b''
            
            while True:
                chunk = f.read(self.chunk_size)
                if not chunk:
                    break
                
                buffer += chunk
                
                try:
                    text = buffer.decode('utf-8', errors='ignore')
                    
                    import re
                    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                    found_emails = re.findall(email_pattern, text)
                    
                    emails.update(found_emails)
                except:
                    pass
                
                buffer = buffer[-10000:]
        
        email_file = os.path.join(self.output_dir, 'email_addresses.txt')
        
        with open(email_file, 'w') as f:
            for email in sorted(emails):
                f.write(email + '\n')
        
        print(f"\033[92m[+] Found {len(emails)} unique email addresses\033[0m")
        print(f"\033[92m[+] Emails saved: {email_file}\033[0m")
    
    def carve_urls(self):
        print(f"\033[93m[*] Extracting URLs...\033[0m")
        
        urls = set()
        
        with open(self.image_path, 'rb') as f:
            buffer = b''
            
            while True:
                chunk = f.read(self.chunk_size)
                if not chunk:
                    break
                
                buffer += chunk
                
                try:
                    text = buffer.decode('utf-8', errors='ignore')
                    
                    import re
                    url_pattern = r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+'
                    found_urls = re.findall(url_pattern, text)
                    
                    urls.update(found_urls)
                except:
                    pass
                
                buffer = buffer[-10000:]
        
        url_file = os.path.join(self.output_dir, 'urls.txt')
        
        with open(url_file, 'w') as f:
            for url in sorted(urls):
                f.write(url + '\n')
        
        print(f"\033[92m[+] Found {len(urls)} unique URLs\033[0m")
        print(f"\033[92m[+] URLs saved: {url_file}\033[0m")
    
    def analyze_file_system_structures(self):
        print(f"\033[93m[*] Analyzing file system structures...\033[0m")
        
        fs_signatures = {
            'NTFS': b'NTFS    ',
            'FAT32': b'FAT32   ',
            'FAT16': b'FAT16   ',
            'EXT2': b'\x53\xEF',
            'EXT3': b'\x53\xEF',
            'EXT4': b'\x53\xEF'
        }
        
        found_fs = []
        
        with open(self.image_path, 'rb') as f:
            for offset in [0, 512, 1024, 2048]:
                f.seek(offset)
                data = f.read(4096)
                
                for fs_type, signature in fs_signatures.items():
                    if signature in data:
                        found_fs.append({
                            'type': fs_type,
                            'offset': offset
                        })
                        print(f"\033[92m[+] Found {fs_type} at offset {offset}\033[0m")
        
        return found_fs
    
    def generate_report(self):
        report_file = os.path.join(self.output_dir, 'carving_report.json')
        
        file_types = defaultdict(int)
        total_size = 0
        
        for carved_file in self.carved_files:
            file_types[carved_file['type']] += 1
            total_size += carved_file['size']
        
        report = {
            'image_path': self.image_path,
            'image_size': os.path.getsize(self.image_path),
            'carving_date': datetime.now().isoformat(),
            'output_directory': self.output_dir,
            'summary': {
                'total_files_carved': len(self.carved_files),
                'total_size_carved': total_size,
                'file_types': dict(file_types)
            },
            'carved_files': self.carved_files[:100]
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n\033[92m[+] Report saved: {report_file}\033[0m")
        
        text_report = os.path.join(self.output_dir, 'carving_report.txt')
        
        with open(text_report, 'w') as f:
            f.write("="*80 + "\n")
            f.write("FILE CARVING ANALYSIS REPORT\n")
            f.write("="*80 + "\n\n")
            f.write(f"Image: {self.image_path}\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("="*80 + "\n")
            f.write("SUMMARY\n")
            f.write("="*80 + "\n")
            f.write(f"Total Files Carved: {len(self.carved_files)}\n")
            f.write(f"Total Size: {total_size / (1024**2):.2f} MB\n\n")
            
            f.write("File Types:\n")
            for file_type, count in sorted(file_types.items(), key=lambda x: x[1], reverse=True):
                f.write(f"  {file_type}: {count}\n")
            
            f.write("\n" + "="*80 + "\n")
            f.write("CARVED FILES (First 50)\n")
            f.write("="*80 + "\n")
            for carved_file in self.carved_files[:50]:
                f.write(f"\nFile: {carved_file['filename']}\n")
                f.write(f"  Type: {carved_file['type']}\n")
                f.write(f"  Offset: {carved_file['offset']}\n")
                f.write(f"  Size: {carved_file['size']} bytes\n")
                f.write(f"  MD5: {carved_file['md5']}\n")
        
        print(f"\033[92m[+] Text report saved: {text_report}\033[0m")

def run():
    print("\033[92m" + "="*70)
    print("     FILE CARVING TOOL")
    print("="*70 + "\033[0m\n")
    
    image_path = input("\033[95m[?] Enter disk image/memory dump path: \033[0m").strip()
    
    if not os.path.exists(image_path):
        print(f"\033[91m[!] File not found\033[0m")
        return
    
    carver = FileCarving(image_path)
    
    print("\n\033[97mCarving Options:\033[0m")
    print("\033[97m  [1] Carve all file types\033[0m")
    print("\033[97m  [2] Carve deleted files\033[0m")
    print("\033[97m  [3] Extract strings\033[0m")
    print("\033[97m  [4] Extract email addresses\033[0m")
    print("\033[97m  [5] Extract URLs\033[0m")
    print("\033[97m  [6] Full analysis (all of the above)\033[0m")
    
    choice = input(f"\n\033[95m[?] Select option: \033[0m").strip()
    
    if choice == '1':
        carver.carve_by_signature()
        carver.generate_report()
    
    elif choice == '2':
        carver.carve_deleted_files()
    
    elif choice == '3':
        min_len = input("\033[95m[?] Minimum string length (default 8): \033[0m").strip()
        min_len = int(min_len) if min_len.isdigit() else 8
        carver.carve_strings(min_len)
    
    elif choice == '4':
        carver.carve_email_addresses()
    
    elif choice == '5':
        carver.carve_urls()
    
    elif choice == '6':
        carver.carve_by_signature()
        carver.carve_strings()
        carver.carve_email_addresses()
        carver.carve_urls()
        carver.analyze_file_system_structures()
        carver.generate_report()
    
    print(f"\n\033[92m[+] Carving complete\033[0m")

if __name__ == "__main__":
    run()
