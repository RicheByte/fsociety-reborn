#!/usr/bin/env python3
import os
import hashlib
import json
import struct
from datetime import datetime
from collections import defaultdict

class SteganographyDetector:
    def __init__(self, file_path):
        self.file_path = file_path
        self.file_type = self.identify_file_type()
        self.results = defaultdict(list)
        self.output_dir = f"steg_analysis_{int(datetime.now().timestamp())}"
    
    def identify_file_type(self):
        with open(self.file_path, 'rb') as f:
            header = f.read(16)
        
        signatures = {
            b'\xFF\xD8\xFF': 'JPEG',
            b'\x89PNG\r\n\x1a\n': 'PNG',
            b'GIF87a': 'GIF',
            b'GIF89a': 'GIF',
            b'RIFF': 'WAV',
            b'ID3': 'MP3',
            b'\xFF\xFB': 'MP3',
            b'BM': 'BMP',
            b'%PDF': 'PDF'
        }
        
        for sig, file_type in signatures.items():
            if header.startswith(sig):
                return file_type
        
        return 'Unknown'
    
    def analyze_lsb(self):
        print(f"\033[93m[*] Analyzing LSB (Least Significant Bit)...\033[0m")
        
        if self.file_type not in ['PNG', 'BMP', 'JPEG']:
            print(f"\033[91m[!] LSB analysis only for images\033[0m")
            return
        
        try:
            from PIL import Image
            
            img = Image.open(self.file_path)
            pixels = list(img.getdata())
            
            lsb_data = []
            
            for pixel in pixels[:10000]:
                if isinstance(pixel, tuple):
                    for value in pixel:
                        lsb_data.append(value & 1)
                else:
                    lsb_data.append(pixel & 1)
            
            byte_data = []
            for i in range(0, len(lsb_data) - 8, 8):
                byte = 0
                for j in range(8):
                    byte |= (lsb_data[i + j] << j)
                byte_data.append(byte)
            
            text = bytes(byte_data).decode('utf-8', errors='ignore')
            
            if any(c.isprintable() for c in text[:100]):
                self.results['lsb']['suspicious'] = True
                self.results['lsb']['sample'] = text[:200]
                print(f"\033[92m[+] Suspicious LSB pattern detected\033[0m")
            else:
                self.results['lsb']['suspicious'] = False
                print(f"\033[97m[*] No obvious LSB steganography\033[0m")
            
            ones_count = sum(lsb_data)
            zeros_count = len(lsb_data) - ones_count
            
            ratio = ones_count / len(lsb_data) if len(lsb_data) > 0 else 0
            
            if abs(ratio - 0.5) < 0.05:
                self.results['lsb']['random_pattern'] = True
                print(f"\033[92m[+] Random LSB pattern detected (possible encryption)\033[0m")
            
            self.results['lsb']['ratio'] = ratio
            
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
    
    def check_metadata_anomalies(self):
        print(f"\033[93m[*] Checking metadata anomalies...\033[0m")
        
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS
            
            img = Image.open(self.file_path)
            
            exif_data = img._getexif()
            
            if exif_data:
                metadata = {}
                
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)
                    metadata[tag] = str(value)[:200]
                
                self.results['metadata']['exif'] = metadata
                
                suspicious_fields = []
                
                for key, value in metadata.items():
                    if len(value) > 100:
                        suspicious_fields.append({
                            'field': key,
                            'length': len(value),
                            'sample': value[:50]
                        })
                
                if suspicious_fields:
                    self.results['metadata']['suspicious_fields'] = suspicious_fields
                    print(f"\033[92m[+] Found {len(suspicious_fields)} suspicious metadata fields\033[0m")
                else:
                    print(f"\033[97m[*] No suspicious metadata found\033[0m")
            else:
                print(f"\033[97m[*] No EXIF data found\033[0m")
        
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
    
    def analyze_file_structure(self):
        print(f"\033[93m[*] Analyzing file structure...\033[0m")
        
        file_size = os.path.getsize(self.file_path)
        
        with open(self.file_path, 'rb') as f:
            data = f.read()
        
        null_bytes = data.count(b'\x00')
        null_ratio = null_bytes / file_size
        
        if null_ratio > 0.3:
            self.results['structure']['high_null_bytes'] = True
            print(f"\033[92m[+] High null byte ratio: {null_ratio:.2%}\033[0m")
        
        entropy = self.calculate_entropy(data)
        self.results['structure']['entropy'] = entropy
        
        if entropy > 7.5:
            print(f"\033[92m[+] High entropy detected: {entropy:.2f} (possible encryption)\033[0m")
        elif entropy < 3.0:
            print(f"\033[97m[*] Low entropy: {entropy:.2f}\033[0m")
        else:
            print(f"\033[97m[*] Normal entropy: {entropy:.2f}\033[0m")
        
        suspicious_strings = []
        
        try:
            text = data.decode('utf-8', errors='ignore')
            
            keywords = ['password', 'secret', 'hidden', 'steganography', 'encrypted', 'base64']
            
            for keyword in keywords:
                if keyword.lower() in text.lower():
                    suspicious_strings.append(keyword)
            
            if suspicious_strings:
                self.results['structure']['suspicious_strings'] = suspicious_strings
                print(f"\033[92m[+] Found suspicious strings: {', '.join(suspicious_strings)}\033[0m")
        except:
            pass
    
    def calculate_entropy(self, data):
        if not data:
            return 0
        
        frequency = defaultdict(int)
        for byte in data:
            frequency[byte] += 1
        
        entropy = 0
        data_len = len(data)
        
        for count in frequency.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * (probability.bit_length() - 1)
        
        import math
        return entropy / math.log(2, 256) * 8
    
    def detect_appended_data(self):
        print(f"\033[93m[*] Detecting appended data...\033[0m")
        
        with open(self.file_path, 'rb') as f:
            data = f.read()
        
        end_markers = {
            'JPEG': b'\xFF\xD9',
            'PNG': b'IEND\xAE\x42\x60\x82',
            'GIF': b'\x00\x3B',
            'PDF': b'%%EOF'
        }
        
        if self.file_type in end_markers:
            marker = end_markers[self.file_type]
            
            marker_pos = data.rfind(marker)
            
            if marker_pos != -1:
                expected_end = marker_pos + len(marker)
                actual_end = len(data)
                
                if actual_end > expected_end:
                    appended_size = actual_end - expected_end
                    
                    self.results['appended']['detected'] = True
                    self.results['appended']['size'] = appended_size
                    self.results['appended']['data_sample'] = data[expected_end:expected_end + 100].hex()
                    
                    print(f"\033[92m[+] Appended data detected: {appended_size} bytes\033[0m")
                    
                    os.makedirs(self.output_dir, exist_ok=True)
                    
                    appended_file = os.path.join(self.output_dir, 'appended_data.bin')
                    
                    with open(appended_file, 'wb') as f:
                        f.write(data[expected_end:])
                    
                    print(f"\033[92m[+] Appended data saved: {appended_file}\033[0m")
                else:
                    print(f"\033[97m[*] No appended data detected\033[0m")
            else:
                print(f"\033[97m[*] End marker not found\033[0m")
        else:
            print(f"\033[97m[*] File type not supported for append detection\033[0m")
    
    def analyze_color_palette(self):
        print(f"\033[93m[*] Analyzing color palette...\033[0m")
        
        if self.file_type not in ['PNG', 'BMP', 'GIF']:
            print(f"\033[91m[!] Palette analysis only for PNG/BMP/GIF\033[0m")
            return
        
        try:
            from PIL import Image
            
            img = Image.open(self.file_path)
            
            if img.mode == 'P':
                palette = img.getpalette()
                
                if palette:
                    unique_colors = len(set(palette))
                    
                    self.results['palette']['unique_colors'] = unique_colors
                    
                    print(f"\033[97m[*] Unique palette colors: {unique_colors}\033[0m")
                    
                    if unique_colors < 10:
                        print(f"\033[92m[+] Limited palette (possible palette-based steganography)\033[0m")
            else:
                pixels = list(img.getdata())
                unique_pixels = len(set(pixels[:10000]))
                
                self.results['palette']['unique_pixels_sample'] = unique_pixels
                
                print(f"\033[97m[*] Unique pixel values in sample: {unique_pixels}\033[0m")
        
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
    
    def check_audio_anomalies(self):
        print(f"\033[93m[*] Checking audio anomalies...\033[0m")
        
        if self.file_type not in ['WAV', 'MP3']:
            print(f"\033[91m[!] Audio analysis only for WAV/MP3\033[0m")
            return
        
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()
            
            if self.file_type == 'WAV':
                if len(data) > 44:
                    header = data[:44]
                    
                    riff = header[0:4]
                    file_size = struct.unpack('<I', header[4:8])[0]
                    wave = header[8:12]
                    
                    actual_size = len(data) - 8
                    
                    if abs(file_size - actual_size) > 100:
                        self.results['audio']['size_mismatch'] = True
                        print(f"\033[92m[+] WAV size mismatch detected\033[0m")
                    
                    audio_data = data[44:]
                    
                    lsb_bits = []
                    for i in range(min(10000, len(audio_data))):
                        lsb_bits.append(audio_data[i] & 1)
                    
                    ones = sum(lsb_bits)
                    ratio = ones / len(lsb_bits) if lsb_bits else 0
                    
                    if abs(ratio - 0.5) < 0.05:
                        self.results['audio']['random_lsb'] = True
                        print(f"\033[92m[+] Random LSB pattern in audio\033[0m")
            
            print(f"\033[97m[*] Audio analysis complete\033[0m")
        
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
    
    def detect_known_tools(self):
        print(f"\033[93m[*] Detecting known steganography tool signatures...\033[0m")
        
        tool_signatures = {
            'steghide': [b'steghide', b'STEGHIDE'],
            'openstego': [b'OpenStego', b'openstego'],
            'outguess': [b'OutGuess', b'outguess'],
            'jphide': [b'JPHIDE', b'jphide'],
            'f5': [b'F5-steganography'],
            'camouflage': [b'camouflage'],
            'snow': [b'SNOW', b'whitespace'],
            'stegdetect': [b'stegdetect'],
            'invisible_secrets': [b'invisible secrets'],
            's-tools': [b's-tools', b'S-TOOLS']
        }
        
        with open(self.file_path, 'rb') as f:
            data = f.read()
        
        detected_tools = []
        
        for tool, signatures in tool_signatures.items():
            for sig in signatures:
                if sig.lower() in data.lower():
                    detected_tools.append(tool)
                    break
        
        if detected_tools:
            self.results['tools']['detected'] = detected_tools
            print(f"\033[92m[+] Detected tool signatures: {', '.join(detected_tools)}\033[0m")
        else:
            print(f"\033[97m[*] No known tool signatures detected\033[0m")
    
    def analyze_dct_coefficients(self):
        print(f"\033[93m[*] Analyzing DCT coefficients (JPEG steganography)...\033[0m")
        
        if self.file_type != 'JPEG':
            return
        
        try:
            from PIL import Image
            import numpy as np
            
            img = Image.open(self.file_path)
            
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            pixels = np.array(img)
            
            height, width = pixels.shape[:2]
            
            suspicious_blocks = 0
            
            for i in range(0, height - 8, 8):
                for j in range(0, width - 8, 8):
                    block = pixels[i:i+8, j:j+8, 0]
                    
                    if np.std(block) < 5:
                        suspicious_blocks += 1
            
            if suspicious_blocks > (height * width) // (8 * 8) * 0.1:
                self.results['dct']['suspicious_blocks'] = suspicious_blocks
                print(f"\033[92m[+] High number of suspicious DCT blocks: {suspicious_blocks}\033[0m")
            else:
                print(f"\033[97m[*] DCT analysis normal\033[0m")
        
        except Exception as e:
            pass
    
    def statistical_analysis(self):
        print(f"\033[93m[*] Performing statistical analysis...\033[0m")
        
        with open(self.file_path, 'rb') as f:
            data = f.read(100000)
        
        byte_freq = defaultdict(int)
        for byte in data:
            byte_freq[byte] += 1
        
        chi_square = 0
        expected = len(data) / 256
        
        for count in byte_freq.values():
            chi_square += ((count - expected) ** 2) / expected
        
        self.results['statistics']['chi_square'] = chi_square
        
        if chi_square < 200:
            print(f"\033[92m[+] Low chi-square: {chi_square:.2f} (possible random data)\033[0m")
        else:
            print(f"\033[97m[*] Chi-square: {chi_square:.2f}\033[0m")
        
        pairs = defaultdict(int)
        for i in range(len(data) - 1):
            pair = (data[i], data[i + 1])
            pairs[pair] += 1
        
        unique_pairs = len(pairs)
        possible_pairs = 256 * 256
        
        pair_diversity = unique_pairs / possible_pairs
        
        self.results['statistics']['pair_diversity'] = pair_diversity
        
        print(f"\033[97m[*] Byte pair diversity: {pair_diversity:.4f}\033[0m")
    
    def generate_report(self):
        os.makedirs(self.output_dir, exist_ok=True)
        
        report_file = os.path.join(self.output_dir, 'steganography_report.json')
        
        report = {
            'file_path': self.file_path,
            'file_type': self.file_type,
            'file_size': os.path.getsize(self.file_path),
            'file_hash': self.hash_file(self.file_path),
            'analysis_date': datetime.now().isoformat(),
            'findings': dict(self.results)
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n\033[92m[+] Report saved: {report_file}\033[0m")
        
        text_report = os.path.join(self.output_dir, 'steganography_report.txt')
        
        with open(text_report, 'w') as f:
            f.write("="*80 + "\n")
            f.write("STEGANOGRAPHY DETECTION ANALYSIS REPORT\n")
            f.write("="*80 + "\n\n")
            f.write(f"File: {self.file_path}\n")
            f.write(f"Type: {self.file_type}\n")
            f.write(f"Size: {os.path.getsize(self.file_path)} bytes\n")
            f.write(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("="*80 + "\n")
            f.write("FINDINGS\n")
            f.write("="*80 + "\n")
            
            for category, findings in self.results.items():
                f.write(f"\n{category.upper()}:\n")
                for key, value in findings.items():
                    f.write(f"  {key}: {value}\n")
        
        print(f"\033[92m[+] Text report saved: {text_report}\033[0m")
    
    def hash_file(self, file_path):
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        
        return sha256.hexdigest()

def run():
    print("\033[92m" + "="*70)
    print("     STEGANOGRAPHY DETECTION TOOL")
    print("="*70 + "\033[0m\n")
    
    file_path = input("\033[95m[?] Enter file path: \033[0m").strip()
    
    if not os.path.exists(file_path):
        print(f"\033[91m[!] File not found\033[0m")
        return
    
    detector = SteganographyDetector(file_path)
    
    print(f"\n\033[97mFile Type: {detector.file_type}\033[0m")
    print(f"\033[97mFile Size: {os.path.getsize(file_path) / 1024:.2f} KB\033[0m\n")
    
    detector.analyze_lsb()
    detector.check_metadata_anomalies()
    detector.analyze_file_structure()
    detector.detect_appended_data()
    detector.analyze_color_palette()
    detector.check_audio_anomalies()
    detector.detect_known_tools()
    detector.statistical_analysis()
    
    detector.generate_report()
    
    print(f"\n\033[92m[+] Analysis complete\033[0m")

if __name__ == "__main__":
    run()
