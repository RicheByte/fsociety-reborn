#!/usr/bin/env python3
import os
import sys
import json
import math
from collections import Counter, defaultdict
from datetime import datetime

class EntropyAnalyzer:
    def __init__(self):
        self.output_dir = f"entropy_analysis_{int(datetime.now().timestamp())}"
        self.results = defaultdict(dict)
        
    def calculate_shannon_entropy(self, data):
        if not data:
            return 0.0
        
        if isinstance(data, str):
            data = data.encode()
        
        counter = Counter(data)
        length = len(data)
        
        entropy = 0.0
        
        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def calculate_min_entropy(self, data):
        if not data:
            return 0.0
        
        if isinstance(data, str):
            data = data.encode()
        
        counter = Counter(data)
        length = len(data)
        
        max_probability = max(counter.values()) / length
        
        min_entropy = -math.log2(max_probability)
        
        return min_entropy
    
    def calculate_kolmogorov_complexity(self, data):
        if isinstance(data, str):
            data = data.encode()
        
        import zlib
        
        compressed = zlib.compress(data, level=9)
        
        complexity = len(compressed) / len(data)
        
        return complexity
    
    def chi_square_test(self, data):
        if isinstance(data, str):
            data = data.encode()
        
        counter = Counter(data)
        length = len(data)
        expected = length / 256
        
        chi_square = 0.0
        
        for i in range(256):
            observed = counter.get(i, 0)
            chi_square += ((observed - expected) ** 2) / expected
        
        degrees_of_freedom = 255
        critical_value = 293.25
        
        is_random = chi_square < critical_value
        
        return {
            'chi_square': chi_square,
            'degrees_of_freedom': degrees_of_freedom,
            'critical_value': critical_value,
            'is_random': is_random,
            'p_value': self.calculate_p_value(chi_square, degrees_of_freedom)
        }
    
    def calculate_p_value(self, chi_square, df):
        from math import exp, sqrt, pi
        
        if chi_square > 1000:
            return 0.0
        
        k = df / 2.0
        x = chi_square / 2.0
        
        if x == 0:
            return 1.0
        
        p = exp(-x)
        
        for i in range(1, int(k)):
            p *= x / i
        
        return 1 - p
    
    def runs_test(self, data):
        if isinstance(data, str):
            data = data.encode()
        
        median = sum(data) / len(data)
        
        runs = 1
        for i in range(1, len(data)):
            if (data[i] >= median) != (data[i-1] >= median):
                runs += 1
        
        n1 = sum(1 for b in data if b >= median)
        n2 = len(data) - n1
        
        expected_runs = (2 * n1 * n2) / (n1 + n2) + 1
        
        variance = (2 * n1 * n2 * (2 * n1 * n2 - n1 - n2)) / ((n1 + n2) ** 2 * (n1 + n2 - 1))
        
        if variance == 0:
            z_score = 0
        else:
            z_score = (runs - expected_runs) / math.sqrt(variance)
        
        is_random = abs(z_score) < 1.96
        
        return {
            'runs': runs,
            'expected_runs': expected_runs,
            'z_score': z_score,
            'is_random': is_random
        }
    
    def serial_correlation_test(self, data):
        if isinstance(data, str):
            data = data.encode()
        
        n = len(data)
        
        if n < 2:
            return {'correlation': 0.0, 'is_random': True}
        
        mean = sum(data) / n
        
        numerator = 0.0
        denominator = 0.0
        
        for i in range(n - 1):
            numerator += (data[i] - mean) * (data[i+1] - mean)
        
        for i in range(n):
            denominator += (data[i] - mean) ** 2
        
        if denominator == 0:
            correlation = 0.0
        else:
            correlation = (n * numerator) / ((n - 1) * denominator)
        
        is_random = abs(correlation) < 0.1
        
        return {
            'correlation': correlation,
            'is_random': is_random,
            'threshold': 0.1
        }
    
    def frequency_test(self, data):
        if isinstance(data, str):
            data = data.encode()
        
        bits = ''.join(format(byte, '08b') for byte in data)
        
        ones = bits.count('1')
        zeros = bits.count('0')
        
        total = len(bits)
        
        s = abs(ones - zeros) / math.sqrt(total)
        
        p_value = math.erfc(s / math.sqrt(2))
        
        is_random = p_value >= 0.01
        
        return {
            'ones': ones,
            'zeros': zeros,
            'ratio': ones / total if total > 0 else 0,
            'p_value': p_value,
            'is_random': is_random
        }
    
    def block_frequency_test(self, data, block_size=128):
        if isinstance(data, str):
            data = data.encode()
        
        bits = ''.join(format(byte, '08b') for byte in data)
        
        n = len(bits)
        m = block_size
        
        num_blocks = n // m
        
        if num_blocks == 0:
            return {'p_value': 1.0, 'is_random': True}
        
        chi_square = 0.0
        
        for i in range(num_blocks):
            block = bits[i*m:(i+1)*m]
            ones = block.count('1')
            pi = ones / m
            chi_square += (pi - 0.5) ** 2
        
        chi_square *= 4 * m
        
        p_value = self.calculate_p_value(chi_square, num_blocks)
        
        is_random = p_value >= 0.01
        
        return {
            'num_blocks': num_blocks,
            'chi_square': chi_square,
            'p_value': p_value,
            'is_random': is_random
        }
    
    def autocorrelation_test(self, data, lag=1):
        if isinstance(data, str):
            data = data.encode()
        
        n = len(data)
        
        if n <= lag:
            return {'correlation': 0.0, 'is_random': True}
        
        mean = sum(data) / n
        
        numerator = sum((data[i] - mean) * (data[i+lag] - mean) for i in range(n - lag))
        denominator = sum((data[i] - mean) ** 2 for i in range(n))
        
        if denominator == 0:
            correlation = 0.0
        else:
            correlation = numerator / denominator
        
        is_random = abs(correlation) < 0.1
        
        return {
            'lag': lag,
            'correlation': correlation,
            'is_random': is_random
        }
    
    def longest_run_test(self, data):
        if isinstance(data, str):
            data = data.encode()
        
        bits = ''.join(format(byte, '08b') for byte in data)
        
        longest_run_ones = 0
        longest_run_zeros = 0
        
        current_run_ones = 0
        current_run_zeros = 0
        
        for bit in bits:
            if bit == '1':
                current_run_ones += 1
                current_run_zeros = 0
                longest_run_ones = max(longest_run_ones, current_run_ones)
            else:
                current_run_zeros += 1
                current_run_ones = 0
                longest_run_zeros = max(longest_run_zeros, current_run_zeros)
        
        n = len(bits)
        expected_run = math.log2(n)
        
        is_random = (longest_run_ones < 2 * expected_run) and (longest_run_zeros < 2 * expected_run)
        
        return {
            'longest_run_ones': longest_run_ones,
            'longest_run_zeros': longest_run_zeros,
            'expected_run': expected_run,
            'is_random': is_random
        }
    
    def analyze_file(self, file_path, sample_size=None):
        print(f"\033[93m[*] Analyzing file: {file_path}\033[0m")
        
        try:
            with open(file_path, 'rb') as f:
                if sample_size:
                    data = f.read(sample_size)
                else:
                    data = f.read()
        except Exception as e:
            print(f"\033[91m[!] Error reading file: {e}\033[0m")
            return None
        
        print(f"\033[97m  Data size: {len(data)} bytes\033[0m")
        
        results = {}
        
        print(f"\n\033[93m[*] Shannon entropy...\033[0m")
        results['shannon_entropy'] = self.calculate_shannon_entropy(data)
        print(f"\033[97m  {results['shannon_entropy']:.6f} bits/byte\033[0m")
        
        print(f"\n\033[93m[*] Min entropy...\033[0m")
        results['min_entropy'] = self.calculate_min_entropy(data)
        print(f"\033[97m  {results['min_entropy']:.6f} bits/byte\033[0m")
        
        print(f"\n\033[93m[*] Kolmogorov complexity...\033[0m")
        results['kolmogorov_complexity'] = self.calculate_kolmogorov_complexity(data)
        print(f"\033[97m  {results['kolmogorov_complexity']:.6f}\033[0m")
        
        print(f"\n\033[93m[*] Chi-square test...\033[0m")
        results['chi_square'] = self.chi_square_test(data)
        print(f"\033[97m  χ² = {results['chi_square']['chi_square']:.2f}\033[0m")
        print(f"\033[97m  Random: {results['chi_square']['is_random']}\033[0m")
        
        print(f"\n\033[93m[*] Runs test...\033[0m")
        results['runs_test'] = self.runs_test(data)
        print(f"\033[97m  Runs: {results['runs_test']['runs']}\033[0m")
        print(f"\033[97m  Random: {results['runs_test']['is_random']}\033[0m")
        
        print(f"\n\033[93m[*] Serial correlation test...\033[0m")
        results['serial_correlation'] = self.serial_correlation_test(data)
        print(f"\033[97m  Correlation: {results['serial_correlation']['correlation']:.6f}\033[0m")
        print(f"\033[97m  Random: {results['serial_correlation']['is_random']}\033[0m")
        
        print(f"\n\033[93m[*] Frequency test...\033[0m")
        results['frequency'] = self.frequency_test(data)
        print(f"\033[97m  1s/0s ratio: {results['frequency']['ratio']:.6f}\033[0m")
        print(f"\033[97m  Random: {results['frequency']['is_random']}\033[0m")
        
        print(f"\n\033[93m[*] Longest run test...\033[0m")
        results['longest_run'] = self.longest_run_test(data)
        print(f"\033[97m  Longest 1s: {results['longest_run']['longest_run_ones']}\033[0m")
        print(f"\033[97m  Longest 0s: {results['longest_run']['longest_run_zeros']}\033[0m")
        print(f"\033[97m  Random: {results['longest_run']['is_random']}\033[0m")
        
        self.results[file_path] = results
        
        return results
    
    def analyze_string(self, data_string):
        print(f"\033[93m[*] Analyzing string data...\033[0m")
        
        data = data_string.encode()
        
        print(f"\033[97m  Data size: {len(data)} bytes\033[0m")
        
        results = {}
        
        results['shannon_entropy'] = self.calculate_shannon_entropy(data)
        results['min_entropy'] = self.calculate_min_entropy(data)
        results['kolmogorov_complexity'] = self.calculate_kolmogorov_complexity(data)
        results['chi_square'] = self.chi_square_test(data)
        results['frequency'] = self.frequency_test(data)
        
        print(f"\n\033[97m  Shannon Entropy: {results['shannon_entropy']:.6f}\033[0m")
        print(f"\033[97m  Min Entropy: {results['min_entropy']:.6f}\033[0m")
        print(f"\033[97m  Kolmogorov: {results['kolmogorov_complexity']:.6f}\033[0m")
        print(f"\033[97m  Chi-square Random: {results['chi_square']['is_random']}\033[0m")
        print(f"\033[97m  Frequency Random: {results['frequency']['is_random']}\033[0m")
        
        return results
    
    def compare_prng_quality(self, generators):
        print(f"\033[93m[*] Comparing PRNG quality...\033[0m")
        
        comparison = {}
        
        for name, generator in generators.items():
            print(f"\n\033[97m  Testing: {name}\033[0m")
            
            data = bytes(generator(1024))
            
            shannon = self.calculate_shannon_entropy(data)
            chi_result = self.chi_square_test(data)
            runs_result = self.runs_test(data)
            
            score = 0
            if shannon > 7.9:
                score += 1
            if chi_result['is_random']:
                score += 1
            if runs_result['is_random']:
                score += 1
            
            comparison[name] = {
                'shannon_entropy': shannon,
                'chi_square_random': chi_result['is_random'],
                'runs_random': runs_result['is_random'],
                'quality_score': score
            }
            
            print(f"\033[97m    Quality score: {score}/3\033[0m")
        
        self.results['prng_comparison'] = comparison
        
        return comparison
    
    def estimate_key_space(self, password):
        print(f"\033[93m[*] Estimating key space for password...\033[0m")
        
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        charset_size = 0
        if has_lower:
            charset_size += 26
        if has_upper:
            charset_size += 26
        if has_digit:
            charset_size += 10
        if has_special:
            charset_size += 32
        
        length = len(password)
        
        key_space = charset_size ** length
        
        entropy = math.log2(key_space) if key_space > 0 else 0
        
        results = {
            'length': length,
            'charset_size': charset_size,
            'key_space': key_space,
            'entropy_bits': entropy,
            'has_lowercase': has_lower,
            'has_uppercase': has_upper,
            'has_digits': has_digit,
            'has_special': has_special
        }
        
        print(f"\033[97m  Length: {length}\033[0m")
        print(f"\033[97m  Charset size: {charset_size}\033[0m")
        print(f"\033[97m  Key space: 10^{math.log10(key_space):.2f}\033[0m")
        print(f"\033[97m  Entropy: {entropy:.2f} bits\033[0m")
        
        return results
    
    def generate_report(self):
        os.makedirs(self.output_dir, exist_ok=True)
        
        report_file = os.path.join(self.output_dir, 'entropy_report.json')
        
        report = {
            'analysis_date': datetime.now().isoformat(),
            'output_directory': self.output_dir,
            'results': dict(self.results)
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n\033[92m[+] Report saved: {report_file}\033[0m")

def run():
    print("\033[92m" + "="*70)
    print("     CRYPTOGRAPHIC ENTROPY ANALYZER")
    print("="*70 + "\033[0m\n")
    
    analyzer = EntropyAnalyzer()
    
    print("\033[97mEntropy Analysis Options:\033[0m")
    print("\033[97m  [1] Analyze file\033[0m")
    print("\033[97m  [2] Analyze string\033[0m")
    print("\033[97m  [3] Estimate password key space\033[0m")
    print("\033[97m  [4] Quick randomness test\033[0m")
    
    choice = input(f"\n\033[95m[?] Select option: \033[0m").strip()
    
    if choice == '1':
        file_path = input("\033[95m[?] File path: \033[0m").strip()
        
        if not os.path.exists(file_path):
            print(f"\033[91m[!] File not found\033[0m")
            return
        
        sample_input = input("\033[95m[?] Sample size in bytes (press Enter for full file): \033[0m").strip()
        sample_size = int(sample_input) if sample_input else None
        
        analyzer.analyze_file(file_path, sample_size)
        analyzer.generate_report()
    
    elif choice == '2':
        data = input("\033[95m[?] String to analyze: \033[0m").strip()
        
        analyzer.analyze_string(data)
        analyzer.generate_report()
    
    elif choice == '3':
        password = input("\033[95m[?] Password to analyze: \033[0m").strip()
        
        analyzer.estimate_key_space(password)
        analyzer.generate_report()
    
    elif choice == '4':
        data = input("\033[95m[?] Data to test: \033[0m").strip()
        
        print(f"\n\033[93m[*] Quick randomness test...\033[0m")
        
        shannon = analyzer.calculate_shannon_entropy(data)
        chi = analyzer.chi_square_test(data)
        
        print(f"\n\033[97m  Shannon entropy: {shannon:.6f}\033[0m")
        print(f"\033[97m  Chi-square random: {chi['is_random']}\033[0m")
        
        if shannon > 7.5 and chi['is_random']:
            print(f"\n\033[92m[+] Data appears random\033[0m")
        else:
            print(f"\n\033[91m[-] Data may not be random\033[0m")
    
    print(f"\n\033[92m[+] Done\033[0m")

if __name__ == "__main__":
    run()
