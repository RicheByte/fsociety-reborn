"""
Phone Number Intelligence Tool
Phone number analysis and carrier lookup
"""
import re
import requests
import json

class PhoneIntelligence:
    def __init__(self):
        self.phone_info = {}
        
    def parse_phone_number(self, phone: str) -> dict:
        """Parse and validate phone number"""
        # Remove all non-digit characters
        digits = re.sub(r'\D', '', phone)
        
        info = {
            'original': phone,
            'digits_only': digits,
            'valid': False,
            'country_code': None,
            'area_code': None,
            'local_number': None
        }
        
        # Basic validation (10-15 digits is common for phone numbers)
        if 10 <= len(digits) <= 15:
            info['valid'] = True
            
            # Try to identify country code
            if len(digits) == 11 and digits.startswith('1'):
                info['country_code'] = '1'  # US/Canada
                info['area_code'] = digits[1:4]
                info['local_number'] = digits[4:]
            elif len(digits) == 10:
                # Assume US/Canada without country code
                info['country_code'] = '1'
                info['area_code'] = digits[0:3]
                info['local_number'] = digits[3:]
            else:
                # International number
                if len(digits) >= 11:
                    info['country_code'] = digits[0:2]
                    info['area_code'] = digits[2:5]
                    info['local_number'] = digits[5:]
        
        return info
    
    def identify_carrier(self, phone: str) -> str:
        """Identify carrier from phone number patterns (US-based)"""
        parsed = self.parse_phone_number(phone)
        
        if not parsed['valid']:
            return "Invalid phone number"
        
        area_code = parsed['area_code']
        
        # This is simplified - real carrier detection requires databases
        print(f"\n\033[93m[*] Analyzing phone number: {phone}\033[0m\n")
        print(f"\033[97m  Digits Only: {parsed['digits_only']}\033[0m")
        print(f"\033[97m  Country Code: +{parsed['country_code']}\033[0m")
        print(f"\033[97m  Area Code: {parsed['area_code']}\033[0m")
        print(f"\033[97m  Local Number: {parsed['local_number']}\033[0m")
        
        # Note: Real carrier detection would use a database or API
        print(f"\n\033[97m[*] Carrier detection requires specialized databases\033[0m")
        print(f"\033[97m[*] For accurate results, use services like Twilio Lookup API\033[0m")
        
        return parsed
    
    def get_area_code_info(self, area_code: str):
        """Get information about area code"""
        # Common US area codes database (simplified)
        area_codes = {
            '212': 'New York, NY',
            '213': 'Los Angeles, CA',
            '310': 'Los Angeles, CA',
            '312': 'Chicago, IL',
            '415': 'San Francisco, CA',
            '510': 'Oakland, CA',
            '617': 'Boston, MA',
            '202': 'Washington, DC',
            '305': 'Miami, FL',
            '404': 'Atlanta, GA',
            '512': 'Austin, TX',
            '214': 'Dallas, TX',
            '713': 'Houston, TX',
            '206': 'Seattle, WA',
            '303': 'Denver, CO',
            '702': 'Las Vegas, NV',
            '480': 'Phoenix, AZ',
            '858': 'San Diego, CA',
            '503': 'Portland, OR',
            '602': 'Phoenix, AZ'
        }
        
        location = area_codes.get(area_code, 'Unknown')
        
        print(f"\n\033[92m[+] Area Code Information:\033[0m")
        print(f"\033[97m  Area Code: {area_code}\033[0m")
        print(f"\033[97m  Location: {location}\033[0m")
        
        return location
    
    def format_phone_number(self, phone: str, format_type: str = 'US'):
        """Format phone number in different styles"""
        parsed = self.parse_phone_number(phone)
        
        if not parsed['valid']:
            return "Invalid phone number"
        
        digits = parsed['digits_only']
        
        formats = {}
        
        if parsed['country_code'] == '1' and len(digits) in [10, 11]:
            # US/Canada formatting
            if len(digits) == 11:
                formats['E.164'] = f"+{digits}"
                formats['National'] = f"({digits[1:4]}) {digits[4:7]}-{digits[7:]}"
                formats['International'] = f"+{digits[0]} ({digits[1:4]}) {digits[4:7]}-{digits[7:]}"
            else:
                formats['E.164'] = f"+1{digits}"
                formats['National'] = f"({digits[0:3]}) {digits[3:6]}-{digits[6:]}"
                formats['International'] = f"+1 ({digits[0:3]}) {digits[3:6]}-{digits[6:]}"
        else:
            formats['E.164'] = f"+{digits}"
            formats['Digits'] = digits
        
        print(f"\n\033[92m[+] Phone Number Formats:\033[0m")
        for format_name, formatted in formats.items():
            print(f"\033[97m  {format_name}: {formatted}\033[0m")
        
        return formats
    
    def check_phone_type(self, phone: str):
        """Determine if phone is mobile, landline, or VoIP"""
        parsed = self.parse_phone_number(phone)
        
        print(f"\n\033[93m[*] Checking phone type...\033[0m\n")
        
        # This is simplified - real detection requires carrier databases
        print(f"\033[97m[*] Phone type detection requires carrier databases or APIs\033[0m")
        print(f"\033[97m[*] Common patterns:\033[0m")
        print(f"\033[97m    - Mobile: Typically assigned by carrier\033[0m")
        print(f"\033[97m    - Landline: Geographic area codes\033[0m")
        print(f"\033[97m    - VoIP: Services like Google Voice, Skype\033[0m")
        
        return "Requires API/Database"
    
    def reverse_phone_lookup(self, phone: str):
        """Attempt reverse phone lookup"""
        print(f"\n\033[93m[*] Performing reverse lookup for: {phone}\033[0m\n")
        
        parsed = self.parse_phone_number(phone)
        
        if parsed['valid']:
            # Generate search URLs
            search_urls = [
                f"https://www.google.com/search?q={parsed['digits_only']}",
                f"https://www.whitepages.com/phone/{parsed['digits_only']}",
                f"https://www.truecaller.com/search/us/{parsed['digits_only']}"
            ]
            
            print(f"\033[92m[+] Search URLs for manual lookup:\033[0m\n")
            for url in search_urls:
                print(f"\033[97m  {url}\033[0m")
            
            print(f"\n\033[97m[*] Note: Most reverse lookup services require registration\033[0m")
        else:
            print(f"\033[91m[!] Invalid phone number format\033[0m")
    
    def batch_analysis(self, phone_numbers: list):
        """Analyze multiple phone numbers"""
        print(f"\n\033[93m[*] Analyzing {len(phone_numbers)} phone numbers...\033[0m\n")
        
        results = []
        
        for phone in phone_numbers:
            parsed = self.parse_phone_number(phone)
            results.append(parsed)
            
            if parsed['valid']:
                print(f"\033[92m[+] {phone} -> Valid\033[0m")
                print(f"\033[97m    Area Code: {parsed['area_code']}\033[0m")
            else:
                print(f"\033[91m[!] {phone} -> Invalid\033[0m")
            print()
        
        return results
    
    def save_results(self, output_file: str, data: dict):
        """Save analysis results"""
        try:
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=4)
            print(f"\n\033[92m[+] Results saved to: {output_file}\033[0m")
        except Exception as e:
            print(f"\n\033[91m[!] Error saving results: {e}\033[0m")

def run():
    """Main function"""
    print("\033[92m" + "="*70)
    print("           PHONE NUMBER INTELLIGENCE TOOL")
    print("="*70 + "\033[0m\n")
    
    print("\033[97mSelect option:\033[0m")
    print("  [1] Analyze single phone number")
    print("  [2] Area code lookup")
    print("  [3] Format phone number")
    print("  [4] Reverse phone lookup")
    print("  [5] Batch analysis (multiple numbers)")
    
    option = input("\n\033[95m[?] Select option (1-5): \033[0m").strip()
    
    tool = PhoneIntelligence()
    
    if option == '1':
        phone = input("\033[95m[?] Enter phone number: \033[0m").strip()
        tool.identify_carrier(phone)
        tool.check_phone_type(phone)
    
    elif option == '2':
        area_code = input("\033[95m[?] Enter area code (3 digits): \033[0m").strip()
        tool.get_area_code_info(area_code)
    
    elif option == '3':
        phone = input("\033[95m[?] Enter phone number: \033[0m").strip()
        tool.format_phone_number(phone)
    
    elif option == '4':
        phone = input("\033[95m[?] Enter phone number: \033[0m").strip()
        tool.reverse_phone_lookup(phone)
    
    elif option == '5':
        print("\033[97m[*] Enter phone numbers (one per line, empty line to finish):\033[0m")
        phones = []
        while True:
            phone = input("\033[95m    > \033[0m").strip()
            if not phone:
                break
            phones.append(phone)
        
        if phones:
            results = tool.batch_analysis(phones)
            
            save = input("\n\033[95m[?] Save results to file? (y/n): \033[0m").strip().lower()
            if save == 'y':
                filename = input("\033[95m[?] Enter filename (default: phone_analysis.json): \033[0m").strip()
                filename = filename if filename else "phone_analysis.json"
                tool.save_results(filename, results)
    
    print("\n" + "\033[92m" + "="*70)
    print("           ANALYSIS COMPLETE")
    print("="*70 + "\033[0m")

if __name__ == "__main__":
    run()
