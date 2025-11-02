# FSociety - OSINT Toolkit

```
 ███╗   ███╗██████╗        ██████╗  ██████╗ ██████╗  ██████╗ ████████╗
 ████╗ ████║██╔══██╗       ██╔══██╗██╔═══██╗██╔══██╗██╔═══██╗╚══██╔══╝
 ██╔████╔██║██████╔╝       ██████╔╝██║   ██║██████╔╝██║   ██║   ██║   
 ██║╚██╔╝██║██╔══██╗       ██╔══██╗██║   ██║██╔══██╗██║   ██║   ██║   
 ██║ ╚═╝ ██║██║  ██║██╗    ██║  ██║╚██████╔╝██████╔╝╚██████╔╝   ██║   
 ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝    ╚═╝  ╚═╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝   
```

A comprehensive OSINT (Open-Source Intelligence) toolkit inspired by the TV series Mr. Robot. This collection of tools is designed for cybersecurity professionals, penetration testers, and security researchers.

## ⚠️ DISCLAIMER

**This toolkit is for EDUCATIONAL and AUTHORIZED TESTING purposes ONLY.**

- Only use these tools on systems you own or have explicit permission to test
- Unauthorized access to computer systems is illegal
- The authors are not responsible for misuse of these tools
- Always comply with local laws and regulations

## 🚀 Features

FSociety includes 10 powerful OSINT tools organized in a single interactive menu:

### 1. **Subdomain Discovery Tool**
- DNS-based subdomain enumeration
- Multi-threaded scanning
- Custom wordlist support
- Export results to CSV

**Use Cases:**
- Map target organization's web infrastructure
- Discover hidden subdomains and services
- Security assessment of domain configurations

### 2. **Email Address Harvester**
- Web scraping from websites
- Common email pattern generation
- DNS record extraction
- Multiple harvesting methods

**Use Cases:**
- Phishing awareness campaigns
- Contact discovery
- Open-source intelligence gathering

### 3. **Social Media Scraper**
- Twitter/X profile information
- GitHub user details and repositories
- Instagram, Reddit, LinkedIn lookups
- Multiple platform support

**Use Cases:**
- Profile investigation
- Social engineering reconnaissance
- Digital footprint analysis

### 4. **Domain & IP Information Tool**
- WHOIS lookups
- IP geolocation
- DNS record enumeration
- Port scanning
- Reverse DNS lookup

**Use Cases:**
- Infrastructure mapping
- Domain ownership verification
- Network reconnaissance

### 5. **Pastebin & Leak Monitor**
- Paste site scanning
- Keyword monitoring
- Email leak detection
- GitHub code search
- Real-time monitoring

**Use Cases:**
- Credential leak detection
- Data breach monitoring
- Security incident response

### 6. **Phone Number Intelligence**
- Phone number parsing and validation
- Area code lookup
- Number formatting (E.164, National, International)
- Batch analysis
- Carrier identification patterns

**Use Cases:**
- Phone number verification
- OSINT investigations
- Contact information validation

### 7. **Image Metadata Analyzer**
- EXIF data extraction
- GPS coordinate recovery
- Camera information
- Metadata stripping
- Batch image analysis

**Use Cases:**
- Digital forensics
- Location tracking
- Privacy analysis
- Photo metadata removal

### 8. **Maltego Automation Wrapper**
- Link analysis graph creation
- Relationship mapping
- Entity management (Person, Domain, Email, IP, Phone, Social Media)
- JSON and Graphviz export
- Interactive graph building

**Use Cases:**
- Investigation visualization
- Connection mapping
- Relationship analysis

### 9. **Shodan IoT Device Finder**
- Network device scanning
- IoT device discovery
- Port enumeration
- Vulnerability detection
- Device type identification

**Use Cases:**
- Network security assessment
- IoT device inventory
- Security vulnerability detection

### 10. **Recon-ng Automation Script**
- Full reconnaissance automation
- DNS enumeration
- Subdomain discovery
- Port scanning
- WHOIS lookup
- Geolocation
- Comprehensive reporting

**Use Cases:**
- Automated reconnaissance
- Full-spectrum OSINT
- Penetration testing preparation

## 📦 Installation

### Prerequisites

```bash
Python 3.7+
```

### Required Python Packages

```bash
pip install -r requirements.txt
```

**Required packages:**
- `requests` - HTTP library
- `beautifulsoup4` - HTML parsing
- `Pillow` - Image processing
- `dnspython` - DNS queries (optional but recommended)

### Optional Dependencies

```bash
# For enhanced functionality
pip install dnspython
```

## 🎯 Usage

### Running FSociety

```bash
python fsociety.py
```

### Main Menu

```
=== OSINT (Open Source Intelligence) ===
[1] OSINT Tools

=== INFORMATION ===
[90] About FSociety
[91] Random Quote
[92] Help

[00] Exit
```

### OSINT Tools Menu

Select option `[1]` from the main menu to access all 10 OSINT tools:

```
[1]  Subdomain Discovery Tool
[2]  Email Address Harvester
[3]  Social Media Scraper
[4]  Domain & IP Information Tool
[5]  Pastebin & Leak Monitor
[6]  Phone Number Intelligence
[7]  Image Metadata Analyzer
[8]  Maltego Automation Wrapper
[9]  Shodan IoT Device Finder
[10] Recon-ng Automation Script
[0]  Back to Main Menu
```

## 📚 Tool Details

### Subdomain Discovery

```bash
Enter target domain: example.com
Use custom wordlist? (y/n): n
Number of threads: 10
```

Features:
- Built-in common subdomain list
- Custom wordlist support
- Multi-threaded scanning
- CSV export

### Email Harvester

```bash
Enter target domain: example.com
Harvesting Methods:
  [1] Web Scraping
  [2] Common Email Patterns
  [3] Both methods
```

Features:
- Website crawling
- Pattern generation
- DNS record parsing
- Result export

### Domain & IP Info

```bash
Enter domain or IP: example.com
Scan common ports? (y/n): y
```

Features:
- Automatic IP/domain detection
- WHOIS information
- DNS records
- Port scanning
- Geolocation

### Image Metadata Analyzer

```bash
Select option:
  [1] Analyze single image
  [2] Analyze directory
  [3] Strip metadata
```

Features:
- EXIF extraction
- GPS coordinate extraction
- Google Maps link generation
- Metadata removal

## 🛠️ Project Structure

```
fsociety/
├── fsociety.py              # Main application
├── osint/                   # OSINT tools package
│   ├── __init__.py
│   ├── subdomain_discovery.py
│   ├── email_harvester.py
│   ├── social_scraper.py
│   ├── domain_ip_info.py
│   ├── pastebin_monitor.py
│   ├── phone_intel.py
│   ├── image_metadata.py
│   ├── maltego_wrapper.py
│   ├── shodan_iot.py
│   └── recon_ng_auto.py
├── README.md
└── requirements.txt
```

## 🔒 Security Notes

1. **Legal Compliance**: Always ensure you have proper authorization before conducting any reconnaissance
2. **Rate Limiting**: Tools implement rate limiting to avoid overwhelming target systems
3. **Privacy**: Respect privacy and data protection regulations (GDPR, etc.)
4. **Logging**: Be aware that your activities may be logged by target systems
5. **VPN/Proxy**: Consider using VPN/proxy for privacy (where legally permitted)

## 🎨 Features

- **Interactive CLI**: User-friendly command-line interface
- **Color-Coded Output**: Easy-to-read colored terminal output
- **Export Options**: Save results in various formats (CSV, JSON, TXT)
- **Multi-Threading**: Fast scanning with concurrent operations
- **Error Handling**: Robust error handling and reporting
- **No External APIs**: Most tools work without requiring API keys

## 🔧 Configuration

### Custom Wordlists

Create custom wordlists for subdomain discovery:

```
# subdomains.txt
www
mail
ftp
admin
portal
api
```

### Network Configuration

For network scanning tools, ensure you're scanning authorized networks:
- Use on local networks you own
- Obtain written permission for external networks
- Follow responsible disclosure practices

## 📊 Output Examples

### Subdomain Discovery Output
```
[+] Found: www.example.com -> 192.0.2.1
[+] Found: mail.example.com -> 192.0.2.2
[+] Found: api.example.com -> 192.0.2.3
```

### Email Harvester Output
```
[+] Found: contact@example.com
[+] Found: support@example.com
[+] Generated: admin@example.com
```

## 🤝 Contributing

Contributions are welcome! Please ensure:
1. Code follows Python best practices
2. Tools are ethical and legal
3. Documentation is updated
4. No external API dependencies (preferred)

## 📝 License

This project is for educational purposes. Use responsibly and legally.

## 🎬 Inspiration

Inspired by the TV series **Mr. Robot** and the philosophy of digital freedom and privacy awareness.

> "Hello, friend." - Mr. Robot

## ⚡ Quick Start Guide

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd fsociety
   ```

2. **Install dependencies**
   ```bash
   pip install requests beautifulsoup4 Pillow dnspython
   ```

3. **Run the tool**
   ```bash
   python fsociety.py
   ```

4. **Select OSINT Tools** (option 1)

5. **Choose your tool** (1-10)

6. **Follow the prompts**

## 🆘 Support

For issues, questions, or contributions:
- Check documentation
- Review error messages
- Ensure all dependencies are installed

## ⚠️ Important Notes

- **No API Keys Required**: Most tools work without external APIs
- **Python 3.7+**: Ensure you're using a compatible Python version
- **Windows/Linux/Mac**: Cross-platform compatible
- **Educational Use**: Designed for learning and authorized testing

---

**Remember**: With great power comes great responsibility. Use these tools ethically and legally.

**Stay Anonymous. Stay Safe. We are FSociety.**
