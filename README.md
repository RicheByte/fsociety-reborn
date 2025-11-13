# FSociety Reborn - On Beta Testings
![main Image](/assets/main.gif)
A comprehensive offensive security toolkit inspired by Mr. Robot. Built for security researchers and ethical penetration testers.

## Overview

FSociety Reborn is a Python-based penetration testing framework featuring 9 specialized categories with over 50 professional-grade tools for security assessment and ethical hacking.

![Demo Video](/assets/video.gif)

## Features

### OSINT (Open Source Intelligence)
- Subdomain Discovery
- Email Harvester
- Social Media Scraper
- Domain & IP Intelligence
- Pastebin Monitor
- Phone Number Intelligence
- Image Metadata Analyzer
- Maltego Automation
- Shodan IoT Finder
- Recon-ng Automation

### Network Penetration Testing
- Port Scanner (Nmap Wrapper)
- Packet Sniffer
- ARP Poisoning
- DNS Spoofing
- Vulnerability Scanner
- Traffic Generator
- Banner Grabber
- NetBIOS Resolver
- SMB Exploiter
- ICMP Ping Sweeper

### Web Application Security
- SQL Injection Tester
- XSS Injector
- Directory Brute-Forcer
- Admin Panel Finder
- CSRF PoC Generator
- LFI/RFI Exploiter
- JWT Token Analyzer
- SSRF Detector
- API Fuzzer
- Web Traffic Generator

### Wireless Security
- WPA/WPA2 Handshake Capture
- Evil Twin Framework
- WPS PIN Brute-Forcer
- Bluetooth Scanner
- Deauth Frame Sender
- Rogue AP Detector
- Zigbee Sniffer
- RFID/NFC Cloner

### Social Engineering
- Phishing Campaign Generator
- Credential Harvester
- Bad USB Injector
- Automated Vishing
- BeEF Hook Generator
- AI Pretext Generator

### Mobile Security
- Android ADB Exploitation
- Frida Script Runner
- APK Analyzer
- iOS Backup Analyzer
- Location Spoofer
- Root Detection Bypass

### Digital Forensics
- Volatility Automation (Memory Forensics)
- File Carving Tool
- Timeline Generator
- Steganography Detector
- Rootkit Scanner

### Password & Cryptography
- Hashcat Automation
- John the Ripper Automation
- Hydra Brute-Force Launcher
- 2FA Bypass Tester
- Entropy Analyzer

### Exploitation & Post-Exploitation
- Metasploit Automation
- Exploit-DB Downloader
- Privilege Escalation Checker
- AV Evasion Payload Generator
- Lateral Movement Simulator
- Cloud IAM Auditor

## Installation

### Prerequisites
- Python 3.8 or higher
- Kali Linux (recommended) or any Linux distribution
- Root/Administrator privileges for certain tools

### Setup

```bash
git clone https://github.com/RicheByte/fsocietyOS.git
cd fsociety-reborn
python -m venv .env
source .env/bin/activate  # On Windows: .env\Scripts\Activate.ps1
pip install -r requirements.txt
```

### External Dependencies

Some tools require additional system packages:

```bash
# Kali Linux / Debian / Ubuntu
sudo apt-get install nmap aircrack-ng hostapd dnsmasq reaver \
    hashcat john hydra metasploit-framework impacket-scripts \
    volatility libnfc-bin
```

## Usage

Launch the main interface:

```bash
python fsociety.py
```

Navigate through categories using the numbered menu system. Each tool includes interactive prompts and usage instructions.

## Legal Disclaimer

This toolkit is designed exclusively for authorized security testing and educational purposes. Users must:

- Obtain explicit written permission before testing any systems
- Comply with all applicable local, state, and federal laws
- Use tools only in controlled environments or against owned systems
- Accept full responsibility for their actions

Unauthorized access to computer systems is illegal. The developers assume no liability for misuse of this software.

## Requirements

See `requirements.txt` for Python dependencies. Key external tools:
- Metasploit Framework
- Impacket
- Aircrack-ng suite
- Hashcat, John the Ripper, Hydra
- Volatility (optional)

## Contributing

Contributions are welcome. Please ensure all submissions:
- Follow existing code style
- Include appropriate error handling
- Are tested on Kali Linux
- Do not include malicious code


## Acknowledgments

Inspired by the Mr. Robot television series. Built for the cybersecurity community.
