import sys
import os
import time
import random

def clear_screen():
	"""Clear the terminal screen (works on both Windows and Unix)"""
	os.system('cls' if os.name == 'nt' else 'clear')

# Real Mr. Robot quotes
MR_ROBOT_QUOTES = [
	"Hello, friend.",
	"Control is an illusion.",
	"The world is a dangerous place, not because of those who do evil, but because of those who look on and do nothing.",
	"I wanted to save the world.",
	"Sometimes I dream of saving everyone from the invisible hand.",
	"Our democracy has been hacked.",
	"I'm only supposed to be your prophet. You're supposed to be my god.",
	"Is any of it real? I mean, look at this. Look at it! A world built on fantasy!",
	"We're all living in each other's paranoia.",
	"Maybe I should ask myself: What would Elliot do?",
	"The only way to patch a vulnerability is to expose it first.",
	"I am Mr. Robot.",
	"We are fsociety.",
	"Power belongs to the people that take it.",
	"What I'm about to tell you is top secret. A conspiracy bigger than all of us."
]

def display_banner():
	"""Display the FSociety banner"""
	clear_screen()
	print('''\033[92m
=========================================================================
|                                                                       |
| ███╗   ███╗██████╗        ██████╗  ██████╗ ██████╗  ██████╗ ████████╗ |
| ████╗ ████║██╔══██╗       ██╔══██╗██╔═══██╗██╔══██╗██╔═══██╗╚══██╔══╝ |
| ██╔████╔██║██████╔╝       ██████╔╝██║   ██║██████╔╝██║   ██║   ██║    |
| ██║╚██╔╝██║██╔══██╗       ██╔══██╗██║   ██║██╔══██╗██║   ██║   ██║    |
| ██║ ╚═╝ ██║██║  ██║██╗    ██║  ██║╚██████╔╝██████╔╝╚██████╔╝   ██║    |
| ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝    ╚═╝  ╚═╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝    |
|      A Offensive Python Script, Inspired From This T.V. Series        |
=========================================================================
\033[0m''')

def display_quote():
	"""Display a random Mr. Robot quote"""
	quote = random.choice(MR_ROBOT_QUOTES)
	print(f"\n\033[93m\"{quote}\"\033[0m")
	print(f"\033[90m- Mr. Robot\033[0m\n")

try:
	display_banner()
	display_quote()
	
	running = True
	while running:
		print('''\033[97m
		 ___ ___  ___   ___ ___ ___ _______   __
		| __/ __|/ _ \ / __|_ _| __|_   _\ \ / /
		| _|\__ \ (_) | (__ | || _|  | |  \ V / 
		|_| |___/\___/ \___|___|___| |_|   |_| \033[0m 
		''')
		print("	\033[97m=========================================================== ")
		print(f"\t\t\033[91m{random.choice(['Control is an illusion', 'Privacy is a myth', 'We are fsociety'])}")
		print(f"\t\t\tDate: {time.strftime('%d/%m/%y')}")
		print("	\033[97m=========================================================== ")
		print('''\033[92m
		=== OSINT (Open Source Intelligence) ===
		[1] OSINT Tools
		
		=== NETWORK PENETRATION TESTING ===
		[2] Network Tools
		
		=== WEB APPLICATION SECURITY ===
		[3] Web Security Tools
		
		=== WIRELESS SECURITY ===
		[4] Wireless Network Tools
		
		=== SOCIAL ENGINEERING ===
		[5] Social Engineering Tools
		
		=== MOBILE SECURITY ===
		[6] Mobile Security Assessment
		
		=== INFORMATION ===
		[90] About FSociety
		[91] Random Quote
		[92] Help
		
		[00] Exit
		\033[0m''')
		
		select = input("\033[95m [?] Choose Any Option : ")		
		
		# OSINT Tools Menu
		if select == '1':
			clear_screen()
			osint_running = True
			while osint_running:
				print("\n\033[92m" + "="*70)
				print("           OSINT TOOLS - Open Source Intelligence")
				print("="*70 + "\033[0m\n")
				
				print("\033[97m[1]  Subdomain Discovery Tool\033[0m")
				print("\033[97m     Enumerate subdomains using DNS brute force\033[0m\n")
				
				print("\033[97m[2]  Email Address Harvester\033[0m")
				print("\033[97m     Find email addresses from websites and sources\033[0m\n")
				
				print("\033[97m[3]  Social Media Scraper\033[0m")
				print("\033[97m     Collect public information from social platforms\033[0m\n")
				
				print("\033[97m[4]  Domain & IP Information Tool\033[0m")
				print("\033[97m     WHOIS lookups and IP geolocation\033[0m\n")
				
				print("\033[97m[5]  Pastebin & Leak Monitor\033[0m")
				print("\033[97m     Scan paste sites for exposed credentials\033[0m\n")
				
				print("\033[97m[6]  Phone Number Intelligence\033[0m")
				print("\033[97m     Analyze and lookup phone numbers\033[0m\n")
				
				print("\033[97m[7]  Image Metadata Analyzer\033[0m")
				print("\033[97m     Extract EXIF data including GPS coordinates\033[0m\n")
				
				print("\033[97m[8]  Maltego Automation Wrapper\033[0m")
				print("\033[97m     Create link analysis and relationship graphs\033[0m\n")
				
				print("\033[97m[9]  Shodan IoT Device Finder\033[0m")
				print("\033[97m     Discover exposed IoT devices on networks\033[0m\n")
				
				print("\033[97m[10] Recon-ng Automation Script\033[0m")
				print("\033[97m     Automated host discovery and reconnaissance\033[0m\n")
				
				print("\033[91m[0]  Back to Main Menu\033[0m\n")
				
				osint_select = input("\033[95m [?] Select OSINT Tool : \033[0m")
				
				if osint_select == '1':
					clear_screen()
					try:
						from osint import subdomain_discovery
						subdomain_discovery.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif osint_select == '2':
					clear_screen()
					try:
						from osint import email_harvester
						email_harvester.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif osint_select == '3':
					clear_screen()
					try:
						from osint import social_scraper
						social_scraper.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif osint_select == '4':
					clear_screen()
					try:
						from osint import domain_ip_info
						domain_ip_info.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif osint_select == '5':
					clear_screen()
					try:
						from osint import pastebin_monitor
						pastebin_monitor.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif osint_select == '6':
					clear_screen()
					try:
						from osint import phone_intel
						phone_intel.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif osint_select == '7':
					clear_screen()
					try:
						from osint import image_metadata
						image_metadata.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif osint_select == '8':
					clear_screen()
					try:
						from osint import maltego_wrapper
						maltego_wrapper.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif osint_select == '9':
					clear_screen()
					try:
						from osint import shodan_iot
						shodan_iot.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif osint_select == '10':
					clear_screen()
					try:
						from osint import recon_ng_auto
						recon_ng_auto.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif osint_select == '0':
					clear_screen()
					osint_running = False
				
				else:
					if osint_select:
						print("\n\033[91m [!] Invalid option. Please try again.\033[0m")
						time.sleep(1)
						clear_screen()
		
		# Network Tools Menu
		elif select == '2':
			clear_screen()
			network_running = True
			while network_running:
				print("\n\033[92m" + "="*70)
				print("           NETWORK PENETRATION TESTING TOOLS")
				print("="*70 + "\033[0m\n")
				
				print("\033[97m[1]  Port Scanner (Nmap Wrapper)\033[0m")
				print("\033[97m     Stealthy SYN scans and service version detection\033[0m\n")
				
				print("\033[97m[2]  Custom Packet Sniffer\033[0m")
				print("\033[97m     Capture and analyze network traffic in real-time\033[0m\n")
				
				print("\033[97m[3]  ARP Cache Poisoning Tool\033[0m")
				print("\033[97m     MITM attack to intercept local network traffic\033[0m\n")
				
				print("\033[97m[4]  DNS Spoofing Tool\033[0m")
				print("\033[97m     Redirect traffic with false DNS records\033[0m\n")
				
				print("\033[97m[5]  Vulnerability Scanner Integrator\033[0m")
				print("\033[97m     Automate network vulnerability scanning\033[0m\n")
				
				print("\033[97m[6]  Controlled Traffic Generator\033[0m")
				print("\033[97m     Ethical DoS simulation and resilience testing\033[0m\n")
				
				print("\033[97m[7]  Banner Grabbing Tool\033[0m")
				print("\033[97m     Retrieve service version information from ports\033[0m\n")
				
				print("\033[97m[8]  NetBIOS Name Resolver\033[0m")
				print("\033[97m     Enumerate Windows hosts, shares, and users\033[0m\n")
				
				print("\033[97m[9]  SMB Vulnerability Exploiter\033[0m")
				print("\033[97m     Exploit SMB vulnerabilities (EternalBlue, etc.)\033[0m\n")
				
				print("\033[97m[10] ICMP Ping Sweeper\033[0m")
				print("\033[97m     Identify live hosts on a network\033[0m\n")
				
				print("\033[91m[0]  Back to Main Menu\033[0m\n")
				
				network_select = input("\033[95m [?] Select Network Tool : \033[0m")
				
				if network_select == '1':
					clear_screen()
					try:
						from network import port_scanner
						port_scanner.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif network_select == '2':
					clear_screen()
					try:
						from network import packet_sniffer
						packet_sniffer.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif network_select == '3':
					clear_screen()
					try:
						from network import arp_poisoning
						arp_poisoning.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif network_select == '4':
					clear_screen()
					try:
						from network import dns_spoof
						dns_spoof.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif network_select == '5':
					clear_screen()
					try:
						from network import vuln_scanner
						vuln_scanner.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif network_select == '6':
					clear_screen()
					try:
						from network import traffic_generator
						traffic_generator.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif network_select == '7':
					clear_screen()
					try:
						from network import banner_grabber
						banner_grabber.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif network_select == '8':
					clear_screen()
					try:
						from network import netbios_resolver
						netbios_resolver.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif network_select == '9':
					clear_screen()
					try:
						from network import smb_exploiter
						smb_exploiter.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif network_select == '10':
					clear_screen()
					try:
						from network import ping_sweeper
						ping_sweeper.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif network_select == '0':
					clear_screen()
					network_running = False
				
				else:
					if network_select:
						print("\n\033[91m [!] Invalid option. Please try again.\033[0m")
						time.sleep(1)
						clear_screen()
		
		# Wireless Security Tools Menu
		elif select == '4':
			clear_screen()
			wireless_running = True
			while wireless_running:
				print("\n\033[92m" + "="*70)
				print("           WIRELESS NETWORK SECURITY TOOLS")
				print("="*70 + "\033[0m\n")
				
				print("\033[97m[1]  WPA/WPA2 Handshake Capture Automator\033[0m")
				print("\033[97m     Automated 4-way handshake capture and cracking\033[0m\n")
				
				print("\033[97m[2]  Evil Twin Framework\033[0m")
				print("\033[97m     Rogue access point with captive portal for credential harvesting\033[0m\n")
				
				print("\033[97m[3]  WPS PIN Brute-Forcer\033[0m")
				print("\033[97m     Pixie Dust, NULL PIN, and full WPS brute force attacks\033[0m\n")
				
				print("\033[97m[4]  Bluetooth Device Scanner\033[0m")
				print("\033[97m     BLE & Classic Bluetooth enumeration with service discovery\033[0m\n")
				
				print("\033[97m[5]  Deauthentication Frame Sender\033[0m")
				print("\033[97m     Targeted, broadcast, and mass deauth attacks\033[0m\n")
				
				print("\033[97m[6]  Rogue AP Detector\033[0m")
				print("\033[97m     Detect Evil Twin and unauthorized access points\033[0m\n")
				
				print("\033[97m[7]  Zigbee Packet Sniffer\033[0m")
				print("\033[97m     IoT protocol analysis and device enumeration\033[0m\n")
				
				print("\033[97m[8]  RFID/NFC Cloner Simulator\033[0m")
				print("\033[97m     Tag reading, UID extraction, and cloning\033[0m\n")
				
				print("\033[91m[0]  Back to Main Menu\033[0m\n")
				
				wireless_select = input("\033[95m [?] Select Wireless Tool : \033[0m")
				
				if wireless_select == '1':
					clear_screen()
					try:
						from wireless import wpa_handshake_capture
						wpa_handshake_capture.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif wireless_select == '2':
					clear_screen()
					try:
						from wireless import evil_twin_framework
						evil_twin_framework.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif wireless_select == '3':
					clear_screen()
					try:
						from wireless import wps_pin_bruteforce
						wps_pin_bruteforce.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif wireless_select == '4':
					clear_screen()
					try:
						from wireless import bluetooth_scanner
						bluetooth_scanner.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif wireless_select == '5':
					clear_screen()
					try:
						from wireless import deauth_frame_sender
						deauth_frame_sender.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif wireless_select == '6':
					clear_screen()
					try:
						from wireless import rogue_ap_detector
						rogue_ap_detector.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif wireless_select == '7':
					clear_screen()
					try:
						from wireless import zigbee_sniffer
						zigbee_sniffer.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif wireless_select == '8':
					clear_screen()
					try:
						from wireless import rfid_nfc_cloner
						rfid_nfc_cloner.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif wireless_select == '0':
					clear_screen()
					wireless_running = False
				
				else:
					if wireless_select:
						print("\n\033[91m [!] Invalid option. Please try again.\033[0m")
						time.sleep(1)
						clear_screen()
		
		# Web Security Tools Menu
		elif select == '3':
			clear_screen()
			web_running = True
			while web_running:
				print("\n\033[92m" + "="*70)
				print("           WEB APPLICATION SECURITY TESTING TOOLS")
				print("="*70 + "\033[0m\n")
				
				print("\033[97m[1]  SQL Injection Tester\033[0m")
				print("\033[97m     Detect SQL injection vulnerabilities (Error/Union/Blind/Time-based)\033[0m\n")
				
				print("\033[97m[2]  XSS (Cross-Site Scripting) Injector\033[0m")
				print("\033[97m     Test for reflected, stored, and DOM-based XSS flaws\033[0m\n")
				
				print("\033[97m[3]  Directory & File Brute-Forcer\033[0m")
				print("\033[97m     Discover hidden directories, files, and backup archives\033[0m\n")
				
				print("\033[97m[4]  Admin Panel Finder\033[0m")
				print("\033[97m     Locate administrative interfaces and login pages\033[0m\n")
				
				print("\033[97m[5]  CSRF PoC Generator\033[0m")
				print("\033[97m     Create Cross-Site Request Forgery proof-of-concept exploits\033[0m\n")
				
				print("\033[97m[6]  LFI/RFI Exploiter\033[0m")
				print("\033[97m     Exploit Local and Remote File Inclusion vulnerabilities\033[0m\n")
				
				print("\033[97m[7]  JWT Token Analyzer\033[0m")
				print("\033[97m     Decode, verify, and crack JSON Web Tokens\033[0m\n")
				
				print("\033[97m[8]  SSRF Detector\033[0m")
				print("\033[97m     Find Server-Side Request Forgery vulnerabilities\033[0m\n")
				
				print("\033[97m[9]  API Endpoint Fuzzer\033[0m")
				print("\033[97m     Fuzz REST/GraphQL/SOAP APIs with malformed data\033[0m\n")
				
				print("\033[97m[10] Web Traffic Generator\033[0m")
				print("\033[97m     HTTP/HTTPS stress testing and DoS simulation\033[0m\n")
				
				print("\033[91m[0]  Back to Main Menu\033[0m\n")
				
				web_select = input("\033[95m [?] Select Web Security Tool : \033[0m")
				
				if web_select == '1':
					clear_screen()
					try:
						from web import sql_injection
						sql_injection.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif web_select == '2':
					clear_screen()
					try:
						from web import xss_injector
						xss_injector.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif web_select == '3':
					clear_screen()
					try:
						from web import directory_bruteforce
						directory_bruteforce.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif web_select == '4':
					clear_screen()
					try:
						from web import admin_finder
						admin_finder.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif web_select == '5':
					clear_screen()
					try:
						from web import csrf_poc_generator
						csrf_poc_generator.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif web_select == '6':
					clear_screen()
					try:
						from web import lfi_rfi_exploiter
						lfi_rfi_exploiter.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif web_select == '7':
					clear_screen()
					try:
						from web import jwt_analyzer
						jwt_analyzer.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif web_select == '8':
					clear_screen()
					try:
						from web import ssrf_detector
						ssrf_detector.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif web_select == '9':
					clear_screen()
					try:
						from web import api_fuzzer
						api_fuzzer.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif web_select == '10':
					clear_screen()
					try:
						from web import traffic_generator
						traffic_generator.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif web_select == '0':
					clear_screen()
					web_running = False
				
				else:
					if wireless_select:
						print("\n\033[91m [!] Invalid option. Please try again.\033[0m")
						time.sleep(1)
						clear_screen()
		
		elif select == '5':
			clear_screen()
			se_running = True
			while se_running:
				print("\n\033[92m" + "="*70)
				print("           SOCIAL ENGINEERING TOOLS")
				print("="*70 + "\033[0m\n")
				
				print("\033[97m[1]  Phishing Campaign Generator\033[0m")
				print("\033[97m     Professional phishing emails with tracking\033[0m\n")
				
				print("\033[97m[2]  Credential Harvester\033[0m")
				print("\033[97m     Fake login pages for credential capture\033[0m\n")
				
				print("\033[97m[3]  Bad USB Injector\033[0m")
				print("\033[97m     Rubber Ducky payload generator\033[0m\n")
				
				print("\033[97m[4]  Automated Vishing System\033[0m")
				print("\033[97m     Voice phishing campaign automation\033[0m\n")
				
				print("\033[97m[5]  BeEF Hook Generator\033[0m")
				print("\033[97m     Browser exploitation framework hooks\033[0m\n")
				
				print("\033[97m[6]  AI Pretext Generator\033[0m")
				print("\033[97m     Advanced social engineering scenarios\033[0m\n")
				
				print("\033[91m[0]  Back to Main Menu\033[0m\n")
				
				se_select = input("\033[95m [?] Select Social Engineering Tool : \033[0m")
				
				if se_select == '1':
					clear_screen()
					try:
						from social_engineering import phishing_campaign_generator
						phishing_campaign_generator.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif se_select == '2':
					clear_screen()
					try:
						from social_engineering import credential_harvester
						credential_harvester.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif se_select == '3':
					clear_screen()
					try:
						from social_engineering import bad_usb_injector
						bad_usb_injector.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif se_select == '4':
					clear_screen()
					try:
						from social_engineering import automated_vishing
						automated_vishing.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif se_select == '5':
					clear_screen()
					try:
						from social_engineering import beef_hook_generator
						beef_hook_generator.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif se_select == '6':
					clear_screen()
					try:
						from social_engineering import ai_pretext_generator
						ai_pretext_generator.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif se_select == '0':
					clear_screen()
					se_running = False
				
				else:
					if se_select:
						print("\n\033[91m [!] Invalid option. Please try again.\033[0m")
						time.sleep(1)
						clear_screen()
		
		elif select == '6':
			clear_screen()
			mobile_running = True
			while mobile_running:
				print("\n\033[92m" + "="*70)
				print("           MOBILE SECURITY ASSESSMENT TOOLS")
				print("="*70 + "\033[0m\n")
				
				print("\033[97m[1]  Android ADB Exploitation Tool\033[0m")
				print("\033[97m     Post-exploitation automation via ADB\033[0m\n")
				
				print("\033[97m[2]  Frida Script Runner\033[0m")
				print("\033[97m     Dynamic instrumentation for mobile apps\033[0m\n")
				
				print("\033[97m[3]  APK Decompilation & Analysis\033[0m")
				print("\033[97m     Reverse engineering Android applications\033[0m\n")
				
				print("\033[97m[4]  iOS Backup Analyzer\033[0m")
				print("\033[97m     Extract data from iTunes backups\033[0m\n")
				
				print("\033[97m[5]  Mobile Location Spoofer\033[0m")
				print("\033[97m     GPS simulation for testing\033[0m\n")
				
				print("\033[97m[6]  Root/Jailbreak Detection Bypass\033[0m")
				print("\033[97m     Evade security checks in mobile apps\033[0m\n")
				
				print("\033[91m[0]  Back to Main Menu\033[0m\n")
				
				mobile_select = input("\033[95m [?] Select Mobile Tool : \033[0m")
				
				if mobile_select == '1':
					clear_screen()
					try:
						from mobile import adb_exploitation
						adb_exploitation.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif mobile_select == '2':
					clear_screen()
					try:
						from mobile import frida_runner
						frida_runner.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif mobile_select == '3':
					clear_screen()
					try:
						from mobile import apk_analyzer
						apk_analyzer.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif mobile_select == '4':
					clear_screen()
					try:
						from mobile import ios_backup_analyzer
						ios_backup_analyzer.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif mobile_select == '5':
					clear_screen()
					try:
						from mobile import location_spoofer
						location_spoofer.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif mobile_select == '6':
					clear_screen()
					try:
						from mobile import root_detection_bypass
						root_detection_bypass.run()
					except Exception as e:
						print(f"\033[91m[!] Error: {str(e)}\033[0m")
					input("\n\033[97m [*] Press Enter to continue...\033[0m")
					clear_screen()
				
				elif mobile_select == '0':
					clear_screen()
					mobile_running = False
				
				else:
					if mobile_select:
						print("\n\033[91m [!] Invalid option. Please try again.\033[0m")
						time.sleep(1)
						clear_screen()
		
		if select == '90':
			clear_screen()
			print("\n\033[92m=== About FSociety ===\033[0m")
			print("\033[97m" + "="*60 + "\033[0m")
			print("\033[93mFSociety is a hacker collective from the TV series Mr. Robot.")
			print("Led by the mysterious Mr. Robot, fsociety aims to take down")
			print("Evil Corp and the corrupt financial system that enslaves society.")
			print("\nThis tool is inspired by the series and designed for")
			print("educational purposes in cybersecurity and penetration testing.\033[0m")
			print("\033[97m" + "="*60 + "\033[0m")
			input("\n\033[97m [*] Press Enter to continue...")
			clear_screen()
		
		elif select == '91':
			clear_screen()
			display_quote()
			input("\n\033[97m [*] Press Enter to continue...")
			clear_screen()
		
		elif select == '92' or select == '?':
			clear_screen()
			print("\n\033[92m=== FSociety Help ===\033[0m")
			print("\033[97m" + "="*60 + "\033[0m")
			print("\033[93m")
			print("This is a penetration testing toolkit inspired by Mr. Robot.")
			print("\nCategories:")
			print("  • RECONNAISSANCE: Information gathering and scanning")
			print("  • EXPLOITATION: Finding and exploiting vulnerabilities")
			print("  • POST-EXPLOITATION: Actions after gaining access")
			print("  • UTILITIES: Helpful security tools")
			print("\nUsage:")
			print("  - Select a tool by entering its number")
			print("  - Type 00 to exit")
			print("  - Type 91 for a random Mr. Robot quote")
			print("\n⚠️  WARNING: Use these tools only on systems you own")
			print("   or have explicit permission to test!")
			print("\033[0m")
			print("\033[97m" + "="*60 + "\033[0m")
			input("\n\033[97m [*] Press Enter to continue...")
			clear_screen()
		
		elif select == '00':
			clear_screen()
			print("\n\033[91m [*] Shutting down FSociety...\033[0m")
			time.sleep(1)
			print("\033[97m [*] Thank you, friend. Visit again...\033[0m")
			time.sleep(1)
			sys.exit()
		
		else:
			if select and select not in ['90', '91', '92', '?', '00']:
				print("\n\033[91m [!] Invalid option. Please try again.\033[0m")
				time.sleep(1)
				clear_screen()

except KeyboardInterrupt:
	print("\n\033[91m [*] Exiting...\033[0m")
	time.sleep(1)
	clear_screen()
	print("\033[97m [*] Thank you, friend. Visit again...\033[0m")
	time.sleep(1)
	sys.exit()
