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
