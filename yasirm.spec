# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['yasirm.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'win32api',
        'win32con',
        'win32file',
        'win32security',
        'win32process',
        'pyautogui',
        'cv2',
        'numpy',
        'keyboard',
        'requests',
        'Crypto',
        'Crypto.Cipher',
        'Crypto.Hash',
        'Crypto.Util.Padding',
        'Crypto.Random',
        'telebot',
        'telebot.types',
        'psutil'
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='yasirm',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None
)
