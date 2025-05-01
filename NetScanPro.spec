# -*- mode: python ; coding: utf-8 -*-
#  python -m PyInstaller NetScanPro.spec
import sys
import os
from PyInstaller.utils.hooks import collect_submodules

block_cipher = None

# Dinamik bağımlılıkları topla
hiddenimports = []
hiddenimports += collect_submodules('tkinter')
hiddenimports += collect_submodules('pandas') if 'pandas' in sys.modules else []
hiddenimports += collect_submodules('matplotlib') if 'matplotlib' in sys.modules else []
hiddenimports += collect_submodules('getmac') if 'getmac' in sys.modules else []
hiddenimports += collect_submodules('scapy') if 'scapy' in sys.modules else []
hiddenimports += collect_submodules('nmap') if 'nmap' in sys.modules else []

# Matplotlib veri dosyalarını ekle
datas = []
try:
    import matplotlib
    mpl_data_dir = matplotlib.get_data_path()
    mpl_data = [(os.path.join(mpl_data_dir, 'fonts', 'ttf'), os.path.join('matplotlib', 'fonts', 'ttf'))]
    datas.extend(mpl_data)
except:
    pass

# Icon dosyasını ve Npcap klasörünü ekle
if os.path.exists('icon.png'):
    datas.append(('icon.png', '.'))
if os.path.exists('npcap'):
    datas.append(('npcap', 'npcap'))

# Temel programımızın analizi
a = Analysis(
    ['boot.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['_tkinter.test', 'tkinter.test', 'lib2to3', 'unittest', 'test', 'pydoc_data'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# Optimize edilmiş PYZ arşivi
pyz = PYZ(
    a.pure, 
    a.zipped_data,
    cipher=block_cipher
)

# Exe oluştur
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='NetScanPro',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,            # Konsol penceresini gizle
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='icon.png' if os.path.exists('icon.png') else None,
    uac_admin=True,           # Yönetici haklarıyla çalıştır
)