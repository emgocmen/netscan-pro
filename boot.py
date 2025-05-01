#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
boot.py – NetScan Pro açılış başlatıcısı
Splash ekranını hemen gösterir, arka planda netscan.py'yi import edip main()'ı çağırır.
"""

import threading
import tkinter as tk
from tkinter import ttk
import sys
import os

# global placeholder for netscan modülü
netscan = None

def show_splash():
    """Splash ekranını oluşturup hemen aç."""
    splash = tk.Tk()
    splash.overrideredirect(True)
    splash.attributes('-topmost', True)

    # ekranı ortala
    w, h = 400, 200
    sw = splash.winfo_screenwidth()
    sh = splash.winfo_screenheight()
    x = (sw - w) // 2
    y = (sh - h) // 2
    splash.geometry(f"{w}x{h}+{x}+{y}")

    frame = tk.Frame(splash, bg='#f0f0f0', width=w, height=h)
    frame.pack_propagate(False)
    frame.pack(fill=tk.BOTH, expand=True)

    tk.Label(frame, text="NetScan Pro", font=('TkDefaultFont', 18, 'bold'),
             bg='#f0f0f0').pack(pady=(30, 5))
    tk.Label(frame, text="Uygulama Başlatılıyor...", font=('TkDefaultFont', 12),
             bg='#f0f0f0').pack(pady=(0, 10))

    progress = ttk.Progressbar(frame, mode='indeterminate', length=300)
    progress.pack(pady=(0, 20))
    progress.start(10)

    splash.update_idletasks()
    return splash

def preload_netscan_module(event):
    """
    Arka planda netscan.py modülünü import et (tüm ağır import'lar burada).
    İş bittiğinde event.set() ile main thread'i uyar.
    """
    global main
    # netscan.py yolunu sys.path'e ekle
    base_dir = os.path.dirname(__file__)
    if base_dir not in sys.path:
        sys.path.insert(0, base_dir)

    # ağır import'lar netscan.py içinde yapılacak
    import main
    main  # referans
    event.set()

def launch_netscan(event, splash):
    """
    netscan modülü hazırsa splash'ı kapatıp main()'ı çalıştır.
    """
    if not event.is_set():
        # henüz hazır değilse 100ms sonra tekrar dene
        splash.after(100, launch_netscan, event, splash)
        return

    # netscan yüklendi, splash'ı kapat
    splash.destroy()

    # komut satırı argümanlarını olduğu gibi aktarmak için sys.argv korunsun
    # netscan.main, GUI veya console moduna göre davranacak
    exit_code = main.main()
    sys.exit(exit_code)

if __name__ == "__main__":
    # splash ekranını göster
    splash = show_splash()

    # arka plan yükleme için Event ve Thread
    loaded_event = threading.Event()
    t = threading.Thread(target=preload_netscan_module, args=(loaded_event,), daemon=True)
    t.start()

    # splash ana döngüsüne, modül hazır olunca launch_netscan tetiklensin
    splash.after(100, launch_netscan, loaded_event, splash)
    splash.mainloop()
