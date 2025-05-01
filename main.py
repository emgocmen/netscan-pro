#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetScan Pro - Gelişmiş Ağ Tarama Aracı
--------------------------------------
Bu uygulama, belirtilen IP aralıklarını tarayarak ağdaki cihazların detaylı bilgilerini tespit eder ve görselleştirir.

Özellikler:
- IP aralıklarını hızlı ve kapsamlı tarama
- Dinamik port seçimi ve özelleştirilebilir tarama ayarları
- MAC adresi tespiti
- Çoklu iş parçacığı ile paralel tarama
- Sonuçları Excel/CSV olarak dışa aktarma
- Kullanıcı dostu modern arayüz
"""

import sys
import os
import socket
import ipaddress
import threading
import queue
import time
import subprocess
import re
import json
import platform
import csv
import logging
import ctypes
import winreg
from datetime import datetime, timedelta
from collections import defaultdict

# GUI kütüphaneleri
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from tkinter.scrolledtext import ScrolledText

# Opsiyonel kütüphaneler (bulunursa kullanılır)
try:
    import ttkthemes
    THEMES_AVAILABLE = True
except ImportError:
    THEMES_AVAILABLE = False

try:
    import getmac
    MAC_MODULE_AVAILABLE = True
except ImportError:
    MAC_MODULE_AVAILABLE = False

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    
try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import nmap
    NMAP_MODULE_AVAILABLE = True
except ImportError:
    NMAP_MODULE_AVAILABLE = False

try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

# Logging yapılandırması
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("netscan.log", mode='w', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("NetScan")

# Yaygın servisler ve portları
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Proxy",
    5432: "PostgreSQL",
    1433: "MS SQL",
    27017: "MongoDB",
    6379: "Redis",
    5900: "VNC",
    111: "RPC",
    135: "RPC",
    139: "NetBIOS",
    161: "SNMP",
    389: "LDAP",
    636: "LDAPS",
    2049: "NFS"
}

# Port kategorileri
PORT_PROFILES = {
    "Temel": [80, 443, 22, 3389],
    "Genişletilmiş": [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 8080],
    "Web": [80, 443, 8080, 8443, 3000, 5000, 8000],
    "Veritabanı": [1433, 1521, 3306, 5432, 6379, 27017],
    "Dosya Paylaşımı": [20, 21, 22, 69, 115, 445, 548],
    "Uzaktan Erişim": [22, 23, 3389, 5900, 5901, 5902],
    "Tümü": list(COMMON_PORTS.keys())
}


class AppSettings:
    """Uygulama ayarları yönetim sınıfı"""
    
    def __init__(self):
        """Varsayılan ayarları başlat"""
        self.settings = {
            # Genel ayarlar
            'ip_range': "192.168.1.0/24",
            'scan_mode': "Normal",  # Fast, Normal, Thorough
            'save_path': "",
            
            # Tarama ayarları
            'thread_count': min(os.cpu_count() * 2 if os.cpu_count() else 8, 20),
            'timeout': 1.0,
            'retry_count': 1,
            'ping_scan': True,
            'arp_scan': True,
            'tcp_scan': True,
            'scan_delay': 0.0,
            
            # Port tarama ayarları
            'port_profile': "Temel",
            'port_timeout': 0.5,
            'max_ports': 100,
            'custom_ports': "80,443,22,3389"
        }
        
        # Ayarları dosyadan yüklemeyi dene
        self.load_settings()
            
    def get(self, key, default=None):
        """Ayar değerini al"""
        return self.settings.get(key, default)
        
    def set(self, key, value):
        """Ayar değerini güncelle"""
        self.settings[key] = value
        
    def save_settings(self):
        """Ayarları dosyaya kaydet"""
        try:
            with open("netscan_settings.json", 'w', encoding='utf-8') as f:
                json.dump(self.settings, f, indent=4, ensure_ascii=False)
            return True
        except Exception as e:
            logger.error(f"Ayarlar kaydedilemedi: {str(e)}")
            return False
            
    def load_settings(self):
        """Ayarları dosyadan yükle"""
        try:
            if os.path.exists("netscan_settings.json"):
                with open("netscan_settings.json", 'r', encoding='utf-8') as f:
                    loaded = json.load(f)
                    # Yüklenen ayarları mevcut ayarlarla birleştir
                    self.settings.update(loaded)
                return True
            return False
        except Exception as e:
            logger.error(f"Ayarlar yüklenemedi: {str(e)}")
            return False


class PortUtils:
    """Port aralığı işleme yardımcı sınıfı"""
    
    @staticmethod
    def parse_port_range(port_string):
        """
        '80,443,8000-8100' gibi port aralığı tanımlarını ayrıştırır
        Örn: "80,443,8000-8100,1-5" -> [1, 2, 3, 4, 5, 80, 443, 8000, 8001, ..., 8100]
        """
        if not port_string or port_string.strip() == "":
            return []
            
        ports = set()
        
        # Virgülle ayrılmış parçalara böl
        parts = port_string.split(',')
        
        for part in parts:
            part = part.strip()
            
            # Aralık kontrolü (içinde tire var mı)
            if '-' in part:
                try:
                    start, end = part.split('-', 1)
                    start_port = int(start.strip())
                    end_port = int(end.strip())
                    
                    # Port aralığı doğrulama
                    if start_port < 1 or start_port > 65535 or end_port < 1 or end_port > 65535:
                        logger.warning(f"Geçersiz port aralığı: {part} (portlar 1-65535 arasında olmalı)")
                        continue
                        
                    if start_port > end_port:
                        start_port, end_port = end_port, start_port
                        
                    # Aralıktaki tüm portları ekle
                    ports.update(range(start_port, end_port + 1))
                except ValueError:
                    logger.warning(f"Geçersiz port aralığı formatı: {part}")
            else:
                # Tek port
                try:
                    port = int(part)
                    if port < 1 or port > 65535:
                        logger.warning(f"Geçersiz port numarası: {port} (1-65535 arasında olmalı)")
                        continue
                    ports.add(port)
                except ValueError:
                    logger.warning(f"Geçersiz port numarası: {part}")
        
        return sorted(list(ports))
    
    @staticmethod
    def format_port_range(port_list):
        """
        Port listesini sıkıştırılmış metin gösterimine dönüştürür
        Örn: [80, 81, 82, 83, 443, 8000, 8001, 8002] -> "80-83,443,8000-8002"
        """
        if not port_list:
            return ""
            
        # Portları sırala
        ports = sorted(port_list)
        
        # Sürekli aralıkları bul
        ranges = []
        range_start = ports[0]
        prev_port = ports[0]
        
        for port in ports[1:]:
            if port > prev_port + 1:
                # Aralık sonu
                if prev_port == range_start:
                    ranges.append(str(range_start))
                else:
                    ranges.append(f"{range_start}-{prev_port}")
                range_start = port
            prev_port = port
            
        # Son aralığı işle
        if prev_port == range_start:
            ranges.append(str(range_start))
        else:
            ranges.append(f"{range_start}-{prev_port}")
            
        return ",".join(ranges)


class NetworkUtils:
    """Ağ işlemleri yardımcı sınıfı"""

    @staticmethod
    def is_npcap_installed():
        """
        Npcap'ın sistemde kurulu olup olmadığını kontrol et
        """
        try:
            # Windows Registry'den kontrol et
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Npcap") as key:
                return True
        except WindowsError:
            # DLL dosyalarını kontrol et
            system32_path = os.path.join(os.environ['SystemRoot'], 'System32')
            npcap_files = ['wpcap.dll', 'Packet.dll']
            
            for file in npcap_files:
                if os.path.exists(os.path.join(system32_path, file)):
                    return True
            
            # Scapy ile test et
            if SCAPY_AVAILABLE:
                try:
                    # Basit bir ağ fonksiyonu çağır ve başarılı olup olmadığını kontrol et
                    scapy.conf.route
                    return True
                except:
                    pass
            
            return False

    @staticmethod
    def check_npcap():
        """Npcap'ı kontrol et ve yükle (yalnızca kurulu değilse)"""
        try:
            # Önce kurulu olup olmadığını kontrol et
            if NetworkUtils.is_npcap_installed():
                logger.info("Npcap zaten kurulu, kurulum atlanıyor.")
                return True
            
            logger.info("Npcap kurulu değil, yükleniyor...")
            # Programın bulunduğu dizini bul
            if getattr(sys, 'frozen', False):
                # PyInstaller ile derlenmişse
                base_path = sys._MEIPASS
            else:
                # Normal Python çalıştırılabilirse
                base_path = os.path.dirname(os.path.abspath(__file__))
            
            # Npcap klasörünün konumunu belirle
            npcappath = os.path.join(base_path, 'npcap')
            installer = os.path.join(npcappath, 'npcap_setup.exe')
            
            logger.info(f"Npcap kurulum dosyası konumu: {installer}")
            
            if not os.path.exists(installer):
                logger.error("npcap_setup.exe dosyası bulunamadı!")
                return False

            # Gizli kurulum penceresi için yapılandırma
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            
            # Yükle (sessiz kurulum seçenekleriyle)
            process = subprocess.Popen(
                [installer, "/S"],  # /S parametresi sessiz kurulum yapar
                startupinfo=startupinfo,
                shell=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            # Kurulumun tamamlanmasını bekle, maksimum 2 dakika
            try:
                process.wait(timeout=120)
                logger.info("Npcap kurulumu tamamlandı")
                return True
            except subprocess.TimeoutExpired:
                process.kill()
                logger.error("Npcap kurulumu zaman aşımına uğradı")
                return False
            
        except Exception as e:
            logger.error(f"Npcap yükleme hatası: {str(e)}")
            return False
    
    @staticmethod
    def get_local_ip():
        """Yerel IP adresini al"""
        try:
            # Giden arabirimi belirlemek için bir soket oluştur
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            logger.error(f"Yerel IP belirlenirken hata: {str(e)}")
            # Yedek yöntem
            hostname = socket.gethostname()
            return socket.gethostbyname(hostname)
    
    @staticmethod
    def get_network_prefix():
        """Yerel IP'den ağ önekini al (örn. 192.168.1.0/24)"""
        try:
            local_ip = NetworkUtils.get_local_ip()
            ip_parts = local_ip.split('.')
            # /24 ağı varsay - gerçek alt ağı tespit etmek için geliştirilebilir
            network_prefix = '.'.join(ip_parts[:-1]) + '.0/24'
            return network_prefix
        except Exception:
            return "192.168.1.0/24"  # Varsayılan
    
    @staticmethod
    def ping(ip, timeout=1, count=1):
        """IP adresine ping gönder (konsol penceresi göstermeden)"""
        try:
            # Gizli pencerede çalıştırma için yapılandırma
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
            command = ['ping', param, str(count), timeout_param, str(timeout * 1000 if platform.system().lower() == 'windows' else timeout), str(ip)]
            
            # Konsol penceresini gizleme bayrağıyla çalıştır
            return subprocess.call(
                command, 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL,
                startupinfo=startupinfo,
                creationflags=subprocess.CREATE_NO_WINDOW
            ) == 0
        except Exception as e:
            logger.debug(f"Ping hatası: {str(e)}")
            return False
    
    @staticmethod
    def get_hostname(ip):
        """IP adresinden hostname çözümlemeyi dene"""
        try:
            return socket.gethostbyaddr(str(ip))[0]
        except Exception:
            return ""
    
    @staticmethod
    def extract_mac_from_arp_output(output, ip):
        """ARP komut çıktısından MAC adresi ayıkla"""
        # Windows ve Linux farklı formatlar kullanır
        lines = output.splitlines()
        for line in lines:
            # MAC adresinin standart biçimi: xx:xx:xx:xx:xx:xx veya xx-xx-xx-xx-xx-xx
            matches = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
            if matches and ip in line:
                return matches.group(0).upper()
        return ""
    
    @staticmethod
    def get_mac_address(ip):
        """
        Geliştirilmiş MAC adresi alma fonksiyonu
        Birden fazla yöntemi sırayla deneyerek daha güvenilir sonuçlar sağlar
        """
        try:
            mac = ""
            ip_str = str(ip)
            
            # Yöntem 1: getmac kütüphanesi (en güvenilir)
            if MAC_MODULE_AVAILABLE:
                try:
                    mac = getmac.get_mac_address(ip=ip_str)
                    if mac:
                        return mac.upper()
                except Exception as e:
                    logger.debug(f"getmac hatası: {str(e)}")
            
            # Yöntem 2: Scapy kütüphanesi (orta güvenilir)
            if SCAPY_AVAILABLE:
                try:
                    # Scapy ile ARP isteği gönder
                    arp_request = scapy.ARP(pdst=ip_str)
                    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                    arp_request_broadcast = broadcast/arp_request
                    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
                    
                    if answered_list:
                        mac = answered_list[0][1].hwsrc.upper()
                        if mac:
                            return mac
                except Exception as e:
                    logger.debug(f"Scapy ARP hatası: {str(e)}")
            
            # Yöntem 3: arp komutu (daha az güvenilir)
            try:
                # Gizli pencerede çalıştırma için yapılandırma
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE
                
                if platform.system().lower() == 'windows':
                    # Windows arp komutu
                    result = subprocess.check_output(
                        f'arp -a {ip_str}', 
                        shell=True, 
                        startupinfo=startupinfo,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                        text=True
                    )
                else:
                    # Linux arp komutu
                    result = subprocess.check_output(
                        f'arp -n {ip_str}', 
                        shell=True, 
                        text=True
                    )
                
                mac = NetworkUtils.extract_mac_from_arp_output(result, ip_str)
                if mac:
                    return mac
            except Exception as e:
                logger.debug(f"ARP komutu hatası: {str(e)}")
            
            # Yöntem 4: Alternatif ping ve sonrasında arp tablosu (yavaş ama bazen etkili)
            try:
                # Önce ping gönder (ARP tablosunu doldurmak için)
                NetworkUtils.ping(ip_str, timeout=0.5, count=1)
                time.sleep(0.2)  # ARP tablosunun güncellenmesi için kısa bekleme
                
                # Sonra ARP tablosunu kontrol et
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE
                
                result = subprocess.check_output(
                    'arp -a', 
                    shell=True, 
                    startupinfo=startupinfo,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    text=True
                )
                
                mac = NetworkUtils.extract_mac_from_arp_output(result, ip_str)
                if mac:
                    return mac
            except Exception as e:
                logger.debug(f"Ping+ARP hatası: {str(e)}")
                
            return ""
            
        except Exception as e:
            logger.debug(f"{ip} için MAC adresi alınırken hata: {str(e)}")
            return ""
    
    @staticmethod
    def check_port(ip, port, timeout=0.5):
        """Belirli bir portun açık olup olmadığını kontrol et"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((str(ip), port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    @staticmethod
    def arp_scan(ip_range, timeout=2):
        """
        Geliştirilmiş ARP taraması - ağda cihazları keşfetmek için
        Scapy kullanılamadığında alternatif yöntemlerle taramayı dener
        """
        results = []
        network = ipaddress.ip_network(ip_range, strict=False)
        
        # Yöntem 1: Scapy kullanarak ARP taraması (en güvenilir)
        if SCAPY_AVAILABLE:
            try:
                logger.info("Scapy ile ARP taraması yapılıyor...")
                # Scapy için string listesine dönüştür
                ip_list = [str(ip) for ip in network.hosts()]
                
                # Scapy'nin arping fonksiyonunu kullan
                ans, _ = scapy.arping(ip_list, timeout=timeout, verbose=0)
                
                for sent, received in ans:
                    results.append((received.psrc, received.hwsrc.upper()))
                    
                if results:
                    return results
            except Exception as e:
                logger.error(f"Scapy ARP taraması sırasında hata: {str(e)}")
        
        # Yöntem 2: arp -a komutu ile tarama
        try:
            logger.info("Alternatif ARP tarama yöntemi kullanılıyor...")
            # Gizli pencerede çalıştırma için yapılandırma
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            
            # arp -a komutu ile mevcut ARP tablosunu al
            output = subprocess.check_output(
                'arp -a', 
                shell=True, 
                startupinfo=startupinfo,
                creationflags=subprocess.CREATE_NO_WINDOW,
                text=True
            )
            
            # Komut çıktısından IP ve MAC adresi eşleşmelerini ayıkla
            ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            mac_pattern = r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})'
            
            for line in output.splitlines():
                ip_match = re.search(ip_pattern, line)
                mac_match = re.search(mac_pattern, line)
                
                if ip_match and mac_match:
                    ip_addr = ip_match.group(0)
                    mac_addr = mac_match.group(0).upper()
                    
                    # IP adresi belirtilen ağda mı kontrol et
                    try:
                        if ipaddress.ip_address(ip_addr) in network:
                            results.append((ip_addr, mac_addr))
                    except:
                        pass
            
            if results:
                return results
                
            # Yöntem 3: Ping taraması + ARP tablosu kullanımı
            logger.info("Ping + ARP taraması yapılıyor...")
            # ARP tablosunu doldurmak için IP aralığına ping gönder
            for ip in network.hosts():
                ip_str = str(ip)
                NetworkUtils.ping(ip_str, timeout=0.2, count=1)
            
            # Kısa bir bekleme ile ARP tablosunun güncellenmesini bekle
            time.sleep(1)
            
            # Güncellenmiş ARP tablosunu tekrar kontrol et
            output = subprocess.check_output(
                'arp -a', 
                shell=True, 
                startupinfo=startupinfo,
                creationflags=subprocess.CREATE_NO_WINDOW,
                text=True
            )
            
            # Sonuçları temizle ve yeniden doldur
            results = []
            
            for line in output.splitlines():
                ip_match = re.search(ip_pattern, line)
                mac_match = re.search(mac_pattern, line)
                
                if ip_match and mac_match:
                    ip_addr = ip_match.group(0)
                    mac_addr = mac_match.group(0).upper()
                    
                    # IP adresi belirtilen ağda mı kontrol et
                    try:
                        if ipaddress.ip_address(ip_addr) in network:
                            results.append((ip_addr, mac_addr))
                    except:
                        pass
                        
        except Exception as e:
            logger.error(f"Alternatif ARP taraması sırasında hata: {str(e)}")
        
        return results


class NetworkScanner:
    """Gelişmiş ağ tarama sınıfı"""
    
    def __init__(self, settings=None, progress_callback=None, status_callback=None, result_callback=None):
        """Initialize scanner with settings and callbacks"""
        self.settings = settings if settings else AppSettings()
        self.progress_callback = progress_callback
        self.status_callback = status_callback
        self.result_callback = result_callback
        
        self.stop_scan = False
        self.scan_results = []
        self.ip_count = 0
        self.scanned_count = 0
        self.start_time = None
        
        # Önbellekler
        self.ip_mac_cache = {}
        self.port_cache = {}
        self.mac_cache = {}
        
        # Npcap kontrolü - yalnızca Windows'ta
        if platform.system().lower() == 'windows':
            if not NetworkUtils.check_npcap():
                logger.warning("Npcap sürücüsü yüklenemedi. ARP taraması sınırlı çalışacak.")
        
    def update_progress(self, percentage, message=""):
        """İlerleme göstergesini güncelle"""
        if self.progress_callback:
            self.progress_callback(percentage, message)
            
    def update_status(self, message):
        """Durum mesajını güncelle"""
        if self.status_callback:
            self.status_callback(message)
            
    def add_result(self, result):
        """Tek bir tarama sonucunu işle ve ekle"""
        if result:
            self.scan_results.append(result)
            if self.result_callback:
                self.result_callback(result)
    
    def scan_ip(self, ip, ports=None, scan_methods=None):
        """
        Tek bir IP adresini belirtilen yöntemlerle tara
        Cihaz bilgilerini içeren sözlük veya cihaz bulunamazsa None döndürür
        """
        if self.stop_scan:
            return None
            
        # Varsayılan tarama yöntemleri
        if scan_methods is None:
            scan_methods = {
                'ping': self.settings.get('ping_scan', True),
                'arp': self.settings.get('arp_scan', True),
                'tcp': self.settings.get('tcp_scan', True)
            }
            
        # Cihazı çoklu yöntemlerle tespit etmeyi dene
        device_active = False
        
        # Ping'e yanıt veriyor mu kontrol et
        if scan_methods.get('ping', True):
            ping_timeout = self.settings.get('timeout', 1.0)
            retry_count = self.settings.get('retry_count', 1)
            
            for _ in range(retry_count):
                if NetworkUtils.ping(ip, timeout=ping_timeout):
                    device_active = True
                    break
        
        # MAC adresini alabilir miyiz (ARP ile)
        mac_address = ""
        if scan_methods.get('arp', True):
            if ip in self.ip_mac_cache:
                mac_address = self.ip_mac_cache[ip]
                if mac_address:
                    device_active = True
            else:
                mac_address = NetworkUtils.get_mac_address(ip)
                self.ip_mac_cache[ip] = mac_address
                if mac_address:
                    device_active = True
        
        # Yaygın portlardan herhangi biri açık mı (TCP bağlantısı)
        open_ports = {}
        if scan_methods.get('tcp', True) and ports:
            port_timeout = self.settings.get('port_timeout', 0.5)
            for port in ports[:min(len(ports), 5)]:  # Tespit için birkaç port dene
                if self.check_port(ip, port, timeout=port_timeout):
                    device_active = True
                    open_ports[port] = COMMON_PORTS.get(port, "Bilinmiyor")
        
        # Hiçbir yöntemle cihaz tespit edilemezse None döndür
        if not device_active:
            return None
        
        # Mümkünse hostname al
        hostname = NetworkUtils.get_hostname(ip)
        
        # Portlar sağlanmışsa daha fazla açık port tara
        if ports and len(open_ports) < len(ports):
            open_ports = self.scan_ports(ip, ports)
        
        # Cihaz bilgilerini döndür
        return {
            "ip": str(ip),
            "status": "Aktif",
            "hostname": hostname,
            "mac_address": mac_address,
            "open_ports": open_ports,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    
    def check_port(self, ip, port, timeout=0.5):
        """Bir portun açık olup olmadığını önbellekli kontrol et"""
        key = f"{ip}:{port}"
        if key in self.port_cache:
            return self.port_cache[key]
        
        is_open = NetworkUtils.check_port(ip, port, timeout)
        self.port_cache[key] = is_open
        return is_open
    
    def scan_ports(self, ip, ports):
        """Bir IP adresinde port listesini tara"""
        open_ports = {}
        port_timeout = self.settings.get('port_timeout', 0.5)
        max_ports = self.settings.get('max_ports', 100)
        
        # Makul sayıya sınırla
        ports_to_scan = ports[:min(len(ports), max_ports)]
        
        for port in ports_to_scan:
            if self.stop_scan:
                break
            if self.check_port(ip, port, timeout=port_timeout):
                service = COMMON_PORTS.get(port, "Bilinmiyor")
                open_ports[port] = service
                
        return open_ports
    
    def scan_ip_range(self, ip_range, ports=None, scan_mode=None):
        """
        Bir IP aralığını aktif cihazlar için tara
        scan_mode: önceden tanımlanmış mod veya tarama yöntemi bayrakları sözlüğü olabilir
        """
        self.stop_scan = False
        self.scan_results = []
        self.start_time = datetime.now()
        
        # Tarama modunu ayrıştır
        scan_methods = None
        if isinstance(scan_mode, dict):
            scan_methods = scan_mode
        elif scan_mode == "Fast":
            scan_methods = {'ping': False, 'arp': True, 'tcp': False}
        elif scan_mode == "Thorough":
            scan_methods = {'ping': True, 'arp': True, 'tcp': True}
            
        # Taranacak portları hazırla
        if ports is None:
            # Varsayılan profili kullan
            profile_name = self.settings.get('port_profile', 'Temel')
            if profile_name in PORT_PROFILES:
                ports = PORT_PROFILES[profile_name]
            else:
                # Ayarlardan özel portları kullan
                port_str = self.settings.get('custom_ports', '80,443,22,3389')
                ports = PortUtils.parse_port_range(port_str)
                
        try:
            # IP aralığını ayrıştır
            network = ipaddress.ip_network(ip_range, strict=False)
            self.ip_count = network.num_addresses
            self.scanned_count = 0
            
            self.update_status(f"IP aralığı taranıyor: {ip_range} ({self.ip_count} adres)")
            
            # ARP taraması etkin ve destekleniyorsa
            if (scan_methods is None or scan_methods.get('arp', True)):
                # Cihazları keşfetmek için hızlı ARP taramasıyla başla
                self.update_status("Cihazları keşfetmek için ARP taraması yapılıyor...")
                arp_results = NetworkUtils.arp_scan(ip_range)
                
                # ARP sonuçlarını MAC önbelleğine ekle
                for ip, mac in arp_results:
                    self.ip_mac_cache[ip] = mac
                
                self.update_status(f"ARP taraması {len(arp_results)} cihaz buldu. Detaylı tarama başlatılıyor...")
            
            # Çok iş parçacıklı tarama kurulumu
            def worker():
                while not q.empty() and not self.stop_scan:
                    ip = q.get()
                    
                    # Tarama gecikmesini uygula (ayarlandıysa)
                    scan_delay = self.settings.get('scan_delay', 0.0)
                    if scan_delay > 0:
                        time.sleep(scan_delay)
                        
                    # IP'yi tara
                    result = self.scan_ip(ip, ports, scan_methods)
                    if result:
                        self.add_result(result)
                    
                    # İlerlemeyi güncelle
                    self.scanned_count += 1
                    progress = (self.scanned_count / self.ip_count) * 100
                    
                    # Tahmini süreyi hesapla
                    eta_str = ""
                    if self.start_time and self.scanned_count > 0:
                        elapsed = datetime.now() - self.start_time
                        if self.scanned_count < self.ip_count:
                            seconds_per_ip = elapsed.total_seconds() / self.scanned_count
                            remaining_ips = self.ip_count - self.scanned_count
                            eta_seconds = seconds_per_ip * remaining_ips
                            eta = datetime.now() + timedelta(seconds=int(eta_seconds))
                            eta_str = f" - Tahmini bitiş: {eta.strftime('%H:%M:%S')}"
                    
                    self.update_progress(progress, 
                                       f"Taranan: {self.scanned_count}/{self.ip_count} - Bulunan: {len(self.scan_results)}{eta_str}")
                    q.task_done()
            
            # İş kuyruğu oluştur
            q = queue.Queue()
            
            # IP'leri kuyruğa ekle
            for ip in network:
                q.put(ip)
                
            # İşçi iş parçacıklarını başlat
            thread_count = self.settings.get('thread_count', min(os.cpu_count() * 2 if os.cpu_count() else 8, 20))
            threads = []
            for _ in range(thread_count):
                t = threading.Thread(target=worker)
                t.daemon = True
                t.start()
                threads.append(t)
                
            # Tüm iş parçacıklarının tamamlanmasını bekle
            while any(t.is_alive() for t in threads) and not self.stop_scan:
                time.sleep(0.2)  # İptal için daha sık kontrol et
                
            if self.stop_scan:
                self.update_status("Tarama kullanıcı tarafından durduruldu.")
            else:
                duration = datetime.now() - self.start_time
                self.update_status(f"Tarama tamamlandı. {len(self.scan_results)} cihaz bulundu ({duration.total_seconds():.1f} saniye).")
                
            return self.scan_results
            
        except Exception as e:
            error_msg = f"Tarama hatası: {str(e)}"
            logger.error(error_msg)
            self.update_status(error_msg)
            return []
    
    def stop_scanning(self):
        """Devam eden taramayı durdur"""
        self.stop_scan = True
        self.update_status("Tarama durduruluyor...")
    
    def export_to_csv(self, filename, results=None):
        """Tarama sonuçlarını CSV'ye aktar"""
        if results is None:
            results = self.scan_results
            
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                # CSV başlıklarını tanımla
                fieldnames = ['ip', 'status', 'hostname', 'mac_address', 'open_ports', 'scan_time']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                # Her sonucu yaz
                for result in results:
                    # Port bilgilerini metne dönüştür
                    ports_str = ', '.join([f"{port} ({service})" for port, service in result.get('open_ports', {}).items()])
                    row = {
                        'ip': result.get('ip', ''),
                        'status': result.get('status', ''),
                        'hostname': result.get('hostname', ''),
                        'mac_address': result.get('mac_address', ''),
                        'open_ports': ports_str,
                        'scan_time': result.get('scan_time', '')
                    }
                    writer.writerow(row)
                    
            return True, f"{len(results)} kayıt başarıyla dışa aktarıldı."
        except Exception as e:
            error_msg = f"Dışa aktarma hatası: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def export_to_excel(self, filename, results=None):
        """Tarama sonuçlarını Excel'e aktar"""
        if not PANDAS_AVAILABLE:
            return False, "Excel aktarımı için pandas kütüphanesi gerekiyor."
            
        if results is None:
            results = self.scan_results
            
        try:
            # DataFrame için veri hazırla
            data = []
            for result in results:
                # Port bilgilerini metne dönüştür
                ports_str = ', '.join([f"{port} ({service})" for port, service in result.get('open_ports', {}).items()])
                row = {
                    'IP Adresi': result.get('ip', ''),
                    'Durum': result.get('status', ''),
                    'Hostname': result.get('hostname', ''),
                    'MAC Adresi': result.get('mac_address', ''),
                    'Açık Portlar': ports_str,
                    'Tarama Zamanı': result.get('scan_time', '')
                }
                data.append(row)
                
            # Ana DataFrame oluştur
            df = pd.DataFrame(data)
            
            # Excel yazıcısı oluştur
            with pd.ExcelWriter(filename, engine='openpyxl') as writer:
                df.to_excel(writer, sheet_name='Tarama Sonuçları', index=False)
                
                # Port detayları için ayrı bir sheet ekle
                port_data = []
                for result in results:
                    ip = result.get('ip', '')
                    for port, service in result.get('open_ports', {}).items():
                        port_data.append({
                            'IP Adresi': ip, 
                            'Port': port, 
                            'Servis': service
                        })
                        
                if port_data:
                    port_df = pd.DataFrame(port_data)
                    port_df.to_excel(writer, sheet_name='Port Detayları', index=False)
                
            return True, f"{len(results)} kayıt başarıyla Excel'e aktarıldı."
        except Exception as e:
            error_msg = f"Excel aktarma hatası: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def get_scan_statistics(self, results=None):
        """Tarama sonuçlarından istatistikler oluştur"""
        if results is None:
            results = self.scan_results
            
        stats = {
            'total_devices': len(results),
            'device_types': defaultdict(int),
            'top_ports': defaultdict(int),
            'hostname_ratio': 0,
            'mac_ratio': 0
        }
        
        if not results:
            return stats
            
        # İstatistikleri hesapla
        hostname_count = 0
        mac_count = 0
        
        for device in results:
            # Hostname'i olan cihazları say
            if device.get('hostname', ''):
                hostname_count += 1
                
            # MAC adresi olan cihazları say
            if device.get('mac_address', ''):
                mac_count += 1
                
            # Port sayılarını topla
            for port, service in device.get('open_ports', {}).items():
                stats['top_ports'][f"{port} ({service})"] += 1
                
                # Portlara göre cihazı sınıflandır
                if port in [80, 443, 8080, 8443]:
                    stats['device_types']['Web Sunucusu'] += 1
                elif port in [21, 22, 23]:
                    stats['device_types']['Uzak Erişim'] += 1
                elif port in [445, 139]:
                    stats['device_types']['Dosya Sunucusu'] += 1
                elif port in [1433, 3306, 5432, 27017]:
                    stats['device_types']['Veritabanı'] += 1
                    
        # Oranları hesapla
        total = len(results)
        stats['hostname_ratio'] = (hostname_count / total) * 100 if total > 0 else 0
        stats['mac_ratio'] = (mac_count / total) * 100 if total > 0 else 0
        
        # Cihaz türlerinin cihazları birden fazla kez saymamasını sağla
        for device_type in stats['device_types']:
            stats['device_types'][device_type] = min(stats['device_types'][device_type], total)
            
        return stats


class PortConfigDialog(tk.Toplevel):
    """Port yapılandırma iletişim kutusu"""
    
    def __init__(self, parent, current_ports=None, profiles=None):
        super().__init__(parent)
        self.title("Port Yapılandırması")
        self.geometry("600x500")
        self.minsize(500, 400)
        self.transient(parent)
        self.grab_set()
        
        # Değişkenleri başlat
        self.result = None
        self.current_ports = current_ports or []
        self.profiles = profiles or PORT_PROFILES.copy()
        self.count_var = tk.StringVar()  
        
        # Bileşenleri oluştur
        self.create_widgets()
        
        # İletişim kutusunu ortala
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')
        
        # İletişim kutusunu modal yap
        self.wait_window(self)
        
    def create_widgets(self):
        # Ana çerçeve
        main_frame = ttk.Frame(self, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Profil seçim çerçevesi
        profile_frame = ttk.LabelFrame(main_frame, text="Port Profilleri")
        profile_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Profil seçimi
        self.profile_var = tk.StringVar()
        profiles = list(self.profiles.keys())
        profile_options = ttk.Combobox(profile_frame, textvariable=self.profile_var, values=profiles, width=20)
        profile_options.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        if profiles:
            profile_options.current(0)
        
        # Profil yükleme butonu
        load_btn = ttk.Button(profile_frame, text="Profili Yükle", command=self.load_profile)
        load_btn.grid(row=0, column=1, padx=5, pady=5)
        
        # Profili kaydetme butonu
        save_btn = ttk.Button(profile_frame, text="Profil Olarak Kaydet", command=self.save_profile)
        save_btn.grid(row=0, column=2, padx=5, pady=5)
        
        # Profil silme butonu
        delete_btn = ttk.Button(profile_frame, text="Profili Sil", command=self.delete_profile)
        delete_btn.grid(row=0, column=3, padx=5, pady=5)
        
        # Manuel port giriş çerçevesi
        entry_frame = ttk.LabelFrame(main_frame, text="Özel Port Aralığı")
        entry_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Yardım metni
        ttk.Label(entry_frame, text="Portları veya aralıkları girin (örn. '80,443,8000-8100'):").grid(
            row=0, column=0, columnspan=3, sticky=tk.W, padx=5, pady=(5, 0))
        
        # Port girişi
        self.port_entry_var = tk.StringVar(value=PortUtils.format_port_range(self.current_ports))
        port_entry = ttk.Entry(entry_frame, textvariable=self.port_entry_var, width=50)
        port_entry.grid(row=1, column=0, padx=5, pady=5, sticky=tk.EW)
        
        # Ayrıştırma butonu
        parse_btn = ttk.Button(entry_frame, text="Ayrıştır", command=self.parse_ports)
        parse_btn.grid(row=1, column=1, padx=5, pady=5)
        
        # Temizleme butonu
        clear_btn = ttk.Button(entry_frame, text="Temizle", command=lambda: self.port_entry_var.set(""))
        clear_btn.grid(row=1, column=2, padx=5, pady=5)
        
        # entry_frame grid yapılandırması
        entry_frame.grid_columnconfigure(0, weight=1)
        
        # Port liste çerçevesi
        list_frame = ttk.LabelFrame(main_frame, text="Seçili Portlar")
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Kaydırma çubuğu ile port listesi
        port_list_frame = ttk.Frame(list_frame)
        port_list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Kaydırma çubukları
        scrollbar_y = ttk.Scrollbar(port_list_frame)
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Onay kutusu seçenekleri ile port listesi
        self.port_listbox = tk.Listbox(port_list_frame, selectmode=tk.EXTENDED,
                                     yscrollcommand=scrollbar_y.set)
        self.port_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar_y.config(command=self.port_listbox.yview)
        
        # Port listesini doldur
        self.update_port_list()
        
        # Port listesi yönetimi için butonlar
        btn_frame = ttk.Frame(list_frame)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Yaygın portlar butonu
        add_common_btn = ttk.Button(btn_frame, text="Yaygın Portları Ekle", command=self.add_common_ports)
        add_common_btn.pack(side=tk.LEFT, padx=2)
        
        # Seçilenleri kaldır butonu
        remove_btn = ttk.Button(btn_frame, text="Seçilenleri Kaldır", command=self.remove_selected)
        remove_btn.pack(side=tk.LEFT, padx=2)
        
        # Tümünü temizle butonu
        clear_all_btn = ttk.Button(btn_frame, text="Tümünü Temizle", command=self.clear_all_ports)
        clear_all_btn.pack(side=tk.LEFT, padx=2)
        
        # Tümünü seç butonu
        select_all_btn = ttk.Button(btn_frame, text="Tümünü Seç", command=self.select_all)
        select_all_btn.pack(side=tk.LEFT, padx=2)
        
        # İletişim kutusu butonları
        dialog_btn_frame = ttk.Frame(main_frame)
        dialog_btn_frame.pack(fill=tk.X, pady=(10, 0))
        
        # İptal butonu
        cancel_btn = ttk.Button(dialog_btn_frame, text="İptal", command=self.cancel)
        cancel_btn.pack(side=tk.RIGHT, padx=5)
        
        # Tamam butonu
        ok_btn = ttk.Button(dialog_btn_frame, text="Tamam", command=self.ok)
        ok_btn.pack(side=tk.RIGHT, padx=5)
        
        # Sayaç etiketi
        self.count_var = tk.StringVar(value=f"Seçili port sayısı: {len(self.current_ports)}")
        count_label = ttk.Label(dialog_btn_frame, textvariable=self.count_var)
        count_label.pack(side=tk.LEFT, padx=5)
        
    def update_port_list(self):
        """Port listesini mevcut portlarla güncelle"""
        self.port_listbox.delete(0, tk.END)
        
        for port in sorted(self.current_ports):
            service = COMMON_PORTS.get(port, "Bilinmiyor")
            self.port_listbox.insert(tk.END, f"{port} - {service}")
            
        self.count_var.set(f"Seçili port sayısı: {len(self.current_ports)}")
        
    def parse_ports(self):
        """Port aralığı metnini ayrıştır ve port listesini güncelle"""
        port_text = self.port_entry_var.get().strip()
        if not port_text:
            return
            
        parsed_ports = PortUtils.parse_port_range(port_text)
        
        # Mevcut portları güncelle
        self.current_ports = parsed_ports
        
        # Görüntülenen listeyi güncelle
        self.update_port_list()
        
    def load_profile(self):
        """Önceden tanımlanmış port profilini yükle"""
        profile_name = self.profile_var.get()
        if not profile_name or profile_name not in self.profiles:
            messagebox.showwarning("Profil Hatası", "Lütfen geçerli bir profil seçin.")
            return
            
        # Seçilen profili yükle
        self.current_ports = self.profiles[profile_name]
        
        # Giriş alanını güncelle
        self.port_entry_var.set(PortUtils.format_port_range(self.current_ports))
        
        # Port listesini güncelle
        self.update_port_list()
        
    def save_profile(self):
        """Mevcut portları profil olarak kaydet"""
        if not self.current_ports:
            messagebox.showwarning("Kayıt Hatası", "Kaydedilecek port seçilmedi.")
            return
            
        # Profil adını sor
        profile_name = simpledialog.askstring("Profil Kaydet", "Profil adını girin:", parent=self)
        if not profile_name:
            return
            
        # Profil varsa üzerine yazma onayı
        if profile_name in self.profiles:
            confirm = messagebox.askyesno("Üzerine Yazma Onayı", 
                                        f"'{profile_name}' profili zaten var. Üzerine yazılsın mı?")
            if not confirm:
                return
                
        # Profili kaydet
        self.profiles[profile_name] = self.current_ports.copy()
        
        # Profil açılır listesini güncelle
        profile_options = self.nametowidget(str(self.profile_var) + 'values')
        if isinstance(profile_options, ttk.Combobox):
            profile_options['values'] = list(self.profiles.keys())
            profile_options.set(profile_name)
            
        messagebox.showinfo("Profil Kaydedildi", f"'{profile_name}' profili {len(self.current_ports)} port ile kaydedildi.")
        
    def delete_profile(self):
        """Seçilen profili sil"""
        profile_name = self.profile_var.get()
        if not profile_name or profile_name not in self.profiles:
            messagebox.showwarning("Silme Hatası", "Lütfen silmek için geçerli bir profil seçin.")
            return
            
        # Yerleşik profillerin silinmesini engelle
        if profile_name in PORT_PROFILES:
            messagebox.showwarning("Silme Hatası", "Yerleşik profiller silinemez.")
            return
            
        # Silme onayı
        confirm = messagebox.askyesno("Silme Onayı", f"'{profile_name}' profili silinsin mi?")
        if not confirm:
            return
            
        # Profili sil
        del self.profiles[profile_name]
        
        # Profil açılır listesini güncelle
        profile_options = self.nametowidget(str(self.profile_var) + 'values')
        if isinstance(profile_options, ttk.Combobox):
            profile_options['values'] = list(self.profiles.keys())
            if profile_options['values']:
                profile_options.current(0)
            else:
                profile_options.set("")
                
        messagebox.showinfo("Profil Silindi", f"'{profile_name}' profili silindi.")
        
    def add_common_ports(self):
        """Mevcut seçime yaygın portları ekle"""
        common_ports = list(COMMON_PORTS.keys())
        
        # Tekrar olmadan mevcut portlara ekle
        for port in common_ports:
            if port not in self.current_ports:
                self.current_ports.append(port)
                
        # Portları sırala
        self.current_ports = sorted(self.current_ports)
        
        # Giriş alanını güncelle
        self.port_entry_var.set(PortUtils.format_port_range(self.current_ports))
        
        # Port listesini güncelle
        self.update_port_list()
        
    def remove_selected(self):
        """Seçilen portları listeden kaldır"""
        selected_indices = self.port_listbox.curselection()
        if not selected_indices:
            return
            
        # Kaldırılacak portları al
        ports_to_remove = []
        for i in selected_indices:
            port_str = self.port_listbox.get(i).split(" - ")[0]
            try:
                port = int(port_str)
                ports_to_remove.append(port)
            except ValueError:
                continue
                
        # Portları kaldır
        self.current_ports = [port for port in self.current_ports if port not in ports_to_remove]
        
        # Giriş alanını güncelle
        self.port_entry_var.set(PortUtils.format_port_range(self.current_ports))
        
        # Port listesini güncelle
        self.update_port_list()
        
    def clear_all_ports(self):
        """Tüm portları listeden temizle"""
        self.current_ports = []
        self.port_entry_var.set("")
        self.update_port_list()
        
    def select_all(self):
        """Listedeki tüm portları seç"""
        self.port_listbox.select_set(0, tk.END)
        
    def ok(self):
        """Değişiklikleri kaydet ve iletişim kutusunu kapat"""
        # Girişteki portların ayrıştırıldığından emin ol
        self.parse_ports()
        
        # Sonucu ayarla ve kapat
        self.result = self.current_ports
        self.destroy()
        
    def cancel(self):
        """İptal et ve kapat"""
        self.result = None
        self.destroy()


class SettingsDialog(tk.Toplevel):
    """Ayarlar iletişim kutusu"""
    
    def __init__(self, parent, settings):
        super().__init__(parent)
        self.title("NetScan Ayarları")
        self.geometry("600x400")
        self.minsize(500, 400)
        self.transient(parent)
        self.grab_set()
        
        # Ayarları sakla
        self.settings = settings
        self.result = False
        
        # Bileşenleri oluştur
        self.create_widgets()
        
        # İletişim kutusunu ortala
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')
        
        # İletişim kutusunu modal yap
        self.wait_window(self)
        
    def create_widgets(self):
        # Sekmeli arayüz için notebook
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Genel ayarlar sekmesi
        general_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(general_frame, text="Genel")
        self.create_general_tab(general_frame)
        
        # Tarama ayarları sekmesi
        scan_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(scan_frame, text="Tarama")
        self.create_scan_tab(scan_frame)
        
        # Port ayarları sekmesi
        port_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(port_frame, text="Portlar")
        self.create_port_tab(port_frame)
        
        # Gelişmiş ayarlar sekmesi
        advanced_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(advanced_frame, text="Gelişmiş")
        self.create_advanced_tab(advanced_frame)
        
        # Alt butonlar
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Varsayılan olarak kaydet butonu
        save_default_btn = ttk.Button(btn_frame, text="Varsayılan Olarak Kaydet", command=self.save_default)
        save_default_btn.pack(side=tk.LEFT, padx=5)
        
        # Sıfırlama butonu
        reset_btn = ttk.Button(btn_frame, text="Varsayılanlara Sıfırla", command=self.reset_defaults)
        reset_btn.pack(side=tk.LEFT, padx=5)
        
        # İptal butonu
        cancel_btn = ttk.Button(btn_frame, text="İptal", command=self.cancel)
        cancel_btn.pack(side=tk.RIGHT, padx=5)
        
        # Tamam butonu
        ok_btn = ttk.Button(btn_frame, text="Tamam", command=self.ok)
        ok_btn.pack(side=tk.RIGHT, padx=5)
        
    def create_general_tab(self, parent):
        """Genel ayarlar sekmesini oluştur"""
        # Varsayılan IP aralığı
        ttk.Label(parent, text="Varsayılan IP Aralığı:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.ip_range_var = tk.StringVar(value=self.settings.get('ip_range'))
        ip_entry = ttk.Entry(parent, textvariable=self.ip_range_var, width=20)
        ip_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Otomatik algılama butonu
        auto_btn = ttk.Button(parent, text="Otomatik Algıla", command=self.auto_detect_network)
        auto_btn.grid(row=0, column=2, padx=5, pady=5)
        
        # Varsayılan tarama modu
        ttk.Label(parent, text="Varsayılan Tarama Modu:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.scan_mode_var = tk.StringVar(value=self.settings.get('scan_mode'))
        mode_combo = ttk.Combobox(parent, textvariable=self.scan_mode_var, width=20)
        mode_combo['values'] = ('Fast', 'Normal', 'Thorough')
        if self.scan_mode_var.get() not in mode_combo['values']:
            self.scan_mode_var.set('Normal')
        mode_combo.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Sonuçları kaydetme yolu
        ttk.Label(parent, text="Sonuçları Kaydetme Yolu:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.save_path_var = tk.StringVar(value=self.settings.get('save_path'))
        path_entry = ttk.Entry(parent, textvariable=self.save_path_var, width=30)
        path_entry.grid(row=2, column=1, columnspan=2, sticky=tk.EW, padx=5, pady=5)
        
        # Gözat butonu
        browse_btn = ttk.Button(parent, text="Gözat...", command=self.browse_path)
        browse_btn.grid(row=2, column=3, padx=5, pady=5)
        
        # Grid yapılandırması
        parent.grid_columnconfigure(1, weight=1)
        
    def create_scan_tab(self, parent):
        """Tarama ayarları sekmesini oluştur"""
        # İş parçacığı sayısı
        ttk.Label(parent, text="Tarama İş Parçacığı Sayısı:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.thread_var = tk.StringVar(value=str(self.settings.get('thread_count')))
        thread_spin = ttk.Spinbox(parent, from_=1, to=50, textvariable=self.thread_var, width=10)
        thread_spin.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Zaman aşımı
        ttk.Label(parent, text="Zaman Aşımı (saniye):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.timeout_var = tk.StringVar(value=str(self.settings.get('timeout')))
        timeout_spin = ttk.Spinbox(parent, from_=0.1, to=10.0, increment=0.1, textvariable=self.timeout_var, width=10)
        timeout_spin.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Yeniden deneme sayısı
        ttk.Label(parent, text="Yeniden Deneme Sayısı:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.retry_var = tk.StringVar(value=str(self.settings.get('retry_count')))
        retry_spin = ttk.Spinbox(parent, from_=0, to=5, textvariable=self.retry_var, width=10)
        retry_spin.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Tarama gecikmesi
        ttk.Label(parent, text="Tarama Gecikmesi (saniye):").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        self.delay_var = tk.StringVar(value=str(self.settings.get('scan_delay')))
        delay_spin = ttk.Spinbox(parent, from_=0.0, to=1.0, increment=0.1, textvariable=self.delay_var, width=10)
        delay_spin.grid(row=3, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Tarama yöntemleri çerçevesi
        methods_frame = ttk.LabelFrame(parent, text="Tarama Yöntemleri")
        methods_frame.grid(row=4, column=0, columnspan=2, sticky=tk.EW, padx=5, pady=10)
        
        # Ping taraması
        self.ping_var = tk.BooleanVar(value=self.settings.get('ping_scan'))
        ping_check = ttk.Checkbutton(methods_frame, text="ICMP Ping Taraması", variable=self.ping_var)
        ping_check.grid(row=0, column=0, sticky=tk.W, padx=20, pady=5)
        
        # ARP taraması
        self.arp_var = tk.BooleanVar(value=self.settings.get('arp_scan'))
        arp_check = ttk.Checkbutton(methods_frame, text="ARP Taraması", variable=self.arp_var)
        arp_check.grid(row=1, column=0, sticky=tk.W, padx=20, pady=5)
        
        # TCP taraması
        self.tcp_var = tk.BooleanVar(value=self.settings.get('tcp_scan'))
        tcp_check = ttk.Checkbutton(methods_frame, text="TCP Bağlantı Taraması", variable=self.tcp_var)
        tcp_check.grid(row=2, column=0, sticky=tk.W, padx=20, pady=5)
        
        # Yöntem açıklaması
        description_frame = ttk.Frame(methods_frame)
        description_frame.grid(row=0, column=1, rowspan=3, padx=10, pady=5, sticky=tk.NSEW)
        
        description_text = (
            "Ping Taraması: Aktif cihazları tespit etmek için ICMP echo istekleri kullanır. Güvenlik duvarları tarafından engellenebilir.\n\n"
            "ARP Taraması: Yerel ağlarda cihazları keşfetmek için ARP protokolünü kullanır. Hızlıdır ancak sadece yerel ağda çalışır.\n\n"
            "TCP Taraması: Yaygın portlara TCP bağlantıları kurmayı dener. Ağlar arası çalışır ancak daha yavaştır."
        )
        
        description_label = ttk.Label(description_frame, text=description_text, wraplength=300, justify=tk.LEFT)
        description_label.pack(fill=tk.BOTH, expand=True)
        
        # Grid yapılandırması
        parent.grid_columnconfigure(1, weight=1)
        methods_frame.grid_columnconfigure(1, weight=1)
        
    def create_port_tab(self, parent):
        """Port tarama ayarları sekmesini oluştur"""
        # Varsayılan port profili
        ttk.Label(parent, text="Varsayılan Port Profili:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.port_profile_var = tk.StringVar(value=self.settings.get('port_profile'))
        profile_combo = ttk.Combobox(parent, textvariable=self.port_profile_var, width=20)
        profile_combo['values'] = list(PORT_PROFILES.keys())
        if self.port_profile_var.get() not in profile_combo['values']:
            self.port_profile_var.set('Temel')
        profile_combo.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Port zaman aşımı
        ttk.Label(parent, text="Port Zaman Aşımı (saniye):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.port_timeout_var = tk.StringVar(value=str(self.settings.get('port_timeout')))
        port_timeout_spin = ttk.Spinbox(parent, from_=0.1, to=5.0, increment=0.1, textvariable=self.port_timeout_var, width=10)
        port_timeout_spin.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Host başına max port
        ttk.Label(parent, text="Host Başına Max Port:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.max_ports_var = tk.StringVar(value=str(self.settings.get('max_ports')))
        max_ports_spin = ttk.Spinbox(parent, from_=1, to=1000, textvariable=self.max_ports_var, width=10)
        max_ports_spin.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Özel portlar
        ttk.Label(parent, text="Özel Portlar:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        self.custom_ports_var = tk.StringVar(value=self.settings.get('custom_ports'))
        ttk.Entry(parent, textvariable=self.custom_ports_var, width=40).grid(row=3, column=1, columnspan=2, sticky=tk.EW, padx=5, pady=5)
        
        # Yapılandırma butonu
        config_btn = ttk.Button(parent, text="Portları Yapılandır...", command=self.configure_ports)
        config_btn.grid(row=3, column=3, padx=5, pady=5)
        
        # Port bilgisi
        info_frame = ttk.LabelFrame(parent, text="Port Profilleri Bilgisi")
        info_frame.grid(row=4, column=0, columnspan=4, sticky=tk.EW, padx=5, pady=10)
        
        # Profil bilgisi için kaydırılabilir metin alanı oluştur
        port_info_text = ScrolledText(info_frame, wrap=tk.WORD, height=10, width=50)
        port_info_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        port_info_text.insert(tk.END, "Port Profilleri:\n\n")
        
        # Her profil hakkında bilgi ekle
        for name, ports in PORT_PROFILES.items():
            port_info_text.insert(tk.END, f"{name}: {len(ports)} port\n")
            port_info_text.insert(tk.END, f"    Örnek portlar: {', '.join(map(str, sorted(ports)[:5]))}")
            if len(ports) > 5:
                port_info_text.insert(tk.END, " ...")
            port_info_text.insert(tk.END, "\n\n")
            
        port_info_text.configure(state='disabled')  # Salt okunur yap
        
        # Grid yapılandırması
        parent.grid_columnconfigure(1, weight=1)
        
    def create_advanced_tab(self, parent):
        """Gelişmiş ayarlar sekmesini oluştur"""
        # Bağımlılık durumu çerçevesi
        dep_frame = ttk.LabelFrame(parent, text="Bağımlılık Durumu")
        dep_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Bağımlılıkları kontrol et
        dep_text = ScrolledText(dep_frame, wrap=tk.WORD, height=12, width=50)
        dep_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        dep_text.insert(tk.END, "NetScan Opsiyonel Bağımlılıkları:\n\n")
        
        # Her opsiyonel bağımlılığı kontrol et
        dependencies = [
            ("getmac", MAC_MODULE_AVAILABLE, "MAC adresi çözümleme"),
            ("pandas", PANDAS_AVAILABLE, "Excel dışa aktarma"),
            ("scapy", SCAPY_AVAILABLE, "Gelişmiş ağ taraması"),
            ("python-nmap", NMAP_MODULE_AVAILABLE, "Detaylı port taraması"),
            ("matplotlib", MATPLOTLIB_AVAILABLE, "Görselleştirmeler"),
            ("ttkthemes", THEMES_AVAILABLE, "Gelişmiş temalar")
        ]
        
        for dep, available, purpose in dependencies:
            status = "Yüklü" if available else "Eksik"
            color = "green" if available else "red"
            dep_text.insert(tk.END, f"{dep}: {status} - {purpose}\n")
            
            # Durum metnine renk uygula
            start = dep_text.search(status, "1.0", tk.END)
            if start:
                end = f"{start}+{len(status)}c"
                dep_text.tag_add(color, start, end)
                dep_text.tag_config(color, foreground=color)
        
        dep_text.insert(tk.END, "\nEksik bağımlılıklar pip ile yüklenebilir:\n")
        dep_text.insert(tk.END, "pip install " + " ".join([d[0] for d in dependencies if not d[1]]))
        
        dep_text.configure(state='disabled')  # Salt okunur yap
        
        # Gelişmiş seçenekler
        adv_frame = ttk.LabelFrame(parent, text="Gelişmiş Seçenekler")
        adv_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Gelişmiş uyarı göster
        warning_text = (
            "Not: Gelişmiş seçenekler tarama performansını ve doğruluğunu etkileyebilir.\n"
            "Çoğu kullanıcı için varsayılan ayarlar önerilir."
        )
        ttk.Label(adv_frame, text=warning_text, wraplength=400).pack(padx=10, pady=10)
        
    def auto_detect_network(self):
        """Yerel ağı otomatik algıla"""
        network = NetworkUtils.get_network_prefix()
        self.ip_range_var.set(network)
        
    def browse_path(self):
        """Sonuçları kaydetme yolu için göz at"""
        directory = filedialog.askdirectory(initialdir=self.save_path_var.get())
        if directory:
            self.save_path_var.set(directory)
            
    def configure_ports(self):
        """Port yapılandırma iletişim kutusunu aç"""
        # Mevcut özel portları ayrıştır
        current_ports = PortUtils.parse_port_range(self.custom_ports_var.get())
        
        # Port yapılandırma iletişim kutusunu aç
        dialog = PortConfigDialog(self, current_ports, PORT_PROFILES)
        
        # İletişim kutusu iptal edilmediyse özel portları güncelle
        if dialog.result is not None:
            self.custom_ports_var.set(PortUtils.format_port_range(dialog.result))
            
    def save_default(self):
        """Mevcut ayarları varsayılan olarak kaydet"""
        if self.apply_settings():
            
            success = self.settings.save_settings()
            if success:
                messagebox.showinfo("Ayarlar", "Ayarlar varsayılan olarak kaydedildi.")
            else:
                messagebox.showerror("Ayar Hatası", "Ayarlar kaydedilemedi.")
            
    def reset_defaults(self):
        """Varsayılan ayarlara sıfırla"""
        confirm = messagebox.askyesno("Sıfırlama Onayı", 
                              "Tüm ayarları varsayılan değerlere sıfırlamak istediğinizden emin misiniz?")
        if not confirm:
            return
            
        # Yeni AppSettings oluşturarak varsayılan ayarları yükle
        self.settings = AppSettings()
        
        # İletişim kutusunu varsayılan ayarlarla yeniden oluştur
        self.destroy()
        SettingsDialog(self.master, self.settings)
            
    def apply_settings(self):
        """Mevcut ayarları yapılandırmaya uygula"""
        try:
            # Genel ayarlar
            self.settings.set('ip_range', self.ip_range_var.get())
            self.settings.set('scan_mode', self.scan_mode_var.get())
            self.settings.set('save_path', self.save_path_var.get())
            
            # Tarama ayarları
            self.settings.set('thread_count', int(self.thread_var.get()))
            self.settings.set('timeout', float(self.timeout_var.get()))
            self.settings.set('retry_count', int(self.retry_var.get()))
            self.settings.set('ping_scan', bool(self.ping_var.get()))
            self.settings.set('arp_scan', bool(self.arp_var.get()))
            self.settings.set('tcp_scan', bool(self.tcp_var.get()))
            self.settings.set('scan_delay', float(self.delay_var.get()))
            
            # Port tarama ayarları
            self.settings.set('port_profile', self.port_profile_var.get())
            self.settings.set('port_timeout', float(self.port_timeout_var.get()))
            self.settings.set('max_ports', int(self.max_ports_var.get()))
            self.settings.set('custom_ports', self.custom_ports_var.get())
            
            return True
        except Exception as e:
            logger.error(f"Ayarlar uygulanırken hata: {str(e)}")
            messagebox.showerror("Ayar Hatası", f"Ayarlar uygulanırken hata: {str(e)}")
            return False
            
    def ok(self):
        """Ayarları uygula ve iletişim kutusunu kapat"""
        if self.apply_settings():
            self.result = True
            self.destroy()
            
    def cancel(self):
        """İptal et ve kapat"""
        self.result = False
        self.destroy()


class NetworkScannerApp(tk.Tk):
    """Ana uygulama penceresi"""
    
    def __init__(self):
        super().__init__()
        self.title("NetScan Pro - Gelişmiş Ağ Tarama Aracı | Developer: Emre Göçmen info@emregocmen.com")
        self.geometry("1200x700")
        self.minsize(900, 600)

        # Tema ayarla
        if THEMES_AVAILABLE:
            self.style = ttkthemes.ThemedStyle(self)
            self.style.set_theme("arc")
        else:
            self.style = ttk.Style()
        
        # Uygulama simgesi
        self.set_app_icon()
        
        # Ayarları yükle
        self.app_settings = AppSettings()
        
        # Tarayıcı nesnesi oluştur
        self.scanner = NetworkScanner(
            settings=self.app_settings,
            progress_callback=self.update_progress,
            status_callback=self.update_status,
            result_callback=self.add_scan_result
        )
        
        # Değişkenleri başlat
        self.scan_results = []
        self.scanning = False
        self.filter_timer = None
        self.last_selected_ip = None
        
        # Ana çerçeveyi oluştur
        self.main_frame = ttk.Frame(self)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # UI bileşenlerini oluştur
        self.create_menu()
        self.create_toolbar()
        self.create_main_content()
        self.create_status_bar()
        
        # Başlangıç durumu
        self.update_status("Hazır. Tarama başlatmak için bir IP aralığı girin ve 'Taramayı Başlat' düğmesine tıklayın.")
        
        # Sütun genişliklerini uygula
        self.result_tree.column("ip", width=120)
        self.result_tree.column("hostname", width=150)
        self.result_tree.column("mac_address", width=150)
        self.result_tree.column("open_ports", width=250)
        
        # Port detay çerçevesini varsayılan olarak gizle
        self.port_detail_frame.pack_forget()     
        
    def set_app_icon(self):
        """Windows’ta görev çubuğu ikonu için güvenli ikon ayarı."""
        try:
            # PyInstaller derlemesi mi?
            if getattr(sys, 'frozen', False):
                base_path = os.path.dirname(sys.executable)
            else:
                base_path = os.path.dirname(__file__)

            # Öncelik .ico, yoksa .png
            ico_path = os.path.join(base_path, "icon.ico")
            png_path = os.path.join(base_path, "icon.png")
            if os.path.exists(ico_path):
                icon_file = ico_path
            elif os.path.exists(png_path):
                icon_file = png_path
            else:
                logger.warning(f"İkon bulunamadı: {ico_path} veya {png_path}")
                return

            # Fotoğrafı pencereye master olarak bağlayarak yükle
            self.icon_photo = tk.PhotoImage(file=icon_file, master=self)
            self.iconphoto(True, self.icon_photo)

        except Exception as e:
            logger.error(f"İkon yükleme hatası: {e}")
    
    def create_menu(self):
        """Uygulama menüsünü oluştur"""
        menubar = tk.Menu(self)
        
        # Dosya menüsü
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Yeni Tarama", command=self.reset_scan)
        file_menu.add_command(label="Sonuçları Aç...", command=self.open_results)
        file_menu.add_command(label="Sonuçları Kaydet...", command=self.save_results)
        file_menu.add_separator()
        file_menu.add_command(label="CSV Olarak Dışa Aktar...", command=lambda: self.export_results("csv"))
        file_menu.add_command(label="Excel Olarak Dışa Aktar...", command=lambda: self.export_results("excel"))
        file_menu.add_separator()
        file_menu.add_command(label="Çıkış", command=self.quit)
        menubar.add_cascade(label="Dosya", menu=file_menu)
        
        # Tarama menüsü
        scan_menu = tk.Menu(menubar, tearoff=0)
        scan_menu.add_command(label="Taramayı Başlat", command=self.start_scan)
        scan_menu.add_command(label="Taramayı Durdur", command=self.stop_scan)
        scan_menu.add_separator()
        scan_menu.add_command(label="Portları Yapılandır...", command=self.configure_ports)
        menubar.add_cascade(label="Tarama", menu=scan_menu)
        
        # Görünüm menüsü
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Görünümü Yenile", command=self.refresh_view)
        view_menu.add_command(label="Sonuçları Temizle", command=self.clear_results)
        view_menu.add_separator()
        view_menu.add_command(label="Port Detaylarını Göster", command=self.toggle_port_details)
        menubar.add_cascade(label="Görünüm", menu=view_menu)
        
        # Araçlar menüsü
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Ağ Bilgisi", command=self.show_network_info)
        tools_menu.add_command(label="Port Referansı", command=self.show_port_reference)
        tools_menu.add_separator()
        tools_menu.add_command(label="Ayarlar...", command=self.show_settings)
        menubar.add_cascade(label="Araçlar", menu=tools_menu)
        
        # Yardım menüsü
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Kullanım Kılavuzu", command=self.show_user_guide)
        help_menu.add_command(label="Güncellemeleri Kontrol Et", command=self.check_updates)
        help_menu.add_separator()
        help_menu.add_command(label="Hakkında", command=self.show_about)
        menubar.add_cascade(label="Yardım", menu=help_menu)
        
        # Menüyü ayarla (configure metodu kullanarak)
        self.configure(menu=menubar)
        
    def create_toolbar(self):
        """Araç çubuğunu oluştur"""
        toolbar_frame = ttk.Frame(self.main_frame)
        toolbar_frame.pack(fill=tk.X, pady=(0, 5))
        
        # Birleşik görünümlü araç çubuğu düğmeleri oluştur
        self.toolbar_buttons = []
        
        # IP aralığı girişi
        ttk.Label(toolbar_frame, text="IP Aralığı:").pack(side=tk.LEFT, padx=(0, 5))
        self.ip_range_var = tk.StringVar(value=self.app_settings.get('ip_range'))
        ip_entry = ttk.Entry(toolbar_frame, textvariable=self.ip_range_var, width=20)
        ip_entry.pack(side=tk.LEFT, padx=5)
        
        # Otomatik algılama düğmesi
        auto_btn = ttk.Button(toolbar_frame, text="Otomatik Algıla", 
                            command=self.auto_detect_network, width=12)
        auto_btn.pack(side=tk.LEFT, padx=5)
        self.toolbar_buttons.append(auto_btn)
        
        # Tarama modu seçimi
        ttk.Label(toolbar_frame, text="Mod:").pack(side=tk.LEFT, padx=(10, 5))
        self.scan_mode_var = tk.StringVar(value=self.app_settings.get('scan_mode'))
        mode_combo = ttk.Combobox(toolbar_frame, textvariable=self.scan_mode_var, width=10)
        mode_combo['values'] = ('Fast', 'Normal', 'Thorough')
        mode_combo.pack(side=tk.LEFT, padx=5)
        
        # Ayırıcı
        ttk.Separator(toolbar_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=5)
        
        # Başlat düğmesi
        self.start_btn = ttk.Button(toolbar_frame, text="Taramayı Başlat", 
                                  command=self.start_scan, width=15)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.toolbar_buttons.append(self.start_btn)
        
        # Durdur düğmesi
        self.stop_btn = ttk.Button(toolbar_frame, text="Durdur", 
                                 command=self.stop_scan, width=10, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        self.toolbar_buttons.append(self.stop_btn)
        
        # Ayırıcı
        ttk.Separator(toolbar_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=5)
        
        # Portları yapılandır düğmesi
        ports_btn = ttk.Button(toolbar_frame, text="Portları Seç", 
                             command=self.configure_ports, width=15)
        ports_btn.pack(side=tk.LEFT, padx=5)
        self.toolbar_buttons.append(ports_btn)
        
        # Ayarlar düğmesi
        settings_btn = ttk.Button(toolbar_frame, text="Ayarlar", 
                                command=self.show_settings, width=10)
        settings_btn.pack(side=tk.LEFT, padx=5)
        self.toolbar_buttons.append(settings_btn)
        
    def create_main_content(self):
        """Ana içerik alanını oluştur"""
        # İlerleme çubuğu
        self.progress_frame = ttk.Frame(self.main_frame)
        self.progress_frame.pack(fill=tk.X, padx=5, pady=(5, 0))
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.progress_frame, variable=self.progress_var, mode='determinate')
        self.progress_bar.pack(fill=tk.X, side=tk.LEFT, expand=True, padx=(0, 5))
        
        self.progress_label = ttk.Label(self.progress_frame, text="0%")
        self.progress_label.pack(side=tk.RIGHT, padx=5)
        
        # Sekmeli arayüz için notebook oluştur
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Sonuçlar sekmesi
        self.results_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.results_frame, text="Tarama Sonuçları")
        self.create_results_tab()
        
        # İstatistikler sekmesi
        if MATPLOTLIB_AVAILABLE:
            self.stats_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.stats_frame, text="İstatistikler")
            self.create_stats_tab()
        
        # Günlük sekmesi
        self.log_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.log_frame, text="Günlük")
        self.create_log_tab()
        
    def create_results_tab(self):
        """Tarama sonuçları sekmesini oluştur"""
        # Filtre çubuğu
        filter_frame = ttk.Frame(self.results_frame)
        filter_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(filter_frame, text="Filtre:").pack(side=tk.LEFT, padx=(0, 5))
        self.filter_var = tk.StringVar()
        self.filter_var.trace("w", self.on_filter_change)
        filter_entry = ttk.Entry(filter_frame, textvariable=self.filter_var, width=30)
        filter_entry.pack(side=tk.LEFT, padx=5)
        
        # Filtre türü seçimi
        ttk.Label(filter_frame, text="Filtre türü:").pack(side=tk.LEFT, padx=(10, 5))
        self.filter_type_var = tk.StringVar(value="Tümü")
        filter_type = ttk.Combobox(filter_frame, textvariable=self.filter_type_var, width=10)
        filter_type['values'] = ('Tümü', 'IP', 'Hostname', 'MAC', 'Portlar')
        filter_type.pack(side=tk.LEFT, padx=5)
        filter_type.bind("<<ComboboxSelected>>", lambda e: self.apply_filter())
        
        # İşlem düğmeleri
        action_frame = ttk.Frame(filter_frame)
        action_frame.pack(side=tk.RIGHT)
        
        self.refresh_btn = ttk.Button(action_frame, text="Yenile", command=self.refresh_view)
        self.refresh_btn.pack(side=tk.LEFT, padx=5)
        
        self.export_btn = ttk.Button(action_frame, text="Dışa Aktar", command=self.show_export_menu)
        self.export_btn.pack(side=tk.LEFT, padx=5)
        
        # Port detay çerçevesi (varsayılan olarak gizli)
        self.port_detail_frame = ttk.LabelFrame(self.results_frame, text="Port Detayları")
        
        # Port detay ağacı
        self.port_detail_tree = ttk.Treeview(self.port_detail_frame, 
                                         columns=("port", "service", "state"),
                                         show="headings", height=5)
        self.port_detail_tree.heading("port", text="Port")
        self.port_detail_tree.heading("service", text="Servis")
        self.port_detail_tree.heading("state", text="Durum")
        
        # Sütun genişliklerini yapılandır
        self.port_detail_tree.column("port", width=80)
        self.port_detail_tree.column("service", width=200)
        self.port_detail_tree.column("state", width=80)
        
        # Kaydırma çubuğu ekle
        port_scroll = ttk.Scrollbar(self.port_detail_frame, orient=tk.VERTICAL, command=self.port_detail_tree.yview)
        self.port_detail_tree.configure(yscrollcommand=port_scroll.set)
        
        # Port detay bileşenlerini yerleştir
        self.port_detail_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        port_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Kaydırma çubuklu ana sonuç ağacı
        tree_frame = ttk.Frame(self.results_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        # Kaydırma çubukları
        ysb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL)
        xsb = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL)
        
        # Ağaç görünümü
        self.result_tree = ttk.Treeview(tree_frame, 
                             columns=("ip", "hostname", "mac_address", "open_ports", "scan_time"),
                             show="headings", 
                             yscrollcommand=ysb.set, 
                             xscrollcommand=xsb.set)
        
        # Kaydırma çubuklarını yapılandır
        ysb.config(command=self.result_tree.yview)
        xsb.config(command=self.result_tree.xview)
        
        # Kaydırma çubuklarını ve ağacı yerleştir
        ysb.pack(side=tk.RIGHT, fill=tk.Y)
        xsb.pack(side=tk.BOTTOM, fill=tk.X)
        self.result_tree.pack(fill=tk.BOTH, expand=True)
        
        # Sütunları yapılandır
        self.result_tree.heading("ip", text="IP Adresi", command=lambda: self.sort_column("ip", False))
        self.result_tree.heading("hostname", text="Hostname", command=lambda: self.sort_column("hostname", False))
        self.result_tree.heading("mac_address", text="MAC Adresi", command=lambda: self.sort_column("mac_address", False))
        self.result_tree.heading("open_ports", text="Açık Portlar", command=lambda: self.sort_column("open_ports", False))
        self.result_tree.heading("scan_time", text="Tarama Zamanı", command=lambda: self.sort_column("scan_time", False))
        
        # Olayları bağla
        self.result_tree.bind("<Double-1>", self.on_item_double_click)
        self.result_tree.bind("<ButtonRelease-1>", self.on_item_select)
        self.result_tree.bind("<Button-3>", self.show_context_menu)  # Sağ tıklama
        
    def create_stats_tab(self):
        """İstatistikler sekmesini oluştur"""
        if not MATPLOTLIB_AVAILABLE:
            ttk.Label(self.stats_frame, text="İstatistikler için matplotlib kütüphanesi gereklidir").pack(pady=20)
            return
            
        # İstatistikler için konteyner oluştur
        stats_container = ttk.Frame(self.stats_frame)
        stats_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Grafikler satırı
        charts_frame = ttk.Frame(stats_container)
        charts_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Cihaz grafiği çerçevesi
        self.device_frame = ttk.LabelFrame(charts_frame, text="Keşfedilen Cihazlar")
        self.device_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Portlar grafiği çerçevesi
        self.ports_frame = ttk.LabelFrame(charts_frame, text="En Yaygın Açık Portlar")
        self.ports_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        # Özet çerçevesi
        self.summary_frame = ttk.LabelFrame(stats_container, text="Tarama Özeti")
        self.summary_frame.pack(fill=tk.X, expand=False, pady=(10, 0))
        
        # Özet tablosu
        self.summary_tree = ttk.Treeview(self.summary_frame, 
                                      columns=("metric", "value"), 
                                      show="headings", 
                                      height=6)
        self.summary_tree.heading("metric", text="Metrik")
        self.summary_tree.heading("value", text="Değer")
        self.summary_tree.column("metric", width=250)
        self.summary_tree.column("value", width=150)
        self.summary_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Yer tutucular ekle
        ttk.Label(self.device_frame, text="Veri yok").pack(expand=True, pady=50)
        ttk.Label(self.ports_frame, text="Veri yok").pack(expand=True, pady=50)
        
        # İlk özeti doldur
        self.update_summary_table({
            'total_devices': 0,
            'device_types': {},
            'top_ports': {},
            'hostname_ratio': 0,
            'mac_ratio': 0
        })
        
    def create_log_tab(self):
        """Günlük sekmesini oluştur"""
        # Günlük kontrolleri
        controls_frame = ttk.Frame(self.log_frame)
        controls_frame.pack(fill=tk.X, pady=(0, 5))
        
        # Günlük seviyesi seçimi
        ttk.Label(controls_frame, text="Günlük Seviyesi:").pack(side=tk.LEFT, padx=(0, 5))
        self.log_level_var = tk.StringVar(value="INFO")
        log_level = ttk.Combobox(controls_frame, textvariable=self.log_level_var, width=10)
        log_level['values'] = ('DEBUG', 'INFO', 'WARNING', 'ERROR')
        log_level.pack(side=tk.LEFT, padx=5)
        
        # Günlüğü temizle düğmesi
        clear_btn = ttk.Button(controls_frame, text="Günlüğü Temizle", command=self.clear_log)
        clear_btn.pack(side=tk.RIGHT, padx=5)
        
        # Günlüğü kaydet düğmesi
        save_btn = ttk.Button(controls_frame, text="Günlüğü Kaydet", command=self.save_log)
        save_btn.pack(side=tk.RIGHT, padx=5)
        
        # Kaydırma çubuklu günlük metin alanı
        self.log_text = ScrolledText(self.log_frame, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # İlk günlük mesajını ayarla
        self.log_text.insert(tk.END, f"NetScan Pro başlatıldı - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.log_text.insert(tk.END, f"Sistem: {platform.system()} {platform.release()} {platform.machine()}\n")
        self.log_text.insert(tk.END, "Hazır.\n\n")
        
    def create_status_bar(self):
        """Durum çubuğunu oluştur"""
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(self.main_frame, textvariable=self.status_var, 
                                relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM, padx=5, pady=5)
        
    def auto_detect_network(self):
        """Yerel ağı otomatik algıla"""
        network = NetworkUtils.get_network_prefix()
        self.ip_range_var.set(network)
        self.update_status(f"Yerel ağ algılandı: {network}")
        
    def update_progress(self, percentage, message=""):
        """İlerleme çubuğunu ve durumu güncelle"""
        self.progress_var.set(percentage)
        self.progress_label.config(text=f"{percentage:.1f}%")
        
        if message:
            self.update_status(message)
            
    def update_status(self, message):
        """Durum çubuğu mesajını güncelle ve günlüğe kaydet"""
        self.status_var.set(message)
        self.log(message)
        
    def log(self, message, level="INFO"):
        """Zaman damgalı mesajı günlüğe ekle"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_msg = f"[{timestamp}] {message}\n"
        
        # Sona ekle ve otomatik kaydır
        self.log_text.insert(tk.END, log_msg)
        self.log_text.see(tk.END)
        
    def clear_log(self):
        """Günlük metin alanını temizle"""
        self.log_text.delete(1.0, tk.END)
        self.log(f"Günlük {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} tarihinde temizlendi")
        
    def save_log(self):
        """Günlük içeriğini dosyaya kaydet"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Günlük dosyaları", "*.log"), ("Metin dosyaları", "*.txt"), ("Tüm dosyalar", "*.*")],
            initialfile=f"netscan_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        
        if not filename:
            return
            
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(self.log_text.get(1.0, tk.END))
            self.update_status(f"Günlük {filename} dosyasına kaydedildi")
        except Exception as e:
            messagebox.showerror("Hata", f"Günlük kaydedilemedi: {str(e)}")
            
    def reset_scan(self):
        """Yeni bir tarama için sıfırla"""
        if self.scanning:
            messagebox.showinfo("Tarama Sürüyor", "Lütfen yeni bir tarama başlatmadan önce mevcut taramayı durdurun.")
            return
            
        confirm = messagebox.askyesno("Sıfırlamayı Onayla", "Bu, tüm mevcut sonuçları temizleyecektir. Devam edilsin mi?")
        if not confirm:
            return
            
        self.clear_results()
        self.update_status("Yeni tarama için hazır.")
        
    def clear_results(self):
        """Tüm tarama sonuçlarını temizle"""
        # Ağaç görünümünü temizle
        for item in self.result_tree.get_children():
            self.result_tree.delete(item)
            
        # Tarama sonuçları listesini temizle
        self.scan_results = []
        
        # Port detaylarını gizle
        self.port_detail_frame.pack_forget()
        
        # İstatistikler varsa temizle
        if MATPLOTLIB_AVAILABLE:
            for widget in self.device_frame.winfo_children():
                widget.destroy()
            for widget in self.ports_frame.winfo_children():
                widget.destroy()
                
            ttk.Label(self.device_frame, text="Veri yok").pack(expand=True, pady=50)
            ttk.Label(self.ports_frame, text="Veri yok").pack(expand=True, pady=50)
            
            self.update_summary_table({
                'total_devices': 0,
                'device_types': {},
                'top_ports': {},
                'hostname_ratio': 0,
                'mac_ratio': 0
            })
            
    def start_scan(self):
        """Ağ taramasını başlat"""
        if self.scanning:
            return
            
        # IP aralığını al
        ip_range = self.ip_range_var.get().strip()
        if not ip_range:
            messagebox.showerror("Hata", "Lütfen geçerli bir IP aralığı girin")
            return
            
        try:
            # IP aralığını doğrula
            ipaddress.ip_network(ip_range, strict=False)
        except ValueError as e:
            messagebox.showerror("Geçersiz IP Aralığı", str(e))
            return
            
        # Taranacak portları al
        custom_ports = self.app_settings.get('custom_ports')
        ports = PortUtils.parse_port_range(custom_ports)
        
        # Tarama modunu al
        scan_mode = self.scan_mode_var.get()
        
        # UI durumunu güncelle
        self.scanning = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress_var.set(0)
        
        # Önceki sonuçları temizle
        if self.scan_results:
            confirm = messagebox.askyesno("Onayla", "Önceki tarama sonuçları temizlensin mi?")
            if confirm:
                self.clear_results()
                
        # Tarama başlangıcını günlüğe kaydet
        self.update_status(f"{ip_range} aralığı {scan_mode} modunda taranıyor...")
        self.log(f"Tarama başlatıldı: {ip_range} - Mod: {scan_mode} - Portlar: {len(ports)}")
        
        # Taramayı ayrı bir iş parçacığında başlat
        scan_thread = threading.Thread(
            target=self.perform_scan,
            args=(ip_range, ports, scan_mode)
        )
        scan_thread.daemon = True
        scan_thread.start()
        
    def perform_scan(self, ip_range, ports, scan_mode):
        """Taramayı ayrı bir iş parçacığında çalıştır"""
        try:
            self.scan_results = self.scanner.scan_ip_range(ip_range, ports, scan_mode)
            
            # Tamamlandığında UI'yi ana iş parçacığında güncelle
            self.after(100, self.scan_completed)
            
        except Exception as e:
            self.after(100, lambda: self.handle_scan_error(str(e)))
            
    def scan_completed(self):
        """Tarama tamamlandığında yapılacak işlemler"""
        self.scanning = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        
        # İstatistikleri güncelle
        if MATPLOTLIB_AVAILABLE:
            self.update_statistics()
            
        # Tamamlanmayı günlüğe kaydet
        self.log(f"Tarama tamamlandı. {len(self.scan_results)} cihaz bulundu.")
        self.update_status(f"Tarama tamamlandı. {len(self.scan_results)} aktif cihaz bulundu.")
        
    def handle_scan_error(self, error_message):
        """Tarama hatalarını ele al"""
        self.scanning = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        
        messagebox.showerror("Tarama Hatası", f"Tarama sırasında bir hata oluştu:\n{error_message}")
        self.update_status(f"Hata: {error_message}")
        
    def stop_scan(self):
        """Devam eden taramayı durdur"""
        if not self.scanning:
            return
            
        self.scanner.stop_scanning()
        self.update_status("Tarama durduruluyor...")
        
    def add_scan_result(self, result):
        """Tek bir tarama sonucunu görüntüye ekle"""
        if not result:
            return
            
        # Port bilgilerini metin olarak biçimlendir
        ports_str = ', '.join([f"{port} ({service})" for port, service in result.get('open_ports', {}).items()])
        
        # Ağaç görünümüne ekle
        self.result_tree.insert("", "end", 
                       values=(
                           result.get('ip', ''),
                           result.get('hostname', ''),
                           result.get('mac_address', ''),
                           ports_str,
                           result.get('scan_time', '')
                       ),
                       tags=('active',))
        
        # Satır görünümünü yapılandır
        self.result_tree.tag_configure('active', background='#e6f3ff')
        
        # IP adresine göre sırala
        self.sort_column("ip", False)
        
        # Durumdaki toplam sayımı güncelle
        total_found = len(self.result_tree.get_children())
        total_scanned = self.scanner.scanned_count
        total_ips = self.scanner.ip_count
        self.status_var.set(f"Bulunan: {total_found} cihaz - Taranan: {total_scanned}/{total_ips} IP")
        
    def on_item_select(self, event):
        """Sonuç ağacındaki bir öğe seçildiğinde işle"""
        try:
            item = self.result_tree.selection()[0]
            values = self.result_tree.item(item, "values")
            ip = values[0]
            
            # Bu IP için port detaylarını göster
            self.show_port_details(ip)
            
            # Seçilen IP'yi hatırla
            self.last_selected_ip = ip
            
        except IndexError:
            # Seçim yok, port detaylarını gizle
            self.port_detail_frame.pack_forget()
            self.last_selected_ip = None
            
    def on_item_double_click(self, event):
        """Bir sonuç öğesine çift tıklandığında işle"""
        try:
            item = self.result_tree.selection()[0]
            values = self.result_tree.item(item, "values")
            ip = values[0]
            
            # Detaylı bilgi iletişim kutusunu göster
            self.show_device_details(ip)
            
        except IndexError:
            pass
            
    def show_port_details(self, ip):
        """Seçilen IP için port detaylarını göster"""
        # Cihaz verilerini bul
        device = None
        for result in self.scan_results:
            if result.get('ip') == ip:
                device = result
                break
                
        if not device or not device.get('open_ports'):
            # Port verisi yok, detay panelini gizle
            self.port_detail_frame.pack_forget()
            return
            
        # Gizliyse port detay çerçevesini göster
        if not self.port_detail_frame.winfo_ismapped():
            self.port_detail_frame.pack(fill=tk.X, padx=5, pady=5, before=self.result_tree.master)
            
        # Mevcut öğeleri temizle
        for item in self.port_detail_tree.get_children():
            self.port_detail_tree.delete(item)
            
        # Port bilgilerini ekle
        for port, service in sorted(device.get('open_ports', {}).items()):
            self.port_detail_tree.insert("", "end", values=(port, service, "Açık"))
            
    def toggle_port_details(self):
        """Port detayları panelinin görünürlüğünü değiştir"""
        if self.port_detail_frame.winfo_ismapped():
            self.port_detail_frame.pack_forget()
        elif self.last_selected_ip:
            self.show_port_details(self.last_selected_ip)
        else:
            # Seçim yok, boş panel göster
            self.port_detail_frame.pack(fill=tk.X, padx=5, pady=5, before=self.result_tree.master)
            for item in self.port_detail_tree.get_children():
                self.port_detail_tree.delete(item)
                
    def show_device_details(self, ip):
        """Cihaz hakkında detaylı bilgileri göster"""
        # Cihaz verilerini bul
        device = None
        for result in self.scan_results:
            if result.get('ip') == ip:
                device = result
                break
                
        if not device:
            return
            
        # Detay iletişim kutusu oluştur
        detail_window = tk.Toplevel(self)
        detail_window.title(f"Cihaz Detayları: {ip}")
        detail_window.geometry("650x400")
        detail_window.minsize(500, 350)
        detail_window.transient(self)
        detail_window.grab_set()
        
        # Sekmeli arayüz için notebook
        notebook = ttk.Notebook(detail_window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Genel bakış sekmesi
        overview_frame = ttk.Frame(notebook, padding=10)
        notebook.add(overview_frame, text="Genel Bakış")
        
        # Cihaz bilgileri ızgarası
        ttk.Label(overview_frame, text="IP Adresi:", anchor=tk.E).grid(row=0, column=0, sticky=tk.E, padx=5, pady=5)
        ttk.Label(overview_frame, text=device.get('ip', ''), font='TkDefaultFont 10 bold').grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(overview_frame, text="Hostname:", anchor=tk.E).grid(row=1, column=0, sticky=tk.E, padx=5, pady=5)
        hostname = device.get('hostname', '')
        ttk.Label(overview_frame, text=hostname if hostname else "Mevcut değil").grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(overview_frame, text="MAC Adresi:", anchor=tk.E).grid(row=2, column=0, sticky=tk.E, padx=5, pady=5)
        mac = device.get('mac_address', '')
        ttk.Label(overview_frame, text=mac if mac else "Mevcut değil").grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(overview_frame, text="Tarama Zamanı:", anchor=tk.E).grid(row=3, column=0, sticky=tk.E, padx=5, pady=5)
        ttk.Label(overview_frame, text=device.get('scan_time', '')).grid(row=3, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(overview_frame, text="Açık Portlar:", anchor=tk.E).grid(row=4, column=0, sticky=tk.NE, padx=5, pady=5)
        
        # Port özeti
        ports_count = len(device.get('open_ports', {}))
        port_summary = f"{ports_count} açık port tespit edildi"
        ttk.Label(overview_frame, text=port_summary).grid(row=4, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Portlar sekmesi
        ports_frame = ttk.Frame(notebook, padding=10)
        notebook.add(ports_frame, text="Portlar")
        
        # Kaydırma çubuklu port listesi
        port_list_frame = ttk.Frame(ports_frame)
        port_list_frame.pack(fill=tk.BOTH, expand=True)
        
        # Kaydırma çubukları
        ports_ysb = ttk.Scrollbar(port_list_frame, orient=tk.VERTICAL)
        
        # Port ağaç görünümü
        ports_tree = ttk.Treeview(port_list_frame, 
                                columns=("port", "service", "state", "description"),
                                show="headings", 
                                yscrollcommand=ports_ysb.set)
        
        # Kaydırma çubuklarını yapılandır
        ports_ysb.config(command=ports_tree.yview)
        
        # Bileşenleri yerleştir
        ports_ysb.pack(side=tk.RIGHT, fill=tk.Y)
        ports_tree.pack(fill=tk.BOTH, expand=True)
        
        # Sütunları yapılandır
        ports_tree.heading("port", text="Port")
        ports_tree.heading("service", text="Servis")
        ports_tree.heading("state", text="Durum")
        ports_tree.heading("description", text="Açıklama")
        
        ports_tree.column("port", width=80)
        ports_tree.column("service", width=100)
        ports_tree.column("state", width=80)
        ports_tree.column("description", width=300)
        
        # Port verilerini doldur
        for port, service in sorted(device.get('open_ports', {}).items()):
            # Yaygın portlar için ek açıklama al
            description = ""
            if port in COMMON_PORTS:
                if port == 80:
                    description = "HTTP Web Sunucusu"
                elif port == 443:
                    description = "HTTPS Güvenli Web Sunucusu"
                elif port == 22:
                    description = "SSH Uzaktan Erişim"
                elif port == 3389:
                    description = "Uzak Masaüstü Protokolü"
                elif port in [139, 445]:
                    description = "Dosya/Yazıcı Paylaşımı (SMB)"
                elif port in [1433, 3306, 5432]:
                    description = "Veritabanı Sunucusu"
                elif port in [25, 110, 143, 465, 587, 993, 995]:
                    description = "E-posta Sunucusu"
                else:
                    description = "Yaygın servis portu"
            
            ports_tree.insert("", "end", values=(port, service, "Açık", description))
            
        # İşlemler sekmesi
        actions_frame = ttk.Frame(notebook, padding=10)
        notebook.add(actions_frame, text="İşlemler")
        
        # İşlemler ızgarası
        actions_lbl = ttk.Label(actions_frame, 
                             text="Bu cihaz için kullanılabilir işlemler:",
                             font='TkDefaultFont 10 bold')
        actions_lbl.pack(anchor=tk.W, pady=(0, 10))
        
        # İşlem düğmeleri
        action_btns_frame = ttk.Frame(actions_frame)
        action_btns_frame.pack(fill=tk.X, pady=5)
        
        # Ping düğmesi
        ping_btn = ttk.Button(action_btns_frame, 
                           text="Ping At", 
                           command=lambda: self.ping_device(ip, detail_window))
        ping_btn.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Traceroute düğmesi
        trace_btn = ttk.Button(action_btns_frame, 
                            text="Traceroute", 
                            command=lambda: self.traceroute_device(ip, detail_window))
        trace_btn.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Port tarama düğmesi
        if NMAP_MODULE_AVAILABLE:
            nmap_btn = ttk.Button(action_btns_frame, 
                               text="Detaylı Port Taraması", 
                               command=lambda: self.detailed_port_scan(ip, ports_tree, detail_window))
            nmap_btn.pack(side=tk.LEFT, padx=5, pady=5)
            
        # Web arayüzü düğmesi (port 80 veya 443 açıksa)
        has_web = any(p in device.get('open_ports', {}) for p in [80, 443, 8080, 8443])
        if has_web:
            web_btn = ttk.Button(action_btns_frame, 
                              text="Web Arayüzünü Aç", 
                              command=lambda: self.open_web_interface(ip, detail_window))
            web_btn.pack(side=tk.LEFT, padx=5, pady=5)
            
        # İşlem çıktısı için sonuçlar alanı
        results_lbl = ttk.Label(actions_frame, text="İşlem Sonuçları:", font='TkDefaultFont 10 bold')
        results_lbl.pack(anchor=tk.W, pady=(20, 5))
        
        results_frame = ttk.Frame(actions_frame)
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        results_text = ScrolledText(results_frame, height=10)
        results_text.pack(fill=tk.BOTH, expand=True)
        results_text.insert(tk.END, "Sonuçları görmek için yukarıdan bir işlem seçin.\n")
        
        # Alt düğmeler
        btn_frame = ttk.Frame(detail_window)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Kapat düğmesi
        close_btn = ttk.Button(btn_frame, text="Kapat", command=detail_window.destroy)
        close_btn.pack(side=tk.RIGHT, padx=5)
        
        # İletişim kutusunu ortala
        detail_window.update_idletasks()
        width = detail_window.winfo_width()
        height = detail_window.winfo_height()
        x = self.winfo_rootx() + (self.winfo_width() // 2) - (width // 2)
        y = self.winfo_rooty() + (self.winfo_height() // 2) - (height // 2)
        detail_window.geometry(f'{width}x{height}+{x}+{y}')
        
        # Sonuç metin alanını düğmelere bağlamak için
        detail_window.results_text = results_text
        
    def ping_device(self, ip, parent_window=None):
        """Cihaza ping gönder ve sonuçları göster"""
        results_text = getattr(parent_window, 'results_text', None)
        
        if results_text:
            results_text.delete(1.0, tk.END)
            results_text.insert(tk.END, f"{ip} ping atılıyor...\n\n")
        
        def run_ping():
            try:
                # Platform'a göre ping parametreleri
                param = '-n' if platform.system().lower() == 'windows' else '-c'
                count = '4'  # 4 ping
                
                # Gizli pencerede çalıştırma için yapılandırma
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE
                
                # Ping komutunu çalıştır
                process = subprocess.Popen(
                    ['ping', param, count, ip],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    startupinfo=startupinfo,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                stdout, stderr = process.communicate()
                
                # UI'yi ana iş parçacığında güncelle
                output = stdout or stderr
                if results_text:
                    parent_window.after(100, lambda: self.update_results_text(results_text, output))
                else:
                    # Günlükte göster
                    for line in output.splitlines():
                        self.after(100, lambda l=line: self.log(l))
                
            except Exception as e:
                error_msg = f"Hata: {str(e)}"
                if results_text:
                    parent_window.after(100, lambda: self.update_results_text(results_text, error_msg))
                else:
                    self.after(100, lambda: self.log(error_msg, "ERROR"))
                
        threading.Thread(target=run_ping, daemon=True).start()
        
    def traceroute_device(self, ip, parent_window=None):
        """Cihaza traceroute çalıştır ve sonuçları göster"""
        results_text = getattr(parent_window, 'results_text', None)
        
        if results_text:
            results_text.delete(1.0, tk.END)
            results_text.insert(tk.END, f"{ip} için traceroute çalıştırılıyor...\n")
            results_text.insert(tk.END, "Bu, tarama seçeneklerine bağlı olarak biraz zaman alabilir.\n\n")
        
        def run_traceroute():
            try:
                # Platform'a göre komut
                cmd = 'tracert' if platform.system().lower() == 'windows' else 'traceroute'
                
                # Gizli pencerede çalıştırma için yapılandırma
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE
                
                # Traceroute komutunu çalıştır
                process = subprocess.Popen(
                    [cmd, ip],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    startupinfo=startupinfo,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                stdout, stderr = process.communicate()
                
                # UI'yi ana iş parçacığında güncelle
                output = stdout or stderr
                if results_text:
                    parent_window.after(100, lambda: self.update_results_text(results_text, output))
                else:
                    # Günlükte göster
                    for line in output.splitlines():
                        self.after(100, lambda l=line: self.log(l))
                
            except Exception as e:
                error_msg = f"Hata: {str(e)}"
                if results_text:
                    parent_window.after(100, lambda: self.update_results_text(results_text, error_msg))
                else:
                    self.after(100, lambda: self.log(error_msg, "ERROR"))
                
        threading.Thread(target=run_traceroute, daemon=True).start()
        
    def open_web_interface(self, ip, parent_window=None):
        """Web arayüzünü varsayılan tarayıcıda aç"""
        try:
            import webbrowser
            url = f"http://{ip}"
            
            webbrowser.open(url)
            
            results_text = getattr(parent_window, 'results_text', None)
            if results_text:
                self.update_results_text(results_text, f"{url} web tarayıcıda açılıyor...")
            else:
                self.log(f"{url} web tarayıcıda açıldı")
                
        except Exception as e:
            error_msg = f"Hata: {str(e)}"
            results_text = getattr(parent_window, 'results_text', None)
            if results_text:
                self.update_results_text(results_text, error_msg)
            else:
                self.log(error_msg, "ERROR")
                
    def detailed_port_scan(self, ip, port_tree, parent_window=None):
        """nmap kullanarak detaylı port taraması yap"""
        if not NMAP_MODULE_AVAILABLE:
            messagebox.showinfo("Eksik Bağımlılık", "Detaylı tarama için python-nmap kütüphanesi gereklidir.")
            return
            
        results_text = getattr(parent_window, 'results_text', None)
        if results_text:
            results_text.delete(1.0, tk.END)
            results_text.insert(tk.END, f"{ip} üzerinde detaylı port taraması çalıştırılıyor...\n")
            results_text.insert(tk.END, "Bu, tarama seçeneklerine bağlı olarak biraz zaman alabilir.\n\n")
        
        # Port ağacını temizle
        for item in port_tree.get_children():
            port_tree.delete(item)
            
        def run_nmap_scan():
            try:
                if results_text:
                    parent_window.after(100, lambda: self.update_results_text(results_text, "Tarama devam ediyor...\n"))
                
                # Tarayıcı başlat
                nm = nmap.PortScanner()
                
                # Servis algılama taraması çalıştır
                nm.scan(ip, arguments='-sV -T4')
                
                # Sonuçları işle
                results = []
                
                if ip in nm.all_hosts():
                    for proto in nm[ip].all_protocols():
                        ports = sorted(nm[ip][proto].keys())
                        for port in ports:
                            state = nm[ip][proto][port]['state']
                            service = nm[ip][proto][port]['name']
                            product = nm[ip][proto][port].get('product', '')
                            version = nm[ip][proto][port].get('version', '')
                            
                            # Açıklama oluştur
                            description = ""
                            if product:
                                description = product
                                if version:
                                    description += f" {version}"
                                    
                            # Sonuçlara ekle
                            results.append((port, service, state, description))
                
                # UI'yi ana iş parçacığında güncelle
                if parent_window:
                    parent_window.after(100, lambda: self.update_port_scan_results(port_tree, results, results_text))
                
            except Exception as e:
                error_msg = f"Hata: {str(e)}"
                if results_text:
                    parent_window.after(100, lambda: self.update_results_text(results_text, error_msg))
                else:
                    self.after(100, lambda: self.log(error_msg, "ERROR"))
                
        threading.Thread(target=run_nmap_scan, daemon=True).start()
        
    def update_port_scan_results(self, port_tree, results, results_text=None):
        """Port tarama sonuçlarını ağaç görünümünde güncelle"""
        # Mevcut girişleri temizle
        for item in port_tree.get_children():
            port_tree.delete(item)
            
        # Yeni sonuçları ekle
        for port, service, state, description in sorted(results, key=lambda x: x[0]):
            port_tree.insert("", "end", values=(port, service, state, description))
            
        # Sonuç metnini güncelle
        if results_text:
            self.update_results_text(results_text, f"Tarama tamamlandı. {len(results)} açık port bulundu.")
            
    def update_results_text(self, text_widget, content):
        """Sonuç metin alanını güncelle"""
        text_widget.delete(1.0, tk.END)
        text_widget.insert(tk.END, content)
        
    def show_context_menu(self, event):
        """Sonuç ağacında sağ tıklandığında bağlam menüsü göster"""
        # İmleç altındaki öğeyi al
        item = self.result_tree.identify_row(event.y)
        if not item:
            return
            
        # Öğeyi seç
        self.result_tree.selection_set(item)
        self.result_tree.focus(item)
        
        # IP adresini al
        values = self.result_tree.item(item, "values")
        ip = values[0]
        
        # Bağlam menüsü oluştur
        context_menu = tk.Menu(self, tearoff=0)
        
        # Menü öğelerini ekle
        context_menu.add_command(label="Detayları Görüntüle", 
                               command=lambda: self.show_device_details(ip))
        context_menu.add_command(label="Ping At", 
                               command=lambda: self.ping_device(ip))
        context_menu.add_command(label="IP'yi Kopyala", 
                               command=lambda: self.copy_to_clipboard(ip))
        
        # Cihazın web portları açık mı kontrol et
        device = None
        for result in self.scan_results:
            if result.get('ip') == ip:
                device = result
                break
                
        if device and any(p in device.get('open_ports', {}) for p in [80, 443, 8080, 8443]):
            context_menu.add_command(label="Web Arayüzünü Aç", 
                                   command=lambda: self.open_web_interface(ip))
            
        # Menüyü imleç konumunda göster
        try:
            context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            context_menu.grab_release()
            
    def copy_to_clipboard(self, text):
        """Metni panoya kopyala"""
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update_status(f"Panoya kopyalandı: {text}")
        
    def on_filter_change(self, *args):
        """Filtre metni değişikliklerini ele al"""
        # Önceki zamanlayıcı varsa iptal et
        if self.filter_timer:
            self.after_cancel(self.filter_timer)
            
        # Aşırı filtrelemeyi önlemek için gecikme ile yeni zamanlayıcı ayarla
        self.filter_timer = self.after(300, self.apply_filter)
        
    def apply_filter(self):
        """Sonuçlara filtre uygula"""
        filter_text = self.filter_var.get().lower()
        filter_type = self.filter_type_var.get()
        
        # Filtre boşsa tüm öğeleri göster
        if not filter_text:
            for item in self.result_tree.get_children():
                self.result_tree.item(item, tags='active')
                
            self.result_tree.tag_configure('active', background='#e6f3ff')
            return
            
        # Filtreleme sırasında port detaylarını gizle
        self.port_detail_frame.pack_forget()
        
        # Her öğeye filtre uygula
        for item in self.result_tree.get_children():
            values = self.result_tree.item(item, "values")
            match = False
            
            if filter_type == "Tümü" or filter_type == "IP":
                if filter_text in values[0].lower():
                    match = True
                    
            if (filter_type == "Tümü" or filter_type == "Hostname") and values[1]:
                if filter_text in values[1].lower():
                    match = True
                    
            if (filter_type == "Tümü" or filter_type == "MAC") and values[2]:
                if filter_text in values[2].lower():
                    match = True
                    
            if (filter_type == "Tümü" or filter_type == "Portlar") and values[3]:
                if filter_text in values[3].lower():
                    match = True
                    
            # Öğe görünürlüğünü güncelle
            if match:
                self.result_tree.item(item, tags='active')
            else:
                self.result_tree.item(item, tags='hidden')
                
        # Stilleri uygula
        self.result_tree.tag_configure('active', background='#e6f3ff')
        self.result_tree.tag_configure('hidden', background='gray90')
        
    def refresh_view(self):
        """Mevcut görünümü yenile"""
        # Filtreyi temizle
        self.filter_var.set("")
        
        # Stilleri yeniden uygula
        for item in self.result_tree.get_children():
            self.result_tree.item(item, tags='active')
            
        self.result_tree.tag_configure('active', background='#e6f3ff')
        
        # Durumu güncelle
        self.update_status(f"Görünüm yenilendi. {len(self.scan_results)} cihaz görüntüleniyor.")
        
    def sort_column(self, column, reverse):
        """Bir sütuna göre ağaç görünümünü sırala"""
        # Değerleriyle birlikte tüm öğeleri al
        item_list = [(self.result_tree.set(item, column), item) for item in self.result_tree.get_children()]
        
        try:
            # IP sütunu için IP adresleri olarak sıralamayı dene
            if column == "ip":
                # Düzgün IP sıralaması için tamsayı demetine dönüştür
                item_list = [(tuple(int(n) for n in k.split('.')), k, v) for k, v in item_list]
                item_list.sort(reverse=reverse)
                item_list = [(k, v) for _, k, v in item_list]
            else:
                # Diğer sütunlar için normal dize sıralaması
                item_list.sort(reverse=reverse)
        except Exception:
            # Dize sıralamasına geri dön
            item_list.sort(reverse=reverse)
            
        # Öğeleri sıralanmış düzende yeniden düzenle
        for index, (_, item) in enumerate(item_list):
            self.result_tree.move(item, '', index)
            
        # Başlığı ters sıralama düzenine geçir
        self.result_tree.heading(column, command=lambda: self.sort_column(column, not reverse))
        
    def show_export_menu(self):
        """Dışa aktarma seçenekleri menüsünü göster"""
        export_menu = tk.Menu(self, tearoff=0)
        export_menu.add_command(label="CSV Olarak Dışa Aktar...", 
                             command=lambda: self.export_results("csv"))
        export_menu.add_command(label="Excel Olarak Dışa Aktar...", 
                             command=lambda: self.export_results("excel"))
                             
        # Menüyü düğme konumunda göster
        x = self.export_btn.winfo_rootx()
        y = self.export_btn.winfo_rooty() + self.export_btn.winfo_height()
        export_menu.tk_popup(x, y)
        
    def export_results(self, format_type):
        """Tarama sonuçlarını dosyaya aktar"""
        if not self.scan_results:
            messagebox.showinfo("Dışa Aktarma", "Dışa aktarılacak sonuç yok.")
            return
            
        # Zaman damgalı varsayılan dosya adı
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"netscan_sonuclar_{timestamp}"
        
        if format_type == "csv":
            filename = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV dosyaları", "*.csv"), ("Tüm dosyalar", "*.*")],
                initialfile=default_filename
            )
            
            if not filename:
                return
                
            success, message = self.scanner.export_to_csv(filename, self.scan_results)
            
        elif format_type == "excel":
            if not PANDAS_AVAILABLE:
                messagebox.showerror("Dışa Aktarma Hatası", 
                                  "Excel aktarımı için pandas kütüphanesi gereklidir.")
                return
                
            filename = filedialog.asksaveasfilename(
                defaultextension=".xlsx",
                filetypes=[("Excel dosyaları", "*.xlsx"), ("Tüm dosyalar", "*.*")],
                initialfile=default_filename
            )
            
            if not filename:
                return
                
            success, message = self.scanner.export_to_excel(filename, self.scan_results)
            
        else:
            return
            
        # Sonuç mesajını göster
        if success:
            messagebox.showinfo("Dışa Aktarma Başarılı", message)
            self.update_status(message)
        else:
            messagebox.showerror("Dışa Aktarma Hatası", message)
            
    def update_statistics(self):
        """İstatistik grafik ve tablolarını güncelle"""
        if not MATPLOTLIB_AVAILABLE or not self.scan_results:
            return
            
        # Tarayıcıdan istatistikleri al
        stats = self.scanner.get_scan_statistics(self.scan_results)
        
        # Özet tablosunu güncelle
        self.update_summary_table(stats)
        
        # Cihaz grafiğini güncelle
        self.update_device_chart(stats)
        
        # Portlar grafiğini güncelle
        self.update_ports_chart(stats)
        
    def update_summary_table(self, stats):
        """Özet istatistikler tablosunu güncelle"""
        # Mevcut öğeleri temizle
        for item in self.summary_tree.get_children():
            self.summary_tree.delete(item)
            
        # Yeni istatistikleri ekle
        self.summary_tree.insert("", "end", values=("Toplam Bulunan Cihaz", stats['total_devices']))
        self.summary_tree.insert("", "end", values=("Toplam Taranan IP", self.scanner.scanned_count))
        self.summary_tree.insert("", "end", values=("Hostname Çözümleme Oranı", f"{stats['hostname_ratio']:.1f}%"))
        self.summary_tree.insert("", "end", values=("MAC Adresi Toplama Oranı", f"{stats['mac_ratio']:.1f}%"))
        
        # Üst portlar varsa ekle
        if stats['top_ports']:
            top_port = max(stats['top_ports'].items(), key=lambda x: x[1])
            self.summary_tree.insert("", "end", values=("En Yaygın Açık Port", f"{top_port[0]} ({top_port[1]} cihaz)"))
            
        # Tarama süresini ekle
        if hasattr(self.scanner, 'start_time'):
            if self.scanner.start_time:
                duration = datetime.now() - self.scanner.start_time
                self.summary_tree.insert("", "end", values=("Tarama Süresi", f"{duration.total_seconds():.1f} saniye"))
                
    def update_device_chart(self, stats):
        """Cihaz istatistikleri grafiğini güncelle"""
        # Mevcut bileşenleri temizle
        for widget in self.device_frame.winfo_children():
            widget.destroy()
            
        # Cihaz grafiği için şekil oluştur
        fig = plt.Figure(figsize=(5, 4), dpi=100)
        ax = fig.add_subplot(111)
        
        # Pasta grafiği için veriyi hazırla
        if stats['device_types']:
            labels = list(stats['device_types'].keys())
            sizes = list(stats['device_types'].values())
        else:
            # Cihaz türleri tanımlanmadıysa jenerik veri oluştur
            labels = ['Bilinmiyor']
            sizes = [stats['total_devices']]
            
        # Pasta grafiği oluştur
        wedges, texts, autotexts = ax.pie(
            sizes, 
            labels=None, 
            autopct='%1.1f%%',
            startangle=90,
            colors=['#3498db', '#2ecc71', '#e74c3c', '#f39c12', '#9b59b6', '#95a5a6']
        )
        
        # Metni şekillendir
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontsize(9)
            
        ax.set_title('Cihaz Türleri')
        ax.axis('equal')  # Dairesel görünüm için eşit en boy oranı
        
        # Açıklama ekle
        ax.legend(
            wedges, 
            labels,
            title="Türler",
            loc="center left",
            bbox_to_anchor=(0.9, 0, 0.5, 1)
        )
        
        # Çerçeveye ekle
        canvas = FigureCanvasTkAgg(fig, master=self.device_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
    def update_ports_chart(self, stats):
        """Portlar istatistikleri grafiğini güncelle"""
        # Mevcut bileşenleri temizle
        for widget in self.ports_frame.winfo_children():
            widget.destroy()
            
        # Portlar grafiği için şekil oluştur
        fig = plt.Figure(figsize=(5, 4), dpi=100)
        ax = fig.add_subplot(111)
        
        # İlk 10 portu al
        top_ports = dict(sorted(stats['top_ports'].items(), key=lambda x: x[1], reverse=True)[:10])
        
        if top_ports:
            # Yatay çubuk grafiği oluştur
            bars = ax.barh(
                list(top_ports.keys()), 
                list(top_ports.values()),
                color='#3498db'
            )
            
            ax.set_title('En Yaygın Açık Portlar')
            ax.set_xlabel('Cihaz Sayısı')
            
            # Çubuklara değer etiketleri ekle
            for bar in bars:
                width = bar.get_width()
                ax.text(
                    width + 0.1, 
                    bar.get_y() + bar.get_height()/2,
                    f'{int(width)}',
                    va='center'
                )
                
            # Daha temiz görünüm için üst ve sağ çizgileri kaldır
            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)
            
            # Çerçeveye ekle
            canvas = FigureCanvasTkAgg(fig, master=self.ports_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        else:
            # Port verisi yok
            ttk.Label(self.ports_frame, text="Port verisi mevcut değil").pack(expand=True, pady=50)
            
    def open_results(self):
        """Kayıtlı tarama sonuçlarını aç"""
        filename = filedialog.askopenfilename(
            filetypes=[("CSV dosyaları", "*.csv"), ("Tüm dosyalar", "*.*")]
        )
        
        if not filename:
            return
            
        try:
            results = []
            with open(filename, 'r', newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Port dizesini sözlüğe geri ayrıştır
                    ports_str = row.get('open_ports', '')
                    open_ports = {}
                    
                    if ports_str:
                        port_items = ports_str.split(', ')
                        for item in port_items:
                            match = re.match(r'(\d+) \((.+)\)', item)
                            if match:
                                port, service = match.groups()
                                open_ports[int(port)] = service
                                
                    # Sonuç sözlüğü oluştur
                    result = {
                        'ip': row.get('ip', ''),
                        'status': row.get('status', 'Aktif'),
                        'hostname': row.get('hostname', ''),
                        'mac_address': row.get('mac_address', ''),
                        'open_ports': open_ports,
                        'scan_time': row.get('scan_time', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                    }
                    results.append(result)
                    
            # Mevcut sonuçları temizle ve güncelle
            self.clear_results()
            self.scan_results = results
            
            # Ağaç görünümünü doldur
            for result in results:
                # Portları biçimlendir
                ports_str = ', '.join([f"{port} ({service})" for port, service in result.get('open_ports', {}).items()])
                
                # Ağaç görünümüne ekle
                self.result_tree.insert("", "end", 
                               values=(
                                   result.get('ip', ''),
                                   result.get('hostname', ''),
                                   result.get('mac_address', ''),
                                   ports_str,
                                   result.get('scan_time', '')
                               ),
                               tags=('active',))
                               
            # Satır görünümünü yapılandır
            self.result_tree.tag_configure('active', background='#e6f3ff')
            
            # İstatistikler varsa güncelle
            if MATPLOTLIB_AVAILABLE:
                self.update_statistics()
                
            # Durumu güncelle
            self.update_status(f"{os.path.basename(filename)} dosyasından {len(results)} cihaz yüklendi")
            
        except Exception as e:
            messagebox.showerror("Açma Hatası", f"Sonuçlar yüklenirken hata oluştu: {str(e)}")
            
    def save_results(self):
        """Tarama sonuçlarını CSV dosyasına kaydet"""
        if not self.scan_results:
            messagebox.showinfo("Kaydet", "Kaydedilecek sonuç yok.")
            return
            
        # Zaman damgalı varsayılan dosya adı
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"netscan_sonuclar_{timestamp}.csv"
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV dosyaları", "*.csv"), ("Tüm dosyalar", "*.*")],
            initialfile=default_filename
        )
        
        if not filename:
            return
            
        success, message = self.scanner.export_to_csv(filename, self.scan_results)
        
        if success:
            messagebox.showinfo("Kaydetme Başarılı", message)
        else:
            messagebox.showerror("Kaydetme Hatası", message)
            
    def configure_ports(self):
        """Port yapılandırma iletişim kutusunu aç"""
        # Yapılandırmadan mevcut özel portları al
        custom_ports = self.app_settings.get('custom_ports')
        current_ports = PortUtils.parse_port_range(custom_ports)
        
        # Port yapılandırma iletişim kutusunu aç
        dialog = PortConfigDialog(self, current_ports, PORT_PROFILES)
        
        # İletişim kutusu iptal edilmediyse yapılandırmayı güncelle
        if dialog.result is not None:
            port_str = PortUtils.format_port_range(dialog.result)
            self.app_settings.set('custom_ports', port_str)
            self.update_status(f"Port yapılandırması güncellendi: {len(dialog.result)} port seçildi")
            
    def show_settings(self):
        """Ayarlar iletişim kutusunu göster"""
        dialog = SettingsDialog(self, self.app_settings)
        
        # İletişim kutusu iptal edilmediyse tarayıcıyı yeni yapılandırmayla güncelle
        if dialog.result:
            self.scanner.settings = self.app_settings
            
    def show_network_info(self):
        """Mevcut ağ hakkında bilgi göster"""
        try:
            # Ağ bilgilerini al
            local_ip = NetworkUtils.get_local_ip()
            network_prefix = NetworkUtils.get_network_prefix()
            hostname = socket.gethostname()
            
            # Ağ arayüzlerini al
            interfaces = []
            if platform.system().lower() == 'windows':
                # Windows - ipconfig kullan
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE
                output = subprocess.check_output('ipconfig', text=True, startupinfo=startupinfo, creationflags=subprocess.CREATE_NO_WINDOW)
                interfaces = [line.strip() for line in output.splitlines()]
            else:
                # Unix benzeri - ifconfig veya ip kullan
                try:
                    output = subprocess.check_output(['ifconfig'], text=True)
                except:
                    try:
                        output = subprocess.check_output(['ip', 'addr'], text=True)
                    except:
                        output = "Ağ arayüzleri alınamadı"
                        
                interfaces = [line.strip() for line in output.splitlines()]
                
            # Bilgi iletişim kutusu oluştur
            info_window = tk.Toplevel(self)
            info_window.title("Ağ Bilgisi")
            info_window.geometry("600x400")
            info_window.transient(self)
            info_window.grab_set()
            
            # İçerik oluştur
            content = ttk.Frame(info_window, padding=10)
            content.pack(fill=tk.BOTH, expand=True)
            
            # Temel bilgiler
            info_frame = ttk.LabelFrame(content, text="Temel Bilgiler")
            info_frame.pack(fill=tk.X, padx=5, pady=5)
            
            ttk.Label(info_frame, text="Yerel IP Adresi:").grid(row=0, column=0, sticky=tk.E, padx=5, pady=2)
            ttk.Label(info_frame, text=local_ip, font='TkDefaultFont 10 bold').grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
            
            ttk.Label(info_frame, text="Ağ Öneki:").grid(row=1, column=0, sticky=tk.E, padx=5, pady=2)
            ttk.Label(info_frame, text=network_prefix).grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
            
            ttk.Label(info_frame, text="Hostname:").grid(row=2, column=0, sticky=tk.E, padx=5, pady=2)
            ttk.Label(info_frame, text=hostname).grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
            
            # Ağ arayüzleri
            if_frame = ttk.LabelFrame(content, text="Ağ Arayüzleri")
            if_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # Arayüz detayları için kaydırmalı metin alanı ekle
            if_text = ScrolledText(if_frame)
            if_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # Arayüz bilgilerini ekle
            for line in interfaces:
                if_text.insert(tk.END, line + "\n")
                
            if_text.configure(state='disabled')  # Salt okunur yap
            
            # Düğmeler
            btn_frame = ttk.Frame(content)
            btn_frame.pack(fill=tk.X, padx=5, pady=5)
            
            close_btn = ttk.Button(btn_frame, text="Kapat", command=info_window.destroy)
            close_btn.pack(side=tk.RIGHT, padx=5)
            
            # İletişim kutusunu ortala
            info_window.update_idletasks()
            width = info_window.winfo_width()
            height = info_window.winfo_height()
            x = self.winfo_rootx() + (self.winfo_width() // 2) - (width // 2)
            y = self.winfo_rooty() + (self.winfo_height() // 2) - (height // 2)
            info_window.geometry(f'{width}x{height}+{x}+{y}')
            
        except Exception as e:
            messagebox.showerror("Hata", f"Ağ bilgisi alınamadı: {str(e)}")
            
    def show_port_reference(self):
        """Yaygın portlar referansını göster"""
        # Referans iletişim kutusu oluştur
        ref_window = tk.Toplevel(self)
        ref_window.title("Yaygın Portlar Referansı")
        ref_window.geometry("500x600")
        ref_window.transient(self)
        ref_window.grab_set()
        
        # İçerik oluştur
        content = ttk.Frame(ref_window, padding=10)
        content.pack(fill=tk.BOTH, expand=True)
        
        # Arama çerçevesi
        search_frame = ttk.Frame(content)
        search_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(search_frame, text="Ara:").pack(side=tk.LEFT, padx=(0, 5))
        search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Port kategorileri
        categories = {
            "Web Servisleri": [80, 443, 8080, 8443],
            "Uzaktan Erişim": [22, 23, 3389, 5900],
            "Dosya Transferi": [20, 21, 69, 115],
            "E-posta": [25, 110, 143, 465, 587, 993, 995],
            "İsim Servisleri": [53, 137],
            "Veritabanları": [1433, 1521, 3306, 5432, 27017],
            "Diğer Yaygın": [123, 161, 445, 548, 631]
        }
        
        category_var = tk.StringVar(value="Tümü")
        cat_combo = ttk.Combobox(search_frame, textvariable=category_var, width=15,
                               values=["Tümü"] + list(categories.keys()))
        cat_combo.pack(side=tk.LEFT, padx=5)
        
        # Kaydırma çubuklu port listesi
        tree_frame = ttk.Frame(content)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Kaydırma çubukları
        ysb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL)
        xsb = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL)
        
        # Port ağaç görünümü
        port_tree = ttk.Treeview(tree_frame, 
                              columns=("port", "name", "description"),
                              show="headings", 
                              yscrollcommand=ysb.set,
                              xscrollcommand=xsb.set)
        
        # Kaydırma çubuklarını yapılandır
        ysb.config(command=port_tree.yview)
        xsb.config(command=port_tree.xview)
        
        # Bileşenleri yerleştir
        ysb.pack(side=tk.RIGHT, fill=tk.Y)
        xsb.pack(side=tk.BOTTOM, fill=tk.X)
        port_tree.pack(fill=tk.BOTH, expand=True)
        
        # Sütunları yapılandır
        port_tree.heading("port", text="Port", command=lambda: sort_tree("port", False))
        port_tree.heading("name", text="Servis", command=lambda: sort_tree("name", False))
        port_tree.heading("description", text="Açıklama")
        
        port_tree.column("port", width=80)
        port_tree.column("name", width=100)
        port_tree.column("description", width=300)
        
        # Port açıklamaları
        port_descriptions = {
            80: "HTTP - Web sunucusu - Dünya Çapında Ağ",
            443: "HTTPS - Güvenli web sunucusu",
            22: "SSH - Güvenli Kabuk uzaktan erişim",
            23: "Telnet - Uzak terminal erişimi (şifrelenmemiş)",
            21: "FTP - Dosya Transfer Protokolü kontrolü",
            20: "FTP - Dosya Transfer Protokolü verisi",
            25: "SMTP - Basit Posta Transfer Protokolü",
            110: "POP3 - Posta Ofisi Protokolü (e-posta alma)",
            143: "IMAP - İnternet Mesaj Erişim Protokolü (e-posta alma)",
            53: "DNS - Alan Adı Sistemi",
            3389: "RDP - Uzak Masaüstü Protokolü",
            3306: "MySQL Veritabanı Sunucusu",
            5432: "PostgreSQL Veritabanı Sunucusu",
            1433: "Microsoft SQL Server",
            445: "SMB - Sunucu Mesaj Bloğu (dosya paylaşımı)",
            139: "NetBIOS Oturum Servisi",
            69: "TFTP - Önemsiz Dosya Transfer Protokolü",
            161: "SNMP - Basit Ağ Yönetim Protokolü",
            123: "NTP - Ağ Zaman Protokolü",
            5900: "VNC - Sanal Ağ Bilgisayarı",
            8080: "HTTP Alternatif (Proxy, Web önbelleği)",
            8443: "HTTPS Alternatif",
            6379: "Redis Veritabanı",
            27017: "MongoDB Veritabanı",
            1521: "Oracle Veritabanı",
            465: "SMTPS - Güvenli SMTP",
            587: "SMTP Gönderimi",
            993: "IMAPS - Güvenli IMAP",
            995: "POP3S - Güvenli POP3",
            137: "NetBIOS İsim Servisi",
            115: "SFTP - Basit Dosya Transfer Protokolü",
            548: "AFP - Apple Dosyalama Protokolü",
            631: "IPP - İnternet Yazdırma Protokolü",
            3000: "Yaygın geliştirme sunucusu portu",
            5000: "Yaygın geliştirme sunucusu portu",
            8000: "Yaygın geliştirme sunucusu portu"
        }
        
        # İlk verileri doldur
        for port, service in sorted(COMMON_PORTS.items()):
            description = port_descriptions.get(port, "")
            port_tree.insert("", "end", values=(port, service, description))
            
        # Port listesini filtreleme işlevi
        def filter_ports(*args):
            search_text = search_var.get().lower()
            category = category_var.get()
            
            # Mevcut öğeleri temizle
            for item in port_tree.get_children():
                port_tree.delete(item)
                
            # Filtrelenmiş öğeleri doldur
            for port, service in sorted(COMMON_PORTS.items()):
                # Seçilen kategoride değilse atla
                if category != "Tümü":
                    if port not in categories.get(category, []):
                        continue
                        
                description = port_descriptions.get(port, "")
                
                # Metin filtresini uygula
                if (search_text in str(port).lower() or 
                    search_text in service.lower() or 
                    search_text in description.lower()):
                    port_tree.insert("", "end", values=(port, service, description))
                    
        # Sıralama işlevi
        def sort_tree(col, reverse):
            items = [(port_tree.set(item, col), item) for item in port_tree.get_children()]
            
            # Düzgün sıralama için port numaralarını tamsayılara dönüştür
            if col == "port":
                # Düzgün IP sıralaması için tamsayı demetine dönüştür
                items = [(int(val), item) for val, item in items]
                items.sort(reverse=reverse)
                items = [(str(val), item) for val, item in items]
            else:
                # Diğer sütunlar için normal dize sıralaması
                items.sort(reverse=reverse)
            
            # Öğeleri sıralanmış düzende yeniden düzenle
            for index, (_, item) in enumerate(items):
                port_tree.move(item, '', index)
                
            # Başlığı ters sıralama düzenine geçir
            port_tree.heading(col, command=lambda: sort_tree(col, not reverse))
            
        # Olayları bağla
        search_var.trace("w", filter_ports)
        cat_combo.bind("<<ComboboxSelected>>", filter_ports)
        
        # Düğmeler
        btn_frame = ttk.Frame(content)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        close_btn = ttk.Button(btn_frame, text="Kapat", command=ref_window.destroy)
        close_btn.pack(side=tk.RIGHT, padx=5)
        
        # İletişim kutusunu ortala
        ref_window.update_idletasks()
        width = ref_window.winfo_width()
        height = ref_window.winfo_height()
        x = self.winfo_rootx() + (self.winfo_width() // 2) - (width // 2)
        y = self.winfo_rooty() + (self.winfo_height() // 2) - (height // 2)
        ref_window.geometry(f'{width}x{height}+{x}+{y}')
        
    def show_user_guide(self):
        """Kullanım kılavuzunu göster"""
        guide_window = tk.Toplevel(self)
        guide_window.title("NetScan Pro - Kullanım Kılavuzu")
        guide_window.geometry("700x500")
        guide_window.transient(self)
        
        # Sekmeli arayüz için notebook oluştur
        notebook = ttk.Notebook(guide_window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Başlangıç sekmesi
        start_frame = ttk.Frame(notebook, padding=10)
        notebook.add(start_frame, text="Başlarken")
        
        start_text = ScrolledText(start_frame, wrap=tk.WORD)
        start_text.pack(fill=tk.BOTH, expand=True)
        
        start_content = """# NetScan Pro ile Başlarken
        """
        start_text.insert(tk.END, start_content)
        start_text.configure(state='disabled')  # Salt okunur yap
        
        # Gelişmiş Özellikler sekmesi
        adv_frame = ttk.Frame(notebook, padding=10)
        notebook.add(adv_frame, text="Gelişmiş Özellikler")
        
        adv_text = ScrolledText(adv_frame, wrap=tk.WORD)
        adv_text.pack(fill=tk.BOTH, expand=True)
        
        adv_content = """
        """
        adv_text.insert(tk.END, adv_content)
        adv_text.configure(state='disabled')  # Salt okunur yap
        
        # İpuçları ve Püf Noktaları sekmesi
        tips_frame = ttk.Frame(notebook, padding=10)
        notebook.add(tips_frame, text="İpuçları ve Püf Noktaları")
        
        tips_text = ScrolledText(tips_frame, wrap=tk.WORD)
        tips_text.pack(fill=tk.BOTH, expand=True)
        
        tips_content = """# İpuçları ve Püf Noktaları

        """
        tips_text.insert(tk.END, tips_content)
        tips_text.configure(state='disabled')  # Salt okunur yap
        
        # Kapat düğmesi
        close_btn = ttk.Button(guide_window, text="Kapat", command=guide_window.destroy)
        close_btn.pack(side=tk.RIGHT, padx=10, pady=10)
        
        # İletişim kutusunu ortala
        guide_window.update_idletasks()
        width = guide_window.winfo_width()
        height = guide_window.winfo_height()
        x = self.winfo_rootx() + (self.winfo_width() // 2) - (width // 2)
        y = self.winfo_rooty() + (self.winfo_height() // 2) - (height // 2)
        guide_window.geometry(f'{width}x{height}+{x}+{y}')
        
    def check_updates(self):
        """Uygulama güncellemelerini kontrol et"""
        messagebox.showinfo("Güncellemeleri Kontrol Et", 
                         "NetScan Pro güncel (Sürüm 2.0.0).")
        
    def show_about(self):
        """Uygulama bilgilerini içeren hakkında iletişim kutusunu göster"""
        about_window = tk.Toplevel(self)
        about_window.title("NetScan Pro Hakkında")
        about_window.geometry("400x300")
        about_window.transient(self)
        about_window.grab_set()
        
        # İçerik oluştur
        content = ttk.Frame(about_window, padding=20)
        content.pack(fill=tk.BOTH, expand=True)
        
        # Uygulama adı
        ttk.Label(content, text="NetScan Pro", font=('TkDefaultFont', 16, 'bold')).pack(pady=(0, 5))
        
        # Sürüm
        ttk.Label(content, text="Sürüm 2.0.0").pack(pady=(0, 20))
        
        # Açıklama
        description = ttk.Label(content, text=(
            "Kapsamlı ağ keşfi, port taraması ve cihaz bilgisi sağlayan\n"
            "profesyonel bir ağ tarama uygulaması."
        ), justify=tk.CENTER)
        description.pack(pady=(0, 20))
        
        # Sistem bilgisi
        sys_frame = ttk.LabelFrame(content, text="Sistem Bilgisi")
        sys_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(sys_frame, text=f"Python: {platform.python_version()}").pack(anchor=tk.W, padx=10, pady=2)
        ttk.Label(sys_frame, text=f"Platform: {platform.system()} {platform.release()}").pack(anchor=tk.W, padx=10, pady=2)
        
        # Bağımlılıklar
        dep_text = "Bağımlılıklar: "
        installed = []
        if MAC_MODULE_AVAILABLE:
            installed.append("getmac")
        if PANDAS_AVAILABLE:
            installed.append("pandas")
        if SCAPY_AVAILABLE:
            installed.append("scapy")
        if NMAP_MODULE_AVAILABLE:
            installed.append("python-nmap")
        if MATPLOTLIB_AVAILABLE:
            installed.append("matplotlib")
            
        dep_text += ", ".join(installed) if installed else "Sadece temel kütüphaneler"
        ttk.Label(sys_frame, text=dep_text, wraplength=350).pack(anchor=tk.W, padx=10, pady=2)
        
        # Kapat düğmesi
        close_btn = ttk.Button(content, text="Kapat", command=about_window.destroy)
        close_btn.pack(side=tk.BOTTOM, pady=10)
        
        # İletişim kutusunu ortala
        about_window.update_idletasks()
        width = about_window.winfo_width()
        height = about_window.winfo_height()
        x = self.winfo_rootx() + (self.winfo_width() // 2) - (width // 2)
        y = self.winfo_rooty() + (self.winfo_height() // 2) - (height // 2)
        about_window.geometry(f'{width}x{height}+{x}+{y}')

# Komut satırı arayüzü
def parse_arguments():
    """Komut satırı argümanlarını ayrıştır"""
    import argparse
    
    parser = argparse.ArgumentParser(description="NetScan Pro - Gelişmiş Ağ Tarama Aracı")
    parser.add_argument("-r", "--range", help="Taranacak IP aralığı (CIDR gösterimi)")
    parser.add_argument("-m", "--mode", choices=["Fast", "Normal", "Thorough"], default="Normal",
                      help="Tarama modu")
    parser.add_argument("-p", "--ports", help="Taranacak portlar (virgülle ayrılmış, aralıklar izin verilen)")
    parser.add_argument("-o", "--output", help="Sonuçlar için çıktı dosyası (CSV formatı)")
    parser.add_argument("-c", "--console", action="store_true", help="Konsol modunda çalıştır (GUI yok)")
    
    return parser.parse_args()

# Ana işlev
def main():
    """Ana uygulama işlevi"""
    # Komut satırı argümanlarını ayrıştır
    args = parse_arguments()
    
    # Konsol modu mu GUI modu mu?
    if args.console:
        print("NetScan Pro - Konsol Modu")
        print("-----------------------")
        
        # Tarayıcı ve ayarları oluştur
        settings = AppSettings()
        scanner = NetworkScanner(
            settings=settings,
            progress_callback=lambda p, m: print(f"{m} ({p:.1f}%)")
        )
        
        # Tarama parametrelerini ayarla
        ip_range = args.range or settings.get('ip_range')
        scan_mode = args.mode
        
        if args.ports:
            ports = PortUtils.parse_port_range(args.ports)
        else:
            profile_name = settings.get('port_profile')
            if profile_name in PORT_PROFILES:
                ports = PORT_PROFILES[profile_name]
            else:
                ports = PortUtils.parse_port_range(settings.get('custom_ports'))
                
        # Konsol modu için durum geri çağrısı
        def console_status(message):
            print(message)
            
        # Durum geri çağrısını ayarla
        scanner.status_callback = console_status
        
        # Taramayı çalıştır
        print(f"{ip_range} aralığı {scan_mode} modunda taranıyor...")
        results = scanner.scan_ip_range(ip_range, ports, scan_mode)
        
        # Sonuçları yazdır
        print(f"\nTarama tamamlandı. {len(results)} cihaz bulundu:")
        for result in results:
            print(f"\nIP: {result['ip']}")
            if result.get('hostname'):
                print(f"Hostname: {result['hostname']}")
            if result.get('mac_address'):
                print(f"MAC: {result['mac_address']}")
            if result.get('open_ports'):
                print("Açık portlar:")
                for port, service in result['open_ports'].items():
                    print(f"  - {port}: {service}")
                    
        # İstenirse sonuçları dışa aktar
        if args.output:
            success, message = scanner.export_to_csv(args.output, results)
            print(message)
            
        return 0
    
    # Ana uygulamayı başlat (bu ana pencereyi oluşturacak)
    app = NetworkScannerApp()
    
    # Argümanlar sağlandıysa uygula
    if args.range:
        app.ip_range_var.set(args.range)
    if args.mode:
        app.scan_mode_var.set(args.mode)
    if args.ports:
        app.app_settings.set('custom_ports', args.ports)
        
    # Hem aralık hem de portlar belirtildiyse taramayı otomatik başlat
    if args.range and args.ports:
        app.after(1000, app.start_scan)

    # GUI olay döngüsünü başlat
    app.mainloop()
    
    return 0

# Programı çalıştır
if __name__ == "__main__":
    sys.exit(main())          