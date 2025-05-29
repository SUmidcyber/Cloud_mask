#!/usr/bin/env python3
"""
Kali Linux Ağ Güvenlik İzleyici
Versiyon: 6.0 (Genişletilmiş)
Özellikler:
- Tüm ağ trafiğini izleme
- Anormal aktiviteleri tespit etme
- Saldırıları loglama
- REST API ile yönetim
"""

import os
import sys
import logging
import threading
import socket
import json
from datetime import datetime
from typing import List, Dict, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
import psutil

# ===== KONFİGÜRASYON =====
class Config:
    LOG_FILE = "/var/log/ag_guvenlik.log"  # Log dosya yolu
    ALERT_FILE = "/var/log/ag_saldırıları.log"  # Saldırı logları
    API_HOST = "0.0.0.0"  # API IP
    API_PORT = 8000  # API Port
    MAX_LOGS = 10000  # Maksimum log kaydı
    
    # Taranacak portlar ve açıklamaları
    TEHLIKELI_PORTLAR = {
        22: "SSH Bruteforce",
        23: "Telnet Attack",
        80: "HTTP Exploit",
        443: "HTTPS Exploit", 
        3389: "RDP Attack",
        445: "SMB Exploit",
        1433: "SQL Injection",
        3306: "MySQL Attack",
        5900: "VNC Attack",
        8080: "Web Exploit"
    }

# ===== VERİ MODELLERİ =====
class SaldiriLogu(BaseModel):
    kaynak_ip: str
    hedef_ip: str
    port: int
    saldiri_turu: str
    zaman: str
    ek_bilgiler: Optional[Dict] = None

# ===== LOG AYARLARI =====
def log_ayarlari():
    """Loglama sistemini kurar"""
    try:
        os.makedirs(os.path.dirname(Config.LOG_FILE), exist_ok=True)
        
        logger = logging.getLogger("AgGuvenlik")
        logger.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Dosya handler
        file_handler = logging.FileHandler(Config.LOG_FILE)
        file_handler.setFormatter(formatter)
        
        # Konsol handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    except Exception as e:
        print(f"Log ayarları yapılamadı: {e}")
        sys.exit(1)

logger = log_ayarlari()

# ===== AĞ İZLEME SİSTEMİ =====
class AgIzleyici:
    def __init__(self):
        self.calisiyor = False
        self.loglar = []
        self.kilit = threading.Lock()
        self.interface = self._ag_arayuzu_sec()
        self.sniffer_thread = None
        
    def _ag_arayuzu_sec(self) -> str:
        """Ağ arayüzünü otomatik seçer"""
        try:
            arayuzler = psutil.net_if_addrs()
            # eth0, wlan0 gibi fiziksel arayüzlere öncelik ver
            for arayuz in ["eth0", "wlan0", "enp0s3"]:
                if arayuz in arayuzler:
                    return arayuz
            return list(arayuzler.keys())[0]  # Yoksa ilk arayüzü seç
        except Exception as e:
            logger.error(f"Ağ arayüzü seçilemedi: {e}")
            return "eth0"  # Varsayılan
    
    def _paket_analiz(self, raw_packet) -> Optional[Dict]:
        """Ham paketleri analiz eder"""
        try:
            # Basit bir IP paket analizi (gerçekte daha kompleks olmalı)
            if len(raw_packet) > 20:  # Minimum IP paket boyutu
                # Kaynak ve hedef IP'leri çek (basitleştirilmiş)
                src_ip = ".".join(str(x) for x in raw_packet[12:16])
                dst_ip = ".".join(str(x) for x in raw_packet[16:20])
                
                # TCP/UDP portlarını kontrol et
                if raw_packet[9] == 6:  # TCP protokolü
                    src_port = int.from_bytes(raw_packet[20:22], 'big')
                    dst_port = int.from_bytes(raw_packet[22:24], 'big')
                    
                    # Tehlikeli port kontrolü
                    if dst_port in Config.TEHLIKELI_PORTLAR:
                        return {
                            "kaynak_ip": src_ip,
                            "hedef_ip": dst_ip,
                            "port": dst_port,
                            "saldiri_turu": Config.TEHLIKELI_PORTLAR[dst_port],
                            "zaman": datetime.now().isoformat(),
                            "paket_boyutu": len(raw_packet)
                        }
                        
        except Exception as e:
            logger.error(f"Paket analiz hatası: {e}")
        return None

    def _saldiri_kaydet(self, saldiri: Dict):
        """Saldırıyı loglara kaydeder"""
        with self.kilit:
            self.loglar.append(saldiri)
            if len(self.loglar) > Config.MAX_LOGS:
                self.loglar.pop(0)
        
        # Log dosyasına yaz
        with open(Config.ALERT_FILE, "a") as f:
            f.write(json.dumps(saldiri) + "\n")
        
        logger.warning(f"SALDIRI TESPİT EDİLDİ: {saldiri}")

    def _paket_yakala(self):
        """Paket yakalama ana döngüsü"""
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            sock.bind((self.interface, 0))
            
            logger.info(f"{self.interface} arayüzünde paket yakalama başladı...")
            
            while self.calisiyor:
                raw_packet, _ = sock.recvfrom(65535)
                if saldiri := self._paket_analiz(raw_packet):
                    self._saldiri_kaydet(saldiri)
                    
        except Exception as e:
            logger.critical(f"Paket yakalama hatası: {e}")
        finally:
            sock.close()

    def izlemeyi_baslat(self):
        """İzlemeyi başlatır"""
        if self.calisiyor:
            return False
            
        self.calisiyor = True
        self.sniffer_thread = threading.Thread(
            target=self._paket_yakala,
            daemon=True
        )
        self.sniffer_thread.start()
        return True

    def izlemeyi_durdur(self):
        """İzlemeyi durdurur"""
        self.calisiyor = False
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=2)
        logger.info("İzleme durduruldu")

# ===== API SUNUCUSU =====
app = FastAPI(
    title="Ağ Güvenlik API",
    description="Gerçek zamanlı ağ saldırı izleme sistemi"
)

izleyici = AgIzleyici()

@app.on_event("startup")
async def baslangic():
    if not izleyici.izlemeyi_baslat():
        logger.error("İzleme başlatılamadı!")
        sys.exit(1)

@app.on_event("shutdown")
async def kapanis():
    izleyici.izlemeyi_durdur()

@app.get("/api/v1/saldirilar")
async def saldirilari_getir(limit: int = 100):
    """Son saldırıları listeler"""
    if limit < 1 or limit > 1000:
        raise HTTPException(400, "Limit 1-1000 arasında olmalı")
    
    with izleyici.kilit:
        return {
            "toplam": len(izleyici.loglar),
            "saldirilar": izleyici.loglar[-limit:]
        }

@app.get("/api/v1/durum")
async def sistem_durumu():
    """Sistem durumunu gösterir"""
    return {
        "durum": "çalışıyor" if izleyici.calisiyor else "durduruldu",
        "arayuz": izleyici.interface,
        "tespit_edilen_saldirilar": len(izleyici.loglar),
        "son_saldiri": izleyici.loglar[-1] if izleyici.loglar else None
    }

# ===== ANA ÇALIŞTIRMA =====
if __name__ == "__main__":
    try:
        # Root kontrolü
        if os.geteuid() != 0:
            logger.error("Bu uygulama root yetkisi gerektirir!")
            sys.exit(1)
            
        logger.info("Ağ güvenlik izleyici başlatılıyor...")
        uvicorn.run(
            app,
            host=Config.API_HOST,
            port=Config.API_PORT,
            log_level="info"
        )
    except Exception as e:
        logger.critical(f"Kritik hata: {e}")
        sys.exit(1)