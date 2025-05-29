#!/usr/bin/env python3
"""
Cloud Security Monitor - Windows Optimized Version
Author: Umidc
Version: 3.5 (Stable Npcap Implementation)
"""

import os
import sys
import logging
import platform
import threading
import socket
from datetime import datetime
from contextlib import asynccontextmanager
import psutil
from fastapi import FastAPI, HTTPException
import uvicorn
from typing import List, Dict, Any, Optional

# --- Configuration ---
class Config:
    LOG_FILE = "security.log"
    API_HOST = "0.0.0.0"
    API_PORT = 8000
    SNIFF_FILTER = "ip"  # Only monitor IP traffic
    THREAT_PORTS = {
        22: "SSH Brute Force",
        3389: "RDP Brute Force",
        445: "SMB Exploit Attempt",
        1433: "SQL Server Bruteforce"
    }
    MAX_THREATS = 1000  # Maximum threats to keep in memory

# --- Windows Initialization ---
if platform.system() == 'Windows':
    import ctypes
    try:
        import scapy.all as scapy
        from scapy.config import conf
        
        # Configure Scapy for Windows
        conf.use_pcap = True
        if not hasattr(scapy.arch.windows, 'L3WinSocket'):
            # Fallback to raw sockets if Npcap not properly installed
            conf.L3socket = scapy.L3RawSocket
        else:
            from scapy.arch.windows import L3WinSocket
            conf.L3socket = L3WinSocket

        # Admin check
        if not ctypes.windll.shell32.IsUserAnAdmin():
            ctypes.windll.user32.MessageBoxW(0, 
                "Please run as Administrator!", 
                "Permission Error", 0x10)
            sys.exit(1)

    except ImportError as e:
        print(f"Critical Scapy import error: {e}")
        print("Please install: pip install scapy==2.4.5")
        sys.exit(1)

# --- Logging Setup ---
def setup_logger() -> logging.Logger:
    """Configure application logging"""
    logger = logging.getLogger("SecurityMonitor")
    logger.setLevel(logging.INFO)
    
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # File handler
    file_handler = logging.FileHandler(Config.LOG_FILE)
    file_handler.setFormatter(formatter)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    # Suppress Scapy warnings
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    
    return logger

logger = setup_logger()

# --- Network Monitor Implementation ---
class NetworkMonitor:
    def __init__(self):
        self.running = False
        self.packet_count = 0
        self.detected_threats: List[Dict[str, Any]] = []
        self.interfaces = self._get_network_interfaces()
        self.lock = threading.Lock()
        self.sniffer_thread: Optional[threading.Thread] = None

    def _get_network_interfaces(self) -> List[Dict[str, str]]:
        """Get active network interfaces with IP addresses"""
        interfaces = []
        try:
            for name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        interfaces.append({
                            'name': name,
                            'ip': addr.address,
                            'netmask': addr.netmask,
                            'mac': next(
                                (a.address for a in addrs 
                                if a.family == psutil.AF_LINK), 
                                '')
                        })
                        break
            logger.info(f"Found {len(interfaces)} network interfaces")
        except Exception as e:
            logger.error(f"Interface detection failed: {e}")
        return interfaces

    def _packet_handler(self, packet) -> None:
        """Process network packets and detect threats"""
        if not self.running:
            return

        self.packet_count += 1
        
        try:
            if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
                ip = packet[scapy.IP]
                tcp = packet[scapy.TCP]
                
                if tcp.dport in Config.THREAT_PORTS:
                    threat = {
                        'type': Config.THREAT_PORTS[tcp.dport],
                        'source': ip.src,
                        'destination': ip.dst,
                        'port': tcp.dport,
                        'timestamp': datetime.now().isoformat(),
                        'flags': str(tcp.flags)
                    }
                    
                    with self.lock:
                        self.detected_threats.append(threat)
                        # Maintain threat list size
                        if len(self.detected_threats) > Config.MAX_THREATS:
                            self.detected_threats.pop(0)
                    
                    logger.warning(f"Threat detected: {threat}")

        except Exception as e:
            logger.error(f"Packet processing error: {e}")

    def start(self) -> bool:
        """Start network monitoring"""
        if not self.interfaces:
            logger.error("No active network interfaces available")
            return False

        if self.running:
            logger.warning("Monitor already running")
            return True

        self.running = True
        self.sniffer_thread = threading.Thread(
            target=self._start_sniffing,
            daemon=True,
            name="PacketSniffer"
        )
        self.sniffer_thread.start()
        logger.info(f"Started monitoring on {self.interfaces[0]['name']}")
        return True

    def _start_sniffing(self) -> None:
        """Main packet sniffing loop"""
        try:
            scapy.sniff(
                prn=self._packet_handler,
                store=False,
                filter=Config.SNIFF_FILTER,
                stop_filter=lambda _: not self.running,
                iface=self.interfaces[0]['name'] if self.interfaces else None
            )
        except Exception as e:
            logger.error(f"Sniffing error: {e}")
            self.running = False

    def stop(self) -> None:
        """Stop network monitoring"""
        if not self.running:
            return

        self.running = False
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=2)
        logger.info("Monitoring stopped")

# --- FastAPI Application ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle management"""
    monitor = NetworkMonitor()
    if not monitor.start():
        raise RuntimeError("Failed to start network monitoring")
    
    app.state.monitor = monitor
    logger.info("Application started")
    
    try:
        yield
    finally:
        monitor.stop()
        logger.info("Application shutdown complete")

app = FastAPI(
    title="Cloud Security Monitor",
    version="3.5",
    description="Real-time network threat detection system",
    lifespan=lifespan
)

# --- API Endpoints ---
@app.get("/stats", summary="Get monitoring statistics")
async def get_stats():
    """Return current monitoring statistics"""
    return {
        'status': 'running',
        'packets_analyzed': app.state.monitor.packet_count,
        'active_threats': len(app.state.monitor.detected_threats),
        'interfaces': app.state.monitor.interfaces,
        'start_time': datetime.now().isoformat()
    }

@app.get("/threats", summary="Get detected threats")
async def get_threats(limit: int = 20):
    """Get list of detected threats"""
    if limit < 1 or limit > 100:
        raise HTTPException(
            status_code=400,
            detail="Limit must be between 1 and 100"
        )
    
    with app.state.monitor.lock:
        return {
            'total': len(app.state.monitor.detected_threats),
            'threats': app.state.monitor.detected_threats[-limit:]
        }

# --- Main Execution ---
if __name__ == "__main__":
    try:
        logger.info("Starting Cloud Security Monitor")
        uvicorn.run(
            app,
            host=Config.API_HOST,
            port=Config.API_PORT,
            log_level="info",
            reload=True
        )
    except Exception as e:
        logger.critical(f"Application failed: {e}")
        sys.exit(1)