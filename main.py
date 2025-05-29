#!/usr/bin/env python3
"""
Cloud Security Monitor - Kali Linux Optimized Version
Author: Umidc
Version: 4.0 (Linux Raw Socket Implementation)
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
    LOG_FILE = "/var/log/security_monitor.log"
    API_HOST = "0.0.0.0"
    API_PORT = 8000
    SNIFF_FILTER = "ip"  # BPF filter syntax
    THREAT_PORTS = {
        22: "SSH Brute Force",
        21: "FTP Exploit Attempt",
        23: "Telnet Attack",
        3389: "RDP Bruteforce",
        445: "SMB Exploit",
        1433: "SQL Injection Attempt",
        3306: "MySQL Attack"
    }
    MAX_THREATS = 2000  # Maximum threats to keep in memory
    INTERFACE = "eth0"  # Default monitoring interface

# --- Linux Privilege Check ---
if platform.system() == 'Linux':
    if os.geteuid() != 0:
        print("ERROR: This application requires root privileges!", file=sys.stderr)
        sys.exit(1)

# --- Logging Setup ---
def setup_logger() -> logging.Logger:
    """Configure application logging"""
    logger = logging.getLogger("KaliSecurityMonitor")
    logger.setLevel(logging.INFO)
    
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # File handler (ensure log directory exists)
    os.makedirs(os.path.dirname(Config.LOG_FILE), exist_ok=True)
    file_handler = logging.FileHandler(Config.LOG_FILE)
    file_handler.setFormatter(formatter)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

logger = setup_logger()

# --- Network Monitor Implementation ---
class NetworkMonitor:
    def __init__(self):
        self.running = False
        self.packet_count = 0
        self.detected_threats: List[Dict[str, Any]] = []
        self.interface = self._validate_interface(Config.INTERFACE)
        self.lock = threading.Lock()
        self.sniffer_thread: Optional[threading.Thread] = None

    def _validate_interface(self, iface: str) -> str:
        """Verify the network interface exists"""
        interfaces = psutil.net_if_addrs().keys()
        if iface not in interfaces:
            available = ", ".join(interfaces)
            logger.warning(f"Interface {iface} not found. Available: {available}")
            return next(iter(interfaces), "")  # Use first available interface
        return iface

    def _packet_handler(self, packet) -> None:
        """Process network packets and detect threats"""
        if not self.running:
            return

        self.packet_count += 1
        
        try:
            # Using direct socket parsing instead of Scapy for better performance
            if socket.IP in packet and socket.TCP in packet:
                ip_src = packet[socket.IP].src
                ip_dst = packet[socket.IP].dst
                tcp_dport = packet[socket.TCP].dport
                
                if tcp_dport in Config.THREAT_PORTS:
                    threat = {
                        'type': Config.THREAT_PORTS[tcp_dport],
                        'source': ip_src,
                        'destination': ip_dst,
                        'port': tcp_dport,
                        'timestamp': datetime.now().isoformat(),
                        'interface': self.interface
                    }
                    
                    with self.lock:
                        self.detected_threats.append(threat)
                        if len(self.detected_threats) > Config.MAX_THREATS:
                            self.detected_threats.pop(0)
                    
                    logger.warning(f"Threat detected: {threat}")

        except Exception as e:
            logger.error(f"Packet processing error: {e}")

    def start(self) -> bool:
        """Start network monitoring"""
        self.running = True
        self.sniffer_thread = threading.Thread(
            target=self._start_sniffing,
            daemon=True,
            name="PacketSniffer"
        )
        self.sniffer_thread.start()
        logger.info(f"Started monitoring on {self.interface}")
        return True

    def _start_sniffing(self) -> None:
        """Main packet sniffing loop using raw sockets"""
        try:
            # Create raw socket
            sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            sniffer.bind((self.interface, 0))
            
            while self.running:
                raw_packet = sniffer.recvfrom(65535)
                self._packet_handler(raw_packet[0])
                
        except Exception as e:
            logger.error(f"Sniffing error: {e}")
            self.running = False
        finally:
            if 'sniffer' in locals():
                sniffer.close()

    def stop(self) -> None:
        """Stop network monitoring"""
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
    title="Kali Security Monitor",
    version="4.0",
    description="Linux-optimized network threat detection system",
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
        'interface': app.state.monitor.interface,
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
        logger.info("Starting Kali Security Monitor")
        uvicorn.run(
            app,
            host=Config.API_HOST,
            port=Config.API_PORT,
            log_level="info",
            reload=False  # Disable reload in production
        )
    except Exception as e:
        logger.critical(f"Application failed: {e}")
        sys.exit(1)