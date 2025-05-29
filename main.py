#!/usr/bin/env python3
"""
Cloud Security Monitor - Kali Linux Complete Version
Author: Umidc
Version: 4.1 (With Proper Logging API)
"""

import os
import sys
import logging
import platform
import threading
import socket
from datetime import datetime
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Query
import uvicorn
from typing import List, Dict, Any, Optional
import json
from pydantic import BaseModel
import psutil

# --- Configuration ---
class Config:
    LOG_FILE = "/var/log/security_monitor.log"
    API_HOST = "0.0.0.0"
    API_PORT = 8000
    SNIFF_FILTER = "ip"
    THREAT_PORTS = {
        22: "SSH Brute Force",
        21: "FTP Exploit Attempt",
        23: "Telnet Attack",
        3389: "RDP Bruteforce",
        445: "SMB Exploit",
        1433: "SQL Injection Attempt",
        3306: "MySQL Attack"
    }
    MAX_LOGS = 5000  # Maximum logs to keep in memory

# --- Request Models ---
class SecurityLog(BaseModel):
    source_ip: str
    event_type: str
    severity: int
    user: Optional[str] = None
    details: Optional[Dict] = None

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
    
    # Ensure log directory exists
    os.makedirs(os.path.dirname(Config.LOG_FILE), exist_ok=True)
    
    # File handler
    file_handler = logging.FileHandler(Config.LOG_FILE)
    file_handler.setFormatter(formatter)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

logger = setup_logger()

# --- Security Log Manager ---
class SecurityLogManager:
    def __init__(self):
        self.logs: List[Dict] = []
        self.lock = threading.Lock()
    
    def add_log(self, log_data: Dict) -> None:
        """Add a new security log"""
        log_entry = {
            **log_data,
            "timestamp": datetime.now().isoformat()
        }
        
        with self.lock:
            self.logs.append(log_entry)
            if len(self.logs) > Config.MAX_LOGS:
                self.logs.pop(0)
        
        logger.info(f"New security event: {log_entry}")

    def get_logs(self, limit: int = 100) -> List[Dict]:
        """Get security logs with limit"""
        with self.lock:
            return self.logs[-limit:]

# --- Network Monitor Implementation ---
class NetworkMonitor:
    def __init__(self, log_manager: SecurityLogManager):
        self.running = False
        self.log_manager = log_manager
        self.interface = self._get_default_interface()
        self.sniffer_thread: Optional[threading.Thread] = None

    def _get_default_interface(self) -> str:
        """Get default network interface"""
        interfaces = psutil.net_if_addrs().keys()
        return next(iter(interfaces), "eth0")

    def _packet_handler(self, raw_packet) -> None:
        """Process network packets"""
        try:
            # Basic packet parsing (replace with your actual parsing logic)
            if b"HTTP" in raw_packet:
                self.log_manager.add_log({
                    "source_ip": "detected",
                    "event_type": "HTTP Traffic",
                    "severity": 1,
                    "details": {"packet": str(raw_packet[:100])}
                })
                
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
        """Main packet sniffing loop"""
        try:
            sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            sniffer.bind((self.interface, 0))
            
            while self.running:
                raw_packet = sniffer.recvfrom(65535)
                self._packet_handler(raw_packet[0])
                
        except Exception as e:
            logger.error(f"Sniffing error: {e}")
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
    log_manager = SecurityLogManager()
    monitor = NetworkMonitor(log_manager)
    
    app.state.log_manager = log_manager
    app.state.monitor = monitor
    
    if not monitor.start():
        raise RuntimeError("Failed to start network monitoring")
    
    logger.info("Application started")
    
    try:
        yield
    finally:
        monitor.stop()
        logger.info("Application shutdown complete")

app = FastAPI(
    title="Kali Security Monitor API",
    version="4.1",
    description="Complete security monitoring solution for Kali Linux",
    lifespan=lifespan
)

# --- API Endpoints ---
@app.post("/api/v1/security/logs", status_code=201)
async def create_security_log(
    source_ip: str = Query(..., description="Source IP address"),
    event_type: str = Query(..., description="Type of security event"),
    severity: int = Query(..., ge=1, le=10, description="Severity level (1-10)"),
    payload: SecurityLog = None
):
    """Create a new security log entry"""
    log_data = {
        "source_ip": source_ip,
        "event_type": event_type,
        "severity": severity,
        "user": payload.user if payload else None,
        "details": payload.details if payload else None
    }
    
    app.state.log_manager.add_log(log_data)
    return {"status": "success", "message": "Log created"}

@app.get("/api/v1/security/logs")
async def get_security_logs(
    limit: int = Query(100, ge=1, le=1000, description="Number of logs to return")
):
    """Get security logs"""
    logs = app.state.log_manager.get_logs(limit)
    return {
        "count": len(logs),
        "logs": logs
    }

@app.get("/stats")
async def get_stats():
    """Get monitoring statistics"""
    return {
        "status": "running",
        "interface": app.state.monitor.interface,
        "log_count": len(app.state.log_manager.logs)
    }

# --- Main Execution ---
if __name__ == "__main__":
    try:
        logger.info("Starting Kali Security Monitor API")
        uvicorn.run(
            app,
            host=Config.API_HOST,
            port=Config.API_PORT,
            log_level="info",
            reload=False
        )
    except Exception as e:
        logger.critical(f"Application failed: {e}")
        sys.exit(1)