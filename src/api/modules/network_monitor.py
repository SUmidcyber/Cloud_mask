import scapy.all as scapy
from scapy.layers import http
import psutil
import socket
from datetime import datetime
from typing import Dict, List
import threading
import platform

class RealNetworkMonitor:
    def __init__(self):
        self.interfaces = self.get_network_interfaces()
        self.running = False
        self.packet_count = 0
        self.suspicious_activities = []
        self.start_time = datetime.now()

    def get_network_interfaces(self) -> List[Dict]:
        """Ağ arayüzlerini psutil ile tespit eder (netifaces olmadan)"""
        interfaces = []
        try:
            for name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        interfaces.append({
                            'name': name,
                            'ip': addr.address,
                            'netmask': addr.netmask,
                            'mac': addr.address if addr.family == psutil.AF_LINK else ''
                        })
        except Exception as e:
            print(f"Interface detection error: {e}")
        return interfaces

    def packet_callback(self, packet):
        """Scapy paket analizi"""
        if not self.running:
            return

        self.packet_count += 1
        
        if packet.haslayer(http.HTTPRequest):
            http_layer = packet.getlayer(http.HTTPRequest)
            ip_layer = packet.getlayer(scapy.IP)
            
            suspicious = {
                'timestamp': datetime.now().isoformat(),
                'source_ip': ip_layer.src,
                'destination': ip_layer.dst,
                'method': http_layer.Method.decode(),
                'path': http_layer.Path.decode(),
                'risk_level': 0
            }

            # Basit threat detection kuralları
            if any(keyword in suspicious['path'].lower() for keyword in ['admin', 'login', 'wp-admin']):
                suspicious['risk_level'] = 70
            if self.packet_count > 1000:
                suspicious['risk_level'] = 90

            if suspicious['risk_level'] > 50:
                self.suspicious_activities.append(suspicious)

    def start_monitoring(self, interface: str = None):
        """Ağ dinlemeyi başlatır"""
        if not self.interfaces:
            print("No active interfaces found!")
            return

        self.running = True
        target_interface = interface or self.interfaces[0]['name']
        
        threading.Thread(
            target=scapy.sniff,
            kwargs={
                'iface': target_interface,
                'prn': self.packet_callback,
                'store': False
            },
            daemon=True
        ).start()

    def stop_monitoring(self):
        self.running = False