import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from cachetools import TTLCache
import logging

class ThreatIntelFeed:
    def __init__(self, api_key: str, cache_ttl: int = 3600):
        self.api_key = api_key
        self.cache = TTLCache(maxsize=1000, ttl=cache_ttl)
        self.logger = logging.getLogger("threat_intel")

    def _make_request(self, url: str, params: Dict = None) -> Optional[Dict]:
        try:
            headers = {
                "Accept": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            }
            response = requests.get(url, headers=headers, params=params, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed: {str(e)}")
            return None

class AbuseIPDBFeed(ThreatIntelFeed):
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    def check_ip(self, ip: str) -> Optional[Dict]:
        if cached := self.cache.get(ip):
            return cached
            
        url = f"{self.BASE_URL}/check"
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        
        if data := self._make_request(url, params):
            result = {
                "is_malicious": data.get("data", {}).get("abuseConfidenceScore", 0) > 50,
                "reports": data.get("data", {}).get("totalReports", 0),
                "last_reported": data.get("data", {}).get("lastReportedAt"),
                "isp": data.get("data", {}).get("isp")
            }
            self.cache[ip] = result
            return result
        return None

class VirusTotalFeed(ThreatIntelFeed):
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def check_hash(self, file_hash: str) -> Optional[Dict]:
        if cached := self.cache.get(file_hash):
            return cached
            
        url = f"{self.BASE_URL}/files/{file_hash}"
        
        if data := self._make_request(url):
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            result = {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
                "type": data.get("data", {}).get("attributes", {}).get("type_description")
            }
            self.cache[file_hash] = result
            return result
        return None

class ThreatIntelligenceAggregator:
    def __init__(self, config: Dict):
        self.feeds = {
            "abuseipdb": AbuseIPDBFeed(config.get("abuseipdb_key")),
            "virustotal": VirusTotalFeed(config.get("virustotal_key"))
        }
        
    def analyze_ip(self, ip: str) -> Dict:
        results = {}
        for name, feed in self.feeds.items():
            if hasattr(feed, "check_ip"):
                results[name] = feed.check_ip(ip)
        return results
        
    def analyze_hash(self, file_hash: str) -> Dict:
        results = {}
        for name, feed in self.feeds.items():
            if hasattr(feed, "check_hash"):
                results[name] = feed.check_hash(file_hash)
        return results