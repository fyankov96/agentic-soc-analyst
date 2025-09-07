# Updated protocols/virustotal_scanner.py with retry logic
import requests
import time
import re
import random
from typing import List, Dict, Any
from colorama import Fore
from secrets_ import VIRUSTOTAL_API_KEY
from protocols.vt_cache import VTCache

class VTRetryError(Exception):
    """Custom exception for VT API retry failures"""
    pass

class VirusTotalScanner:
    def __init__(self, cache_ttl_hours: int = 24):
        self.api_key = VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"X-Apikey": self.api_key}
        self.cache = VTCache(ttl_hours=cache_ttl_hours)
        
        # Retry configuration
        self.max_retries = 3
        self.base_delay = 1.0  # Base delay in seconds
        self.max_delay = 60.0  # Maximum delay cap
        self.backoff_multiplier = 2.0
        self.jitter = True  # Add random jitter to avoid thundering herd
        
    def calculate_delay(self, attempt: int, suggested_delay: int = None) -> float:
        """Calculate exponential backoff delay with jitter"""
        if suggested_delay:
            return min(suggested_delay + random.uniform(0, 5), self.max_delay)
        
        delay = self.base_delay * (self.backoff_multiplier ** attempt)
        
        if self.jitter:
            delay += random.uniform(0, delay * 0.1)  # Add 10% jitter
        
        return min(delay, self.max_delay)
    
    def make_api_request(self, url: str) -> Dict[str, Any]:
        """Make API request with retry logic"""
        for attempt in range(self.max_retries):
            try:
                response = requests.get(url, headers=self.headers, timeout=30)
                
                # Success
                if response.status_code == 200:
                    return {"success": True, "data": response.json()}
                
                # Not found - don't retry
                elif response.status_code == 404:
                    return {"success": True, "status": "not_found"}
                
                # Rate limit - extract retry delay from headers
                elif response.status_code == 429:
                    retry_after = response.headers.get('Retry-After')
                    suggested_delay = int(retry_after) if retry_after else None
                    
                    if attempt < self.max_retries - 1:
                        delay = self.calculate_delay(attempt, suggested_delay)
                        print(f"{Fore.LIGHTYELLOW_EX}Rate limited. Retrying in {delay:.1f}s...")
                        time.sleep(delay)
                        continue
                    else:
                        return {"success": False, "error": "Rate limit exceeded", "status_code": 429}
                
                # Server errors (5xx) - retry
                elif 500 <= response.status_code < 600:
                    if attempt < self.max_retries - 1:
                        delay = self.calculate_delay(attempt)
                        print(f"{Fore.LIGHTYELLOW_EX}Server error {response.status_code}. Retrying in {delay:.1f}s...")
                        time.sleep(delay)
                        continue
                    else:
                        return {"success": False, "error": f"Server error: {response.status_code}", "status_code": response.status_code}
                
                # Client errors (4xx, except 429) - don't retry
                elif 400 <= response.status_code < 500:
                    return {"success": False, "error": f"Client error: {response.status_code}", "status_code": response.status_code}
                
                # Other errors - retry
                else:
                    if attempt < self.max_retries - 1:
                        delay = self.calculate_delay(attempt)
                        print(f"{Fore.LIGHTYELLOW_EX}Unexpected status {response.status_code}. Retrying in {delay:.1f}s...")
                        time.sleep(delay)
                        continue
                    else:
                        return {"success": False, "error": f"Unexpected status: {response.status_code}", "status_code": response.status_code}
            
            except requests.exceptions.Timeout:
                if attempt < self.max_retries - 1:
                    delay = self.calculate_delay(attempt)
                    print(f"{Fore.LIGHTYELLOW_EX}Request timeout. Retrying in {delay:.1f}s...")
                    time.sleep(delay)
                    continue
                else:
                    return {"success": False, "error": "Request timeout"}
            
            except requests.exceptions.ConnectionError:
                if attempt < self.max_retries - 1:
                    delay = self.calculate_delay(attempt)
                    print(f"{Fore.LIGHTYELLOW_EX}Connection error. Retrying in {delay:.1f}s...")
                    time.sleep(delay)
                    continue
                else:
                    return {"success": False, "error": "Connection error"}
            
            except Exception as e:
                if attempt < self.max_retries - 1:
                    delay = self.calculate_delay(attempt)
                    print(f"{Fore.LIGHTYELLOW_EX}Unexpected error: {str(e)}. Retrying in {delay:.1f}s...")
                    time.sleep(delay)
                    continue
                else:
                    return {"success": False, "error": f"Unexpected error: {str(e)}"}
        
        return {"success": False, "error": "Max retries exceeded"}
    
    def is_valid_hash(self, ioc: str) -> bool:
        """Check if IOC is a valid hash (MD5, SHA1, SHA256)"""
        hash_patterns = {
            32: r'^[a-fA-F0-9]{32}$',  # MD5
            40: r'^[a-fA-F0-9]{40}$',  # SHA1
            64: r'^[a-fA-F0-9]{64}$'   # SHA256
        }
        return len(ioc) in hash_patterns and re.match(hash_patterns[len(ioc)], ioc)
    
    def is_valid_ip(self, ioc: str) -> bool:
        """Check if IOC is a valid IP address"""
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return re.match(ip_pattern, ioc) is not None and not self.is_timestamp(ioc)
    
    def is_valid_domain(self, ioc: str) -> bool:
        """Check if IOC is a valid domain"""
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return re.match(domain_pattern, ioc) is not None and not self.is_timestamp(ioc)
    
    def is_valid_url(self, ioc: str) -> bool:
        """Check if IOC is a valid URL"""
        return ioc.startswith(('http://', 'https://'))
    
    def is_timestamp(self, ioc: str) -> bool:
        """Check if string is a timestamp or date"""
        timestamp_patterns = [
            r'\d{4}-\d{2}-\d{2}',  # Date format
            r'\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}',  # DateTime
            r'\d{10,}',  # Unix timestamp
            r'.*\+\d{2}:\d{2}$',  # Timezone offset
        ]
        return any(re.search(pattern, ioc) for pattern in timestamp_patterns)
    
    def is_valid_email(self, ioc: str) -> bool:
        """Check if IOC is a valid email address"""
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(email_pattern, ioc) is not None
    
    def categorize_ioc(self, ioc: str) -> str:
        """Determine IOC type"""
        # Skip timestamps and other non-IOC data
        if self.is_timestamp(ioc) or len(ioc) < 3:
            return "skip"
        elif self.is_valid_hash(ioc):
            return "file"
        elif self.is_valid_ip(ioc):
            return "ip_address"
        elif self.is_valid_url(ioc):
            return "url"
        elif self.is_valid_email(ioc):
            return "skip"
        elif self.is_valid_domain(ioc):
            return "domain"
        else:
            return "unknown"
    
    def scan_ioc(self, ioc: str) -> Dict[str, Any]:
        """Scan single IOC with VirusTotal (with caching and retry logic)"""
        ioc_type = self.categorize_ioc(ioc)
        
        if ioc_type == "skip":
            return {"ioc": ioc, "type": ioc_type, "skip": True}
        
        # Check cache only for valid IOCs
        cached_result = self.cache.get(ioc)
        if cached_result:
            cached_result["cache_hit"] = True
            return cached_result
        
        if ioc_type in ["unknown", "skip"]:
            return {"ioc": ioc, "type": ioc_type, "error": "Unsupported IOC type or invalid data"}
        
        try:
            if ioc_type == "file":
                url = f"{self.base_url}/files/{ioc}"
            elif ioc_type == "ip_address":
                url = f"{self.base_url}/ip_addresses/{ioc}"
            elif ioc_type == "domain":
                url = f"{self.base_url}/domains/{ioc}"
            elif ioc_type == "url":
                import base64
                url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
                url = f"{self.base_url}/urls/{url_id}"
            
            # Make API request with retry logic
            api_result = self.make_api_request(url)
            
            if api_result["success"]:
                if api_result.get("status") == "not_found":
                    result = {"ioc": ioc, "type": ioc_type, "status": "not_found", "malicious": 0, "suspicious": 0, "clean": 0}
                else:
                    result = self.parse_vt_response(ioc, ioc_type, api_result["data"])
            else:
                result = {"ioc": ioc, "type": ioc_type, "error": api_result["error"]}
            
            # Cache successful results (including not_found)
            if api_result["success"]:
                result["cache_hit"] = False
                self.cache.set(ioc, ioc_type, result)
            
            return result
                
        except Exception as e:
            return {"ioc": ioc, "type": ioc_type, "error": f"Unexpected error: {str(e)}"}
    
    def parse_vt_response(self, ioc: str, ioc_type: str, data: Dict) -> Dict[str, Any]:
        """Parse VirusTotal API response"""
        try:
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            result = {
                "ioc": ioc,
                "type": ioc_type,
                "status": "analyzed",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "clean": stats.get("harmless", 0) + stats.get("undetected", 0),
                "total_engines": sum(stats.values()) if stats else 0,
                "scan_date": attributes.get("last_analysis_date"),
                "reputation": attributes.get("reputation", 0)
            }
            
            # Add type-specific info
            if ioc_type == "file":
                result["file_type"] = attributes.get("type_description", "Unknown")
                result["size"] = attributes.get("size", 0)
                result["names"] = attributes.get("names", [])[:5]
            
            elif ioc_type in ["domain", "ip_address"]:
                result["country"] = attributes.get("country", "Unknown")
                result["asn"] = attributes.get("asn", "Unknown")
            
            return result
            
        except Exception as e:
            return {"ioc": ioc, "type": ioc_type, "error": f"Parse error: {str(e)}"}
    
    def scan_multiple_iocs(self, iocs: List[str], delay: float = 0.25) -> List[Dict[str, Any]]:
        """Scan multiple IOCs with caching, retry logic, and rate limiting"""
        results = []
        cache_hits = 0
        api_calls = 0
        skipped = 0
        errors = 0
        
        for ioc in iocs:
            if ioc.strip():
                result = self.scan_ioc(ioc.strip())
                
                if result.get("type") == "skip" or result.get("skip"):
                    skipped += 1
                    continue
                
                results.append(result)
                
                if result.get("cache_hit"):
                    cache_hits += 1
                elif result.get("error"):
                    errors += 1
                else:
                    api_calls += 1
                    time.sleep(delay)  # Rate limiting between successful calls
        
        print(f"{Fore.LIGHTBLUE_EX}Scan stats: {cache_hits} cached, {api_calls} API calls, {errors} errors, {skipped} skipped")
        return results
    
    def cleanup_cache(self) -> int:
        """Clean expired cache entries"""
        return self.cache.cleanup_expired()
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return self.cache.get_stats()