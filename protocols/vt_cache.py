import json
import sqlite3
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from pathlib import Path

class VTCache:
    def __init__(self, cache_file: str = "vt_cache.db", ttl_hours: int = 24):
        self.cache_file = cache_file
        self.ttl_hours = ttl_hours
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database for caching"""
        conn = sqlite3.connect(self.cache_file)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vt_cache (
                ioc TEXT PRIMARY KEY,
                ioc_type TEXT,
                result TEXT,
                cached_at TIMESTAMP,
                expires_at TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_expires_at ON vt_cache(expires_at)
        """)
        conn.commit()
        conn.close()
    
    def get(self, ioc: str) -> Optional[Dict[str, Any]]:
        """Get cached result for IOC"""
        conn = sqlite3.connect(self.cache_file)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT result FROM vt_cache 
            WHERE ioc = ? AND expires_at > ?
        """, (ioc, datetime.now()))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return json.loads(row[0])
        return None
    
    def set(self, ioc: str, ioc_type: str, result: Dict[str, Any]):
        """Cache result for IOC"""
        conn = sqlite3.connect(self.cache_file)
        
        expires_at = datetime.now() + timedelta(hours=self.ttl_hours)
        
        conn.execute("""
            INSERT OR REPLACE INTO vt_cache 
            (ioc, ioc_type, result, cached_at, expires_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            ioc, 
            ioc_type, 
            json.dumps(result), 
            datetime.now(), 
            expires_at
        ))
        
        conn.commit()
        conn.close()
    
    def cleanup_expired(self):
        """Remove expired cache entries"""
        conn = sqlite3.connect(self.cache_file)
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM vt_cache WHERE expires_at < ?", (datetime.now(),))
        deleted = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        return deleted
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        conn = sqlite3.connect(self.cache_file)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM vt_cache")
        total = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM vt_cache WHERE expires_at > ?", (datetime.now(),))
        valid = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM vt_cache WHERE expires_at <= ?", (datetime.now(),))
        expired = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "total_entries": total,
            "valid_entries": valid,
            "expired_entries": expired
        }