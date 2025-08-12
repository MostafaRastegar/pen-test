"""
Performance Optimization Module - src/utils/performance.py

Provides caching, memory optimization, and network request pooling
"""

import json
import hashlib
import psutil
import threading
import time
from typing import Any, Dict, Optional, List, Callable
from pathlib import Path
from datetime import datetime, timedelta
from collections import OrderedDict
from dataclasses import dataclass
import pickle
import gzip
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from src.utils.logger import log_info, log_warning, log_error, log_debug


@dataclass
class CacheEntry:
    """Cache entry with metadata"""

    data: Any
    timestamp: datetime
    ttl: int  # Time to live in seconds
    size: int  # Size in bytes
    access_count: int = 0
    last_access: datetime = None

    def is_expired(self) -> bool:
        """Check if cache entry is expired"""
        if self.ttl == 0:  # Never expires
            return False
        return datetime.now() - self.timestamp > timedelta(seconds=self.ttl)

    def update_access(self):
        """Update access statistics"""
        self.access_count += 1
        self.last_access = datetime.now()


class ScanResultCache:
    """
    LRU Cache for scan results with TTL and memory management
    """

    def __init__(
        self,
        max_size: int = 100,
        default_ttl: int = 3600,
        cache_dir: Optional[Path] = None,
    ):
        """
        Initialize cache

        Args:
            max_size: Maximum number of cache entries
            default_ttl: Default time to live in seconds
            cache_dir: Directory for persistent cache (None for memory-only)
        """
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cache_dir = cache_dir
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.RLock()
        self._stats = {"hits": 0, "misses": 0, "evictions": 0, "memory_usage": 0}

        # Create cache directory if needed
        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            self._load_persistent_cache()

    def _generate_key(self, target: str, scan_type: str, options: Dict) -> str:
        """Generate cache key from scan parameters"""
        key_data = {
            "target": target,
            "scan_type": scan_type,
            "options": sorted(options.items()) if options else [],
        }
        key_string = json.dumps(key_data, sort_keys=True)
        return hashlib.sha256(key_string.encode()).hexdigest()[:16]

    def get(self, target: str, scan_type: str, options: Dict = None) -> Optional[Any]:
        """
        Get cached scan result

        Args:
            target: Scan target
            scan_type: Type of scan
            options: Scan options

        Returns:
            Cached result or None if not found/expired
        """
        options = options or {}
        key = self._generate_key(target, scan_type, options)

        with self._lock:
            if key not in self._cache:
                self._stats["misses"] += 1
                return None

            entry = self._cache[key]

            # Check if expired
            if entry.is_expired():
                log_debug(f"Cache entry expired for {target}:{scan_type}")
                del self._cache[key]
                self._stats["misses"] += 1
                return None

            # Update access and move to end (LRU)
            entry.update_access()
            self._cache.move_to_end(key)
            self._stats["hits"] += 1

            log_debug(f"Cache hit for {target}:{scan_type}")
            return entry.data

    def set(
        self,
        target: str,
        scan_type: str,
        result: Any,
        options: Dict = None,
        ttl: Optional[int] = None,
    ):
        """
        Cache scan result

        Args:
            target: Scan target
            scan_type: Type of scan
            result: Scan result to cache
            options: Scan options
            ttl: Time to live (uses default if None)
        """
        options = options or {}
        ttl = ttl if ttl is not None else self.default_ttl
        key = self._generate_key(target, scan_type, options)

        # Calculate size
        size = self._calculate_size(result)

        with self._lock:
            # Remove existing entry if present
            if key in self._cache:
                old_entry = self._cache[key]
                self._stats["memory_usage"] -= old_entry.size
                del self._cache[key]

            # Create new entry
            entry = CacheEntry(
                data=result, timestamp=datetime.now(), ttl=ttl, size=size
            )

            # Add to cache
            self._cache[key] = entry
            self._stats["memory_usage"] += size

            # Evict if necessary
            self._evict_if_necessary()

            # Save to persistent cache if enabled
            if self.cache_dir:
                self._save_entry_to_disk(key, entry)

            log_debug(
                f"Cached result for {target}:{scan_type} (size: {size} bytes, TTL: {ttl}s)"
            )

    def _calculate_size(self, obj: Any) -> int:
        """Calculate approximate size of object in bytes"""
        try:
            return len(pickle.dumps(obj))
        except Exception:
            # Fallback estimation
            if isinstance(obj, (str, bytes)):
                return len(obj)
            elif isinstance(obj, (list, tuple)):
                return sum(self._calculate_size(item) for item in obj)
            elif isinstance(obj, dict):
                return sum(
                    self._calculate_size(k) + self._calculate_size(v)
                    for k, v in obj.items()
                )
            else:
                return 1024  # Default estimate

    def _evict_if_necessary(self):
        """Evict least recently used entries if cache is full"""
        while len(self._cache) > self.max_size:
            # Remove oldest entry
            key, entry = self._cache.popitem(last=False)
            self._stats["memory_usage"] -= entry.size
            self._stats["evictions"] += 1

            # Remove from disk cache
            if self.cache_dir:
                disk_file = self.cache_dir / f"{key}.cache"
                if disk_file.exists():
                    disk_file.unlink()

            log_debug(f"Evicted cache entry: {key}")

    def _load_persistent_cache(self):
        """Load cache from disk"""
        if not self.cache_dir or not self.cache_dir.exists():
            return

        loaded_count = 0
        for cache_file in self.cache_dir.glob("*.cache"):
            try:
                key = cache_file.stem
                with gzip.open(cache_file, "rb") as f:
                    entry = pickle.load(f)

                # Check if still valid
                if not entry.is_expired():
                    self._cache[key] = entry
                    self._stats["memory_usage"] += entry.size
                    loaded_count += 1
                else:
                    cache_file.unlink()  # Remove expired entry

            except Exception as e:
                log_warning(f"Failed to load cache entry {cache_file}: {e}")
                cache_file.unlink()

        if loaded_count > 0:
            log_info(f"Loaded {loaded_count} cached entries from disk")

    def _save_entry_to_disk(self, key: str, entry: CacheEntry):
        """Save cache entry to disk"""
        try:
            cache_file = self.cache_dir / f"{key}.cache"
            with gzip.open(cache_file, "wb") as f:
                pickle.dump(entry, f)
        except Exception as e:
            log_warning(f"Failed to save cache entry to disk: {e}")

    def clear(self):
        """Clear all cache entries"""
        with self._lock:
            self._cache.clear()
            self._stats = {"hits": 0, "misses": 0, "evictions": 0, "memory_usage": 0}

            # Clear disk cache
            if self.cache_dir and self.cache_dir.exists():
                for cache_file in self.cache_dir.glob("*.cache"):
                    cache_file.unlink()

        log_info("Cache cleared")

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._lock:
            total_requests = self._stats["hits"] + self._stats["misses"]
            hit_rate = (
                (self._stats["hits"] / total_requests * 100)
                if total_requests > 0
                else 0
            )

            return {
                **self._stats,
                "entries": len(self._cache),
                "hit_rate": round(hit_rate, 2),
                "memory_usage_mb": round(self._stats["memory_usage"] / 1024 / 1024, 2),
            }

    def cleanup_expired(self):
        """Remove expired entries"""
        with self._lock:
            expired_keys = [
                key for key, entry in self._cache.items() if entry.is_expired()
            ]

            for key in expired_keys:
                entry = self._cache[key]
                self._stats["memory_usage"] -= entry.size
                del self._cache[key]

                # Remove from disk
                if self.cache_dir:
                    disk_file = self.cache_dir / f"{key}.cache"
                    if disk_file.exists():
                        disk_file.unlink()

            if expired_keys:
                log_info(f"Cleaned up {len(expired_keys)} expired cache entries")


class MemoryMonitor:
    """
    Monitor and optimize memory usage during scans
    """

    def __init__(
        self, warning_threshold: float = 80.0, critical_threshold: float = 90.0
    ):
        """
        Initialize memory monitor

        Args:
            warning_threshold: Memory usage percentage to trigger warning
            critical_threshold: Memory usage percentage to trigger cleanup
        """
        self.warning_threshold = warning_threshold
        self.critical_threshold = critical_threshold
        self._monitoring = False
        self._monitor_thread = None

    def get_memory_usage(self) -> Dict[str, Any]:
        """Get current memory usage statistics"""
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            system_memory = psutil.virtual_memory()

            return {
                "process_memory_mb": round(memory_info.rss / 1024 / 1024, 2),
                "process_memory_percent": round(process.memory_percent(), 2),
                "system_memory_total_gb": round(
                    system_memory.total / 1024 / 1024 / 1024, 2
                ),
                "system_memory_available_gb": round(
                    system_memory.available / 1024 / 1024 / 1024, 2
                ),
                "system_memory_percent": system_memory.percent,
            }
        except Exception as e:
            log_warning(f"Failed to get memory usage: {e}")
            return {}

    def check_memory_pressure(self) -> str:
        """
        Check current memory pressure level

        Returns:
            Memory pressure level: 'normal', 'warning', 'critical'
        """
        usage = self.get_memory_usage()
        system_percent = usage.get("system_memory_percent", 0)

        if system_percent >= self.critical_threshold:
            return "critical"
        elif system_percent >= self.warning_threshold:
            return "warning"
        else:
            return "normal"

    def start_monitoring(self, interval: int = 30, callback: Optional[Callable] = None):
        """
        Start background memory monitoring

        Args:
            interval: Monitoring interval in seconds
            callback: Optional callback function for memory events
        """
        if self._monitoring:
            return

        self._monitoring = True

        def monitor_loop():
            while self._monitoring:
                try:
                    pressure = self.check_memory_pressure()
                    usage = self.get_memory_usage()

                    if pressure == "critical":
                        log_warning(
                            f"Critical memory usage: {usage.get('system_memory_percent', 0):.1f}%"
                        )
                        if callback:
                            callback("critical", usage)
                    elif pressure == "warning":
                        log_info(
                            f"High memory usage: {usage.get('system_memory_percent', 0):.1f}%"
                        )
                        if callback:
                            callback("warning", usage)

                    time.sleep(interval)

                except Exception as e:
                    log_error(f"Memory monitoring error: {e}")
                    time.sleep(interval)

        self._monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self._monitor_thread.start()
        log_info("Memory monitoring started")

    def stop_monitoring(self):
        """Stop background memory monitoring"""
        self._monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
        log_info("Memory monitoring stopped")


class NetworkOptimizer:
    """
    Optimize network requests with connection pooling and retry logic
    """

    def __init__(
        self, pool_connections: int = 10, pool_maxsize: int = 20, max_retries: int = 3
    ):
        """
        Initialize network optimizer

        Args:
            pool_connections: Number of connection pools
            pool_maxsize: Maximum connections per pool
            max_retries: Maximum number of retries
        """
        self.session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
        )

        # Configure adapters with connection pooling
        adapter = HTTPAdapter(
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
            max_retries=retry_strategy,
        )

        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Set default headers
        self.session.headers.update(
            {
                "User-Agent": "Auto-Pentest-Framework/0.9.1",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
            }
        )

        log_info(
            f"Network optimizer initialized (pools: {pool_connections}, max_size: {pool_maxsize})"
        )

    def get(self, url: str, timeout: int = 30, **kwargs) -> requests.Response:
        """Make optimized GET request"""
        return self.session.get(url, timeout=timeout, **kwargs)

    def post(self, url: str, timeout: int = 30, **kwargs) -> requests.Response:
        """Make optimized POST request"""
        return self.session.post(url, timeout=timeout, **kwargs)

    def head(self, url: str, timeout: int = 30, **kwargs) -> requests.Response:
        """Make optimized HEAD request"""
        return self.session.head(url, timeout=timeout, **kwargs)

    def close(self):
        """Close session and cleanup connections"""
        self.session.close()
        log_info("Network optimizer closed")


class PerformanceManager:
    """
    Centralized performance management for the scanning framework
    """

    def __init__(
        self,
        cache_size: int = 100,
        cache_ttl: int = 3600,
        cache_dir: Optional[Path] = None,
        enable_memory_monitoring: bool = True,
    ):
        """
        Initialize performance manager

        Args:
            cache_size: Maximum cache entries
            cache_ttl: Default cache TTL in seconds
            cache_dir: Directory for persistent cache
            enable_memory_monitoring: Enable background memory monitoring
        """
        self.cache = ScanResultCache(
            max_size=cache_size, default_ttl=cache_ttl, cache_dir=cache_dir
        )

        self.memory_monitor = MemoryMonitor()
        self.network_optimizer = NetworkOptimizer()

        if enable_memory_monitoring:
            self.memory_monitor.start_monitoring(callback=self._handle_memory_pressure)

        log_info("Performance manager initialized")

    def _handle_memory_pressure(self, level: str, usage: Dict[str, Any]):
        """Handle memory pressure events"""
        if level == "critical":
            log_warning("Critical memory pressure detected - cleaning up cache")
            self.cache.cleanup_expired()
            # Could also trigger garbage collection here
            import gc

            gc.collect()
        elif level == "warning":
            log_info("Memory pressure warning - consider optimizing scan parameters")

    def get_performance_stats(self) -> Dict[str, Any]:
        """Get comprehensive performance statistics"""
        return {
            "cache": self.cache.get_stats(),
            "memory": self.memory_monitor.get_memory_usage(),
            "memory_pressure": self.memory_monitor.check_memory_pressure(),
            "timestamp": datetime.now().isoformat(),
        }

    def cleanup(self):
        """Cleanup resources"""
        self.memory_monitor.stop_monitoring()
        self.network_optimizer.close()
        log_info("Performance manager cleanup completed")

    def optimize_for_large_scan(self):
        """Optimize settings for large scan operations"""
        # Reduce cache size for large scans
        self.cache.max_size = min(50, self.cache.max_size)

        # More aggressive cache cleanup
        self.cache.cleanup_expired()

        # Force garbage collection
        import gc

        gc.collect()

        log_info("Optimized for large scan operation")

    def optimize_for_speed(self):
        """Optimize settings for speed"""
        # Increase cache size for speed
        self.cache.max_size = max(200, self.cache.max_size)

        # Longer TTL for faster subsequent scans
        self.cache.default_ttl = 7200  # 2 hours

        log_info("Optimized for speed")


# Global performance manager instance
_performance_manager: Optional[PerformanceManager] = None


def get_performance_manager() -> PerformanceManager:
    """Get global performance manager instance"""
    global _performance_manager
    if _performance_manager is None:
        from config.settings import OUTPUT_DIR

        cache_dir = OUTPUT_DIR / "cache"
        _performance_manager = PerformanceManager(cache_dir=cache_dir)
    return _performance_manager


def cleanup_performance_manager():
    """Cleanup global performance manager"""
    global _performance_manager
    if _performance_manager:
        _performance_manager.cleanup()
        _performance_manager = None


# Decorator for caching scan results
def cache_scan_result(scan_type: str, ttl: Optional[int] = None):
    """
    Decorator to automatically cache scan results

    Args:
        scan_type: Type of scan for cache key generation
        ttl: Time to live for cache entry
    """

    def decorator(func):
        def wrapper(self, target: str, *args, **kwargs):
            pm = get_performance_manager()

            # Try to get from cache first
            options = {
                "args": args,
                "kwargs": {
                    k: v
                    for k, v in kwargs.items()
                    if isinstance(v, (str, int, float, bool, list, dict))
                },
            }

            cached_result = pm.cache.get(target, scan_type, options)
            if cached_result is not None:
                log_info(f"Using cached result for {scan_type} scan of {target}")
                return cached_result

            # Execute scan
            result = func(self, target, *args, **kwargs)

            # Cache result if successful
            if (
                result
                and hasattr(result, "status")
                and result.status.name == "COMPLETED"
            ):
                pm.cache.set(target, scan_type, result, options, ttl)

            return result

        return wrapper

    return decorator
