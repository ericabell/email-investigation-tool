"""Network traffic monitoring for the email investigation tool."""

import os
import time
import threading
import psutil
import socket
from typing import List, Dict, Optional, Set
from dataclasses import dataclass
from pathlib import Path
import logging

@dataclass
class NetworkConnection:
    """Represents a network connection."""
    timestamp: float
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    protocol: str
    status: str
    process_name: str
    
    def __str__(self) -> str:
        return (f"{time.strftime('%H:%M:%S', time.localtime(self.timestamp))} "
                f"{self.protocol} {self.local_addr}:{self.local_port} -> "
                f"{self.remote_addr}:{self.remote_port} [{self.status}]")

@dataclass
class NetworkStats:
    """Network monitoring statistics."""
    total_connections: int = 0
    smtp_connections: int = 0
    imap_connections: int = 0
    dns_queries: int = 0
    other_connections: int = 0
    suspicious_connections: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0

class NetworkMonitor:
    """Monitors network traffic for the current process."""
    
    def __init__(self, log_file: Optional[str] = None):
        self.process = psutil.Process(os.getpid())
        self.monitoring = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.connections: List[NetworkConnection] = []
        self.stats = NetworkStats()
        self.known_connections: Set[str] = set()
        
        # Setup logging
        if log_file is None:
            log_dir = Path("logs")
            log_dir.mkdir(exist_ok=True)
            log_file = log_dir / f"network_traffic_{int(time.time())}.log"
        
        self.logger = logging.getLogger("network_monitor")
        self.logger.setLevel(logging.INFO)
        
        # Remove existing handlers
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
        
        # File handler for network logs
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        ))
        self.logger.addHandler(file_handler)
        
        self.log_file_path = str(log_file)
        
        # Suspicious patterns to watch for
        self.suspicious_patterns = [
            "telemetry",
            "analytics", 
            "tracking",
            "metrics",
            "stats",
            "api.github.com",  # Except legitimate API calls
            "pypi.org",       # Package index (should not happen during runtime)
        ]
        
        # Expected email/network services
        self.expected_services = {
            25: "SMTP",
            587: "SMTP-STARTTLS", 
            465: "SMTPS",
            993: "IMAPS",
            143: "IMAP",
            53: "DNS",
            80: "HTTP",
            443: "HTTPS"
        }
    
    def start_monitoring(self):
        """Start network monitoring in background thread."""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        self.logger.info("=== NETWORK MONITORING STARTED ===")
        self.logger.info(f"Process PID: {self.process.pid}")
        self.logger.info(f"Process Name: {self.process.name()}")
        self.logger.info("Monitoring all network connections for this process...")
    
    def stop_monitoring(self):
        """Stop network monitoring."""
        if not self.monitoring:
            return
        
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1.0)
        
        self.logger.info("=== NETWORK MONITORING STOPPED ===")
        self.logger.info(f"Total connections monitored: {self.stats.total_connections}")
        self.logger.info(f"SMTP connections: {self.stats.smtp_connections}")
        self.logger.info(f"IMAP connections: {self.stats.imap_connections}")
        self.logger.info(f"DNS queries: {self.stats.dns_queries}")
        self.logger.info(f"Suspicious connections: {self.stats.suspicious_connections}")
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        last_check = time.time()
        
        while self.monitoring:
            try:
                current_time = time.time()
                
                # Get current connections for our process
                connections = self.process.connections(kind='inet')
                
                for conn in connections:
                    if conn.status == psutil.CONN_NONE:
                        continue
                    
                    # Create connection identifier
                    conn_id = f"{conn.laddr}:{conn.raddr}:{conn.status}"
                    
                    # Skip if we've already logged this connection
                    if conn_id in self.known_connections:
                        continue
                    
                    self.known_connections.add(conn_id)
                    
                    # Extract connection details
                    local_addr = conn.laddr.ip if conn.laddr else "unknown"
                    local_port = conn.laddr.port if conn.laddr else 0
                    remote_addr = conn.raddr.ip if conn.raddr else "unknown"
                    remote_port = conn.raddr.port if conn.raddr else 0
                    
                    # Determine protocol
                    protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                    
                    # Create connection record
                    net_conn = NetworkConnection(
                        timestamp=current_time,
                        local_addr=local_addr,
                        local_port=local_port,
                        remote_addr=remote_addr,
                        remote_port=remote_port,
                        protocol=protocol,
                        status=conn.status,
                        process_name=self.process.name()
                    )
                    
                    self.connections.append(net_conn)
                    self.stats.total_connections += 1
                    
                    # Categorize connection
                    self._categorize_connection(net_conn, remote_port)
                    
                    # Log the connection
                    self._log_connection(net_conn)
                
                # Sleep briefly
                time.sleep(0.5)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(1.0)
    
    def _categorize_connection(self, conn: NetworkConnection, remote_port: int):
        """Categorize the type of connection."""
        if remote_port in [25, 587, 465, 2525]:
            self.stats.smtp_connections += 1
            self.logger.info(f"SMTP CONNECTION: {conn}")
        elif remote_port in [993, 143]:
            self.stats.imap_connections += 1
            self.logger.info(f"IMAP CONNECTION: {conn}")
        elif remote_port == 53:
            self.stats.dns_queries += 1
            self.logger.info(f"DNS QUERY: {conn}")
        else:
            self.stats.other_connections += 1
            
            # Check for suspicious connections
            if self._is_suspicious_connection(conn):
                self.stats.suspicious_connections += 1
                self.logger.warning(f"SUSPICIOUS CONNECTION: {conn}")
            else:
                self.logger.info(f"OTHER CONNECTION: {conn}")
    
    def _is_suspicious_connection(self, conn: NetworkConnection) -> bool:
        """Check if a connection looks suspicious."""
        # Check remote address for suspicious patterns
        remote_lower = conn.remote_addr.lower()
        
        for pattern in self.suspicious_patterns:
            if pattern in remote_lower:
                return True
        
        # Check for unexpected ports
        if conn.remote_port not in self.expected_services:
            # High ports might be suspicious for unexpected outbound connections
            if conn.remote_port > 8000 and conn.remote_port != 8080 and conn.remote_port != 8443:
                return True
        
        return False
    
    def _log_connection(self, conn: NetworkConnection):
        """Log a connection with detailed information."""
        service_name = self.expected_services.get(conn.remote_port, "UNKNOWN")
        
        # Try to resolve hostname
        hostname = "unknown"
        try:
            hostname = socket.gethostbyaddr(conn.remote_addr)[0]
        except (socket.herror, socket.gaierror):
            pass
        
        log_msg = (f"CONNECTION: {conn.protocol} "
                  f"{conn.local_addr}:{conn.local_port} -> "
                  f"{conn.remote_addr}:{conn.remote_port} "
                  f"[{conn.status}] Service: {service_name}")
        
        if hostname != "unknown":
            log_msg += f" Hostname: {hostname}"
        
        self.logger.info(log_msg)
    
    def get_recent_connections(self, limit: int = 10) -> List[NetworkConnection]:
        """Get the most recent network connections."""
        return self.connections[-limit:] if self.connections else []
    
    def get_smtp_connections(self) -> List[NetworkConnection]:
        """Get all SMTP connections."""
        return [conn for conn in self.connections 
                if conn.remote_port in [25, 587, 465, 2525]]
    
    def get_imap_connections(self) -> List[NetworkConnection]:
        """Get all IMAP connections."""
        return [conn for conn in self.connections 
                if conn.remote_port in [993, 143]]
    
    def get_suspicious_connections(self) -> List[NetworkConnection]:
        """Get all connections flagged as suspicious."""
        suspicious = []
        for conn in self.connections:
            if self._is_suspicious_connection(conn):
                suspicious.append(conn)
        return suspicious
    
    def get_stats_summary(self) -> str:
        """Get a summary of network monitoring statistics."""
        return (f"Network Monitor: {self.stats.total_connections} total, "
                f"{self.stats.smtp_connections} SMTP, "
                f"{self.stats.imap_connections} IMAP, "
                f"{self.stats.suspicious_connections} suspicious")
    
    def export_report(self, output_file: Optional[str] = None) -> str:
        """Export a detailed network monitoring report."""
        if output_file is None:
            log_dir = Path("logs")
            log_dir.mkdir(exist_ok=True)
            output_file = log_dir / f"network_report_{int(time.time())}.txt"
        
        with open(output_file, 'w') as f:
            f.write("=== EMAIL INVESTIGATION TOOL - NETWORK MONITORING REPORT ===\n")
            f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Process PID: {self.process.pid}\n")
            f.write(f"Log File: {self.log_file_path}\n\n")
            
            f.write("=== STATISTICS ===\n")
            f.write(f"Total connections: {self.stats.total_connections}\n")
            f.write(f"SMTP connections: {self.stats.smtp_connections}\n")
            f.write(f"IMAP connections: {self.stats.imap_connections}\n")
            f.write(f"DNS queries: {self.stats.dns_queries}\n")
            f.write(f"Other connections: {self.stats.other_connections}\n")
            f.write(f"Suspicious connections: {self.stats.suspicious_connections}\n\n")
            
            f.write("=== EMAIL SERVER CONNECTIONS ===\n")
            email_conns = self.get_smtp_connections() + self.get_imap_connections()
            for conn in email_conns:
                f.write(f"{conn}\n")
            
            if not email_conns:
                f.write("No email server connections detected.\n")
            
            f.write("\n=== SUSPICIOUS CONNECTIONS ===\n")
            suspicious = self.get_suspicious_connections()
            for conn in suspicious:
                f.write(f"{conn}\n")
            
            if not suspicious:
                f.write("No suspicious connections detected.\n")
            
            f.write("\n=== ALL CONNECTIONS ===\n")
            for conn in self.connections:
                f.write(f"{conn}\n")
        
        return str(output_file)