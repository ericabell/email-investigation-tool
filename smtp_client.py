"""Enhanced SMTP client with comprehensive debugging and ISP interference detection."""

import smtplib
import ssl
import socket
import time
import logging
from typing import Optional, List, Dict, Any, Callable
from dataclasses import dataclass
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import os

@dataclass
class SMTPStats:
    """Statistics for SMTP operations."""
    connection_time: float = 0.0
    auth_time: float = 0.0
    send_time: float = 0.0
    total_time: float = 0.0
    bytes_sent: int = 0
    chunks_sent: int = 0
    errors: List[str] = None
    warnings: List[str] = None
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.warnings is None:
            self.warnings = []

@dataclass
class SMTPLogEntry:
    """Single SMTP protocol log entry."""
    timestamp: float
    direction: str  # '→' for outgoing, '←' for incoming
    data: str
    is_error: bool = False
    timing_info: Optional[str] = None

class DebugSMTP(smtplib.SMTP):
    """Enhanced SMTP client with detailed logging and debugging."""
    
    def __init__(self, host='', port=0, local_hostname=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, 
                 source_address=None, log_callback: Optional[Callable[[SMTPLogEntry], None]] = None):
        self.log_callback = log_callback
        self.protocol_log: List[SMTPLogEntry] = []
        self.stats = SMTPStats()
        self.connection_start_time = 0.0
        self.last_command_time = 0.0
        
        super().__init__(host, port, local_hostname, timeout, source_address)
    
    def _log_entry(self, direction: str, data: str, is_error: bool = False, timing_info: Optional[str] = None):
        """Log a protocol entry."""
        entry = SMTPLogEntry(
            timestamp=time.time(),
            direction=direction,
            data=data.strip(),
            is_error=is_error,
            timing_info=timing_info
        )
        self.protocol_log.append(entry)
        
        if self.log_callback:
            self.log_callback(entry)
    
    def connect(self, host='localhost', port=0):
        """Connect with timing and detailed logging."""
        self.connection_start_time = time.time()
        self._log_entry("→", f"Connecting to {host}:{port}...")
        
        try:
            result = super().connect(host, port)
            self.stats.connection_time = time.time() - self.connection_start_time
            self._log_entry("←", f"Connected successfully", timing_info=f"{self.stats.connection_time:.3f}s")
            return result
        except Exception as e:
            self.stats.errors.append(f"Connection failed: {str(e)}")
            self._log_entry("←", f"Connection failed: {str(e)}", is_error=True)
            raise
    
    def send(self, s):
        """Override send to log all outgoing data."""
        if isinstance(s, str):
            s = s.encode('ascii')
        
        # Log the command (sanitize passwords)
        log_data = s.decode('ascii', errors='replace')
        if 'AUTH PLAIN' in log_data or 'AUTH LOGIN' in log_data:
            log_data = log_data.split()[0] + " [CREDENTIALS HIDDEN]"
        
        self.last_command_time = time.time()
        self._log_entry("→", log_data)
        
        try:
            result = super().send(s)
            self.stats.bytes_sent += len(s)
            return result
        except Exception as e:
            self.stats.errors.append(f"Send failed: {str(e)}")
            self._log_entry("←", f"Send failed: {str(e)}", is_error=True)
            raise
    
    def getreply(self):
        """Override getreply to log all incoming data."""
        try:
            code, msg = super().getreply()
            response_time = time.time() - self.last_command_time
            timing_info = f"{response_time:.3f}s" if response_time > 0.001 else None
            
            full_response = f"{code} {msg.decode('ascii', errors='replace') if isinstance(msg, bytes) else msg}"
            self._log_entry("←", full_response, timing_info=timing_info)
            
            # Check for potential ISP interference indicators
            if code >= 400:
                if "timeout" in msg.lower() or "connection" in msg.lower():
                    self.stats.warnings.append("Potential ISP connection interference detected")
                elif "size" in msg.lower() or "limit" in msg.lower():
                    self.stats.warnings.append("Server size limit reached")
            
            return code, msg
        except Exception as e:
            self.stats.errors.append(f"Response failed: {str(e)}")
            self._log_entry("←", f"Response failed: {str(e)}", is_error=True)
            raise
    
    def starttls(self, keyfile=None, certfile=None, context=None):
        """Start TLS with enhanced logging."""
        self._log_entry("→", "STARTTLS")
        tls_start = time.time()
        
        try:
            result = super().starttls(keyfile, certfile, context)
            tls_time = time.time() - tls_start
            
            # Get TLS information
            if hasattr(self.sock, 'cipher'):
                cipher_info = self.sock.cipher()
                if cipher_info:
                    cipher_name = cipher_info[0] if cipher_info else "Unknown"
                    tls_version = cipher_info[1] if len(cipher_info) > 1 else "Unknown"
                    self._log_entry("←", f"TLS established: {tls_version}, {cipher_name}", 
                                  timing_info=f"{tls_time:.3f}s")
                else:
                    self._log_entry("←", "TLS established", timing_info=f"{tls_time:.3f}s")
            else:
                self._log_entry("←", "TLS established", timing_info=f"{tls_time:.3f}s")
                
            return result
        except Exception as e:
            self.stats.errors.append(f"TLS failed: {str(e)}")
            self._log_entry("←", f"TLS failed: {str(e)}", is_error=True)
            raise
    
    def login(self, user, password):
        """Login with timing."""
        auth_start = time.time()
        try:
            result = super().login(user, password)
            self.stats.auth_time = time.time() - auth_start
            self._log_entry("←", f"Authentication successful", timing_info=f"{self.stats.auth_time:.3f}s")
            return result
        except Exception as e:
            self.stats.errors.append(f"Authentication failed: {str(e)}")
            self._log_entry("←", f"Authentication failed: {str(e)}", is_error=True)
            raise
    
    def data(self, msg):
        """Send email data with chunk monitoring."""
        send_start = time.time()
        self._log_entry("→", "DATA")
        
        try:
            # Monitor chunked sending for large messages
            if len(msg) > 1024 * 1024:  # 1MB threshold
                self._log_entry("→", f"Large message detected: {len(msg):,} bytes")
                chunk_size = 8192
                total_chunks = (len(msg) + chunk_size - 1) // chunk_size
                self.stats.chunks_sent = total_chunks
                self._log_entry("→", f"Will send in {total_chunks} chunks of {chunk_size} bytes")
            
            result = super().data(msg)
            
            self.stats.send_time = time.time() - send_start
            self._log_entry("←", f"Message sent successfully", timing_info=f"{self.stats.send_time:.3f}s")
            
            return result
        except Exception as e:
            self.stats.errors.append(f"Data send failed: {str(e)}")
            self._log_entry("←", f"Data send failed: {str(e)}", is_error=True)
            raise
    
    def quit(self):
        """Quit with timing summary."""
        self.stats.total_time = time.time() - self.connection_start_time
        self._log_entry("→", "QUIT")
        try:
            result = super().quit()
            self._log_entry("←", f"Session ended. Total time: {self.stats.total_time:.3f}s")
            return result
        except Exception as e:
            self._log_entry("←", f"Quit failed: {str(e)}", is_error=True)
            raise

class SMTPDebugger:
    """High-level SMTP debugging interface."""
    
    def __init__(self, host: str, port: int, use_tls: bool = True, 
                 log_callback: Optional[Callable[[SMTPLogEntry], None]] = None):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.log_callback = log_callback
        self.smtp: Optional[DebugSMTP] = None
    
    def connect_and_auth(self, username: str, password: str) -> SMTPStats:
        """Connect and authenticate, returning detailed statistics."""
        
        try:
            # For port 465, use SMTP_SSL. For other ports, use SMTP with optional STARTTLS
            if self.port == 465:
                # SMTPS - SSL from the start
                class DebugSMTP_SSL(smtplib.SMTP_SSL):
                    def __init__(self, host='', port=0, local_hostname=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
                        self.log_callback = None
                        self.protocol_log = []
                        self.stats = SMTPStats()
                        self.connection_start_time = 0.0
                        self.last_command_time = 0.0
                        super().__init__(host, port, local_hostname, timeout=timeout)
                    
                    def _log_entry(self, direction, data, is_error=False, timing_info=None):
                        entry = SMTPLogEntry(
                            timestamp=time.time(),
                            direction=direction,
                            data=data.strip(),
                            is_error=is_error,
                            timing_info=timing_info
                        )
                        self.protocol_log.append(entry)
                        if self.log_callback:
                            self.log_callback(entry)
                    
                    def connect(self, host='localhost', port=0):
                        self.connection_start_time = time.time()
                        self._log_entry("→", f"Connecting to {host}:{port} (SSL)...")
                        try:
                            result = super().connect(host, port)
                            self.stats.connection_time = time.time() - self.connection_start_time
                            self._log_entry("←", f"SSL connection established", timing_info=f"{self.stats.connection_time:.3f}s")
                            return result
                        except Exception as e:
                            self.stats.errors.append(f"SSL connection failed: {str(e)}")
                            self._log_entry("←", f"SSL connection failed: {str(e)}", is_error=True)
                            raise
                    
                    def send(self, s):
                        if isinstance(s, str):
                            s = s.encode('ascii')
                        log_data = s.decode('ascii', errors='replace')
                        if 'AUTH PLAIN' in log_data or 'AUTH LOGIN' in log_data:
                            log_data = log_data.split()[0] + " [CREDENTIALS HIDDEN]"
                        self.last_command_time = time.time()
                        self._log_entry("→", log_data)
                        try:
                            result = super().send(s)
                            self.stats.bytes_sent += len(s)
                            return result
                        except Exception as e:
                            self.stats.errors.append(f"Send failed: {str(e)}")
                            self._log_entry("←", f"Send failed: {str(e)}", is_error=True)
                            raise
                    
                    def getreply(self):
                        try:
                            code, msg = super().getreply()
                            response_time = time.time() - self.last_command_time
                            timing_info = f"{response_time:.3f}s" if response_time > 0.001 else None
                            full_response = f"{code} {msg.decode('ascii', errors='replace') if isinstance(msg, bytes) else msg}"
                            self._log_entry("←", full_response, timing_info=timing_info)
                            return code, msg
                        except Exception as e:
                            self.stats.errors.append(f"Response failed: {str(e)}")
                            self._log_entry("←", f"Response failed: {str(e)}", is_error=True)
                            raise
                    
                    def login(self, user, password):
                        auth_start = time.time()
                        try:
                            result = super().login(user, password)
                            self.stats.auth_time = time.time() - auth_start
                            self._log_entry("←", f"Authentication successful", timing_info=f"{self.stats.auth_time:.3f}s")
                            return result
                        except Exception as e:
                            self.stats.errors.append(f"Authentication failed: {str(e)}")
                            self._log_entry("←", f"Authentication failed: {str(e)}", is_error=True)
                            raise
                    
                    def data(self, msg):
                        send_start = time.time()
                        self._log_entry("→", "DATA")
                        try:
                            if len(msg) > 1024 * 1024:  # 1MB threshold
                                self._log_entry("→", f"Large message detected: {len(msg):,} bytes")
                                chunk_size = 8192
                                total_chunks = (len(msg) + chunk_size - 1) // chunk_size
                                self.stats.chunks_sent = total_chunks
                                self._log_entry("→", f"Will send in {total_chunks} chunks of {chunk_size} bytes")
                            
                            result = super().data(msg)
                            self.stats.send_time = time.time() - send_start
                            self._log_entry("←", f"Message sent successfully", timing_info=f"{self.stats.send_time:.3f}s")
                            return result
                        except Exception as e:
                            self.stats.errors.append(f"Data send failed: {str(e)}")
                            self._log_entry("←", f"Data send failed: {str(e)}", is_error=True)
                            raise
                    
                    def quit(self):
                        self.stats.total_time = time.time() - self.connection_start_time
                        self._log_entry("→", "QUIT")
                        try:
                            result = super().quit()
                            self._log_entry("←", f"Session ended. Total time: {self.stats.total_time:.3f}s")
                            return result
                        except Exception as e:
                            self._log_entry("←", f"Quit failed: {str(e)}", is_error=True)
                            raise
                
                self.smtp = DebugSMTP_SSL(
                    host=self.host, 
                    port=self.port,
                    timeout=30
                )
                self.smtp.log_callback = self.log_callback
                self.smtp.ehlo()
            else:
                # Standard SMTP with optional STARTTLS
                self.smtp = DebugSMTP(log_callback=self.log_callback, timeout=30)
                self.smtp.connect(self.host, self.port)
                self.smtp.ehlo()
                
                if self.use_tls:
                    self.smtp.starttls()
                    self.smtp.ehlo()  # EHLO again after STARTTLS
            
            self.smtp.login(username, password)
            return self.smtp.stats
            
        except Exception as e:
            if self.smtp:
                self.smtp.stats.errors.append(f"Connection/auth failed: {str(e)}")
                return self.smtp.stats
            raise
    
    def send_test_email(self, from_addr: str, to_addr: str, subject: str, 
                       body: str, attachments: Optional[List[str]] = None) -> SMTPStats:
        """Send a test email with detailed monitoring."""
        if not self.smtp:
            raise RuntimeError("Must connect first")
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = from_addr
        msg['To'] = to_addr
        msg['Subject'] = subject
        
        # Add body
        msg.attach(MIMEText(body, 'plain'))
        
        # Track original size
        original_size = len(body)
        
        # Add attachments if provided
        if attachments:
            for attachment_path in attachments:
                if os.path.exists(attachment_path):
                    with open(attachment_path, 'rb') as f:
                        part = MIMEBase('application', 'octet-stream')
                        part.set_payload(f.read())
                        encoders.encode_base64(part)
                        part.add_header(
                            'Content-Disposition',
                            f'attachment; filename= {os.path.basename(attachment_path)}'
                        )
                        msg.attach(part)
                        original_size += os.path.getsize(attachment_path)
        
        # Get final message
        message_text = msg.as_string()
        final_size = len(message_text)
        
        # Log size information
        if self.log_callback:
            size_entry = SMTPLogEntry(
                timestamp=time.time(),
                direction="→",
                data=f"Message size: {original_size:,} bytes → {final_size:,} bytes (overhead: +{((final_size/original_size-1)*100):.1f}%)"
            )
            self.log_callback(size_entry)
        
        # Send the email
        try:
            self.smtp.send_message(msg, from_addr, [to_addr])
            return self.smtp.stats
        except Exception as e:
            self.smtp.stats.errors.append(f"Send failed: {str(e)}")
            return self.smtp.stats
    
    def disconnect(self):
        """Disconnect from SMTP server."""
        if self.smtp:
            try:
                self.smtp.quit()
            except:
                pass
            self.smtp = None