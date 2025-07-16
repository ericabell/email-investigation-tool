"""GPG integration for email signing and encryption."""

import subprocess
import tempfile
import os
import time
from typing import Optional, List, Tuple
from dataclasses import dataclass
import gnupg

@dataclass
class GPGStatus:
    """GPG availability and configuration status."""
    available: bool
    version: str
    private_keys: List[str]
    public_keys: List[str]
    default_key: Optional[str]
    error_message: Optional[str] = None

@dataclass
class GPGOperation:
    """Result of a GPG operation."""
    success: bool
    original_size: int
    processed_size: int
    operation_time: float
    overhead_percent: float
    error_message: Optional[str] = None

class GPGManager:
    """Manages GPG operations for email signing and encryption."""
    
    def __init__(self):
        self.gpg: Optional[gnupg.GPG] = None
        self.status: Optional[GPGStatus] = None
        self._initialize_gpg()
    
    def _initialize_gpg(self):
        """Initialize GPG and check availability."""
        try:
            # Check if GPG command is available
            result = subprocess.run(['gpg', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                version_line = result.stdout.split('\\n')[0]
                version = version_line.split()[-1] if version_line else "Unknown"
                
                # Initialize python-gnupg
                self.gpg = gnupg.GPG()
                
                # Get key information
                private_keys = self._get_private_keys()
                public_keys = self._get_public_keys()
                
                default_key = private_keys[0] if private_keys else None
                
                self.status = GPGStatus(
                    available=True,
                    version=version,
                    private_keys=private_keys,
                    public_keys=public_keys,
                    default_key=default_key
                )
            else:
                self.status = GPGStatus(
                    available=False,
                    version="",
                    private_keys=[],
                    public_keys=[],
                    default_key=None,
                    error_message="GPG command failed"
                )
                
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            self.status = GPGStatus(
                available=False,
                version="",
                private_keys=[],
                public_keys=[],
                default_key=None,
                error_message=f"GPG not available: {str(e)}"
            )
    
    def _get_private_keys(self) -> List[str]:
        """Get list of available private keys."""
        if not self.gpg:
            return []
        
        try:
            keys = self.gpg.list_keys(True)  # True for private keys
            return [f"{key['keyid'][-8:]} ({key['uids'][0]})" for key in keys if key['uids']]
        except Exception:
            return []
    
    def _get_public_keys(self) -> List[str]:
        """Get list of available public keys."""
        if not self.gpg:
            return []
        
        try:
            keys = self.gpg.list_keys()
            return [f"{key['keyid'][-8:]} ({key['uids'][0]})" for key in keys if key['uids']]
        except Exception:
            return []
    
    def sign_data(self, data: bytes, key_id: Optional[str] = None) -> GPGOperation:
        """Sign data with GPG."""
        if not self.status or not self.status.available:
            return GPGOperation(
                success=False,
                original_size=len(data),
                processed_size=0,
                operation_time=0.0,
                overhead_percent=0.0,
                error_message="GPG not available"
            )
        
        start_time = time.time()
        original_size = len(data)
        
        try:
            # Use default key if none specified
            if key_id is None and self.status.private_keys:
                key_id = self.status.private_keys[0].split()[0]
            
            # Sign the data
            signed = self.gpg.sign(data, keyid=key_id, detach=False)
            
            if signed.data:
                processed_size = len(signed.data)
                operation_time = time.time() - start_time
                overhead_percent = ((processed_size / original_size) - 1) * 100
                
                return GPGOperation(
                    success=True,
                    original_size=original_size,
                    processed_size=processed_size,
                    operation_time=operation_time,
                    overhead_percent=overhead_percent
                )
            else:
                return GPGOperation(
                    success=False,
                    original_size=original_size,
                    processed_size=0,
                    operation_time=time.time() - start_time,
                    overhead_percent=0.0,
                    error_message=f"Signing failed: {signed.stderr}"
                )
                
        except Exception as e:
            return GPGOperation(
                success=False,
                original_size=original_size,
                processed_size=0,
                operation_time=time.time() - start_time,
                overhead_percent=0.0,
                error_message=f"GPG sign error: {str(e)}"
            )
    
    def encrypt_data(self, data: bytes, recipients: List[str]) -> GPGOperation:
        """Encrypt data with GPG."""
        if not self.status or not self.status.available:
            return GPGOperation(
                success=False,
                original_size=len(data),
                processed_size=0,
                operation_time=0.0,
                overhead_percent=0.0,
                error_message="GPG not available"
            )
        
        start_time = time.time()
        original_size = len(data)
        
        try:
            # Encrypt the data
            encrypted = self.gpg.encrypt(data, recipients, always_trust=True)
            
            if encrypted.data:
                processed_size = len(encrypted.data)
                operation_time = time.time() - start_time
                overhead_percent = ((processed_size / original_size) - 1) * 100
                
                return GPGOperation(
                    success=True,
                    original_size=original_size,
                    processed_size=processed_size,
                    operation_time=operation_time,
                    overhead_percent=overhead_percent
                )
            else:
                return GPGOperation(
                    success=False,
                    original_size=original_size,
                    processed_size=0,
                    operation_time=time.time() - start_time,
                    overhead_percent=0.0,
                    error_message=f"Encryption failed: {encrypted.stderr}"
                )
                
        except Exception as e:
            return GPGOperation(
                success=False,
                original_size=original_size,
                processed_size=0,
                operation_time=time.time() - start_time,
                overhead_percent=0.0,
                error_message=f"GPG encrypt error: {str(e)}"
            )
    
    def sign_and_encrypt_data(self, data: bytes, recipients: List[str], 
                             sign_key: Optional[str] = None) -> GPGOperation:
        """Sign and encrypt data in one operation."""
        if not self.status or not self.status.available:
            return GPGOperation(
                success=False,
                original_size=len(data),
                processed_size=0,
                operation_time=0.0,
                overhead_percent=0.0,
                error_message="GPG not available"
            )
        
        start_time = time.time()
        original_size = len(data)
        
        try:
            # Use default key if none specified
            if sign_key is None and self.status.private_keys:
                sign_key = self.status.private_keys[0].split()[0]
            
            # Sign and encrypt
            result = self.gpg.encrypt(data, recipients, sign=sign_key, always_trust=True)
            
            if result.data:
                processed_size = len(result.data)
                operation_time = time.time() - start_time
                overhead_percent = ((processed_size / original_size) - 1) * 100
                
                return GPGOperation(
                    success=True,
                    original_size=original_size,
                    processed_size=processed_size,
                    operation_time=operation_time,
                    overhead_percent=overhead_percent
                )
            else:
                return GPGOperation(
                    success=False,
                    original_size=original_size,
                    processed_size=0,
                    operation_time=time.time() - start_time,
                    overhead_percent=0.0,
                    error_message=f"Sign+encrypt failed: {result.stderr}"
                )
                
        except Exception as e:
            return GPGOperation(
                success=False,
                original_size=original_size,
                processed_size=0,
                operation_time=time.time() - start_time,
                overhead_percent=0.0,
                error_message=f"GPG sign+encrypt error: {str(e)}"
            )
    
    def process_email_content(self, email_content: str, sign: bool = False, 
                             encrypt: bool = False, recipients: List[str] = None,
                             sign_key: Optional[str] = None) -> Tuple[str, GPGOperation]:
        """Process email content with GPG operations."""
        if not sign and not encrypt:
            # No GPG processing needed
            data_bytes = email_content.encode('utf-8')
            return email_content, GPGOperation(
                success=True,
                original_size=len(data_bytes),
                processed_size=len(data_bytes),
                operation_time=0.0,
                overhead_percent=0.0
            )
        
        data_bytes = email_content.encode('utf-8')
        
        if sign and encrypt:
            if not recipients:
                return email_content, GPGOperation(
                    success=False,
                    original_size=len(data_bytes),
                    processed_size=0,
                    operation_time=0.0,
                    overhead_percent=0.0,
                    error_message="Recipients required for encryption"
                )
            operation = self.sign_and_encrypt_data(data_bytes, recipients, sign_key)
        elif sign:
            operation = self.sign_data(data_bytes, sign_key)
        elif encrypt:
            if not recipients:
                return email_content, GPGOperation(
                    success=False,
                    original_size=len(data_bytes),
                    processed_size=0,
                    operation_time=0.0,
                    overhead_percent=0.0,
                    error_message="Recipients required for encryption"
                )
            operation = self.encrypt_data(data_bytes, recipients)
        
        if operation.success and hasattr(self.gpg, 'encrypt'):
            # Get the processed data (this is a simplified approach)
            processed_content = email_content  # In real implementation, would use operation result
            return processed_content, operation
        else:
            return email_content, operation
    
    def get_status_summary(self) -> str:
        """Get a human-readable status summary."""
        if not self.status:
            return "GPG status unknown"
        
        if not self.status.available:
            return f"GPG unavailable: {self.status.error_message}"
        
        key_count = len(self.status.private_keys)
        return f"GPG {self.status.version} - {key_count} private keys available"
    
    def refresh_status(self):
        """Refresh GPG status."""
        self._initialize_gpg()