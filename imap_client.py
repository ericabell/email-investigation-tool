"""IMAP client for folder listing and inbox retrieval."""

import imaplib
import email
import ssl
import time
from typing import List, Optional, Tuple
from dataclasses import dataclass
from email.header import decode_header

@dataclass
class EmailMessage:
    """Represents an email message."""
    uid: str
    subject: str
    sender: str
    date: str
    size: int
    flags: List[str]
    has_attachments: bool = False

@dataclass
class IMAPFolder:
    """Represents an IMAP folder."""
    name: str
    flags: List[str]
    message_count: int
    delimiter: str = "/"

@dataclass
class IMAPStats:
    """IMAP operation statistics."""
    connection_time: float = 0.0
    folder_list_time: float = 0.0
    message_fetch_time: float = 0.0
    total_folders: int = 0
    total_messages: int = 0
    errors: List[str] = None
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []

class IMAPClient:
    """Enhanced IMAP client for email folder and message analysis."""
    
    def __init__(self, host: str, port: int, use_ssl: bool = True):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.connection: Optional[imaplib.IMAP4] = None
        self.stats = IMAPStats()
        self.folders: List[IMAPFolder] = []
        self.inbox_messages: List[EmailMessage] = []
    
    def connect(self, username: str, password: str) -> bool:
        """Connect to IMAP server and authenticate."""
        start_time = time.time()
        
        try:
            if self.use_ssl:
                self.connection = imaplib.IMAP4_SSL(self.host, self.port)
            else:
                self.connection = imaplib.IMAP4(self.host, self.port)
            
            # Authenticate
            self.connection.login(username, password)
            
            self.stats.connection_time = time.time() - start_time
            return True
            
        except Exception as e:
            self.stats.errors.append(f"IMAP connection failed: {str(e)}")
            return False
    
    def list_folders(self) -> List[IMAPFolder]:
        """List all available folders."""
        if not self.connection:
            self.stats.errors.append("Not connected to IMAP server")
            return []
        
        start_time = time.time()
        folders = []
        
        try:
            # List all folders
            status, folder_list = self.connection.list()
            
            if status == 'OK':
                for folder_info in folder_list:
                    if isinstance(folder_info, bytes):
                        folder_str = folder_info.decode('utf-8')
                    else:
                        folder_str = folder_info
                    
                    # Parse folder information
                    # Format: (flags) "delimiter" "folder_name"
                    parts = folder_str.split('"')
                    if len(parts) >= 3:
                        flags_part = parts[0].strip('() ')
                        delimiter = parts[1] if len(parts) > 1 else "/"
                        folder_name = parts[-1] if len(parts) > 2 else "Unknown"
                        
                        flags = [f.strip() for f in flags_part.split() if f.strip()]
                        
                        # Get message count for this folder
                        message_count = self._get_folder_message_count(folder_name)
                        
                        folder = IMAPFolder(
                            name=folder_name,
                            flags=flags,
                            message_count=message_count,
                            delimiter=delimiter
                        )
                        folders.append(folder)
            
            self.folders = folders
            self.stats.folder_list_time = time.time() - start_time
            self.stats.total_folders = len(folders)
            
        except Exception as e:
            self.stats.errors.append(f"Failed to list folders: {str(e)}")
        
        return folders
    
    def _get_folder_message_count(self, folder_name: str) -> int:
        """Get message count for a specific folder."""
        try:
            status, messages = self.connection.select(folder_name, readonly=True)
            if status == 'OK' and messages and messages[0]:
                return int(messages[0])
        except Exception:
            pass
        return 0
    
    def fetch_inbox_messages(self, limit: int = 10) -> List[EmailMessage]:
        """Fetch recent messages from inbox."""
        if not self.connection:
            self.stats.errors.append("Not connected to IMAP server")
            return []
        
        start_time = time.time()
        messages = []
        
        try:
            # Select inbox
            status, message_count = self.connection.select('INBOX')
            
            if status == 'OK' and message_count and message_count[0]:
                total_messages = int(message_count[0])
                self.stats.total_messages = total_messages
                
                # Fetch recent messages (last N messages)
                start_idx = max(1, total_messages - limit + 1)
                end_idx = total_messages
                
                if start_idx <= end_idx:
                    # Fetch message UIDs and basic info
                    status, msg_data = self.connection.fetch(
                        f'{start_idx}:{end_idx}',
                        '(UID ENVELOPE RFC822.SIZE FLAGS BODYSTRUCTURE)'
                    )
                    
                    if status == 'OK':
                        # Parse messages (simplified parsing)
                        for response_part in msg_data:
                            if isinstance(response_part, tuple):
                                self._parse_message_response(response_part, messages)
            
            self.inbox_messages = messages
            self.stats.message_fetch_time = time.time() - start_time
            
        except Exception as e:
            self.stats.errors.append(f"Failed to fetch inbox: {str(e)}")
        
        return messages
    
    def _parse_message_response(self, response_part: tuple, messages: List[EmailMessage]):
        """Parse a single message response."""
        try:
            if len(response_part) >= 2:
                header_data = response_part[1]
                if isinstance(header_data, bytes):
                    header_str = header_data.decode('utf-8', errors='ignore')
                else:
                    header_str = str(header_data)
                
                # This is a simplified parser - in a real implementation,
                # you'd want to use proper IMAP response parsing
                uid = self._extract_uid(header_str)
                subject = self._extract_subject(header_str)
                sender = self._extract_sender(header_str)
                date = self._extract_date(header_str)
                size = self._extract_size(header_str)
                flags = self._extract_flags(header_str)
                has_attachments = self._check_attachments(header_str)
                
                message = EmailMessage(
                    uid=uid,
                    subject=subject,
                    sender=sender,
                    date=date,
                    size=size,
                    flags=flags,
                    has_attachments=has_attachments
                )
                messages.append(message)
                
        except Exception as e:
            self.stats.errors.append(f"Failed to parse message: {str(e)}")
    
    def _extract_uid(self, header_str: str) -> str:
        """Extract UID from header string."""
        # Simplified UID extraction
        import re
        uid_match = re.search(r'UID (\d+)', header_str)
        return uid_match.group(1) if uid_match else "unknown"
    
    def _extract_subject(self, header_str: str) -> str:
        """Extract subject from header string."""
        # Simplified subject extraction
        import re
        subject_match = re.search(r'ENVELOPE.*?"([^"]*)"', header_str)
        return subject_match.group(1) if subject_match else "No subject"
    
    def _extract_sender(self, header_str: str) -> str:
        """Extract sender from header string."""
        # Simplified sender extraction
        import re
        sender_match = re.search(r'ENVELOPE.*?"[^"]*".*?"([^"]*)"', header_str)
        return sender_match.group(1) if sender_match else "Unknown sender"
    
    def _extract_date(self, header_str: str) -> str:
        """Extract date from header string."""
        # Simplified date extraction
        return "Recent"  # Would parse proper date in real implementation
    
    def _extract_size(self, header_str: str) -> int:
        """Extract message size from header string."""
        import re
        size_match = re.search(r'RFC822\.SIZE (\d+)', header_str)
        return int(size_match.group(1)) if size_match else 0
    
    def _extract_flags(self, header_str: str) -> List[str]:
        """Extract flags from header string."""
        import re
        flags_match = re.search(r'FLAGS \(([^)]*)\)', header_str)
        if flags_match:
            return flags_match.group(1).split()
        return []
    
    def _check_attachments(self, header_str: str) -> bool:
        """Check if message has attachments."""
        # Simplified attachment detection
        return 'BODYSTRUCTURE' in header_str and 'multipart' in header_str.lower()
    
    def get_folder_by_name(self, name: str) -> Optional[IMAPFolder]:
        """Get folder by name."""
        for folder in self.folders:
            if folder.name.lower() == name.lower():
                return folder
        return None
    
    def disconnect(self):
        """Disconnect from IMAP server."""
        if self.connection:
            try:
                self.connection.logout()
            except Exception:
                pass
            self.connection = None
    
    def get_stats_summary(self) -> str:
        """Get a summary of IMAP statistics."""
        if self.stats.errors:
            return f"IMAP errors: {len(self.stats.errors)}"
        
        return (f"IMAP: {self.stats.total_folders} folders, "
                f"{self.stats.total_messages} messages in inbox, "
                f"connected in {self.stats.connection_time:.1f}s")

class IMAPDebugger:
    """High-level IMAP debugging interface."""
    
    def __init__(self, host: str, port: int, use_ssl: bool = True):
        self.client = IMAPClient(host, port, use_ssl)
    
    def connect_and_analyze(self, username: str, password: str) -> Tuple[List[IMAPFolder], List[EmailMessage], IMAPStats]:
        """Connect and perform full analysis."""
        success = self.client.connect(username, password)
        
        if not success:
            return [], [], self.client.stats
        
        # List folders
        folders = self.client.list_folders()
        
        # Fetch inbox messages
        messages = self.client.fetch_inbox_messages(limit=10)
        
        return folders, messages, self.client.stats
    
    def disconnect(self):
        """Disconnect from server."""
        self.client.disconnect()