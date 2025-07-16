"""Large file generator for email attachment testing."""

import os
import tempfile
import hashlib
import random
import time
from typing import Optional, Tuple
from dataclasses import dataclass

@dataclass
class FileInfo:
    """Information about a generated file."""
    path: str
    size: int
    sha256: str
    generation_time: float
    filename: str

class FileGenerator:
    """Generates random files of specified sizes for testing."""
    
    def __init__(self, temp_dir: Optional[str] = None):
        self.temp_dir = temp_dir or tempfile.gettempdir()
        self.generated_files: list[FileInfo] = []
    
    def generate_file(self, size_mb: int, filename: Optional[str] = None) -> FileInfo:
        """Generate a random file of specified size in MB."""
        size_bytes = size_mb * 1024 * 1024
        
        # Generate filename if not provided
        if filename is None:
            timestamp = int(time.time())
            filename = f"test_{size_mb}mb_{timestamp}.dat"
        
        filepath = os.path.join(self.temp_dir, filename)
        
        # Generate random data and write to file
        start_time = time.time()
        sha256_hash = hashlib.sha256()
        
        with open(filepath, 'wb') as f:
            remaining = size_bytes
            chunk_size = 64 * 1024  # 64KB chunks
            
            while remaining > 0:
                # Generate random chunk
                current_chunk_size = min(chunk_size, remaining)
                chunk = os.urandom(current_chunk_size)
                
                # Write chunk and update hash
                f.write(chunk)
                sha256_hash.update(chunk)
                remaining -= current_chunk_size
        
        generation_time = time.time() - start_time
        
        # Create file info
        file_info = FileInfo(
            path=filepath,
            size=size_bytes,
            sha256=sha256_hash.hexdigest(),
            generation_time=generation_time,
            filename=filename
        )
        
        self.generated_files.append(file_info)
        return file_info
    
    def generate_patterned_file(self, size_mb: int, pattern: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 
                               filename: Optional[str] = None) -> FileInfo:
        """Generate a file with a repeating pattern (useful for compression testing)."""
        size_bytes = size_mb * 1024 * 1024
        
        if filename is None:
            timestamp = int(time.time())
            filename = f"pattern_{size_mb}mb_{timestamp}.dat"
        
        filepath = os.path.join(self.temp_dir, filename)
        
        start_time = time.time()
        sha256_hash = hashlib.sha256()
        
        with open(filepath, 'wb') as f:
            remaining = size_bytes
            pattern_bytes = pattern.encode('ascii')
            pattern_len = len(pattern_bytes)
            
            while remaining > 0:
                # Calculate how much of the pattern to write
                write_size = min(remaining, pattern_len)
                chunk = pattern_bytes[:write_size]
                
                f.write(chunk)
                sha256_hash.update(chunk)
                remaining -= write_size
        
        generation_time = time.time() - start_time
        
        file_info = FileInfo(
            path=filepath,
            size=size_bytes,
            sha256=sha256_hash.hexdigest(),
            generation_time=generation_time,
            filename=filename
        )
        
        self.generated_files.append(file_info)
        return file_info
    
    def generate_binary_file(self, size_mb: int, filename: Optional[str] = None) -> FileInfo:
        """Generate a binary file with specific patterns that might trigger ISP filtering."""
        size_bytes = size_mb * 1024 * 1024
        
        if filename is None:
            timestamp = int(time.time())
            filename = f"binary_{size_mb}mb_{timestamp}.bin"
        
        filepath = os.path.join(self.temp_dir, filename)
        
        start_time = time.time()
        sha256_hash = hashlib.sha256()
        
        with open(filepath, 'wb') as f:
            remaining = size_bytes
            
            # Create patterns that might trigger DPI
            patterns = [
                b'\x00\x01\x02\x03\x04\x05\x06\x07',  # Sequential bytes
                b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF',  # All ones
                b'\x00\x00\x00\x00\x00\x00\x00\x00',  # All zeros
                b'\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11',  # Mixed pattern
            ]
            
            pattern_index = 0
            while remaining > 0:
                # Use different patterns throughout the file
                pattern = patterns[pattern_index % len(patterns)]
                write_size = min(remaining, len(pattern))
                chunk = pattern[:write_size]
                
                f.write(chunk)
                sha256_hash.update(chunk)
                remaining -= write_size
                
                # Switch patterns occasionally
                if random.random() < 0.1:  # 10% chance to switch
                    pattern_index += 1
        
        generation_time = time.time() - start_time
        
        file_info = FileInfo(
            path=filepath,
            size=size_bytes,
            sha256=sha256_hash.hexdigest(),
            generation_time=generation_time,
            filename=filename
        )
        
        self.generated_files.append(file_info)
        return file_info
    
    def get_file_sizes(self) -> list[Tuple[str, int, str]]:
        """Get list of generated files with their sizes and paths."""
        return [(f.filename, f.size, f.path) for f in self.generated_files]
    
    def cleanup_file(self, file_info: FileInfo):
        """Remove a generated file from disk."""
        try:
            if os.path.exists(file_info.path):
                os.remove(file_info.path)
            if file_info in self.generated_files:
                self.generated_files.remove(file_info)
        except Exception as e:
            print(f"Error cleaning up file {file_info.path}: {e}")
    
    def cleanup_all(self):
        """Remove all generated files from disk."""
        for file_info in self.generated_files.copy():
            self.cleanup_file(file_info)
    
    def get_file_info(self, path: str) -> Optional[FileInfo]:
        """Get file info for a specific path."""
        for file_info in self.generated_files:
            if file_info.path == path:
                return file_info
        return None
    
    @staticmethod
    def format_size(size_bytes: int) -> str:
        """Format file size in human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"
    
    @staticmethod
    def get_compression_ratio(original_size: int, compressed_size: int) -> float:
        """Calculate compression ratio."""
        if original_size == 0:
            return 0.0
        return (original_size - compressed_size) / original_size * 100