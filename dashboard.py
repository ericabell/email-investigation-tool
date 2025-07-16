"""Rich-based dashboard for email investigation tool."""

import time
from typing import List, Optional, Callable
from datetime import datetime
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn
from rich.text import Text
from rich.live import Live
from rich.align import Align
from rich.columns import Columns

from themes import ThemeManager
from smtp_client import SMTPLogEntry, SMTPStats
from network_analyzer import NetworkPath, PortScanResult, ISPAnalysis
from file_generator import FileInfo
from imap_client import IMAPFolder, EmailMessage
from network_monitor import NetworkMonitor

class Dashboard:
    """Main dashboard interface."""
    
    def __init__(self, theme_manager: ThemeManager, network_monitor: Optional[NetworkMonitor] = None):
        self.console = Console(theme=theme_manager.rich_theme)
        self.theme = theme_manager
        self.layout = Layout()
        self.smtp_log: List[SMTPLogEntry] = []
        self.network_analysis: Optional[NetworkPath] = None
        self.isp_analysis: Optional[ISPAnalysis] = None
        self.port_scan_results: List[PortScanResult] = []
        self.current_stats: Optional[SMTPStats] = None
        self.generated_files: List[FileInfo] = []
        self.imap_folders: List[IMAPFolder] = []
        self.inbox_messages: List[EmailMessage] = []
        self.network_monitor = network_monitor
        
        # Email composition state
        self.email_to = ""
        self.email_from = ""
        self.email_subject = ""
        self.selected_attachment: Optional[str] = None
        self.gpg_sign = False
        self.gpg_encrypt = False
        
        self._setup_layout()
    
    def _setup_layout(self):
        """Setup the dashboard layout."""
        self.layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=3)
        )
        
        self.layout["main"].split_row(
            Layout(name="left_column"),
            Layout(name="right_column")
        )
        
        self.layout["left_column"].split_column(
            Layout(name="smtp_log", ratio=2),
            Layout(name="email_composition", size=8)
        )
        
        self.layout["right_column"].split_column(
            Layout(name="network_analysis", size=15),
            Layout(name="file_management", size=8),
            Layout(name="statistics", ratio=1)
        )
    
    def add_smtp_log_entry(self, entry: SMTPLogEntry):
        """Add a new SMTP log entry."""
        self.smtp_log.append(entry)
        # Keep only last 50 entries
        if len(self.smtp_log) > 50:
            self.smtp_log.pop(0)
    
    def update_network_analysis(self, network_path: NetworkPath):
        """Update network analysis results."""
        self.network_analysis = network_path
    
    def update_isp_analysis(self, isp_analysis: ISPAnalysis):
        """Update ISP analysis results."""
        self.isp_analysis = isp_analysis
    
    def update_port_scan(self, results: List[PortScanResult]):
        """Update port scan results."""
        self.port_scan_results = results
    
    def update_stats(self, stats: SMTPStats):
        """Update SMTP statistics."""
        self.current_stats = stats
    
    def add_generated_file(self, file_info: FileInfo):
        """Add a generated file to the list."""
        self.generated_files.append(file_info)
    
    def update_imap_data(self, folders: List[IMAPFolder], messages: List[EmailMessage]):
        """Update IMAP folder and message data."""
        self.imap_folders = folders
        self.inbox_messages = messages
    
    def _create_header(self) -> Panel:
        """Create the header panel."""
        title = Text("Email Investigation Tool - SMTP Debugger & ISP Analysis", 
                    style=self.theme.get_title_style())
        
        theme_indicator = f"Theme: {self.theme.current_theme_name.title()} (Press 'T' to toggle)"
        
        header_text = Align.center(title)
        theme_text = Text(theme_indicator, style=self.theme.get_info_style())
        
        return Panel(
            Align.center(title),
            style=self.theme.get_panel_style(),
            height=3
        )
    
    def _create_smtp_log_panel(self) -> Panel:
        """Create the SMTP protocol log panel."""
        log_text = Text()
        
        # Show last 20 log entries
        recent_logs = self.smtp_log[-20:] if len(self.smtp_log) > 20 else self.smtp_log
        
        for entry in recent_logs:
            timestamp = datetime.fromtimestamp(entry.timestamp).strftime("%H:%M:%S.%f")[:-3]
            
            if entry.is_error:
                style = self.theme.get_smtp_error_style()
            elif entry.direction == "→":
                style = self.theme.get_smtp_outgoing_style()
            else:
                style = self.theme.get_smtp_incoming_style()
            
            timing_info = f" ({entry.timing_info})" if entry.timing_info else ""
            log_line = f"[{timestamp}] {entry.direction} {entry.data}{timing_info}\\n"
            
            log_text.append(log_line, style=style)
        
        if not recent_logs:
            log_text.append("No SMTP activity yet. Connect to start logging.", 
                          style=self.theme.get_info_style())
        
        return Panel(
            log_text,
            title="SMTP Protocol Log",
            style=self.theme.get_panel_style()
        )
    
    def _create_network_analysis_panel(self) -> Panel:
        """Create the network analysis panel."""
        if not self.network_analysis:
            content = Text("Network analysis not yet performed.", 
                         style=self.theme.get_info_style())
        else:
            table = Table(show_header=True, header_style=self.theme.get_title_style())
            table.add_column("Hop", style=self.theme.get_info_style())
            table.add_column("IP Address", style=self.theme.get_info_style())
            table.add_column("Hostname", style=self.theme.get_info_style())
            table.add_column("RTT", style=self.theme.get_info_style())
            
            for hop in self.network_analysis.hops[-10:]:  # Show last 10 hops
                hostname = hop.hostname if hop.hostname else "N/A"
                rtt = f"{hop.response_time:.1f}ms" if not hop.is_timeout else "timeout"
                
                table.add_row(
                    str(hop.hop_number),
                    hop.ip_address,
                    hostname,
                    rtt
                )
            
            # Add summary
            summary = Text()
            summary.append(f"Total hops: {self.network_analysis.total_hops}  ", 
                         style=self.theme.get_info_style())
            summary.append(f"Packet loss: {self.network_analysis.packet_loss:.1f}%  ", 
                         style=self.theme.get_warning_style() if self.network_analysis.packet_loss > 5 else self.theme.get_success_style())
            summary.append(f"Avg RTT: {self.network_analysis.avg_rtt:.1f}ms\\n", 
                         style=self.theme.get_info_style())
            
            if self.network_analysis.isp_detected:
                summary.append(f"ISP: {self.network_analysis.isp_detected}\\n", 
                             style=self.theme.get_warning_style())
            
            content = Columns([table, summary])
        
        return Panel(
            content,
            title="Network Path Analysis",
            style=self.theme.get_panel_style()
        )
    
    def _create_email_composition_panel(self) -> Panel:
        """Create the email composition panel."""
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("Label", style=self.theme.get_info_style())
        table.add_column("Value", style=self.theme.get_info_style())
        
        table.add_row("To:", self.email_to or "[Enter recipient]")
        table.add_row("From:", self.email_from or "[Enter sender]")
        table.add_row("Subject:", self.email_subject or "[Enter subject]")
        table.add_row("Attachment:", self.selected_attachment or "[No file selected]")
        
        # GPG options
        sign_status = "✓" if self.gpg_sign else "✗"
        encrypt_status = "✓" if self.gpg_encrypt else "✗"
        table.add_row("GPG Sign:", sign_status)
        table.add_row("GPG Encrypt:", encrypt_status)
        
        return Panel(
            table,
            title="Email Composition",
            style=self.theme.get_panel_style()
        )
    
    def _create_file_management_panel(self) -> Panel:
        """Create the file management panel."""
        if not self.generated_files:
            content = Text("No files generated yet.", style=self.theme.get_info_style())
        else:
            table = Table(show_header=True, header_style=self.theme.get_title_style())
            table.add_column("Filename", style=self.theme.get_info_style())
            table.add_column("Size", style=self.theme.get_info_style())
            table.add_column("Generated", style=self.theme.get_info_style())
            
            for file_info in self.generated_files[-5:]:  # Show last 5 files
                size_str = f"{file_info.size / (1024*1024):.1f} MB"
                gen_time = f"{file_info.generation_time:.1f}s"
                
                table.add_row(
                    file_info.filename,
                    size_str,
                    gen_time
                )
            
            content = table
        
        return Panel(
            content,
            title="Generated Files",
            style=self.theme.get_panel_style()
        )
    
    def _create_imap_info_panel(self) -> Panel:
        """Create the IMAP folder and inbox info panel."""
        if not self.imap_folders and not self.inbox_messages:
            content = Text("IMAP data not loaded yet.", style=self.theme.get_info_style())
        else:
            # Create two columns: folders and inbox
            folders_table = Table(show_header=True, header_style=self.theme.get_title_style(), title="Folders")
            folders_table.add_column("Name", style=self.theme.get_info_style())
            folders_table.add_column("Count", style=self.theme.get_info_style())
            
            for folder in self.imap_folders[:5]:  # Show first 5 folders
                folders_table.add_row(folder.name, str(folder.message_count))
            
            inbox_table = Table(show_header=True, header_style=self.theme.get_title_style(), title="Recent Inbox")
            inbox_table.add_column("From", style=self.theme.get_info_style())
            inbox_table.add_column("Subject", style=self.theme.get_info_style())
            
            for msg in self.inbox_messages[:5]:  # Show first 5 messages
                subject = msg.subject[:30] + "..." if len(msg.subject) > 30 else msg.subject
                sender = msg.sender[:20] + "..." if len(msg.sender) > 20 else msg.sender
                inbox_table.add_row(sender, subject)
            
            content = Columns([folders_table, inbox_table])
        
        return Panel(
            content,
            title="IMAP - Folders & Inbox",
            style=self.theme.get_panel_style()
        )
    
    def _create_statistics_panel(self) -> Panel:
        """Create the statistics panel."""
        if not self.current_stats:
            content = Text("No SMTP statistics available.", style=self.theme.get_info_style())
        else:
            table = Table(show_header=False, box=None)
            table.add_column("Metric", style=self.theme.get_info_style())
            table.add_column("Value", style=self.theme.get_success_style())
            
            table.add_row("Connection Time:", f"{self.current_stats.connection_time:.3f}s")
            table.add_row("Auth Time:", f"{self.current_stats.auth_time:.3f}s")
            table.add_row("Send Time:", f"{self.current_stats.send_time:.3f}s")
            table.add_row("Bytes Sent:", f"{self.current_stats.bytes_sent:,}")
            
            if self.current_stats.chunks_sent > 0:
                table.add_row("Chunks Sent:", str(self.current_stats.chunks_sent))
            
            # Show errors and warnings
            if self.current_stats.errors:
                table.add_row("Errors:", str(len(self.current_stats.errors)))
            if self.current_stats.warnings:
                table.add_row("Warnings:", str(len(self.current_stats.warnings)))
            
            # Add network monitoring stats if available
            if self.network_monitor:
                table.add_row("", "")  # Separator
                table.add_row("Network Monitor:", "")
                table.add_row("- Total Connections:", str(self.network_monitor.stats.total_connections))
                table.add_row("- SMTP Connections:", str(self.network_monitor.stats.smtp_connections))
                table.add_row("- IMAP Connections:", str(self.network_monitor.stats.imap_connections))
                
                # Highlight suspicious connections
                if self.network_monitor.stats.suspicious_connections > 0:
                    table.add_row("- Suspicious:", 
                                str(self.network_monitor.stats.suspicious_connections),
                                style=self.theme.get_error_style())
                else:
                    table.add_row("- Suspicious:", "0")
            
            content = table
        
        return Panel(
            content,
            title="SMTP Statistics",
            style=self.theme.get_panel_style()
        )
    
    def _create_footer(self) -> Panel:
        """Create the footer panel."""
        controls = Text()
        controls.append("Controls: ", style=self.theme.get_info_style())
        controls.append("T", style=self.theme.get_success_style())
        controls.append("=Toggle Theme  ", style=self.theme.get_info_style())
        controls.append("Q", style=self.theme.get_success_style())
        controls.append("=Quit  ", style=self.theme.get_info_style())
        controls.append("S", style=self.theme.get_success_style())
        controls.append("=Send Email  ", style=self.theme.get_info_style())
        controls.append("G", style=self.theme.get_success_style())
        controls.append("=Generate File  ", style=self.theme.get_info_style())
        controls.append("I", style=self.theme.get_success_style())
        controls.append("=Reload IMAP", style=self.theme.get_info_style())
        
        return Panel(
            Align.center(controls),
            style=self.theme.get_panel_style(),
            height=3
        )
    
    def update_display(self):
        """Update all dashboard panels."""
        self.layout["header"].update(self._create_header())
        self.layout["smtp_log"].update(self._create_smtp_log_panel())
        self.layout["network_analysis"].update(self._create_network_analysis_panel())
        self.layout["email_composition"].update(self._create_email_composition_panel())
        self.layout["file_management"].update(self._create_file_management_panel())
        self.layout["statistics"].update(self._create_statistics_panel())
        self.layout["footer"].update(self._create_footer())
    
    def render(self) -> Layout:
        """Render the complete dashboard."""
        self.update_display()
        return self.layout
    
    def toggle_theme(self):
        """Toggle between light and dark themes."""
        self.theme.toggle_theme()
        self.console = Console(theme=self.theme.rich_theme)
    
    def set_email_field(self, field: str, value: str):
        """Set email composition field."""
        if field == "to":
            self.email_to = value
        elif field == "from":
            self.email_from = value
        elif field == "subject":
            self.email_subject = value
        elif field == "attachment":
            self.selected_attachment = value
    
    def toggle_gpg_option(self, option: str):
        """Toggle GPG options."""
        if option == "sign":
            self.gpg_sign = not self.gpg_sign
        elif option == "encrypt":
            self.gpg_encrypt = not self.gpg_encrypt