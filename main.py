"""Email Investigation Tool - SMTP Debugger & ISP Analysis."""

import asyncio
import logging
import os
import sys
import time
from pathlib import Path

from rich.live import Live
from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm

from config import load_config, validate_config
from themes import ThemeManager
from dashboard import Dashboard
from smtp_client import SMTPDebugger, SMTPLogEntry
from network_analyzer import NetworkAnalyzer
from file_generator import FileGenerator
from gpg_manager import GPGManager
from imap_client import IMAPDebugger
from network_monitor import NetworkMonitor

class EmailInvestigationTool:
    """Main application class."""
    
    def __init__(self):
        self.config = load_config()
        self.theme_manager = ThemeManager(self.config.default_theme)
        self.network_monitor = NetworkMonitor()
        self.dashboard = Dashboard(self.theme_manager, self.network_monitor)
        self.console = Console(theme=self.theme_manager.rich_theme)
        self.smtp_debugger: SMTPDebugger = None
        self.imap_debugger: IMAPDebugger = None
        self.network_analyzer = NetworkAnalyzer()
        self.file_generator = FileGenerator()
        self.gpg_manager = GPGManager()
        self.running = True
        
        # Setup logging
        self._setup_logging()
        
        # Validate configuration
        config_errors = validate_config(self.config)
        if config_errors:
            self.console.print("[red]Configuration errors found:[/red]")
            for error in config_errors:
                self.console.print(f"  • {error}")
            self.console.print("\\nPlease check your .env file and try again.")
            sys.exit(1)
    
    def _setup_logging(self):
        """Setup file logging for SMTP/IMAP communications."""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        # Setup file handler
        log_file = log_dir / f"email_debug_{int(time.time())}.log"
        logging.basicConfig(
            level=getattr(logging, self.config.log_level),
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"Email Investigation Tool starting - Log file: {log_file}")
        
        # Start network monitoring
        self.network_monitor.start_monitoring()
        self.logger.info(f"Network monitoring started - Network log: {self.network_monitor.log_file_path}")
    
    def _smtp_log_callback(self, entry: SMTPLogEntry):
        """Callback for SMTP log entries."""
        self.dashboard.add_smtp_log_entry(entry)
        
        # Also log to file
        direction = "SEND" if entry.direction == "→" else "RECV"
        timing = f" ({entry.timing_info})" if entry.timing_info else ""
        self.logger.info(f"SMTP {direction}: {entry.data}{timing}")
    
    async def run_network_analysis(self):
        """Run comprehensive network analysis."""
        self.console.print("[yellow]Running network analysis...[/yellow]")
        
        # DNS analysis
        self.console.print(f"[cyan]• Resolving DNS for {self.config.smtp.host}...[/cyan]")
        dns_result = self.network_analyzer.resolve_dns(self.config.smtp.host)
        if dns_result.ip_addresses:
            self.console.print(f"[green]  ✓ Resolved to {dns_result.ip_addresses[0]} ({dns_result.response_time:.3f}s)[/green]")
        else:
            self.console.print(f"[red]  ✗ DNS resolution failed[/red]")
        
        # Traceroute
        self.console.print(f"[cyan]• Tracing network path to {self.config.smtp.host}...[/cyan]")
        self.console.print("[dim]  (Testing connectivity and network path)[/dim]")
        network_path = self.network_analyzer.traceroute(self.config.smtp.host)
        self.dashboard.update_network_analysis(network_path)
        
        if network_path.hops:
            if len(network_path.hops) > 1:
                self.console.print(f"[green]  ✓ Traced {len(network_path.hops)} hops, avg RTT: {network_path.avg_rtt:.1f}ms[/green]")
            else:
                self.console.print(f"[green]  ✓ Connectivity confirmed, RTT: {network_path.avg_rtt:.1f}ms[/green]")
            if network_path.isp_detected:
                self.console.print(f"[blue]  ℹ ISP detected: {network_path.isp_detected}[/blue]")
        else:
            self.console.print(f"[yellow]  ⚠ Network path analysis unavailable[/yellow]")
        
        # Port scanning
        self.console.print(f"[cyan]• Scanning SMTP ports on {self.config.smtp.host}...[/cyan]")
        port_results = self.network_analyzer.scan_smtp_ports(self.config.smtp.host)
        self.dashboard.update_port_scan(port_results)
        
        open_ports = [str(p.port) for p in port_results if p.is_open]
        blocked_ports = [str(p.port) for p in port_results if not p.is_open]
        if open_ports:
            self.console.print(f"[green]  ✓ Open ports: {', '.join(open_ports)}[/green]")
        if blocked_ports:
            self.console.print(f"[red]  ✗ Blocked ports: {', '.join(blocked_ports)}[/red]")
        
        # ISP analysis
        self.console.print("[cyan]• Analyzing ISP interference patterns...[/cyan]")
        isp_analysis = self.network_analyzer.analyze_isp_interference(
            self.config.smtp.host, self.config.smtp.port
        )
        self.dashboard.update_isp_analysis(isp_analysis)
        
        if isp_analysis.suspicious_behavior:
            self.console.print(f"[yellow]  ⚠ {len(isp_analysis.suspicious_behavior)} potential issues detected[/yellow]")
            for issue in isp_analysis.suspicious_behavior[:3]:  # Show first 3
                self.console.print(f"[dim]    • {issue}[/dim]")
        else:
            self.console.print("[green]  ✓ No ISP interference detected[/green]")
        
        self.console.print("[green]Network analysis complete[/green]")
    
    async def load_imap_data(self):
        """Load IMAP folders and inbox messages."""
        self.console.print("[yellow]Loading IMAP data...[/yellow]")
        
        try:
            # Initialize IMAP debugger
            self.console.print(f"[cyan]• Connecting to {self.config.imap.host}:{self.config.imap.port}...[/cyan]")
            self.imap_debugger = IMAPDebugger(
                self.config.imap.host,
                self.config.imap.port,
                self.config.imap.use_ssl
            )
            
            # Connect and fetch data
            self.console.print("[cyan]• Authenticating and fetching folder list...[/cyan]")
            folders, messages, stats = self.imap_debugger.connect_and_analyze(
                self.config.imap.username,
                self.config.imap.password
            )
            
            if stats.errors:
                self.console.print(f"[yellow]  ⚠ IMAP warning: {stats.errors[-1]}[/yellow]")
            else:
                self.console.print(f"[green]  ✓ Connected in {stats.connection_time:.1f}s[/green]")
                self.console.print(f"[green]  ✓ Found {len(folders)} folders, {len(messages)} recent messages[/green]")
                self.dashboard.update_imap_data(folders, messages)
            
            # Disconnect
            self.imap_debugger.disconnect()
            
        except Exception as e:
            self.console.print(f"[yellow]  ⚠ IMAP unavailable: {e}[/yellow]")
    
    def generate_test_file(self):
        """Generate a test file for attachment."""
        try:
            self.console.print("[bold]Generate Test File[/bold]")
            
            size_mb = IntPrompt.ask("File size in MB", default=5, console=self.console)
            file_type = Prompt.ask(
                "File type", 
                choices=["random", "pattern", "binary"], 
                default="random",
                console=self.console
            )
            
            self.console.print(f"[yellow]Generating {size_mb}MB {file_type} file...[/yellow]")
            
            if file_type == "random":
                file_info = self.file_generator.generate_file(size_mb)
            elif file_type == "pattern":
                file_info = self.file_generator.generate_patterned_file(size_mb)
            else:  # binary
                file_info = self.file_generator.generate_binary_file(size_mb)
            
            self.dashboard.add_generated_file(file_info)
            self.dashboard.set_email_field("attachment", file_info.path)
            
            self.console.print(
                f"[green]✓ Generated {file_info.filename} "
                f"({self.file_generator.format_size(file_info.size)}) "
                f"in {file_info.generation_time:.1f}s[/green]"
            )
            
            # Give user time to see the result
            self.console.print("[dim]Press Enter to return to dashboard...[/dim]")
            self.console.input()
            
        except KeyboardInterrupt:
            self.console.print("[yellow]File generation cancelled[/yellow]")
        except Exception as e:
            self.console.print(f"[red]Error generating file: {e}[/red]")
    
    def compose_email(self):
        """Interactive email composition."""
        try:
            self.console.print("[bold]Email Composition[/bold]")
            
            to_addr = Prompt.ask("To address", default=self.dashboard.email_to, console=self.console)
            from_addr = Prompt.ask("From address", default=self.dashboard.email_from or self.config.smtp.username, console=self.console)
            subject = Prompt.ask("Subject", default=self.dashboard.email_subject or "Test Email", console=self.console)
            
            self.dashboard.set_email_field("to", to_addr)
            self.dashboard.set_email_field("from", from_addr)
            self.dashboard.set_email_field("subject", subject)
            
            # GPG options
            if self.gpg_manager.status and self.gpg_manager.status.available:
                sign = Confirm.ask("Sign email?", default=False, console=self.console)
                encrypt = Confirm.ask("Encrypt email?", default=False, console=self.console)
                
                if sign:
                    self.dashboard.toggle_gpg_option("sign")
                if encrypt:
                    self.dashboard.toggle_gpg_option("encrypt")
            
            self.console.print("[green]✓ Email composition updated![/green]")
            self.console.print("[dim]Press Enter to return to dashboard...[/dim]")
            self.console.input()
            
        except KeyboardInterrupt:
            self.console.print("[yellow]Email composition cancelled[/yellow]")
        except Exception as e:
            self.console.print(f"[red]Error in composition: {e}[/red]")
    
    async def send_test_email(self):
        """Send a test email with comprehensive debugging."""
        if not self.dashboard.email_to or not self.dashboard.email_from:
            self.console.print("[red]Please compose email first (To and From required)[/red]")
            self.console.print("[dim]Press Enter to return to dashboard...[/dim]")
            self.console.input()
            return
        
        try:
            self.console.print("[bold]Sending Test Email[/bold]")
            self.console.print(f"[cyan]To: {self.dashboard.email_to}[/cyan]")
            self.console.print(f"[cyan]From: {self.dashboard.email_from}[/cyan]")
            self.console.print(f"[cyan]Subject: {self.dashboard.email_subject}[/cyan]")
            
            self.console.print("[yellow]Connecting to SMTP server...[/yellow]")
            
            # Initialize SMTP debugger
            self.smtp_debugger = SMTPDebugger(
                self.config.smtp.host,
                self.config.smtp.port,
                self.config.smtp.use_tls,
                self._smtp_log_callback
            )
            
            # Connect and authenticate
            self.console.print("[dim]Authenticating...[/dim]")
            stats = self.smtp_debugger.connect_and_auth(
                self.config.smtp.username,
                self.config.smtp.password
            )
            
            if stats.errors:
                self.console.print(f"[red]Connection failed: {stats.errors[-1]}[/red]")
                self.console.print("[dim]Press Enter to return to dashboard...[/dim]")
                self.console.input()
                return
            
            self.console.print("[green]✓ Connected and authenticated[/green]")
            self.dashboard.update_stats(stats)
            
            # Prepare email content
            body = f"""This is a test email from the Email Investigation Tool.
            
Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}
Tool Version: 0.1.0
SMTP Server: {self.config.smtp.host}:{self.config.smtp.port}

This email is being sent to test SMTP functionality and debug potential issues."""
            
            # Process with GPG if enabled
            if self.dashboard.gpg_sign or self.dashboard.gpg_encrypt:
                recipients = [self.dashboard.email_to] if self.dashboard.gpg_encrypt else []
                processed_body, gpg_operation = self.gpg_manager.process_email_content(
                    body,
                    sign=self.dashboard.gpg_sign,
                    encrypt=self.dashboard.gpg_encrypt,
                    recipients=recipients
                )
                
                if not gpg_operation.success:
                    self.console.print(f"[red]GPG processing failed: {gpg_operation.error_message}[/red]")
                    return
                
                body = processed_body
            
            # Send email
            attachments = [self.dashboard.selected_attachment] if self.dashboard.selected_attachment else None
            
            if attachments:
                self.console.print(f"[dim]Attaching file: {attachments[0]}[/dim]")
            
            self.console.print("[yellow]Sending email...[/yellow]")
            send_stats = self.smtp_debugger.send_test_email(
                self.dashboard.email_from,
                self.dashboard.email_to,
                self.dashboard.email_subject,
                body,
                attachments
            )
            
            self.dashboard.update_stats(send_stats)
            
            if send_stats.errors:
                self.console.print(f"[red]✗ Send failed: {send_stats.errors[-1]}[/red]")
            else:
                self.console.print("[green]✓ Email sent successfully![/green]")
                self.console.print(f"[dim]Total time: {send_stats.total_time:.1f}s[/dim]")
                self.console.print(f"[dim]Bytes sent: {send_stats.bytes_sent:,}[/dim]")
            
            # Disconnect
            self.smtp_debugger.disconnect()
            
            self.console.print("[dim]Press Enter to return to dashboard...[/dim]")
            self.console.input()
            
        except Exception as e:
            self.console.print(f"[red]Error sending email: {e}[/red]")
            if self.smtp_debugger:
                self.smtp_debugger.disconnect()
            self.console.print("[dim]Press Enter to return to dashboard...[/dim]")
            self.console.input()
    
    async def main_loop(self):
        """Main application loop with Rich Live display."""
        self.console.print("[bold green]🚀 Email Investigation Tool Starting[/bold green]")
        self.console.print(f"[dim]SMTP: {self.config.smtp.host}:{self.config.smtp.port}[/dim]")
        self.console.print(f"[dim]IMAP: {self.config.imap.host}:{self.config.imap.port}[/dim]")
        self.console.print(f"[dim]Network log: {self.network_monitor.log_file_path}[/dim]")
        self.console.print()
        
        # Initial network analysis and IMAP data loading
        await self.run_network_analysis()
        await self.load_imap_data()
        
        self.console.print()
        self.console.print("[bold green]🎯 Initialization Complete - Starting Dashboard[/bold green]")
        self.console.print()
        
        with Live(self.dashboard.render(), console=self.console, refresh_per_second=2) as live:
            self.console.print("[green]Email Investigation Tool started![/green]")
            self.console.print("Commands: [cyan]T[/cyan]=Theme, [cyan]G[/cyan]=Generate File, [cyan]C[/cyan]=Compose, [cyan]S[/cyan]=Send, [cyan]N[/cyan]=Network Analysis, [cyan]I[/cyan]=Reload IMAP, [cyan]Q[/cyan]=Quit")
            
            while self.running:
                try:
                    # Update display
                    live.update(self.dashboard.render())
                    
                    # Get user input (non-blocking)
                    key = self.console.input("")
                    
                    if key.lower() == 'q':
                        self.running = False
                    elif key.lower() == 't':
                        self.dashboard.toggle_theme()
                        self.console = Console(theme=self.theme_manager.rich_theme)
                        live.console = self.console
                    elif key.lower() == 'g':
                        live.stop()
                        self.generate_test_file()
                        live.start()
                    elif key.lower() == 'c':
                        live.stop()
                        self.compose_email()
                        live.start()
                    elif key.lower() == 's':
                        live.stop()
                        await self.send_test_email()
                        live.start()
                    elif key.lower() == 'n':
                        live.stop()
                        await self.run_network_analysis()
                        live.start()
                    elif key.lower() == 'i':
                        live.stop()
                        await self.load_imap_data()
                        live.start()
                    
                    # Small delay to prevent excessive CPU usage
                    await asyncio.sleep(0.1)
                    
                except KeyboardInterrupt:
                    self.running = False
                except Exception as e:
                    self.logger.error(f"Error in main loop: {e}")
        
        # Cleanup
        self.console.print("[yellow]Stopping network monitoring and generating report...[/yellow]")
        self.network_monitor.stop_monitoring()
        
        # Generate network monitoring report
        report_file = self.network_monitor.export_report()
        self.console.print(f"[green]Network monitoring report saved: {report_file}[/green]")
        
        # Show network stats
        self.console.print(f"[cyan]{self.network_monitor.get_stats_summary()}[/cyan]")
        
        # Check for suspicious connections
        suspicious = self.network_monitor.get_suspicious_connections()
        if suspicious:
            self.console.print(f"[red]WARNING: {len(suspicious)} suspicious connections detected![/red]")
            self.console.print("[red]Review the network monitoring report for details.[/red]")
        else:
            self.console.print("[green]No suspicious network connections detected.[/green]")
        
        self.file_generator.cleanup_all()
        self.console.print("[yellow]Email Investigation Tool shutdown complete.[/yellow]")

def main():
    """Main entry point."""
    try:
        app = EmailInvestigationTool()
        asyncio.run(app.main_loop())
    except KeyboardInterrupt:
        print("\\nShutdown requested by user.")
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
