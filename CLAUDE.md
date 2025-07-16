# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

The `email-investigation-tool` is a comprehensive SMTP debugging and ISP interference detection tool designed for investigating issues with large email attachments (especially around 20MB). It provides real-time protocol visualization, network path analysis, and comprehensive logging to identify why emails fail to send.

## Architecture

### Core Components
- **main.py**: Main application orchestrator with Rich Live dashboard
- **smtp_client.py**: Enhanced SMTP client with detailed protocol logging and SSL/TLS support (port 465 + STARTTLS)
- **network_analyzer.py**: Network path analysis, DNS resolution, traceroute, and ISP detection
- **dashboard.py**: Rich-based multi-panel dashboard with real-time updates
- **themes.py**: Light/dark mode theme system for terminal compatibility
- **file_generator.py**: Generates test files up to 20MB+ with various patterns
- **gpg_manager.py**: GPG integration for email signing and encryption with size tracking
- **config.py**: Configuration management with .env file support
- **imap_client.py**: IMAP folder browsing and inbox message retrieval
- **network_monitor.py**: Process-specific network traffic monitoring for security verification

### Key Features
- **Real-time SMTP Protocol Logging**: Complete conversation logging with timing
- **ISP Interference Detection**: Analyzes connection patterns, port blocking, throttling
- **Large File Testing**: Generates files up to 20MB+ for attachment testing
- **Network Path Analysis**: Traceroute, DNS resolution, port scanning
- **GPG Support**: Email signing/encryption with overhead analysis
- **Theme System**: Light/dark mode for different terminal backgrounds

## Development Commands

### Setup
```bash
# Install dependencies (recommended: use uv)
uv sync
# Alternative: pip install -r requirements.txt

# Copy environment template
cp .env.example .env
# Edit .env with your SMTP/IMAP credentials
```

### Running the Application
```bash
python main.py
```

### Testing Commands
```bash
# No specific test framework - use the interactive testing features
# Generate test files: G command in application
# Send test emails: S command in application
# Network analysis: N command in application
```

### Interactive Commands (in application)
- `T` - Toggle light/dark theme
- `G` - Generate test file (various sizes and types)
- `C` - Compose email (To, From, Subject, GPG options)
- `S` - Send test email with full debugging
- `N` - Run network analysis
- `I` - Reload IMAP folder data
- `Q` - Quit application

## Configuration

The application requires a `.env` file with SMTP/IMAP credentials:
```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_app_password
```

## Key Debugging Features

### SMTP Protocol Analysis
- Complete command/response logging with timestamps
- TLS negotiation details
- Authentication timing
- Chunked transfer monitoring for large files
- Base64 encoding overhead calculation

### ISP Interference Detection
- Port blocking detection (25, 465, 587, 2525)
- Connection reset monitoring
- Traffic throttling analysis
- DNS manipulation detection
- Deep packet inspection signatures

### Large File Handling
- Files up to 20MB+ generation
- Multiple file types: random, pattern, binary
- Size explosion tracking (original → Base64 → encrypted)
- Memory usage monitoring
- Chunk transfer analysis

### Network Traffic Monitoring & Security
- **Real-time network monitoring** of the application's connections
- **Process-specific traffic filtering** (eliminates noise from other apps)
- **Suspicious connection detection** (unexpected hosts/ports)
- **Comprehensive network logs** in `logs/network_traffic_<timestamp>.log`
- **Automatic security reporting** on shutdown with connection analysis
- **Credential safety verification** - monitors for unexpected outbound connections

## Logging

All communications and network activity are logged to:
- **Real-time dashboard display** - Live protocol visualization
- **Email debug log**: `logs/email_debug_<timestamp>.log` - SMTP/IMAP operations
- **Network traffic log**: `logs/network_traffic_<timestamp>.log` - All network connections
- **Network report**: `logs/network_report_<timestamp>.txt` - Summary report on shutdown
- **Console output** with structured format

## Dependencies

Critical dependencies for core functionality:
- `rich` - Terminal UI and theming
- `python-dotenv` - Environment configuration
- `python-gnupg` - GPG operations
- `dnspython` - DNS resolution analysis
- `scapy` - Network packet analysis
- `psutil` - System resource monitoring

## Important Implementation Details

### SMTP SSL/TLS Handling
The tool correctly handles both SSL and TLS connections:
- **Port 465**: Uses `SMTP_SSL` for immediate SSL connection
- **Port 587**: Uses `SMTP` with `STARTTLS` for opportunistic TLS
- **Port 25**: Plain SMTP (usually blocked by ISPs)
- **Port 2525**: Alternative submission port

### Network Security
- **Process-specific monitoring**: Only tracks connections from the current Python process
- **Credential protection**: Sanitizes all logs to prevent credential leakage
- **Suspicious connection detection**: Alerts on unexpected outbound connections
- **Comprehensive auditing**: Full network traffic logs for security verification

### Error Handling
- **Graceful degradation**: Network analysis continues even if some components fail
- **Timeout management**: Prevents hanging on slow network operations
- **User feedback**: Clear error messages and troubleshooting hints
- **Recovery mechanisms**: Automatic retry and fallback strategies

### Performance Considerations
- **Chunked transfers**: Handles large files efficiently with 8KB chunks
- **Memory management**: Streams large files rather than loading entirely into memory
- **Async operations**: Network analysis runs concurrently where possible
- **Resource cleanup**: Proper cleanup of temporary files and connections

## Development Notes

This tool is specifically designed for debugging SMTP issues with large attachments where ISP interference is suspected. The comprehensive logging and network analysis capabilities make it ideal for identifying exactly where and why email transfers fail.

### Recent Fixes
- Fixed SMTP_SSL constructor parameter mismatch for port 465 connections
- Improved interactive prompt handling with Live dashboard
- Enhanced traceroute timeout handling to prevent hanging
- Added comprehensive network traffic monitoring for security verification