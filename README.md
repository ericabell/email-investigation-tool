# Email Investigation Tool

A comprehensive Python-based email debugging and investigation tool designed for SMTP troubleshooting, large file attachment testing, and ISP interference detection. Perfect for diagnosing email delivery issues, testing server configurations, and analyzing network paths.

## =€ Features

### SMTP Debugging & Analysis
- **Protocol-level logging** with detailed SMTP command/response tracking
- **SSL/TLS support** for both port 465 (SMTPS) and STARTTLS
- **Large file testing** with attachments up to 20MB+
- **Chunked transfer monitoring** for large messages
- **Authentication debugging** with credential protection
- **Real-time connection monitoring** with timing analysis

### Network Analysis
- **DNS resolution monitoring** with response time tracking
- **Network path analysis** using traceroute
- **ISP interference detection** with suspicious behavior alerts
- **Port scanning** for SMTP services (25, 465, 587, 2525)
- **Connection quality assessment** with RTT measurements

### Email Composition & Testing
- **Interactive email composition** with To/From/Subject fields
- **Test file generation** (random, pattern, or binary data)
- **GPG integration** for email signing and encryption
- **Size analysis** with encoding overhead tracking
- **IMAP folder browsing** and inbox message retrieval

### Security & Monitoring
- **Network traffic monitoring** for security verification
- **Process-specific connection tracking** to detect data exfiltration
- **Comprehensive logging** with separate files for debugging
- **Credential protection** with sanitized logs

### User Interface
- **Rich terminal dashboard** with real-time updates
- **Light/dark theme support** for terminal compatibility
- **Interactive commands** with live status updates
- **Detailed error reporting** with troubleshooting hints

## =æ Installation

### Prerequisites
- Python 3.8+
- Optional: GPG for email encryption/signing

### Using uv (Recommended)
```bash
git clone https://github.com/ericabell/email-investigation-tool.git
cd email-investigation-tool
uv sync
```

### Using pip
```bash
git clone https://github.com/ericabell/email-investigation-tool.git
cd email-investigation-tool
pip install -r requirements.txt
```

## ™ Configuration

1. **Copy the example environment file:**
   ```bash
   cp .env.example .env
   ```

2. **Edit `.env` with your email credentials:**
   ```env
   # SMTP Configuration
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USE_TLS=true
   SMTP_USERNAME=your_email@gmail.com
   SMTP_PASSWORD=your_app_password
   
   # IMAP Configuration
   IMAP_HOST=imap.gmail.com
   IMAP_PORT=993
   IMAP_USE_SSL=true
   IMAP_USERNAME=your_email@gmail.com
   IMAP_PASSWORD=your_app_password
   ```

3. **For Gmail users:** Use [App Passwords](https://support.google.com/accounts/answer/185833) instead of your regular password.

## <¯ Usage

### Basic Usage
```bash
python main.py
```

### Dashboard Commands
- **T** - Toggle light/dark theme
- **G** - Generate test file for attachment
- **C** - Compose email (To, From, Subject)
- **S** - Send test email with debugging
- **N** - Run network analysis
- **I** - Reload IMAP folder data
- **Q** - Quit application

### Example Workflow
1. Start the tool: `python main.py`
2. Generate a test file: Press **G** ’ Choose size (e.g., 5MB)
3. Compose email: Press **C** ’ Enter recipient details
4. Send with debugging: Press **S** ’ Watch real-time SMTP protocol
5. Review logs in `logs/` directory

## =Ê Output & Logging

### Real-time Dashboard
- **Connection Status**: Live SMTP/IMAP connection monitoring
- **Network Analysis**: DNS, traceroute, and port scan results
- **Email Composition**: Current message details and GPG status
- **SMTP Protocol**: Real-time command/response logging
- **Statistics**: Timing, size, and performance metrics

### Log Files
- `logs/email_debug_*.log` - Detailed SMTP/IMAP debugging
- `logs/network_traffic_*.log` - Network connection monitoring
- `logs/network_report_*.json` - Network analysis report

## =' Advanced Features

### Large File Testing
Generate test files up to 20MB+ for attachment testing:
```python
# Random data
file_info = file_generator.generate_file(size_mb=10)

# Pattern-based data
file_info = file_generator.generate_patterned_file(size_mb=5)

# Binary data
file_info = file_generator.generate_binary_file(size_mb=15)
```

### GPG Integration
- Automatically detects available GPG keys
- Supports email signing and encryption
- Tracks encryption overhead and performance
- Secure key management with user prompts

### Network Analysis
- **DNS Resolution**: Monitors response times and IP addresses
- **Traceroute**: Maps network path with hop-by-hop analysis
- **Port Scanning**: Tests common SMTP ports for availability
- **ISP Detection**: Identifies potential interference patterns

## =á Security Features

### Credential Protection
- Environment variables for sensitive data
- Sanitized logs with `[CREDENTIALS HIDDEN]` markers
- Network monitoring to detect data exfiltration
- Process-specific connection tracking

### Network Monitoring
- Real-time connection monitoring for security verification
- Suspicious connection detection and alerts
- Comprehensive network traffic logs
- Process isolation to prevent noise

## =Ë Common Use Cases

### SMTP Troubleshooting
- Debug connection failures and timeouts
- Analyze authentication issues
- Test different ports and encryption methods
- Monitor large file upload performance

### ISP Interference Detection
- Identify port blocking or throttling
- Detect connection manipulation
- Analyze network path anomalies
- Monitor for suspicious behavior patterns

### Email Server Testing
- Validate SMTP server configurations
- Test attachment size limits
- Verify SSL/TLS certificate handling
- Benchmark server performance

### Security Analysis
- Monitor for credential leakage
- Detect unexpected network connections
- Verify GPG encryption/signing
- Audit network traffic patterns

## = Troubleshooting

### Common Issues

**Connection Timeouts:**
- Check firewall settings
- Verify SMTP server and port
- Test different encryption methods (SSL vs STARTTLS)

**Authentication Failures:**
- Use App Passwords for Gmail/Outlook
- Verify username/password in `.env`
- Check if 2FA is enabled

**Large File Issues:**
- Monitor server size limits
- Check ISP throttling
- Verify network stability
- Review attachment encoding overhead

**Network Analysis Problems:**
- Run with elevated permissions for traceroute
- Check DNS resolution
- Verify firewall rules
- Test network connectivity

## > Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## =Ä License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## =O Acknowledgments

- Built with [Rich](https://github.com/Textualize/rich) for beautiful terminal UI
- Uses [psutil](https://github.com/giampaolo/psutil) for network monitoring
- Inspired by the need for comprehensive email debugging tools

---

**  Disclaimer**: This tool is for legitimate email debugging and testing purposes only. Always ensure you have proper authorization before testing email systems.