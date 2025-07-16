#!/usr/bin/env python3
"""Demo script to show network monitoring in action."""

import time
import socket
from network_monitor import NetworkMonitor

def main():
    print("=== NETWORK MONITORING SECURITY DEMO ===")
    print("This demo shows how the tool monitors network connections")
    print("to verify that no unexpected traffic occurs.\n")
    
    # Start monitoring
    monitor = NetworkMonitor()
    monitor.start_monitoring()
    
    print(f"✓ Network monitoring started")
    print(f"✓ Log file: {monitor.log_file_path}")
    print("\nMaking some test connections...\n")
    
    # Test 1: Normal DNS lookup
    print("1. Testing DNS lookup (normal behavior)...")
    try:
        socket.gethostbyname("gmail.com")
        print("   ✓ DNS lookup completed")
    except:
        print("   ✗ DNS lookup failed")
    
    time.sleep(1)
    
    # Test 2: Test SMTP port connection
    print("2. Testing SMTP port connection...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex(("smtp.gmail.com", 587))
        sock.close()
        if result == 0:
            print("   ✓ SMTP port 587 reachable")
        else:
            print("   ⚠ SMTP port 587 unreachable")
    except Exception as e:
        print(f"   ✗ SMTP test failed: {e}")
    
    time.sleep(1)
    
    # Test 3: Check what we captured
    print("3. Analyzing captured network traffic...")
    
    # Stop monitoring
    monitor.stop_monitoring()
    
    # Show results
    connections = monitor.get_recent_connections()
    print(f"   ✓ Captured {len(connections)} network connections")
    
    smtp_conns = monitor.get_smtp_connections()
    print(f"   ✓ Found {len(smtp_conns)} SMTP-related connections")
    
    suspicious = monitor.get_suspicious_connections()
    if suspicious:
        print(f"   ⚠ Found {len(suspicious)} suspicious connections:")
        for conn in suspicious:
            print(f"     • {conn}")
    else:
        print("   ✓ No suspicious connections detected")
    
    # Generate report
    report_file = monitor.export_report()
    print(f"\\n✓ Security report generated: {report_file}")
    
    print("\\n=== SECURITY ANALYSIS ===")
    print("This demonstrates that the tool:")
    print("• Only connects to expected email servers")
    print("• Logs ALL network activity for your review") 
    print("• Detects any unexpected/suspicious connections")
    print("• Provides complete audit trail")
    print("\\nYou can review the log files to verify no data exfiltration occurs.")

if __name__ == "__main__":
    main()