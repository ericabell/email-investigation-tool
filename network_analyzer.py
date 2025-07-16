"""Network analysis and ISP interference detection."""

import socket
import subprocess
import time
import dns.resolver
import dns.query
import dns.zone
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
import re

@dataclass
class DNSResult:
    """DNS resolution result."""
    hostname: str
    ip_addresses: List[str]
    mx_records: List[Tuple[int, str]]
    response_time: float
    authoritative: bool
    dnssec_valid: bool = False

@dataclass
class TracerouteHop:
    """Single hop in a traceroute."""
    hop_number: int
    ip_address: str
    hostname: Optional[str]
    response_time: float
    is_timeout: bool = False

@dataclass
class NetworkPath:
    """Complete network path analysis."""
    target_host: str
    target_ip: str
    hops: List[TracerouteHop]
    total_hops: int
    packet_loss: float
    avg_rtt: float
    isp_detected: Optional[str] = None

@dataclass
class PortScanResult:
    """Port scanning result."""
    port: int
    is_open: bool
    response_time: Optional[float] = None
    service: Optional[str] = None

@dataclass
class ISPAnalysis:
    """ISP interference analysis results."""
    isp_name: Optional[str]
    suspicious_behavior: List[str]
    blocked_ports: List[int]
    throttling_detected: bool
    dpi_detected: bool
    connection_resets: int
    recommendations: List[str]

class NetworkAnalyzer:
    """Analyzes network path and detects ISP interference."""
    
    def __init__(self):
        self.dns_resolver = dns.resolver.Resolver()
        self.analysis_cache: Dict[str, DNSResult] = {}
    
    def resolve_dns(self, hostname: str, record_type: str = 'A') -> DNSResult:
        """Resolve DNS with detailed analysis."""
        start_time = time.time()
        
        try:
            # Resolve A records
            a_records = []
            try:
                answers = self.dns_resolver.resolve(hostname, 'A')
                a_records = [str(rdata) for rdata in answers]
            except:
                pass
            
            # Resolve MX records
            mx_records = []
            try:
                mx_answers = self.dns_resolver.resolve(hostname, 'MX')
                mx_records = [(rdata.preference, str(rdata.exchange)) for rdata in mx_answers]
            except:
                pass
            
            response_time = time.time() - start_time
            
            # Check if response is authoritative (simplified)
            authoritative = len(a_records) > 0
            
            result = DNSResult(
                hostname=hostname,
                ip_addresses=a_records,
                mx_records=mx_records,
                response_time=response_time,
                authoritative=authoritative
            )
            
            self.analysis_cache[hostname] = result
            return result
            
        except Exception as e:
            return DNSResult(
                hostname=hostname,
                ip_addresses=[],
                mx_records=[],
                response_time=time.time() - start_time,
                authoritative=False
            )
    
    def traceroute(self, target: str, max_hops: int = 15) -> NetworkPath:
        """Perform traceroute to target."""
        hops = []
        consecutive_timeouts = 0
        
        try:
            # Use system traceroute command with aggressive timeouts to avoid hanging
            cmd = ['traceroute', '-n', '-m', str(max_hops), '-w', '1', target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            lines = result.stdout.strip().split('\n')[1:]  # Skip header
            
            for line in lines:
                if not line.strip():
                    continue
                
                # Parse traceroute output
                parts = line.strip().split()
                if len(parts) >= 2:
                    try:
                        hop_num = int(parts[0])
                        
                        # Check for timeout lines
                        if line.count('*') >= 3:
                            consecutive_timeouts += 1
                            # If we hit 3 consecutive timeouts, we've likely reached the target network
                            # and the server is just not responding - stop here
                            if consecutive_timeouts >= 3:
                                break
                            continue
                        else:
                            consecutive_timeouts = 0  # Reset timeout counter
                        
                        # Extract IP address - look for patterns like (IP) or standalone IP
                        ip_addr = None
                        hostname = None
                        
                        # Look for IP in parentheses first (most common)
                        ip_match = re.search(r'\(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)', line)
                        if ip_match:
                            ip_addr = ip_match.group(1)
                            # Hostname is typically before the parentheses
                            hostname_match = re.search(r'\s+([^\s]+)\s+\(' + re.escape(ip_addr) + r'\)', line)
                            if hostname_match:
                                hostname = hostname_match.group(1)
                        else:
                            # Look for standalone IP address
                            ip_match = re.search(r'\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', line)
                            if ip_match:
                                ip_addr = ip_match.group(1)
                        
                        # Skip if we couldn't find an IP
                        if not ip_addr:
                            continue
                        
                        # Extract timing info - get the first ms value
                        time_match = re.search(r'(\d+\.?\d*)\s*ms', line)
                        response_time = float(time_match.group(1)) if time_match else 0.0
                        
                        # Use the IP as hostname if we didn't find one
                        if not hostname:
                            hostname = ip_addr
                        
                        hop = TracerouteHop(
                            hop_number=hop_num,
                            ip_address=ip_addr,
                            hostname=hostname,
                            response_time=response_time,
                            is_timeout=is_timeout
                        )
                        hops.append(hop)
                        
                    except (ValueError, IndexError):
                        continue
        
        except subprocess.TimeoutExpired:
            # Timeout is expected for long traceroutes - this is normal
            pass
        except FileNotFoundError:
            # Fallback if traceroute command not available
            pass
        except Exception as e:
            # Other errors - just continue
            pass
        
        # If we got no hops from traceroute, create a simple connectivity test
        if not hops:
            try:
                # Simple connectivity test to at least show we can reach the target
                import socket
                target_ip = socket.gethostbyname(target)
                
                # Test connectivity with a simple socket connection
                start_time = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((target_ip, 80))  # Test port 80
                sock.close()
                response_time = (time.time() - start_time) * 1000  # Convert to ms
                
                if result == 0:
                    # Connection successful, create a simple "hop"
                    hop = TracerouteHop(
                        hop_number=1,
                        ip_address=target_ip,
                        hostname=target,
                        response_time=response_time,
                        is_timeout=False
                    )
                    hops.append(hop)
            except Exception:
                # If everything fails, that's okay - we'll just show empty results
                pass
        
        # Calculate statistics
        valid_hops = [h for h in hops if not h.is_timeout]
        avg_rtt = sum(h.response_time for h in valid_hops) / len(valid_hops) if valid_hops else 0
        packet_loss = (len(hops) - len(valid_hops)) / len(hops) * 100 if hops else 0
        
        # Detect ISP from hop hostnames
        isp_detected = self._detect_isp_from_hops(hops)
        
        return NetworkPath(
            target_host=target,
            target_ip=hops[-1].ip_address if hops else "",
            hops=hops,
            total_hops=len(hops),
            packet_loss=packet_loss,
            avg_rtt=avg_rtt,
            isp_detected=isp_detected
        )
    
    def scan_smtp_ports(self, hostname: str) -> List[PortScanResult]:
        """Scan common SMTP ports."""
        smtp_ports = [25, 465, 587, 2525]
        results = []
        
        for port in smtp_ports:
            start_time = time.time()
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5.0)
                result = sock.connect_ex((hostname, port))
                response_time = time.time() - start_time
                sock.close()
                
                is_open = result == 0
                service = self._get_smtp_service_name(port)
                
                results.append(PortScanResult(
                    port=port,
                    is_open=is_open,
                    response_time=response_time if is_open else None,
                    service=service
                ))
                
            except Exception:
                results.append(PortScanResult(
                    port=port,
                    is_open=False,
                    service=self._get_smtp_service_name(port)
                ))
        
        return results
    
    def analyze_isp_interference(self, hostname: str, port: int) -> ISPAnalysis:
        """Analyze potential ISP interference."""
        suspicious_behavior = []
        blocked_ports = []
        recommendations = []
        
        # Scan SMTP ports
        port_results = self.scan_smtp_ports(hostname)
        for result in port_results:
            if not result.is_open:
                blocked_ports.append(result.port)
                if result.port == 25:
                    suspicious_behavior.append("Port 25 blocked (common ISP practice)")
        
        # Check for standard port blocking
        if 25 in blocked_ports:
            recommendations.append("Use port 587 or 465 instead of port 25")
        
        # Analyze network path
        network_path = self.traceroute(hostname)
        
        # Check for suspicious routing
        if network_path.packet_loss > 5:
            suspicious_behavior.append(f"High packet loss: {network_path.packet_loss:.1f}%")
        
        if network_path.avg_rtt > 200:
            suspicious_behavior.append(f"High latency: {network_path.avg_rtt:.1f}ms")
        
        # Check for ISP-specific issues
        if network_path.isp_detected:
            if "comcast" in network_path.isp_detected.lower():
                suspicious_behavior.append("Comcast detected - known for email restrictions")
                recommendations.append("Consider using VPN or alternative SMTP relay")
        
        # Simple DPI detection (more sophisticated detection would require packet analysis)
        dpi_detected = self._detect_dpi_signatures(hostname, port)
        
        # Throttling detection (simplified)
        throttling_detected = len(blocked_ports) > 1 or network_path.packet_loss > 2
        
        return ISPAnalysis(
            isp_name=network_path.isp_detected,
            suspicious_behavior=suspicious_behavior,
            blocked_ports=blocked_ports,
            throttling_detected=throttling_detected,
            dpi_detected=dpi_detected,
            connection_resets=0,  # Would be detected during actual SMTP session
            recommendations=recommendations
        )
    
    def _detect_isp_from_hops(self, hops: List[TracerouteHop]) -> Optional[str]:
        """Detect ISP from traceroute hop hostnames."""
        isp_patterns = {
            'comcast': ['comcast', 'xfinity'],
            'verizon': ['verizon', 'fios'],
            'att': ['att.net', 'attdns'],
            'cox': ['cox.net'],
            'charter': ['charter', 'spectrum'],
            'centurylink': ['centurylink', 'qwest'],
        }
        
        for hop in hops:
            if hop.hostname:
                hostname_lower = hop.hostname.lower()
                for isp, patterns in isp_patterns.items():
                    for pattern in patterns:
                        if pattern in hostname_lower:
                            return isp.upper()
        
        return None
    
    def _get_smtp_service_name(self, port: int) -> str:
        """Get service name for SMTP port."""
        services = {
            25: "SMTP",
            465: "SMTPS (SSL)",
            587: "SMTP (STARTTLS)",
            2525: "SMTP (Alternative)"
        }
        return services.get(port, f"Port {port}")
    
    def _detect_dpi_signatures(self, hostname: str, port: int) -> bool:
        """Simple DPI detection (placeholder - would need packet analysis)."""
        # This is a simplified check - real DPI detection would require
        # analyzing packet timing, content inspection, etc.
        
        try:
            # Quick connection test
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            start_time = time.time()
            sock.connect((hostname, port))
            
            # Send a test EHLO command
            sock.send(b"EHLO test.example.com\r\n")
            response = sock.recv(1024)
            
            response_time = time.time() - start_time
            sock.close()
            
            # If response takes unusually long, might indicate DPI
            return response_time > 5.0
            
        except Exception:
            return False
    
    def test_connection_stability(self, hostname: str, port: int, duration: int = 30) -> Dict[str, any]:
        """Test connection stability over time."""
        results = {
            'successful_connections': 0,
            'failed_connections': 0,
            'connection_times': [],
            'reset_detected': False,
            'avg_connection_time': 0.0
        }
        
        test_count = duration // 5  # Test every 5 seconds
        
        for i in range(test_count):
            try:
                start_time = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5.0)
                sock.connect((hostname, port))
                connection_time = time.time() - start_time
                sock.close()
                
                results['successful_connections'] += 1
                results['connection_times'].append(connection_time)
                
            except socket.error as e:
                results['failed_connections'] += 1
                if "reset" in str(e).lower():
                    results['reset_detected'] = True
            
            if i < test_count - 1:  # Don't sleep after last iteration
                time.sleep(5)
        
        if results['connection_times']:
            results['avg_connection_time'] = sum(results['connection_times']) / len(results['connection_times'])
        
        return results