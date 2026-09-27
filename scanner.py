"""
Safe local-network scanner for CCTV Cam Scanner Radar.

No authentication attempts, no exploits, no video-stream access.
Only:
- private IPv4 target validation
- TCP connect checks
- optional HTTP HEAD banner read
"""

import ipaddress
import socket
import time
from http.client import HTTPConnection

# Common ports seen on IP cameras/NVRs and embedded web interfaces.
# We only test whether TCP accepts a connection.
CAMERA_PORTS = (80, 443, 554, 8000, 8080, 8081, 8443, 8554, 8899)

CAMERA_HINTS = (
    "camera", "ipcam", "webcam", "nvr", "dvr", "hikvision",
    "dahua", "axis", "uniview", "ubiquiti", "reolink", "vivotek",
    "surveillance"
)

def get_local_ipv4():
    """Best-effort local IPv4 detection without sending application data."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))
        return s.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "192.168.1.10"
    finally:
        s.close()

def get_default_private_cidr():
    ip = get_local_ipv4()
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version == 4 and addr.is_private:
            parts = ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except ValueError:
        pass
    return "192.168.1.0/24"

def is_allowed_private_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return addr.version == 4 and (addr.is_private or addr.is_loopback or addr.is_link_local)
    except ValueError:
        return False

def tcp_open(ip, port, timeout):
    if not is_allowed_private_ip(ip):
        return False, None

    start = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        code = sock.connect_ex((ip, port))
        latency_ms = round((time.perf_counter() - start) * 1000, 1)
        return code == 0, latency_ms
    except OSError:
        return False, None
    finally:
        sock.close()

def http_head_server(ip, port, timeout):
    """Read only standard HTTP response metadata. No login or camera path is requested."""
    if port not in (80, 8000, 8080, 8081, 8899):
        return ""

    conn = HTTPConnection(ip, port=port, timeout=timeout)
    try:
        conn.request("HEAD", "/", headers={"User-Agent": "CCTV-Radar-Authorized-Scanner/1.0"})
        resp = conn.getresponse()
        server = resp.getheader("Server", "") or ""
        realm = resp.getheader("WWW-Authenticate", "") or ""
        combined = " ".join(x for x in (server, realm) if x).strip()
        return combined[:160]
    except Exception:
        return ""
    finally:
        try:
            conn.close()
        except Exception:
            pass

def classify(open_ports, server_header):
    if not open_ports:
        return "No tested service", False

    text = (server_header or "").lower()
    hint_match = any(word in text for word in CAMERA_HINTS)

    # RTSP is a strong CCTV/IP-camera/NVR indicator, but still not proof.
    if 554 in open_ports or 8554 in open_ports:
        return "Possible camera/NVR (RTSP service)", True

    if hint_match:
        return "Possible camera/NVR (HTTP banner hint)", True

    # Port 8000 is common on embedded camera systems but is not unique to them.
    if 8000 in open_ports and any(p in open_ports for p in (80, 443, 8080, 8443)):
        return "Possible embedded camera/NVR service", True

    return "Network device / web service", False

def scan_host(ip, timeout=0.35):
    if not is_allowed_private_ip(ip):
        raise ValueError("Refusing to scan non-private IP address.")

    open_ports = []
    best_latency = None

    for port in CAMERA_PORTS:
        is_open, latency = tcp_open(ip, port, timeout)
        if is_open:
            open_ports.append(port)
            if latency is not None:
                best_latency = latency if best_latency is None else min(best_latency, latency)

    server_header = ""
    for port in (80, 8000, 8080, 8081, 8899):
        if port in open_ports:
            server_header = http_head_server(ip, port, timeout)
            if server_header:
                break

    assessment, possible = classify(open_ports, server_header)
    reachable = bool(open_ports)

    return {
        "ip": ip,
        "reachable": reachable,
        "open_ports": open_ports,
        "assessment": assessment,
        "server": server_header,
        "latency_ms": best_latency if best_latency is not None else "",
        "possible_camera": possible,
    }
