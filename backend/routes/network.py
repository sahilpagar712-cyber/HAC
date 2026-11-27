"""Network info endpoint: safe passive local network information."""

import socket
import datetime
import platform
from fastapi import APIRouter
from schemas import NetworkInfoResponse

router = APIRouter(prefix="/api/network", tags=["Network Monitor"])


@router.get("/info", response_model=NetworkInfoResponse)
def get_network_info():
    hostname = socket.gethostname()

    # Get local IP (safe passive check)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1)
        s.connect(("8.8.8.8", 80))  # Does NOT send any data, just resolves local route
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "127.0.0.1"

    # Gather interface info using socket
    interfaces = []
    try:
        addrs = socket.getaddrinfo(hostname, None)
        seen = set()
        for addr in addrs:
            ip = addr[4][0]
            family = "IPv4" if addr[0] == socket.AF_INET else "IPv6"
            key = f"{family}:{ip}"
            if key not in seen:
                seen.add(key)
                interfaces.append({
                    "address": ip,
                    "family": family,
                    "hostname": hostname,
                })
    except Exception:
        interfaces = [{"address": local_ip, "family": "IPv4", "hostname": hostname}]

    return NetworkInfoResponse(
        hostname=hostname,
        local_ip=local_ip,
        interfaces=interfaces,
        checked_at=datetime.datetime.utcnow(),
    )
