"""Firewall status endpoint: reports CSP policy and security recommendations."""

from fastapi import APIRouter
from schemas import FirewallStatusResponse

router = APIRouter(prefix="/api/firewall", tags=["Firewall"])


@router.get("/status", response_model=FirewallStatusResponse)
def get_firewall_status():
    """
    Report the application's Content Security Policy and network security posture.
    This does NOT control the OS firewall — it reports the app-level security configuration.
    """
    return FirewallStatusResponse(
        csp_policy="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; font-src 'self' data:;",
        connect_src_locked=True,
        backend_note=(
            "The CSP connect-src directive is set to 'self', allowing API calls to the same origin "
            "(proxied via Vite dev server). No external network egress is permitted. "
            "This endpoint reports application-level policy — it does not control the OS firewall."
        ),
        recommendations=[
            "Keep CSP connect-src restricted to 'self' in production",
            "Use HTTPS with HSTS headers in production deployment",
            "Enable rate limiting on authentication endpoints",
            "Rotate JWT secret keys periodically",
            "Consider adding Subresource Integrity (SRI) for external scripts if any are added",
        ],
    )
