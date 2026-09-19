"""Rule-based risk scoring for scanned ports."""

from __future__ import annotations

from typing import Optional, Tuple, List

# -- Data-driven rule table -------------------------------------------------
# Each rule: (port?, service?, banner_substr?, level, rationale)
#   port / service / banner_substr may be None (matches anything).
# banner_substr is a tuple of lowercase substrings; the banner must contain
# at least one of them to match (or None matches any banner).
# First matching rule *in list order* wins — order is severity priority
# (critical first, then high, medium, low, informational).

# Banner substring patterns used by multiple rules.
_VS_FTP = ("vsftpd 2.3.4",)           # known backdoor
_SAMBA_OLD = ("3.0.", "samba 3.")     # old vulnerable samba versions
_SSH_VERSION = ("ssh-2.0-",)          # any SSH banner that reveals version
_HTTP_VERSION = ("server:",)          # HTTP response with Server: header present
_SMTP_BANNER = ("220 ",)              # SMTP 220 greeting present


RISK_RULES: List[Tuple[
    Optional[int], Optional[str], Optional[Tuple[str, ...]], str, str
]] = [
    # ===== critical =====
    # RDP exposed - always critical regardless of banner
    (3389, None, None, "critical",
     "Remote Desktop Protocol (RDP) is exposed. RDP is a frequent attack surface; "
     "ensure it is not directly internet-facing without MFA."),
    # Telnet open - always critical
    (23, None, None, "critical",
     "Telnet is unencrypted and often targeted. Replace with SSH; disable Telnet if not required."),
    # FTP with known-vsFTPd backdoor banner - critical
    (21, "ftp", _VS_FTP, "critical",
     "vsFTPd 2.3.4 contains a known backdoor (CVE-2011-2523). This version should "
     "never be internet-exposed."),
    # DNS on non-standard high port for DNS is informational, but DNS on port 53 is fine.
    # ===== high =====
    # Database ports - always high when service matches, banner doesn't change it
    (3306, "mysql", None, "high",
     "MySQL database port exposed. Databases should not be directly reachable from "
     "untrusted networks unless explicitly required."),
    (5432, "postgresql", None, "high",
     "PostgreSQL database port exposed. Databases should not be directly reachable "
     "from untrusted networks."),
    (6379, "redis", None, "high",
     "Redis port exposed. Redis often runs without authentication by default; ensure "
     "it is not internet-facing."),
    (27017, "mongodb", None, "high",
     "MongoDB port exposed. MongoDB instances should be protected by authentication "
     "and not exposed to the public internet."),
    # SNMP - high regardless of banner
    (161, "snmp", None, "high",
     "SNMP service is exposed. SNMP can reveal sensitive network information. Use "
     "SNMPv3 with strong community strings and restrict access."),
    (162, "snmp-trap", None, "high",
     "SNMP trap service is exposed. SNMP can reveal sensitive network information; "
     "use SNMPv3 and restrict access."),
    # SSH with identifiable version banner - high
    (22, "ssh", _SSH_VERSION, "high",
     "SSH service is exposed with an identifiable version banner. Version disclosure "
     "aids attackers — consider restricting access by IP and keeping the server updated."),
    # VNC - high
    (5900, "vnc", None, "high",
     "VNC remote desktop service is exposed. VNC often lacks strong encryption; ensure "
     "it is tunnelled over SSH or restricted to trusted networks."),
    (5800, "vnc-alt", None, "high",
     "Alternative VNC port exposed. VNC often lacks strong encryption; tunnel over SSH "
     "or restrict to trusted networks."),
    # ===== medium =====
    # SSH without version-identifiable banner (banner absent or no version string) - medium
    (22, "ssh", None, "medium",
     "SSH service is enabled on a standard port. Ensure key-based authentication, disable "
     "root login if not needed, and consider restricting access by IP."),
    # HTTP plaintext - medium (banner doesn't change level; if banner present, still medium)
    (80, "http", None, "medium",
     "HTTP service detected on port 80. Plain HTTP transmits data unencrypted. Consider "
     "redirecting to HTTPS or restricting access."),
    # HTTPS - medium
    (443, "https", None, "medium",
     "HTTPS service detected on port 443. While encrypted, exposed HTTPS endpoints should "
     "be reviewed for necessity, certificate validity, and TLS configuration."),
    # HTTP proxy on non-standard port
    (8080, "http-proxy", None, "medium",
     "HTTP proxy on a non-standard port. Ensure proxy access is restricted and not open "
     "to external networks."),
    # HTTPS on non-standard port
    (8443, "https-alt", None, "medium",
     "HTTPS on a non-standard port with service detected. Confirm it is intentionally "
     "exposed and properly secured."),
    # MSSQL - medium (less common than MySQL/PostgreSQL but still notable)
    (1433, "mssql", None, "medium",
     "Microsoft SQL Server port detected. Ensure the database is not directly exposed "
     "to the internet and uses strong authentication."),
    # Oracle DB
    (1521, "oracle-db", None, "medium",
     "Oracle Database port detected. Ensure it is not internet-facing unless required "
     "and protected by firewalls and authentication."),
    # SMTP with banner (identifiable) - medium; without banner we still match this rule
    # because it's the only SMTP rule and it doesn't require a banner pattern
    (25, "smtp", None, "medium",
     "SMTP service exposed. Mail servers are frequent spam-relay targets; ensure proper "
     "relay restrictions and authentication."),
    # ===== low =====
    # POP3 - low regardless
    (110, "pop3", None, "low",
     "POP3 service exposed. POP3 transmits credentials in cleartext by default; prefer "
     "POP3S (995) and restrict access."),
    # IMAP - low regardless
    (143, "imap4", None, "low",
     "IMAP service exposed. Unencrypted IMAP transmits credentials in cleartext; prefer "
     "IMAPS (993) and restrict access."),
    # ===== informational =====
    # DNS on standard port
    (53, "domain", None, "informational",
     "DNS service detected on standard port 53. Confirm it is intended to be reachable "
     "and restricted to authorised resolvers."),
    # Standard HTTP/HTTPS with a version-identifiable banner - informational (version known, no obvious vuln)
    # Placed after medium rules so banner-present web services still get medium, but if we want
    # to downgrade to informational when banner shows a recent version we'd add more rules.
    # For v1 we keep web at medium even with banner.
]


def _banner_matches(
    banner: Optional[str],
    substrings: Optional[Tuple[str, ...]],
) -> bool:
    """Return True if *banner* (lowercased) contains any of *substrings*.

    If *substrings* is None, any banner (including None) matches.
    If *banner* is None and *substrings* is not None, returns False.
    """
    if substrings is None:
        return True
    if banner is None:
        return False
    banner_lower = banner.lower()
    return any(s.lower() in banner_lower for s in substrings)


def assess_risk(
    port: int,
    service: str,
    banner: Optional[str],
) -> Tuple[str, str]:
    """Apply the rule table to determine risk level and rationale.

    Returns ``(level, rationale)`` where *level* is one of:
    ``informational``, ``low``, ``medium``, ``high``, ``critical``.
    """
    for port_rule, svc_rule, banner_substrs, level, rationale in RISK_RULES:
        port_ok = (port_rule is None) or (port == port_rule)
        svc_ok = (svc_rule is None) or (service == svc_rule)
        banner_ok = _banner_matches(banner, banner_substrs)

        if port_ok and svc_ok and banner_ok:
            return (level, rationale)

    # Fallback: unmatched port.
    if port <= 1023:
        return (
            "informational",
            f"Well-known port {port} opened with no specific risk rule matched. "
            f"Detected service: '{service}'.",
        )
    return (
        "high",
        f"Non-standard port {port} is open with no known service mapping "
        f"(detected service: '{service}'). Unknown services on non-standard ports "
        f"carry elevated risk because their purpose and security posture are uncertain.",
    )
