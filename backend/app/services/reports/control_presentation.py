"""Presentation metadata for security controls.

This module is PURELY a display layer.  It adds human-readable names,
business-language risk narratives, severity labels, and optional cost
estimates to raw control IDs.  It does not import from or affect any
execution, detection, or remediation logic.

Cost estimate ranges are sourced from IBM Cost of a Data Breach Report 2023
and Verizon Data Breach Investigations Report 2023.  They are industry
benchmarks for SMB environments and must be presented as estimates only.
"""

from typing import TypedDict, Optional


class CostEstimate(TypedDict):
    range: str
    basis: str


class ControlMeta(TypedDict):
    name: str
    short_name: str
    severity: str  # Critical | High | Medium | Low
    narrative: str  # One or two sentences for a non-technical reader
    cost_estimate: Optional[CostEstimate]


# ---------------------------------------------------------------------------
# Presentation registry — keyed by control_id
# ---------------------------------------------------------------------------

_PRESENTATION: dict[str, ControlMeta] = {
    "IDENTITY_USER_NO_MFA": {
        "name": "User Accounts Without Multi-Factor Authentication",
        "short_name": "Missing User MFA",
        "severity": "High",
        "narrative": (
            "Accounts that rely on a password alone are significantly easier to compromise "
            "through phishing or credential theft. A single stolen password gives an attacker "
            "direct access to email, files, and internal systems with no additional barrier."
        ),
        "cost_estimate": {
            "range": "$15,000 – $90,000",
            "basis": "Average SMB credential-based breach cost (IBM Cost of a Data Breach 2023)",
        },
    },
    "IDENTITY_ADMIN_NO_MFA": {
        "name": "Administrator Accounts Without Multi-Factor Authentication",
        "short_name": "Missing Admin MFA",
        "severity": "Critical",
        "narrative": (
            "Administrator accounts without MFA are the highest-value target in any environment. "
            "A compromised admin can reset passwords, disable security controls, and access all "
            "organisational data — giving an attacker complete and immediate control."
        ),
        "cost_estimate": {
            "range": "$120,000 – $500,000",
            "basis": (
                "Privileged-account breaches carry 3–5× higher remediation cost " "(Verizon DBIR 2023; IBM 2023)"
            ),
        },
    },
    "IDENTITY_UNUSED_ACCOUNT": {
        "name": "Unused User Accounts",
        "short_name": "Unused Accounts",
        "severity": "Medium",
        "narrative": (
            "Accounts with no meaningful sign-in or Microsoft 365 workload activity "
            "(email, Teams, OneDrive, SharePoint) remain valid sign-in paths. Attackers "
            "target these because they are often unmonitored and may retain broad permissions."
        ),
        "cost_estimate": {
            "range": "$10,000 – $60,000",
            "basis": "Stale-credential access vector (Verizon DBIR 2023)",
        },
    },
    "IDENTITY_ADMIN_COUNT_EXCESS": {
        "name": "Too Many Global Administrator Accounts",
        "short_name": "Excess Global Admins",
        "severity": "Critical",
        "narrative": (
            "Having more Global Administrators than necessary increases the number of accounts "
            "that can make irreversible changes to your environment. Industry guidance recommends "
            "fewer than five; each additional admin account is an additional breach path."
        ),
        "cost_estimate": {
            "range": "$80,000 – $350,000",
            "basis": "Blast-radius amplification from excess privilege (IBM 2023)",
        },
    },
    "IDENTITY_OVERPRIVILEGED_USER": {
        "name": "Users with Excessive Administrative Permissions",
        "short_name": "Over-Privileged Users",
        "severity": "High",
        "narrative": (
            "Users holding admin roles beyond what their job requires create unnecessary risk. "
            "If one of these accounts is compromised, the attacker inherits those elevated "
            "permissions immediately, with no further escalation needed."
        ),
        "cost_estimate": {
            "range": "$45,000 – $200,000",
            "basis": "Privilege misuse is a leading cause of insider and external breaches (DBIR 2023)",
        },
    },
    "IDENTITY_BREAK_GLASS_ACCOUNT": {
        "name": "Emergency Access Accounts Not Configured",
        "short_name": "Break-Glass Accounts",
        "severity": "Medium",
        "narrative": (
            "Emergency access accounts allow administrators to recover from lockout scenarios. "
            "Without them, a misconfigured policy or lost credentials can make your entire "
            "environment inaccessible. Proper setup reduces operational and business continuity risk."
        ),
        "cost_estimate": None,
    },
    "IDENTITY_BREAK_GLASS_USAGE": {
        "name": "Emergency Access Account Used — Review Required",
        "short_name": "Break-Glass Account Activity",
        "severity": "High",
        "narrative": (
            "Use of an emergency access account outside a documented incident is a significant "
            "security signal. This activity should be reviewed immediately to confirm it was "
            "authorised, as it may indicate a compromised administrative credential."
        ),
        "cost_estimate": None,
    },
    "IDENTITY_GUEST_INVITES_OPEN": {
        "name": "External Guest Access Is Unrestricted",
        "short_name": "Open Guest Invitations",
        "severity": "Medium",
        "narrative": (
            "When any user can invite external guests, sensitive data can be shared outside "
            "the organisation without oversight. Restricting guest invitations to administrators "
            "ensures all external access is intentional and auditable."
        ),
        "cost_estimate": {
            "range": "$20,000 – $80,000",
            "basis": "Data exfiltration via oversharing (IBM 2023 — cloud misconfiguration category)",
        },
    },
    "IDENTITY_USER_CONSENT_POLICY": {
        "name": "Users Can Grant Third-Party App Access Without Approval",
        "short_name": "Unrestricted App Consent",
        "severity": "High",
        "narrative": (
            "When users can approve third-party applications themselves, malicious OAuth apps "
            "can gain access to email, contacts, and files without triggering any security alert. "
            "Requiring administrator approval for all app consent closes this attack path."
        ),
        "cost_estimate": {
            "range": "$30,000 – $150,000",
            "basis": "OAuth phishing and consent-grant attacks (Verizon DBIR 2023)",
        },
    },
    "IDENTITY_ILLICIT_CONSENT_GRANTS": {
        "name": "Suspicious Application Permissions Already Granted",
        "short_name": "Illicit Consent Grants",
        "severity": "High",
        "narrative": (
            "Applications with existing consent grants may already have access to organisational "
            "data. These grants should be reviewed immediately to determine whether any "
            "unauthorised application has been given persistent access."
        ),
        "cost_estimate": {
            "range": "$40,000 – $180,000",
            "basis": "Persistent OAuth access is a key exfiltration vector (Verizon DBIR 2023)",
        },
    },
    "CA_MFA_ALL_USERS": {
        "name": "Conditional Access: MFA Not Enforced for All Users",
        "short_name": "CA — MFA All Users",
        "severity": "High",
        "narrative": (
            "A Conditional Access policy enforcing MFA for all users is the most effective "
            "single control for preventing account compromise. Without it, sign-in from any "
            "device or location is protected only by a password."
        ),
        "cost_estimate": {
            "range": "$15,000 – $90,000",
            "basis": "Credential-based attacks account for 49% of breaches (DBIR 2023)",
        },
    },
    "CA_MFA_ADMINS": {
        "name": "Conditional Access: MFA Not Enforced for Administrators",
        "short_name": "CA — MFA Admins",
        "severity": "Critical",
        "narrative": (
            "Administrator sign-ins without MFA enforcement represent the highest single "
            "preventable risk in most environments. This policy should be active in enforcement "
            "mode, not report-only, to provide real protection."
        ),
        "cost_estimate": {
            "range": "$120,000 – $500,000",
            "basis": "Admin credential compromise (IBM 2023; Verizon DBIR 2023)",
        },
    },
    "CA_LEGACY_AUTH_BLOCK": {
        "name": "Legacy Authentication Protocols Are Not Blocked",
        "short_name": "Legacy Auth Not Blocked",
        "severity": "High",
        "narrative": (
            "Legacy protocols such as IMAP and SMTP do not support modern MFA, making any "
            "account that uses them vulnerable to password spray attacks. Blocking these "
            "protocols forces all sign-ins through modern, MFA-capable authentication flows."
        ),
        "cost_estimate": {
            "range": "$20,000 – $100,000",
            "basis": "Password spray via legacy auth — common initial access vector (DBIR 2023)",
        },
    },
    "CA_DEVICE_CODE_FLOW_BLOCK": {
        "name": "Device Code Flow Authentication Is Not Blocked",
        "short_name": "Device Code Flow",
        "severity": "Medium",
        "narrative": (
            "The device code flow is a legitimate sign-in method for devices without browsers, "
            "but attackers exploit it in phishing campaigns to bypass MFA. Blocking it unless "
            "explicitly required removes this attack path with minimal operational impact."
        ),
        "cost_estimate": None,
    },
    "CA_AUTHENTICATION_TRANSFER_BLOCK": {
        "name": "Authentication Transfer Is Not Blocked",
        "short_name": "Auth Transfer",
        "severity": "High",
        "narrative": (
            "Authentication transfer can be abused to move a valid sign-in session between devices "
            "or flows in ways users do not expect. Blocking it removes another low-friction path "
            "for phishing-assisted token abuse."
        ),
        "cost_estimate": None,
    },
    "CA_GUEST_MFA": {
        "name": "Guest and External Users Are Not Required to Use MFA",
        "short_name": "Guest MFA",
        "severity": "High",
        "narrative": (
            "External collaboration accounts often have weaker oversight than employee accounts. "
            "Requiring MFA for guests and external users reduces the chance that a compromised "
            "partner or guest identity can be used to access shared data."
        ),
        "cost_estimate": {
            "range": "$20,000 – $100,000",
            "basis": "External collaboration abuse and oversharing risk (IBM 2023 cloud misconfiguration category)",
        },
    },
    "CA_BREAK_GLASS_EXCLUSION": {
        "name": "Emergency Accounts Not Excluded from Conditional Access Policies",
        "short_name": "CA Break-Glass Exclusion",
        "severity": "Low",
        "narrative": (
            "Emergency access accounts must be excluded from Conditional Access policies so "
            "they remain usable during a lockout. Without this exclusion, a misconfigured policy "
            "can make the environment completely inaccessible with no recovery path."
        ),
        "cost_estimate": None,
    },
}

# ---------------------------------------------------------------------------
# Severity ordering (used for sorting in the executive summary)
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: dict[str, int] = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
}

# ---------------------------------------------------------------------------
# Score-to-narrative mapping
# ---------------------------------------------------------------------------

_SCORE_NARRATIVES: list[tuple[int, str, str]] = [
    # (min_score, label, narrative)
    (
        80,
        "Strong",
        "Your identity security posture is strong. Core controls are in place and "
        "the environment aligns with common cyber insurance expectations. "
        "Continue monitoring to maintain this standard.",
    ),
    (
        60,
        "Moderate",
        "Your identity security posture is at a moderate level. Several controls are "
        "in place, but the gaps identified in this report carry real business risk and "
        "should be addressed before your next insurance review or renewal.",
    ),
    (
        40,
        "Elevated Risk",
        "Your identity security posture shows elevated risk. The findings in this report "
        "represent controls that attackers actively exploit. Addressing the critical items "
        "should be prioritised immediately.",
    ),
    (
        0,
        "High Risk",
        "Your identity security posture requires urgent attention. Multiple high-severity "
        "controls are not in place, which significantly increases the likelihood of a "
        "successful account compromise or data breach.",
    ),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def enrich_control(control_id: str, *, include_cost_estimate: bool = True) -> dict:
    """Return a presentation-enriched dict for a given control_id.

    Always includes: control_id, name, short_name, severity, narrative.
    Includes cost_estimate when include_cost_estimate=True AND the control
    has a defined estimate.  Returns a graceful fallback for unknown IDs.
    """
    meta = _PRESENTATION.get(control_id)
    if meta is None:
        return {
            "control_id": control_id,
            "name": control_id.replace("_", " ").title(),
            "short_name": control_id,
            "severity": "Unknown",
            "narrative": "No additional detail is available for this control.",
            "cost_estimate": None,
        }

    result: dict = {
        "control_id": control_id,
        "name": meta["name"],
        "short_name": meta["short_name"],
        "severity": meta["severity"],
        "narrative": meta["narrative"],
    }

    if include_cost_estimate:
        result["cost_estimate"] = meta.get("cost_estimate")

    return result


def severity_sort_key(control_id: str) -> int:
    """Return a sort key (lower = higher severity) for a control_id."""
    meta = _PRESENTATION.get(control_id)
    if meta is None:
        return 99
    return _SEVERITY_ORDER.get(meta["severity"], 99)


def get_score_narrative(score: int | None) -> dict:
    """Return a label and narrative sentence for a posture score."""
    if score is None:
        return {
            "label": "Not yet assessed",
            "narrative": "No posture scan has been completed for this environment yet.",
        }
    for min_score, label, narrative in _SCORE_NARRATIVES:
        if score >= min_score:
            return {"label": label, "narrative": narrative}
    return {"label": "High Risk", "narrative": _SCORE_NARRATIVES[-1][2]}
