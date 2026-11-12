IDENTITY_CONTROL_GUIDANCE = {
    "IDENTITY_USER_CONSENT_POLICY": {
        "title": "Users can consent to OAuth applications",
        "severity": "HIGH",
        "summary": ("Users can grant application permissions without administrator approval."),
        "manual_steps": [
            "Disable user consent for applications",
            "Enable admin consent workflow",
        ],
    },
    "IDENTITY_GUEST_INVITES_OPEN": {
        "title": "Guest invitations are unrestricted",
        "severity": "MEDIUM",
        "summary": ("Any user can invite external guests, increasing external access risk."),
        "manual_steps": [
            "Restrict guest invitations to administrators only",
        ],
    },
    "IDENTITY_BREAK_GLASS_ACCOUNT": {
        "title": "Break-glass coverage is insufficient",
        "severity": "HIGH",
        "summary": (
            "At least two properly configured emergency access accounts should exist and remain outside restrictive Conditional Access coverage."
        ),
        "manual_steps": [
            "Maintain at least two cloud-only Global Administrator emergency accounts",
            "Tag them consistently with break-glass or emergency markers",
            "Exclude them from MFA and location or device Conditional Access restrictions",
            "Review password strength and storage procedures manually",
        ],
    },
}
