"""Insurance Impact Summary — six plain-language rows for Page 1.

Pure function: takes already-computed posture signals and returns a status chip
plus one business-implication sentence per category. No DB, no jargon.
"""

_STRONG = "Strong"
_MODERATE = "Moderate"
_NEEDS = "Needs Attention"


def build_insurance_impact_summary(
    *,
    mfa_enforcement_pass: bool,
    mfa_coverage_pct: int,
    admin_mfa_missing: int,
    privileged_access_pass: bool,
    identity_governance_pass: bool,
    oauth_consent_failed: bool,
    has_prior_report: bool,
    tier_state: str,
) -> list[dict]:
    rows: list[dict] = []

    # 1. MFA Enforcement
    if mfa_enforcement_pass:
        rows.append(
            {
                "category": "MFA Enforcement",
                "status": _STRONG,
                "commentary": (
                    f"Multi-factor authentication protects {mfa_coverage_pct}% of users "
                    "and every administrator, sharply reducing account-takeover risk."
                ),
            }
        )
    elif admin_mfa_missing > 0:
        rows.append(
            {
                "category": "MFA Enforcement",
                "status": _NEEDS,
                "commentary": (
                    f"{admin_mfa_missing} privileged account(s) can sign in without MFA — "
                    "a common cause of insurance claims and a frequent underwriting blocker."
                ),
            }
        )
    else:
        rows.append(
            {
                "category": "MFA Enforcement",
                "status": _MODERATE,
                "commentary": (
                    f"MFA covers {mfa_coverage_pct}% of users; closing the remaining gap "
                    "would further lower the likelihood of a compromised login."
                ),
            }
        )

    # 2. Privileged Access Controls
    rows.append(
        {
            "category": "Privileged Access Controls",
            "status": _STRONG if privileged_access_pass else _NEEDS,
            "commentary": (
                "Administrative access is limited to the smallest practical group, "
                "which contains the damage a single compromised account could cause."
                if privileged_access_pass
                else "More accounts hold administrative rights than recommended, widening the "
                "potential impact of a breach and raising access-governance questions."
            ),
        }
    )

    # 3. Identity Governance
    rows.append(
        {
            "category": "Identity Governance",
            "status": _STRONG if identity_governance_pass else _MODERATE,
            "commentary": (
                "Accounts and roles are actively reviewed and kept current, supporting "
                "least-privilege and clean joiner/leaver hygiene."
                if identity_governance_pass
                else "Some accounts or role assignments need review; periodic recertification "
                "would tighten governance and reduce standing risk."
            ),
        }
    )

    # 4. Application Consent Controls
    rows.append(
        {
            "category": "Application Consent Controls",
            "status": _NEEDS if oauth_consent_failed else _STRONG,
            "commentary": (
                "Users can grant third-party applications access to company data without "
                "review, a known path for data exposure and token abuse."
                if oauth_consent_failed
                else "Third-party application access requires administrator approval, preventing "
                "risky apps from silently obtaining data access."
            ),
        }
    )

    # 5. Evidence Maturity
    rows.append(
        {
            "category": "Evidence Maturity",
            "status": _STRONG if has_prior_report else _MODERATE,
            "commentary": (
                "Controls are evaluated continuously and prior reports are retained, so "
                "improvement over time can be demonstrated, not just asserted."
                if has_prior_report
                else "This is the first archived assessment; once a second period is recorded, "
                "measurable trend evidence becomes available."
            ),
        }
    )

    # 6. Underwriting Supportability (composite, driven by the verdict tier)
    support_status = {
        "READY": _STRONG,
        "CONDITIONAL": _MODERATE,
        "HIGH_RISK": _NEEDS,
        "NOT_READY": _NEEDS,
    }.get(tier_state, _MODERATE)
    rows.append(
        {
            "category": "Underwriting Supportability",
            "status": support_status,
            "commentary": (
                "The combined evidence presents a posture that is well supported for " "underwriting review."
                if support_status == _STRONG
                else "The evidence supports an underwriting conversation, with clearly scoped "
                "actions that would strengthen the position."
                if support_status == _MODERATE
                else "Key controls should be addressed to present a supportable posture for " "underwriting review."
            ),
        }
    )

    return rows
