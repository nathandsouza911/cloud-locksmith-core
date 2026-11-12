"""Generic risk vocabulary.

Lifted from ``oauth_review/resources.py`` because none of it is OAuth-specific —
it is an ordering over four severity labels plus a way to explain an assessment
to a technician. What *drives* an assessment stays in each workflow's own risk
module.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class RiskLevel:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    ALL = (CRITICAL, HIGH, MEDIUM, LOW)
    _ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}
    # Ascending severity, used by escalate().
    _ASCENDING = (LOW, MEDIUM, HIGH, CRITICAL)

    @classmethod
    def rank(cls, level: str) -> int:
        """Sort key — lower is more severe. Unknown levels sort last."""
        return cls._ORDER.get(level, len(cls._ORDER))

    @classmethod
    def worst(cls, levels) -> str:
        levels = list(levels)
        return min(levels, key=cls.rank) if levels else cls.LOW

    @classmethod
    def escalate(cls, level: str) -> str:
        """One level more severe, saturating at CRITICAL."""
        index = cls._ASCENDING.index(level) if level in cls._ASCENDING else 0
        return cls._ASCENDING[min(index + 1, len(cls._ASCENDING) - 1)]


@dataclass(frozen=True)
class RiskAssessment:
    """A risk level plus the prose a technician can hand to a client.

    ``explanation`` is written for a person justifying a decision, not for a log
    line. ``drivers`` are short machine-readable tags (``"mfa:none"``) used for
    grouping and reporting.
    """

    level: str
    explanation: str
    recommended_action: str
    drivers: list[str] = field(default_factory=list)
