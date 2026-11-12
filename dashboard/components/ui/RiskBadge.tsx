"use client";

type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

type RiskBadgeProps = {
  value?: string | null;
};

const riskStyles: Record<RiskLevel, string> = {
  LOW: "border-green-500/30 bg-green-500/10 text-green-300",
  MEDIUM: "border-yellow-500/30 bg-yellow-500/10 text-yellow-300",
  HIGH: "border-orange-500/30 bg-orange-500/10 text-orange-300",
  CRITICAL: "border-red-500/30 bg-red-500/10 text-red-300",
};

export default function RiskBadge({ value }: RiskBadgeProps) {
  const normalized = (typeof value === "string" ? value.toUpperCase() : "LOW") as RiskLevel;
  const style = riskStyles[normalized] ?? riskStyles.LOW;

  return (
    <span
      className={`inline-flex items-center rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.2em] ${style}`}
    >
      {normalized}
    </span>
  );
}
