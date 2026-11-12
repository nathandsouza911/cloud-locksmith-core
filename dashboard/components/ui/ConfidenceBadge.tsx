"use client";

type ConfidenceLevel = "LOW" | "MEDIUM" | "HIGH";

type ConfidenceBadgeProps = {
  value?: string | number | null;
};

const confidenceStyles: Record<ConfidenceLevel, string> = {
  LOW: "border-gray-600 bg-gray-800 text-gray-300",
  MEDIUM: "border-cyan-500/30 bg-cyan-500/10 text-cyan-300",
  HIGH: "border-blue-500/30 bg-blue-500/10 text-blue-300",
};

function normalizeConfidence(value?: string | number | null): ConfidenceLevel {
  if (typeof value === "number") {
    if (value >= 0.8) return "HIGH";
    if (value >= 0.5) return "MEDIUM";
    return "LOW";
  }

  if (typeof value === "string") {
    const normalized = value.toUpperCase();
    if (normalized === "LOW" || normalized === "MEDIUM" || normalized === "HIGH") {
      return normalized;
    }
  }

  return "MEDIUM";
}

export default function ConfidenceBadge({ value }: ConfidenceBadgeProps) {
  const normalized = normalizeConfidence(value);
  const style = confidenceStyles[normalized];

  return (
    <span
      className={`inline-flex items-center rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.2em] ${style}`}
    >
      {normalized}
    </span>
  );
}
