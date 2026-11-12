/**
 * components/ui/index.tsx
 * Lightweight primitives used across all pages.
 */

import React from "react";
import type { Severity, DecisionStatus, ScoreBand } from "@/types";
import { scoreBandAccent } from "@/utils/posture";

// ─── Badge ────────────────────────────────────────────────────────────────────

const severityStyles: Record<Severity, string> = {
  CRITICAL: "bg-red-500/15 text-red-400 border border-red-500/30",
  HIGH: "bg-orange-500/15 text-orange-400 border border-orange-500/30",
  MEDIUM: "bg-yellow-500/15 text-yellow-400 border border-yellow-500/30",
  LOW: "bg-blue-500/15 text-blue-400 border border-blue-500/30",
  INFO: "bg-gray-500/15 text-gray-400 border border-gray-500/30",
};

const statusStyles: Record<string, string> = {
  PENDING: "bg-yellow-500/15 text-yellow-400 border border-yellow-500/30",
  IN_PROGRESS: "bg-blue-500/15 text-blue-400 border border-blue-500/30",
  COMPLETED: "bg-green-500/15 text-green-400 border border-green-500/30",
  OPEN: "bg-cyan-500/15 text-cyan-400 border border-cyan-500/30",
  CLOSED: "bg-gray-700/40 text-gray-300 border border-gray-600/40",
  APPROVED: "bg-blue-500/15 text-blue-400 border border-blue-500/30",
  EXECUTED: "bg-green-500/15 text-green-400 border border-green-500/30",
  VERIFIED: "bg-cyan-500/15 text-cyan-400 border border-cyan-500/30",
  RESOLVED: "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30",
  ROLLED_BACK: "bg-purple-500/15 text-purple-400 border border-purple-500/30",
  BLOCKED: "bg-red-500/15 text-red-400 border border-red-500/30",
  AUTO_REMEDIATED: "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30",
  ACKNOWLEDGED: "bg-emerald-500/15 text-emerald-300 border border-emerald-500/30",
  FAILED: "bg-red-600/15 text-red-500 border border-red-600/30",
  FAILED_SAFE: "bg-red-600/15 text-red-500 border border-red-600/30",
  SKIPPED: "bg-gray-700/40 text-gray-300 border border-gray-600/40",
  LOCKED: "bg-gray-800/80 text-gray-400 border border-gray-700/60",
};

export function SeverityBadge({ value }: { value?: Severity | string | null }) {
  const safeValue = (typeof value === "string" ? value.toUpperCase() : "INFO") as Severity;
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-semibold tracking-wide ${severityStyles[safeValue] ?? severityStyles.INFO}`}
    >
      {safeValue}
    </span>
  );
}

export function StatusBadge({ value }: { value?: DecisionStatus | string | null }) {
  const safeValue = (
    typeof value === "string" && value.length > 0 ? value.toUpperCase() : "PENDING"
  ) as DecisionStatus;
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-semibold tracking-wide ${statusStyles[safeValue] ?? statusStyles.PENDING}`}
    >
      {safeValue.replace("_", " ")}
    </span>
  );
}

export function ScoreBadge({ score, scoreBand }: { score: number; scoreBand?: ScoreBand | null }) {
  const color = scoreBandAccent(scoreBand ?? null);
  return (
    <span className={`font-bold text-lg tabular-nums ${color}`}>
      {score}
      <span className="text-xs font-normal text-gray-500 ml-0.5">/ 100</span>
    </span>
  );
}

// ─── Card ─────────────────────────────────────────────────────────────────────

interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
}

export function Card({ children, className = "", ...props }: CardProps) {
  return (
    <div
      className={`rounded-xl border border-gray-800 bg-gray-900/70 backdrop-blur-sm ${className}`}
      {...props}
    >
      {children}
    </div>
  );
}

// ─── StatCard ─────────────────────────────────────────────────────────────────

interface StatCardProps {
  label: string;
  value: string | number;
  sub?: string;
  accent?: string; // tailwind text color class
  icon?: React.ReactNode;
}

export function StatCard({ label, value, sub, accent = "text-white", icon }: StatCardProps) {
  return (
    <Card className="p-5 flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <p className="text-xs font-medium text-gray-400 uppercase tracking-wider">{label}</p>
        {icon && <div className="text-gray-500">{icon}</div>}
      </div>
      <p className={`text-3xl font-bold tabular-nums ${accent}`}>{value}</p>
      {sub && <p className="text-xs text-gray-500">{sub}</p>}
    </Card>
  );
}

// ─── PageHeader ───────────────────────────────────────────────────────────────

export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: string;
  subtitle?: string;
  actions?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-6">
      <div>
        <h1 className="text-xl font-bold text-white tracking-tight">{title}</h1>
        {subtitle && <p className="text-sm text-gray-400 mt-0.5">{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

// ─── Skeleton ─────────────────────────────────────────────────────────────────

export function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`animate-pulse rounded-md bg-gray-800 ${className}`} />;
}

export function TableSkeleton({ rows = 6, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div className="space-y-2">
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="flex gap-4">
          {Array.from({ length: cols }).map((_, c) => (
            <Skeleton key={c} className={`h-8 flex-1 ${c === 0 ? "max-w-[120px]" : ""}`} />
          ))}
        </div>
      ))}
    </div>
  );
}

// ─── Button ──────────────────────────────────────────────────────────────────

type ButtonVariant = "primary" | "secondary" | "danger" | "ghost";

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: "sm" | "md";
  loading?: boolean;
}

const variantCls: Record<ButtonVariant, string> = {
  primary: "bg-cyan-600 hover:bg-cyan-500 text-white border border-cyan-500 shadow-sm shadow-cyan-500/20",
  secondary: "bg-gray-800 hover:bg-gray-700 text-gray-200 border border-gray-700",
  danger: "bg-red-600/20 hover:bg-red-600/30 text-red-400 border border-red-500/30",
  ghost: "text-gray-400 hover:text-gray-200 hover:bg-gray-800",
};

const sizeCls = {
  sm: "px-3 py-1.5 text-xs",
  md: "px-4 py-2 text-sm",
};

export function Button({
  variant = "secondary",
  size = "sm",
  loading,
  children,
  className = "",
  disabled,
  ...props
}: ButtonProps) {
  return (
    <button
      disabled={loading || disabled}
      className={`
        inline-flex items-center gap-1.5 rounded-lg font-medium transition-all
        disabled:opacity-50 disabled:cursor-not-allowed
        ${variantCls[variant]} ${sizeCls[size]} ${className}
      `}
      {...props}
    >
      {loading && (
        <span className="w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin" />
      )}
      {children}
    </button>
  );
}

// ─── Empty state ──────────────────────────────────────────────────────────────

export function EmptyState({ message = "No data available" }: { message?: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-gray-500">
      <div className="w-12 h-12 rounded-full border-2 border-dashed border-gray-700 flex items-center justify-center mb-3">
        <span className="text-xl">∅</span>
      </div>
      <p className="text-sm">{message}</p>
    </div>
  );
}

// ─── Error ────────────────────────────────────────────────────────────────────

export function ErrorState({ message }: { message: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-12 text-red-400">
      <p className="text-sm">⚠ {message}</p>
    </div>
  );
}

// ─── Score ring ───────────────────────────────────────────────────────────────

export function ScoreRing({ score, scoreBand }: { score: number; scoreBand?: ScoreBand | null }) {
  const r = 36;
  const circ = 2 * Math.PI * r;
  const offset = circ * (1 - score / 100);
  const color =
    scoreBand === "GOOD"
      ? "#22d3ee"
      : scoreBand === "MODERATE"
        ? "#facc15"
        : scoreBand === "HIGH"
          ? "#fb923c"
          : "#f87171";

  return (
    <div className="relative inline-flex items-center justify-center">
      <svg width="96" height="96" className="-rotate-90">
        <circle cx="48" cy="48" r={r} stroke="#1f2937" strokeWidth="8" fill="none" />
        <circle
          cx="48"
          cy="48"
          r={r}
          stroke={color}
          strokeWidth="8"
          fill="none"
          strokeDasharray={circ}
          strokeDashoffset={offset}
          strokeLinecap="round"
          style={{ transition: "stroke-dashoffset 0.6s ease" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-2xl font-bold text-white tabular-nums">{score}</span>
        <span className="text-[9px] text-gray-400 uppercase tracking-wider">Score</span>
      </div>
    </div>
  );
}

// ─── Select filter ────────────────────────────────────────────────────────────

export function FilterSelect({
  value,
  onChange,
  options,
  placeholder = "All",
}: {
  value: string;
  onChange: (v: string) => void;
  options: { label: string; value: string }[];
  placeholder?: string;
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="bg-gray-800 border border-gray-700 text-sm text-gray-300 rounded-lg px-3 py-1.5 outline-none focus:border-cyan-500 transition-colors"
    >
      <option value="">{placeholder}</option>
      {options.map((o) => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  );
}

export { default as ConfirmModal } from "./ConfirmModal";
export type { ConfirmModalProps } from "./ConfirmModal";
export { default as SimulationPanel } from "./SimulationPanel";
export type { SimulationResult, SimulationConflict } from "./SimulationPanel";
export { default as PolicyEditor } from "./PolicyEditor";
export type { EditablePolicy } from "./PolicyEditor";
export { default as RiskBadge } from "./RiskBadge";
export { default as ConfidenceBadge } from "./ConfidenceBadge";
