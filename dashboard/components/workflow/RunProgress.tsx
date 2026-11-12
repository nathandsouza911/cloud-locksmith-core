/**
 * components/workflow/RunProgress.tsx
 *
 * Resource-driven progress display for a workflow run: "N resources ·
 * N reviewed · N remaining · N% complete" plus a bar. Deliberately never
 * phrased as "Step X of Y" — a run's progress is how many of its resources
 * have been reviewed, not which stage it happens to be in.
 */

import React from "react";

export interface RunProgressProps {
  total: number;
  reviewed: number;
  className?: string;
}

export function RunProgress({ total, reviewed, className = "" }: RunProgressProps) {
  const safeTotal = Math.max(0, total);
  const safeReviewed = Math.min(Math.max(0, reviewed), safeTotal);
  const remaining = safeTotal - safeReviewed;
  // Zero resources reads as fully complete, not a division by zero.
  const percent = safeTotal === 0 ? 100 : Math.round((safeReviewed / safeTotal) * 100);

  return (
    <div className={className}>
      <div className="flex items-center justify-between text-xs text-gray-400 mb-1.5">
        <span className="text-gray-300 tabular-nums">
          {`${safeTotal} ${safeTotal === 1 ? "resource" : "resources"} · ${safeReviewed} reviewed · ${remaining} remaining`}
        </span>
        <span className="text-gray-200 font-semibold tabular-nums">{`${percent}% complete`}</span>
      </div>
      <div className="h-1.5 w-full rounded-full bg-gray-800 overflow-hidden">
        <div
          data-testid="run-progress-bar"
          className="h-full rounded-full bg-cyan-500 transition-all"
          style={{ width: `${percent}%` }}
        />
      </div>
    </div>
  );
}
