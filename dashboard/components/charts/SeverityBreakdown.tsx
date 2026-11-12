"use client";

import { BarChart, Bar, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer, Cell } from "recharts";
import type { ComplianceResult } from "@/types";

interface SeverityBreakdownProps {
  results: ComplianceResult[];
  height?: number;
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "#f87171",
  HIGH: "#fb923c",
  MEDIUM: "#facc15",
  LOW: "#60a5fa",
  INFO: "#9ca3af",
};

export default function SeverityBreakdown({ results, height = 200 }: SeverityBreakdownProps) {
  // Group by severity
  const counts: Record<string, { passed: number; failed: number }> = {};

  for (const r of results) {
    if (!counts[r.severity]) counts[r.severity] = { passed: 0, failed: 0 };
    if (r.passed) counts[r.severity].passed++;
    else counts[r.severity].failed++;
  }

  const data = Object.entries(counts)
    .sort((a, b) => {
      const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
      return order.indexOf(a[0]) - order.indexOf(b[0]);
    })
    .map(([severity, vals]) => ({
      severity,
      ...vals,
    }));

  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} barSize={20} barGap={4}>
        <XAxis
          dataKey="severity"
          tick={{ fill: "#6b7280", fontSize: 10 }}
          axisLine={false}
          tickLine={false}
        />
        <YAxis tick={{ fill: "#6b7280", fontSize: 10 }} axisLine={false} tickLine={false} width={28} />
        <Tooltip
          contentStyle={{
            background: "#111827",
            border: "1px solid #374151",
            borderRadius: 8,
            color: "#e5e7eb",
            fontSize: 12,
          }}
          cursor={{ fill: "rgba(255,255,255,0.03)" }}
        />
        <Legend
          formatter={(v) => (
            <span style={{ color: "#9ca3af", fontSize: 11 }}>{v.charAt(0).toUpperCase() + v.slice(1)}</span>
          )}
        />
        <Bar dataKey="failed" name="failed" radius={[3, 3, 0, 0]}>
          {data.map((entry, i) => (
            <Cell key={i} fill={SEVERITY_COLORS[entry.severity] ?? "#6b7280"} opacity={0.85} />
          ))}
        </Bar>
        <Bar dataKey="passed" name="passed" fill="#374151" radius={[3, 3, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}
