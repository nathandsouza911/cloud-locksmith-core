"use client";

import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
  CartesianGrid,
} from "recharts";
import type { NormalizedTimelinePoint } from "@/types";

interface PostureChartProps {
  data: NormalizedTimelinePoint[];
  height?: number;
  showGrid?: boolean;
  showReferences?: boolean;
}

const CustomTooltip = ({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: { value: number | null }[];
  label?: string;
}) => {
  if (!active || !payload?.length || payload[0].value === null) return null;
  return (
    <div className="bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-xs shadow-xl">
      <p className="text-gray-400 mb-1">
        {label
          ? new Date(label).toLocaleDateString("en-US", {
              month: "short",
              day: "numeric",
              year: "numeric",
            })
          : ""}
      </p>
      <p className="font-bold text-white">
        Score:{" "}
        <span
          style={{
            color: payload[0].value >= 80 ? "#22d3ee" : payload[0].value >= 60 ? "#facc15" : "#f87171",
          }}
        >
          {payload[0].value}
        </span>
      </p>
    </div>
  );
};

export default function PostureChart({
  data,
  height = 220,
  showGrid = false,
  showReferences = true,
}: PostureChartProps) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: 0 }}>
        <defs>
          <linearGradient id="postureGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.18} />
            <stop offset="95%" stopColor="#22d3ee" stopOpacity={0} />
          </linearGradient>
        </defs>

        {showGrid && <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" vertical={false} />}

        <XAxis
          dataKey="date"
          tick={{ fill: "#6b7280", fontSize: 10 }}
          axisLine={false}
          tickLine={false}
          tickFormatter={(v) =>
            new Date(v).toLocaleDateString("en-US", {
              month: "short",
              day: "numeric",
            })
          }
          interval="preserveStartEnd"
        />

        <YAxis
          domain={[0, 100]}
          tick={{ fill: "#6b7280", fontSize: 10 }}
          axisLine={false}
          tickLine={false}
          width={28}
        />

        <Tooltip content={<CustomTooltip />} />

        {showReferences && (
          <>
            <ReferenceLine y={80} stroke="#22d3ee" strokeDasharray="4 4" strokeOpacity={0.25} />
            <ReferenceLine y={60} stroke="#f87171" strokeDasharray="4 4" strokeOpacity={0.25} />
          </>
        )}

        <Area
          type="monotone"
          dataKey="score"
          stroke="#22d3ee"
          strokeWidth={2}
          fill="url(#postureGrad)"
          dot={false}
          connectNulls
          activeDot={{ r: 4, fill: "#22d3ee", stroke: "#0e7490", strokeWidth: 2 }}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}
