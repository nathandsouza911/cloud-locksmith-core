"use client";

import type { FindingGuidance } from "@/types";

function isRenderablePrimitive(value: unknown): value is string | number {
  return typeof value === "string" || typeof value === "number";
}

export function renderUnknownValue(value: unknown): React.ReactNode {
  if (value == null) {
    return <span className="text-gray-600">—</span>;
  }

  if (typeof value === "boolean") {
    return value ? "Yes" : "No";
  }

  if (isRenderablePrimitive(value)) {
    return value;
  }

  if (Array.isArray(value)) {
    if (value.length === 0) {
      return <span className="text-gray-600">—</span>;
    }

    const allPrimitive = value.every(
      (entry) => entry == null || isRenderablePrimitive(entry) || typeof entry === "boolean",
    );
    if (allPrimitive) {
      return value
        .map((entry) => (typeof entry === "boolean" ? (entry ? "Yes" : "No") : String(entry ?? "—")))
        .join(", ");
    }

    return (
      <pre className="max-w-full overflow-x-auto whitespace-pre-wrap break-words text-xs text-gray-400">
        {JSON.stringify(value, null, 2)}
      </pre>
    );
  }

  if (typeof value === "object") {
    return (
      <pre className="max-w-full overflow-x-auto whitespace-pre-wrap break-words text-xs text-gray-400">
        {JSON.stringify(value, null, 2)}
      </pre>
    );
  }

  return String(value);
}

function renderManualSteps(manualSteps?: string | string[]) {
  if (!manualSteps) return <p className="text-xs text-gray-500">No manual steps provided.</p>;

  if (Array.isArray(manualSteps)) {
    return (
      <ul className="list-disc space-y-1 pl-4 text-xs text-gray-400">
        {manualSteps.map((step, index) => (
          <li key={`${step}-${index}`}>{step}</li>
        ))}
      </ul>
    );
  }

  return <p className="text-xs text-gray-400">{manualSteps}</p>;
}

export function FindingGuidanceCard({ guidance }: { guidance?: string | FindingGuidance }) {
  if (!guidance) {
    return <span className="text-gray-500">—</span>;
  }

  if (typeof guidance === "string") {
    return <p className="text-xs text-gray-400">{guidance}</p>;
  }

  return (
    <div className="space-y-2">
      <div className="space-y-1">
        <p className="text-xs font-semibold text-gray-200">{guidance?.title ?? "Guidance"}</p>
        <p className="text-xs text-gray-400">{guidance?.summary ?? "No summary available."}</p>
        {guidance?.severity ? (
          <span className="inline-flex rounded-md bg-gray-800 px-2 py-0.5 text-[11px] font-semibold text-gray-300">
            {guidance?.severity}
          </span>
        ) : null}
      </div>
      {renderManualSteps(guidance?.manual_steps)}
    </div>
  );
}
