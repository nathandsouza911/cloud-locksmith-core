"use client";

import { isDemoMode } from "@/lib/demo";

export function DemoBanner() {
  if (!isDemoMode()) return null;
  return (
    <div
      role="status"
      className="sticky top-0 z-50 w-full border-b border-amber-500/40 bg-amber-500/15 px-4 py-2 text-center text-xs font-semibold text-amber-200"
    >
      DEMO MODE: a recorded scan of a fictional tenant. Nothing here is connected to Microsoft, and changes
      are disabled. The fix simulation still works.
    </div>
  );
}
