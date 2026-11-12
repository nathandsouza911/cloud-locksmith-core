"use client";

import { Eye } from "lucide-react";
import { startMicrosoftOAuth } from "@/lib/auth";

export function PreviewModeBanner() {
  return (
    <div className="w-full bg-amber-500/10 border-b border-amber-500/30 px-4 lg:px-6 py-2.5 flex items-center justify-between gap-4">
      <div className="flex items-center gap-2 text-amber-300 text-sm">
        <Eye size={14} className="shrink-0" />
        <span>
          <span className="font-semibold">Preview Mode</span> — no changes will be made to your tenant.
        </span>
      </div>
      <button
        onClick={() => startMicrosoftOAuth("smb_onboarding")}
        className="shrink-0 text-xs font-semibold text-amber-200 bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 rounded-lg px-3 py-1.5 transition-colors"
      >
        Unlock Remediation
      </button>
    </div>
  );
}
