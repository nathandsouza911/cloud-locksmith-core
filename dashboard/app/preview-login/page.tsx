"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { Eye, Shield } from "lucide-react";

import { startMicrosoftOAuth, POST_LOGIN_LANDING } from "@/lib/auth";
import { useAuth } from "@/lib/auth-context";

export default function PreviewLoginPage() {
  const { authed, loading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!loading && authed) {
      router.replace(POST_LOGIN_LANDING);
    }
  }, [authed, loading, router]);

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-950">
        <div className="h-5 w-5 animate-spin rounded-full border-2 border-amber-500 border-t-transparent" />
      </div>
    );
  }

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-gray-950 px-4">
      <div className="w-full max-w-sm space-y-8 text-center">
        <div className="flex flex-col items-center gap-3">
          <div className="relative">
            <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-amber-500 to-orange-600 flex items-center justify-center shadow-lg shadow-amber-500/20">
              <Shield size={26} className="text-white" />
            </div>
            <div className="absolute -bottom-1 -right-1 w-6 h-6 rounded-full bg-gray-950 flex items-center justify-center">
              <Eye size={12} className="text-amber-400" />
            </div>
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Preview Mode</h1>
            <p className="text-sm text-gray-400 mt-1">Cloud Locksmith</p>
          </div>
        </div>

        <div className="space-y-3 text-left bg-gray-900/60 border border-gray-800 rounded-2xl p-5">
          <p className="text-sm font-semibold text-amber-300">What you can do in Preview:</p>
          <ul className="space-y-2 text-sm text-gray-400">
            <li className="flex items-start gap-2">
              <span className="text-amber-400 mt-0.5">✓</span>Run a full identity security scan
            </li>
            <li className="flex items-start gap-2">
              <span className="text-amber-400 mt-0.5">✓</span>View MFA gaps, dormant users, and risks
            </li>
            <li className="flex items-start gap-2">
              <span className="text-amber-400 mt-0.5">✓</span>See your compliance posture and score
            </li>
            <li className="flex items-start gap-2">
              <span className="text-gray-600 mt-0.5">✗</span>
              <span className="text-gray-500">No remediation or write actions</span>
            </li>
          </ul>
        </div>

        <button
          onClick={() => startMicrosoftOAuth("preview")}
          className="w-full flex items-center justify-center gap-2.5 rounded-xl bg-amber-500 hover:bg-amber-400 text-gray-950 font-semibold text-sm px-4 py-3 transition-colors shadow-lg shadow-amber-500/20"
        >
          <svg width="18" height="18" viewBox="0 0 21 21" fill="none">
            <rect x="1" y="1" width="9" height="9" fill="#F25022" />
            <rect x="11" y="1" width="9" height="9" fill="#7FBA00" />
            <rect x="1" y="11" width="9" height="9" fill="#00A4EF" />
            <rect x="11" y="11" width="9" height="9" fill="#FFB900" />
          </svg>
          Continue with Microsoft (Read-Only)
        </button>

        <p className="text-xs text-gray-500">
          Only read-only permissions will be requested.{" "}
          <a href="/login" className="text-cyan-400 hover:underline">
            Sign in with full access instead
          </a>
        </p>
      </div>
    </div>
  );
}
