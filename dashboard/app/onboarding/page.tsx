"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

import { useAuth } from "@/lib/auth-context";
import { POST_LOGIN_LANDING } from "@/lib/auth";

export default function OnboardingPage() {
  const { authed, loading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!loading && authed) {
      router.replace(POST_LOGIN_LANDING);
    }
  }, [authed, loading, router]);

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-950 px-4">
      <div className="w-full max-w-md rounded-lg border border-gray-800 bg-gray-900 p-8 text-center">
        <div className="mx-auto mb-4 h-8 w-8 animate-spin rounded-full border-2 border-cyan-500 border-t-transparent" />
        <h1 className="text-xl font-semibold text-white">Finishing your setup</h1>
        <p className="mt-2 text-sm text-gray-400">We&apos;re getting your tenant ready.</p>
      </div>
    </div>
  );
}
