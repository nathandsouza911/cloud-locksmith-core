"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { ArrowRight, Shield } from "lucide-react";

import { startMicrosoftOAuth, POST_LOGIN_LANDING } from "@/lib/auth";
import { useAuth } from "@/lib/auth-context";
import { signInErrorFromSearch } from "@/lib/connect-errors";
import { DEMO_LANDING, isDemoMode, signInToDemo } from "@/lib/demo";

export default function LoginPage() {
  const { authed, loading } = useAuth();
  const router = useRouter();
  const [loginLoading, setLoginLoading] = useState(false);
  const [demoError, setDemoError] = useState<string | null>(null);
  const [signInError, setSignInError] = useState<string | null>(null);
  const demo = isDemoMode();

  useEffect(() => {
    if (!loading && authed) {
      router.replace(POST_LOGIN_LANDING);
    }
  }, [authed, loading, router]);

  useEffect(() => {
    setSignInError(signInErrorFromSearch(window.location.search));
  }, []);

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-950">
        <div className="h-5 w-5 animate-spin rounded-full border-2 border-cyan-500 border-t-transparent" />
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-950 p-4">
      <div className="w-full max-w-md rounded-lg border border-gray-800 bg-gray-900 p-8 shadow-2xl">
        <div className="mb-8 flex flex-col items-center text-center">
          <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-lg bg-cyan-600 text-white">
            <Shield size={28} />
          </div>
          <h1 className="text-2xl font-bold text-white">Cloud Locksmith</h1>
          <p className="mt-2 text-sm text-gray-400">
            Sign in with a Microsoft 365 administrator account to connect your tenant and begin your Cloud
            Locksmith security assessment.
          </p>
        </div>

        {demo ? (
          <>
            <button
              type="button"
              onClick={async () => {
                if (loginLoading) return;
                setLoginLoading(true);
                setDemoError(null);
                try {
                  await signInToDemo();
                  // Full navigation so the auth context reloads the new session.
                  window.location.assign(DEMO_LANDING);
                } catch (error) {
                  setDemoError(error instanceof Error ? error.message : "Demo sign-in failed");
                  setLoginLoading(false);
                }
              }}
              disabled={loginLoading}
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-cyan-600 px-4 py-3 font-semibold text-white transition-colors hover:bg-cyan-500 disabled:cursor-not-allowed disabled:opacity-70"
            >
              {loginLoading ? "Signing in..." : "Sign in to the demo"}
              {!loginLoading ? <ArrowRight size={16} /> : null}
            </button>
            {demoError ? (
              <p role="alert" className="mt-3 text-center text-sm text-red-400">
                {demoError}
              </p>
            ) : null}
          </>
        ) : (
          <>
            {signInError ? (
              <p
                role="alert"
                className="mb-4 rounded-lg border border-red-500/20 bg-red-500/5 p-3 text-center text-sm text-red-400"
              >
                {signInError}
              </p>
            ) : null}
            <button
              type="button"
              onClick={() => {
                if (loginLoading) return;
                setLoginLoading(true);
                const started = startMicrosoftOAuth();
                if (!started) {
                  setLoginLoading(false);
                }
              }}
              disabled={loginLoading}
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-cyan-600 px-4 py-3 font-semibold text-white transition-colors hover:bg-cyan-500 disabled:cursor-not-allowed disabled:opacity-70"
            >
              {loginLoading ? "Redirecting..." : "Sign in with Microsoft"}
              {!loginLoading ? <ArrowRight size={16} /> : null}
            </button>

            <p className="mt-6 text-center text-sm text-gray-500">
              MSP administrator?{" "}
              <Link href="/msp/login" className="text-cyan-400 hover:text-cyan-300">
                Use MSP login
              </Link>
            </p>
          </>
        )}
      </div>
    </div>
  );
}
