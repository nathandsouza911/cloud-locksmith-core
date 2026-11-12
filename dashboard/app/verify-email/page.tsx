"use client";

import { Suspense, useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Shield } from "lucide-react";
import { api } from "@/lib/api/client";

type State = "verifying" | "success" | "error";

function VerifyEmailContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const [state, setState] = useState<State>("verifying");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    const token = searchParams.get("token");
    if (!token) {
      setState("error");
      setErrorMsg("Missing verification token.");
      return;
    }

    api
      .post("/api/auth/verify-email", { token })
      .then(() => {
        setState("success");
        setTimeout(() => router.replace("/msp/login"), 2000);
      })
      .catch((err: unknown) => {
        setState("error");
        setErrorMsg(err instanceof Error ? err.message : "Verification failed. The link may have expired.");
      });
  }, [searchParams, router]);

  return (
    <>
      {state === "verifying" && <p className="text-gray-400 text-sm">Verifying your email…</p>}

      {state === "success" && <p className="text-green-400 text-sm">Email verified! Redirecting to login…</p>}

      {state === "error" && (
        <>
          <p className="text-red-400 text-sm mb-4">{errorMsg}</p>
          <a href="/msp/login" className="text-cyan-400 hover:text-cyan-300 text-sm">
            Go to login
          </a>
        </>
      )}
    </>
  );
}

export default function VerifyEmailPage() {
  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center p-4">
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-8 shadow-2xl w-full max-w-md text-center">
        <div className="w-14 h-14 rounded-lg bg-cyan-600 flex items-center justify-center mx-auto mb-4">
          <Shield size={28} className="text-white" />
        </div>
        <h1 className="text-xl font-bold text-white mb-2">Email Verification</h1>
        <Suspense fallback={<p className="text-gray-400 text-sm">Verifying your email…</p>}>
          <VerifyEmailContent />
        </Suspense>
      </div>
    </div>
  );
}
