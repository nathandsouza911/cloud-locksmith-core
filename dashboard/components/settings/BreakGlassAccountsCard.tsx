"use client";

import { useCallback, useEffect, useState } from "react";
import { Button, Card } from "@/components/ui";
import {
  getBreakGlassAccounts,
  registerBreakGlassAccount,
  removeBreakGlassAccount,
} from "@/lib/api/endpoints";
import type { BreakGlassAccount } from "@/types";

const WARNING_TEXT: Record<string, string> = {
  synced_from_on_premises:
    "Registered, but this account is synced from on-premises. Microsoft recommends cloud-only emergency accounts.",
};

function errorMessage(error: unknown, fallback: string) {
  return error instanceof Error && error.message ? error.message : fallback;
}

export default function BreakGlassAccountsCard() {
  const [accounts, setAccounts] = useState<BreakGlassAccount[] | null>(null);
  const [canManage, setCanManage] = useState(false);
  const [userRef, setUserRef] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [confirmId, setConfirmId] = useState<number | null>(null);

  const load = useCallback(async () => {
    try {
      const result = await getBreakGlassAccounts();
      setAccounts(result.accounts);
      setCanManage(result.can_manage);
    } catch (err) {
      setError(errorMessage(err, "Could not load break-glass accounts."));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function handleRegister() {
    const value = userRef.trim();
    if (!value) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const created = await registerBreakGlassAccount(value);
      setUserRef("");
      setNotice(created.warnings.map((w) => WARNING_TEXT[w] ?? w).join(" ") || "Account registered.");
      await load();
    } catch (err) {
      setError(errorMessage(err, "Registration failed."));
    } finally {
      setBusy(false);
    }
  }

  async function handleRemove(id: number) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await removeBreakGlassAccount(id);
      setConfirmId(null);
      await load();
    } catch (err) {
      setError(errorMessage(err, "Removal failed."));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card className="p-6 space-y-4 max-w-2xl">
      <div>
        <h2 className="text-sm font-semibold text-gray-200">Break-glass accounts</h2>
        <p className="text-xs text-gray-500">
          Emergency Global Administrator accounts that every Conditional Access fix excludes. Each one is
          checked again before every Conditional Access change.
        </p>
      </div>

      {accounts !== null && accounts.length === 0 && (
        <p className="text-sm text-yellow-300">
          None registered. Conditional Access fixes are blocked until at least one is registered.
        </p>
      )}

      {accounts !== null && accounts.length > 0 && (
        <ul className="space-y-2">
          {accounts.map((account) => (
            <li
              key={account.id}
              className="flex items-center justify-between gap-3 p-3 bg-gray-800/50 rounded-lg border border-gray-700"
            >
              <span className="font-mono text-xs text-gray-200 break-all">{account.user_external_id}</span>
              {canManage &&
                (confirmId === account.id ? (
                  <span className="flex shrink-0 gap-2">
                    <Button
                      variant="danger"
                      size="sm"
                      loading={busy}
                      onClick={() => handleRemove(account.id)}
                    >
                      Confirm remove
                    </Button>
                    <Button variant="secondary" size="sm" onClick={() => setConfirmId(null)}>
                      Cancel
                    </Button>
                  </span>
                ) : (
                  <Button variant="secondary" size="sm" onClick={() => setConfirmId(account.id)}>
                    Remove
                  </Button>
                ))}
            </li>
          ))}
        </ul>
      )}

      {canManage ? (
        <div className="flex flex-col gap-2 sm:flex-row sm:items-end">
          <label className="flex-1 text-xs text-gray-400">
            Object ID or UPN
            <input
              value={userRef}
              onChange={(event) => setUserRef(event.target.value)}
              maxLength={256}
              placeholder="emergency-admin@contoso.onmicrosoft.com"
              className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-gray-100"
            />
          </label>
          <Button
            variant="primary"
            size="sm"
            loading={busy}
            disabled={!userRef.trim()}
            onClick={handleRegister}
          >
            Register
          </Button>
        </div>
      ) : (
        accounts !== null && (
          <p className="text-xs text-gray-500">
            Only the tenant owner can register or remove break-glass accounts.
          </p>
        )
      )}

      {notice && <p className="text-sm text-sky-300">{notice}</p>}
      {error && (
        <p role="alert" className="text-sm text-red-400">
          {error}
        </p>
      )}
    </Card>
  );
}
