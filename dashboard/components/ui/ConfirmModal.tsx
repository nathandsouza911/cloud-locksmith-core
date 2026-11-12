"use client";

import { useEffect, useRef, useState } from "react";
import { AlertTriangle, X } from "lucide-react";
import { Button } from "./index";

export interface ConfirmModalProps {
  open: boolean;
  title: string;
  message: string;
  /** Label on the confirm button (default: "Confirm") */
  confirmLabel?: string;
  /** "danger" = red, "warning" = amber (default: "danger") */
  variant?: "danger" | "warning";
  /**
   * When true the user must type the word CONFIRM before the button enables.
   * Use for irreversible / high-impact actions (execute, rollback, break-glass).
   */
  requireTypedConfirm?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export default function ConfirmModal({
  open,
  title,
  message,
  confirmLabel = "Confirm",
  variant = "danger",
  requireTypedConfirm = false,
  onConfirm,
  onCancel,
}: ConfirmModalProps) {
  const [typed, setTyped] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  // Reset typed value whenever the modal opens/closes.
  useEffect(() => {
    if (open) {
      setTyped("");
      // Focus the input after the paint so it's immediately keyboard-ready.
      if (requireTypedConfirm) {
        setTimeout(() => inputRef.current?.focus(), 50);
      }
    }
  }, [open, requireTypedConfirm]);

  // Close on Escape.
  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onCancel();
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [open, onCancel]);

  if (!open) return null;

  const confirmed = !requireTypedConfirm || typed.trim() === "CONFIRM";

  const accentBorder = variant === "danger" ? "border-red-500/40" : "border-amber-500/40";
  const accentText = variant === "danger" ? "text-red-400" : "text-amber-400";
  const accentBg = variant === "danger" ? "bg-red-500/10" : "bg-amber-500/10";
  const buttonVariant = variant === "danger" ? "danger" : "secondary";

  return (
    /* Backdrop */
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
      onClick={onCancel}
      aria-modal="true"
      role="dialog"
      aria-labelledby="confirm-modal-title"
    >
      {/* Panel — stop propagation so clicking inside doesn't close */}
      <div
        className={`relative w-full max-w-md mx-4 rounded-2xl border ${accentBorder} ${accentBg} bg-gray-900 shadow-2xl p-6`}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Close button */}
        <button
          onClick={onCancel}
          className="absolute top-4 right-4 text-gray-500 hover:text-gray-200 transition-colors"
          aria-label="Cancel"
        >
          <X size={16} />
        </button>

        {/* Icon + title */}
        <div className="flex items-start gap-3 mb-4">
          <AlertTriangle size={20} className={`shrink-0 mt-0.5 ${accentText}`} />
          <h2 id="confirm-modal-title" className={`text-base font-semibold ${accentText}`}>
            {title}
          </h2>
        </div>

        {/* Message */}
        <p className="text-sm text-gray-300 leading-relaxed mb-5">{message}</p>

        {/* Typed-confirm input */}
        {requireTypedConfirm && (
          <div className="mb-5">
            <label className="block text-xs text-gray-400 mb-1.5">
              Type <span className="font-mono font-bold text-gray-200">CONFIRM</span> to proceed
            </label>
            <input
              ref={inputRef}
              type="text"
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              placeholder="CONFIRM"
              className="w-full bg-gray-800 border border-gray-700 text-sm text-gray-200 rounded-lg px-3 py-2 outline-none focus:border-red-500 transition-colors font-mono tracking-widest placeholder:tracking-normal placeholder:text-gray-600"
              autoComplete="off"
              spellCheck={false}
            />
          </div>
        )}

        {/* Actions */}
        <div className="flex justify-end gap-2">
          <Button variant="secondary" size="sm" onClick={onCancel}>
            Cancel
          </Button>
          <Button
            variant={buttonVariant as "danger" | "secondary"}
            size="sm"
            disabled={!confirmed}
            onClick={onConfirm}
          >
            {confirmLabel}
          </Button>
        </div>
      </div>
    </div>
  );
}
