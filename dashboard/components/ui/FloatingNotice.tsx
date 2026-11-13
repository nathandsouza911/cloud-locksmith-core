/**
 * A short result message pinned to the bottom of the viewport, so the outcome of an
 * action (including a refusal) is visible wherever the user clicked, not only at the
 * top of a long page.
 */
export function FloatingNotice({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <div
      role="status"
      aria-live="polite"
      className="fixed bottom-6 left-1/2 z-50 w-[min(90vw,32rem)] -translate-x-1/2 rounded-lg border border-cyan-500/30 bg-gray-900/95 px-4 py-3 text-sm text-cyan-100 shadow-2xl"
    >
      {message}
    </div>
  );
}
