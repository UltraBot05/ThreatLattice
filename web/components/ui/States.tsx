import type { ReactNode } from "react";
import { Button } from "./Button";

/** Empty: a mono label, one plain sentence, one action. An invitation, not an apology. */
export function EmptyState({
  label = "NO RESULTS",
  message,
  action,
}: {
  label?: string;
  message: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-start gap-2 border border-dashed border-rule px-4 py-6">
      <p className="tl-label">{label}</p>
      <p className="text-[13px] text-paper-dim">{message}</p>
      {action}
    </div>
  );
}

/** Error: hazard rule + the API's error.message + Retry. */
export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="flex flex-col items-start gap-2 border-l-2 border-hazard bg-hazard-dim px-4 py-3">
      <p className="tl-label text-hazard">COULD NOT LOAD</p>
      <p className="text-[13px] text-paper">{message}</p>
      {onRetry ? (
        <Button size="sm" onClick={onRetry}>
          Retry
        </Button>
      ) : null}
    </div>
  );
}
