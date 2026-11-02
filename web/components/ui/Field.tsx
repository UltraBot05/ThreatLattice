import type { InputHTMLAttributes, ReactNode, SelectHTMLAttributes } from "react";

const control =
  "h-9 w-full rounded-[2px] border border-rule bg-ink-2 px-3 text-[13px] text-paper placeholder:text-paper-faint hover:border-rule-strong focus-visible:border-hazard";

export function Input({ className = "", ...rest }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={`${control} ${className}`} {...rest} />;
}

export function Select({ className = "", children, ...rest }: SelectHTMLAttributes<HTMLSelectElement> & { children: ReactNode }) {
  return (
    <select className={`${control} pr-8 ${className}`} {...rest}>
      {children}
    </select>
  );
}

/** Label + control + optional error, stacked. */
export function Field({
  label,
  htmlFor,
  error,
  children,
}: {
  label: string;
  htmlFor: string;
  error?: string;
  children: ReactNode;
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={htmlFor} className="tl-label">
        {label}
      </label>
      {children}
      {error ? (
        <p className="text-xs text-hazard" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}
