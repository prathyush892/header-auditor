import type { InputHTMLAttributes } from "react";

export interface FieldProps extends Omit<InputHTMLAttributes<HTMLInputElement>, "id"> {
  readonly id: string;
  readonly label: string;
  readonly error?: string | undefined;
  readonly hint?: string | undefined;
}

/** Labelled input; the error and hint are wired to it with aria-describedby. */
export function Field({ id, label, error, hint, className = "", ...input }: FieldProps) {
  const describedBy = [
    error === undefined ? null : `${id}-error`,
    hint === undefined ? null : `${id}-hint`,
  ]
    .filter((value) => value !== null)
    .join(" ");
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={id} className="text-sm font-medium">
        {label}
      </label>
      <input
        id={id}
        aria-invalid={error === undefined ? undefined : true}
        aria-describedby={describedBy === "" ? undefined : describedBy}
        className={`rounded-md border bg-white px-3 py-2 text-sm shadow-sm outline-none transition focus:ring-2 focus:ring-brand-500 dark:bg-slate-900 ${
          error === undefined
            ? "border-slate-300 dark:border-slate-700"
            : "border-red-500 dark:border-red-500"
        } ${className}`}
        {...input}
      />
      {hint === undefined ? null : (
        <p id={`${id}-hint`} className="text-xs text-slate-500 dark:text-slate-400">
          {hint}
        </p>
      )}
      {error === undefined ? null : (
        <p id={`${id}-error`} className="text-sm text-red-600 dark:text-red-400">
          {error}
        </p>
      )}
    </div>
  );
}
