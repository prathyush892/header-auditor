import type { ReactNode } from "react";

import { Logo } from "@/components/logo";

export default function AuthLayout({ children }: { readonly children: ReactNode }) {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-10 px-4 py-12">
      <Logo className="text-lg" />
      <div className="flex w-full max-w-md justify-center rounded-xl border border-slate-200 bg-white p-8 shadow-sm dark:border-slate-800 dark:bg-slate-900">
        {children}
      </div>
    </main>
  );
}
