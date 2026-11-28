"use client";

import { useSession } from "@/lib/session";

export function Greeting() {
  const { state } = useSession();
  if (state.status !== "authenticated") return null;
  return (
    <div>
      <h1 className="text-2xl font-bold tracking-tight">Overview</h1>
      <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
        Signed in as <span className="font-medium">{state.user.email}</span>
      </p>
    </div>
  );
}
