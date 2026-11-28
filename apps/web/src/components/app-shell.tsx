"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { type ReactNode, useEffect, useState } from "react";

import { describeError } from "@/lib/api";
import { loginUrlFor } from "@/lib/redirect";
import { useSession } from "@/lib/session";

import { Button } from "./button";
import { Logo } from "./logo";

const NAV = [{ href: "/dashboard", label: "Overview" }] as const;

/**
 * Frame for every signed-in page. Renders nothing private until the API has
 * confirmed the session; a signed-out visitor is sent to /login with `next`.
 */
export function AppShell({ children }: { readonly children: ReactNode }) {
  const { state, signOut, refresh } = useSession();
  const router = useRouter();
  const pathname = usePathname();
  const [signingOut, setSigningOut] = useState(false);
  const [signOutError, setSignOutError] = useState<string | null>(null);

  useEffect(() => {
    if (state.status === "anonymous" && !signingOut) router.replace(loginUrlFor(pathname));
  }, [pathname, router, signingOut, state.status]);

  async function onSignOut() {
    setSigningOut(true);
    setSignOutError(null);
    try {
      await signOut();
    } catch (error) {
      // Signed out locally either way; tell the user the server didn't confirm.
      setSignOutError(describeError(error));
    }
    router.replace("/login");
  }

  if (state.status === "error") {
    return (
      <main className="mx-auto flex min-h-screen max-w-md flex-col items-center justify-center gap-4 px-4 text-center">
        <p role="alert">{state.message}</p>
        <Button variant="secondary" onClick={() => void refresh()}>
          Try again
        </Button>
      </main>
    );
  }

  if (state.status !== "authenticated") {
    return (
      <main className="flex min-h-screen items-center justify-center" aria-busy="true">
        <p className="text-sm text-slate-500">Loading…</p>
      </main>
    );
  }

  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
        <div className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-4 py-3">
          <div className="flex items-center gap-8">
            <Link href="/dashboard" aria-label="header-auditor home">
              <Logo />
            </Link>
            <nav aria-label="Main" className="hidden gap-4 text-sm sm:flex">
              {NAV.map((item) => (
                <Link
                  key={item.href}
                  href={item.href}
                  aria-current={pathname === item.href ? "page" : undefined}
                  className="text-slate-600 hover:text-slate-900 aria-[current=page]:font-semibold aria-[current=page]:text-slate-900 dark:text-slate-400 dark:hover:text-white dark:aria-[current=page]:text-white"
                >
                  {item.label}
                </Link>
              ))}
            </nav>
          </div>
          <div className="flex items-center gap-3">
            <span className="hidden max-w-[16rem] truncate text-sm text-slate-600 sm:inline dark:text-slate-400">
              {state.user.email}
            </span>
            <Button variant="secondary" busy={signingOut} onClick={() => void onSignOut()}>
              Sign out
            </Button>
          </div>
        </div>
      </header>
      {signOutError === null ? null : (
        <p role="alert" className="bg-amber-50 px-4 py-2 text-center text-sm text-amber-900">
          {signOutError}
        </p>
      )}
      <main className="mx-auto max-w-6xl px-4 py-8">{children}</main>
    </div>
  );
}
