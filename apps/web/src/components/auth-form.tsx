"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { type SubmitEvent, useEffect, useId, useRef, useState } from "react";

import { authErrorMessages } from "@/lib/auth-errors";
import { safeNextPath } from "@/lib/redirect";
import { useSession } from "@/lib/session";
import {
  type FieldErrors,
  hasErrors,
  PASSWORD_MAX_LENGTH,
  PASSWORD_MIN_LENGTH,
  validateLogin,
  validateRegistration,
} from "@/lib/validation";

import { Button } from "./button";
import { Field } from "./field";

export type AuthMode = "login" | "register";

/** A text field's value; files (or a missing field) become "". */
function formText(data: FormData, name: string): string {
  const value = data.get(name);
  return typeof value === "string" ? value : "";
}

const COPY = {
  login: {
    title: "Sign in",
    submit: "Sign in",
    busy: "Signing in…",
    switchText: "New here?",
    switchLink: "Create an account",
    switchHref: "/register",
  },
  register: {
    title: "Create your account",
    submit: "Create account",
    busy: "Creating account…",
    switchText: "Already have an account?",
    switchLink: "Sign in",
    switchHref: "/login",
  },
} as const;

export function AuthForm({ mode }: { readonly mode: AuthMode }) {
  const copy = mode === "login" ? COPY.login : COPY.register;
  const router = useRouter();
  const params = useSearchParams();
  const next = safeNextPath(params.get("next"));
  const { state, signIn, register } = useSession();
  const [errors, setErrors] = useState<FieldErrors>({});
  const [busy, setBusy] = useState(false);
  const formErrorRef = useRef<HTMLDivElement>(null);
  const id = useId();

  // Already signed in (e.g. opened /login in a second tab): go on.
  useEffect(() => {
    if (state.status === "authenticated") router.replace(next);
  }, [next, router, state.status]);

  useEffect(() => {
    if (errors._form !== undefined) formErrorRef.current?.focus();
  }, [errors._form]);

  async function onSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    const data = new FormData(event.currentTarget);
    const credentials = {
      email: formText(data, "email"),
      password: formText(data, "password"),
    };
    const problems =
      mode === "login" ? validateLogin(credentials) : validateRegistration(credentials);
    setErrors(problems);
    if (hasErrors(problems)) return;

    setBusy(true);
    try {
      await (mode === "login" ? signIn(credentials) : register(credentials));
      router.replace(next);
    } catch (error) {
      setErrors(authErrorMessages(error));
      setBusy(false);
    }
  }

  const switchHref =
    next === safeNextPath(null)
      ? copy.switchHref
      : `${copy.switchHref}?next=${encodeURIComponent(next)}`;

  return (
    <div className="w-full max-w-sm">
      <h1 className="mb-6 text-2xl font-bold tracking-tight">{copy.title}</h1>
      <form noValidate onSubmit={(event) => void onSubmit(event)} className="flex flex-col gap-4">
        {errors._form === undefined ? null : (
          <div
            ref={formErrorRef}
            tabIndex={-1}
            role="alert"
            className="rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-800 dark:border-red-800 dark:bg-red-950 dark:text-red-200"
          >
            {errors._form}
          </div>
        )}
        <Field
          id={`${id}-email`}
          name="email"
          type="email"
          label="Email"
          autoComplete="email"
          inputMode="email"
          autoCapitalize="none"
          spellCheck={false}
          required
          maxLength={254}
          error={errors.email}
        />
        <Field
          id={`${id}-password`}
          name="password"
          type="password"
          label="Password"
          autoComplete={mode === "login" ? "current-password" : "new-password"}
          required
          minLength={mode === "register" ? PASSWORD_MIN_LENGTH : undefined}
          maxLength={mode === "register" ? PASSWORD_MAX_LENGTH : 1024}
          hint={
            mode === "register"
              ? `At least ${String(PASSWORD_MIN_LENGTH)} characters. A passphrase is easiest.`
              : undefined
          }
          error={errors.password}
        />
        <Button type="submit" busy={busy} className="mt-2 w-full">
          {busy ? copy.busy : copy.submit}
        </Button>
      </form>
      <p className="mt-6 text-sm text-slate-600 dark:text-slate-400">
        {copy.switchText}{" "}
        <Link href={switchHref} className="font-medium text-brand-600 hover:text-brand-700">
          {copy.switchLink}
        </Link>
      </p>
    </div>
  );
}
