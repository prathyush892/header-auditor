import type { Metadata } from "next";
import { Suspense } from "react";

import { AuthForm } from "@/components/auth-form";

export const metadata: Metadata = { title: "Sign in" };

export default function LoginPage() {
  // useSearchParams (for ?next=) needs a Suspense boundary to prerender.
  return (
    <Suspense>
      <AuthForm mode="login" />
    </Suspense>
  );
}
