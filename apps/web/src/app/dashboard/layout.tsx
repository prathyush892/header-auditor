import type { ReactNode } from "react";

import { AppShell } from "@/components/app-shell";

export default function DashboardLayout({ children }: { readonly children: ReactNode }) {
  return <AppShell>{children}</AppShell>;
}
