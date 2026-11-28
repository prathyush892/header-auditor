import "./globals.css";

import type { Metadata, Viewport } from "next";
import type { ReactNode } from "react";

import { SessionProvider } from "@/lib/session";

export const metadata: Metadata = {
  title: { default: "header-auditor", template: "%s · header-auditor" },
  description: "Self-hosted security scanner for your websites' HTTP headers, TLS and DNS.",
  // A private dashboard: nothing here should be in a search index.
  robots: { index: false, follow: false },
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({ children }: { readonly children: ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen font-sans">
        <SessionProvider>{children}</SessionProvider>
      </body>
    </html>
  );
}
