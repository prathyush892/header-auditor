import type { Metadata } from "next";

import { Greeting } from "./greeting";

export const metadata: Metadata = { title: "Overview" };

export default function DashboardPage() {
  return (
    <div className="flex flex-col gap-8">
      <Greeting />
      <section
        aria-labelledby="sites-heading"
        className="rounded-xl border border-dashed border-slate-300 bg-white p-8 text-center dark:border-slate-700 dark:bg-slate-900"
      >
        <h2 id="sites-heading" className="text-lg font-semibold">
          No sites yet
        </h2>
        <p className="mx-auto mt-2 max-w-md text-sm text-slate-600 dark:text-slate-400">
          Add a site, prove you own its domain with a DNS TXT record, and header-auditor will grade
          its security headers, TLS and DNS on a schedule. Adding sites from the dashboard is coming
          next.
        </p>
      </section>
    </div>
  );
}
