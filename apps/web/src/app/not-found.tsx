import Link from "next/link";

export default function NotFound() {
  return (
    <main className="mx-auto flex min-h-screen max-w-md flex-col items-center justify-center gap-4 px-4 text-center">
      <p className="text-sm font-semibold text-brand-600">404</p>
      <h1 className="text-2xl font-bold">Page not found</h1>
      <Link href="/dashboard" className="text-brand-600 underline hover:text-brand-700">
        Back to the dashboard
      </Link>
    </main>
  );
}
