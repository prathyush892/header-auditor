import type { NextConfig } from "next";

import { API_PROXY_PREFIX, parseApiInternalUrl, SECURITY_HEADERS } from "./src/lib/server-config";

const apiOrigin = parseApiInternalUrl(process.env.API_INTERNAL_URL);

const config: NextConfig = {
  reactStrictMode: true,
  // `X-Powered-By: Next.js` is exactly the info-disclosure header our own scanner flags.
  poweredByHeader: false,
  // The workspace runs ESLint from the root (`pnpm lint`); don't lint twice.
  eslint: { ignoreDuringBuilds: true },
  async headers() {
    return Promise.resolve([{ source: "/:path*", headers: [...SECURITY_HEADERS] }]);
  },
  // The browser only ever talks to its own origin. `/api/*` is forwarded to
  // the API server-side, so the session cookie is first-party, SameSite works
  // as intended, and the API needs no CORS at all.
  async rewrites() {
    return Promise.resolve([
      { source: `${API_PROXY_PREFIX}/:path*`, destination: `${apiOrigin}/:path*` },
    ]);
  },
};

export default config;
