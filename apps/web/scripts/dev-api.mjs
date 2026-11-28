// Local-development API for working on the dashboard without Postgres or Redis.
//
//   pnpm build && pnpm --filter @header-auditor/web dev:api
//
// Starts the real API (built `@header-auditor/api`) with in-memory auth and
// site stores on 127.0.0.1:3001. Everything is lost on restart. Refuses to
// run with NODE_ENV=production: this is not a deployment path.
import { MemoryAuthStore, MemorySiteStore, start } from "@header-auditor/api";

if (process.env.NODE_ENV === "production") {
  process.stderr.write("dev-api: refusing to start with NODE_ENV=production\n");
  process.exit(1);
}

await start({
  env: {
    ...process.env,
    NODE_ENV: "development",
    API_HOST: "127.0.0.1",
    API_PORT: process.env.API_PORT ?? "3001",
    // Plain http on localhost: browsers drop Secure cookies there.
    AUTH_COOKIE_SECURE: "false",
    // The dashboard's one canonical origin: open http://localhost:3000, not 127.0.0.1.
    API_ALLOWED_ORIGINS: process.env.API_ALLOWED_ORIGINS ?? "http://localhost:3000",
  },
  auth: { store: new MemoryAuthStore() },
  sites: { store: new MemorySiteStore() },
});
