/**
 * DATABASE_URL validation.
 *
 * The API and worker read the connection string from the environment; a typo
 * there should fail at startup with a clear message, not as an opaque driver
 * error on the first query. Error messages never echo the password.
 */

export class DatabaseConfigError extends Error {
  override readonly name = "DatabaseConfigError";
}

const ALLOWED_PROTOCOLS = new Set(["postgres:", "postgresql:"]);

/** Same URL with the password replaced, safe to log. */
export function redactDatabaseUrl(url: URL | string): string {
  let parsed: URL;
  try {
    parsed = new URL(url.toString());
  } catch {
    return "<invalid database url>";
  }
  if (parsed.password !== "") parsed.password = "***";
  return parsed.toString();
}

/**
 * Parses and checks a PostgreSQL connection string.
 *
 * Requires a postgres(ql):// scheme, a host and a database name. Query
 * parameters (sslmode, schema, connection_limit, ...) are passed through.
 */
export function parseDatabaseUrl(raw: string | undefined): URL {
  if (raw === undefined || raw.trim() === "") {
    throw new DatabaseConfigError("DATABASE_URL is not set");
  }
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    // The raw value may contain a password, so it is not included.
    throw new DatabaseConfigError("DATABASE_URL is not a valid URL");
  }
  if (!ALLOWED_PROTOCOLS.has(url.protocol)) {
    throw new DatabaseConfigError(
      `DATABASE_URL must use postgres:// or postgresql://, got ${url.protocol}//`,
    );
  }
  if (url.hostname === "") {
    throw new DatabaseConfigError(`DATABASE_URL has no host: ${redactDatabaseUrl(url)}`);
  }
  const database = decodeURIComponent(url.pathname.replace(/^\//, ""));
  if (database === "" || database.includes("/")) {
    throw new DatabaseConfigError(
      `DATABASE_URL must name exactly one database: ${redactDatabaseUrl(url)}`,
    );
  }
  return url;
}
