/**
 * Guards on docker-compose.yml and .env.example: local databases must never
 * listen on every interface, and the committed example must stay a template.
 * Text-based on purpose: no YAML dependency, and CI also runs
 * `docker compose config` to check the file actually parses.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { parseDatabaseUrl } from "../src/index.js";

const root = new URL("../../../", import.meta.url);
const read = (name: string): string =>
  // Fixed repo files named in this test, not user input.
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  readFileSync(fileURLToPath(new URL(name, root)), "utf8");

const compose = read("docker-compose.yml");
const envExample = read(".env.example");

function publishedPorts(yaml: string): string[] {
  const ports: string[] = [];
  let inPorts = false;
  for (const line of yaml.split("\n")) {
    if (/^\s+ports:\s*$/.test(line)) {
      inPorts = true;
      continue;
    }
    const item = /^\s+-\s+"?([^"]+)"?\s*$/.exec(line);
    if (inPorts && item?.[1] !== undefined) {
      ports.push(item[1]);
      continue;
    }
    inPorts = false;
  }
  return ports;
}

describe("docker-compose.yml", () => {
  it("defines postgres and redis", () => {
    expect(compose).toMatch(/^ {2}postgres:$/m);
    expect(compose).toMatch(/^ {2}redis:$/m);
  });

  it("publishes every port on 127.0.0.1 only", () => {
    const ports = publishedPorts(compose);
    expect(ports).toHaveLength(2);
    for (const port of ports) expect(port).toMatch(/^127\.0\.0\.1:/);
  });

  it("has no default passwords", () => {
    expect(compose).toContain("${POSTGRES_PASSWORD:?");
    expect(compose).toContain("${REDIS_PASSWORD:?");
    expect(compose).not.toMatch(/PASSWORD:-/);
  });

  it("pins image versions instead of :latest", () => {
    const images = [...compose.matchAll(/^\s+image:\s+(\S+)$/gm)].map((m) => m[1]);
    expect(images.length).toBeGreaterThan(0);
    for (const image of images) expect(image).toMatch(/:\d/);
  });
});

describe(".env.example", () => {
  it("contains only placeholder secrets", () => {
    for (const line of envExample.split("\n")) {
      const match = /^(\w*PASSWORD)=(.*)$/.exec(line);
      if (match) expect(match[2]).toBe("change-me-local-only");
    }
  });

  it("has a DATABASE_URL that passes the same validation the app uses", () => {
    const line = envExample.split("\n").find((l) => l.startsWith("DATABASE_URL="));
    const url = parseDatabaseUrl(line?.slice("DATABASE_URL=".length));
    expect(url.hostname).toBe("127.0.0.1");
  });
});
