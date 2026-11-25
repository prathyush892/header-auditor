/** Engine results built from the real core functions, without any network. */
import { buildContentReport, buildReport, HeaderMap, runAll } from "@header-auditor/core";

import type { EngineResult } from "../../src/engine.js";
import type { ProcessorLogger } from "../../src/processor.js";

export const SCAN_ID = "0b9d6c3e-6a0f-4c5e-9f51-3f0b3f2c9a10";

export function fakeResult(url = "https://shop.example.com/"): EngineResult {
  const headers = new HeaderMap({
    "strict-transport-security": "max-age=63072000; includeSubDomains",
    "x-content-type-options": "nosniff",
    server: "nginx/1.25.3",
  });
  const report = buildReport(url, 200, runAll(headers, { isHttps: true }));
  const content = buildContentReport({
    pageUrl: url,
    headers,
    redirects: [],
    html: "<p>hello</p>",
    bodyBytes: 12,
    bodyTruncated: false,
  });
  return {
    engine: { name: "header-auditor-core", version: "0.0.0" },
    requestedUrl: url.replace(/\/$/, ""),
    finalUrl: url,
    httpStatus: 200,
    score: report.score,
    grade: report.grade,
    redirects: [],
    headers: report,
    content,
    tls: { status: "error", code: "TIMEOUT", message: "The site did not respond in time." },
    dns: { status: "skipped", reason: "test" },
    wellKnown: { status: "skipped", reason: "test" },
  };
}

export interface LogEntry {
  readonly level: "info" | "warn" | "error";
  readonly object: Record<string, unknown>;
  readonly message: string;
}

export class TestLogger implements ProcessorLogger {
  readonly entries: LogEntry[] = [];

  info(object: Record<string, unknown>, message: string): void {
    this.entries.push({ level: "info", object, message });
  }

  warn(object: Record<string, unknown>, message: string): void {
    this.entries.push({ level: "warn", object, message });
  }

  error(object: Record<string, unknown>, message: string): void {
    this.entries.push({ level: "error", object, message });
  }

  messages(): string[] {
    return this.entries.map((e) => e.message);
  }
}
