/**
 * robots.txt sensitive-path exposure.
 *
 * robots.txt is public and is only a request to well-behaved crawlers, so a
 * `Disallow: /old-backup/` line doesn't hide anything: it hands the path to
 * anyone who reads the file. This check parses the rules (RFC 9309) and flags
 * paths that look like admin panels, backups, secrets or source control.
 *
 * It never requests the listed paths: it reports what the site advertises,
 * not whether those paths are actually reachable.
 */
import { makeFinding, Status, type Finding } from "../finding.js";
import type { WellKnownObservation } from "./observation.js";
import { stripBom } from "./security-txt.js";

export const ROBOTS_TXT_CHECK = "robots.txt";
export const ROBOTS_TXT_WEIGHT = 10;
export const ROBOTS_TXT_PATH = "/robots.txt";
/** RFC 9309 §2.5: crawlers must parse at least 500 KiB. */
export const ROBOTS_TXT_MAX_BYTES = 512 * 1024;
/** Rules kept from one file; the rest are counted but not analysed. */
export const MAX_ROBOTS_RULES = 5000;
/** Example paths listed per finding. */
export const MAX_ROBOTS_EXAMPLES = 8;

export type RuleKind = "allow" | "disallow";

export interface RobotsRule {
  readonly kind: RuleKind;
  readonly path: string;
  /** User agents of the group this rule belongs to (lower-cased). */
  readonly userAgents: readonly string[];
  readonly line: number;
}

export interface ParsedRobotsTxt {
  readonly rules: readonly RobotsRule[];
  readonly sitemaps: readonly string[];
  /** Rules beyond MAX_ROBOTS_RULES that were not kept. */
  readonly droppedRules: number;
}

/**
 * Parses robots.txt per RFC 9309: `user-agent` lines open a group (consecutive
 * ones share it), `allow`/`disallow` lines belong to the current group,
 * comments start at `#`, unknown lines are ignored. Never throws.
 */
export function parseRobotsTxt(text: string): ParsedRobotsTxt {
  const rules: RobotsRule[] = [];
  const sitemaps: string[] = [];
  let dropped = 0;
  let agents: string[] = [];
  let lastWasAgent = false;
  const lines = stripBom(text).split(/\r?\n|\r/);
  for (const [index, raw] of lines.entries()) {
    const hash = raw.indexOf("#");
    const content = (hash === -1 ? raw : raw.slice(0, hash)).trim();
    const colon = content.indexOf(":");
    if (colon === -1) continue;
    const key = content.slice(0, colon).trim().toLowerCase();
    const value = content.slice(colon + 1).trim();
    if (key === "user-agent") {
      agents = lastWasAgent ? [...agents, value.toLowerCase()] : [value.toLowerCase()];
      lastWasAgent = true;
      continue;
    }
    lastWasAgent = false;
    if (key === "sitemap") {
      if (value !== "") sitemaps.push(value);
      continue;
    }
    if ((key !== "allow" && key !== "disallow") || value === "") continue;
    if (rules.length >= MAX_ROBOTS_RULES) {
      dropped += 1;
      continue;
    }
    rules.push(
      Object.freeze({
        kind: key,
        path: value,
        userAgents: Object.freeze(agents.length > 0 ? [...agents] : ["*"]),
        line: index + 1,
      }),
    );
  }
  return Object.freeze({
    rules: Object.freeze(rules),
    sitemaps: Object.freeze(sitemaps),
    droppedRules: dropped,
  });
}

/** How much listing a path gives away. "low" is reported but costs nothing. */
export type ExposureLevel = "high" | "medium" | "low";

export type ExposureCategory =
  | "source-control"
  | "secrets-config"
  | "backup-dump"
  | "admin-interface"
  | "non-production"
  | "internal"
  | "logs"
  | "installer"
  | "framework-default";

export interface SensitivePath {
  readonly path: string;
  readonly kind: RuleKind;
  readonly category: ExposureCategory;
  readonly level: ExposureLevel;
  readonly line: number;
}

interface Pattern {
  readonly category: ExposureCategory;
  readonly level: ExposureLevel;
  /** Whole path segments (or their stem before the first dot). */
  readonly segments?: readonly string[];
  /** Segment prefixes, for dot-files like `.env.local`. */
  readonly prefixes?: readonly string[];
  /** File extensions, without the dot. */
  readonly extensions?: readonly string[];
}

/**
 * Ordered most to least severe: a path is classified by the first match.
 * Matching is on whole segments, so `/administration-guide` isn't "admin".
 */
export const SENSITIVE_PATTERNS: readonly Pattern[] = [
  {
    category: "source-control",
    level: "high",
    prefixes: [".git", ".svn", ".hg", ".bzr"],
    segments: ["cvs"],
  },
  {
    category: "secrets-config",
    level: "high",
    prefixes: [".env", ".aws", ".ssh", ".htpasswd", ".npmrc", ".docker"],
    segments: ["wp-config", "credentials", "secrets", "id_rsa", "config.php", "settings.php"],
    extensions: ["pem", "key", "env"],
  },
  {
    category: "backup-dump",
    level: "high",
    segments: ["backup", "backups", "bak", "dump", "dumps", "db_backup", "database"],
    // Archive extensions (.zip, .gz) are left out: sites often disallow crawling
    // ordinary downloads, so they'd be noise. These are clearly leftovers.
    extensions: ["sql", "bak", "backup", "old", "orig", "dump", "swp"],
  },
  {
    category: "framework-default",
    level: "low",
    segments: ["wp-admin", "wp-includes", "wp-login"],
  },
  {
    category: "admin-interface",
    level: "medium",
    segments: [
      "admin",
      "administrator",
      "phpmyadmin",
      "pma",
      "adminer",
      "cpanel",
      "manager",
      "server-status",
      "server-info",
      "actuator",
      "_admin",
    ],
  },
  {
    category: "installer",
    level: "medium",
    segments: ["install", "installer", "setup"],
  },
  {
    category: "logs",
    level: "medium",
    segments: ["log", "logs", "error_log"],
    extensions: ["log"],
  },
  {
    category: "non-production",
    level: "medium",
    segments: ["staging", "dev", "debug", "tmp", "temp", "test", "beta", "old", "phpinfo"],
  },
  {
    category: "internal",
    level: "medium",
    segments: ["internal", "private", "secret", "hidden", "confidential"],
  },
];

/** Splits a robots path into lower-cased segments, dropping wildcards and the query. */
export function pathSegments(path: string): string[] {
  let p = path.toLowerCase();
  const q = p.indexOf("?");
  if (q !== -1) p = p.slice(0, q);
  try {
    p = decodeURIComponent(p);
  } catch {
    // Keep the raw path when it has invalid percent-escapes.
  }
  return p
    .split("/")
    .map((s) => s.replaceAll("*", "").replaceAll("$", "").trim())
    .filter((s) => s !== "");
}

function matches(pattern: Pattern, segment: string): boolean {
  const dot = segment.indexOf(".", 1);
  const stem = dot === -1 ? segment : segment.slice(0, dot);
  const lastDot = segment.lastIndexOf(".");
  // A leading dot counts too: "/*.sql$" leaves the segment ".sql".
  const ext = lastDot === -1 ? "" : segment.slice(lastDot + 1);
  if (pattern.segments?.some((s) => s === segment || s === stem)) return true;
  if (pattern.prefixes?.some((p) => segment.startsWith(p))) return true;
  return ext !== "" && (pattern.extensions?.includes(ext) ?? false);
}

/** Classifies one robots path, or undefined when nothing sensitive is in it. */
export function classifyPath(path: string): Pick<SensitivePath, "category" | "level"> | undefined {
  const segments = pathSegments(path);
  for (const pattern of SENSITIVE_PATTERNS) {
    if (segments.some((segment) => matches(pattern, segment))) {
      return { category: pattern.category, level: pattern.level };
    }
  }
  return undefined;
}

/** Every rule whose path looks sensitive, de-duplicated by path. */
export function findSensitivePaths(rules: readonly RobotsRule[]): SensitivePath[] {
  const seen = new Set<string>();
  const found: SensitivePath[] = [];
  for (const rule of rules) {
    if (seen.has(rule.path)) continue;
    seen.add(rule.path);
    const hit = classifyPath(rule.path);
    if (hit) {
      found.push(Object.freeze({ path: rule.path, kind: rule.kind, line: rule.line, ...hit }));
    }
  }
  return found;
}

function describe(paths: readonly SensitivePath[]): string {
  const shown = paths.slice(0, MAX_ROBOTS_EXAMPLES).map((p) => `${p.path} (${p.category})`);
  const more = paths.length - shown.length;
  return shown.join(", ") + (more > 0 ? `, and ${String(more)} more` : "");
}

/**
 * Grades a robots.txt observation:
 * - pass (10): missing, or nothing sensitive listed (framework defaults like
 *   `/wp-admin/` are mentioned but not penalised: they reveal nothing new);
 * - warn (7): admin, staging, internal, log or installer paths listed;
 * - warn (3): source control, secrets/config or backup paths listed;
 * - info: couldn't be fetched, unscored.
 */
export function checkRobotsTxt(obs: WellKnownObservation): Finding {
  const base = { check: ROBOTS_TXT_CHECK, weight: ROBOTS_TXT_WEIGHT };
  if (obs.kind === "error") {
    return makeFinding({
      check: ROBOTS_TXT_CHECK,
      status: Status.Info,
      detail: `Could not be fetched (${obs.code}).`,
    });
  }
  if (obs.kind === "missing") {
    return makeFinding({
      ...base,
      status: Status.Pass,
      score: ROBOTS_TXT_WEIGHT,
      detail: `No robots.txt (${obs.reason}); no paths advertised.`,
    });
  }
  const parsed = parseRobotsTxt(obs.text);
  const sensitive = findSensitivePaths(parsed.rules);
  const scored = sensitive.filter((p) => p.level !== "low");
  const counted = `${String(parsed.rules.length)} rule(s)${
    parsed.droppedRules > 0 ? ` (+${String(parsed.droppedRules)} not analysed)` : ""
  }${obs.truncated ? ", file truncated" : ""}`;

  if (scored.length === 0) {
    const defaults =
      sensitive.length > 0 ? ` Framework defaults only: ${describe(sensitive)}.` : "";
    return makeFinding({
      ...base,
      status: Status.Pass,
      score: ROBOTS_TXT_WEIGHT,
      detail: `${counted}; no sensitive paths advertised.${defaults}`,
    });
  }
  // High-risk entries (VCS, secrets, backups) cost more than medium ones (admin, staging...).
  const score = scored.some((p) => p.level === "high") ? 3 : 7;
  return makeFinding({
    ...base,
    status: Status.Warn,
    score,
    detail: `${counted}; advertises ${String(scored.length)} sensitive path(s): ${describe(scored)}.`,
    recommendation:
      "robots.txt is public and does not restrict access. Remove these entries and protect " +
      "the paths with authentication, or remove the files (backups, VCS metadata, secrets) " +
      "from the web root entirely.",
  });
}
