/**
 * Persistence boundary for sites.
 *
 * Every method takes the owner's id and every query filters on it. There is
 * deliberately no "find site by id" without an owner: the only way to reach a
 * site is through the user who owns it, so a route can't forget the
 * authorization check, because there is no unscoped query to call by mistake.
 */
import { randomUUID } from "node:crypto";

export const SCHEDULES = ["NONE", "DAILY", "WEEKLY"] as const;
export type Schedule = (typeof SCHEDULES)[number];

export interface SiteRecord {
  readonly id: string;
  readonly ownerId: string;
  readonly name: string;
  /** Normalised origin, e.g. "https://example.com". */
  readonly url: string;
  readonly verificationToken: string;
  readonly verifiedAt: Date | null;
  readonly schedule: Schedule;
  readonly firstPartyHosts: readonly string[];
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

export interface NewSite {
  readonly ownerId: string;
  readonly name: string;
  readonly url: string;
  readonly verificationToken: string;
  readonly schedule: Schedule;
  readonly firstPartyHosts: readonly string[];
}

/** Fields left undefined are unchanged. */
export interface SitePatch {
  readonly name?: string | undefined;
  readonly schedule?: Schedule | undefined;
  readonly firstPartyHosts?: readonly string[] | undefined;
}

/** Position in the newest-first listing; the next page starts strictly after it. */
export interface SiteCursor {
  readonly createdAt: Date;
  readonly id: string;
}

export interface ListSitesOptions {
  readonly limit: number;
  readonly after?: SiteCursor;
}

/** The owner already has a site with this (normalised) URL. */
export class SiteExistsError extends Error {
  override readonly name = "SiteExistsError";

  constructor() {
    super("site already exists for this owner");
  }
}

/** The owner is at their site quota. */
export class SiteLimitError extends Error {
  override readonly name = "SiteLimitError";

  constructor(readonly limit: number) {
    super(`site limit of ${String(limit)} reached`);
  }
}

export interface SiteStore {
  /** Newest first, ties broken by id, so pages never overlap or skip rows. */
  listSites(ownerId: string, options: ListSitesOptions): Promise<SiteRecord[]>;
  findSite(ownerId: string, id: string): Promise<SiteRecord | null>;
  /**
   * Atomically checks the quota and the per-owner URL uniqueness, then inserts.
   * @throws SiteLimitError, SiteExistsError
   */
  createSite(site: NewSite, maxSites: number): Promise<SiteRecord>;
  /** Null when the site doesn't exist or belongs to someone else. */
  updateSite(ownerId: string, id: string, patch: SitePatch): Promise<SiteRecord | null>;
  /** False when the site doesn't exist or belongs to someone else. */
  deleteSite(ownerId: string, id: string): Promise<boolean>;
}

/** Newest-first comparison shared by the memory store and the cursor tests. */
export function compareNewestFirst(a: SiteCursor, b: SiteCursor): number {
  const byTime = b.createdAt.getTime() - a.createdAt.getTime();
  if (byTime !== 0) return byTime;
  if (a.id === b.id) return 0;
  return a.id < b.id ? 1 : -1;
}

/** In-process store for tests. Mirrors the Postgres semantics, including atomic create. */
export class MemorySiteStore implements SiteStore {
  private readonly sites = new Map<string, SiteRecord>();

  constructor(private readonly now: () => Date = () => new Date()) {}

  listSites(ownerId: string, options: ListSitesOptions): Promise<SiteRecord[]> {
    const { after } = options;
    const page = this.owned(ownerId)
      .sort(compareNewestFirst)
      .filter((site) => after === undefined || compareNewestFirst(after, site) < 0)
      .slice(0, options.limit);
    return Promise.resolve(page);
  }

  findSite(ownerId: string, id: string): Promise<SiteRecord | null> {
    const site = this.sites.get(id);
    return Promise.resolve(site?.ownerId === ownerId ? site : null);
  }

  createSite(site: NewSite, maxSites: number): Promise<SiteRecord> {
    // No await between the checks and the insert, so this is atomic like the SQL version.
    const owned = this.owned(site.ownerId);
    if (owned.some((existing) => existing.url === site.url)) {
      return Promise.reject(new SiteExistsError());
    }
    if (owned.length >= maxSites) return Promise.reject(new SiteLimitError(maxSites));
    const at = this.now();
    const record: SiteRecord = {
      ...site,
      firstPartyHosts: [...site.firstPartyHosts],
      id: randomUUID(),
      verifiedAt: null,
      createdAt: at,
      updatedAt: at,
    };
    this.sites.set(record.id, record);
    return Promise.resolve(record);
  }

  updateSite(ownerId: string, id: string, patch: SitePatch): Promise<SiteRecord | null> {
    const site = this.sites.get(id);
    if (site?.ownerId !== ownerId) return Promise.resolve(null);
    const updated: SiteRecord = {
      ...site,
      ...(patch.name === undefined ? {} : { name: patch.name }),
      ...(patch.schedule === undefined ? {} : { schedule: patch.schedule }),
      ...(patch.firstPartyHosts === undefined
        ? {}
        : { firstPartyHosts: [...patch.firstPartyHosts] }),
      updatedAt: this.now(),
    };
    this.sites.set(id, updated);
    return Promise.resolve(updated);
  }

  deleteSite(ownerId: string, id: string): Promise<boolean> {
    if (this.sites.get(id)?.ownerId !== ownerId) return Promise.resolve(false);
    this.sites.delete(id);
    return Promise.resolve(true);
  }

  /** Test helper: marks a site verified (domain verification arrives in roadmap step 17). */
  markVerified(id: string, at: Date): void {
    const site = this.sites.get(id);
    if (site !== undefined) this.sites.set(id, { ...site, verifiedAt: at });
  }

  private owned(ownerId: string): SiteRecord[] {
    return [...this.sites.values()].filter((site) => site.ownerId === ownerId);
  }
}
