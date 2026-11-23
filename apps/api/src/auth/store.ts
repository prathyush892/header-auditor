/**
 * Persistence boundary for auth. Routes depend on this interface only, so
 * tests run against `MemoryAuthStore` and production plugs in the Prisma
 * implementation (`createPrismaAuthStore`) without the routes changing.
 */
import { randomUUID } from "node:crypto";

export interface UserRecord {
  readonly id: string;
  /** Always lower-case. */
  readonly email: string;
  readonly passwordHash: string;
  readonly createdAt: Date;
}

export interface SessionRecord {
  readonly id: string;
  readonly userId: string;
  readonly tokenHash: string;
  readonly createdAt: Date;
  readonly lastSeenAt: Date;
  readonly expiresAt: Date;
  readonly userAgent: string | null;
}

export interface NewSession {
  readonly userId: string;
  readonly tokenHash: string;
  readonly createdAt: Date;
  readonly expiresAt: Date;
  readonly userAgent: string | null;
}

/** Thrown by `createUser` when the (lower-cased) email already exists. */
export class EmailTakenError extends Error {
  override readonly name = "EmailTakenError";

  constructor() {
    super("email already registered");
  }
}

export interface AuthStore {
  findUserByEmail(email: string): Promise<UserRecord | null>;
  findUserById(id: string): Promise<UserRecord | null>;
  /** @throws EmailTakenError */
  createUser(email: string, passwordHash: string): Promise<UserRecord>;
  updatePasswordHash(userId: string, passwordHash: string): Promise<void>;

  createSession(session: NewSession): Promise<SessionRecord>;
  findSessionByTokenHash(tokenHash: string): Promise<SessionRecord | null>;
  touchSession(id: string, lastSeenAt: Date): Promise<void>;
  /** No-op if it is already gone. */
  deleteSession(id: string): Promise<void>;
  deleteUserSessions(userId: string): Promise<number>;
  /** Removes sessions whose absolute expiry or idle deadline has passed. */
  deleteExpiredSessions(now: Date, idleMs: number): Promise<number>;
}

export function isSessionExpired(session: SessionRecord, now: Date, idleMs: number): boolean {
  return (
    session.expiresAt.getTime() <= now.getTime() ||
    session.lastSeenAt.getTime() + idleMs <= now.getTime()
  );
}

/** In-process store for tests and local experiments. Not shared between instances. */
export class MemoryAuthStore implements AuthStore {
  private readonly users = new Map<string, UserRecord>();
  private readonly sessions = new Map<string, SessionRecord>();

  findUserByEmail(email: string): Promise<UserRecord | null> {
    return Promise.resolve(this.userByEmail(email.toLowerCase()));
  }

  findUserById(id: string): Promise<UserRecord | null> {
    return Promise.resolve(this.users.get(id) ?? null);
  }

  createUser(email: string, passwordHash: string): Promise<UserRecord> {
    // Check-and-insert with no await in between, so it is atomic like a unique index.
    const lower = email.toLowerCase();
    if (this.userByEmail(lower) !== null) return Promise.reject(new EmailTakenError());
    const user: UserRecord = {
      id: randomUUID(),
      email: lower,
      passwordHash,
      createdAt: new Date(),
    };
    this.users.set(user.id, user);
    return Promise.resolve(user);
  }

  updatePasswordHash(userId: string, passwordHash: string): Promise<void> {
    const user = this.users.get(userId);
    if (user !== undefined) this.users.set(userId, { ...user, passwordHash });
    return Promise.resolve();
  }

  createSession(session: NewSession): Promise<SessionRecord> {
    const record: SessionRecord = { id: randomUUID(), lastSeenAt: session.createdAt, ...session };
    this.sessions.set(record.id, record);
    return Promise.resolve(record);
  }

  findSessionByTokenHash(tokenHash: string): Promise<SessionRecord | null> {
    for (const session of this.sessions.values()) {
      if (session.tokenHash === tokenHash) return Promise.resolve(session);
    }
    return Promise.resolve(null);
  }

  touchSession(id: string, lastSeenAt: Date): Promise<void> {
    const session = this.sessions.get(id);
    if (session !== undefined) this.sessions.set(id, { ...session, lastSeenAt });
    return Promise.resolve();
  }

  deleteSession(id: string): Promise<void> {
    this.sessions.delete(id);
    return Promise.resolve();
  }

  deleteUserSessions(userId: string): Promise<number> {
    return Promise.resolve(this.deleteWhere((s) => s.userId === userId));
  }

  deleteExpiredSessions(now: Date, idleMs: number): Promise<number> {
    return Promise.resolve(this.deleteWhere((s) => isSessionExpired(s, now, idleMs)));
  }

  private userByEmail(lowerEmail: string): UserRecord | null {
    for (const user of this.users.values()) {
      if (user.email === lowerEmail) return user;
    }
    return null;
  }

  /** Test helper: every stored session. */
  allSessions(): SessionRecord[] {
    return [...this.sessions.values()];
  }

  private deleteWhere(predicate: (session: SessionRecord) => boolean): number {
    let removed = 0;
    for (const [id, session] of this.sessions) {
      if (predicate(session)) {
        this.sessions.delete(id);
        removed += 1;
      }
    }
    return removed;
  }
}
