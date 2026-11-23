/**
 * `AuthStore` backed by PostgreSQL through Prisma (`@header-auditor/db`).
 *
 * The client is typed structurally (just the delegate methods used here)
 * rather than importing `PrismaClient`, so this module has no build-time
 * dependency on the generated client and tests can pass the real client.
 */
import {
  type AuthStore,
  EmailTakenError,
  type NewSession,
  type SessionRecord,
  type UserRecord,
} from "./store.js";

interface UserRow {
  readonly id: string;
  readonly email: string;
  readonly passwordHash: string;
  readonly createdAt: Date;
}

type SessionRow = SessionRecord;

interface CountResult {
  readonly count: number;
}

type SessionWhere =
  | { readonly id: string }
  | { readonly userId: string }
  | {
      readonly OR: [
        { readonly expiresAt: { readonly lte: Date } },
        { readonly lastSeenAt: { readonly lte: Date } },
      ];
    };

export interface PrismaAuthClient {
  readonly user: {
    findUnique(args: {
      where: { email: string } | { id: string };
      select: UserSelect;
    }): PromiseLike<UserRow | null>;
    create(args: {
      data: { email: string; passwordHash: string };
      select: UserSelect;
    }): PromiseLike<UserRow>;
    updateMany(args: {
      where: { id: string };
      data: { passwordHash: string };
    }): PromiseLike<CountResult>;
  };
  readonly session: {
    create(args: {
      data: NewSession & { lastSeenAt: Date };
      select: SessionSelect;
    }): PromiseLike<SessionRow>;
    findUnique(args: {
      where: { tokenHash: string };
      select: SessionSelect;
    }): PromiseLike<SessionRow | null>;
    updateMany(args: {
      where: { id: string };
      data: { lastSeenAt: Date };
    }): PromiseLike<CountResult>;
    deleteMany(args: { where: SessionWhere }): PromiseLike<CountResult>;
  };
}

interface UserSelect {
  id: true;
  email: true;
  passwordHash: true;
  createdAt: true;
}

interface SessionSelect {
  id: true;
  userId: true;
  tokenHash: true;
  createdAt: true;
  lastSeenAt: true;
  expiresAt: true;
  userAgent: true;
}

const USER_SELECT: UserSelect = { id: true, email: true, passwordHash: true, createdAt: true };
const SESSION_SELECT: SessionSelect = {
  id: true,
  userId: true,
  tokenHash: true,
  createdAt: true,
  lastSeenAt: true,
  expiresAt: true,
  userAgent: true,
};

/** Prisma's unique-constraint violation (duck-typed so we don't import the runtime). */
export function isUniqueViolation(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "P2002";
}

export function createPrismaAuthStore(client: PrismaAuthClient): AuthStore {
  return {
    findUserByEmail: async (email) =>
      client.user.findUnique({ where: { email: email.toLowerCase() }, select: USER_SELECT }),

    findUserById: async (id) => client.user.findUnique({ where: { id }, select: USER_SELECT }),

    async createUser(email, passwordHash): Promise<UserRecord> {
      try {
        return await client.user.create({
          data: { email: email.toLowerCase(), passwordHash },
          select: USER_SELECT,
        });
      } catch (error) {
        // Two concurrent registrations for one email: the unique index decides.
        if (isUniqueViolation(error)) throw new EmailTakenError();
        throw error;
      }
    },

    async updatePasswordHash(userId, passwordHash) {
      await client.user.updateMany({ where: { id: userId }, data: { passwordHash } });
    },

    createSession: async (session) =>
      client.session.create({
        data: { ...session, lastSeenAt: session.createdAt },
        select: SESSION_SELECT,
      }),

    findSessionByTokenHash: async (tokenHash) =>
      client.session.findUnique({ where: { tokenHash }, select: SESSION_SELECT }),

    async touchSession(id, lastSeenAt) {
      // updateMany: a session deleted concurrently (logout in another tab) is not an error.
      await client.session.updateMany({ where: { id }, data: { lastSeenAt } });
    },

    async deleteSession(id) {
      await client.session.deleteMany({ where: { id } });
    },

    async deleteUserSessions(userId) {
      return (await client.session.deleteMany({ where: { userId } })).count;
    },

    async deleteExpiredSessions(now, idleMs) {
      const idleCutoff = new Date(now.getTime() - idleMs);
      const result = await client.session.deleteMany({
        where: { OR: [{ expiresAt: { lte: now } }, { lastSeenAt: { lte: idleCutoff } }] },
      });
      return result.count;
    },
  };
}
