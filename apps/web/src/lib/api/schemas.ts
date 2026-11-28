/**
 * Runtime schemas for what the API sends back.
 *
 * TypeScript types disappear at runtime, so a type alone can't tell us the API
 * actually returned a user. Every response the client hands to the UI is
 * parsed here first; if the API and the dashboard drift apart (a renamed
 * field, a deploy of one without the other), the client fails loudly with
 * `ApiResponseError` instead of rendering `undefined`. The contract test runs
 * these schemas against the real API so drift is caught in CI, not in prod.
 */
import { z } from "zod";

const isoDate = z.iso.datetime({ offset: true });

export const userSchema = z.object({
  id: z.string().min(1),
  email: z.string().min(1),
  createdAt: isoDate,
});

/** Body of `POST /auth/register` and `POST /auth/login`. */
export const sessionResponseSchema = z.object({
  user: userSchema,
  csrfToken: z.string().min(1),
  expiresAt: isoDate,
});

/** Body of `GET /auth/session`. */
export const currentSessionSchema = sessionResponseSchema.extend({
  idleExpiresAt: isoDate,
});

/** Body of `GET /health`. */
export const healthSchema = z.object({
  status: z.literal("ok"),
  uptimeSeconds: z.number().int().nonnegative(),
});

/** The one error shape every API failure uses (see apps/api/src/errors.ts). */
export const errorBodySchema = z.object({
  error: z.object({
    code: z.string().min(1),
    message: z.string(),
    requestId: z.string(),
    details: z.array(z.object({ path: z.string(), message: z.string() })).optional(),
  }),
});

export type User = z.infer<typeof userSchema>;
export type SessionResponse = z.infer<typeof sessionResponseSchema>;
export type CurrentSession = z.infer<typeof currentSessionSchema>;
export type Health = z.infer<typeof healthSchema>;
export type ErrorBody = z.infer<typeof errorBodySchema>;
export type ErrorDetail = NonNullable<ErrorBody["error"]["details"]>[number];

export interface Credentials {
  readonly email: string;
  readonly password: string;
}
