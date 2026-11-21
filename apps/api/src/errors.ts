/**
 * One error shape for every failure the API returns:
 *
 *   { "error": { "code": "VALIDATION_FAILED", "message": "...", "requestId": "...", "details": [...] } }
 *
 * Client errors (4xx) explain what was wrong. Server errors (5xx) never leak
 * internals: the client gets a generic message plus the request id, and the
 * real error goes to the log under that same id.
 */
import type { FastifyError, FastifyReply, FastifyRequest } from "fastify";
import { ZodError } from "zod";

export interface ErrorDetail {
  readonly path: string;
  readonly message: string;
}

export interface ErrorBody {
  readonly error: {
    readonly code: string;
    readonly message: string;
    readonly requestId: string;
    readonly details?: readonly ErrorDetail[];
  };
}

export interface AppErrorOptions {
  readonly details?: readonly ErrorDetail[];
  readonly cause?: unknown;
}

/**
 * An error the application throws on purpose. Its message is shown to the
 * client for 4xx statuses; for 5xx it is only logged.
 */
export class AppError extends Error {
  override readonly name = "AppError";
  readonly statusCode: number;
  readonly code: string;
  readonly details: readonly ErrorDetail[] | undefined;

  constructor(statusCode: number, code: string, message: string, options: AppErrorOptions = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    if (!isHttpErrorStatus(statusCode)) {
      throw new RangeError(`AppError status must be 400-599, got ${String(statusCode)}`);
    }
    if (!/^[A-Z][A-Z0-9_]{0,63}$/.test(code)) {
      throw new RangeError(`AppError code must be UPPER_SNAKE_CASE, got ${JSON.stringify(code)}`);
    }
    this.statusCode = statusCode;
    this.code = code;
    this.details = options.details;
  }
}

export const INTERNAL_ERROR_MESSAGE = "Internal Server Error";

/** Codes for 4xx errors raised by Fastify itself (bad JSON, body too large, ...). */
const STATUS_CODES: ReadonlyMap<number, string> = new Map([
  [400, "BAD_REQUEST"],
  [401, "UNAUTHORIZED"],
  [403, "FORBIDDEN"],
  [404, "NOT_FOUND"],
  [405, "METHOD_NOT_ALLOWED"],
  [406, "NOT_ACCEPTABLE"],
  [408, "REQUEST_TIMEOUT"],
  [409, "CONFLICT"],
  [413, "PAYLOAD_TOO_LARGE"],
  [415, "UNSUPPORTED_MEDIA_TYPE"],
  [422, "UNPROCESSABLE_ENTITY"],
  [429, "RATE_LIMITED"],
  [431, "HEADERS_TOO_LARGE"],
  [503, "SERVICE_UNAVAILABLE"],
]);

export function isHttpErrorStatus(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 400 && value <= 599;
}

function issuePath(path: readonly PropertyKey[]): string {
  return path.length === 0 ? "<root>" : path.map(String).join(".");
}

export function zodDetails(error: ZodError): ErrorDetail[] {
  return error.issues.map((issue) => ({ path: issuePath(issue.path), message: issue.message }));
}

/** Fastify's JSON-schema validation errors carry `validation` (Ajv output). */
function fastifyValidationDetails(error: FastifyError): ErrorDetail[] | undefined {
  if (!Array.isArray(error.validation)) return undefined;
  return error.validation.map((item) => ({
    path:
      item.instancePath === ""
        ? "<root>"
        : item.instancePath.replace(/^\//, "").replaceAll("/", "."),
    message: item.message ?? "is invalid",
  }));
}

export interface ClassifiedError {
  readonly statusCode: number;
  readonly code: string;
  readonly message: string;
  readonly details?: readonly ErrorDetail[];
  /** True when the client sees a generic message and the cause must be logged. */
  readonly internal: boolean;
}

/** Decides what the client sees for any thrown value. Pure, so it is unit-tested directly. */
export function classifyError(error: unknown): ClassifiedError {
  if (error instanceof ZodError) {
    return {
      statusCode: 400,
      code: "VALIDATION_FAILED",
      message: "Request validation failed",
      details: zodDetails(error),
      internal: false,
    };
  }
  if (error instanceof AppError) {
    if (error.statusCode >= 500) {
      return {
        statusCode: error.statusCode,
        code: error.code,
        message: INTERNAL_ERROR_MESSAGE,
        internal: true,
      };
    }
    return {
      statusCode: error.statusCode,
      code: error.code,
      message: error.message,
      ...(error.details === undefined ? {} : { details: error.details }),
      internal: false,
    };
  }
  const fastifyError = error as Partial<FastifyError> | null;
  const statusCode = fastifyError?.statusCode;
  if (isHttpErrorStatus(statusCode) && statusCode < 500 && error instanceof Error) {
    const details = fastifyValidationDetails(error as FastifyError);
    if (details !== undefined) {
      return {
        statusCode: 400,
        code: "VALIDATION_FAILED",
        message: "Request validation failed",
        details,
        internal: false,
      };
    }
    return {
      statusCode,
      code: STATUS_CODES.get(statusCode) ?? "BAD_REQUEST",
      message: error.message,
      internal: false,
    };
  }
  return {
    statusCode: 500,
    code: "INTERNAL_ERROR",
    message: INTERNAL_ERROR_MESSAGE,
    internal: true,
  };
}

export function errorBody(classified: ClassifiedError, requestId: string): ErrorBody {
  return {
    error: {
      code: classified.code,
      message: classified.message,
      requestId,
      ...(classified.details === undefined ? {} : { details: classified.details }),
    },
  };
}

/** Fastify error handler: classify, log at the right level, reply with ErrorBody. */
export function errorHandler(
  error: unknown,
  request: FastifyRequest,
  reply: FastifyReply,
): FastifyReply {
  const classified = classifyError(error);
  if (classified.internal) {
    request.log.error({ err: error }, "request failed");
  } else {
    request.log.info({ statusCode: classified.statusCode, code: classified.code }, "client error");
  }
  return reply
    .status(classified.statusCode)
    .type("application/json; charset=utf-8")
    .send(errorBody(classified, request.id));
}

/** 404 for unknown routes. The path is not echoed back, so nothing user-supplied is reflected. */
export function notFoundHandler(request: FastifyRequest, reply: FastifyReply): FastifyReply {
  const classified: ClassifiedError = {
    statusCode: 404,
    code: "NOT_FOUND",
    message: "Route not found",
    internal: false,
  };
  return reply
    .status(404)
    .type("application/json; charset=utf-8")
    .send(errorBody(classified, request.id));
}
