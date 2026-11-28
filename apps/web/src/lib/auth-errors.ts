/**
 * Turns whatever a sign-in or sign-up call threw into messages for the form.
 * Pure, so every branch is unit-tested without rendering anything.
 */
import { ApiError, describeError, fieldErrors } from "./api";
import type { FieldErrors } from "./validation";

const FIELD_NAMES = ["email", "password"] as const;

function capitalise(message: string): string {
  const text = message.charAt(0).toUpperCase() + message.slice(1);
  return /[.!?]$/.test(text) ? text : `${text}.`;
}

export function authErrorMessages(error: unknown): FieldErrors {
  if (!(error instanceof ApiError)) return { _form: describeError(error) };
  switch (error.code) {
    case "INVALID_CREDENTIALS":
      // Same wording whether the account exists or not, like the API.
      return { _form: "That email and password don't match an account." };
    case "EMAIL_TAKEN":
      return { email: "An account with this email already exists. Sign in instead?" };
    case "VALIDATION_FAILED": {
      const grouped = fieldErrors(error);
      const result: Record<string, string> = {};
      for (const name of FIELD_NAMES) {
        // eslint-disable-next-line security/detect-object-injection -- name is a fixed literal
        const messages = grouped[name];
        if (messages !== undefined && messages.length > 0) {
          // eslint-disable-next-line security/detect-object-injection -- name is a fixed literal
          result[name] = messages.map(capitalise).join(" ");
        }
      }
      return Object.keys(result).length > 0 ? result : { _form: describeError(error) };
    }
    default:
      return { _form: describeError(error) };
  }
}
