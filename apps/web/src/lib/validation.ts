/**
 * Client-side checks for the auth forms. They mirror the API's rules
 * (apps/api/src/auth/password.ts) so users get instant feedback, but they are
 * a convenience only: the API validates everything again, and its answer wins.
 */
export const PASSWORD_MIN_LENGTH = 15;
export const PASSWORD_MAX_LENGTH = 128;
export const EMAIL_MAX_LENGTH = 254;

export type FieldErrors = Readonly<Partial<Record<"email" | "password" | "_form", string>>>;

/** Same normalisation the API applies before storing or looking up an email. */
export function normalizeEmail(value: string): string {
  return value.trim().toLowerCase();
}

/** NFC, as the API does before hashing, so "é" typed two ways is one password. */
function normalizePassword(password: string): string {
  return password.normalize("NFC");
}

function emailProblem(email: string): string | undefined {
  if (email === "") return "Enter your email address.";
  if (email.length > EMAIL_MAX_LENGTH) return "That email address is too long.";
  // Deliberately loose: one @, something on each side, a dot in the domain.
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return "Enter a valid email address.";
  return undefined;
}

export function validateLogin(input: { email: string; password: string }): FieldErrors {
  const errors: Record<string, string> = {};
  const email = emailProblem(normalizeEmail(input.email));
  if (email !== undefined) errors.email = email;
  if (input.password === "") errors.password = "Enter your password.";
  return errors;
}

export function validateRegistration(input: { email: string; password: string }): FieldErrors {
  const errors: Record<string, string> = {};
  const normalizedEmail = normalizeEmail(input.email);
  const email = emailProblem(normalizedEmail);
  if (email !== undefined) errors.email = email;
  const password = normalizePassword(input.password);
  // Code points, not UTF-16 units, so an emoji counts as one character (as on the API).
  // eslint-disable-next-line @typescript-eslint/no-misused-spread
  const length = [...password].length;
  if (length < PASSWORD_MIN_LENGTH) {
    errors.password = `Use at least ${String(PASSWORD_MIN_LENGTH)} characters. A few random words work well.`;
  } else if (length > PASSWORD_MAX_LENGTH) {
    errors.password = `Use at most ${String(PASSWORD_MAX_LENGTH)} characters.`;
  } else if (password.trim() === "") {
    errors.password = "The password can't be only spaces.";
  } else if (new Set(password).size === 1) {
    errors.password = "The password can't be one character repeated.";
  } else if (password.toLowerCase() === normalizedEmail) {
    errors.password = "The password can't be your email address.";
  }
  return errors;
}

export function hasErrors(errors: FieldErrors): boolean {
  return Object.keys(errors).length > 0;
}
