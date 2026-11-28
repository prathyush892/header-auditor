/**
 * Optimistic gate for signed-in pages: no session cookie at all → straight
 * to /login, without rendering the app shell first. This is a UX shortcut,
 * not access control. Every API call is authorised by the API itself.
 */
import { type NextRequest, NextResponse } from "next/server";

import { loginUrlFor } from "./lib/redirect";
import { hasSessionCookie } from "./lib/session-cookie";

export function middleware(request: NextRequest): NextResponse {
  if (hasSessionCookie(request.cookies)) return NextResponse.next();
  const { pathname, search } = request.nextUrl;
  // Next.js needs an absolute Location here. It is built from the request's
  // own URL, never from the Host header, so a forged Host can't turn this into
  // a redirect to another site.
  return NextResponse.redirect(new URL(loginUrlFor(`${pathname}${search}`), request.nextUrl));
}

export const config = {
  matcher: ["/dashboard/:path*"],
};
