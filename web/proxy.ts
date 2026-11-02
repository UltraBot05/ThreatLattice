import { NextResponse, type NextRequest } from "next/server";
import { readSessionToken, SESSION_COOKIE } from "@/lib/auth/token";

/**
 * Optimistic page guard (Next 16 "proxy", formerly middleware).
 * - App pages need a valid session cookie, else -> /login?next=<page>.
 * - /admin pages need the admin role in the token, else -> /dashboard.
 * - Signed-in users visiting /login or /register go to /dashboard.
 * This only improves navigation. The real check is requireUser()/requireRole()
 * in every API route, which also re-reads the user from MySQL.
 */
const PROTECTED = ["/dashboard", "/search", "/explore", "/investigations", "/cve", "/spotlight", "/admin", "/styleguide"];

export async function proxy(req: NextRequest) {
  const { pathname, search } = req.nextUrl;
  const user = await readSessionToken(req.cookies.get(SESSION_COOKIE)?.value);

  if ((pathname === "/login" || pathname === "/register") && user) {
    return NextResponse.redirect(new URL("/dashboard", req.url));
  }

  const isProtected = PROTECTED.some((p) => pathname === p || pathname.startsWith(`${p}/`));
  if (isProtected && !user) {
    const url = new URL("/login", req.url);
    url.searchParams.set("next", pathname + search);
    return NextResponse.redirect(url);
  }

  if (pathname.startsWith("/admin") && user?.role !== "admin") {
    return NextResponse.redirect(new URL("/dashboard", req.url));
  }

  return NextResponse.next();
}

export const config = {
  // Skip API routes, Next internals and static files.
  matcher: ["/((?!api|_next/static|_next/image|icon.svg|favicon.ico).*)"],
};
