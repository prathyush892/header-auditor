import { NextRequest } from "next/server";
import { describe, expect, it } from "vitest";

import { config, middleware } from "@/middleware";

function request(path: string, cookie?: string): NextRequest {
  return new NextRequest(new URL(path, "http://localhost:3000"), {
    headers: cookie === undefined ? {} : { cookie },
  });
}

describe("middleware", () => {
  it("only runs on dashboard routes", () => {
    expect(config.matcher).toEqual(["/dashboard/:path*"]);
  });

  it("sends a visitor without a session cookie to /login", () => {
    const response = middleware(request("/dashboard"));
    expect(response.status).toBe(307);
    expect(response.headers.get("location")).toBe("http://localhost:3000/login");
  });

  it("keeps where they were going in ?next=", () => {
    const response = middleware(request("/dashboard/sites?page=2"));
    expect(response.headers.get("location")).toBe(
      "http://localhost:3000/login?next=%2Fdashboard%2Fsites%3Fpage%3D2",
    );
  });

  it.each(["ha_session=x", "__Host-ha_session=x"])("lets %s through", (cookie) => {
    const response = middleware(request("/dashboard", cookie));
    expect(response.headers.get("location")).toBeNull();
    expect(response.headers.get("x-middleware-next")).toBe("1");
  });

  it("ignores a forged Host header when building the redirect", () => {
    const response = middleware(
      new NextRequest(new URL("/dashboard", "http://localhost:3000"), {
        headers: { host: "evil.example" },
      }),
    );
    expect(response.headers.get("location")).toBe("http://localhost:3000/login");
  });

  it("ignores unrelated cookies", () => {
    expect(middleware(request("/dashboard", "theme=dark")).status).toBe(307);
  });
});
