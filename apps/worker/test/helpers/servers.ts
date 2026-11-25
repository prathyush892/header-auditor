/** Mock target sites. Everything listens on 127.0.0.1 with an OS-assigned port. */
import { createServer as createHttpServer, type RequestListener, type Server } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import type { AddressInfo } from "node:net";

export interface MockSite {
  readonly port: number;
  readonly requests: string[];
  close(): Promise<void>;
}

async function listen(server: Server, requests: string[]): Promise<MockSite> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    port,
    requests,
    close: () =>
      new Promise((resolve, reject) => {
        server.closeAllConnections();
        server.close((error) => {
          if (error) reject(error);
          else resolve();
        });
      }),
  };
}

/** A small site: a hardened home page, security.txt and robots.txt. */
export function siteHandler(requests: string[]): RequestListener {
  return (req, res) => {
    requests.push(req.url ?? "");
    if (req.url === "/.well-known/security.txt") {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("Contact: mailto:security@shop.test\nExpires: 2099-01-01T00:00:00.000Z\n");
      return;
    }
    if (req.url === "/robots.txt") {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("User-agent: *\nDisallow: /admin/\n");
      return;
    }
    if (req.url === "/") {
      res.writeHead(200, {
        "content-type": "text/html; charset=utf-8",
        "strict-transport-security": "max-age=63072000; includeSubDomains",
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()",
        "cross-origin-opener-policy": "same-origin",
      });
      res.end(
        '<!doctype html><title>Shop</title><script src="https://assets.cdn-provider.test/app.js"></script>',
      );
      return;
    }
    res.writeHead(404, { "content-type": "text/plain" });
    res.end("not found");
  };
}

export function startHttpSite(): Promise<MockSite> {
  const requests: string[] = [];
  return listen(createHttpServer(siteHandler(requests)), requests);
}

export function startHttpsSite(tls: { key: string; cert: string }): Promise<MockSite> {
  const requests: string[] = [];
  return listen(createHttpsServer({ ...tls }, siteHandler(requests)), requests);
}
