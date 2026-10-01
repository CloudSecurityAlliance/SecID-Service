// What the MCP endpoint (/mcp and /mcp/) answers for every HTTP method
// other than POST. One function, one table, so the rule cannot drift
// between routes.
//
// Same behaviour as CSA-MCP-Core `src/mcp/method-gate.ts` (the csa-mcp
// server); kept as a local copy because this repo is public and that one is
// not. If you change the table here, change it there — the fleet check that
// tests every hosted CSA MCP server against one contract is what catches the
// two drifting apart.
//
// Why it exists: on 2026-09-30 csa-mcp was found redirecting GET /mcp to an
// HTML page, which put MCP clients in a one-second reconnect loop (the TS
// SDK follows the redirect, never checks Content-Type, reads the HTML as an
// empty SSE stream and resets its retry counter). SecID already answered GET
// and DELETE with 405 (since 2026-03-05) but returned 404 for every other
// method, sent no Allow header, and advertised methods it does not serve.
//
// The asymmetry that decides every ambiguous case: a browser wrongly given a
// 405 sees an error page once; an MCP client wrongly given a redirect loops
// for its whole session. So browsers are identified POSITIVELY and
// everything else is treated as an MCP client.

import type { Context, MiddlewareHandler } from "hono";

/** Every 405 names what the endpoint does accept (RFC 9110 §10.2.1: MUST). */
export const MCP_ENDPOINT_ALLOW = "POST, OPTIONS";

/**
 * Registered HTTP methods this endpoint does not serve. RFC 9110 §9.1:
 * recognised but not allowed → 405; anything else → 501. QUERY is RFC 10008
 * (2026-06-15). TRACE and CONNECT are refused by Cloudflare's edge before
 * they reach the Worker; listed so the origin answers correctly regardless.
 */
const KNOWN_UNSERVED_METHODS = new Set(["GET", "HEAD", "PUT", "PATCH", "DELETE", "QUERY", "TRACE", "CONNECT"]);

/**
 * True only for a request we can positively identify as a person in a
 * browser navigating to the URL. MCP-client signals are checked first, so a
 * client sending a broad Accept header is never mistaken for a browser.
 */
export function isBrowserNavigation(headers: Headers): boolean {
  const accept = (headers.get("accept") ?? "").toLowerCase();
  // MCP spec (2025-06-18, 2025-11-25): a client's GET "MUST include an Accept
  // header, listing text/event-stream". Browsers never send it on a navigation.
  if (accept.includes("text/event-stream")) return false;
  // Only MCP clients send these.
  if (headers.has("mcp-protocol-version") || headers.has("mcp-session-id")) return false;
  // W3C Fetch Metadata: set by the browser itself, unmodifiable from
  // JavaScript. Not guaranteed on every browser, hence the fallback.
  if ((headers.get("sec-fetch-mode") ?? "").toLowerCase() === "navigate") return true;
  return accept.includes("text/html");
}

/** The status a non-POST, non-OPTIONS request to the MCP endpoint gets. */
export function statusForMethod(method: string, browser: boolean, hasSetupUrl: boolean): 302 | 405 | 501 {
  const m = method.toUpperCase();
  if ((m === "GET" || m === "HEAD") && browser && hasSetupUrl) return 302;
  return KNOWN_UNSERVED_METHODS.has(m) ? 405 : 501;
}

/**
 * Middleware for exactly `/mcp` and `/mcp/`. POST passes through to the MCP
 * handler; OPTIONS never arrives here because the CORS middleware answers it
 * first. HEAD keeps its method here (Hono only reroutes it through the GET
 * routes), so statusForMethod treats HEAD exactly like GET (RFC 9110 §9.3.2).
 */
export function mcpEndpointMethodGate<C extends Context>(setupUrl: (c: C) => string | undefined): MiddlewareHandler {
  return async (c, next) => {
    const method = c.req.method.toUpperCase();
    if (method === "POST" || method === "OPTIONS") return next();

    const url = setupUrl(c as C);
    const status = statusForMethod(method, isBrowserNavigation(c.req.raw.headers), Boolean(url));

    // The answer depends on request headers, so a cache must be told, and must
    // never hand one requester's answer to another.
    c.header("Vary", "Accept, Sec-Fetch-Mode");
    c.header("Cache-Control", "no-store");

    if (status === 302 && url) {
      return c.redirect(url, 302);
    }

    c.header("Allow", MCP_ENDPOINT_ALLOW);
    const hint = url ? ` Setup instructions: ${url}` : "";
    const message =
      status === 405
        ? `Method Not Allowed. This MCP endpoint accepts POST only: it offers no SSE stream on GET and no sessions to DELETE (stateless server).${hint}`
        : `Not Implemented. Unrecognised HTTP method.${hint}`;
    return c.json({ jsonrpc: "2.0", error: { code: -32000, message }, id: null }, status);
  };
}
