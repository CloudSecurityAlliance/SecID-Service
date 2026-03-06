import { Hono } from "hono";
import { cors } from "hono/cors";
import { handleResolve, handleRegistryDownload } from "./api";
import { handleMCP } from "./mcp";
import type { AppEnv } from "./types";
import { buildErrorEntry, recordError } from "./observability";

const app = new Hono<AppEnv>();

app.use("*", cors());

// Global error handler — catches anything that escapes individual route handlers
app.onError(async (err, c) => {
  const entry = buildErrorEntry("global", c.req.url, err, c.req.raw);
  const errorId = await recordError(c.env.secid_OBSERVABILITY, entry);

  return c.json(
    {
      secid_query: c.req.query("secid") ?? "",
      status: "error",
      results: [],
      message: `Internal error resolving query. Reference: ${errorId}`,
      error_id: errorId,
    },
    500,
  );
});

app.get("/api/v1/resolve", handleResolve);
app.get("/api/v1/registry.json", handleRegistryDownload);

app.get("/health", (c) => c.json({ status: "ok" }));

// MCP Streamable HTTP endpoint (POST only — stateless, no SSE streaming)
app.post("/mcp", handleMCP);
app.get("/mcp", (c) =>
  c.json({ jsonrpc: "2.0", error: { code: -32000, message: "SSE streaming not supported. Use POST for JSON-RPC requests." }, id: null }, 405)
);
app.delete("/mcp", (c) =>
  c.json({ jsonrpc: "2.0", error: { code: -32000, message: "Session management not supported. This is a stateless server." }, id: null }, 405)
);

// Shareable resolve URL — redirects to homepage with ?secid= for client-side resolution
app.get("/resolve", (c) => {
  const secid = c.req.query("secid");
  if (secid) {
    const target = new URL("/", c.req.url);
    target.searchParams.set("secid", secid);
    return c.redirect(target.toString(), 302);
  }
  return c.redirect("/", 302);
});

// 404 for unmatched routes (static assets are served before this by [assets])
app.all("*", (c) => c.json({ error: "Not found" }, 404));

export default app;
