import { Hono } from "hono";
import { cors } from "hono/cors";
import { handleResolve, handleRegistryDownload, handleTypes } from "./api";
import { handleMCP } from "./mcp";
import { mcpEndpointMethodGate } from "./method-gate";
import type { AppEnv } from "./types";
import { buildErrorEntry, recordError } from "./observability";

const app = new Hono<AppEnv>();

// CORS: open to browser-hosted MCP clients and API callers. SecID is public
// and unauthenticated, so there is no ambient credential to protect; never add
// credentials: true. Methods are listed explicitly — the bare cors() default
// advertised PUT, DELETE and PATCH, which nothing here serves.
app.use(
  "*",
  cors({
    origin: "*",
    allowMethods: ["GET", "HEAD", "POST", "OPTIONS"],
    allowHeaders: ["Content-Type", "Accept", "MCP-Protocol-Version", "Mcp-Method", "Mcp-Name"],
    maxAge: 86400,
  }),
);

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
app.get("/api/v1/types", handleTypes);

app.get("/health", (c) => c.json({ status: "ok" }));

// MCP Streamable HTTP endpoint — stateless, POST only. Every other method on
// /mcp and /mcp/ is answered by the method gate (src/method-gate.ts): 405 with
// Allow for MCP clients and for every registered method, a 302 to the setup
// section of the homepage for a browser navigation, 501 for unregistered
// methods. Registered before the POST route so the table covers /mcp/ too.
const methodGate = mcpEndpointMethodGate((c) => new URL("/#mcp-setup", c.req.url).toString());
app.use("/mcp", methodGate);
app.use("/mcp/", methodGate);
app.post("/mcp", handleMCP);
app.post("/mcp/", handleMCP);

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
