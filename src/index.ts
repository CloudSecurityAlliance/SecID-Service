import { Hono } from "hono";
import { cors } from "hono/cors";
import { handleResolve } from "./api";
import { handleMCP } from "./mcp";

const app = new Hono();

app.use("*", cors());

app.get("/api/v1/resolve", handleResolve);

app.get("/health", (c) => c.json({ status: "ok" }));

// MCP Streamable HTTP endpoint
app.post("/mcp", handleMCP);
app.get("/mcp", handleMCP);
app.delete("/mcp", handleMCP);

// 404 for unmatched routes (static assets are served before this by [assets])
app.all("*", (c) => c.json({ error: "Not found" }, 404));

export default app;
