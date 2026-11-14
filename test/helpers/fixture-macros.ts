/**
 * Macros in test/fixtures/mcp-sanitize-fixtures.json, expanded before use so
 * multi-megabyte budget cases stay small in the file. SecID-Server-API's
 * python/test_mcp_sanitize.py implements the same expansion.
 *   {"$repeat": [[piece, count], ...]}  a string
 *   {"$list": [count, item]}             a list of `count` copies
 *   {"$map": [prefix, count, value]}     an object with keys prefix0..prefix(count-1)
 */
export function expandFixture(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(expandFixture);
  if (v && typeof v === "object") {
    const o = v as Record<string, unknown>;
    const keys = Object.keys(o);
    if (keys.length === 1 && keys[0] === "$repeat") {
      return (o.$repeat as Array<[string, number]>).map(([piece, n]) => piece.repeat(n)).join("");
    }
    if (keys.length === 1 && keys[0] === "$list") {
      const [n, item] = o.$list as [number, unknown];
      return Array.from({ length: n }, () => expandFixture(item));
    }
    if (keys.length === 1 && keys[0] === "$map") {
      const [prefix, n, value] = o.$map as [string, number, unknown];
      const out: Record<string, unknown> = {};
      for (let i = 0; i < n; i++) out[`${prefix}${i}`] = expandFixture(value);
      return out;
    }
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(o)) {
      Object.defineProperty(out, k, { value: expandFixture(x), enumerable: true, writable: true, configurable: true });
    }
    return out;
  }
  return v;
}
