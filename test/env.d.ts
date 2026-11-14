// Bindings the vitest-pool-workers runtime provides to tests via
// `import { env } from "cloudflare:test"`, as declared in wrangler.toml.
// Non-optional here (unlike AppBindings) because the test runtime always
// creates all of them.
declare module "cloudflare:test" {
  interface ProvidedEnv {
    secid_REGISTRY: KVNamespace;
    secid_OBSERVABILITY: KVNamespace;
    secid_FEEDBACK: KVNamespace;
    secid_DEMAND: AnalyticsEngineDataset;
  }
}

// Vite `?raw` imports (used to load JSON fixtures as text, so JSON.parse keeps
// keys such as "__proto__" as plain own properties).
declare module "*?raw" {
  const text: string;
  export default text;
}
