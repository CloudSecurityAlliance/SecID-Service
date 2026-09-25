import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

export default defineWorkersConfig({
  test: {
    include: ["test/**/*.test.ts"],
    // beforeAll hooks seed the whole registry into test KV (seedRegistryKV).
    // That grows with the registry — disa.json alone has ~14k patterns — and
    // on a slow CI runner it brushed the 10s default, failing a production
    // deploy at random. Generous, because a false timeout blocks a deploy.
    hookTimeout: 60_000,
    poolOptions: {
      workers: {
        wrangler: { configPath: "./wrangler.toml" },
      },
    },
  },
});
