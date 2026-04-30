# Repository Guidelines

## Project Structure & Module Organization
- `src/`: Worker runtime code (API, MCP, parser, resolver, KV access).
- `test/`: Vitest unit/integration tests.
- `e2e/`: Playwright browser tests.
- `scripts/`: registry build/upload and operational scripts.
- `website/`: Astro frontend bundled into Worker assets.
- `wrangler.toml`: Worker/KV/routing configuration.

## Build, Test, and Development Commands
Run from repo root.

- `npm ci`: install dependencies.
- `npm run build:registry [path-to-secid-repo]`: compile registry JSON into `src/registry.ts`.
- `npm run dev`: run local Worker with Wrangler.
- `npm run test`: run Vitest suite (`test/**/*.test.ts`).
- `npm run test:e2e`: run Playwright suite (uses `SITE_URL` or production default).
- `npm run build:website`: build Astro site for Worker static assets.
- `npm run deploy`: deploy Worker.

## Coding Style & Naming Conventions
- TypeScript + ESM modules throughout; keep interfaces in `src/types.ts` coherent with API responses.
- Prefer small, pure helpers for parser/resolver paths and keep edge-case handling covered by tests.
- Maintain clear separation between API envelope logic, resolver logic, and MCP tool wiring.

## Testing Guidelines
- Add or update Vitest coverage for parser, resolver, API envelope, KV behavior, and MCP changes.
- Add Playwright coverage for user-facing behavior when website UX or routing changes.
- When touching registry compilation/upload logic, run `npm run build:registry` and validate generated output.

## Commit & Pull Request Guidelines
- Use imperative commit messages and keep changes scoped (`parser`, `resolver`, `website`, `scripts`, etc.).
- PRs should include commands run (`test`, `test:e2e`, `build:registry`) and noteworthy output.
- Flag production-impacting changes explicitly (KV schema/key changes, limits, routing, error envelopes).

## Security & Configuration Tips
- Do not commit secrets from `.env` files.
- Treat KV namespace IDs, account IDs, and deployment tokens as operationally sensitive even when some IDs are public in config.
- Preserve explicit input limits and payload guards; they are part of abuse-resistance controls.
