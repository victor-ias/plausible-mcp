# plausible-mcp

MCP server for [Plausible Analytics](https://plausible.io) — query traffic, conversions, and compare time periods from any AI tool that supports [Model Context Protocol](https://modelcontextprotocol.io).

Built for teams that want to ask questions like:
- "Did our deploy on Tuesday affect traffic to /pricing?"
- "What's the signup conversion rate on /blog this month?"
- "How does this week's bounce rate compare to last week?"

## Tools

| Tool | Description |
|------|-------------|
| `get_timeseries` | Traffic and conversion metrics over time (daily/weekly/monthly) |
| `get_breakdown` | Break down by page, source, country, device, browser, OS, UTM params |
| `get_conversions` | Goal conversion rates, optionally per-page |
| `compare_periods` | Side-by-side comparison of two date ranges with absolute and % deltas |

All query tools are **read-only** and annotated with `readOnlyHint: true`.

Hosted deployments additionally expose `send_feedback`, which files feedback about the server itself (confusing errors, missing capabilities) into the maintainers' Sentry User Feedback inbox. It is only registered when the server runs with Sentry (`enableFeedbackTool`).

## Quick Start

### Remote (Hosted)

A hosted instance is available at **`https://plausible-mcp.sentry.dev`**.

**With your own Plausible API key** (any user):

```bash
claude mcp add --transport http plausible https://plausible-mcp.sentry.dev/mcp --header "Authorization: Bearer YOUR_PLAUSIBLE_API_KEY"
```

> Keep the URL **before** `--header`. `--header` is variadic, so if it comes last it swallows the URL and the CLI fails with `error: missing required argument 'commandOrUrl'`.

Or add manually to your MCP client config (Claude Desktop, Cursor, etc.):

```json
{
  "mcpServers": {
    "plausible": {
      "url": "https://plausible-mcp.sentry.dev/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_PLAUSIBLE_API_KEY"
      }
    }
  }
}
```

**InAppStory team** (via OAuth 2.1 + Google):

The `/internal` endpoint is an OAuth 2.1 server — no API key needed. Add it as a remote/custom connector in any OAuth-capable MCP client (Cowork, Claude.ai connectors, Claude Desktop):

```
https://plausible-mcp.victor-a1c.workers.dev/internal
```

The client discovers the OAuth endpoints automatically, sends you through Google sign-in, and only verified `@inappstory.com` identities are granted access. Queries run against a shared, server-side Plausible API key — the key is never sent to the client.

> The public `/mcp` endpoint remains bring-your-own-key and does not use the server-side key. ChatGPT should connect to `/internal`.

### Local (STDIO)

If you prefer to run it locally, use Node.js 20 or newer:

```bash
git clone https://github.com/getsentry/plausible-mcp.git
cd plausible-mcp
pnpm install
pnpm build
```

Add to Claude Code:

```bash
claude mcp add plausible -e PLAUSIBLE_API_KEY=your-key -- node /path/to/plausible-mcp/dist/index.js
```

Or Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "plausible": {
      "command": "node",
      "args": ["/path/to/plausible-mcp/dist/index.js"],
      "env": {
        "PLAUSIBLE_API_KEY": "your-key"
      }
    }
  }
}
```

### Self-Hosting (Cloudflare Workers)

Deploy your own instance:

```bash
git clone https://github.com/getsentry/plausible-mcp.git
cd plausible-mcp
pnpm install
npx wrangler deploy
```

The worker exposes two endpoints:

- **`/mcp`** — bring-your-own-key. Each user passes their own Plausible API key via the `Authorization: Bearer` header. No shared secrets needed on the server. Works with any header-capable MCP client (Claude Code, Cursor, MCP Inspector).
- **`/internal`** — OAuth-protected endpoint for ChatGPT. The Worker acts as an OAuth 2.1 authorization server and delegates human sign-in to Google. It verifies `email_verified`, applies the exact domain allowlist in `ALLOWED_EMAIL_DOMAIN`, and then uses the shared server-side Plausible key.

#### Setting up the `/internal` endpoint (Google OAuth)

1. Create a Workers KV namespace and bind it as `OAUTH_KV` in `wrangler.toml`. The OAuth provider stores tokens, rotating refresh tokens, grants, and short-lived Google state there.
2. In Google Cloud, create an OAuth 2.0 **Web application** client. Add this exact authorized redirect URI:
   `https://plausible-mcp.victor-a1c.workers.dev/oauth/google/callback`
3. Add Worker variables/secrets in Cloudflare:
   - `GOOGLE_CLIENT_ID` — the Google OAuth client ID.
   - `GOOGLE_CLIENT_SECRET` — secret.
   - `PLAUSIBLE_API_KEY` — secret used only by `/internal`.
   - `ALLOWED_EMAIL_DOMAIN` — `inappstory.com` for this deployment.
4. Deploy, then point ChatGPT at:
   `https://plausible-mcp.victor-a1c.workers.dev/internal`

The Worker publishes OAuth authorization-server and protected-resource metadata, supports PKCE and ChatGPT Client ID Metadata Documents, and issues rotating refresh tokens through `@cloudflare/workers-oauth-provider`. Other OAuth clients and redirect domains fail closed.

## Configuration

| Environment Variable | Required | Default | Description |
|---------------------|----------|---------|-------------|
| `PLAUSIBLE_API_KEY` | Yes (STDIO; Worker `/internal`) | — | Your Plausible API key ([get one here](https://plausible.io/docs/stats-api)). On the Worker this is the shared key for `/internal`; `/mcp` takes each user's own key via Bearer. |
| `PLAUSIBLE_BASE_URL` | No | `https://plausible.io` | URL of your Plausible instance (for self-hosted) |
| `PLAUSIBLE_DEFAULT_SITE_ID` | No | — | Default site domain so you don't have to pass `site_id` every call |
| `GOOGLE_CLIENT_ID` | Yes (Worker `/internal`) | — | OAuth 2.0 Web application client ID from Google Cloud. |
| `GOOGLE_CLIENT_SECRET` | Yes (Worker `/internal`) | — | OAuth client secret. Store as a Cloudflare Worker secret. |
| `OAUTH_KV` | Yes (Worker `/internal`) | — | Workers KV binding used by the OAuth 2.1 provider and short-lived Google authorization state. |
| `SENTRY_DSN` | No (Worker) | — | Sentry DSN for the Worker's own telemetry (`wrangler secret put SENTRY_DSN`). Unset disables Sentry — use your own DSN if you want telemetry on a self-hosted deployment. |
| `ALLOWED_EMAIL_DOMAIN` | Yes (Worker `/internal`) | — | Comma-separated verified Google email domain(s) allowed to sign in to `/internal`. Empty values fail closed. |
| `MCP_ALLOWED_HOSTNAMES` | Yes (Worker) | — | Comma-separated hostname allowlist used to validate MCP `Host` headers. |
| `MCP_PUBLIC_URL` | Yes (Worker `/internal`) | — | Canonical HTTPS Worker origin used to construct the exact Google callback URL. |
| `MCP_ALLOWED_ORIGIN_HOSTNAMES` | No (Worker `/internal`) | — | Comma-separated browser Origin hostnames allowed to call `/internal`. A present Origin is rejected when the list is empty. |

On the Worker, the `/mcp` endpoint needs no server-side key — each user passes their own via `Authorization: Bearer`. The `/internal` endpoint uses Google sign-in plus the Worker's OAuth 2.1 provider and a shared server-side `PLAUSIBLE_API_KEY` secret.

## Plausible API

This server wraps the [Plausible Stats API v2](https://plausible.io/docs/stats-api) (`POST /api/v2/query`). It works with both [Plausible Cloud](https://plausible.io) and [self-hosted](https://plausible.io/docs/self-hosting) instances.

### Supported Metrics

`visitors`, `visits`, `pageviews`, `views_per_visit`, `bounce_rate`, `visit_duration`, `events`, `scroll_depth`, `percentage`, `conversion_rate`, `group_conversion_rate`, `average_revenue`, `total_revenue`, `time_on_page`

### Supported Dimensions

`event:page`, `event:goal`, `event:hostname`, `visit:entry_page`, `visit:exit_page`, `visit:source`, `visit:referrer`, `visit:channel`, `visit:utm_medium`, `visit:utm_source`, `visit:utm_campaign`, `visit:utm_content`, `visit:utm_term`, `visit:device`, `visit:browser`, `visit:browser_version`, `visit:os`, `visit:os_version`, `visit:country`, `visit:region`, `visit:city`, `visit:country_name`, `visit:region_name`, `visit:city_name`

The `*_name` geography dimensions return human-readable names (e.g. "Canada"); the plain `visit:country`/`region`/`city` return ISO/Geoname codes.

### Filtering

Every query tool accepts `property_filters`, which — despite the name — filters by built-in dimensions as well as custom event properties. Each entry is `{ "property", "operator", "values" }`:

- `property` — a built-in dimension (e.g. `visit:channel`, `visit:source`, `event:page`) or a custom property as its bare name (`"plan"` targets `event:props:plan`).
- `operator` — `is`, `is_not`, `contains`, `contains_not` (default `is`). `event:goal` supports only `is` and `contains`.
- Multiple entries combine with AND, as do the `page`/`goal` shortcut parameters. Targeting `event:page`/`event:goal` from both a shortcut and `property_filters` in the same call is rejected — use one or the other.

For example, top pages for organic search traffic: `get_breakdown` with `dimension: "event:page"` and `property_filters: [{ "property": "visit:channel", "values": ["Organic Search"] }]`.

### Custom Properties

Sites send their own [custom event properties](https://plausible.io/docs/custom-props/introduction), addressed as `event:props:<name>`. These are site-specific, so there's no fixed list.

- **Break down by** a custom property: pass `get_breakdown` a `dimension` of `event:props:<name>` (e.g. `event:props:plan`).
- **Filter by** a custom property via `property_filters` with the bare name, e.g. `[{ "property": "plan", "operator": "is", "values": ["pro"] }]`.

## Development

```bash
pnpm install
pnpm build         # TypeScript compilation
pnpm test          # Run unit + integration tests
pnpm test:watch    # Watch mode
```

### Testing with MCP Inspector

```bash
pnpm build
PLAUSIBLE_API_KEY=your-key npx @modelcontextprotocol/inspector node dist/index.js
```

### LLM Evals

Verifies the model picks the right tool for natural language analytics questions. Runs through
OpenRouter, so any tool-calling model works — the default is `anthropic/claude-sonnet-5`:

```bash
OPENROUTER_API_KEY=sk-or-... pnpm eval
OPENROUTER_MODEL=openai/gpt-5 OPENROUTER_API_KEY=sk-or-... pnpm eval  # try another model
```

## Architecture

```
src/
├── index.ts              # STDIO entry point (local use)
├── worker.ts             # Shared Worker MCP handlers
├── oauth-worker.ts       # OAuth 2.1 Worker entry point (remote)
├── google-oauth.ts       # Google login, consent, CSRF/state, domain checks
├── env.ts                # Worker environment bindings
├── cf-access.ts          # Legacy verifier retained for upstream tests
├── server.ts             # Creates McpServer, registers all tools
├── plausible.ts          # PlausibleClient — standalone API client
├── schemas.ts            # Shared Zod schemas and filter helpers
├── errors.ts             # UserFacingError and tool-error reporting
├── telemetry.ts          # Pure classifiers — route, MCP request kind, client family
├── mcp-telemetry.ts      # Records MCP client info onto the active span
├── redaction.ts          # Strips PII from Sentry events on the BYOK path
└── tools/
    ├── get-timeseries.ts
    ├── get-breakdown.ts
    ├── get-conversions.ts
    ├── compare-periods.ts
    └── send-feedback.ts
```

`PlausibleClient` has zero MCP dependency and can be used standalone.

### Observability & data collection

When `SENTRY_DSN` is configured, the Worker reports with an endpoint-dependent privacy posture:

- **`/mcp` (bring-your-own-key)** — fully anonymous. Tool inputs and outputs are **not** recorded (that data belongs to the caller and their own key), no identity is attached, and the ingest-inferred client IP is stripped (`src/redaction.ts`). Only operational telemetry remains: tool names, span timings, and failures.
- **`/internal` (OAuth-gated)** — attributed. Requests carry the authenticated Google email (`Sentry.setUser`), and tool inputs/outputs **are** recorded (`recordToolIO`) for attribution and abuse-tracing on the shared server-side key.

`Authorization` / `Cookie` / `Cf-Access-Jwt-Assertion` headers are stripped from spans on both paths. As a belt-and-suspenders backstop, enable **Prevent Storing of IP Addresses** in the Sentry project's Security & Privacy settings.

## License

MIT — see [LICENSE](LICENSE).
