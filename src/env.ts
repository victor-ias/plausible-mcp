import type { OAuthHelpers } from "@cloudflare/workers-oauth-provider";

interface RateLimiter {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

/** Worker environment bindings. */
export interface Env {
  // Plausible
  PLAUSIBLE_BASE_URL?: string;
  PLAUSIBLE_DEFAULT_SITE_ID?: string;
  /** Shared Plausible API key used by the OAuth-protected /internal endpoint. */
  PLAUSIBLE_API_KEY?: string;

  // Sentry
  /**
   * Sentry DSN for the Worker's own telemetry. Set as a secret on deployments that
   * want Sentry (`wrangler secret put SENTRY_DSN`); leave unset to run without it.
   */
  SENTRY_DSN?: string;
  SENTRY_RELEASE?: string;

  /**
   * Comma-separated email domain(s) allowed to sign in to /internal (the "@" is
   * optional). The verified Google identity is checked after login and again on
   * every authenticated MCP request.
   */
  ALLOWED_EMAIL_DOMAIN?: string;

  /** Comma-separated hostname allowlist for MCP Host-header validation. */
  MCP_ALLOWED_HOSTNAMES: string;
  /** Canonical public origin used for OAuth redirect URI construction. */
  MCP_PUBLIC_URL?: string;
  /** Browser Origin hostnames allowed to call the OAuth-authenticated /internal endpoint. */
  MCP_ALLOWED_ORIGIN_HOSTNAMES?: string;

  // Cloudflare bindings
  RATE_LIMITER?: RateLimiter;
  OAUTH_KV: KVNamespace;
  /** Injected by @cloudflare/workers-oauth-provider for authorization routes. */
  OAUTH_PROVIDER?: OAuthHelpers;

  // Google OAuth
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
}
