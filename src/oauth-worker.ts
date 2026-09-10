import * as Sentry from "@sentry/cloudflare";
import OAuthProvider from "@cloudflare/workers-oauth-provider";
import type { Env } from "./env.js";
import {
  googleMcpHandler,
  oauthDefaultHandler,
  sentryConfig,
} from "./worker.js";

const oauthProvider = new OAuthProvider<Env>({
  apiRoute: "/internal",
  apiHandler: googleMcpHandler,
  defaultHandler: oauthDefaultHandler,
  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/oauth/token",
  clientIdMetadataDocumentEnabled: true,
  scopesSupported: ["plausible:read"],
  resourceMetadata: {
    resource: "https://plausible-mcp.victor-a1c.workers.dev/internal",
    authorization_servers: ["https://plausible-mcp.victor-a1c.workers.dev"],
    scopes_supported: ["plausible:read"],
    bearer_methods_supported: ["header"],
    resource_name: "InAppStory Plausible Analytics",
  },
  allowPlainPKCE: false,
  allowImplicitFlow: false,
  accessTokenTTL: 60 * 60,
  refreshTokenTTL: 30 * 24 * 60 * 60,
});

const oauthHandler = {
  fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return oauthProvider.fetch(request, env, ctx);
  },
} satisfies ExportedHandler<Env>;

export default Sentry.withSentry(sentryConfig, oauthHandler);
