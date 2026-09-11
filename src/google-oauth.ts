import type {
  AuthRequest,
  OAuthHelpers,
} from "@cloudflare/workers-oauth-provider";
import type { Env } from "./env.js";

const GOOGLE_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo";
const STATE_PREFIX = "google-oauth-state:";
const STATE_TTL_SECONDS = 20 * 60;

interface GoogleIdentity {
  sub?: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
}

export interface GoogleAuthProps {
  email: string;
  name: string;
}

function securityHeaders(): HeadersInit {
  return {
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
  };
}

function textResponse(message: string, status = 400): Response {
  return new Response(message, { status, headers: securityHeaders() });
}

function isRandomUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function googleCallbackUrl(env: Env): string | undefined {
  if (!env.MCP_PUBLIC_URL) return undefined;
  try {
    const origin = new URL(env.MCP_PUBLIC_URL);
    if (origin.protocol !== "https:") return undefined;
    return new URL("/oauth/google/callback", origin).href;
  } catch {
    return undefined;
  }
}

export function parseAllowedEmailDomains(value: string | undefined): string[] {
  return value
    ?.split(",")
    .map((domain) => domain.trim().toLowerCase().replace(/^@/, ""))
    .filter(Boolean) ?? [];
}

export function isAllowedGoogleIdentity(
  identity: GoogleIdentity,
  allowedDomains: string[],
): identity is Required<Pick<GoogleIdentity, "sub" | "email">> & GoogleIdentity {
  if (!identity.sub || !identity.email || identity.email_verified !== true) return false;
  if (allowedDomains.length === 0) return false;
  const at = identity.email.lastIndexOf("@");
  if (at <= 0) return false;
  return allowedDomains.includes(identity.email.slice(at + 1).toLowerCase());
}

export function isAllowedEmail(email: string, allowedDomains: string[]): boolean {
  const at = email.lastIndexOf("@");
  return at > 0 && allowedDomains.includes(email.slice(at + 1).toLowerCase());
}

export function isAllowedChatGptOAuthRequest(request: AuthRequest): boolean {
  if (!request.clientId || !request.redirectUri) return false;
  try {
    const client = new URL(request.clientId);
    const redirect = new URL(request.redirectUri);
    const allowedClientPath = client.pathname === "/oauth/client.json" ||
      /^\/oauth\/[^/]+\/client\.json$/.test(client.pathname);
    const allowedRedirectPath = redirect.pathname === "/connector_platform_oauth_redirect" ||
      /^\/connector\/oauth\/[^/]+$/.test(redirect.pathname);
    return client.origin === "https://chatgpt.com" && allowedClientPath &&
      redirect.origin === "https://chatgpt.com" && allowedRedirectPath;
  } catch {
    return false;
  }
}

async function parseAuthorizationRequest(
  request: Request,
  helpers: OAuthHelpers | undefined,
): Promise<AuthRequest | Response> {
  if (!helpers) return textResponse("OAuth server is not configured.", 500);
  try {
    const parsed = await helpers.parseAuthRequest(request);
    if (!isAllowedChatGptOAuthRequest(parsed)) {
      return textResponse("This OAuth client is not allowed.", 403);
    }
    return parsed;
  } catch {
    return textResponse("Invalid OAuth authorization request.");
  }
}

async function beginGoogleLogin(
  env: Env,
  oauthRequest: AuthRequest,
): Promise<Response> {
  const callbackUrl = googleCallbackUrl(env);
  if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET || !callbackUrl) {
    return textResponse("Google OAuth is not configured.", 500);
  }
  const state = crypto.randomUUID();
  await env.OAUTH_KV.put(`${STATE_PREFIX}${state}`, JSON.stringify(oauthRequest), {
    expirationTtl: STATE_TTL_SECONDS,
  });
  const google = new URL(GOOGLE_AUTHORIZE_URL);
  google.searchParams.set("client_id", env.GOOGLE_CLIENT_ID);
  google.searchParams.set("redirect_uri", callbackUrl);
  google.searchParams.set("response_type", "code");
  google.searchParams.set("scope", "openid email profile");
  google.searchParams.set("state", state);
  google.searchParams.set("hd", parseAllowedEmailDomains(env.ALLOWED_EMAIL_DOMAIN)[0] ?? "");
  google.searchParams.set("prompt", "select_account");

  const headers = new Headers({ Location: google.href });
  return new Response(null, { status: 302, headers });
}

async function exchangeGoogleCode(
  code: string,
  redirectUri: string,
  env: Env,
): Promise<string | undefined> {
  if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET) return undefined;
  const response = await fetch(GOOGLE_TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      code,
      grant_type: "authorization_code",
      redirect_uri: redirectUri,
    }),
  });
  if (!response.ok) return undefined;
  const body = await response.json() as { access_token?: string };
  return body.access_token;
}

async function finishGoogleLogin(request: Request, env: Env): Promise<Response> {
  const helpers = env.OAUTH_PROVIDER;
  const callbackUrl = googleCallbackUrl(env);
  if (!helpers || !env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET || !callbackUrl) {
    return textResponse("OAuth server is not configured.", 500);
  }
  const url = new URL(request.url);
  if (url.searchParams.has("error")) return textResponse("Google sign-in was cancelled.");
  const state = url.searchParams.get("state");
  const code = url.searchParams.get("code");
  if (!state || !code) return textResponse("Missing Google authorization response.");
  if (!isRandomUuid(state)) {
    return textResponse("Invalid or expired authorization session.");
  }
  const stateKey = `${STATE_PREFIX}${state}`;
  const stored = await env.OAUTH_KV.get(stateKey);
  if (!stored) return textResponse("Invalid or expired authorization state.");
  await env.OAUTH_KV.delete(stateKey);

  let oauthRequest: AuthRequest;
  try {
    oauthRequest = JSON.parse(stored) as AuthRequest;
  } catch {
    return textResponse("Invalid authorization state.", 500);
  }

  const googleToken = await exchangeGoogleCode(code, callbackUrl, env);
  if (!googleToken) return textResponse("Google token exchange failed.", 502);
  const userResponse = await fetch(GOOGLE_USERINFO_URL, {
    headers: { Authorization: `Bearer ${googleToken}` },
  });
  if (!userResponse.ok) return textResponse("Google identity lookup failed.", 502);
  const identity = await userResponse.json() as GoogleIdentity;
  const allowedDomains = parseAllowedEmailDomains(env.ALLOWED_EMAIL_DOMAIN);
  if (!isAllowedGoogleIdentity(identity, allowedDomains)) {
    return textResponse("Access is limited to a verified account in the allowed email domain.", 403);
  }

  const grantedScopes = oauthRequest.scope.filter((scope) => scope === "plausible:read");
  if (!grantedScopes.includes("plausible:read")) {
    return textResponse("The required Plausible read scope was not requested.", 403);
  }
  const { redirectTo } = await helpers.completeAuthorization({
    request: oauthRequest,
    userId: identity.sub,
    metadata: { label: identity.email },
    scope: grantedScopes,
    props: {
      email: identity.email.toLowerCase(),
      name: identity.name ?? identity.email,
    } satisfies GoogleAuthProps,
  });
  return new Response(null, { status: 302, headers: { Location: redirectTo } });
}

export async function handleGoogleOAuth(
  request: Request,
  env: Env,
): Promise<Response | undefined> {
  const url = new URL(request.url);
  if (url.pathname === "/authorize" && request.method === "GET") {
    const parsed = await parseAuthorizationRequest(request, env.OAUTH_PROVIDER);
    if (parsed instanceof Response) return parsed;
    return beginGoogleLogin(env, parsed);
  }
  if (url.pathname === "/oauth/google/callback" && request.method === "GET") {
    return finishGoogleLogin(request, env);
  }
  return undefined;
}
