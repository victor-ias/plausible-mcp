import type {
  AuthRequest,
  OAuthHelpers,
} from "@cloudflare/workers-oauth-provider";
import type { Env } from "./env.js";

const GOOGLE_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo";
const STATE_PREFIX = "google-oauth-state:";
const STATE_TTL_SECONDS = 10 * 60;
const CSRF_COOKIE = "__Host-PLAUSIBLE_MCP_CSRF";
const STATE_COOKIE = "__Host-PLAUSIBLE_MCP_STATE";

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

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function readCookie(request: Request, name: string): string | undefined {
  const cookie = request.headers.get("Cookie") ?? "";
  for (const part of cookie.split(";")) {
    const trimmed = part.trim();
    if (trimmed.startsWith(`${name}=`)) {
      return trimmed.slice(name.length + 1);
    }
  }
  return undefined;
}

function setCookie(name: string, value: string, maxAge = STATE_TTL_SECONDS): string {
  return `${name}=${value}; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=${maxAge}`;
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

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
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

async function renderConsent(
  request: Request,
  helpers: OAuthHelpers,
  oauthRequest: AuthRequest,
): Promise<Response> {
  const client = oauthRequest.clientId
    ? await helpers.lookupClient(oauthRequest.clientId)
    : null;
  const clientName = escapeHtml(client?.clientName ?? "ChatGPT");
  const csrf = crypto.randomUUID();
  const action = escapeHtml(`${new URL(request.url).pathname}${new URL(request.url).search}`);
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize Plausible Analytics</title><style>
body{font-family:system-ui,sans-serif;background:#f6f7f9;color:#17212b;margin:0;padding:32px}.card{background:white;max-width:520px;margin:8vh auto;padding:32px;border-radius:14px;box-shadow:0 8px 30px #0002}h1{font-size:24px;margin-top:0}p{line-height:1.5}.muted{color:#5d6875}.actions{display:flex;justify-content:flex-end;margin-top:28px}button{background:#1769e0;color:white;border:0;border-radius:8px;padding:11px 18px;font-size:16px;cursor:pointer}
</style></head><body><main class="card"><h1>Connect Plausible Analytics</h1>
<p><strong>${clientName}</strong> is requesting read-only access to aggregated analytics for inappstory.com.</p>
<p class="muted">Continue with your verified @inappstory.com Google account. No Plausible API key is sent to the client.</p>
<form method="post" action="${action}"><input type="hidden" name="csrf_token" value="${csrf}"><div class="actions"><button type="submit">Continue with Google</button></div></form>
</main></body></html>`;
  const headers = new Headers(securityHeaders());
  headers.set("Content-Type", "text/html; charset=utf-8");
  headers.set("Set-Cookie", setCookie(CSRF_COOKIE, csrf));
  return new Response(html, { status: 200, headers });
}

async function beginGoogleLogin(
  request: Request,
  env: Env,
  oauthRequest: AuthRequest,
): Promise<Response> {
  const callbackUrl = googleCallbackUrl(env);
  if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET || !callbackUrl) {
    return textResponse("Google OAuth is not configured.", 500);
  }
  const form = await request.formData();
  const submittedCsrf = form.get("csrf_token");
  const cookieCsrf = readCookie(request, CSRF_COOKIE);
  if (typeof submittedCsrf !== "string" || !cookieCsrf || submittedCsrf !== cookieCsrf) {
    return textResponse("Invalid or expired authorization session.");
  }

  const state = crypto.randomUUID();
  await env.OAUTH_KV.put(`${STATE_PREFIX}${state}`, JSON.stringify(oauthRequest), {
    expirationTtl: STATE_TTL_SECONDS,
  });
  const stateHash = await sha256Hex(state);
  const google = new URL(GOOGLE_AUTHORIZE_URL);
  google.searchParams.set("client_id", env.GOOGLE_CLIENT_ID);
  google.searchParams.set("redirect_uri", callbackUrl);
  google.searchParams.set("response_type", "code");
  google.searchParams.set("scope", "openid email profile");
  google.searchParams.set("state", state);
  google.searchParams.set("hd", parseAllowedEmailDomains(env.ALLOWED_EMAIL_DOMAIN)[0] ?? "");
  google.searchParams.set("prompt", "select_account");

  const headers = new Headers({ Location: google.href });
  headers.append("Set-Cookie", setCookie(STATE_COOKIE, stateHash));
  headers.append("Set-Cookie", setCookie(CSRF_COOKIE, "", 0));
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

  const expectedHash = readCookie(request, STATE_COOKIE);
  if (!expectedHash || await sha256Hex(state) !== expectedHash) {
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
  const headers = new Headers({ Location: redirectTo });
  headers.set("Set-Cookie", setCookie(STATE_COOKIE, "", 0));
  return new Response(null, { status: 302, headers });
}

export async function handleGoogleOAuth(
  request: Request,
  env: Env,
): Promise<Response | undefined> {
  const url = new URL(request.url);
  if (url.pathname === "/authorize" && request.method === "GET") {
    const parsed = await parseAuthorizationRequest(request, env.OAUTH_PROVIDER);
    if (parsed instanceof Response) return parsed;
    return renderConsent(request, env.OAUTH_PROVIDER!, parsed);
  }
  if (url.pathname === "/authorize" && request.method === "POST") {
    const parsed = await parseAuthorizationRequest(request, env.OAUTH_PROVIDER);
    if (parsed instanceof Response) return parsed;
    return beginGoogleLogin(request, env, parsed);
  }
  if (url.pathname === "/oauth/google/callback" && request.method === "GET") {
    return finishGoogleLogin(request, env);
  }
  return undefined;
}
