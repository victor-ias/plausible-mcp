import { afterEach, describe, expect, it, vi } from "vitest";
import type { AuthRequest, OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import {
  handleGoogleOAuth,
  isAllowedChatGptOAuthRequest,
  isAllowedGoogleIdentity,
  parseAllowedEmailDomains,
} from "../src/google-oauth.js";
import type { Env } from "../src/env.js";

class MemoryKv {
  values = new Map<string, string>();

  async get(key: string) {
    return this.values.get(key) ?? null;
  }

  async put(key: string, value: string) {
    this.values.set(key, value);
  }

  async delete(key: string) {
    this.values.delete(key);
  }
}

function authRequest(): AuthRequest {
  return {
    clientId: "https://chatgpt.com/oauth/client.json",
    redirectUri: "https://chatgpt.com/connector_platform_oauth_redirect",
    responseType: "code",
    scope: ["plausible:read"],
    state: "chatgpt-state",
    codeChallenge: "challenge",
    codeChallengeMethod: "S256",
    resource: "https://plausible-mcp.victor-a1c.workers.dev/internal",
  } as AuthRequest;
}

function makeEnv() {
  const kv = new MemoryKv();
  const helpers = {
    parseAuthRequest: vi.fn(async () => authRequest()),
    lookupClient: vi.fn(async () => ({ clientName: "ChatGPT" })),
    completeAuthorization: vi.fn(async () => ({
      redirectTo: "https://chatgpt.com/connector_platform_oauth_redirect?code=local-code",
    })),
  } as unknown as OAuthHelpers;
  const env = {
    ALLOWED_EMAIL_DOMAIN: "inappstory.com",
    GOOGLE_CLIENT_ID: "google-client-id",
    GOOGLE_CLIENT_SECRET: "google-client-secret",
    MCP_ALLOWED_HOSTNAMES: "test.local",
    MCP_PUBLIC_URL: "https://test.local",
    OAUTH_KV: kv as unknown as KVNamespace,
    OAUTH_PROVIDER: helpers,
  } satisfies Env;
  return { env, helpers, kv };
}

async function beginFlow(env: Env) {
  const authorizeUrl = "https://test.local/authorize?client_id=chatgpt";
  const consent = await handleGoogleOAuth(new Request(authorizeUrl), env);
  const csrf = (await consent!.text()).match(/name="csrf_token" value="([^"]+)"/)?.[1];
  const csrfCookie = consent!.headers.get("Set-Cookie")?.split(";")[0];
  const begin = await handleGoogleOAuth(new Request(authorizeUrl, {
    method: "POST",
    headers: {
      Cookie: csrfCookie ?? "",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({ csrf_token: csrf ?? "" }),
  }), env);
  const googleUrl = new URL(begin!.headers.get("Location")!);
  const stateCookie = begin!.headers.get("Set-Cookie")!
    .match(/__Host-PLAUSIBLE_MCP_STATE_[^=]+=[^;]+/)?.[0];
  return { begin: begin!, googleUrl, stateCookie };
}

afterEach(() => vi.restoreAllMocks());

describe("Google OAuth", () => {
  it("normalizes domains and rejects unverified or foreign identities", () => {
    expect(parseAllowedEmailDomains(" @InAppStory.com, partners.example "))
      .toEqual(["inappstory.com", "partners.example"]);
    expect(isAllowedGoogleIdentity(
      { sub: "1", email: "user@inappstory.com", email_verified: true },
      ["inappstory.com"],
    )).toBe(true);
    expect(isAllowedGoogleIdentity(
      { sub: "1", email: "user@evil.example", email_verified: true },
      ["inappstory.com"],
    )).toBe(false);
    expect(isAllowedGoogleIdentity(
      { sub: "1", email: "user@inappstory.com", email_verified: false },
      ["inappstory.com"],
    )).toBe(false);
  });

  it("allows only ChatGPT client metadata and callbacks", () => {
    expect(isAllowedChatGptOAuthRequest(authRequest())).toBe(true);
    expect(isAllowedChatGptOAuthRequest({
      ...authRequest(),
      clientId: "https://attacker.example/client.json",
    })).toBe(false);
    expect(isAllowedChatGptOAuthRequest({
      ...authRequest(),
      redirectUri: "https://attacker.example/callback",
    })).toBe(false);
  });

  it("uses consent + CSRF before redirecting to Google", async () => {
    const { env, kv } = makeEnv();
    const { begin, googleUrl } = await beginFlow(env);

    expect(begin.status).toBe(302);
    expect(googleUrl.origin).toBe("https://accounts.google.com");
    expect(googleUrl.searchParams.get("hd")).toBe("inappstory.com");
    expect(googleUrl.searchParams.get("redirect_uri"))
      .toBe("https://test.local/oauth/google/callback");
    expect(kv.values.has(`google-oauth-state:${googleUrl.searchParams.get("state")}`))
      .toBe(true);
  });

  it("finishes authorization only for a verified allowed Google account", async () => {
    const { env, helpers } = makeEnv();
    const { googleUrl, stateCookie } = await beginFlow(env);
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.hostname === "oauth2.googleapis.com") {
        return Response.json({ access_token: "google-access-token" });
      }
      if (url.hostname === "openidconnect.googleapis.com") {
        return Response.json({
          sub: "google-user-1",
          email: "Analyst@InAppStory.com",
          email_verified: true,
          name: "Analyst",
        });
      }
      throw new Error(`Unexpected request: ${url}`);
    });

    const callback = new URL("https://test.local/oauth/google/callback");
    callback.searchParams.set("code", "google-code");
    callback.searchParams.set("state", googleUrl.searchParams.get("state")!);
    const response = await handleGoogleOAuth(new Request(callback, {
      headers: { Cookie: stateCookie ?? "" },
    }), env);

    expect(response!.status).toBe(302);
    expect(response!.headers.get("Location")).toContain("chatgpt.com");
    expect(helpers.completeAuthorization).toHaveBeenCalledWith(expect.objectContaining({
      userId: "google-user-1",
      scope: ["plausible:read"],
      props: { email: "analyst@inappstory.com", name: "Analyst" },
    }));
  });

  it("keeps parallel Google authorization sessions independent", async () => {
    const { env } = makeEnv();
    const first = await beginFlow(env);
    const second = await beginFlow(env);

    expect(first.googleUrl.searchParams.get("state"))
      .not.toBe(second.googleUrl.searchParams.get("state"));
    expect(first.stateCookie?.split("=")[0])
      .not.toBe(second.stateCookie?.split("=")[0]);
  });
});
