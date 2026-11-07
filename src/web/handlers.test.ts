import { beforeEach, describe, expect, it, vi } from "vitest";
import { createAiClient } from "../ai.js";
import { createAuthClient } from "../client.js";
import { GrantManager, MemoryGrantStore } from "../grants.js";
import {
  CLIENT_ID,
  CLIENT_SECRET,
  GATEWAY_URL,
  ISSUER,
  createMockIdp,
  createTestAuth,
  jsonResponse,
  nowSeconds,
} from "../test-support/mock-idp.js";
import type { MockIdp } from "../test-support/mock-idp.js";
import { createAuthHandlers } from "./handlers.js";
import type { AuthHandlers, AuthHandlersOptions } from "./handlers.js";
import { MemorySessionStore } from "./sessions.js";
import type { Session } from "./sessions.js";

const ORIGIN = "https://app.test";
const SECRET = "0123456789abcdef0123456789abcdef";
const EVENT = "http://schemas.openid.net/event/backchannel-logout";
const SESSION_COOKIE = "__Host-aai_session";
const LOGIN_COOKIE = "__Host-aai_login";
const LOGOUT_COOKIE = "__Host-aai_logout";

let idp: MockIdp;
let sessions: MemorySessionStore;
let grants: GrantManager;
let handlers: AuthHandlers;
let onError: ReturnType<typeof vi.fn<(error: unknown) => void>>;
let onSessionsEnded: ReturnType<
  typeof vi.fn<(ended: readonly Session[]) => void>
>;
let refreshes: number;
let currentRoles: string[];

async function build(
  overrides: Partial<AuthHandlersOptions> = {},
  postLogoutRedirectUri = `${ORIGIN}/`,
): Promise<void> {
  const auth = createTestAuth(idp, {
    redirectUri: `${ORIGIN}/auth/callback`,
    postLogoutRedirectUri,
  });
  grants = new GrantManager({ auth, store: new MemoryGrantStore() });
  handlers = await createAuthHandlers({
    auth,
    grants,
    sessions,
    secret: SECRET,
    onError,
    onSessionsEnded,
    ...overrides,
  });
}

beforeEach(async () => {
  idp = await createMockIdp();
  sessions = new MemorySessionStore();
  onError = vi.fn();
  onSessionsEnded = vi.fn();
  refreshes = 0;
  currentRoles = ["editor"];
  idp.tokenHandler = async (request) => {
    const nonce = (idp as { nonce?: string }).nonce;
    const base = {
      token_type: "Bearer",
      expires_in: 3600,
      scope: "openid roles",
    };
    if (request.form.get("grant_type") === "refresh_token") {
      refreshes += 1;
      return jsonResponse({
        ...base,
        access_token: `access-r${refreshes}`,
        refresh_token: `refresh-${refreshes}`,
        id_token: await idp.idToken({
          sid: "sid-1",
          roles: currentRoles,
          features: { maxProjects: 10 },
        }),
      });
    }
    return jsonResponse({
      ...base,
      access_token: "access-0",
      refresh_token: "refresh-0",
      id_token: await idp.idToken({
        nonce,
        sid: "sid-1",
        name: "Ada",
        email: "ada@example.com",
        email_verified: true,
        roles: currentRoles,
        permissions: ["docs.write"],
        features: { maxProjects: 10 },
        plan: "Premium",
        org_id: "org-1",
      }),
    });
  };
  await build();
});

const get = (path: string, headers: Record<string, string> = {}) =>
  new Request(`${ORIGIN}${path}`, { headers });

function cookiesOf(response: Response): Map<string, string> {
  const cookies = new Map<string, string>();
  for (const line of response.headers.getSetCookie()) {
    const [pair = ""] = line.split(";");
    const separator = pair.indexOf("=");
    cookies.set(pair.slice(0, separator), pair.slice(separator + 1));
  }
  return cookies;
}

const cookieHeader = (...pairs: [string, string][]) =>
  pairs.map(([name, value]) => `${name}=${value}`).join("; ");

async function mustHandle(request: Request): Promise<Response> {
  const response = await handlers.handle(request);
  if (!response) throw new Error("the request was not handled");
  return response;
}

/** Runs login then callback and returns the session cookie value. */
async function signIn(next = "/dashboard"): Promise<string> {
  const login = await mustHandle(
    get(`/auth/login?next=${encodeURIComponent(next)}`),
  );
  const authorize = new URL(login.headers.get("location") ?? "");
  (idp as { nonce?: string }).nonce = authorize.searchParams.get("nonce") ?? "";
  const callback = await mustHandle(
    get(
      `/auth/callback?code=abc&state=${authorize.searchParams.get("state")}&iss=${encodeURIComponent(ISSUER)}`,
      {
        cookie: cookieHeader([
          LOGIN_COOKIE,
          cookiesOf(login).get(LOGIN_COOKIE) ?? "",
        ]),
      },
    ),
  );
  expect(callback.status).toBe(303);
  const cookie = cookiesOf(callback).get(SESSION_COOKIE);
  if (!cookie) throw new Error("no session cookie");
  return cookie;
}

const withSession = (
  cookie: string,
  init: RequestInit = {},
  path = "/auth/me",
) =>
  new Request(`${ORIGIN}${path}`, {
    ...init,
    headers: {
      ...(init.headers as Record<string, string> | undefined),
      cookie: cookieHeader([SESSION_COOKIE, cookie]),
    },
  });

function logoutToken(overrides: Record<string, unknown> = {}): Promise<string> {
  const iat = nowSeconds();
  return idp.signJwt(
    {
      iss: ISSUER,
      aud: CLIENT_ID,
      sub: "user-1",
      sid: "sid-1",
      iat,
      exp: iat + 120,
      jti: crypto.randomUUID(),
      events: { [EVENT]: {} },
      ...overrides,
    },
    { typ: "logout+jwt" },
  );
}

const postLogoutToken = (token: string) =>
  new Request(`${ORIGIN}/auth/backchannel-logout`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ logout_token: token }),
  });

describe("login", () => {
  it("redirects to the provider with a sealed, hardened handshake cookie", async () => {
    const response = await mustHandle(
      get("/auth/login?next=/a%3Fb%3D1&prompt=login"),
    );

    expect(response.status).toBe(302);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const location = new URL(response.headers.get("location") ?? "");
    expect(location.origin + location.pathname).toBe(`${ISSUER}/authorize`);
    expect(location.searchParams.get("prompt")).toBe("login");

    const [setCookie] = response.headers.getSetCookie();
    expect(setCookie).toContain(`${LOGIN_COOKIE}=`);
    expect(setCookie).toContain("HttpOnly");
    expect(setCookie).toContain("Secure");
    expect(setCookie).toContain("SameSite=Lax");
    expect(setCookie).toContain("Max-Age=600");
    // The PKCE verifier must not be readable from the cookie.
    const state = location.searchParams.get("state") ?? "";
    expect(setCookie).not.toContain(state);
  });

  it("ignores an unknown prompt", async () => {
    const response = await mustHandle(get("/auth/login?prompt=bogus"));
    expect(
      new URL(response.headers.get("location") ?? "").searchParams.has(
        "prompt",
      ),
    ).toBe(false);
  });
});

describe("callback", () => {
  it("creates a session, stores the grant and lands on the requested page", async () => {
    const login = await mustHandle(
      get("/auth/login?next=/dashboard%3Ftab%3D2"),
    );
    const authorize = new URL(login.headers.get("location") ?? "");
    (idp as { nonce?: string }).nonce =
      authorize.searchParams.get("nonce") ?? "";

    const callback = await mustHandle(
      get(
        `/auth/callback?code=abc&state=${authorize.searchParams.get("state")}&iss=${encodeURIComponent(ISSUER)}`,
        {
          cookie: cookieHeader([
            LOGIN_COOKIE,
            cookiesOf(login).get(LOGIN_COOKIE) ?? "",
          ]),
        },
      ),
    );

    expect(callback.status).toBe(303);
    expect(callback.headers.get("location")).toBe("/dashboard?tab=2");
    const setCookies = callback.headers.getSetCookie();
    expect(
      setCookies.some(
        (c) => c.startsWith(`${LOGIN_COOKIE}=;`) && c.includes("Max-Age=0"),
      ),
    ).toBe(true);
    const session =
      setCookies.find((c) => c.startsWith(`${SESSION_COOKIE}=`)) ?? "";
    expect(session).toContain("HttpOnly");
    expect(session).toContain("Secure");
    expect(session).toContain("Max-Age=28800");

    expect(await grants.has("user-1")).toBe(true);
    expect(await sessions.countByUser("user-1")).toBe(1);
    // The token endpoint was reached on the registered URI, not a request header.
    expect(idp.requestsTo("/token")[0]?.form.get("redirect_uri")).toBe(
      `${ORIGIN}/auth/callback`,
    );
  });

  it("stores only a hash of the session cookie", async () => {
    const cookie = await signIn();
    const [stored] = await sessions.deleteByProviderSession("sid-1");
    expect(stored?.id).not.toBe(cookie);
    expect(stored?.id).toHaveLength(43);
  });

  it("refuses a callback without the handshake cookie", async () => {
    const response = await mustHandle(get("/auth/callback?code=abc&state=x"));
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({
      error: { code: "SES_005", message: "Sign-in failed" },
    });
    expect(onError).toHaveBeenCalledWith(
      expect.objectContaining({ code: "SES_002" }),
    );
    expect(idp.requestsTo("/token")).toHaveLength(0);
  });

  it("refuses a tampered handshake cookie", async () => {
    const login = await mustHandle(get("/auth/login"));
    const sealed = cookiesOf(login).get(LOGIN_COOKIE) ?? "";
    const response = await mustHandle(
      get("/auth/callback?code=abc&state=x", {
        cookie: cookieHeader([LOGIN_COOKIE, `${sealed.slice(0, -3)}AAA`]),
      }),
    );
    expect(response.status).toBe(403);
  });

  it("refuses a callback whose state is not the one of this browser", async () => {
    const login = await mustHandle(get("/auth/login"));
    const response = await mustHandle(
      get(
        `/auth/callback?code=abc&state=forged&iss=${encodeURIComponent(ISSUER)}`,
        {
          cookie: cookieHeader([
            LOGIN_COOKIE,
            cookiesOf(login).get(LOGIN_COOKIE) ?? "",
          ]),
        },
      ),
    );
    expect(response.status).toBe(403);
    expect(idp.requestsTo("/token")).toHaveLength(0);
    expect(onError).toHaveBeenCalled();
    expect(await sessions.countByUser("user-1")).toBe(0);
  });

  it("refuses an ID token without sid by default", async () => {
    const login = await mustHandle(get("/auth/login"));
    const authorize = new URL(login.headers.get("location") ?? "");
    const idToken = await idp.idToken({
      nonce: authorize.searchParams.get("nonce") ?? "",
    });
    idp.tokenHandler = () =>
      jsonResponse({
        access_token: "a",
        token_type: "Bearer",
        expires_in: 60,
        refresh_token: "r",
        id_token: idToken,
      });
    const response = await mustHandle(
      get(
        `/auth/callback?code=abc&state=${authorize.searchParams.get("state")}&iss=${encodeURIComponent(ISSUER)}`,
        {
          cookie: cookieHeader([
            LOGIN_COOKIE,
            cookiesOf(login).get(LOGIN_COOKIE) ?? "",
          ]),
        },
      ),
    );
    expect(response.status).toBe(403);
    expect(
      ((await response.json()) as { error: { code: string } }).error.code,
    ).toBe("SES_005");
    // The misconfiguration is for the application's logs, not for the browser.
    expect(onError).toHaveBeenCalledWith(
      expect.objectContaining({ code: "SES_003" }),
    );
    expect(await grants.has("user-1")).toBe(false);
  });

  it("answers the same 403 whatever failed, so a probe learns nothing", async () => {
    const login = await mustHandle(get("/auth/login"));
    const authorize = new URL(login.headers.get("location") ?? "");
    const cookie = cookieHeader([
      LOGIN_COOKIE,
      cookiesOf(login).get(LOGIN_COOKIE) ?? "",
    ]);
    const callback = `/auth/callback?code=abc&state=${authorize.searchParams.get("state")}&iss=${encodeURIComponent(ISSUER)}`;
    const answers: string[] = [];
    for (const rejected of [
      { error: "invalid_client" },
      { error: "invalid_grant", error_description: "code expired" },
      { error: "server_error" },
    ]) {
      idp.tokenHandler = () => jsonResponse(rejected, 401);
      const response = await mustHandle(get(callback, { cookie }));
      answers.push(`${response.status} ${await response.text()}`);
    }
    answers.push(
      `${(await mustHandle(get("/auth/callback?error=access_denied"))).status}`,
    );
    expect(answers.slice(0, 3)).toEqual(
      Array(3).fill(
        `403 ${JSON.stringify({ error: { code: "SES_005", message: "Sign-in failed" } })}`,
      ),
    );
    expect(answers[3]).toBe("403");
    expect(onError).toHaveBeenCalledTimes(4);
  });

  it("redirects to the error page when one is configured", async () => {
    await build({ errorRedirect: "/signin-error" });
    const response = await mustHandle(
      get("/auth/callback?error=access_denied"),
    );
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe(
      "/signin-error?error=SES_005",
    );
  });

  it("limits a session to the ID token without a refresh token", async () => {
    const login = await mustHandle(get("/auth/login"));
    const authorize = new URL(login.headers.get("location") ?? "");
    const idToken = await idp.idToken({
      nonce: authorize.searchParams.get("nonce") ?? "",
      sid: "s",
    });
    idp.tokenHandler = () =>
      jsonResponse({
        access_token: "a",
        token_type: "Bearer",
        expires_in: 60,
        id_token: idToken,
      });
    const callback = await mustHandle(
      get(
        `/auth/callback?code=abc&state=${authorize.searchParams.get("state")}&iss=${encodeURIComponent(ISSUER)}`,
        {
          cookie: cookieHeader([
            LOGIN_COOKIE,
            cookiesOf(login).get(LOGIN_COOKIE) ?? "",
          ]),
        },
      ),
    );
    expect(callback.status).toBe(303);
    expect(await grants.has("user-1")).toBe(false);
    expect(callback.headers.getSetCookie().join(";")).toContain(
      "Max-Age=28800",
    );
    const [stored] = await sessions.deleteByProviderSession("s");
    expect(stored?.expiresAt).toBe(stored?.claims.exp);
    expect(stored?.renewAt).toBe(stored?.expiresAt);
  });
});

describe("userinfo", () => {
  it("fills email from UserInfo when the ID token omits it", async () => {
    idp.tokenHandler = async () => {
      const nonce = (idp as { nonce?: string }).nonce;
      return jsonResponse({
        token_type: "Bearer",
        expires_in: 3600,
        access_token: "access-0",
        refresh_token: "refresh-0",
        id_token: await idp.idToken({ nonce, sid: "sid-1", name: "Ada" }),
      });
    };
    idp.userinfoHandler = () =>
      jsonResponse({
        sub: "user-1",
        email: "ada@example.com",
        email_verified: true,
      });

    const cookie = await signIn();
    const response = await mustHandle(
      new Request(`${ORIGIN}/auth/me`, {
        headers: { cookie: cookieHeader([SESSION_COOKIE, cookie]) },
      }),
    );
    const body = (await response.json()) as {
      user: { email?: string; emailVerified?: boolean };
    };

    expect(body.user.email).toBe("ada@example.com");
    expect(body.user.emailVerified).toBe(true);
    const [request] = idp.requestsTo("/userinfo");
    expect(request?.headers.get("authorization")).toBe("Bearer access-0");
  });

  it("fills claims the refreshed ID token omits from UserInfo on renewal", async () => {
    await build({ claimsRenewSeconds: 0 });
    idp.userinfoHandler = () =>
      jsonResponse({
        sub: "user-1",
        email: "renewed@example.com",
        email_verified: true,
      });

    const cookie = await signIn();
    const response = await mustHandle(withSession(cookie));
    const body = (await response.json()) as {
      user: { email?: string; emailVerified?: boolean };
    };

    expect(refreshes).toBe(1);
    expect(body.user.email).toBe("renewed@example.com");
    expect(body.user.emailVerified).toBe(true);
    expect(
      idp.requestsTo("/userinfo").at(-1)?.headers.get("authorization"),
    ).toBe("Bearer access-r1");
  });

  it("keeps the session and answers 502 when UserInfo is unreachable on renewal", async () => {
    await build({ claimsRenewSeconds: 0 });
    const cookie = await signIn();
    idp.userinfoHandler = () => {
      throw new TypeError("fetch failed");
    };

    expect((await mustHandle(withSession(cookie))).status).toBe(502);
    expect(await sessions.countByUser("user-1")).toBe(1);
    expect(onError).toHaveBeenCalledWith(
      expect.objectContaining({ code: "OIDC_003" }),
    );
  });

  it("does not replace claims already present in the ID token", async () => {
    idp.userinfoHandler = () =>
      jsonResponse({ sub: "user-1", name: "From UserInfo" });

    const cookie = await signIn();
    const response = await mustHandle(
      new Request(`${ORIGIN}/auth/me`, {
        headers: { cookie: cookieHeader([SESSION_COOKIE, cookie]) },
      }),
    );
    const body = (await response.json()) as { user: { name?: string } };

    expect(body.user.name).toBe("Ada");
  });

  it("refuses UserInfo for another subject", async () => {
    idp.userinfoHandler = () =>
      jsonResponse({ sub: "someone-else", email: "other@example.com" });

    const login = await mustHandle(get("/auth/login"));
    const authorize = new URL(login.headers.get("location") ?? "");
    (idp as { nonce?: string }).nonce =
      authorize.searchParams.get("nonce") ?? "";
    const response = await mustHandle(
      get(
        `/auth/callback?code=abc&state=${authorize.searchParams.get("state")}&iss=${encodeURIComponent(ISSUER)}`,
        {
          cookie: cookieHeader([
            LOGIN_COOKIE,
            cookiesOf(login).get(LOGIN_COOKIE) ?? "",
          ]),
        },
      ),
    );

    expect(response.status).toBe(403);
    expect(await sessions.countByUser("user-1")).toBe(0);
    expect(onError).toHaveBeenCalled();
  });
});

describe("me", () => {
  it("returns the user without any token or provider session id", async () => {
    const cookie = await signIn();
    const response = await mustHandle(withSession(cookie));
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const body = (await response.json()) as {
      user: Record<string, unknown>;
      expiresAt: number;
    };
    expect(body.user).toEqual({
      sub: "user-1",
      name: "Ada",
      email: "ada@example.com",
      emailVerified: true,
      roles: ["editor"],
      permissions: ["docs.write"],
      features: { maxProjects: 10 },
      plan: "Premium",
      orgId: "org-1",
    });
    expect(JSON.stringify(body)).not.toMatch(/sid|access|refresh|idToken/);
    expect(body.expiresAt).toBeGreaterThan(nowSeconds());
  });

  it("answers 401 without a session, with a forged cookie, and after expiry", async () => {
    expect((await mustHandle(get("/auth/me"))).status).toBe(401);
    expect((await mustHandle(withSession("forged"))).status).toBe(401);

    vi.useFakeTimers({ now: Date.now() });
    try {
      const cookie = await signIn();
      vi.setSystemTime(Date.now() + 29_000 * 1000);
      expect((await mustHandle(withSession(cookie))).status).toBe(401);
    } finally {
      vi.useRealTimers();
    }
  });

  it("renews the claims from the provider when they are due", async () => {
    await build({ claimsRenewSeconds: 0 });
    const cookie = await signIn();
    currentRoles = ["editor", "admin"];

    const response = await mustHandle(withSession(cookie));
    const body = (await response.json()) as { user: { roles: string[] } };

    expect(body.user.roles).toEqual(["editor", "admin"]);
    expect(refreshes).toBe(1);
    expect(idp.requestsTo("/token").at(-1)?.form.get("refresh_token")).toBe(
      "refresh-0",
    );
    expect(idp.requestsTo("/token").at(-1)?.form.has("resource")).toBe(false);
  });

  it("shares one renewal between simultaneous requests", async () => {
    await build({ claimsRenewSeconds: 0 });
    const cookie = await signIn();
    await Promise.all([
      handlers.getSession(withSession(cookie)),
      handlers.getSession(withSession(cookie)),
      handlers.getSession(withSession(cookie)),
    ]);
    expect(refreshes).toBe(1);
  });

  it("ends the session when the provider rejects the grant", async () => {
    await build({ claimsRenewSeconds: 0 });
    const cookie = await signIn();
    idp.tokenHandler = () => jsonResponse({ error: "invalid_grant" }, 400);

    expect((await mustHandle(withSession(cookie))).status).toBe(401);
    expect(await sessions.countByUser("user-1")).toBe(0);
    expect(onSessionsEnded).toHaveBeenCalledOnce();
  });

  it("fails loudly, keeping the session, when the provider is unreachable", async () => {
    await build({ claimsRenewSeconds: 0 });
    const cookie = await signIn();
    idp.tokenHandler = () => jsonResponse({ error: "server_error" }, 500);

    expect((await mustHandle(withSession(cookie))).status).toBe(502);
    expect(await sessions.countByUser("user-1")).toBe(1);
  });

  it("refuses a refreshed ID token of another user", async () => {
    await build({ claimsRenewSeconds: 0 });
    const cookie = await signIn();
    idp.tokenHandler = async () =>
      jsonResponse({
        access_token: "a",
        token_type: "Bearer",
        expires_in: 60,
        id_token: await idp.idToken({ sub: "someone-else", sid: "sid-1" }),
      });
    expect((await mustHandle(withSession(cookie))).status).toBe(401);
    expect(await sessions.countByUser("user-1")).toBe(0);
  });

  it("refuses a refresh that returns no ID token", async () => {
    await build({ claimsRenewSeconds: 0 });
    const cookie = await signIn();
    idp.tokenHandler = () =>
      jsonResponse({ access_token: "a", token_type: "Bearer", expires_in: 60 });
    expect((await mustHandle(withSession(cookie))).status).toBe(401);
  });
});

describe("requireSession", () => {
  it("returns the session or throws SES_001", async () => {
    const cookie = await signIn();
    expect((await handlers.requireSession(withSession(cookie))).userId).toBe(
      "user-1",
    );
    await expect(handlers.requireSession(get("/x"))).rejects.toMatchObject({
      code: "SES_001",
    });
  });
});

describe("logout", () => {
  const post = (cookie: string | null, headers: Record<string, string> = {}) =>
    new Request(`${ORIGIN}/auth/logout`, {
      method: "POST",
      headers: {
        ...(cookie ? { cookie: cookieHeader([SESSION_COOKIE, cookie]) } : {}),
        ...headers,
      },
    });

  it("ends the session, revokes the grant and returns the provider logout URL", async () => {
    const cookie = await signIn();
    const response = await mustHandle(
      post(cookie, { origin: ORIGIN, accept: "application/json" }),
    );

    expect(response.status).toBe(200);
    const { logoutUrl } = (await response.json()) as { logoutUrl: string };
    const url = new URL(logoutUrl);
    expect(url.origin + url.pathname).toBe(`${ISSUER}/end-session`);
    expect(url.searchParams.get("id_token_hint")).toBeTruthy();
    expect(response.headers.getSetCookie()[0]).toContain("Max-Age=0");

    expect(await sessions.countByUser("user-1")).toBe(0);
    expect(await grants.has("user-1")).toBe(false);
    expect(idp.requestsTo("/revoke")[0]?.form.get("token")).toBe("refresh-0");
    expect(onSessionsEnded).toHaveBeenCalledOnce();
  });

  it("redirects a plain form post to the provider", async () => {
    const cookie = await signIn();
    const response = await mustHandle(post(cookie, { origin: ORIGIN }));
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toContain(`${ISSUER}/end-session`);
  });

  it("keeps the grant while the user has another session", async () => {
    const first = await signIn();
    await signIn();
    await mustHandle(post(first, { origin: ORIGIN }));
    expect(await sessions.countByUser("user-1")).toBe(1);
    expect(await grants.has("user-1")).toBe(true);
    expect(idp.requestsTo("/revoke")).toHaveLength(0);
  });

  it("refuses a cross-site request and leaves the session alone", async () => {
    const cookie = await signIn();
    const response = await mustHandle(
      post(cookie, { origin: "https://evil.test" }),
    );
    expect(response.status).toBe(403);
    expect(await sessions.countByUser("user-1")).toBe(1);
  });

  it("still answers the provider logout URL without a session, with no id_token_hint", async () => {
    const response = await mustHandle(
      post(null, { origin: ORIGIN, accept: "application/json" }),
    );
    expect(response.status).toBe(200);
    const { logoutUrl } = (await response.json()) as { logoutUrl: string };
    const url = new URL(logoutUrl);
    expect(url.origin + url.pathname).toBe(`${ISSUER}/end-session`);
    expect(url.searchParams.has("id_token_hint")).toBe(false);
    expect(onSessionsEnded).not.toHaveBeenCalled();
  });

  it("redirects a plain form post without a session to the provider logout", async () => {
    const response = await mustHandle(post(null, { origin: ORIGIN }));
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toContain(`${ISSUER}/end-session`);
  });

  it("falls back to the default redirect without a session when the provider has no end-session", async () => {
    delete idp.metadata["end_session_endpoint"];
    await build();
    const response = await mustHandle(post(null, { origin: ORIGIN }));
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/");
    expect(onError).toHaveBeenCalled();
  });

  it("keeps the requested destination when the provider has no end-session", async () => {
    const cookie = await signIn();
    delete idp.metadata["end_session_endpoint"];
    await build();
    const response = await mustHandle(
      new Request(`${ORIGIN}/auth/logout?next=/settings`, {
        method: "POST",
        headers: {
          cookie: cookieHeader([SESSION_COOKIE, cookie]),
          origin: ORIGIN,
        },
      }),
    );
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/settings");
  });

  it("still ends the local session when the provider has no end-session endpoint", async () => {
    const cookie = await signIn();
    delete idp.metadata["end_session_endpoint"];
    await build();
    await grants.save("user-1", "refresh-0");
    const rebuilt = await mustHandle(
      post(cookie, { origin: ORIGIN, accept: "application/json" }),
    );
    expect(rebuilt.status).toBe(200);
    expect(await rebuilt.json()).toEqual({ logoutUrl: null });
    expect(await sessions.countByUser("user-1")).toBe(0);
    expect(onError).toHaveBeenCalled();
  });

  it("reports an unreachable provider without blocking the sign-out", async () => {
    const cookie = await signIn();
    idp.revocationStatus = 500;
    const response = await mustHandle(
      post(cookie, { origin: ORIGIN, accept: "application/json" }),
    );
    expect(response.status).toBe(200);
    expect(await sessions.countByUser("user-1")).toBe(0);
    expect(await grants.has("user-1")).toBe(false);
    expect(onError).toHaveBeenCalledOnce();
  });
});

describe("logout callback", () => {
  const post = (cookie: string, headers: Record<string, string> = {}) =>
    new Request(`${ORIGIN}/auth/logout`, {
      method: "POST",
      headers: {
        cookie: cookieHeader([SESSION_COOKIE, cookie]),
        ...headers,
      },
    });

  it("sends state and returns through the logout callback", async () => {
    await build({}, `${ORIGIN}/auth/logout/callback`);
    const cookie = await signIn();
    const response = await mustHandle(
      post(cookie, { origin: ORIGIN, accept: "application/json" }),
    );
    const { logoutUrl } = (await response.json()) as { logoutUrl: string };
    const url = new URL(logoutUrl);
    const state = url.searchParams.get("state");
    expect(state).toBeTruthy();
    expect(url.searchParams.get("post_logout_redirect_uri")).toBe(
      `${ORIGIN}/auth/logout/callback`,
    );
    const sealed = cookiesOf(response).get(LOGOUT_COOKIE);
    expect(sealed).toBeTruthy();

    const callback = await mustHandle(
      new Request(`${ORIGIN}/auth/logout/callback?state=${state}`, {
        headers: { cookie: cookieHeader([LOGOUT_COOKIE, sealed ?? ""]) },
      }),
    );

    expect(callback.status).toBe(303);
    expect(callback.headers.get("location")).toBe("/");
    expect(callback.headers.getSetCookie()[0]).toContain("Max-Age=0");
  });

  it.each(["", "?state=other"])(
    "accepts a missing or different state after logout (%s)",
    async (query) => {
      await build({}, `${ORIGIN}/auth/logout/callback`);
      const cookie = await signIn();
      const response = await mustHandle(
        post(cookie, { origin: ORIGIN, accept: "application/json" }),
      );
      const sealed = cookiesOf(response).get(LOGOUT_COOKIE);

      const callback = await mustHandle(
        new Request(`${ORIGIN}/auth/logout/callback${query}`, {
          headers: { cookie: cookieHeader([LOGOUT_COOKIE, sealed ?? ""]) },
        }),
      );

      expect(callback.status).toBe(303);
      expect(callback.headers.get("location")).toBe("/");
    },
  );

  it("redirects to the default page without a logout cookie", async () => {
    const response = await mustHandle(
      get("/auth/logout/callback?state=missing"),
    );
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/");
  });
});

describe("back-channel logout", () => {
  it("ends the sessions of the provider session and revokes the grant", async () => {
    const cookie = await signIn();
    const response = await mustHandle(postLogoutToken(await logoutToken()));

    expect(response.status).toBe(204);
    expect(await sessions.countByUser("user-1")).toBe(0);
    expect(await grants.has("user-1")).toBe(false);
    expect(onSessionsEnded).toHaveBeenCalledOnce();
    expect((await mustHandle(withSession(cookie))).status).toBe(401);
  });

  it("is idempotent for an unknown provider session", async () => {
    const response = await mustHandle(
      postLogoutToken(await logoutToken({ sid: "unknown" })),
    );
    expect(response.status).toBe(204);
    expect(onSessionsEnded).not.toHaveBeenCalled();
  });

  it("refuses a replayed token", async () => {
    await signIn();
    const token = await logoutToken();
    expect((await mustHandle(postLogoutToken(token))).status).toBe(204);
    expect((await mustHandle(postLogoutToken(token))).status).toBe(400);
  });

  it("refuses a token for another client", async () => {
    await signIn();
    expect(
      (await mustHandle(postLogoutToken(await logoutToken({ aud: "other" }))))
        .status,
    ).toBe(400);
    expect(await sessions.countByUser("user-1")).toBe(1);
  });
});

describe("routing and configuration", () => {
  it("leaves other paths to the application", async () => {
    expect(await handlers.handle(get("/"))).toBeNull();
    expect(await handlers.handle(get("/auth"))).toBeNull();
    expect(await handlers.handle(get("/auth/unknown"))).toBeNull();
    expect(await handlers.handle(get("/authx/login"))).toBeNull();
  });

  it("answers 405 with the allowed method", async () => {
    const response = await mustHandle(new Request(`${ORIGIN}/auth/logout`));
    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe("POST");
    expect(
      (
        await mustHandle(
          new Request(`${ORIGIN}/auth/login`, { method: "POST" }),
        )
      ).status,
    ).toBe(405);
  });

  it("supports another base path when redirectUri follows it", async () => {
    const auth = createTestAuth(idp, {
      redirectUri: `${ORIGIN}/api/sso/callback`,
    });
    const custom = await createAuthHandlers({
      auth,
      grants: new GrantManager({ auth, store: new MemoryGrantStore() }),
      sessions,
      secret: SECRET,
      basePath: "/api/sso",
    });
    expect(custom.basePath).toBe("/api/sso");
    expect((await custom.handle(get("/api/sso/login")))?.status).toBe(302);
    expect(await custom.handle(get("/auth/login"))).toBeNull();
  });

  it("uses plain cookies for a local http redirect URI", async () => {
    const auth = createTestAuth(idp, {
      redirectUri: "http://localhost:3000/auth/callback",
    });
    const local = await createAuthHandlers({
      auth,
      grants: new GrantManager({ auth, store: new MemoryGrantStore() }),
      sessions,
      secret: SECRET,
    });
    const response = await local.handle(
      new Request("http://localhost:3000/auth/login"),
    );
    const [cookie] = response?.headers.getSetCookie() ?? [];
    expect(cookie).toMatch(/^aai_login=/);
    expect(cookie).not.toContain("Secure");
  });

  it.each([
    [
      "a redirectUri not matching the callback route",
      { redirectUri: `${ORIGIN}/cb` },
      {},
    ],
    ["a base path with a trailing slash", {}, { basePath: "/auth/" }],
    ["a base path without a leading slash", {}, { basePath: "auth" }],
    ["a short secret", {}, { secret: "short" }],
  ])("rejects %s", async (_label, authOverride, handlerOverride) => {
    const auth = createTestAuth(idp, {
      redirectUri: `${ORIGIN}/auth/callback`,
      ...authOverride,
    });
    await expect(
      createAuthHandlers({
        auth,
        grants: new GrantManager({ auth, store: new MemoryGrantStore() }),
        sessions,
        secret: SECRET,
        ...handlerOverride,
      }),
    ).rejects.toMatchObject({ code: "CFG_001" });
  });

  it("reports an unexpected failure and answers generically", async () => {
    class FailingStore extends MemorySessionStore {
      override get(): Promise<Session | undefined> {
        return Promise.reject(new Error("db down: password=hunter2"));
      }
    }
    const failing = new FailingStore();
    await build({ sessions: failing });
    const response = await mustHandle(withSession("any"));
    expect(response.status).toBe(500);
    expect(JSON.stringify(await response.json())).not.toContain("hunter2");
    expect(onError).toHaveBeenCalledOnce();
  });
});

describe("frontend data routes", () => {
  const account = {
    balance: "9007199254740993",
    isUnlimited: false,
    canSpend: true,
    currency: "eur",
  };

  async function buildWithAi(): Promise<void> {
    const auth = createAuthClient(
      {
        issuer: ISSUER,
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        redirectUri: `${ORIGIN}/auth/callback`,
        gatewayUrl: GATEWAY_URL,
      },
      {
        fetch: async (input, init) => {
          const request = new Request(input, init);
          return new URL(request.url).origin === GATEWAY_URL
            ? jsonResponse({ data: [{ id: "gpt-4o-mini" }] })
            : idp.fetch(input, init);
        },
      },
    );
    grants = new GrantManager({ auth, store: new MemoryGrantStore() });
    handlers = await createAuthHandlers({
      auth,
      grants,
      sessions,
      secret: SECRET,
      ai: createAiClient({ auth, grants }),
    });
  }

  it("serves the wallet of the signed-in user with the top-up link", async () => {
    await buildWithAi();
    const cookie = await signIn();
    idp.apiHandler = () => jsonResponse(account);

    const response = await mustHandle(withSession(cookie, {}, "/auth/wallet"));

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      ...account,
      topupUrl: `${ISSUER}/profile`,
    });
    expect(idp.requests.at(-1)?.headers.get("authorization")).toBe(
      `Bearer access-r1`,
    );
  });

  it("serves the spend statistics and validates the window", async () => {
    await buildWithAi();
    const cookie = await signIn();
    idp.apiHandler = (request) =>
      jsonResponse({
        days: Number(request.url.searchParams.get("days") ?? 30),
        total: "0",
        notBilled: "0",
        calls: 0,
        series: [],
        byApplication: [],
        byKind: [],
        byModel: [],
        daily: [],
      });

    const ok = await mustHandle(
      withSession(cookie, {}, "/auth/wallet/stats?days=7"),
    );
    expect(((await ok.json()) as { days: number }).days).toBe(7);

    for (const days of ["0", "91", "x", "1.5"]) {
      expect(
        (
          await mustHandle(
            withSession(cookie, {}, `/auth/wallet/stats?days=${days}`),
          )
        ).status,
      ).toBe(400);
    }
    const bad = await mustHandle(
      withSession(cookie, {}, "/auth/wallet/stats?days=0"),
    );
    expect(await bad.json()).toEqual({
      error: { code: "REQ_001", message: "Invalid request" },
    });
  });

  it("lists the gateway models", async () => {
    await buildWithAi();
    const cookie = await signIn();
    const response = await mustHandle(withSession(cookie, {}, "/auth/models"));
    expect(
      ((await response.json()) as { models: { id: string }[] }).models[0]?.id,
    ).toBe("gpt-4o-mini");
  });

  it("requires a session", async () => {
    await buildWithAi();
    expect((await mustHandle(get("/auth/wallet"))).status).toBe(401);
    expect((await mustHandle(get("/auth/models"))).status).toBe(401);
  });

  it("does not exist unless an AI client was provided", async () => {
    const cookie = await signIn();
    expect(
      await handlers.handle(withSession(cookie, {}, "/auth/wallet")),
    ).toBeNull();
  });
});
