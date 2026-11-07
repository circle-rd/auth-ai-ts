import Fastify from "fastify";
import type { FastifyInstance } from "fastify";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { GrantManager, MemoryGrantStore } from "../grants.js";
import {
  CLIENT_ID,
  ISSUER,
  createMockIdp,
  createTestAuth,
  jsonResponse,
  nowSeconds,
} from "../test-support/mock-idp.js";
import type { MockIdp } from "../test-support/mock-idp.js";
import { createAuthHandlers } from "../web/handlers.js";
import type { AuthHandlers } from "../web/handlers.js";
import { MemorySessionStore } from "../web/sessions.js";
import { authPlugin, loadSession, requireAuth } from "./index.js";

const ORIGIN = "https://app.test";
const EVENT = "http://schemas.openid.net/event/backchannel-logout";
const SESSION_COOKIE = "__Host-aai_session";
const LOGIN_COOKIE = "__Host-aai_login";

let idp: MockIdp;
let handlers: AuthHandlers;
let sessions: MemorySessionStore;
let app: FastifyInstance;
let nonce: string;

beforeEach(async () => {
  idp = await createMockIdp();
  sessions = new MemorySessionStore();
  nonce = "";
  idp.tokenHandler = async () =>
    jsonResponse({
      access_token: "access-0",
      token_type: "Bearer",
      expires_in: 3600,
      refresh_token: "refresh-0",
      id_token: await idp.idToken({ nonce, sid: "sid-1", roles: ["editor"] }),
    });
  const auth = createTestAuth(idp, { redirectUri: `${ORIGIN}/auth/callback` });
  handlers = await createAuthHandlers({
    auth,
    grants: new GrantManager({ auth, store: new MemoryGrantStore() }),
    sessions,
    secret: "0123456789abcdef0123456789abcdef",
  });

  app = Fastify();
  await app.register(authPlugin, { handlers });
  app.get(
    "/private",
    { preHandler: requireAuth(handlers) },
    async (request) => ({
      sub: request.authSession?.userId,
      roles: request.authSession?.claims.roles,
    }),
  );
  app.get("/maybe", { preHandler: loadSession(handlers) }, async (request) => ({
    signedIn: request.authSession !== null,
  }));
  app.get("/public", async () => ({ ok: true }));
  await app.ready();
});

afterEach(() => app.close());

function cookiesOf(
  setCookie: string | string[] | undefined,
): Map<string, string> {
  const cookies = new Map<string, string>();
  for (const line of [setCookie ?? []].flat()) {
    const [pair = ""] = line.split(";");
    const separator = pair.indexOf("=");
    cookies.set(pair.slice(0, separator), pair.slice(separator + 1));
  }
  return cookies;
}

async function signIn(): Promise<string> {
  const login = await app.inject({
    method: "GET",
    url: "/auth/login?next=/home",
  });
  expect(login.statusCode).toBe(302);
  const authorize = new URL(login.headers.location as string);
  nonce = authorize.searchParams.get("nonce") ?? "";
  const callback = await app.inject({
    method: "GET",
    url: `/auth/callback?code=abc&state=${authorize.searchParams.get("state")}&iss=${encodeURIComponent(ISSUER)}`,
    headers: {
      cookie: `${LOGIN_COOKIE}=${cookiesOf(login.headers["set-cookie"]).get(LOGIN_COOKIE)}`,
    },
  });
  expect(callback.statusCode).toBe(303);
  expect(callback.headers.location).toBe("/home");
  return cookiesOf(callback.headers["set-cookie"]).get(SESSION_COOKIE) ?? "";
}

const asUser = (cookie: string) => ({ cookie: `${SESSION_COOKIE}=${cookie}` });

describe("routes", () => {
  it("serves login with its cookie and redirect", async () => {
    const response = await app.inject({ method: "GET", url: "/auth/login" });
    expect(response.statusCode).toBe(302);
    expect(response.headers.location).toContain(`${ISSUER}/authorize`);
    expect(response.headers["cache-control"]).toBe("no-store");
    expect([response.headers["set-cookie"]].flat()[0]).toContain(LOGIN_COOKIE);
  });

  it("completes a sign-in and serves /me", async () => {
    const cookie = await signIn();
    const me = await app.inject({
      method: "GET",
      url: "/auth/me",
      headers: asUser(cookie),
    });
    expect(me.statusCode).toBe(200);
    expect(me.headers["content-type"]).toContain("application/json");
    expect(me.json().user.roles).toEqual(["editor"]);
  });

  it("logs out and clears the cookie", async () => {
    const cookie = await signIn();
    const response = await app.inject({
      method: "POST",
      url: "/auth/logout",
      headers: {
        ...asUser(cookie),
        origin: ORIGIN,
        accept: "application/json",
      },
    });
    expect(response.statusCode).toBe(200);
    expect(response.json().logoutUrl).toContain(`${ISSUER}/end-session`);
    expect([response.headers["set-cookie"]].flat()[0]).toContain("Max-Age=0");
    expect(
      (
        await app.inject({
          method: "GET",
          url: "/auth/me",
          headers: asUser(cookie),
        })
      ).statusCode,
    ).toBe(401);
  });

  it("parses the back-channel logout form", async () => {
    const cookie = await signIn();
    const iat = nowSeconds();
    const token = await idp.signJwt(
      {
        iss: ISSUER,
        aud: CLIENT_ID,
        sub: "user-1",
        sid: "sid-1",
        iat,
        exp: iat + 120,
        jti: "j1",
        events: { [EVENT]: {} },
      },
      { typ: "logout+jwt" },
    );
    const response = await app.inject({
      method: "POST",
      url: "/auth/backchannel-logout",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({ logout_token: token }).toString(),
    });
    expect(response.statusCode).toBe(200);
    expect(response.body).toBe("");
    expect(
      (
        await app.inject({
          method: "GET",
          url: "/auth/me",
          headers: asUser(cookie),
        })
      ).statusCode,
    ).toBe(401);
  });

  it("answers 405 and 404 through the handlers", async () => {
    const wrongMethod = await app.inject({
      method: "POST",
      url: "/auth/login",
    });
    expect(wrongMethod.statusCode).toBe(405);
    expect(wrongMethod.headers.allow).toBe("GET");
    expect(
      (await app.inject({ method: "GET", url: "/auth/nothing" })).statusCode,
    ).toBe(404);
    expect(
      (await app.inject({ method: "GET", url: "/public" })).json(),
    ).toEqual({ ok: true });
  });

  it("builds URLs on the registered origin, not on the Host header", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/auth/login",
      headers: { host: "evil.test" },
    });
    expect(response.statusCode).toBe(302);
    expect(response.headers.location).not.toContain("evil.test");
    expect(idp.requests.every((r) => !r.url.host.includes("evil.test"))).toBe(
      true,
    );
  });

  it("ignores a request target that is not an origin-form path", async () => {
    const response = await app.inject({ method: "GET", url: "/auth/login//" });
    expect(response.statusCode).toBe(404);
  });
});

describe("hooks", () => {
  it("requireAuth answers 401 to a signed-out request", async () => {
    const response = await app.inject({ method: "GET", url: "/private" });
    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({
      error: { code: "SES_001", message: "Not signed in" },
    });
  });

  it("requireAuth exposes the session to the handler", async () => {
    const cookie = await signIn();
    const response = await app.inject({
      method: "GET",
      url: "/private",
      headers: asUser(cookie),
    });
    expect(response.json()).toEqual({ sub: "user-1", roles: ["editor"] });
  });

  it("loadSession never blocks", async () => {
    expect((await app.inject({ method: "GET", url: "/maybe" })).json()).toEqual(
      { signedIn: false },
    );
    const cookie = await signIn();
    expect(
      (
        await app.inject({
          method: "GET",
          url: "/maybe",
          headers: asUser(cookie),
        })
      ).json(),
    ).toEqual({
      signedIn: true,
    });
  });

  it("reports a provider failure as an error response, not a crash", async () => {
    const auth = createTestAuth(idp, {
      redirectUri: `${ORIGIN}/auth/callback`,
    });
    const renewing = await createAuthHandlers({
      auth,
      grants: new GrantManager({ auth, store: new MemoryGrantStore() }),
      sessions,
      secret: "0123456789abcdef0123456789abcdef",
      claimsRenewSeconds: 0,
    });
    const second = Fastify();
    await second.register(authPlugin, { handlers: renewing });
    second.get("/private", { preHandler: requireAuth(renewing) }, async () => ({
      ok: true,
    }));
    second.get("/maybe", { preHandler: loadSession(renewing) }, async () => ({
      ok: true,
    }));
    await second.ready();

    const login = await second.inject({ method: "GET", url: "/auth/login" });
    const authorize = new URL(login.headers.location as string);
    nonce = authorize.searchParams.get("nonce") ?? "";
    const callback = await second.inject({
      method: "GET",
      url: `/auth/callback?code=abc&state=${authorize.searchParams.get("state")}&iss=${encodeURIComponent(ISSUER)}`,
      headers: {
        cookie: `${LOGIN_COOKIE}=${cookiesOf(login.headers["set-cookie"]).get(LOGIN_COOKIE)}`,
      },
    });
    const cookie =
      cookiesOf(callback.headers["set-cookie"]).get(SESSION_COOKIE) ?? "";
    idp.tokenHandler = () => jsonResponse({ error: "server_error" }, 500);

    for (const url of ["/private", "/maybe"]) {
      const response = await second.inject({
        method: "GET",
        url,
        headers: asUser(cookie),
      });
      expect(response.statusCode).toBe(502);
      expect(response.json().error.code).toBe("OIDC_003");
    }
    await second.close();
  });
});
