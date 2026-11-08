import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  CLIENT_ID,
  ISSUER,
  createMockIdp,
  createTestAuth,
  nowSeconds,
} from "../test-support/mock-idp.js";
import type { MockIdp } from "../test-support/mock-idp.js";
import {
  MemoryReplayStore,
  createBackchannelLogoutHandler,
  verifyLogoutToken,
} from "./backchannel-logout.js";

const EVENT = "http://schemas.openid.net/event/backchannel-logout";

let idp: MockIdp;
let onLogout: ReturnType<
  typeof vi.fn<(event: { sid: string; sub: string }) => void>
>;
let onError: ReturnType<typeof vi.fn<(error: unknown) => void>>;
let handle: (request: Request) => Promise<Response>;

beforeEach(async () => {
  idp = await createMockIdp();
  onLogout = vi.fn();
  onError = vi.fn();
  handle = createBackchannelLogoutHandler({
    auth: createTestAuth(idp),
    onLogout,
    onError,
  });
});

function logoutClaims(overrides: Record<string, unknown> = {}) {
  const iat = nowSeconds();
  return {
    iss: ISSUER,
    aud: CLIENT_ID,
    sub: "user-1",
    sid: "sid-1",
    iat,
    exp: iat + 120,
    jti: crypto.randomUUID(),
    events: { [EVENT]: {} },
    ...overrides,
  };
}

function logoutToken(
  overrides: Record<string, unknown> = {},
  typ: string | null = "logout+jwt",
): Promise<string> {
  return idp.signJwt(logoutClaims(overrides), typ ? { typ } : {});
}

function post(token: string | undefined, init: RequestInit = {}): Request {
  const body = new URLSearchParams(token ? { logout_token: token } : {});
  return new Request("https://app.test/backchannel-logout", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
    ...init,
  });
}

describe("back-channel logout handler", () => {
  it("ends the session named by a valid token", async () => {
    const response = await handle(post(await logoutToken()));
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(onLogout).toHaveBeenCalledExactlyOnceWith({
      sid: "sid-1",
      sub: "user-1",
    });
    expect(onError).not.toHaveBeenCalled();
  });

  it("can accept a provider's missing typ only when explicitly configured", async () => {
    const permissive = createBackchannelLogoutHandler({
      auth: createTestAuth(idp),
      onLogout,
      allowMissingTyp: true,
      onError,
    });

    const response = await permissive(post(await logoutToken({}, null)));

    expect(response.status).toBe(200);
    expect(onLogout).toHaveBeenCalledExactlyOnceWith({
      sid: "sid-1",
      sub: "user-1",
    });
  });

  it("refuses a replayed token", async () => {
    const token = await logoutToken();
    expect((await handle(post(token))).status).toBe(200);
    const replay = await handle(post(token));
    expect(replay.status).toBe(400);
    expect(await replay.json()).toEqual({ error: "invalid_request" });
    expect(onLogout).toHaveBeenCalledTimes(1);
    expect(onError).toHaveBeenCalledTimes(1);
  });

  it.each([
    ["a wrong typ", () => logoutToken({}, "JWT")],
    ["no typ", () => logoutToken({}, null)],
    ["another audience", () => logoutToken({ aud: "other-app" })],
    ["another issuer", () => logoutToken({ iss: "https://evil.test" })],
    ["no event", () => logoutToken({ events: {} })],
    ["a nonce", () => logoutToken({ nonce: "n" })],
    ["no sid", () => logoutToken({ sid: undefined })],
    ["no jti", () => logoutToken({ jti: undefined })],
    ["no iat", () => logoutToken({ iat: undefined })],
    ["an iat in the future", () => logoutToken({ iat: nowSeconds() + 3600 })],
    [
      "a lifetime beyond 10 minutes",
      () => logoutToken({ exp: nowSeconds() + 7200 }),
    ],
    [
      "an expiry in the past",
      () => logoutToken({ iat: nowSeconds() - 600, exp: nowSeconds() - 300 }),
    ],
  ])("rejects a token with %s", async (_label, build) => {
    const response = await handle(post(await build()));
    expect(response.status).toBe(400);
    expect(onLogout).not.toHaveBeenCalled();
    expect(onError).toHaveBeenCalledTimes(1);
  });

  it("rejects a token signed by an unknown key", async () => {
    const forged = await idp.signJwt(logoutClaims(), {
      typ: "logout+jwt",
      key: await idp.generateForeignKey(),
    });
    expect((await handle(post(forged))).status).toBe(400);
    expect(onLogout).not.toHaveBeenCalled();
  });

  it("does not let a failed validation burn the jti", async () => {
    const jti = "shared-jti";
    await handle(post(await logoutToken({ jti, nonce: "n" })));
    expect((await handle(post(await logoutToken({ jti })))).status).toBe(200);
  });

  it("answers 405 to anything but POST", async () => {
    const response = await handle(
      new Request("https://app.test/backchannel-logout", { method: "GET" }),
    );
    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe("POST");
  });

  it("rejects a body that is not a form", async () => {
    const request = new Request("https://app.test/x", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ logout_token: await logoutToken() }),
    });
    expect((await handle(request)).status).toBe(400);
  });

  it("rejects a form without logout_token", async () => {
    expect((await handle(post(undefined))).status).toBe(400);
  });

  it("rejects an oversized body", async () => {
    const huge = "x".repeat(20_000);
    expect((await handle(post(huge))).status).toBe(400);
    const lying = post("x", {
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        "content-length": "99999",
      },
    });
    expect((await handle(lying)).status).toBe(400);
    expect(idp.requests).toHaveLength(0);
  });

  it("answers 500 and reports when ending the session fails", async () => {
    onLogout.mockRejectedValueOnce(new Error("db down"));
    const response = await handle(post(await logoutToken()));
    expect(response.status).toBe(500);
    expect(await response.json()).toEqual({ error: "server_error" });
    expect(onError).toHaveBeenCalledTimes(1);
  });

  it("works without an error callback", async () => {
    const quiet = createBackchannelLogoutHandler({
      auth: createTestAuth(idp),
      onLogout,
    });
    expect((await quiet(post("not-a-jwt"))).status).toBe(400);
  });
});

describe("verifyLogoutToken", () => {
  it("returns the claims", async () => {
    const claims = await verifyLogoutToken(
      createTestAuth(idp),
      await logoutToken({ jti: "j1" }),
      new MemoryReplayStore(),
    );
    expect(claims).toMatchObject({ sid: "sid-1", sub: "user-1", jti: "j1" });
  });
});

describe("MemoryReplayStore", () => {
  it("accepts a jti again once its token expired", async () => {
    vi.useFakeTimers({ now: Date.UTC(2026, 9, 31, 8, 0, 0) });
    try {
      const store = new MemoryReplayStore();
      const expiry = Date.now() / 1000 + 120;
      expect(await store.claim("j", expiry)).toBe(true);
      expect(await store.claim("j", expiry)).toBe(false);
      vi.setSystemTime(Date.now() + 121_000);
      expect(await store.claim("j", Date.now() / 1000 + 120)).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });
});
