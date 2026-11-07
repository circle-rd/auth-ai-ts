import { createHash } from "node:crypto";
import { beforeEach, describe, expect, it } from "vitest";
import { AuthAiError } from "./errors.js";
import { createAuthClient } from "./client.js";
import type { AuthClient } from "./client.js";
import type { LoginHandshake } from "./types.js";
import {
  CLIENT_ID,
  CLIENT_SECRET,
  ISSUER,
  REDIRECT_URI,
  createMockIdp,
  jsonResponse,
} from "./test-support/mock-idp.js";
import type { MockIdp } from "./test-support/mock-idp.js";

const RESOURCES = ["https://app.test", "https://llm.test"];

let idp: MockIdp;
let auth: AuthClient;

beforeEach(async () => {
  idp = await createMockIdp();
  auth = createAuthClient(
    {
      issuer: ISSUER,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      redirectUri: REDIRECT_URI,
      postLogoutRedirectUri: "https://app.test/",
      resources: RESOURCES,
    },
    { fetch: idp.fetch },
  );
});

async function expectAuthAiError(
  promise: Promise<unknown>,
  code: string,
): Promise<AuthAiError> {
  const err = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(AuthAiError);
  expect((err as AuthAiError).code).toBe(code);
  return err as AuthAiError;
}

function callbackUrl(handshake: LoginHandshake, extra = ""): string {
  return `${REDIRECT_URI}?code=abc&state=${handshake.state}&iss=${encodeURIComponent(ISSUER)}${extra}`;
}

async function respondWithTokens(
  handshake: LoginHandshake,
  idTokenClaims: Record<string, unknown> = {},
): Promise<void> {
  const idToken = await idp.idToken({
    nonce: handshake.nonce,
    sid: "sid-1",
    roles: ["editor"],
    features: { maxProjects: 10 },
    ...idTokenClaims,
  });
  idp.tokenHandler = () =>
    jsonResponse({
      access_token: "access-1",
      token_type: "Bearer",
      expires_in: 3600,
      refresh_token: "refresh-1",
      scope: "openid roles",
      id_token: idToken,
    });
}

describe("startLogin", () => {
  it("builds a PKCE authorization URL requesting every resource", async () => {
    const { url, handshake } = await auth.startLogin({ prompt: "login" });
    const params = new URL(url).searchParams;

    expect(url.startsWith(`${ISSUER}/authorize?`)).toBe(true);
    expect(params.get("client_id")).toBe(CLIENT_ID);
    expect(params.get("response_type")).toBe("code");
    expect(params.get("redirect_uri")).toBe(REDIRECT_URI);
    expect(params.get("scope")).toContain("offline_access");
    expect(params.get("state")).toBe(handshake.state);
    expect(params.get("nonce")).toBe(handshake.nonce);
    expect(params.get("prompt")).toBe("login");
    expect(params.getAll("resource")).toEqual(RESOURCES);
    expect(params.get("code_challenge_method")).toBe("S256");
    expect(params.get("code_challenge")).toBe(
      createHash("sha256").update(handshake.codeVerifier).digest("base64url"),
    );
  });

  it("creates distinct secrets per attempt and discovers once", async () => {
    const first = await auth.startLogin();
    const second = await auth.startLogin({ loginHint: "a@b.c" });
    expect(first.handshake.state).not.toBe(second.handshake.state);
    expect(first.handshake.codeVerifier).not.toBe(
      second.handshake.codeVerifier,
    );
    expect(new URL(second.url).searchParams.get("login_hint")).toBe("a@b.c");
    expect(idp.requestsTo("/.well-known/openid-configuration")).toHaveLength(1);
  });
});

describe("discovery", () => {
  it("fails with OIDC_001 and retries on the next call", async () => {
    idp.discoveryFailures = 1;
    await expectAuthAiError(auth.startLogin(), "OIDC_001");
    await expect(auth.startLogin()).resolves.toHaveProperty("url");
  });

  it("rejects a provider without asymmetric signing algorithms", async () => {
    idp.metadata["id_token_signing_alg_values_supported"] = ["HS256"];
    await expectAuthAiError(auth.startLogin(), "OIDC_001");
  });

  it("rejects a provider that only advertises the deprecated EdDSA", async () => {
    idp.metadata["id_token_signing_alg_values_supported"] = ["EdDSA"];
    await expectAuthAiError(auth.startLogin(), "OIDC_001");
  });
});

describe("handleCallback", () => {
  it("exchanges the code and returns verified claims", async () => {
    const { handshake } = await auth.startLogin();
    await respondWithTokens(handshake);

    const result = await auth.handleCallback(callbackUrl(handshake), handshake);

    expect(result.sessionId).toBe("sid-1");
    expect(result.claims.roles).toEqual(["editor"]);
    expect(result.claims.features).toEqual({ maxProjects: 10 });
    expect(result.tokens.accessToken).toBe("access-1");
    expect(result.tokens.refreshToken).toBe("refresh-1");
    expect(result.tokens.expiresAt).toBeGreaterThan(Date.now() / 1000);

    const [request] = idp.requestsTo("/token");
    expect(request?.form.get("grant_type")).toBe("authorization_code");
    expect(request?.form.get("code_verifier")).toBe(handshake.codeVerifier);
    expect(request?.form.get("redirect_uri")).toBe(REDIRECT_URI);
    expect(request?.form.has("resource")).toBe(false);
    // RFC 6749 §2.3.1: both parts are form-urlencoded before the base64 step.
    const [scheme, encoded] = (
      request?.headers.get("authorization") ?? ""
    ).split(" ");
    expect(scheme).toBe("Basic");
    const [id, secret] = atob(encoded ?? "").split(":");
    expect([
      decodeURIComponent(id ?? ""),
      decodeURIComponent(secret ?? ""),
    ]).toEqual([CLIENT_ID, CLIENT_SECRET]);
  });

  it("rejects a callback carrying another state", async () => {
    const { handshake } = await auth.startLogin();
    await respondWithTokens(handshake);
    const forged = { ...handshake, state: "someone-else" };
    await expectAuthAiError(
      auth.handleCallback(callbackUrl(handshake), forged),
      "OIDC_002",
    );
    expect(idp.requestsTo("/token")).toHaveLength(0);
  });

  it("surfaces an authorization error from the provider", async () => {
    const { handshake } = await auth.startLogin();
    const err = await expectAuthAiError(
      auth.handleCallback(
        `${REDIRECT_URI}?error=access_denied&state=${handshake.state}&iss=${encodeURIComponent(ISSUER)}`,
        handshake,
      ),
      "OIDC_002",
    );
    expect(err.details?.["oauthError"]).toBe("access_denied");
  });

  it("surfaces a token endpoint rejection without leaking the code", async () => {
    const { handshake } = await auth.startLogin();
    idp.tokenHandler = () =>
      jsonResponse(
        { error: "invalid_grant", error_description: "code expired" },
        400,
      );
    const err = await expectAuthAiError(
      auth.handleCallback(callbackUrl(handshake), handshake),
      "OIDC_003",
    );
    expect(err.details).toEqual({
      oauthError: "invalid_grant",
      status: 400,
      description: "code expired",
    });
    expect(JSON.stringify(err.toJSON())).not.toContain("abc");
  });

  it("rejects an ID token signed by an unknown key", async () => {
    const { handshake } = await auth.startLogin();
    const foreign = await idp.generateForeignKey();
    const forgedIdToken = await idp.signJwt(
      {
        iss: ISSUER,
        sub: "attacker",
        aud: CLIENT_ID,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 300,
        nonce: handshake.nonce,
      },
      { key: foreign },
    );
    idp.tokenHandler = () =>
      jsonResponse({
        access_token: "a",
        token_type: "Bearer",
        expires_in: 60,
        id_token: forgedIdToken,
      });
    await expectAuthAiError(
      auth.handleCallback(callbackUrl(handshake), handshake),
      "TOK_001",
    );
  });

  it("rejects an ID token issued for another audience", async () => {
    const { handshake } = await auth.startLogin();
    await respondWithTokens(handshake, { aud: "another-app" });
    await expectAuthAiError(
      auth.handleCallback(callbackUrl(handshake), handshake),
      "OIDC_002",
    );
  });

  it("rejects an ID token bound to another nonce", async () => {
    const { handshake } = await auth.startLogin();
    await respondWithTokens(handshake, { nonce: "replayed" });
    await expectAuthAiError(
      auth.handleCallback(callbackUrl(handshake), handshake),
      "OIDC_002",
    );
  });

  it("rejects ID token claims of an unexpected shape", async () => {
    const { handshake } = await auth.startLogin();
    await respondWithTokens(handshake, { roles: "admin" });
    await expectAuthAiError(
      auth.handleCallback(callbackUrl(handshake), handshake),
      "TOK_001",
    );
  });

  it("rejects a token response without expires_in", async () => {
    const { handshake } = await auth.startLogin();
    const idToken = await idp.idToken({ nonce: handshake.nonce });
    idp.tokenHandler = () =>
      jsonResponse({
        access_token: "a",
        token_type: "Bearer",
        id_token: idToken,
      });
    await expectAuthAiError(
      auth.handleCallback(callbackUrl(handshake), handshake),
      "OIDC_003",
    );
  });

  it("reports no session id when the provider omits sid", async () => {
    const { handshake } = await auth.startLogin();
    await respondWithTokens(handshake);
    const idToken = await idp.idToken({ nonce: handshake.nonce });
    idp.tokenHandler = () =>
      jsonResponse({
        access_token: "a",
        token_type: "Bearer",
        expires_in: 60,
        id_token: idToken,
      });
    const result = await auth.handleCallback(callbackUrl(handshake), handshake);
    expect(result.sessionId).toBeUndefined();
  });
});

describe("refresh", () => {
  it("narrows to one resource without sending a scope", async () => {
    idp.tokenHandler = () =>
      jsonResponse({
        access_token: "access-2",
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: "refresh-2",
      });

    const tokens = await auth.refresh("refresh-1", {
      resource: "https://llm.test",
    });

    expect(tokens.accessToken).toBe("access-2");
    expect(tokens.refreshToken).toBe("refresh-2");
    const [request] = idp.requestsTo("/token");
    expect(request?.form.get("grant_type")).toBe("refresh_token");
    expect(request?.form.get("refresh_token")).toBe("refresh-1");
    expect(request?.form.get("resource")).toBe("https://llm.test");
    expect(request?.form.has("scope")).toBe(false);
  });

  it("reports an absent rotation as no refresh token", async () => {
    idp.tokenHandler = () =>
      jsonResponse({ access_token: "a", token_type: "Bearer", expires_in: 60 });
    const tokens = await auth.refresh("refresh-1");
    expect(tokens.refreshToken).toBeUndefined();
    expect(idp.requestsTo("/token")[0]?.form.has("resource")).toBe(false);
  });

  it("surfaces invalid_grant with its OAuth error code", async () => {
    idp.tokenHandler = () => jsonResponse({ error: "invalid_grant" }, 400);
    const err = await expectAuthAiError(auth.refresh("stale"), "OIDC_003");
    expect(err.details?.["oauthError"]).toBe("invalid_grant");
  });

  it("wraps a transport failure", async () => {
    idp.tokenHandler = () => {
      throw new TypeError("fetch failed");
    };
    await expectAuthAiError(auth.refresh("refresh-1"), "OIDC_003");
  });
});

describe("logoutUrl", () => {
  it("builds an RP-initiated logout URL", async () => {
    const url = new URL(
      await auth.logoutUrl({ idTokenHint: "id.token", state: "s" }),
    );
    expect(url.origin + url.pathname).toBe(`${ISSUER}/end-session`);
    expect(url.searchParams.get("id_token_hint")).toBe("id.token");
    expect(url.searchParams.get("post_logout_redirect_uri")).toBe(
      "https://app.test/",
    );
    expect(url.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(url.searchParams.get("state")).toBe("s");
  });

  it("fails when the provider has no end session endpoint", async () => {
    delete idp.metadata["end_session_endpoint"];
    await expectAuthAiError(auth.logoutUrl(), "OIDC_004");
  });
});

describe("revoke and introspect", () => {
  it("revokes a refresh token", async () => {
    await auth.revoke("refresh-1", "refresh_token");
    const [request] = idp.requestsTo("/revoke");
    expect(request?.form.get("token")).toBe("refresh-1");
    expect(request?.form.get("token_type_hint")).toBe("refresh_token");
  });

  it("fails a revocation the provider rejects", async () => {
    idp.revocationStatus = 400;
    await expectAuthAiError(auth.revoke("refresh-1"), "OIDC_003");
  });

  it("fails when the provider has no revocation endpoint", async () => {
    delete idp.metadata["revocation_endpoint"];
    await expectAuthAiError(auth.revoke("t"), "OIDC_004");
  });

  it("introspects a token", async () => {
    idp.introspection = { active: true, sub: "u1", scope: "openid" };
    const result = await auth.introspect("access-1", "access_token");
    expect(result).toMatchObject({ active: true, sub: "u1" });
    expect(idp.requestsTo("/introspect")[0]?.form.get("token")).toBe(
      "access-1",
    );
  });

  it("fails when the provider has no introspection endpoint", async () => {
    delete idp.metadata["introspection_endpoint"];
    await expectAuthAiError(auth.introspect("t"), "OIDC_004");
  });
});

describe("public client", () => {
  it("sends no client authentication", async () => {
    const publicAuth = createAuthClient(
      { issuer: ISSUER, clientId: CLIENT_ID, redirectUri: REDIRECT_URI },
      { fetch: idp.fetch },
    );
    idp.tokenHandler = () =>
      jsonResponse({ access_token: "a", token_type: "Bearer", expires_in: 60 });
    await publicAuth.refresh("refresh-1");
    const [request] = idp.requestsTo("/token");
    expect(request?.headers.get("authorization")).toBeNull();
    expect(request?.form.has("client_secret")).toBe(false);
  });
});

describe("client_secret_post", () => {
  it("sends the credentials in the body", async () => {
    const postAuth = createAuthClient(
      {
        issuer: ISSUER,
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        tokenEndpointAuthMethod: "client_secret_post",
        redirectUri: REDIRECT_URI,
      },
      { fetch: idp.fetch },
    );
    idp.tokenHandler = () =>
      jsonResponse({ access_token: "a", token_type: "Bearer", expires_in: 60 });
    await postAuth.refresh("refresh-1");
    const [request] = idp.requestsTo("/token");
    expect(request?.headers.get("authorization")).toBeNull();
    expect(request?.form.get("client_secret")).toBe(CLIENT_SECRET);
  });
});

describe("verifyIdToken", () => {
  it("verifies a refreshed ID token on demand", async () => {
    const claims = await auth.verifyIdToken(
      await idp.idToken({ org_id: "org-1" }),
    );
    expect(claims.org_id).toBe("org-1");
  });

  it("rejects an expired ID token", async () => {
    const now = Math.floor(Date.now() / 1000);
    const expired = await idp.idToken({ iat: now - 600, exp: now - 300 });
    await expectAuthAiError(auth.verifyIdToken(expired), "TOK_001");
  });
});

describe("fetchUserInfo", () => {
  it("returns the standard claims", async () => {
    idp.userinfoHandler = () =>
      jsonResponse({ sub: "user-1", email: "ada@example.com" });
    const info = await auth.fetchUserInfo("access-0");
    expect(info.email).toBe("ada@example.com");
  });

  it("wraps a transport failure as a failed provider request", async () => {
    idp.userinfoHandler = () => {
      throw new TypeError("fetch failed");
    };
    await expectAuthAiError(auth.fetchUserInfo("access-0"), "OIDC_003");
  });

  it("wraps a provider refusal as a failed provider request", async () => {
    idp.userinfoHandler = () => new Response("unavailable", { status: 503 });
    await expectAuthAiError(auth.fetchUserInfo("access-0"), "OIDC_003");
  });

  it("rejects a successful answer that is not JSON", async () => {
    idp.userinfoHandler = () =>
      new Response("<html></html>", {
        status: 200,
        headers: { "content-type": "text/html" },
      });
    await expectAuthAiError(auth.fetchUserInfo("access-0"), "TOK_001");
  });

  it("rejects a successful answer without a subject", async () => {
    idp.userinfoHandler = () => jsonResponse({ email: "ada@example.com" });
    await expectAuthAiError(auth.fetchUserInfo("access-0"), "TOK_001");
  });
});

describe("clientCredentials", () => {
  it("requests a machine token with the given scope and resource", async () => {
    idp.tokenHandler = () =>
      jsonResponse({ access_token: "m", token_type: "Bearer", expires_in: 60 });
    const tokens = await auth.clientCredentials({
      scope: "billing:read",
      resource: "https://app.test",
    });
    expect(tokens.accessToken).toBe("m");
    expect(tokens.refreshToken).toBeUndefined();
    const [request] = idp.requestsTo("/token");
    expect(request?.form.get("grant_type")).toBe("client_credentials");
    expect(request?.form.get("scope")).toBe("billing:read");
    expect(request?.form.get("resource")).toBe("https://app.test");
  });

  it("surfaces a rejected client", async () => {
    idp.tokenHandler = () => jsonResponse({ error: "invalid_scope" }, 400);
    const err = await expectAuthAiError(
      auth.clientCredentials({ scope: "wallet:debit" }),
      "OIDC_003",
    );
    expect(err.details?.["oauthError"]).toBe("invalid_scope");
  });

  it("explains a client authentication challenge", async () => {
    idp.tokenHandler = () =>
      new Response(null, {
        status: 401,
        headers: { "www-authenticate": 'Basic realm="token"' },
      });
    const err = await expectAuthAiError(auth.clientCredentials(), "OIDC_003");
    expect(err.details).toEqual({ status: 401 });
    expect(err.message).toContain("clientSecret");
  });

  it("is refused to a public client", async () => {
    const publicAuth = createAuthClient(
      { issuer: ISSUER, clientId: CLIENT_ID, redirectUri: REDIRECT_URI },
      { fetch: idp.fetch },
    );
    await expectAuthAiError(publicAuth.clientCredentials(), "CFG_001");
  });
});

describe("verifyJwt", () => {
  it("verifies against the provider keys", async () => {
    const payload = await auth.verifyJwt(await idp.idToken(), {
      audience: CLIENT_ID,
    });
    expect(payload.sub).toBe("user-1");
  });
});

describe("fetch", () => {
  it("defaults to the global fetch, resolved at call time", async () => {
    const calls: string[] = [];
    const original = globalThis.fetch;
    globalThis.fetch = (async (input: Parameters<typeof fetch>[0]) => {
      calls.push(String(input));
      return new Response("{}");
    }) as typeof fetch;
    try {
      const defaultAuth = createAuthClient({
        issuer: ISSUER,
        clientId: CLIENT_ID,
        redirectUri: REDIRECT_URI,
      });
      await defaultAuth.fetch("https://example.test/ping");
      expect(calls).toEqual(["https://example.test/ping"]);
    } finally {
      globalThis.fetch = original;
    }
  });
});
