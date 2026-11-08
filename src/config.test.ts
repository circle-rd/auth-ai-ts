import { describe, expect, it } from "vitest";
import {
  DEFAULT_SCOPES,
  WALLET_SELF_SCOPE,
  parseAuthClientConfig,
} from "./config.js";
import { AuthAiError } from "./errors.js";

const valid = {
  issuer: "https://auth.example.com",
  clientId: "my-app",
  redirectUri: "https://app.example.com/callback",
};

function rejection(input: unknown): AuthAiError {
  try {
    parseAuthClientConfig(input);
  } catch (err) {
    if (err instanceof AuthAiError) return err;
    throw err;
  }
  throw new Error("expected the configuration to be rejected");
}

describe("parseAuthClientConfig", () => {
  it("applies the documented defaults", () => {
    const config = parseAuthClientConfig(valid);
    expect(config.scopes).toEqual([...DEFAULT_SCOPES]);
    expect(config.resources).toEqual([]);
    expect(config.tokenEndpointAuthMethod).toBe("client_secret_basic");
    expect(config.clockToleranceSeconds).toBe(5);
    expect(config.timeoutMs).toBe(10_000);
    expect(config.clientSecret).toBeUndefined();
  });

  it("accepts an http redirect URI on loopback only", () => {
    expect(
      parseAuthClientConfig({
        ...valid,
        redirectUri: "http://localhost:3000/callback",
      }).redirectUri,
    ).toBe("http://localhost:3000/callback");
    expect(
      rejection({ ...valid, redirectUri: "http://app.example.com/callback" })
        .code,
    ).toBe("CFG_001");
  });

  it("accepts path-based issuers with a trailing slash", () => {
    const issuer = "https://www.certification.openid.net/test/a/rp-ts-basic/";
    expect(parseAuthClientConfig({ ...valid, issuer }).issuer).toBe(issuer);
  });

  it.each([
    ["an http issuer", { issuer: "http://auth.example.com" }],
    ["an issuer with a query", { issuer: "https://auth.example.com?tenant=1" }],
    [
      "an issuer with a fragment",
      { issuer: "https://auth.example.com#tenant" },
    ],
    ["scopes without openid", { scopes: ["profile"] }],
    ["a non-URL resource", { resources: ["not a url"] }],
    ["a non-URL redirect URI", { redirectUri: "not a url" }],
    ["an empty client id", { clientId: "" }],
    ["an unknown auth method", { tokenEndpointAuthMethod: "none" }],
  ])("rejects %s", (_label, override) => {
    const err = rejection({ ...valid, ...override });
    expect(err.code).toBe("CFG_001");
    expect(err.message).toContain(Object.keys(override)[0]);
  });

  it("names every missing field and never echoes the secret", () => {
    const err = rejection({ clientSecret: "super-secret-value" });
    expect(err.message).toContain("issuer");
    expect(err.message).toContain("clientId");
    expect(err.message).toContain("redirectUri");
    expect(err.message).not.toContain("super-secret-value");
  });
});

describe("gatewayUrl", () => {
  const gatewayUrl = "https://llm.example.com";

  it("adds the gateway and auth-service audiences and the wallet scope", () => {
    const config = parseAuthClientConfig({
      ...valid,
      resources: ["https://app.example.com"],
      gatewayUrl,
    });
    expect(config.resources).toEqual([
      "https://app.example.com",
      gatewayUrl,
      valid.issuer,
    ]);
    expect(config.scopes).toContain(WALLET_SELF_SCOPE);
    expect(config.scopes).toEqual([...DEFAULT_SCOPES, WALLET_SELF_SCOPE]);
  });

  it("does not duplicate what the application already listed", () => {
    const config = parseAuthClientConfig({
      ...valid,
      resources: [gatewayUrl, valid.issuer],
      scopes: ["openid", WALLET_SELF_SCOPE],
      gatewayUrl,
    });
    expect(config.resources).toEqual([gatewayUrl, valid.issuer]);
    expect(config.scopes).toEqual(["openid", WALLET_SELF_SCOPE]);
  });

  it("leaves scopes and resources alone without a gateway", () => {
    const config = parseAuthClientConfig(valid);
    expect(config.scopes).not.toContain(WALLET_SELF_SCOPE);
    expect(config.resources).toEqual([]);
    expect(config.gatewayUrl).toBeUndefined();
  });

  it.each(["https://llm.example.com/", "ftp://llm.example.com", "llm"])(
    "rejects %s",
    (value) => {
      expect(rejection({ ...valid, gatewayUrl: value }).code).toBe("CFG_001");
    },
  );

  it("accepts a loopback gateway over http for local development", () => {
    expect(
      parseAuthClientConfig({ ...valid, gatewayUrl: "http://localhost:4000" })
        .gatewayUrl,
    ).toBe("http://localhost:4000");
  });
});
