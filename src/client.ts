import * as oidc from "openid-client";
import { idTokenClaimsSchema, userInfoClaimsSchema } from "./claims.js";
import type { IdTokenClaims, UserInfoClaims } from "./claims.js";
import { parseAuthClientConfig } from "./config.js";
import type { AuthClientConfig, ResolvedAuthClientConfig } from "./config.js";
import { ERR } from "./errors.js";
import { introspectionSchema } from "./introspection.js";
import type { IntrospectionResult } from "./introspection.js";
import type { JWTPayload } from "jose";
import type { VerifyJwtOptions } from "./jwt.js";
import { toAuthAiError } from "./oauth-errors.js";
import { createProviderLoader } from "./provider.js";
import type { Provider } from "./provider.js";
import type {
  LoginHandshake,
  LoginRequest,
  LoginResult,
  ClientCredentialsOptions,
  LogoutUrlOptions,
  RefreshOptions,
  StartLoginOptions,
  TokenSet,
  TokenTypeHint,
} from "./types.js";

export interface AuthClientOptions {
  /** Replaces the global `fetch`, e.g. to add a proxy or an observability layer. */
  readonly fetch?: typeof fetch;
}

type TokenResponse = Awaited<ReturnType<typeof oidc.refreshTokenGrant>>;

function toTokenSet(response: TokenResponse): TokenSet {
  const expiresIn = response.expiresIn();
  if (expiresIn === undefined) {
    throw ERR.OIDC_003("The token response carries no expires_in");
  }
  return {
    accessToken: response.access_token,
    tokenType: response.token_type,
    expiresAt: Math.floor(Date.now() / 1000) + expiresIn,
    ...(response.scope ? { scope: response.scope } : {}),
    ...(response.refresh_token ? { refreshToken: response.refresh_token } : {}),
    ...(response.id_token ? { idToken: response.id_token } : {}),
  };
}

/**
 * OIDC relying party for auth-service: authorization-code grant with PKCE,
 * refresh with RFC 8707 resource narrowing, logout, revocation and
 * introspection. It keeps no session: callers persist the handshake, the
 * tokens and the claims where it suits them.
 */
export class AuthClient {
  readonly config: ResolvedAuthClientConfig;
  /** The fetch used for every request, shared with the REST API clients built on this one. */
  readonly fetch: typeof fetch;
  readonly #loadProvider: () => Promise<Provider>;

  constructor(config: AuthClientConfig, options: AuthClientOptions = {}) {
    this.config = parseAuthClientConfig(config);
    this.fetch =
      options.fetch ?? ((input, init) => globalThis.fetch(input, init));
    this.#loadProvider = createProviderLoader(this.config, options.fetch);
  }

  async startLogin(options: StartLoginOptions = {}): Promise<LoginRequest> {
    const { configuration } = await this.#loadProvider();
    const handshake: LoginHandshake = {
      state: oidc.randomState(),
      nonce: oidc.randomNonce(),
      codeVerifier: oidc.randomPKCECodeVerifier(),
    };

    const parameters = new URLSearchParams({
      redirect_uri: this.config.redirectUri,
      scope: this.config.scopes.join(" "),
      state: handshake.state,
      nonce: handshake.nonce,
      code_challenge: await oidc.calculatePKCECodeChallenge(
        handshake.codeVerifier,
      ),
      code_challenge_method: "S256",
    });
    if (options.prompt) parameters.set("prompt", options.prompt);
    if (options.loginHint) parameters.set("login_hint", options.loginHint);
    for (const resource of this.config.resources) {
      parameters.append("resource", resource);
    }

    return {
      url: oidc.buildAuthorizationUrl(configuration, parameters).href,
      handshake,
    };
  }

  /**
   * Completes the sign-in from the callback URL. `resource` is deliberately not
   * sent on the code exchange: the token is then issued for every audience
   * requested at sign-in and each refresh narrows it to one.
   */
  async handleCallback(
    callbackUrl: URL | string,
    handshake: LoginHandshake,
  ): Promise<LoginResult> {
    const provider = await this.#loadProvider();

    let response: TokenResponse;
    try {
      response = await oidc.authorizationCodeGrant(
        provider.configuration,
        new URL(callbackUrl),
        {
          pkceCodeVerifier: handshake.codeVerifier,
          expectedState: handshake.state,
          expectedNonce: handshake.nonce,
          idTokenExpected: true,
        },
      );
    } catch (err) {
      throw toAuthAiError(err, "authorization-response");
    }

    const tokens = toTokenSet(response);
    if (!tokens.idToken) {
      throw ERR.OIDC_002("The token response carries no ID token");
    }
    let claims = await this.#verifyIdToken(provider, tokens.idToken);
    if (claims["nonce"] !== handshake.nonce) {
      throw ERR.TOK_001("ID token nonce mismatch");
    }
    claims = await this.#applyUserInfo(provider, claims, tokens.accessToken);

    return {
      tokens: { ...tokens, idToken: tokens.idToken },
      claims,
      sessionId: claims.sid,
    };
  }

  async verifyIdToken(idToken: string): Promise<IdTokenClaims> {
    return this.#verifyIdToken(await this.#loadProvider(), idToken);
  }

  async fetchUserInfo(accessToken: string): Promise<UserInfoClaims> {
    const { configuration } = await this.#loadProvider();
    if (!configuration.serverMetadata().userinfo_endpoint) {
      throw ERR.OIDC_004("The provider advertises no userinfo_endpoint");
    }
    let info: oidc.UserInfoResponse;
    try {
      info = await oidc.fetchUserInfo(
        configuration,
        accessToken,
        oidc.skipSubjectCheck,
      );
    } catch (err) {
      throw toAuthAiError(err, "userinfo");
    }
    try {
      return userInfoClaimsSchema.parse(info);
    } catch (err) {
      throw ERR.TOK_001("The UserInfo response has an unexpected shape", {
        cause: err,
      });
    }
  }

  /**
   * Fills claims the ID token omits from UserInfo, without replacing values.
   *
   * auth-service keeps email and profile claims out of the ID token when an
   * access token is issued; UserInfo is then the authoritative source. The
   * registered and entitlement claims already present in the ID token are
   * never overwritten.
   */
  async applyUserInfo(
    claims: IdTokenClaims,
    accessToken: string,
  ): Promise<IdTokenClaims> {
    const provider = await this.#loadProvider();
    return this.#applyUserInfo(provider, claims, accessToken);
  }

  /**
   * Exchanges a refresh token for fresh tokens. The provider rotates the
   * refresh token on every use: the returned one replaces the presented one,
   * and a replayed stale token revokes the whole family. Concurrent callers
   * should go through a grant manager. `scope` is never sent: the rotated
   * token would be left with the scopes of that request only.
   */
  async refresh(
    refreshToken: string,
    options: RefreshOptions = {},
  ): Promise<TokenSet> {
    const { configuration } = await this.#loadProvider();
    try {
      const response = await oidc.refreshTokenGrant(
        configuration,
        refreshToken,
        options.resource ? { resource: options.resource } : undefined,
      );
      return toTokenSet(response);
    } catch (err) {
      throw toAuthAiError(err, "token-request");
    }
  }

  /** URL ending the provider session (RP-initiated logout). */
  async logoutUrl(options: LogoutUrlOptions = {}): Promise<string> {
    const { configuration } = await this.#loadProvider();
    if (!configuration.serverMetadata().end_session_endpoint) {
      throw ERR.OIDC_004("The provider advertises no end_session_endpoint");
    }
    const parameters = new URLSearchParams();
    if (this.config.postLogoutRedirectUri) {
      parameters.set(
        "post_logout_redirect_uri",
        this.config.postLogoutRedirectUri,
      );
    }
    if (options.idTokenHint) {
      parameters.set("id_token_hint", options.idTokenHint);
    }
    if (options.state) parameters.set("state", options.state);
    return oidc.buildEndSessionUrl(configuration, parameters).href;
  }

  async revoke(token: string, hint?: TokenTypeHint): Promise<void> {
    const { configuration } = await this.#loadProvider();
    if (!configuration.serverMetadata().revocation_endpoint) {
      throw ERR.OIDC_004("The provider advertises no revocation_endpoint");
    }
    try {
      await oidc.tokenRevocation(
        configuration,
        token,
        hint ? { token_type_hint: hint } : undefined,
      );
    } catch (err) {
      throw toAuthAiError(err, "token-request");
    }
  }

  async introspect(
    token: string,
    hint?: TokenTypeHint,
  ): Promise<IntrospectionResult> {
    const { configuration } = await this.#loadProvider();
    if (!configuration.serverMetadata().introspection_endpoint) {
      throw ERR.OIDC_004("The provider advertises no introspection_endpoint");
    }
    try {
      const response = await oidc.tokenIntrospection(
        configuration,
        token,
        hint ? { token_type_hint: hint } : undefined,
      );
      return introspectionSchema.parse(response);
    } catch (err) {
      throw toAuthAiError(err, "token-request");
    }
  }

  /**
   * Verifies the signature, issuer, audience and expiry of a JWT signed by the
   * provider. Low-level: prefer the bearer and logout token verifiers.
   */
  async verifyJwt(
    token: string,
    options: VerifyJwtOptions,
  ): Promise<JWTPayload> {
    return (await this.#loadProvider()).verifyJwt(token, options);
  }

  /**
   * `client_credentials` grant for the application itself: no user is bound to
   * the token. Needs a confidential client.
   */
  async clientCredentials(
    options: ClientCredentialsOptions = {},
  ): Promise<TokenSet> {
    if (!this.config.clientSecret) {
      throw ERR.CFG_001("clientCredentials requires a clientSecret");
    }
    const { configuration } = await this.#loadProvider();
    const parameters: Record<string, string> = {};
    if (options.scope) parameters["scope"] = options.scope;
    if (options.resource) parameters["resource"] = options.resource;
    try {
      return toTokenSet(
        await oidc.clientCredentialsGrant(configuration, parameters),
      );
    } catch (err) {
      throw toAuthAiError(err, "token-request");
    }
  }

  async #applyUserInfo(
    provider: Provider,
    claims: IdTokenClaims,
    accessToken: string,
  ): Promise<IdTokenClaims> {
    if (!provider.configuration.serverMetadata().userinfo_endpoint) {
      return claims;
    }
    const info = await this.fetchUserInfo(accessToken);
    if (info.sub !== claims.sub) {
      throw ERR.TOK_001("The UserInfo response belongs to another user");
    }
    const current = claims as Record<string, unknown>;
    const updates: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(info)) {
      if (key === "sub" || value === undefined || value === null) continue;
      if (current[key] === undefined || current[key] === null) {
        updates[key] = value;
      }
    }
    return Object.keys(updates).length > 0
      ? ({ ...claims, ...updates } as IdTokenClaims)
      : claims;
  }

  async #verifyIdToken(
    provider: Provider,
    idToken: string,
  ): Promise<IdTokenClaims> {
    const payload = await provider.verifyJwt(idToken, {
      audience: this.config.clientId,
    });
    const claims = idTokenClaimsSchema.safeParse(payload);
    if (!claims.success) {
      throw ERR.TOK_001("The ID token claims have an unexpected shape", {
        cause: claims.error,
      });
    }
    return claims.data;
  }
}

export function createAuthClient(
  config: AuthClientConfig,
  options: AuthClientOptions = {},
): AuthClient {
  return new AuthClient(config, options);
}
