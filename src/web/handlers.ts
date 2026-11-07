import { z } from "zod";
import type { AiClient } from "../ai.js";
import type { AuthClient } from "../client.js";
import type { IdTokenClaims } from "../claims.js";
import { AuthAiError, ERR } from "../errors.js";
import type { GrantManager } from "../grants.js";
import { toSessionUser } from "../session-user.js";
import {
  MemoryReplayStore,
  createBackchannelLogoutHandler,
} from "../server/backchannel-logout.js";
import type { ReplayStore } from "../server/backchannel-logout.js";
import {
  clearCookie,
  cookieName,
  parseCookies,
  serializeCookie,
} from "./cookies.js";
import {
  errorResponse,
  isCrossSite,
  jsonResponse,
  redirectResponse,
  safeRedirectPath,
} from "./http.js";
import { createAiRoutes } from "./ai-routes.js";
import { deriveSealKey, seal, unseal } from "./seal.js";
import type { Session, SessionStore } from "./sessions.js";

const HANDSHAKE_TTL_SECONDS = 600;
const DEFAULT_SESSION_TTL_SECONDS = 8 * 3600;
const DEFAULT_CLAIMS_RENEW_SECONDS = 900;
const PROMPTS = [
  "login",
  "consent",
  "select_account",
  "create",
  "none",
] as const;
type Prompt = (typeof PROMPTS)[number];

const isPrompt = (value: string | null): value is Prompt =>
  PROMPTS.some((prompt) => prompt === value);

const handshakeSchema = z.object({
  state: z.string(),
  nonce: z.string(),
  codeVerifier: z.string(),
  next: z.string(),
});

const logoutCookieSchema = z.object({
  state: z.string(),
  next: z.string(),
});

export interface AuthHandlersOptions {
  readonly auth: AuthClient;
  readonly grants: GrantManager;
  readonly sessions: SessionStore;
  /** At least 32 random characters: seals the sign-in cookie. Keep it out of source control. */
  readonly secret: string;
  /** Path prefix of the routes; `redirectUri` must be `<origin><basePath>/callback`. */
  readonly basePath?: string;
  /** Where users land after sign-in or sign-out without a target. */
  readonly defaultRedirect?: string;
  /** Absolute lifetime of a session. */
  readonly sessionTtlSeconds?: number;
  /** How often claims (roles, features…) are renewed from the provider. */
  readonly claimsRenewSeconds?: number;
  /** Refuse an ID token without `sid`: no back-channel logout could ever reach it. */
  readonly requireProviderSession?: boolean;
  /** Redirect target of a failed sign-in, with `?error=<code>`; JSON when unset. */
  readonly errorRedirect?: string;
  /** Adds `/wallet`, `/wallet/stats` and `/models` for the frontend, read with the user's tokens. */
  readonly ai?: AiClient;
  readonly replayStore?: ReplayStore;
  /** Called after sessions end (sign-out or back-channel logout): close sockets, drop caches. */
  readonly onSessionsEnded?: (
    sessions: readonly Session[],
  ) => Promise<void> | void;
  /** Receives unexpected failures and the ones the response must not detail. */
  readonly onError?: (error: unknown) => void;
}

export interface AuthHandlers {
  /** Serves the routes below `basePath`; null for any other path. */
  handle(request: Request): Promise<Response | null>;
  /** The signed-in session of a request, with claims renewed when due; null when signed out. */
  getSession(request: Request): Promise<Session | null>;
  /** Like `getSession`, throwing SES_001 when signed out. */
  requireSession(request: Request): Promise<Session>;
  /** Origin the SDK builds URLs on: that of `redirectUri`, never a request header. */
  readonly origin: string;
  readonly basePath: string;
  /** The `onError` the handlers were created with: adapters use it for their own failures. */
  readonly onError: ((error: unknown) => void) | undefined;
}

function base64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

async function sha256Base64Url(value: string): Promise<string> {
  return base64Url(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
    ),
  );
}

const randomId = (): string =>
  base64Url(crypto.getRandomValues(new Uint8Array(32)));

const nowSeconds = (): number => Math.floor(Date.now() / 1000);

/**
 * Backend-for-frontend sign-in: the browser holds an opaque session cookie and
 * never sees a token. Mount `handle` on every request below `basePath`.
 */
export async function createAuthHandlers(
  options: AuthHandlersOptions,
): Promise<AuthHandlers> {
  const { auth, grants, sessions } = options;
  const basePath = options.basePath ?? "/auth";
  const defaultRedirect = options.defaultRedirect ?? "/";
  const sessionTtl = options.sessionTtlSeconds ?? DEFAULT_SESSION_TTL_SECONDS;
  const renewSeconds =
    options.claimsRenewSeconds ?? DEFAULT_CLAIMS_RENEW_SECONDS;
  const requireProviderSession = options.requireProviderSession ?? true;
  const replayStore = options.replayStore ?? new MemoryReplayStore();

  if (!/^\/[A-Za-z0-9/_-]*$/.test(basePath) || basePath.endsWith("/")) {
    throw ERR.CFG_001("basePath must look like /auth, with no trailing slash");
  }
  const redirect = new URL(auth.config.redirectUri);
  if (redirect.pathname !== `${basePath}/callback`) {
    throw ERR.CFG_001(`redirectUri must end with ${basePath}/callback`);
  }
  const origin = redirect.origin;
  const secure = redirect.protocol === "https:";
  const key = await deriveSealKey(options.secret);
  const sessionCookie = cookieName("aai_session", secure);
  const loginCookie = cookieName("aai_login", secure);
  const logoutCookie = cookieName("aai_logout", secure);

  const withCookies = (...cookies: string[]): Headers => {
    const headers = new Headers();
    for (const cookie of cookies) headers.append("set-cookie", cookie);
    return headers;
  };

  async function readSession(request: Request): Promise<Session | null> {
    const cookie = parseCookies(request.headers.get("cookie")).get(
      sessionCookie,
    );
    if (!cookie) return null;
    return (await sessions.get(await sha256Base64Url(cookie))) ?? null;
  }

  async function renewClaims(session: Session): Promise<Session | null> {
    let tokens;
    try {
      tokens = await grants.refreshTokens(session.userId);
    } catch (err) {
      if (err instanceof AuthAiError && err.code === "TOK_002") {
        await endSessions([session]);
        return null;
      }
      throw err;
    }
    if (!tokens.idToken) {
      throw ERR.TOK_001("The provider returned no ID token on refresh");
    }
    let claims = await auth.verifyIdToken(tokens.idToken);
    if (claims.sub !== session.userId) {
      await endSessions([session]);
      throw ERR.TOK_001("The refreshed ID token belongs to another user");
    }
    claims = await auth.applyUserInfo(claims, tokens.accessToken);
    const renewed: Session = {
      ...session,
      claims,
      idToken: tokens.idToken,
      renewAt: Math.min(nowSeconds() + renewSeconds, session.expiresAt),
    };
    await sessions.update(renewed);
    return renewed;
  }

  // Two simultaneous requests of one session share a single renewal.
  const renewing = new Map<string, Promise<Session | null>>();

  async function getSession(request: Request): Promise<Session | null> {
    const session = await readSession(request);
    if (!session || nowSeconds() < session.renewAt) return session;
    let pending = renewing.get(session.id);
    if (!pending) {
      pending = renewClaims(session).finally(() => renewing.delete(session.id));
      renewing.set(session.id, pending);
    }
    return pending;
  }

  async function requireSession(request: Request): Promise<Session> {
    const session = await getSession(request);
    if (!session) throw ERR.SES_001();
    return session;
  }

  /** Ends sessions, and revokes the grant of every user left with none. */
  async function endSessions(ended: readonly Session[]): Promise<void> {
    for (const session of ended) await sessions.delete(session.id);
    await afterSessionsRemoved(ended);
  }

  async function afterSessionsRemoved(
    ended: readonly Session[],
  ): Promise<void> {
    for (const userId of new Set(ended.map((session) => session.userId))) {
      if ((await sessions.countByUser(userId)) > 0) continue;
      try {
        await grants.revoke(userId);
      } catch (err) {
        // The grant is already gone locally: the provider will expire it.
        options.onError?.(err);
      }
    }
    if (ended.length > 0) await options.onSessionsEnded?.(ended);
  }

  async function login(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const prompt = url.searchParams.get("prompt");
    const { url: authorizationUrl, handshake } = await auth.startLogin(
      isPrompt(prompt) ? { prompt } : {},
    );
    const sealed = await seal(
      key,
      {
        ...handshake,
        next: safeRedirectPath(url.searchParams.get("next"), defaultRedirect),
      },
      HANDSHAKE_TTL_SECONDS,
    );
    return redirectResponse(
      authorizationUrl,
      302,
      withCookies(
        serializeCookie(loginCookie, sealed, {
          maxAgeSeconds: HANDSHAKE_TTL_SECONDS,
          secure,
        }),
      ),
    );
  }

  async function createSession(
    claims: IdTokenClaims,
    idToken: string,
    hasRefreshToken: boolean,
  ): Promise<{ session: Session; cookie: string }> {
    const now = nowSeconds();
    const expiresAt = hasRefreshToken
      ? now + sessionTtl
      : Math.min(now + sessionTtl, claims.exp);
    const cookie = randomId();
    const session: Session = {
      id: await sha256Base64Url(cookie),
      userId: claims.sub,
      sessionId: claims.sid,
      claims,
      idToken,
      createdAt: now,
      expiresAt,
      renewAt: hasRefreshToken
        ? Math.min(now + renewSeconds, expiresAt)
        : expiresAt,
    };
    await sessions.create(session);
    return { session, cookie };
  }

  async function callback(request: Request): Promise<Response> {
    const clear = clearCookie(loginCookie, secure);
    try {
      const sealed = parseCookies(request.headers.get("cookie")).get(
        loginCookie,
      );
      if (!sealed) throw ERR.SES_002();
      const { next, ...handshake } = await unseal(key, sealed, handshakeSchema);

      // Rebuilt on the registered URI: the request's own host is not trusted.
      const callbackUrl = new URL(auth.config.redirectUri);
      callbackUrl.search = new URL(request.url).search;
      const result = await auth.handleCallback(callbackUrl, handshake);

      if (requireProviderSession && !result.sessionId) {
        throw ERR.SES_003(
          "The ID token carries no sid: enable end session or a back-channel logout URI on the application",
        );
      }
      const { refreshToken } = result.tokens;
      if (refreshToken) await grants.save(result.claims.sub, refreshToken);
      const { cookie } = await createSession(
        result.claims,
        result.tokens.idToken,
        refreshToken !== undefined,
      );
      return redirectResponse(
        next,
        303,
        withCookies(
          clear,
          serializeCookie(sessionCookie, cookie, {
            maxAgeSeconds: sessionTtl,
            secure,
          }),
        ),
      );
    } catch (err) {
      // Whatever failed (state, code, client credentials, claims), the browser
      // learns one thing: the sign-in failed. Telling a rejected client secret
      // from a forged state would help whoever probes the callback; the cause
      // reaches the application's logs.
      options.onError?.(err);
      const failure = ERR.SES_005(undefined, { cause: err });
      if (options.errorRedirect) {
        return redirectResponse(
          `${options.errorRedirect}?error=${failure.code}`,
          303,
          withCookies(clear),
        );
      }
      return errorResponse(failure, undefined, withCookies(clear));
    }
  }

  async function me(request: Request): Promise<Response> {
    const session = await getSession(request);
    if (!session) return errorResponse(ERR.SES_001(), options.onError);
    return jsonResponse({
      user: toSessionUser(session.claims),
      expiresAt: session.expiresAt,
    });
  }

  async function logout(request: Request): Promise<Response> {
    if (isCrossSite(request, origin)) {
      return errorResponse(ERR.SES_004(), options.onError);
    }
    const session = await readSession(request);
    const state = randomId();
    const next = safeRedirectPath(
      new URL(request.url).searchParams.get("next"),
      defaultRedirect,
    );
    const sealPath = await seal(key, { state, next }, HANDSHAKE_TTL_SECONDS);
    const logoutCookieValue = serializeCookie(logoutCookie, sealPath, {
      maxAgeSeconds: HANDSHAKE_TTL_SECONDS,
      secure,
    });
    let logoutUrl: string | null = null;
    try {
      // The SSO session is shared by every application: end it even without a local session.
      logoutUrl = await auth.logoutUrl(
        session ? { idTokenHint: session.idToken, state } : { state },
      );
    } catch (err) {
      // A provider without end-session still lets the local session end.
      options.onError?.(err);
    }
    if (session) await endSessions([session]);

    const headers = withCookies(
      clearCookie(sessionCookie, secure),
      logoutCookieValue,
    );
    if (request.headers.get("accept")?.includes("application/json")) {
      return jsonResponse({ logoutUrl }, 200, headers);
    }
    return redirectResponse(logoutUrl ?? next, 303, headers);
  }

  /**
   * Handles the OP's post-logout redirect. The local session is already gone;
   * the sealed cookie only carries the destination and the state hint. A
   * missing or different state must not strand the user after the provider has
   * ended the session, so the redirect still succeeds.
   */
  async function logoutCallback(request: Request): Promise<Response> {
    let target = defaultRedirect;
    const sealed = parseCookies(request.headers.get("cookie")).get(
      logoutCookie,
    );
    if (sealed) {
      try {
        const cookie = await unseal(key, sealed, logoutCookieSchema);
        target = safeRedirectPath(cookie.next, defaultRedirect);
      } catch {
        // A tampered or expired cookie only loses the return target.
      }
    }
    return redirectResponse(
      target,
      303,
      withCookies(clearCookie(logoutCookie, secure)),
    );
  }

  const backchannelLogout = createBackchannelLogoutHandler({
    auth,
    replayStore,
    ...(options.onError ? { onError: options.onError } : {}),
    onLogout: async ({ sid }) => {
      await afterSessionsRemoved(await sessions.deleteByProviderSession(sid));
    },
  });

  const routes: Record<
    string,
    { method: "GET" | "POST"; run: (request: Request) => Promise<Response> }
  > = {
    "/login": { method: "GET", run: login },
    "/callback": { method: "GET", run: callback },
    "/me": { method: "GET", run: me },
    "/logout": { method: "POST", run: logout },
    "/logout/callback": { method: "GET", run: logoutCallback },
    "/backchannel-logout": { method: "POST", run: backchannelLogout },
  };
  if (options.ai) {
    const aiRoutes = createAiRoutes(options.ai, requireSession);
    for (const [path, run] of Object.entries(aiRoutes)) {
      routes[path] = { method: "GET", run };
    }
  }

  return {
    origin,
    basePath,
    onError: options.onError,
    getSession,
    requireSession,
    async handle(request) {
      const { pathname } = new URL(request.url);
      if (!pathname.startsWith(`${basePath}/`)) return null;
      const route = routes[pathname.slice(basePath.length)];
      if (!route) return null;
      if (request.method !== route.method) {
        return new Response(null, {
          status: 405,
          headers: { allow: route.method, "cache-control": "no-store" },
        });
      }
      try {
        return await route.run(request);
      } catch (err) {
        return errorResponse(err, options.onError);
      }
    },
  };
}
