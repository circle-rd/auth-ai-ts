import { decodeProtectedHeader } from "jose";
import type { JWTPayload } from "jose";
import type { AuthClient } from "../client.js";
import { ERR } from "../errors.js";

const LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";
const LOGOUT_TOKEN_TYP = "logout+jwt";
// auth-service issues 120 s tokens; anything far beyond is not one of its.
const MAX_LOGOUT_TOKEN_LIFETIME_SECONDS = 600;
const MAX_BODY_BYTES = 16_384;

/**
 * Remembers the `jti` of accepted logout tokens until they expire. Share it
 * across replicas (e.g. a Redis `SET NX PX`): a per-process store only stops
 * replays that hit the same instance.
 */
export interface ReplayStore {
  /** Returns true the first time a `jti` is claimed, false on a replay. */
  claim(jti: string, expiresAt: number): Promise<boolean>;
}

export class MemoryReplayStore implements ReplayStore {
  readonly #seen = new Map<string, number>();

  claim(jti: string, expiresAt: number): Promise<boolean> {
    const now = Date.now() / 1000;
    for (const [seenJti, seenExpiry] of this.#seen) {
      if (seenExpiry <= now) this.#seen.delete(seenJti);
    }
    if (this.#seen.has(jti)) return Promise.resolve(false);
    this.#seen.set(jti, expiresAt);
    return Promise.resolve(true);
  }
}

export interface LogoutTokenClaims {
  readonly sid: string;
  readonly sub: string;
  readonly jti: string;
  readonly iat: number;
  readonly exp: number;
}

type LogoutAuth = Pick<AuthClient, "verifyJwt" | "config">;

/**
 * Validates an OIDC Back-Channel Logout token (spec §2.6) and records its
 * `jti`. auth-service always names both the session and the user.
 */
export async function verifyLogoutToken(
  auth: LogoutAuth,
  token: string,
  replayStore: ReplayStore,
  allowMissingTyp = false,
): Promise<LogoutTokenClaims> {
  let payload: JWTPayload;
  if (allowMissingTyp) {
    const typ = decodeProtectedHeader(token).typ;
    if (
      typ !== undefined &&
      typ !== LOGOUT_TOKEN_TYP &&
      typ !== `application/${LOGOUT_TOKEN_TYP}`
    ) {
      throw ERR.TOK_001("The logout token has an unexpected typ header");
    }
    payload = await auth.verifyJwt(token, { audience: auth.config.clientId });
  } else {
    payload = await auth.verifyJwt(token, {
      audience: auth.config.clientId,
      typ: LOGOUT_TOKEN_TYP,
    });
  }

  const { events, nonce, jti, sid, sub, iat, exp } = payload;
  const hasEvent =
    typeof events === "object" && events !== null && LOGOUT_EVENT in events;
  if (!hasEvent) {
    throw ERR.TOK_001("The logout token lacks the back-channel logout event");
  }
  if (nonce !== undefined) {
    throw ERR.TOK_001("A logout token must not carry a nonce");
  }
  if (typeof jti !== "string" || !jti || typeof sid !== "string" || !sid) {
    throw ERR.TOK_001("The logout token lacks jti or sid");
  }
  if (typeof sub !== "string" || typeof iat !== "number" || exp === undefined) {
    throw ERR.TOK_001("The logout token lacks sub, iat or exp");
  }
  const now = Date.now() / 1000;
  if (
    iat > now + auth.config.clockToleranceSeconds ||
    exp - iat > MAX_LOGOUT_TOKEN_LIFETIME_SECONDS
  ) {
    throw ERR.TOK_001("The logout token has an implausible lifetime");
  }
  if (!(await replayStore.claim(jti, exp))) {
    throw ERR.TOK_001("The logout token was already used");
  }
  return { sid, sub, jti, iat, exp };
}

export interface BackchannelLogoutEvent {
  /** End every local session whose stored `sid` equals this one. */
  readonly sid: string;
  /** For per-user state, when you keep any. */
  readonly sub: string;
}

export interface BackchannelLogoutHandlerOptions {
  readonly auth: LogoutAuth;
  readonly onLogout: (event: BackchannelLogoutEvent) => Promise<void> | void;
  readonly replayStore?: ReplayStore;
  /** Accept missing `typ` only for providers with a known non-conforming logout-token implementation. */
  readonly allowMissingTyp?: boolean;
  /** Receives every rejected token and failed callback: the response carries no detail. */
  readonly onError?: (error: unknown) => void;
}

const NO_STORE = { "cache-control": "no-store" } as const;

function jsonError(status: number, error: string): Response {
  return new Response(JSON.stringify({ error }), {
    status,
    headers: { ...NO_STORE, "content-type": "application/json" },
  });
}

/**
 * Web-standard handler for the application's back-channel logout endpoint.
 * It is called without cookies or credentials: mount it outside any session
 * or CSRF protection.
 */
export function createBackchannelLogoutHandler(
  options: BackchannelLogoutHandlerOptions,
): (request: Request) => Promise<Response> {
  const replayStore = options.replayStore ?? new MemoryReplayStore();

  return async (request) => {
    if (request.method !== "POST") {
      return new Response(null, {
        status: 405,
        headers: { ...NO_STORE, allow: "POST" },
      });
    }

    const declaredLength = Number(request.headers.get("content-length") ?? 0);
    const isForm = (request.headers.get("content-type") ?? "")
      .toLowerCase()
      .startsWith("application/x-www-form-urlencoded");
    if (!isForm || declaredLength > MAX_BODY_BYTES) {
      return jsonError(400, "invalid_request");
    }
    const body = await request.text();
    const token =
      body.length <= MAX_BODY_BYTES
        ? new URLSearchParams(body).get("logout_token")
        : null;
    if (!token) return jsonError(400, "invalid_request");

    let claims: LogoutTokenClaims;
    try {
      claims = await verifyLogoutToken(
        options.auth,
        token,
        replayStore,
        options.allowMissingTyp,
      );
    } catch (err) {
      options.onError?.(err);
      return jsonError(400, "invalid_request");
    }

    try {
      await options.onLogout({ sid: claims.sid, sub: claims.sub });
    } catch (err) {
      options.onError?.(err);
      return jsonError(500, "server_error");
    }
    return new Response(null, { status: 200, headers: NO_STORE });
  };
}
