import {
  createRemoteJWKSet,
  customFetch,
  decodeProtectedHeader,
  errors as joseErrors,
  jwtVerify,
} from "jose";
import type { JWTPayload } from "jose";
import { ERR } from "./errors.js";

// Re-fetch an unknown `kid` (key rotation) at most once per cooldown.
const JWKS_COOLDOWN_MS = 30_000;
const JWKS_UNKNOWN_KID_COOLDOWN_MS = 1_000;
const JWKS_MAX_AGE_MS = 3_600_000;

export interface JwtVerifierOptions {
  readonly issuer: string;
  readonly jwksUri: string;
  /** Pinned to the algorithms the provider declares: `none` and HMAC never qualify. */
  readonly algorithms: readonly string[];
  readonly clockToleranceSeconds: number;
  readonly timeoutMs: number;
  readonly fetch: typeof fetch | undefined;
}

export interface VerifyJwtOptions {
  readonly audience: string;
  readonly typ?: string;
}

export type JwtVerifier = (
  token: string,
  options: VerifyJwtOptions,
) => Promise<JWTPayload>;

export function createJwtVerifier(options: JwtVerifierOptions): JwtVerifier {
  const jwks = createRemoteJWKSet(new URL(options.jwksUri), {
    cooldownDuration: JWKS_COOLDOWN_MS,
    cacheMaxAge: JWKS_MAX_AGE_MS,
    timeoutDuration: options.timeoutMs,
    ...(options.fetch ? { [customFetch]: options.fetch } : {}),
  });
  let lastUnknownKidReloadAt = 0;

  return async (token, { audience, typ }) => {
    try {
      const { kid } = decodeProtectedHeader(token);
      const cached = jwks.jwks();
      const hasMatchingKid =
        typeof kid === "string" &&
        cached?.keys.some((key) => key.kid === kid) === true;
      const needsRefresh = typeof kid !== "string" || !hasMatchingKid;
      if (
        cached &&
        needsRefresh &&
        Date.now() - lastUnknownKidReloadAt >= JWKS_UNKNOWN_KID_COOLDOWN_MS
      ) {
        await jwks.reload();
        lastUnknownKidReloadAt = Date.now();
      }
      const { payload } = await jwtVerify(token, jwks, {
        issuer: options.issuer,
        audience,
        algorithms: [...options.algorithms],
        clockTolerance: options.clockToleranceSeconds,
        requiredClaims: ["exp", "iss", "sub"],
        ...(typ ? { typ } : {}),
      });
      return payload;
    } catch (err) {
      if (err instanceof joseErrors.JOSEError) {
        throw ERR.TOK_001(`Token verification failed: ${err.message}`, {
          details: { reason: err.code },
          cause: err,
        });
      }
      throw ERR.TOK_001(undefined, { cause: err });
    }
  };
}
