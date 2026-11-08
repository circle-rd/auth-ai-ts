import * as oidc from "openid-client";
import type { ResolvedAuthClientConfig } from "./config.js";
import { ERR } from "./errors.js";
import { createJwtVerifier } from "./jwt.js";
import type { JwtVerifier } from "./jwt.js";
import { toAuthAiError } from "./oauth-errors.js";

// Discovery and keys change rarely; an hour keeps rotation picked up without a restart.
const PROVIDER_TTL_MS = 3_600_000;

const ASYMMETRIC_ALGORITHMS = new Set([
  "ES256",
  "ES384",
  "ES512",
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
]);

export interface Provider {
  readonly configuration: oidc.Configuration;
  readonly verifyJwt: JwtVerifier;
}

function clientAuthentication(
  config: ResolvedAuthClientConfig,
): oidc.ClientAuth {
  if (!config.clientSecret) return oidc.None();
  return config.tokenEndpointAuthMethod === "client_secret_post"
    ? oidc.ClientSecretPost(config.clientSecret)
    : oidc.ClientSecretBasic(config.clientSecret);
}

// openid-client types its body wider than RequestInit under `exactOptionalPropertyTypes`
// (it admits a Uint8Array over a SharedArrayBuffer), but only ever sends strings or form data.
function asCustomFetch(fetchImpl: typeof fetch): oidc.CustomFetch {
  return (url, { body, ...init }) =>
    fetchImpl(
      url,
      body === undefined ? init : { ...init, body: body as BodyInit },
    );
}

async function loadProvider(
  config: ResolvedAuthClientConfig,
  fetchImpl: typeof fetch | undefined,
): Promise<Provider> {
  const timeoutSeconds = Math.ceil(config.timeoutMs / 1000);
  const auth = clientAuthentication(config);

  let discovered: oidc.Configuration;
  try {
    discovered = await oidc.discovery(
      new URL(config.issuer),
      config.clientId,
      undefined,
      auth,
      {
        timeout: timeoutSeconds,
        ...(fetchImpl ? { [oidc.customFetch]: asCustomFetch(fetchImpl) } : {}),
      },
    );
  } catch (err) {
    throw toAuthAiError(err, "discovery");
  }

  const server = discovered.serverMetadata();
  const algorithms = (
    server.id_token_signing_alg_values_supported ?? []
  ).filter((alg) => ASYMMETRIC_ALGORITHMS.has(alg));
  const [idTokenAlgorithm] = algorithms;
  if (!idTokenAlgorithm || !server.jwks_uri) {
    throw ERR.OIDC_001(
      "The provider advertises no asymmetric ID token algorithm or no jwks_uri",
    );
  }

  // The library assumes RS256 unless told otherwise, whereas auth-service signs with ES256.
  const configuration = new oidc.Configuration(
    server,
    config.clientId,
    {
      id_token_signed_response_alg: idTokenAlgorithm,
      [oidc.clockTolerance]: config.clockToleranceSeconds,
    },
    auth,
  );
  configuration.timeout = timeoutSeconds;
  if (fetchImpl) configuration[oidc.customFetch] = asCustomFetch(fetchImpl);

  return {
    configuration,
    verifyJwt: createJwtVerifier({
      issuer: config.issuer,
      jwksUri: server.jwks_uri,
      algorithms: [idTokenAlgorithm],
      clockToleranceSeconds: config.clockToleranceSeconds,
      timeoutMs: config.timeoutMs,
      fetch: fetchImpl,
    }),
  };
}

export function createProviderLoader(
  config: ResolvedAuthClientConfig,
  fetchImpl: typeof fetch | undefined,
): () => Promise<Provider> {
  let cached: { loadedAt: number; provider: Promise<Provider> } | undefined;

  return () => {
    if (cached && Date.now() - cached.loadedAt < PROVIDER_TTL_MS) {
      return cached.provider;
    }
    const provider = loadProvider(config, fetchImpl);
    const entry = { loadedAt: Date.now(), provider };
    cached = entry;
    // A failed load is not cached: the next call retries.
    provider.catch(() => {
      if (cached === entry) cached = undefined;
    });
    return provider;
  };
}
