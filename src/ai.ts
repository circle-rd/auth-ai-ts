import type { AuthClient } from "./client.js";
import { ERR } from "./errors.js";
import { GatewayClient } from "./gateway.js";
import type { GatewayTokens } from "./gateway.js";
import type { GrantManager } from "./grants.js";
import { JsonHttp } from "./http.js";
import { OrganizationsClient } from "./organizations.js";
import { ResourceSharingClient } from "./sharing.js";
import { WalletClient } from "./wallet.js";

type AiAuth = Pick<AuthClient, "config" | "fetch">;
type AiGrants = Pick<GrantManager, "getAccessToken" | "invalidate">;

export interface AiClientOptions {
  readonly auth: AiAuth;
  /** Holds the refresh token of each user: access tokens are minted from it. */
  readonly grants: AiGrants;
}

/** What an application does for one signed-in user: wallet, resources, teams, gateway. */
export class UserAi {
  readonly wallet: WalletClient;
  readonly resources: ResourceSharingClient;
  readonly organizations: OrganizationsClient;
  readonly #auth: AiAuth;
  readonly #gatewayTokens: GatewayTokens | undefined;
  #gateway: GatewayClient | undefined;

  constructor(auth: AiAuth, grants: AiGrants, grantId: string) {
    this.#auth = auth;
    const { config } = auth;
    const tokensFor = (resource: string): GatewayTokens => ({
      getToken: async () =>
        (await grants.getAccessToken(grantId, { resource })).accessToken,
      invalidate: () => grants.invalidate(grantId, resource),
    });

    // A user has a single wallet audience, so the supplier ignores the key.
    const walletTokens = tokensFor(config.issuer);
    const issuerHttp = new JsonHttp({
      baseUrl: config.issuer,
      fetch: auth.fetch,
      timeoutMs: config.timeoutMs,
      tokens: {
        getToken: () => walletTokens.getToken(),
        invalidate: () => walletTokens.invalidate(),
      },
    });
    this.wallet = new WalletClient(issuerHttp, config.issuer);
    this.resources = new ResourceSharingClient(issuerHttp);
    this.organizations = new OrganizationsClient(issuerHttp);
    this.#gatewayTokens = config.gatewayUrl
      ? tokensFor(config.gatewayUrl)
      : undefined;
  }

  /** Needs `gatewayUrl` in the client configuration. */
  get gateway(): GatewayClient {
    const { gatewayUrl, timeoutMs } = this.#auth.config;
    if (!gatewayUrl || !this.#gatewayTokens) {
      throw ERR.CFG_001(
        "The gateway requires `gatewayUrl` in the configuration",
      );
    }
    this.#gateway ??= new GatewayClient({
      gatewayUrl,
      tokens: this.#gatewayTokens,
      fetch: this.#auth.fetch,
      timeoutMs,
    });
    return this.#gateway;
  }
}

/**
 * Wallet and gateway clients bound to a user's grant. Each call mints (or
 * reuses) a short-lived access token for the right audience: the wallet is
 * served by auth-service, the gateway by its own URL.
 */
export class AiClient {
  readonly #options: AiClientOptions;

  constructor(options: AiClientOptions) {
    this.#options = options;
  }

  /** `grantId` is the key the user's refresh token was saved under (typically `sub`). */
  forUser(grantId: string): UserAi {
    return new UserAi(this.#options.auth, this.#options.grants, grantId);
  }
}

export function createAiClient(options: AiClientOptions): AiClient {
  return new AiClient(options);
}
