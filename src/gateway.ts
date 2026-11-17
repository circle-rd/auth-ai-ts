import { z } from "zod";
import { ERR } from "./errors.js";
import { toGatewayError } from "./gateway-errors.js";

const SERVER_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;
// The gateway's own `/v1/mcp/...` routes own this segment: no server can be named so.
const RESERVED_SERVER_NAME = "v1";

export const gatewayModelSchema = z.looseObject({
  id: z.string(),
  object: z.string().optional(),
  created: z.number().optional(),
  owned_by: z.string().optional(),
});

const modelListSchema = z.object({ data: z.array(gatewayModelSchema) });

export const gatewayAgentSchema = z.looseObject({
  agent_id: z.string(),
  agent_name: z.string(),
});

export const gatewayMcpServerSchema = z.looseObject({
  server_id: z.string(),
  server_name: z.string().nullish(),
  alias: z.string().nullish(),
  description: z.string().nullish(),
  transport: z.string().nullish(),
});

export type GatewayModel = z.infer<typeof gatewayModelSchema>;
export type GatewayAgent = z.infer<typeof gatewayAgentSchema>;
export type GatewayMcpServer = z.infer<typeof gatewayMcpServerSchema>;

/** Supplies the access token minted for the gateway audience. */
export interface GatewayTokens {
  getToken(): Promise<string>;
  /** Drops the token the gateway refused, so the next call mints a fresh one. */
  invalidate(): void;
}

export interface GatewayClientOptions {
  /** Public URL of the gateway: the token audience, with no trailing slash. */
  readonly gatewayUrl: string;
  readonly tokens: GatewayTokens;
  readonly fetch: typeof fetch;
  readonly timeoutMs: number;
}

/**
 * The LiteLLM gateway on behalf of a signed-in user. The user's access token
 * is the API key: it lives one hour, so it is minted per call (and cached by
 * the grant manager) and never stored. The gateway bills the user's wallet.
 */
export class GatewayClient {
  readonly #options: GatewayClientOptions;

  constructor(options: GatewayClientOptions) {
    this.#options = options;
  }

  /** `baseURL` of an OpenAI-compatible SDK. */
  get openAiBaseUrl(): string {
    return `${this.#options.gatewayUrl}/v1`;
  }

  /**
   * `fetch` that signs requests to the gateway with a fresh user token. Pass it
   * to an OpenAI-compatible SDK together with `baseURL: openAiBaseUrl` and any
   * placeholder `apiKey`; it refuses any other origin so the token cannot leak.
   * A 401 drops the cached token: retrying the call mints a new one.
   */
  readonly fetch: typeof fetch = async (input, init) => {
    const request = new Request(input, init);
    if (
      new URL(request.url).origin !== new URL(this.#options.gatewayUrl).origin
    ) {
      throw ERR.CFG_001("This fetch only serves requests to the gateway");
    }
    request.headers.set(
      "authorization",
      `Bearer ${await this.#options.tokens.getToken()}`,
    );
    const response = await this.#options.fetch(request);
    if (response.status === 401) this.#options.tokens.invalidate();
    return response;
  };

  /** A fresh access token, for clients that cannot take a custom `fetch`. */
  getAccessToken(): Promise<string> {
    return this.#options.tokens.getToken();
  }

  /** The models the user may call: the ones they own or that are shared with them. */
  async listModels(): Promise<GatewayModel[]> {
    return (await this.#getJson("/v1/models", modelListSchema)).data;
  }

  /** The agents the user may reach. */
  listAgents(): Promise<GatewayAgent[]> {
    return this.#getJson("/v1/agents", z.array(gatewayAgentSchema));
  }

  /** The MCP servers the user may reach. */
  listMcpServers(): Promise<GatewayMcpServer[]> {
    return this.#getJson("/v1/mcp/server", z.array(gatewayMcpServerSchema));
  }

  /**
   * Endpoint of the gateway's MCP server, or of one registered server: connect
   * an MCP client to it with the `Authorization: Bearer` header of
   * `getAccessToken()`.
   */
  mcpUrl(serverName?: string): string {
    if (serverName === undefined) return `${this.#options.gatewayUrl}/mcp`;
    if (
      !SERVER_NAME_PATTERN.test(serverName) ||
      serverName.toLowerCase() === RESERVED_SERVER_NAME
    ) {
      throw ERR.CFG_001("Invalid MCP server name");
    }
    return `${this.#options.gatewayUrl}/${serverName}/mcp`;
  }

  /**
   * POSTs JSON to a gateway route (`/v1/chat/completions`, `/v1/embeddings`…)
   * and returns the parsed answer, which the caller validates. A refusal
   * becomes a gateway error: GW_001 when the wallet cannot pay (402).
   */
  async postJson(path: string, body: unknown): Promise<unknown> {
    return this.#send(path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  }

  async #getJson<T>(path: string, schema: z.ZodType<T>): Promise<T> {
    const parsed = schema.safeParse(await this.#send(path, {}));
    if (!parsed.success) {
      throw ERR.GW_005(undefined, { cause: parsed.error });
    }
    return parsed.data;
  }

  async #send(path: string, init: RequestInit): Promise<unknown> {
    const response = await this.fetch(`${this.#options.gatewayUrl}${path}`, {
      ...init,
      headers: { accept: "application/json", ...init.headers },
      redirect: "error",
      signal: AbortSignal.timeout(this.#options.timeoutMs),
    });
    const body: unknown = await response.json().catch(() => undefined);
    if (!response.ok) {
      throw toGatewayError(response.status, body, response.headers);
    }
    return body;
  }
}
