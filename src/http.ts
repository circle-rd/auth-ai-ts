import { z } from "zod";
import { ERR } from "./errors.js";

const apiErrorSchema = z.object({
  error: z.object({
    code: z.string(),
    message: z.string(),
  }),
});

/** Supplies the Bearer token of a call, by the scope or audience the endpoint requires. */
export interface HttpTokens {
  getToken(key: string): Promise<string>;
  /** Drops a token the API refused, so the retry mints a fresh one. */
  invalidate(key: string): void;
}

export interface JsonHttpOptions {
  /** Origin the request paths are resolved against: no trailing slash. */
  readonly baseUrl: string;
  readonly fetch: typeof fetch;
  readonly timeoutMs: number;
  readonly tokens: HttpTokens;
}

export interface ApiRequest<T> {
  readonly method: "GET" | "POST";
  /** Path below the base URL; segments must already be URL-encoded. */
  readonly path: string;
  /** Key passed to the token supplier: a machine scope, or an audience. */
  readonly scope: string;
  readonly query?: Readonly<Record<string, string | number | undefined>>;
  readonly body?: unknown;
  readonly schema: z.ZodType<T>;
}

/** Authenticated JSON calls to the auth-service REST API. */
export class JsonHttp {
  readonly #options: JsonHttpOptions;

  constructor(options: JsonHttpOptions) {
    this.#options = options;
  }

  async request<T>(request: ApiRequest<T>): Promise<T> {
    let response = await this.#send(request);
    // A revoked or rotated credential surfaces as 401: retry once with a fresh token.
    if (response.status === 401) {
      this.#options.tokens.invalidate(request.scope);
      response = await this.#send(request);
    }
    if (!response.ok) throw await this.#toError(response);

    const parsed = request.schema.safeParse(
      await response.json().catch(() => undefined),
    );
    if (!parsed.success) {
      throw ERR.API_002(undefined, { cause: parsed.error });
    }
    return parsed.data;
  }

  async #send(request: ApiRequest<unknown>): Promise<Response> {
    const url = new URL(`${this.#options.baseUrl}${request.path}`);
    for (const [name, value] of Object.entries(request.query ?? {})) {
      if (value !== undefined) url.searchParams.set(name, String(value));
    }
    const token = await this.#options.tokens.getToken(request.scope);
    return this.#options.fetch(url, {
      method: request.method,
      headers: {
        authorization: `Bearer ${token}`,
        accept: "application/json",
        ...(request.body === undefined
          ? {}
          : { "content-type": "application/json" }),
      },
      ...(request.body === undefined
        ? {}
        : { body: JSON.stringify(request.body) }),
      redirect: "error",
      signal: AbortSignal.timeout(this.#options.timeoutMs),
    });
  }

  async #toError(response: Response) {
    const body = apiErrorSchema.safeParse(
      await response.json().catch(() => undefined),
    );
    if (!body.success) {
      return ERR.API_001(`auth-service answered ${response.status}`, {
        details: { status: response.status },
      });
    }
    const { code, message } = body.data.error;
    return ERR.API_001(
      `auth-service answered ${response.status} ${code}: ${message}`,
      { details: { status: response.status, apiCode: code } },
    );
  }
}
