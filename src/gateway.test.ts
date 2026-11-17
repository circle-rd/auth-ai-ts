import { beforeEach, describe, expect, it, vi } from "vitest";
import { AuthAiError } from "./errors.js";
import { GatewayClient } from "./gateway.js";
import {
  isInsufficientCredit,
  isInsufficientCreditStatus,
  toGatewayError,
} from "./gateway-errors.js";
import {
  GATEWAY_URL,
  createMockGateway,
  jsonResponse,
} from "./test-support/mock-idp.js";
import type { MockGateway } from "./test-support/mock-idp.js";

let gateway: MockGateway;
let invalidate: ReturnType<typeof vi.fn<() => void>>;
let minted: number;
let client: GatewayClient;

beforeEach(() => {
  gateway = createMockGateway();
  invalidate = vi.fn();
  minted = 0;
  client = new GatewayClient({
    gatewayUrl: GATEWAY_URL,
    tokens: {
      getToken: async () => `gw-token-${(minted += 1)}`,
      invalidate,
    },
    fetch: async (input, init) => {
      const request = new Request(input, init);
      gateway.requests.push(request.clone());
      return gateway.handler(request);
    },
    timeoutMs: 5_000,
  });
});

async function rejection(promise: Promise<unknown>): Promise<AuthAiError> {
  const err = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(AuthAiError);
  return err as AuthAiError;
}

describe("fetch", () => {
  it("signs a request to the gateway with a fresh token each time", async () => {
    gateway.handler = () => jsonResponse({ ok: true });
    await client.fetch(`${GATEWAY_URL}/v1/chat/completions`, {
      method: "POST",
      body: JSON.stringify({ model: "m" }),
      headers: { "content-type": "application/json" },
    });
    await client.fetch(new Request(`${GATEWAY_URL}/v1/models`));
    expect(gateway.requests.map((r) => r.headers.get("authorization"))).toEqual(
      ["Bearer gw-token-1", "Bearer gw-token-2"],
    );
    expect(await gateway.requests[0]?.json()).toEqual({ model: "m" });
    expect(gateway.requests[0]?.headers.get("content-type")).toBe(
      "application/json",
    );
  });

  it("replaces a placeholder key set by an OpenAI-compatible SDK", async () => {
    gateway.handler = () => jsonResponse({});
    await client.fetch(`${GATEWAY_URL}/v1/models`, {
      headers: { authorization: "Bearer placeholder" },
    });
    expect(gateway.requests[0]?.headers.get("authorization")).toBe(
      "Bearer gw-token-1",
    );
  });

  it("refuses any other origin, so the token cannot leak", async () => {
    await expect(
      client.fetch("https://evil.test/v1/models"),
    ).rejects.toMatchObject({ code: "CFG_001" });
    await expect(
      client.fetch("https://llm.test.evil.test/v1/models"),
    ).rejects.toMatchObject({ code: "CFG_001" });
    expect(gateway.requests).toHaveLength(0);
    expect(minted).toBe(0);
  });

  it("drops the cached token on a 401 and returns the response", async () => {
    gateway.handler = () => new Response(null, { status: 401 });
    const response = await client.fetch(`${GATEWAY_URL}/v1/models`);
    expect(response.status).toBe(401);
    expect(invalidate).toHaveBeenCalledOnce();
  });

  it("is usable detached from the client, as an SDK option", async () => {
    gateway.handler = () => jsonResponse({});
    const { fetch: detached } = client;
    await detached(`${GATEWAY_URL}/v1/models`);
    expect(gateway.requests).toHaveLength(1);
  });
});

describe("OpenAI-compatible access", () => {
  it("exposes the base URL and a raw token", async () => {
    expect(client.openAiBaseUrl).toBe(`${GATEWAY_URL}/v1`);
    expect(await client.getAccessToken()).toBe("gw-token-1");
  });
});

describe("listing", () => {
  it("lists the models of the plan", async () => {
    gateway.handler = () =>
      jsonResponse({
        object: "list",
        data: [
          {
            id: "gpt-4o-mini",
            object: "model",
            created: 1,
            owned_by: "openai",
          },
          { id: "local-llama", extra: true },
        ],
      });
    const models = await client.listModels();
    expect(models.map((m) => m.id)).toEqual(["gpt-4o-mini", "local-llama"]);
    expect(gateway.requests[0]?.url).toBe(`${GATEWAY_URL}/v1/models`);
    expect(gateway.requests[0]?.headers.get("accept")).toBe("application/json");
  });

  it("lists agents and MCP servers", async () => {
    gateway.handler = (request) =>
      request.url.endsWith("/v1/agents")
        ? jsonResponse([{ agent_id: "a1", agent_name: "Researcher" }])
        : jsonResponse([
            { server_id: "s1", server_name: "docs", description: null },
            { server_id: "s2", alias: "web" },
          ]);
    expect((await client.listAgents())[0]?.agent_name).toBe("Researcher");
    expect((await client.listMcpServers()).map((s) => s.server_id)).toEqual([
      "s1",
      "s2",
    ]);
  });

  it("flags an answer that is not the documented shape", async () => {
    gateway.handler = () => jsonResponse({ data: [{ name: "no-id" }] });
    expect((await rejection(client.listModels())).code).toBe("GW_005");
  });

  it("maps a refused listing to a gateway error", async () => {
    gateway.handler = () =>
      jsonResponse(
        {
          error: {
            message: "This endpoint is not available to users",
            type: "auth_error",
          },
        },
        403,
      );
    const err = await rejection(client.listAgents());
    expect(err.code).toBe("GW_003");
    expect(err.details).toEqual({ status: 403, type: "auth_error" });
  });
});

describe("postJson", () => {
  it("posts JSON with a fresh token and returns the parsed answer", async () => {
    gateway.handler = () =>
      jsonResponse({ choices: [{ message: { content: "hi" } }] });
    const answer = await client.postJson("/v1/chat/completions", {
      model: "m",
      messages: [],
    });
    expect(answer).toEqual({ choices: [{ message: { content: "hi" } }] });
    const [request] = gateway.requests;
    expect(request?.method).toBe("POST");
    expect(request?.headers.get("authorization")).toBe("Bearer gw-token-1");
    expect(request?.headers.get("content-type")).toBe("application/json");
    expect(await request?.json()).toEqual({ model: "m", messages: [] });
  });

  it("maps an empty wallet to GW_001", async () => {
    gateway.handler = () =>
      jsonResponse(
        {
          error: {
            message: "Insufficient credit. Top up your account to continue.",
            type: "insufficient_credit",
            code: "402",
          },
        },
        402,
      );
    const err = await rejection(
      client.postJson("/v1/embeddings", { input: "x" }),
    );
    expect(err.code).toBe("GW_001");
    expect(err.details).toEqual({ status: 402, type: "insufficient_credit" });
  });
});

describe("MCP endpoints", () => {
  it("builds the gateway and per-server URLs", () => {
    expect(client.mcpUrl()).toBe(`${GATEWAY_URL}/mcp`);
    expect(client.mcpUrl("docs-server_1")).toBe(
      `${GATEWAY_URL}/docs-server_1/mcp`,
    );
  });

  it.each(["", "a/b", "..", "a b", "x?y=1", "x#y", "-start", "v1", "V1"])(
    "refuses the server name %j",
    (name) => {
      expect(() => client.mcpUrl(name)).toThrowError(
        expect.objectContaining({ code: "CFG_001" }),
      );
    },
  );
});

describe("toGatewayError", () => {
  it.each([
    [402, "GW_001"],
    [429, "GW_002"],
    [401, "GW_003"],
    [403, "GW_003"],
    [503, "GW_004"],
    [500, "GW_005"],
    [404, "GW_005"],
  ])("maps HTTP %s to %s", (status, code) => {
    expect(toGatewayError(status, undefined).code).toBe(code);
  });

  it("keeps the gateway message and error type", () => {
    const err = toGatewayError(402, {
      error: {
        message: "Insufficient credit. Top up your account to continue.",
        type: "insufficient_credit",
        code: "402",
      },
    });
    expect(err.message).toBe(
      "Insufficient credit. Top up your account to continue.",
    );
    expect(err.details).toEqual({ status: 402, type: "insufficient_credit" });
    expect(isInsufficientCredit(err)).toBe(true);
  });

  it("reports how long to wait before retrying a rate limit", () => {
    const err = toGatewayError(
      429,
      undefined,
      new Headers({ "retry-after": "12" }),
    );
    expect(err.details).toEqual({ status: 429, retryAfterSeconds: 12 });
    expect(
      toGatewayError(429, undefined, new Headers({ "retry-after": "soon" }))
        .details,
    ).toEqual({ status: 429 });
  });

  it("falls back to a message naming the status", () => {
    expect(toGatewayError(502, "<html>").message).toBe(
      "The gateway answered 502",
    );
  });
});

describe("credit helpers", () => {
  it("recognises the status of an OpenAI-compatible SDK error", () => {
    expect(
      isInsufficientCreditStatus(
        Object.assign(new Error("x"), { status: 402 }),
      ),
    ).toBe(true);
    expect(isInsufficientCreditStatus({ status: 500 })).toBe(false);
    expect(isInsufficientCreditStatus(null)).toBe(false);
    expect(isInsufficientCreditStatus("402")).toBe(false);
    expect(isInsufficientCredit(new Error("x"))).toBe(false);
  });
});
