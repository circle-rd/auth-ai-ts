import { describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { AuthAiError } from "./errors.js";
import { JsonHttp } from "./http.js";

function createHttp(handler: (request: Request) => Response) {
  const requests: Request[] = [];
  const invalidate = vi.fn();
  const http = new JsonHttp({
    baseUrl: "https://auth.test",
    timeoutMs: 1_000,
    fetch: async (input, init) => {
      const request = new Request(input, init);
      requests.push(request);
      return handler(request);
    },
    tokens: { getToken: async () => "token-1", invalidate },
  });
  return { http, requests, invalidate };
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function rejection(promise: Promise<unknown>): Promise<AuthAiError> {
  return promise.then(
    () => {
      throw new Error("expected a rejection");
    },
    (err: unknown) => {
      expect(err).toBeInstanceOf(AuthAiError);
      return err as AuthAiError;
    },
  );
}

describe("JsonHttp", () => {
  it.each(["PUT", "PATCH"] as const)(
    "sends a %s with a JSON body",
    async (method) => {
      const { http, requests } = createHttp(() => json({ ok: true }));
      const body = { displayName: "renamed" };
      const schema = z.object({ ok: z.boolean() });
      await expect(
        http.request({ method, path: "/api/x", scope: "s", body, schema }),
      ).resolves.toEqual({ ok: true });
      const [request] = requests;
      expect(request?.method).toBe(method);
      expect(request?.headers.get("content-type")).toBe("application/json");
      expect(await request?.json()).toEqual(body);
    },
  );

  it("sends a DELETE without a body", async () => {
    const { http, requests } = createHttp(() => json({ removed: true }));
    await http.request({
      method: "DELETE",
      path: "/api/x/1",
      scope: "s",
      schema: z.object({ removed: z.boolean() }),
    });
    const [request] = requests;
    expect(request?.method).toBe("DELETE");
    expect(request?.body).toBeNull();
    expect(request?.headers.has("content-type")).toBe(false);
  });

  it("accepts a 204 when the schema accepts no body", async () => {
    const { http } = createHttp(() => new Response(null, { status: 204 }));
    await expect(
      http.request({
        method: "DELETE",
        path: "/api/x",
        scope: "s",
        schema: z.void(),
      }),
    ).resolves.toBeUndefined();
  });

  it("flags a 204 when a body was expected", async () => {
    const { http } = createHttp(() => new Response(null, { status: 204 }));
    const err = await rejection(
      http.request({
        method: "DELETE",
        path: "/api/x",
        scope: "s",
        schema: z.object({ removed: z.boolean() }),
      }),
    );
    expect(err.code).toBe("API_002");
  });

  it("retries once with a fresh token after a 401", async () => {
    let calls = 0;
    const { http, invalidate } = createHttp(() =>
      (calls += 1) === 1
        ? json({ error: { code: "AUTH_001", message: "expired" } }, 401)
        : json({ ok: true }),
    );
    await expect(
      http.request({
        method: "GET",
        path: "/api/x",
        scope: "scope-key",
        schema: z.object({ ok: z.boolean() }),
      }),
    ).resolves.toEqual({ ok: true });
    expect(calls).toBe(2);
    expect(invalidate).toHaveBeenCalledWith("scope-key");
  });
});
