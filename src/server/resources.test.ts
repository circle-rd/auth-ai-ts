import { beforeEach, describe, expect, it } from "vitest";
import { AuthAiError } from "../errors.js";
import {
  createMockIdp,
  createTestAuth,
  jsonResponse,
} from "../test-support/mock-idp.js";
import type { MockIdp, RecordedRequest } from "../test-support/mock-idp.js";
import { createMachineApi } from "./machine-api.js";
import type { MachineApi } from "./machine-api.js";

const RESOURCE_ID = "4b1f6f3e-5a6c-4d0e-9c53-0a4c6f0f7a11";

let idp: MockIdp;
let api: MachineApi;

beforeEach(async () => {
  idp = await createMockIdp();
  idp.tokenHandler = () =>
    jsonResponse({
      access_token: "machine-1",
      token_type: "Bearer",
      expires_in: 3600,
    });
  idp.apiHandler = () => jsonResponse({});
  api = createMachineApi(createTestAuth(idp));
});

function lastApiRequest(): RecordedRequest {
  const request = idp.requests
    .filter((r) => r.url.pathname.startsWith("/api/"))
    .at(-1);
  if (!request) throw new Error("no API request was made");
  return request;
}

async function rejection(promise: Promise<unknown>): Promise<AuthAiError> {
  const err = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(AuthAiError);
  return err as AuthAiError;
}

const AUTHORIZE = {
  subjectId: "user-1",
  clientId: "acme-app",
  resourceUri: "llm://acme/gpt-x",
  audience: "https://llm.test",
} as const;

describe("resources.authorize", () => {
  it("returns the admission with the decision data", async () => {
    idp.apiHandler = () =>
      jsonResponse({
        decision: "allow",
        resourceId: RESOURCE_ID,
        resourceUri: "llm://acme/gpt-x",
        applicationSlug: "acme",
        ownerType: "application",
        ownerId: "app-1",
        accessKind: "grant",
      });
    const decision = await api.resources.authorize({
      ...AUTHORIZE,
      requestId: "req-1",
      source: "api",
    });
    expect(decision).toEqual({
      decision: "allow",
      resourceId: RESOURCE_ID,
      resourceUri: "llm://acme/gpt-x",
      applicationSlug: "acme",
      ownerType: "application",
      ownerId: "app-1",
      accessKind: "grant",
    });
    const request = lastApiRequest();
    expect(request.method).toBe("POST");
    expect(request.url.pathname).toBe("/api/internal/gateway/authorize");
    expect(JSON.parse(request.body ?? "")).toEqual({
      ...AUTHORIZE,
      requestId: "req-1",
      source: "api",
    });
    expect(idp.requestsTo("/token")[0]?.form.get("scope")).toBe(
      "resources:authorize",
    );
  });

  it("returns a denial without any reason", async () => {
    idp.apiHandler = () =>
      jsonResponse({ decision: "deny", reason: "no_grant" });
    expect(await api.resources.authorize(AUTHORIZE)).toEqual({
      decision: "deny",
    });
  });

  it("never reads an unknown decision as an admission", async () => {
    idp.apiHandler = () => jsonResponse({ decision: "maybe" });
    expect((await rejection(api.resources.authorize(AUTHORIZE))).code).toBe(
      "API_002",
    );
  });

  it("refuses an admission that lacks its data", async () => {
    idp.apiHandler = () => jsonResponse({ decision: "allow" });
    expect((await rejection(api.resources.authorize(AUTHORIZE))).code).toBe(
      "API_002",
    );
  });

  it("flags an answer that is not JSON", async () => {
    idp.apiHandler = () => new Response("<html>", { status: 200 });
    expect((await rejection(api.resources.authorize(AUTHORIZE))).code).toBe(
      "API_002",
    );
  });

  it.each([
    ["an empty subject", { subjectId: "" }],
    ["an empty client", { clientId: "" }],
    ["a too short URI", { resourceUri: "a:" }],
    ["a URI over 512 characters", { resourceUri: `llm://${"a".repeat(510)}` }],
    ["an empty audience", { audience: "" }],
    ["an unknown source", { source: "browser" }],
  ])("rejects %s before any request", async (_label, override) => {
    const err = await rejection(
      api.resources.authorize({ ...AUTHORIZE, ...override } as never),
    );
    expect(err.code).toBe("CFG_001");
    expect(idp.requests).toHaveLength(0);
  });

  it("rejects a field auth-service does not know", async () => {
    const err = await rejection(
      api.resources.authorize({ ...AUTHORIZE, userId: "other" } as never),
    );
    expect(err.code).toBe("CFG_001");
    expect(idp.requests).toHaveLength(0);
  });

  it("surfaces a missing scope as an API error", async () => {
    idp.apiHandler = () =>
      jsonResponse(
        {
          error: {
            code: "AUTH_011",
            message: "Client is not authorized for scope: resources:authorize",
          },
        },
        403,
      );
    const err = await rejection(api.resources.authorize(AUTHORIZE));
    expect(err.code).toBe("API_001");
    expect(err.details).toEqual({ status: 403, apiCode: "AUTH_011" });
  });
});

describe("resources.listAccessible", () => {
  const ITEM = {
    resourceId: RESOURCE_ID,
    resourceUri: "llm://acme/gpt-x",
    scheme: "llm",
    displayName: "gpt-x",
    applicationId: "app-1",
    applicationSlug: "acme",
    applicationName: "Acme",
    ownerType: "application",
    ownerId: "app-1",
    accessKind: "grant",
    grantSubjectType: "plan",
  };

  it("lists what a user may use, optionally by scheme", async () => {
    idp.apiHandler = () => jsonResponse({ resources: [ITEM] });
    expect(await api.resources.listAccessible("user/1")).toEqual([ITEM]);
    const first = lastApiRequest();
    expect(first.url.pathname).toBe(
      "/api/internal/gateway/resources/accessible",
    );
    expect(first.url.searchParams.get("subjectId")).toBe("user/1");
    expect(first.url.searchParams.has("scheme")).toBe(false);

    await api.resources.listAccessible("user-1", { scheme: "llm" });
    expect(lastApiRequest().url.searchParams.get("scheme")).toBe("llm");
    expect(idp.requestsTo("/token")[0]?.form.get("scope")).toBe(
      "resources:authorize",
    );
  });

  it("accepts an owned resource, which has no grant subject", async () => {
    const { grantSubjectType: _omit, ...owned } = ITEM;
    idp.apiHandler = () =>
      jsonResponse({ resources: [{ ...owned, accessKind: "owner" }] });
    const [resource] = await api.resources.listAccessible("user-1");
    expect(resource?.accessKind).toBe("owner");
    expect(resource?.grantSubjectType).toBeUndefined();
  });

  it("flags an unknown access kind", async () => {
    idp.apiHandler = () =>
      jsonResponse({ resources: [{ ...ITEM, accessKind: "admin" }] });
    expect((await rejection(api.resources.listAccessible("user-1"))).code).toBe(
      "API_002",
    );
  });

  it.each([
    ["an empty subject", "", undefined],
    ["a scheme in upper case", "user-1", "LLM"],
    ["a scheme with a separator", "user-1", "llm://"],
  ])("rejects %s before any request", async (_label, subject, scheme) => {
    const err = await rejection(
      api.resources.listAccessible(subject, scheme ? { scheme } : {}),
    );
    expect(err.code).toBe("CFG_001");
    expect(idp.requests).toHaveLength(0);
  });
});

describe("resources.validate", () => {
  const STATE = {
    id: RESOURCE_ID,
    uri: "acme://project-1",
    status: "validated",
    validationError: null,
  };

  it("reports the outcome of the ownership check", async () => {
    idp.apiHandler = () => jsonResponse({ resource: STATE });
    const state = await api.resources.validate(RESOURCE_ID, {
      result: "validated",
      evidence: { checkedBy: "acme-backend" },
    });
    expect(state).toEqual(STATE);
    const request = lastApiRequest();
    expect(request.method).toBe("POST");
    expect(request.url.pathname).toBe(
      `/api/internal/gateway/resources/${RESOURCE_ID}/validate`,
    );
    expect(JSON.parse(request.body ?? "")).toEqual({
      result: "validated",
      evidence: { checkedBy: "acme-backend" },
    });
    expect(idp.requestsTo("/token")[0]?.form.get("scope")).toBe(
      "resources:validate",
    );
  });

  it("reports a failure with its trimmed reason", async () => {
    idp.apiHandler = () =>
      jsonResponse({
        resource: {
          ...STATE,
          status: "validation_failed",
          validationError: "not yours",
        },
      });
    const state = await api.resources.validate(RESOURCE_ID, {
      result: "validation_failed",
      reason: "  not yours  ",
    });
    expect(state.status).toBe("validation_failed");
    expect(JSON.parse(lastApiRequest().body ?? "")).toEqual({
      result: "validation_failed",
      reason: "not yours",
    });
  });

  it.each([
    ["an id that is not a UUID", "../../admin", { result: "validated" }],
    ["an unknown result", RESOURCE_ID, { result: "approved" }],
    [
      "a reason over 500 characters",
      RESOURCE_ID,
      { result: "validation_failed", reason: "x".repeat(501) },
    ],
  ])("rejects %s before any request", async (_label, id, outcome) => {
    const err = await rejection(api.resources.validate(id, outcome as never));
    expect(err.code).toBe("CFG_001");
    expect(idp.requests).toHaveLength(0);
  });

  it("surfaces a refusal from a client that is not the validator", async () => {
    idp.apiHandler = () =>
      jsonResponse(
        {
          error: {
            code: "AUTH_011",
            message: "Client is not the validator for this resource scheme",
          },
        },
        403,
      );
    const err = await rejection(
      api.resources.validate(RESOURCE_ID, { result: "validated" }),
    );
    expect(err.details).toEqual({ status: 403, apiCode: "AUTH_011" });
  });
});

describe("resources.invalidate", () => {
  it("disables a resource whose ownership was lost", async () => {
    idp.apiHandler = () =>
      jsonResponse({
        resource: {
          id: RESOURCE_ID,
          uri: "acme://project-1",
          status: "disabled",
          validationError: "project-deleted",
        },
      });
    const state = await api.resources.invalidate(
      RESOURCE_ID,
      " project-deleted ",
    );
    expect(state.status).toBe("disabled");
    const request = lastApiRequest();
    expect(request.url.pathname).toBe(
      `/api/internal/gateway/resources/${RESOURCE_ID}/invalidate`,
    );
    expect(JSON.parse(request.body ?? "")).toEqual({
      reason: "project-deleted",
    });
    expect(idp.requestsTo("/token")[0]?.form.get("scope")).toBe(
      "resources:validate",
    );
  });

  it.each([
    ["a blank reason", RESOURCE_ID, "   "],
    ["a reason over 500 characters", RESOURCE_ID, "x".repeat(501)],
    ["an id that is not a UUID", "1/../2", "gone"],
  ])("rejects %s before any request", async (_label, id, reason) => {
    const err = await rejection(api.resources.invalidate(id, reason));
    expect(err.code).toBe("CFG_001");
    expect(idp.requests).toHaveLength(0);
  });
});
