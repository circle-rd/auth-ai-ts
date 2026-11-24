import { beforeEach, describe, expect, it, vi } from "vitest";
import { createAiClient } from "./ai.js";
import type { AiClient } from "./ai.js";
import type { AuthAiError } from "./errors.js";
import {
  ISSUER,
  createMockIdp,
  createTestAuth,
  jsonResponse,
} from "./test-support/mock-idp.js";
import type { MockIdp, RecordedRequest } from "./test-support/mock-idp.js";

const RESOURCE_ID = "4b1f6f3e-5a6c-4d0e-9c53-0a4c6f0f7a11";
const GRANT_ID = "9d2a0c4e-6b7f-4a1d-8e2c-3f5b6a7c8d90";
const APPLICATION_ID = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
const CREATED = "2026-11-18T10:00:00.000Z";

const RESOURCE = {
  id: RESOURCE_ID,
  applicationId: APPLICATION_ID,
  applicationSlug: "acme",
  applicationName: "Acme",
  scheme: "acme",
  schemeDisplayName: "Acme",
  locator: "project-1",
  uri: "acme://project-1",
  displayName: "Project 1",
  ownerType: "user",
  ownerId: "user-1",
  status: "pending_validation",
  listed: true,
  metadata: null,
  validationRequestedAt: null,
  validatedAt: null,
  validationError: null,
  createdAt: CREATED,
  updatedAt: CREATED,
} as const;

const GRANT = {
  id: GRANT_ID,
  resourceId: RESOURCE_ID,
  subjectType: "user",
  subjectId: "user-2",
  subjectLabel: "Bob",
  permission: "read",
  expiresAt: null,
  revokedAt: null,
  createdBy: "user-1",
  createdAt: CREATED,
} as const;

let idp: MockIdp;
let ai: AiClient;
let getToken: ReturnType<typeof vi.fn<(resource?: string) => Promise<string>>>;

beforeEach(async () => {
  idp = await createMockIdp();
  idp.apiHandler = () => jsonResponse({});
  getToken = vi.fn(async () => "user-token");
  ai = createAiClient({
    auth: createTestAuth(idp, { resourceSharing: true }),
    grants: {
      getAccessToken: async (_grantId, options) => ({
        accessToken: await getToken(options?.resource),
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      }),
      invalidate: vi.fn(),
    },
  });
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
  expect(err).toBeDefined();
  return err as AuthAiError;
}

describe("user.resources.listOwned", () => {
  it("returns the user's resources with their grant count", async () => {
    idp.apiHandler = () =>
      jsonResponse({ resources: [{ ...RESOURCE, grantCount: 2 }] });
    const resources = await ai.forUser("user-sub").resources.listOwned();
    expect(resources[0]?.id).toBe(RESOURCE_ID);
    const request = lastApiRequest();
    expect(request.method).toBe("GET");
    expect(request.url.pathname).toBe("/api/user/resources");
    expect(request.headers.get("authorization")).toBe("Bearer user-token");
    expect(getToken).toHaveBeenCalledWith(ISSUER);
  });

  it("flags an unexpected answer", async () => {
    idp.apiHandler = () => jsonResponse({ resources: [{ id: "x" }] });
    expect((await rejection(ai.forUser("u").resources.listOwned())).code).toBe(
      "API_002",
    );
  });
});

describe("user.resources.getResource", () => {
  it("fetches one resource", async () => {
    idp.apiHandler = () => jsonResponse({ resource: RESOURCE });
    expect(
      await ai.forUser("u").resources.getResource(RESOURCE_ID),
    ).toMatchObject({
      id: RESOURCE_ID,
      uri: "acme://project-1",
    });
    expect(lastApiRequest().url.pathname).toBe(
      `/api/user/resources/${RESOURCE_ID}`,
    );
  });

  it("rejects an id that is not a UUID before any request", async () => {
    expect(
      (await rejection(ai.forUser("u").resources.getResource("../admin"))).code,
    ).toBe("CFG_001");
    expect(idp.requests).toHaveLength(0);
  });
});

describe("user.resources.create", () => {
  it("declares a resource and sends an audience in the same call", async () => {
    idp.apiHandler = () => jsonResponse({ resource: RESOURCE }, 201);
    const resource = await ai.forUser("u").resources.create({
      applicationId: APPLICATION_ID,
      scheme: "acme",
      locator: "  project-1  ",
      displayName: "  Project 1  ",
      metadata: { region: "eu" },
      audience: { type: "everyone" },
    });
    expect(resource.id).toBe(RESOURCE_ID);
    const request = lastApiRequest();
    expect(request.method).toBe("POST");
    expect(request.url.pathname).toBe("/api/user/resources");
    expect(JSON.parse(request.body ?? "")).toEqual({
      applicationId: APPLICATION_ID,
      scheme: "acme",
      locator: "project-1",
      displayName: "Project 1",
      metadata: { region: "eu" },
      audience: { type: "everyone" },
    });
  });

  it("omits the optional fields when they are absent", async () => {
    idp.apiHandler = () => jsonResponse({ resource: RESOURCE }, 201);
    await ai.forUser("u").resources.create({
      applicationId: APPLICATION_ID,
      scheme: "acme",
      displayName: "Project 1",
    });
    expect(JSON.parse(lastApiRequest().body ?? "")).toEqual({
      applicationId: APPLICATION_ID,
      scheme: "acme",
      displayName: "Project 1",
    });
  });

  it.each([
    ["an application id that is not a UUID", { applicationId: "acme" }],
    ["an upper-case scheme", { scheme: "ACME" }],
    ["an empty display name", { displayName: "   " }],
    ["a locator over 255 characters", { locator: "x".repeat(256) }],
    ["metadata with an oversized key", { metadata: { ["k".repeat(65)]: 1 } }],
    ["metadata over 4 KiB", { metadata: { blob: "x".repeat(4097) } }],
    [
      "a user audience with both id and e-mail",
      { audience: { type: "user", userId: "u", email: "a@b.test" } },
    ],
    ["an unknown field", { ownerId: "someone" }],
  ])("rejects %s before any request", async (_label, override) => {
    const err = await rejection(
      ai.forUser("u").resources.create({
        applicationId: APPLICATION_ID,
        scheme: "acme",
        displayName: "Project 1",
        ...override,
      } as never),
    );
    expect(err.code).toBe("CFG_001");
    expect(idp.requests).toHaveLength(0);
  });
});

describe("user.resources.update", () => {
  it("patches only the provided fields", async () => {
    idp.apiHandler = () => jsonResponse({ resource: RESOURCE });
    await ai.forUser("u").resources.update(RESOURCE_ID, {
      displayName: " Renamed ",
      listed: false,
    });
    const request = lastApiRequest();
    expect(request.method).toBe("PATCH");
    expect(JSON.parse(request.body ?? "")).toEqual({
      displayName: "Renamed",
      listed: false,
    });
  });

  it("rejects an empty update before any request", async () => {
    expect(
      (await rejection(ai.forUser("u").resources.update(RESOURCE_ID, {}))).code,
    ).toBe("CFG_001");
    expect(idp.requests).toHaveLength(0);
  });
});

describe("user.resources.delete", () => {
  it("deletes the resource and returns it", async () => {
    idp.apiHandler = () => jsonResponse({ resource: RESOURCE });
    const deleted = await ai.forUser("u").resources.delete(RESOURCE_ID);
    expect(deleted.id).toBe(RESOURCE_ID);
    const sent = lastApiRequest();
    expect(sent.method).toBe("DELETE");
    expect(sent.url.pathname).toBe(`/api/user/resources/${RESOURCE_ID}`);
  });

  it("surfaces the refusal while the relay still serves the model", async () => {
    idp.apiHandler = () =>
      jsonResponse({ error: { code: "RES_019", message: "served" } }, 409);
    const err = await rejection(ai.forUser("u").resources.delete(RESOURCE_ID));
    expect(err.details).toEqual({ status: 409, apiCode: "RES_019" });
  });
});

describe("user.resources.requestValidation", () => {
  it("asks the scheme's validator to check ownership", async () => {
    idp.apiHandler = () =>
      jsonResponse({
        resource: RESOURCE,
        validatorUrl: "https://acme.test/validate",
        validationCommand: null,
      });
    const request = await ai
      .forUser("u")
      .resources.requestValidation(RESOURCE_ID);
    expect(request.validatorUrl).toBe("https://acme.test/validate");
    const sent = lastApiRequest();
    expect(sent.method).toBe("POST");
    expect(sent.url.pathname).toBe(
      `/api/user/resources/${RESOURCE_ID}/validation-request`,
    );
  });
});

describe("user.resources grants", () => {
  it("lists the grants of a resource", async () => {
    idp.apiHandler = () => jsonResponse({ grants: [GRANT] });
    expect(await ai.forUser("u").resources.listGrants(RESOURCE_ID)).toEqual([
      GRANT,
    ]);
    expect(lastApiRequest().url.pathname).toBe(
      `/api/user/resources/${RESOURCE_ID}/grants`,
    );
  });

  it("shares a resource with a user named by e-mail", async () => {
    const expiresAt = new Date(Date.now() + 86_400_000);
    idp.apiHandler = () => jsonResponse({ grant: GRANT }, 201);
    await ai.forUser("u").resources.createGrant(RESOURCE_ID, {
      subjectType: "user",
      subjectEmail: "  bob@example.com ",
      expiresAt,
    });
    const sent = lastApiRequest();
    expect(sent.method).toBe("POST");
    expect(sent.url.pathname).toBe(`/api/user/resources/${RESOURCE_ID}/grants`);
    expect(JSON.parse(sent.body ?? "")).toEqual({
      subjectType: "user",
      subjectEmail: "bob@example.com",
      expiresAt: expiresAt.toISOString(),
    });
  });

  it("shares with everyone without a subject", async () => {
    idp.apiHandler = () => jsonResponse({ grant: GRANT }, 201);
    await ai.forUser("u").resources.createGrant(RESOURCE_ID, {
      subjectType: "everyone",
    });
    expect(JSON.parse(lastApiRequest().body ?? "")).toEqual({
      subjectType: "everyone",
    });
  });

  it("sends the permission only when it is given", async () => {
    idp.apiHandler = () =>
      jsonResponse({ grant: { ...GRANT, permission: "write" } }, 201);
    const grant = await ai.forUser("u").resources.createGrant(RESOURCE_ID, {
      subjectType: "user",
      subjectId: "user-2",
      permission: "write",
    });
    expect(grant.permission).toBe("write");
    expect(JSON.parse(lastApiRequest().body ?? "")).toEqual({
      subjectType: "user",
      subjectId: "user-2",
      permission: "write",
    });
  });

  it("shares with an application named by its slug", async () => {
    idp.apiHandler = () =>
      jsonResponse({ grant: { ...GRANT, subjectType: "application" } }, 201);
    await ai.forUser("u").resources.createGrant(RESOURCE_ID, {
      subjectType: "application",
      subjectId: "chat",
    });
    expect(JSON.parse(lastApiRequest().body ?? "")).toEqual({
      subjectType: "application",
      subjectId: "chat",
    });
  });

  it.each([
    [
      "both an id and an e-mail",
      { subjectType: "user", subjectId: "u", subjectEmail: "a@b.test" },
    ],
    ["everyone with an id", { subjectType: "everyone", subjectId: "u" }],
    [
      "an organisation with an e-mail",
      { subjectType: "organization", subjectEmail: "a@b.test" },
    ],
    ["a missing subject", { subjectType: "organization" }],
    ["an application without a slug", { subjectType: "application" }],
    [
      "a permission outside the closed set",
      { subjectType: "user", subjectId: "u", permission: "admin" },
    ],
    [
      "the legacy use permission",
      { subjectType: "user", subjectId: "u", permission: "use" },
    ],
    [
      "an expired grant",
      { subjectType: "user", subjectId: "u", expiresAt: new Date(0) },
    ],
    [
      "an expired everyone grant",
      { subjectType: "everyone", expiresAt: new Date(0) },
    ],
    [
      "an expired e-mail grant",
      { subjectType: "user", subjectEmail: "a@b.test", expiresAt: new Date(0) },
    ],
    ["an unknown subject type", { subjectType: "team", subjectId: "u" }],
  ])("rejects %s before any request", async (_label, input) => {
    expect(
      (
        await rejection(
          ai.forUser("u").resources.createGrant(RESOURCE_ID, input as never),
        )
      ).code,
    ).toBe("CFG_001");
    expect(idp.requests).toHaveLength(0);
  });

  it("revokes a grant", async () => {
    idp.apiHandler = () =>
      jsonResponse({ grant: { ...GRANT, revokedAt: CREATED } });
    const grant = await ai
      .forUser("u")
      .resources.revokeGrant(RESOURCE_ID, GRANT_ID);
    expect(grant.revokedAt).toBe(CREATED);
    const sent = lastApiRequest();
    expect(sent.method).toBe("DELETE");
    expect(sent.url.pathname).toBe(
      `/api/user/resources/${RESOURCE_ID}/grants/${GRANT_ID}`,
    );
    expect(sent.url.searchParams.has("permanent")).toBe(false);
  });

  it("deletes a past grant for good", async () => {
    idp.apiHandler = () => new Response(null, { status: 204 });
    await ai.forUser("u").resources.deleteGrant(RESOURCE_ID, GRANT_ID);
    const sent = lastApiRequest();
    expect(sent.method).toBe("DELETE");
    expect(sent.url.pathname).toBe(
      `/api/user/resources/${RESOURCE_ID}/grants/${GRANT_ID}`,
    );
    expect(sent.url.searchParams.get("permanent")).toBe("true");
  });

  it("surfaces the refusal to delete an active grant", async () => {
    idp.apiHandler = () =>
      jsonResponse({ error: { code: "RES_020", message: "active" } }, 409);
    const err = await rejection(
      ai.forUser("u").resources.deleteGrant(RESOURCE_ID, GRANT_ID),
    );
    expect(err.details).toEqual({ status: 409, apiCode: "RES_020" });
  });

  it("changes the level of a grant without revoking it", async () => {
    idp.apiHandler = () =>
      jsonResponse({ grant: { ...GRANT, permission: "write" } });
    const grant = await ai
      .forUser("u")
      .resources.updateGrant(RESOURCE_ID, GRANT_ID, { permission: "write" });
    expect(grant.permission).toBe("write");
    const sent = lastApiRequest();
    expect(sent.method).toBe("PATCH");
    expect(sent.url.pathname).toBe(
      `/api/user/resources/${RESOURCE_ID}/grants/${GRANT_ID}`,
    );
    expect(JSON.parse(sent.body ?? "")).toEqual({ permission: "write" });
  });

  it.each([
    ["an unknown level", { permission: "admin" }],
    ["no level", {}],
    ["an extra field", { permission: "read", expiresAt: null }],
  ])("rejects a grant update with %s", async (_label, input) => {
    expect(
      (
        await rejection(
          ai
            .forUser("u")
            .resources.updateGrant(RESOURCE_ID, GRANT_ID, input as never),
        )
      ).code,
    ).toBe("CFG_001");
    expect(idp.requests).toHaveLength(0);
  });
});

describe("user.resources.shareWithApplication", () => {
  it("shares several resources and reports each outcome", async () => {
    const results = [
      { resourceId: RESOURCE_ID, grantId: GRANT_ID, code: null },
      { resourceId: APPLICATION_ID, grantId: null, code: "RES_014" },
    ];
    idp.apiHandler = () => jsonResponse({ results });
    const expiresAt = new Date(Date.now() + 86_400_000);
    expect(
      await ai
        .forUser("u")
        .resources.shareWithApplication([RESOURCE_ID, APPLICATION_ID], {
          applicationSlug: "chat",
          permission: "write",
          expiresAt,
        }),
    ).toEqual(results);
    const sent = lastApiRequest();
    expect(sent.method).toBe("POST");
    expect(sent.url.pathname).toBe("/api/user/resource-shares");
    expect(JSON.parse(sent.body ?? "")).toEqual({
      resourceIds: [RESOURCE_ID, APPLICATION_ID],
      applicationSlug: "chat",
      permission: "write",
      expiresAt: expiresAt.toISOString(),
    });
  });

  it.each([
    ["no resource", [], { applicationSlug: "chat" }],
    [
      "more than 100 resources",
      Array.from({ length: 101 }, () => RESOURCE_ID),
      { applicationSlug: "chat" },
    ],
    ["an id that is not a UUID", ["nope"], { applicationSlug: "chat" }],
    ["an empty slug", [RESOURCE_ID], { applicationSlug: " " }],
    [
      "an unknown level",
      [RESOURCE_ID],
      { applicationSlug: "chat", permission: "admin" },
    ],
    [
      "an expired share",
      [RESOURCE_ID],
      { applicationSlug: "chat", expiresAt: new Date(0) },
    ],
  ])("rejects %s before any request", async (_label, ids, input) => {
    expect(
      (
        await rejection(
          ai.forUser("u").resources.shareWithApplication(ids, input as never),
        )
      ).code,
    ).toBe("CFG_001");
    expect(idp.requests).toHaveLength(0);
  });
});

describe("user.resources.listAccessible", () => {
  const ITEM = {
    resourceId: RESOURCE_ID,
    resourceUri: "llm://acme/gpt-x",
    scheme: "llm",
    displayName: "gpt-x",
    applicationId: APPLICATION_ID,
    applicationSlug: "acme",
    applicationName: "Acme",
    ownerType: "application",
    ownerId: APPLICATION_ID,
    accessKind: "grant",
    permission: "write",
    grantSubjectType: "plan",
  };

  it("filters by scheme and application", async () => {
    idp.apiHandler = () => jsonResponse({ resources: [ITEM] });
    expect(
      await ai.forUser("u").resources.listAccessible({
        scheme: "llm",
        applicationId: APPLICATION_ID,
      }),
    ).toEqual([ITEM]);
    const sent = lastApiRequest();
    expect(sent.url.pathname).toBe("/api/user/accessible-resources");
    expect(sent.url.searchParams.get("scheme")).toBe("llm");
    expect(sent.url.searchParams.get("applicationId")).toBe(APPLICATION_ID);
  });

  it.each([
    ["an upper-case scheme", { scheme: "LLM" }],
    ["a non-UUID application", { applicationId: "acme" }],
    ["an unknown field", { ownerId: "u" }],
  ])("rejects %s before any request", async (_label, options) => {
    expect(
      (
        await rejection(
          ai.forUser("u").resources.listAccessible(options as never),
        )
      ).code,
    ).toBe("CFG_001");
    expect(idp.requests).toHaveLength(0);
  });
});

describe("user.resources.getCatalogue", () => {
  it("returns the applications, resources and enabled schemes", async () => {
    idp.apiHandler = () =>
      jsonResponse({
        applications: [{ slug: "acme", name: "Acme" }],
        resources: [],
        enabledSchemes: ["llm", "acme"],
      });
    expect(await ai.forUser("u").resources.getCatalogue()).toEqual({
      applications: [{ slug: "acme", name: "Acme" }],
      resources: [],
      enabledSchemes: ["llm", "acme"],
    });
    expect(lastApiRequest().url.pathname).toBe("/api/user/resource-catalogue");
  });
});
