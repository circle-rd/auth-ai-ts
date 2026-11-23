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

const ORGANIZATION_ID = "org_1a2b3c4d5e6f";
const CREATED = "2026-11-23T10:00:00.000Z";

const ORGANIZATION = {
  id: ORGANIZATION_ID,
  name: "Acme Lab",
  slug: "acme-lab-1a2b3c",
  logo: null,
  role: "owner",
  team: true,
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
    auth: createTestAuth(idp, { teamManagement: true }),
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

describe("user.organizations.listOrganizations", () => {
  it("returns the user's organizations", async () => {
    idp.apiHandler = () => jsonResponse({ organizations: [ORGANIZATION] });
    const organizations = await ai
      .forUser("u")
      .organizations.listOrganizations();
    expect(organizations[0]).toMatchObject({
      id: ORGANIZATION_ID,
      team: true,
    });
    const request = lastApiRequest();
    expect(request.method).toBe("GET");
    expect(request.url.pathname).toBe("/api/user/organizations");
    expect(request.url.searchParams.has("team")).toBe(false);
    expect(request.headers.get("authorization")).toBe("Bearer user-token");
    expect(getToken).toHaveBeenCalledWith(ISSUER);
  });

  it.each([
    [true, "true"],
    [false, "false"],
  ])("filters teams with team=%j", async (team, expected) => {
    idp.apiHandler = () => jsonResponse({ organizations: [] });
    await ai.forUser("u").organizations.listOrganizations({ team });
    expect(lastApiRequest().url.searchParams.get("team")).toBe(expected);
  });

  it("rejects an unknown option before any request", async () => {
    const err = await rejection(
      ai
        .forUser("u")
        .organizations.listOrganizations({ type: "team" } as never),
    );
    expect(err.code).toBe("CFG_001");
    expect(idp.requests).toHaveLength(0);
  });
});

describe("user.organizations.create", () => {
  it("creates a team without a slug", async () => {
    idp.apiHandler = () => jsonResponse({ organization: ORGANIZATION }, 201);
    const organization = await ai.forUser("u").organizations.create({
      name: "  Acme Lab  ",
      logo: "https://cdn.example.com/logo.png",
    });
    expect(organization.id).toBe(ORGANIZATION_ID);
    const request = lastApiRequest();
    expect(request.method).toBe("POST");
    expect(request.url.pathname).toBe("/api/user/organizations");
    expect(JSON.parse(request.body ?? "{}")).toEqual({
      name: "Acme Lab",
      logo: "https://cdn.example.com/logo.png",
    });
  });

  it("rejects reserved fields such as a domain or a slug", async () => {
    await expect(
      rejection(
        ai.forUser("u").organizations.create({
          name: "Acme",
          domain: "acme.com",
        } as never),
      ),
    ).resolves.toMatchObject({ code: "CFG_001" });
    await expect(
      rejection(
        ai.forUser("u").organizations.create({
          name: "Acme",
          slug: "acme",
        } as never),
      ),
    ).resolves.toMatchObject({ code: "CFG_001" });
    expect(idp.requests).toHaveLength(0);
  });

  it("rejects a logo that is not https", async () => {
    const err = await rejection(
      ai.forUser("u").organizations.create({
        name: "Acme",
        logo: "http://cdn.example.com/logo.png",
      }),
    );
    expect(err.code).toBe("CFG_001");
  });

  it("surfaces the auth-service error code", async () => {
    idp.apiHandler = () =>
      jsonResponse(
        { error: { code: "ORG_013", message: "team quota reached" } },
        403,
      );
    const err = await rejection(
      ai.forUser("u").organizations.create({ name: "Acme" }),
    );
    expect(err.code).toBe("API_001");
    expect(err.details).toMatchObject({ status: 403, apiCode: "ORG_013" });
  });
});

describe("user.organizations.join", () => {
  it("redeems an invitation token", async () => {
    idp.apiHandler = () => jsonResponse({ organization: ORGANIZATION }, 201);
    const organization = await ai
      .forUser("u")
      .organizations.join("  invite-token  ");
    expect(organization.role).toBe("owner");
    const request = lastApiRequest();
    expect(request.method).toBe("POST");
    expect(request.url.pathname).toBe("/api/user/organizations/join");
    expect(JSON.parse(request.body ?? "{}")).toEqual({
      token: "invite-token",
    });
  });

  it("rejects an empty token before any request", async () => {
    const err = await rejection(ai.forUser("u").organizations.join("   "));
    expect(err.code).toBe("CFG_001");
    expect(idp.requests).toHaveLength(0);
  });
});

describe("user.organizations.leave", () => {
  it("leaves a team", async () => {
    idp.apiHandler = () => new Response(null, { status: 204 });
    await expect(
      ai.forUser("u").organizations.leave(ORGANIZATION_ID),
    ).resolves.toBeUndefined();
    const request = lastApiRequest();
    expect(request.method).toBe("POST");
    expect(request.url.pathname).toBe(
      `/api/user/organizations/${ORGANIZATION_ID}/leave`,
    );
  });

  it.each(["  ", ".", "..", "a/b", "\ud800"])(
    "rejects the id %j before any request",
    async (id) => {
      const err = await rejection(ai.forUser("u").organizations.leave(id));
      expect(err.code).toBe("CFG_001");
      expect(idp.requests).toHaveLength(0);
    },
  );
});

describe("user.organizations.createInvitationToken", () => {
  it("issues a token with its expiry", async () => {
    idp.apiHandler = () =>
      jsonResponse(
        { token: "fresh-token", expiresAt: "2026-11-30T10:00:00.000Z" },
        201,
      );
    const invitation = await ai
      .forUser("u")
      .organizations.createInvitationToken(ORGANIZATION_ID);
    expect(invitation).toEqual({
      token: "fresh-token",
      expiresAt: "2026-11-30T10:00:00.000Z",
    });
    const request = lastApiRequest();
    expect(request.method).toBe("POST");
    expect(request.url.pathname).toBe(
      `/api/user/organizations/${ORGANIZATION_ID}/invitation-token`,
    );
  });

  it("flags an unexpected answer", async () => {
    idp.apiHandler = () => jsonResponse({ token: "" }, 201);
    expect(
      (
        await rejection(
          ai.forUser("u").organizations.createInvitationToken(ORGANIZATION_ID),
        )
      ).code,
    ).toBe("API_002");
  });
});

describe("user.organizations.revokeInvitationToken", () => {
  it("revokes the token", async () => {
    idp.apiHandler = () => new Response(null, { status: 204 });
    await expect(
      ai.forUser("u").organizations.revokeInvitationToken(ORGANIZATION_ID),
    ).resolves.toBeUndefined();
    const request = lastApiRequest();
    expect(request.method).toBe("DELETE");
    expect(request.url.pathname).toBe(
      `/api/user/organizations/${ORGANIZATION_ID}/invitation-token`,
    );
  });
});

describe("organization ids", () => {
  it("accepts the alphanumeric ids auth-service derives", async () => {
    idp.apiHandler = () => new Response(null, { status: 204 });
    await ai.forUser("u").organizations.leave("org_1a2b-3c4d");
    expect(lastApiRequest().url.pathname).toBe(
      "/api/user/organizations/org_1a2b-3c4d/leave",
    );
  });
});
