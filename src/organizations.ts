import { z } from "zod";
import type { JsonHttp } from "./http.js";
import { parseInput } from "./validation.js";

const USER_PATH = "/api/user";
const ORGANIZATIONS_PATH = `${USER_PATH}/organizations`;
// The user token is minted for the auth-service audience: the key is ignored.
const SCOPE_KEY = "organizations";

const isoDateTime = z.iso.datetime();

export const organizationSchema = z.looseObject({
  id: z.string(),
  name: z.string(),
  slug: z.string(),
  logo: z.string().nullish(),
  role: z.string(),
  team: z.boolean(),
  createdAt: isoDateTime,
});

export const invitationTokenSchema = z.object({
  token: z.string().min(1),
  expiresAt: isoDateTime,
});

const organizationResponseSchema = z.object({
  organization: organizationSchema,
});

const httpsLogoSchema = z
  .string()
  .url()
  .refine((value) => value.startsWith("https://"), {
    message: "must be an https URL",
  });

const createInputSchema = z
  .object({
    name: z.string().trim().min(1).max(100),
    logo: httpsLogoSchema.optional(),
  })
  .strict();

const listOptionsSchema = z
  .object({
    team: z.boolean().optional(),
  })
  .strict();

const joinInputSchema = z
  .object({
    token: z.string().trim().min(1).max(256),
  })
  .strict();

// auth-service derives organization ids (alphanumeric), they are not UUIDs and
// must stay one path segment: `.` and `..` would be normalised by `new URL`.
const identifierSchema = z
  .string()
  .trim()
  .regex(/^[A-Za-z0-9_-]{1,128}$/, { message: "must be an organization id" });

export type Organization = z.infer<typeof organizationSchema>;
export type InvitationToken = z.infer<typeof invitationTokenSchema>;

export interface CreateOrganizationInput {
  /** 1 to 100 characters after trimming. */
  readonly name: string;
  /** Public logo, HTTPS only. */
  readonly logo?: string;
}

export interface ListOrganizationsOptions {
  /** Only teams (`true`), only companies (`false`), or both when omitted. */
  readonly team?: boolean;
}

function identifier(value: string, what: string): string {
  return parseInput(what, identifierSchema, value);
}

function organizationPath(id: string): string {
  return `${ORGANIZATIONS_PATH}/${encodeURIComponent(id)}`;
}

/**
 * The signed-in user's organizations. The token carries the
 * `organizations:self:manage` scope (`teamManagement`); auth-service stays the
 * decision point. Only domain-less teams can be created here: companies with a
 * domain and auto-enrollment are managed from the auth-service admin.
 */
export class OrganizationsClient {
  readonly #http: JsonHttp;

  constructor(http: JsonHttp) {
    this.#http = http;
  }

  /** The organizations the user belongs to, optionally filtered by team flag. */
  async list(options: ListOrganizationsOptions = {}): Promise<Organization[]> {
    const { team } = parseInput("list options", listOptionsSchema, options);
    const query: Record<string, string> = {};
    if (team !== undefined) query["team"] = String(team);
    const { organizations } = await this.#http.request({
      method: "GET",
      path: ORGANIZATIONS_PATH,
      scope: SCOPE_KEY,
      query,
      schema: z.object({ organizations: z.array(organizationSchema) }),
    });
    return organizations;
  }

  /**
   * Creates a team owned by the user. The slug is derived by auth-service, so
   * two teams with the same name never collide and company slugs stay opaque.
   */
  async create(input: CreateOrganizationInput): Promise<Organization> {
    const data = parseInput("organization", createInputSchema, input);
    const body: Record<string, unknown> = { name: data.name };
    if (data.logo !== undefined) body["logo"] = data.logo;
    const { organization } = await this.#http.request({
      method: "POST",
      path: ORGANIZATIONS_PATH,
      scope: SCOPE_KEY,
      body,
      schema: organizationResponseSchema,
    });
    return organization;
  }

  /** Joins a team with its invitation token, as a plain member. */
  async join(token: string): Promise<Organization> {
    const data = parseInput("invitation", joinInputSchema, { token });
    const { organization } = await this.#http.request({
      method: "POST",
      path: `${ORGANIZATIONS_PATH}/join`,
      scope: SCOPE_KEY,
      body: data,
      schema: organizationResponseSchema,
    });
    return organization;
  }

  /**
   * Leaves a team. The last owner cannot leave, and a company is never left
   * this way: it stays an admin decision.
   */
  async leave(organizationId: string): Promise<void> {
    const id = identifier(organizationId, "organization id");
    await this.#http.request({
      method: "POST",
      path: `${organizationPath(id)}/leave`,
      scope: SCOPE_KEY,
      schema: z.void(),
    });
  }

  /**
   * Issues the team's invitation token, valid seven days with unlimited uses
   * until expiry or revocation. A new token revokes the previous one, and the
   * plaintext is returned once: store it only for as long as you display it.
   */
  async createInvitationToken(
    organizationId: string,
  ): Promise<InvitationToken> {
    const id = identifier(organizationId, "organization id");
    return this.#http.request({
      method: "POST",
      path: `${organizationPath(id)}/invitation-token`,
      scope: SCOPE_KEY,
      schema: invitationTokenSchema,
    });
  }

  async revokeInvitationToken(organizationId: string): Promise<void> {
    const id = identifier(organizationId, "organization id");
    await this.#http.request({
      method: "DELETE",
      path: `${organizationPath(id)}/invitation-token`,
      scope: SCOPE_KEY,
      schema: z.void(),
    });
  }
}
