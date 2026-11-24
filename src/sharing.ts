import { z } from "zod";
import type { JsonHttp } from "./http.js";
import type { audienceSchema } from "./sharing-inputs.js";
import {
  accessibleQuerySchema,
  bulkShareInputSchema,
  createInputSchema,
  grantInputSchema,
  grantUpdateInputSchema,
  updateInputSchema,
} from "./sharing-inputs.js";
import {
  accessibleResourceSchema,
  grantSubjectTypeSchema,
  ownerTypeSchema,
  resourcePermissionSchema,
  resourceStatusSchema,
} from "./resource-types.js";
import type {
  AccessibleResource,
  ResourcePermission,
} from "./resource-types.js";
import { parseInput } from "./validation.js";

const USER_PATH = "/api/user";
const RESOURCES_PATH = `${USER_PATH}/resources`;
// The user token is minted for the auth-service audience: the key is ignored.
const SCOPE_KEY = "resources";

const isoDateTime = z.iso.datetime();

export const resourceSchema = z.looseObject({
  id: z.string(),
  applicationId: z.string(),
  applicationSlug: z.string().nullish(),
  applicationName: z.string().nullish(),
  scheme: z.string(),
  schemeDisplayName: z.string().nullish(),
  /** The levels the scheme supports; present on single-resource answers. */
  permissions: z.array(resourcePermissionSchema).optional(),
  locator: z.string().nullish(),
  uri: z.string(),
  displayName: z.string(),
  ownerType: ownerTypeSchema,
  ownerId: z.string(),
  status: resourceStatusSchema,
  listed: z.boolean(),
  metadata: z.record(z.string(), z.unknown()).nullish(),
  validationRequestedAt: isoDateTime.nullish(),
  validatedAt: isoDateTime.nullish(),
  validationError: z.string().nullish(),
  createdAt: isoDateTime,
  updatedAt: isoDateTime,
});

const ownedResourceSchema = resourceSchema.extend({
  grantCount: z.number(),
  grants: z.array(z.looseObject({ id: z.string() })).optional(),
});

export const grantSchema = z.looseObject({
  id: z.string(),
  resourceId: z.string(),
  subjectType: grantSubjectTypeSchema,
  subjectId: z.string().nullable(),
  subjectLabel: z.string().nullish(),
  permission: resourcePermissionSchema,
  expiresAt: isoDateTime.nullable(),
  revokedAt: isoDateTime.nullish(),
  createdBy: z.string(),
  createdAt: isoDateTime,
});

const memberApplicationSchema = z.looseObject({
  id: z.string(),
  name: z.string(),
  slug: z.string(),
  description: z.string().nullish(),
  icon: z.string().nullish(),
  canCreate: z.boolean(),
});

const catalogueApplicationSchema = z.object({
  slug: z.string(),
  name: z.string(),
});

const catalogueSchema = z.object({
  applications: z.array(catalogueApplicationSchema),
  resources: z.array(accessibleResourceSchema),
  enabledSchemes: z.array(z.string()),
});

const validationRequestSchema = z.object({
  resource: resourceSchema,
  validatorUrl: z.string().nullable(),
  validationCommand: z.string().nullable(),
});

const bulkShareResultSchema = z.object({
  results: z.array(
    z.object({
      resourceId: z.string(),
      grantId: z.string().nullable(),
      code: z.string().nullable(),
    }),
  ),
});

const resourceResponseSchema = z.object({ resource: resourceSchema });
const grantResponseSchema = z.object({ grant: grantSchema });

export type Resource = z.infer<typeof resourceSchema>;
export type Grant = z.infer<typeof grantSchema>;
export type MemberApplication = z.infer<typeof memberApplicationSchema>;
export type CatalogueApplication = z.infer<typeof catalogueApplicationSchema>;
export type Catalogue = z.infer<typeof catalogueSchema>;
export type ValidationRequest = z.infer<typeof validationRequestSchema>;
export type BulkShareResult = z.infer<
  typeof bulkShareResultSchema
>["results"][number];
export type ResourceAudience = z.infer<typeof audienceSchema>;

export interface CreateResourceInput {
  /** The application that owns the resource scheme. */
  readonly applicationId: string;
  /** Scheme of the resource, e.g. `llm` or `acme`. */
  readonly scheme: string;
  readonly displayName: string;
  readonly locator?: string;
  /** Free-form owner data, bounded to 4 KiB. */
  readonly metadata?: Readonly<Record<string, unknown>>;
  /** Shares the new resource in the same call. */
  readonly audience?: ResourceAudience;
}

export interface UpdateResourceInput {
  readonly displayName?: string;
  readonly listed?: boolean;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface CreateGrantInput {
  /**
   * `application` shares the resource with another application; its `subjectId`
   * is that application's slug. A scheme an application defines is shared
   * inside that application only.
   */
  readonly subjectType:
    "user" | "organization" | "plan" | "everyone" | "application";
  readonly subjectId?: string | null;
  /** Only a user grant accepts an e-mail, resolved among active members. */
  readonly subjectEmail?: string;
  /** `read` by default; `write` also covers `read`. A scheme may support `read` only. */
  readonly permission?: ResourcePermission;
  /** Timezone-aware, in the future. */
  readonly expiresAt?: Date | null;
}

export interface ShareWithApplicationInput {
  /** The application slug that receives the resources. */
  readonly applicationSlug: string;
  readonly permission?: ResourcePermission;
  readonly expiresAt?: Date | null;
}

export interface UpdateGrantInput {
  readonly permission: ResourcePermission;
}

export interface ListUserAccessibleOptions {
  readonly scheme?: string;
  readonly applicationId?: string;
}

const identifierSchema = z.uuid();

function identifier(value: string, what: string): string {
  return parseInput(what, identifierSchema, value);
}

function resourcePath(id: string): string {
  return `${RESOURCES_PATH}/${encodeURIComponent(id)}`;
}

/**
 * The signed-in user's own resources and shares, with their access token for
 * the auth-service audience and the `resources:self:manage` scope (`resourceSharing`).
 * An application acts only on what that user owns or administers; auth-service
 * stays the decision point.
 */
export class ResourceSharingClient {
  readonly #http: JsonHttp;

  constructor(http: JsonHttp) {
    this.#http = http;
  }

  /** The applications the user belongs to that have resource sharing on. */
  async listMemberApplications(): Promise<MemberApplication[]> {
    const { applications } = await this.#http.request({
      method: "GET",
      path: `${USER_PATH}/resource-applications`,
      scope: SCOPE_KEY,
      schema: z.object({ applications: z.array(memberApplicationSchema) }),
    });
    return applications;
  }

  /** The resources the user owns, with their active grant count. */
  async listOwned(): Promise<Resource[]> {
    const { resources } = await this.#http.request({
      method: "GET",
      path: RESOURCES_PATH,
      scope: SCOPE_KEY,
      schema: z.object({ resources: z.array(ownedResourceSchema) }),
    });
    return resources;
  }

  async getResource(resourceId: string): Promise<Resource> {
    const id = identifier(resourceId, "resource id");
    const { resource } = await this.#http.request({
      method: "GET",
      path: resourcePath(id),
      scope: SCOPE_KEY,
      schema: resourceResponseSchema,
    });
    return resource;
  }

  /**
   * Declares a resource owned by the user. It starts in `pending_validation`;
   * the application that owns the scheme must validate it. `audience` shares it
   * in the same call.
   */
  async create(input: CreateResourceInput): Promise<Resource> {
    const data = parseInput("resource", createInputSchema, input);
    const body: Record<string, unknown> = {
      applicationId: data.applicationId,
      scheme: data.scheme,
      displayName: data.displayName,
    };
    if (data.locator !== undefined) body["locator"] = data.locator;
    if (data.metadata !== undefined) body["metadata"] = data.metadata;
    if (data.audience !== undefined) body["audience"] = data.audience;
    const { resource } = await this.#http.request({
      method: "POST",
      path: RESOURCES_PATH,
      scope: SCOPE_KEY,
      body,
      schema: resourceResponseSchema,
    });
    return resource;
  }

  async update(
    resourceId: string,
    input: UpdateResourceInput,
  ): Promise<Resource> {
    const id = identifier(resourceId, "resource id");
    const data = parseInput("resource update", updateInputSchema, input);
    const body: Record<string, unknown> = {};
    if (data.displayName !== undefined) body["displayName"] = data.displayName;
    if (data.listed !== undefined) body["listed"] = data.listed;
    if (data.metadata !== undefined) body["metadata"] = data.metadata;
    const { resource } = await this.#http.request({
      method: "PATCH",
      path: resourcePath(id),
      scope: SCOPE_KEY,
      body,
      schema: resourceResponseSchema,
    });
    return resource;
  }

  /**
   * Deletes a resource for good, with its grants and invitations. Refused with
   * `RES_019` while the relay still serves the model.
   */
  async delete(resourceId: string): Promise<Resource> {
    const id = identifier(resourceId, "resource id");
    const { resource } = await this.#http.request({
      method: "DELETE",
      path: resourcePath(id),
      scope: SCOPE_KEY,
      schema: resourceResponseSchema,
    });
    return resource;
  }

  /** Asks the scheme's validator to check ownership of a pending resource. */
  async requestValidation(resourceId: string): Promise<ValidationRequest> {
    const id = identifier(resourceId, "resource id");
    return this.#http.request({
      method: "POST",
      path: `${resourcePath(id)}/validation-request`,
      scope: SCOPE_KEY,
      schema: validationRequestSchema,
    });
  }

  async listGrants(resourceId: string): Promise<Grant[]> {
    const id = identifier(resourceId, "resource id");
    const { grants } = await this.#http.request({
      method: "GET",
      path: `${resourcePath(id)}/grants`,
      scope: SCOPE_KEY,
      schema: z.object({ grants: z.array(grantSchema) }),
    });
    return grants;
  }

  /**
   * Shares an existing resource. A `user` subject is named by id or by e-mail,
   * never both; `expiresAt` must be in the future.
   */
  async createGrant(
    resourceId: string,
    input: CreateGrantInput,
  ): Promise<Grant> {
    const id = identifier(resourceId, "resource id");
    const data = parseInput("grant", grantInputSchema, input);
    const body: Record<string, unknown> = { subjectType: data.subjectType };
    if (data.subjectId !== undefined) body["subjectId"] = data.subjectId;
    if (data.subjectEmail !== undefined) {
      body["subjectEmail"] = data.subjectEmail;
    }
    if (data.permission !== undefined) body["permission"] = data.permission;
    if (data.expiresAt !== undefined) {
      body["expiresAt"] = data.expiresAt?.toISOString() ?? null;
    }
    const { grant } = await this.#http.request({
      method: "POST",
      path: `${resourcePath(id)}/grants`,
      scope: SCOPE_KEY,
      body,
      schema: grantResponseSchema,
    });
    return grant;
  }

  /** Revokes an active grant: access ends at once and the row stays as history. */
  async revokeGrant(resourceId: string, grantId: string): Promise<Grant> {
    const id = identifier(resourceId, "resource id");
    const target = identifier(grantId, "grant id");
    const { grant } = await this.#http.request({
      method: "DELETE",
      path: `${resourcePath(id)}/grants/${encodeURIComponent(target)}`,
      scope: SCOPE_KEY,
      schema: grantResponseSchema,
    });
    return grant;
  }

  /**
   * Deletes a grant that is already revoked or expired. An active grant is
   * refused with `RES_020`: revoke it first.
   */
  async deleteGrant(resourceId: string, grantId: string): Promise<void> {
    const id = identifier(resourceId, "resource id");
    const target = identifier(grantId, "grant id");
    await this.#http.request({
      method: "DELETE",
      path: `${resourcePath(id)}/grants/${encodeURIComponent(target)}`,
      scope: SCOPE_KEY,
      query: { permanent: "true" },
      schema: z.undefined(),
    });
  }

  /**
   * Changes the level of an active grant without revoking it. A level the
   * resource's scheme does not support is refused with `RES_014`, and an
   * inactive grant with `RES_015`.
   */
  async updateGrant(
    resourceId: string,
    grantId: string,
    input: UpdateGrantInput,
  ): Promise<Grant> {
    const id = identifier(resourceId, "resource id");
    const target = identifier(grantId, "grant id");
    const body = parseInput("grant update", grantUpdateInputSchema, input);
    const { grant } = await this.#http.request({
      method: "PATCH",
      path: `${resourcePath(id)}/grants/${encodeURIComponent(target)}`,
      scope: SCOPE_KEY,
      body,
      schema: grantResponseSchema,
    });
    return grant;
  }

  /**
   * Shares up to 100 of the user's resources with one application in a single
   * call. Each resource is checked like a single grant: a refusal is reported
   * on its own entry (`code`) and does not stop the others.
   */
  async shareWithApplication(
    resourceIds: readonly string[],
    input: ShareWithApplicationInput,
  ): Promise<BulkShareResult[]> {
    const data = parseInput("resource share", bulkShareInputSchema, {
      resourceIds,
      ...input,
    });
    const { results } = await this.#http.request({
      method: "POST",
      path: `${USER_PATH}/resource-shares`,
      scope: SCOPE_KEY,
      body: {
        resourceIds: data.resourceIds,
        applicationSlug: data.applicationSlug,
        ...(data.permission === undefined
          ? {}
          : { permission: data.permission }),
        ...(data.expiresAt === undefined
          ? {}
          : { expiresAt: data.expiresAt?.toISOString() ?? null }),
      },
      schema: bulkShareResultSchema,
    });
    return results;
  }

  /**
   * The validated resources the user may use through the calling application,
   * each with the `permission` the user holds. A listing filter, not an admission.
   */
  async listAccessible(
    options: ListUserAccessibleOptions = {},
  ): Promise<AccessibleResource[]> {
    const query = parseInput(
      "accessible query",
      accessibleQuerySchema,
      options,
    );
    const { resources } = await this.#http.request({
      method: "GET",
      path: `${USER_PATH}/accessible-resources`,
      scope: SCOPE_KEY,
      query,
      schema: z.object({ resources: z.array(accessibleResourceSchema) }),
    });
    return resources;
  }

  /** The applications and resources offered to the user, with enabled schemes. */
  getCatalogue(): Promise<Catalogue> {
    return this.#http.request({
      method: "GET",
      path: `${USER_PATH}/resource-catalogue`,
      scope: SCOPE_KEY,
      schema: catalogueSchema,
    });
  }
}
