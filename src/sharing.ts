import { z } from "zod";
import type { JsonHttp } from "./http.js";
import {
  RESOURCE_SCHEME_PATTERN,
  accessibleResourceSchema,
  grantSubjectTypeSchema,
  ownerTypeSchema,
  resourceStatusSchema,
} from "./resource-types.js";
import type { AccessibleResource } from "./resource-types.js";
import { parseInput } from "./validation.js";

const USER_PATH = "/api/user";
const RESOURCES_PATH = `${USER_PATH}/resources`;
// The user token is minted for the auth-service audience: the key is ignored.
const SCOPE_KEY = "resources";
const METADATA_MAX_BYTES = 4096;

const isoDateTime = z.iso.datetime();

function isSmallMetadata(value: Record<string, unknown>): boolean {
  try {
    return JSON.stringify(value).length <= METADATA_MAX_BYTES;
  } catch {
    return false;
  }
}

const metadataSchema = z
  .record(z.string().max(64), z.unknown())
  .refine(isSmallMetadata, { message: "metadata is too large" });

const emailSchema = z.string().trim().pipe(z.email().max(320));

const audienceSchema = z.union([
  z.object({ type: z.literal("everyone") }).strict(),
  z.object({ type: z.literal("plan"), planId: z.uuid() }).strict(),
  z
    .object({
      type: z.literal("organization"),
      organizationId: z.string().trim().min(1).max(128),
    })
    .strict(),
  z
    .object({
      type: z.literal("user"),
      userId: z.string().trim().min(1).max(128),
    })
    .strict(),
  z.object({ type: z.literal("user"), email: emailSchema }).strict(),
]);

const createInputSchema = z
  .object({
    applicationId: z.uuid(),
    scheme: z.string().regex(RESOURCE_SCHEME_PATTERN),
    locator: z.string().trim().min(1).max(255).optional(),
    displayName: z.string().trim().min(1).max(200),
    metadata: metadataSchema.optional(),
    audience: audienceSchema.optional(),
  })
  .strict();

const updateInputSchema = z
  .object({
    displayName: z.string().trim().min(1).max(200).optional(),
    listed: z.boolean().optional(),
    metadata: metadataSchema.optional(),
  })
  .strict()
  .refine(
    (value) =>
      value.displayName !== undefined ||
      value.listed !== undefined ||
      value.metadata !== undefined,
    { message: "at least one field is required" },
  );

const grantInputSchema = z
  .object({
    subjectType: grantSubjectTypeSchema,
    subjectId: z.string().trim().min(1).max(256).nullable().optional(),
    subjectEmail: emailSchema.optional(),
    expiresAt: z.date().nullable().optional(),
  })
  .strict()
  .superRefine((value, ctx) => {
    if (
      value.expiresAt !== undefined &&
      value.expiresAt !== null &&
      value.expiresAt.getTime() <= Date.now()
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["expiresAt"],
        message: "must be in the future",
      });
    }
    if (value.subjectType === "everyone") {
      if (value.subjectId !== undefined && value.subjectId !== null) {
        ctx.addIssue({
          code: "custom",
          path: ["subjectId"],
          message: "everyone has no subject id",
        });
      }
      if (value.subjectEmail !== undefined) {
        ctx.addIssue({
          code: "custom",
          path: ["subjectEmail"],
          message: "everyone has no e-mail",
        });
      }
      return;
    }
    if (value.subjectType === "user" && value.subjectEmail !== undefined) {
      if (value.subjectId !== undefined && value.subjectId !== null) {
        ctx.addIssue({
          code: "custom",
          path: ["subjectId"],
          message: "give either a subject id or a subject e-mail",
        });
      }
      return;
    }
    if (value.subjectEmail !== undefined) {
      ctx.addIssue({
        code: "custom",
        path: ["subjectEmail"],
        message: "only a user grant accepts a subject e-mail",
      });
    }
    if (!value.subjectId) {
      ctx.addIssue({
        code: "custom",
        path: ["subjectId"],
        message: "a subject id is required",
      });
    }
  });

const accessibleQuerySchema = z
  .object({
    scheme: z.string().regex(RESOURCE_SCHEME_PATTERN).optional(),
    applicationId: z.uuid().optional(),
  })
  .strict();

export const resourceSchema = z.looseObject({
  id: z.string(),
  applicationId: z.string(),
  applicationSlug: z.string().nullish(),
  applicationName: z.string().nullish(),
  scheme: z.string(),
  schemeDisplayName: z.string().nullish(),
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
  permission: z.string(),
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

const deletedResourceSchema = z.object({
  resource: resourceSchema,
  removed: z.boolean(),
});

const resourceResponseSchema = z.object({ resource: resourceSchema });
const grantResponseSchema = z.object({ grant: grantSchema });

export type Resource = z.infer<typeof resourceSchema>;
export type Grant = z.infer<typeof grantSchema>;
export type MemberApplication = z.infer<typeof memberApplicationSchema>;
export type CatalogueApplication = z.infer<typeof catalogueApplicationSchema>;
export type Catalogue = z.infer<typeof catalogueSchema>;
export type ValidationRequest = z.infer<typeof validationRequestSchema>;
export type DeletedResource = z.infer<typeof deletedResourceSchema>;
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
  readonly subjectType: "user" | "organization" | "plan" | "everyone";
  readonly subjectId?: string | null;
  /** Only a user grant accepts an e-mail, resolved among active members. */
  readonly subjectEmail?: string;
  /** Timezone-aware, in the future. */
  readonly expiresAt?: Date | null;
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

  async get(resourceId: string): Promise<Resource> {
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

  async delete(resourceId: string): Promise<DeletedResource> {
    const id = identifier(resourceId, "resource id");
    return this.#http.request({
      method: "DELETE",
      path: resourcePath(id),
      scope: SCOPE_KEY,
      schema: deletedResourceSchema,
    });
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

  /** Every validated resource the user may use; a listing filter, not an admission. */
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
