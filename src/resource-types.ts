import { z } from "zod";

/** Grammar of a resource scheme, shared by both resource-sharing clients. */
export const RESOURCE_SCHEME_PATTERN = /^[a-z][a-z0-9]{0,49}$/;

/** Wire shapes auth-service uses for resource sharing, shared by both clients. */
export const ownerTypeSchema = z.enum(["user", "application"]);

export const accessKindSchema = z.enum(["owner", "grant"]);

export const grantSubjectTypeSchema = z.enum([
  "user",
  "organization",
  "plan",
  "everyone",
  "application",
]);

/** Closed set, ordered from the weakest: `write` covers `read`. */
export const RESOURCE_PERMISSIONS = ["read", "write"] as const;
export const resourcePermissionSchema = z.enum(RESOURCE_PERMISSIONS);

export const resourceStatusSchema = z.enum([
  "pending_validation",
  "validation_failed",
  "validated",
  "disabled",
]);

export const accessibleResourceSchema = z.object({
  resourceId: z.string(),
  resourceUri: z.string(),
  scheme: z.string(),
  displayName: z.string(),
  applicationId: z.string(),
  applicationSlug: z.string(),
  applicationName: z.string(),
  ownerType: ownerTypeSchema,
  /** Present only for the application that owns the resource. */
  ownerId: z.string().optional(),
  accessKind: accessKindSchema,
  /** The level the user holds: the owner and a `write` grant can act. */
  permission: resourcePermissionSchema,
  grantSubjectType: grantSubjectTypeSchema.optional(),
});

export type ResourcePermission = z.infer<typeof resourcePermissionSchema>;
export type AccessibleResource = z.infer<typeof accessibleResourceSchema>;
