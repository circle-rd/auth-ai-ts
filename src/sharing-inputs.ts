import { z } from "zod";
import {
  RESOURCE_SCHEME_PATTERN,
  grantSubjectTypeSchema,
  resourcePermissionSchema,
} from "./resource-types.js";

const METADATA_MAX_BYTES = 4096;
export const BULK_SHARE_LIMIT = 100;

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

export const audienceSchema = z.union([
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

export const createInputSchema = z
  .object({
    applicationId: z.uuid(),
    scheme: z.string().regex(RESOURCE_SCHEME_PATTERN),
    locator: z.string().trim().min(1).max(255).optional(),
    displayName: z.string().trim().min(1).max(200),
    metadata: metadataSchema.optional(),
    audience: audienceSchema.optional(),
  })
  .strict();

export const updateInputSchema = z
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

export const grantInputSchema = z
  .object({
    subjectType: grantSubjectTypeSchema,
    subjectId: z.string().trim().min(1).max(256).nullable().optional(),
    subjectEmail: emailSchema.optional(),
    permission: resourcePermissionSchema.optional(),
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

export const grantUpdateInputSchema = z
  .object({ permission: resourcePermissionSchema })
  .strict();

export const bulkShareInputSchema = z
  .object({
    resourceIds: z.array(z.uuid()).min(1).max(BULK_SHARE_LIMIT),
    applicationSlug: z.string().trim().min(1).max(256),
    permission: resourcePermissionSchema.optional(),
    expiresAt: z
      .date()
      .nullable()
      .optional()
      .refine((value) => !value || value.getTime() > Date.now(), {
        message: "must be in the future",
      }),
  })
  .strict();

export const accessibleQuerySchema = z
  .object({
    scheme: z.string().regex(RESOURCE_SCHEME_PATTERN).optional(),
    applicationId: z.uuid().optional(),
  })
  .strict();
