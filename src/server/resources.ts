import { z } from "zod";
import type { JsonHttp } from "../http.js";
import {
  RESOURCE_SCHEME_PATTERN,
  accessKindSchema,
  accessibleResourceSchema,
  ownerTypeSchema,
  resourcePermissionSchema,
  resourceStatusSchema,
} from "../resource-types.js";
import type {
  AccessibleResource,
  ResourcePermission,
} from "../resource-types.js";
import { parseInput } from "../validation.js";

const AUTHORIZE_SCOPE = "resources:authorize";
const VALIDATE_SCOPE = "resources:validate";
const USAGE_SCOPE = "resources:usage:write";
const FUTURE_TOLERANCE_MS = 5 * 60_000;
const PAST_WINDOW_MS = 30 * 24 * 60 * 60_000;
const GATEWAY_PATH = "/api/internal/gateway";
const BASE_PATH = `${GATEWAY_PATH}/resources`;

const authorizeInputSchema = z
  .object({
    subjectId: z.string().min(1).max(256),
    actorClientId: z.string().min(1).max(256).optional(),
    resourceUri: z.string().min(3).max(512),
    audience: z.string().min(1).max(2048),
    permission: resourcePermissionSchema.optional(),
    requestId: z.string().min(1).max(256).optional(),
    source: z.enum(["gateway", "ssh", "external", "api"]).optional(),
  })
  .strict();

const accessibleInputSchema = z
  .object({
    subjectId: z.string().min(1).max(256),
    scheme: z.string().regex(RESOURCE_SCHEME_PATTERN).optional(),
  })
  .strict();

const validationInputSchema = z
  .object({
    result: z.enum(["validated", "validation_failed"]),
    reason: z.string().trim().max(500).optional(),
    evidence: z.record(z.string(), z.unknown()).optional(),
  })
  .strict();

const usageInputSchema = z
  .object({
    decisionId: z.string().min(1).max(2048),
    startedAt: z.date(),
    resourceId: z.uuid(),
    resourceUri: z.string().min(3).max(512),
    requestId: z.string().regex(/^[a-f0-9]{64}$/, "must be a trusted event id"),
    occurredAt: z.date(),
    usageSource: z.enum(["provider", "unsupported"]),
    costUsd: z
      .string()
      .regex(
        /^(0|[1-9][0-9]{0,17})(\.[0-9]{1,18})?$/,
        "must be a plain decimal",
      )
      .nullable()
      .default(null),
    promptTokens: z.number().int().min(0).nullable().default(null),
    completionTokens: z.number().int().min(0).nullable().default(null),
    totalTokens: z.number().int().min(0).nullable().default(null),
  })
  .strict()
  .superRefine((value, ctx) => {
    const now = Date.now();
    const at = value.occurredAt.getTime();
    if (at > now + FUTURE_TOLERANCE_MS || at < now - PAST_WINDOW_MS) {
      ctx.addIssue({
        code: "custom",
        path: ["occurredAt"],
        message: "occurredAt is outside the accepted accounting window",
      });
    }
    const tokens = [
      value.promptTokens,
      value.completionTokens,
      value.totalTokens,
    ];
    if (value.usageSource === "unsupported") {
      if (value.costUsd !== null || tokens.some((t) => t !== null)) {
        ctx.addIssue({
          code: "custom",
          message: "unsupported usage must not carry cost or tokens",
        });
      }
    } else if (value.costUsd === null) {
      ctx.addIssue({
        code: "custom",
        path: ["costUsd"],
        message: "provider usage requires a reported cost",
      });
    }
  });

const usageReceiptSchema = z.object({
  usage: z.object({
    id: z.string(),
    resourceId: z.string(),
    requestId: z.string(),
    occurredAt: z.string(),
  }),
  replayed: z.boolean(),
});

const invalidationReasonSchema = z.string().trim().min(1).max(500);
const resourceIdSchema = z.uuid();

// Only `allow` carries data; a decision this SDK does not know fails parsing,
// so an unexpected answer can never read as an admission.
const authorizeDecisionSchema = z.discriminatedUnion("decision", [
  z.object({ decision: z.literal("deny") }),
  z.object({
    decision: z.literal("allow"),
    decisionId: z.string(),
    expiresAt: z.iso.datetime(),
    resourceId: z.string(),
    resourceUri: z.string(),
    applicationSlug: z.string(),
    ownerType: ownerTypeSchema,
    ownerId: z.string().optional(),
    accessKind: accessKindSchema,
    permission: resourcePermissionSchema,
  }),
]);

const resourceStateSchema = z.object({
  id: z.string(),
  uri: z.string(),
  status: resourceStatusSchema,
  validationError: z.string().nullable(),
});

export type AuthorizeDecision = z.infer<typeof authorizeDecisionSchema>;
export type { AccessibleResource, ResourcePermission };
export type ResourceState = z.infer<typeof resourceStateSchema>;
export type UsageReceipt = z.infer<typeof usageReceiptSchema>;

export interface AuthorizeRequest {
  /** The user: the verified `sub` of the access token the caller received. */
  readonly subjectId: string;
  /**
   * The client the end user came through (the verified `azp`). It is recorded
   * in the access log only: the application asking is the machine credential.
   */
  readonly actorClientId?: string;
  /** Canonical URI of the resource, `<scheme>://<locator>`. */
  readonly resourceUri: string;
  /** The audience the token was verified for. */
  readonly audience: string;
  /** The level the request needs: `read` by default, `write` to act on the resource. */
  readonly permission?: ResourcePermission;
  /** Correlates the access event with the caller's own request id. */
  readonly requestId?: string;
  /** Recorded in the access log; `gateway` by default. */
  readonly source?: "gateway" | "ssh" | "external" | "api";
}

export interface ListAccessibleOptions {
  /** Narrows the list to one resource scheme, e.g. `llm`. */
  readonly scheme?: string;
}

export interface ValidationOutcome {
  readonly result: "validated" | "validation_failed";
  /** Shown to the owner when validation failed; 500 characters at most. */
  readonly reason?: string;
  /** Proof gathered by the validator. Never put a secret in it. */
  readonly evidence?: Readonly<Record<string, unknown>>;
}

export interface UsageRecord {
  /**
   * The `decisionId` of the admission that let the request through. It names the
   * person and the application, so a usage event cannot claim either.
   */
  readonly decisionId: string;
  /** When the admitted request started; it must fall within the decision's lifetime. */
  readonly startedAt: Date;
  readonly resourceId: string;
  readonly resourceUri: string;
  /** The event's trusted identifier: 64 lowercase hex characters. */
  readonly requestId: string;
  /** When the usage happened: at most five minutes ahead, 30 days back. */
  readonly occurredAt: Date;
  /** `provider` requires `costUsd`; `unsupported` carries no cost or tokens. */
  readonly usageSource: "provider" | "unsupported";
  /** Gross cost in USD as a plain decimal string, e.g. `"0.0042"`. */
  readonly costUsd?: string | null;
  readonly promptTokens?: number | null;
  readonly completionTokens?: number | null;
  readonly totalTokens?: number | null;
}

function resourceId(id: string): string {
  return parseInput("resource id", resourceIdSchema, id);
}

/**
 * Resource sharing from the side of an adapter service or of an application
 * that owns a resource scheme. The decision point stays auth-service: these
 * calls ask it, they never decide.
 *
 * `resources:authorize` is granted to an application's machine credential. Every
 * decision is taken for that application: it sees the resources it owns and the
 * ones shared with it, never everything a user owns. `resources:validate`
 * is granted to new confidential applications and acts only for the resource
 * schemes bound to the calling client.
 */
export class ResourcesApi {
  readonly #http: JsonHttp;

  constructor(http: JsonHttp) {
    this.#http = http;
  }

  /**
   * Asks whether a user may use a resource through the calling application.
   * Take `subjectId` and `audience` from a token you verified, never from the
   * request body; the calling application is the machine credential itself.
   * Anything other than `decision: "allow"` is a refusal, and so is a thrown
   * error: fail closed. A denial carries no reason, so it cannot be used to
   * probe. An allow carries the `permission` the user holds and a short-lived
   * `decisionId` to hand to `recordUsage`. Needs `resources:authorize`.
   */
  async authorize(request: AuthorizeRequest): Promise<AuthorizeDecision> {
    const body = parseInput("authorize request", authorizeInputSchema, request);
    return this.#http.request({
      method: "POST",
      path: `${GATEWAY_PATH}/authorize`,
      scope: AUTHORIZE_SCOPE,
      body,
      schema: authorizeDecisionSchema,
    });
  }

  /**
   * Every validated resource a user may use through the calling application.
   * Use it to filter a listing, never as the admission of a request: call
   * `authorize` for that. Needs `resources:authorize`.
   */
  async listAccessible(
    subjectId: string,
    options: ListAccessibleOptions = {},
  ): Promise<AccessibleResource[]> {
    const query = parseInput("accessible query", accessibleInputSchema, {
      subjectId,
      ...(options.scheme === undefined ? {} : { scheme: options.scheme }),
    });
    const { resources } = await this.#http.request({
      method: "GET",
      path: `${BASE_PATH}/accessible`,
      scope: AUTHORIZE_SCOPE,
      query,
      schema: z.object({ resources: z.array(accessibleResourceSchema) }),
    });
    return resources;
  }

  /**
   * Reports the outcome of the ownership check the validator ran on a
   * resource. Only the client bound to the resource's scheme may call it;
   * auth-service refuses any other with `AUTH_011`. Needs `resources:validate`.
   */
  async validate(
    id: string,
    outcome: ValidationOutcome,
  ): Promise<ResourceState> {
    const target = resourceId(id);
    const body = parseInput(
      "validation outcome",
      validationInputSchema,
      outcome,
    );
    const { resource } = await this.#http.request({
      method: "POST",
      path: `${BASE_PATH}/${encodeURIComponent(target)}/validate`,
      scope: VALIDATE_SCOPE,
      body,
      schema: z.object({ resource: resourceStateSchema }),
    });
    return resource;
  }

  /**
   * Disables a resource whose ownership was lost (a host key changed, the
   * object was deleted): new access is refused at once. The reason is kept in
   * the audit trail. Only the client bound to the scheme may call it. Needs
   * `resources:validate`.
   */
  async invalidate(id: string, reason: string): Promise<ResourceState> {
    const target = resourceId(id);
    const body = {
      reason: parseInput(
        "invalidation reason",
        invalidationReasonSchema,
        reason,
      ),
    };
    const { resource } = await this.#http.request({
      method: "POST",
      path: `${BASE_PATH}/${encodeURIComponent(target)}/invalidate`,
      scope: VALIDATE_SCOPE,
      body,
      schema: z.object({ resource: resourceStateSchema }),
    });
    return resource;
  }

  /**
   * Records the usage a provider billed for a shared resource. auth-service
   * owns accounting: this is the only write and reading stays with it. Needs
   * `resources:usage:write`, granted to the platform's metering components
   * only. Replaying an event is safe (`replayed: true`); a payload that
   * conflicts with the stored event is refused (`RES_012`), and so is a caller
   * with no access to the resource (`RES_011`).
   */
  async recordUsage(record: UsageRecord): Promise<UsageReceipt> {
    const usage = parseInput("usage record", usageInputSchema, record);
    return this.#http.request({
      method: "POST",
      path: `${GATEWAY_PATH}/usage`,
      scope: USAGE_SCOPE,
      body: {
        ...usage,
        startedAt: usage.startedAt.toISOString(),
        occurredAt: usage.occurredAt.toISOString(),
      },
      schema: usageReceiptSchema,
    });
  }
}
