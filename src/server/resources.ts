import { z } from "zod";
import { ERR } from "../errors.js";
import type { JsonHttp } from "../http.js";

const AUTHORIZE_SCOPE = "resources:authorize";
const VALIDATE_SCOPE = "resources:validate";
const GATEWAY_PATH = "/api/internal/gateway";
const BASE_PATH = `${GATEWAY_PATH}/resources`;

const SCHEME_PATTERN = /^[a-z][a-z0-9]{0,49}$/;

const ownerTypeSchema = z.enum(["user", "application"]);
const accessKindSchema = z.enum(["owner", "grant"]);
const grantSubjectTypeSchema = z.enum([
  "user",
  "organization",
  "plan",
  "everyone",
]);
const resourceStatusSchema = z.enum([
  "pending_validation",
  "validation_failed",
  "validated",
  "disabled",
]);

const authorizeInputSchema = z
  .object({
    subjectId: z.string().min(1).max(256),
    clientId: z.string().min(1).max(256),
    resourceUri: z.string().min(3).max(512),
    audience: z.string().min(1).max(2048),
    requestId: z.string().min(1).max(256).optional(),
    source: z.enum(["gateway", "ssh", "external", "api"]).optional(),
  })
  .strict();

const accessibleInputSchema = z
  .object({
    subjectId: z.string().min(1).max(256),
    scheme: z.string().regex(SCHEME_PATTERN).optional(),
  })
  .strict();

const validationInputSchema = z
  .object({
    result: z.enum(["validated", "validation_failed"]),
    reason: z.string().trim().max(500).optional(),
    evidence: z.record(z.string(), z.unknown()).optional(),
  })
  .strict();

const invalidationReasonSchema = z.string().trim().min(1).max(500);
const resourceIdSchema = z.uuid();

// Only `allow` carries data; a decision this SDK does not know fails parsing,
// so an unexpected answer can never read as an admission.
const authorizeDecisionSchema = z.discriminatedUnion("decision", [
  z.object({ decision: z.literal("deny") }),
  z.object({
    decision: z.literal("allow"),
    resourceId: z.string(),
    resourceUri: z.string(),
    applicationSlug: z.string(),
    ownerType: ownerTypeSchema,
    ownerId: z.string(),
    accessKind: accessKindSchema,
  }),
]);

const accessibleResourceSchema = z.object({
  resourceId: z.string(),
  resourceUri: z.string(),
  scheme: z.string(),
  displayName: z.string(),
  applicationId: z.string(),
  applicationSlug: z.string(),
  applicationName: z.string(),
  ownerType: ownerTypeSchema,
  ownerId: z.string(),
  accessKind: accessKindSchema,
  grantSubjectType: grantSubjectTypeSchema.optional(),
});

const resourceStateSchema = z.object({
  id: z.string(),
  uri: z.string(),
  status: resourceStatusSchema,
  validationError: z.string().nullable(),
});

export type AuthorizeDecision = z.infer<typeof authorizeDecisionSchema>;
export type AccessibleResource = z.infer<typeof accessibleResourceSchema>;
export type ResourceState = z.infer<typeof resourceStateSchema>;

export interface AuthorizeRequest {
  /** The user: the verified `sub` of the access token the caller received. */
  readonly subjectId: string;
  /** The calling client: the verified `azp` of that token. */
  readonly clientId: string;
  /** Canonical URI of the resource, `<scheme>://<locator>`. */
  readonly resourceUri: string;
  /** The audience the token was verified for. */
  readonly audience: string;
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

function invalid(what: string, error: z.ZodError): never {
  const issues = error.issues
    .map((issue) => `${issue.path.join(".")}: ${issue.message}`)
    .join("; ");
  throw ERR.CFG_001(`Invalid ${what}: ${issues}`, { cause: error });
}

function parseInput<T>(what: string, schema: z.ZodType<T>, input: unknown): T {
  const parsed = schema.safeParse(input);
  if (!parsed.success) invalid(what, parsed.error);
  return parsed.data;
}

function resourceId(id: string): string {
  return parseInput("resource id", resourceIdSchema, id);
}

/**
 * Resource sharing from the side of an adapter service or of an application
 * that owns a resource scheme. The decision point stays auth-service: these
 * calls ask it, they never decide.
 *
 * `resources:authorize` reaches every user and every resource of the instance,
 * so a superadmin grants it only to a trusted enforcement point. `resources:validate`
 * is granted to new confidential applications and acts only for the resource
 * schemes bound to the calling client.
 */
export class ResourcesApi {
  readonly #http: JsonHttp;

  constructor(http: JsonHttp) {
    this.#http = http;
  }

  /**
   * Asks whether a user may use a resource. Take `subjectId`, `clientId` and
   * `audience` from a token you verified, never from the request body. Anything
   * other than `decision: "allow"` is a refusal, and so is a thrown error:
   * fail closed. A denial carries no reason, so it cannot be used to probe.
   * Needs `resources:authorize`.
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
   * Every validated resource a user may use, across applications. Use it to
   * filter a listing, never as the admission of a request: call `authorize`
   * for that. Needs `resources:authorize`.
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
}
