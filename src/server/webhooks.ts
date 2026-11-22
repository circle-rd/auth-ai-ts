import { z } from "zod";
import { ERR } from "../errors.js";
import {
  grantSubjectTypeSchema,
  ownerTypeSchema,
  resourceStatusSchema,
} from "../resource-types.js";

const HEADER = "x-auth-service-signature";
const DEFAULT_TOLERANCE_SECONDS = 300;
const HEX_SIGNATURE = /^[0-9a-f]{64}$/i;
const ENCODER = new TextEncoder();

export const resourceWebhookEventTypeSchema = z.enum([
  "resource.grant.created",
  "resource.grant.revoked",
]);

const applicationSchema = z.object({ id: z.string(), slug: z.string() });

const resourceSchema = z.object({
  id: z.string(),
  uri: z.string(),
  scheme: z.string(),
  displayName: z.string(),
  ownerType: ownerTypeSchema,
  ownerId: z.string(),
  status: resourceStatusSchema,
});

const grantSchema = z.object({
  id: z.string(),
  subjectType: grantSubjectTypeSchema,
  subjectId: z.string().nullable(),
  expiresAt: z.iso.datetime().nullable(),
});

const recipientsSchema = z.object({
  userIds: z.array(z.string()).nullable(),
  allMembers: z.boolean(),
});

export const resourceEventSchema = z.object({
  eventId: z.string(),
  type: resourceWebhookEventTypeSchema,
  occurredAt: z.iso.datetime(),
  application: applicationSchema,
  resource: resourceSchema,
  grant: grantSchema,
  recipients: recipientsSchema,
});

export type ResourceWebhookEventType = z.infer<
  typeof resourceWebhookEventTypeSchema
>;
export type ResourceEvent = z.infer<typeof resourceEventSchema>;

export type ResourceEventHeaders =
  Headers | Readonly<Record<string, string | readonly string[] | undefined>>;

export interface VerifyResourceEventOptions {
  /** The application's resource webhook secret from auth-service. */
  readonly secret: string;
  /** Accepted distance from the delivery timestamp, 300 seconds by default. */
  readonly toleranceSeconds?: number;
  /** Current time in unix seconds; tests pass it, production leaves it out. */
  readonly now?: number;
}

function headerValue(
  headers: ResourceEventHeaders,
  name: string,
): string | null {
  if (headers instanceof Headers) return headers.get(name);
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== name) continue;
    if (value === undefined) return null;
    return typeof value === "string" ? value : (value[0] ?? null);
  }
  return null;
}

async function hmacSha256(
  secret: string,
  data: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    ENCODER.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
}

function hexBytes(value: string): Uint8Array | null {
  if (!HEX_SIGNATURE.test(value)) return null;
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

/**
 * Verifies and parses a resource-sharing webhook signed with
 * `X-Auth-Service-Signature` (`t=<unix seconds>,v1=<hex HMAC-SHA256>`), computed
 * over `<t>.<raw body>`. The timestamp bounds replay; deduplicate on `eventId`.
 */
export async function verifyResourceEvent(
  headers: ResourceEventHeaders,
  body: string | Uint8Array,
  options: VerifyResourceEventOptions,
): Promise<ResourceEvent> {
  const tolerance = options.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS;
  if (options.secret.length === 0) {
    throw ERR.CFG_001("The webhook secret must not be empty");
  }
  if (!Number.isInteger(tolerance) || tolerance < 0) {
    throw ERR.CFG_001("toleranceSeconds must be a non-negative integer");
  }

  const header = headerValue(headers, HEADER);
  if (header === null) {
    throw ERR.REQ_001("Missing X-Auth-Service-Signature header");
  }

  let timestamp: string | undefined;
  const signatures: string[] = [];
  for (const part of header.split(",")) {
    const [name, ...rest] = part.trim().split("=");
    const value = rest.join("=");
    if (name === "t") timestamp = value;
    else if (name === "v1") signatures.push(value);
  }
  if (timestamp === undefined || signatures.length === 0) {
    throw ERR.REQ_001("Malformed X-Auth-Service-Signature header");
  }

  const signedAt = Number(timestamp);
  if (!/^[0-9]+$/.test(timestamp) || !Number.isSafeInteger(signedAt)) {
    throw ERR.REQ_001("Malformed webhook timestamp");
  }
  const now = options.now ?? Date.now() / 1_000;
  if (Math.abs(now - signedAt) > tolerance) {
    throw ERR.REQ_001("Webhook timestamp is outside the accepted window");
  }
  const raw = typeof body === "string" ? ENCODER.encode(body) : body;
  const prefix = ENCODER.encode(`${timestamp}.`);
  const signed = new Uint8Array(prefix.length + raw.length);
  signed.set(prefix);
  signed.set(raw, prefix.length);
  const expected = await hmacSha256(options.secret, signed);
  const matches = signatures.some((candidate) => {
    const actual = hexBytes(candidate);
    return actual !== null && equalBytes(actual, expected);
  });
  if (!matches) {
    throw ERR.REQ_001("Webhook signature does not match");
  }

  let payload: unknown;
  try {
    payload = JSON.parse(
      typeof body === "string" ? body : new TextDecoder().decode(body),
    );
  } catch (err) {
    throw ERR.REQ_001("Webhook body is not valid JSON", { cause: err });
  }
  const parsed = resourceEventSchema.safeParse(payload);
  if (!parsed.success) {
    throw ERR.REQ_001("Webhook body has an unexpected shape", {
      cause: parsed.error,
    });
  }
  return parsed.data;
}
