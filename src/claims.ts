import { z } from "zod";

const featureValueSchema = z.union([z.string(), z.number(), z.boolean()]);

const audienceSchema = z.union([z.string(), z.array(z.string())]);

// Present only when the matching scope was granted.
const entitlementShape = {
  roles: z.array(z.string()).optional(),
  permissions: z.array(z.string()).optional(),
  features: z.record(z.string(), featureValueSchema).optional(),
  plan: z.string().optional(),
  org_id: z.string().optional(),
};

const registeredShape = {
  iss: z.string(),
  sub: z.string(),
  aud: audienceSchema,
  exp: z.number(),
  iat: z.number(),
};

const profileShape = {
  name: z.string().optional(),
  given_name: z.string().optional(),
  family_name: z.string().optional(),
  middle_name: z.string().optional(),
  nickname: z.string().optional(),
  preferred_username: z.string().optional(),
  profile: z.string().optional(),
  picture: z.string().optional(),
  website: z.string().optional(),
  gender: z.string().optional(),
  birthdate: z.string().optional(),
  zoneinfo: z.string().optional(),
  locale: z.string().optional(),
  company: z.string().optional(),
  updated_at: z.number().optional(),
  email: z.string().optional(),
  email_verified: z.boolean().optional(),
  phone_number: z.string().optional(),
  phone_number_verified: z.boolean().optional(),
};

/** Claims of an ID token issued by auth-service. Unknown claims are kept as is. */
export const idTokenClaimsSchema = z.looseObject({
  ...registeredShape,
  sid: z.string().optional(),
  azp: z.string().optional(),
  ...profileShape,
  ...entitlementShape,
});

/** Standard claims returned by the UserInfo endpoint (no token claims). */
export const userInfoClaimsSchema = z.looseObject({
  sub: z.string(),
  ...profileShape,
  ...entitlementShape,
});

/**
 * Claims of a JWT access token. `azp` is the OAuth client that obtained the
 * token and `scope` is a space-separated list.
 */
export const accessTokenClaimsSchema = z.looseObject({
  ...registeredShape,
  azp: z.string(),
  scope: z.string().optional(),
  sid: z.string().optional(),
  ...entitlementShape,
});

export type FeatureValue = z.infer<typeof featureValueSchema>;
export type IdTokenClaims = z.infer<typeof idTokenClaimsSchema>;
export type UserInfoClaims = z.infer<typeof userInfoClaimsSchema>;
export type AccessTokenClaims = z.infer<typeof accessTokenClaimsSchema>;

export type PermissionAction = "read" | "write";

type EntitlementClaims = Pick<
  IdTokenClaims,
  "roles" | "permissions" | "features"
>;

export function hasRole(claims: EntitlementClaims, role: string): boolean {
  return claims.roles?.includes(role) ?? false;
}

/**
 * `resource` grants read access and `resource.write` grants write access,
 * which also implies read: auth-service keeps only the highest action.
 */
export function hasPermission(
  claims: EntitlementClaims,
  resource: string,
  action: PermissionAction = "read",
): boolean {
  const permissions = claims.permissions;
  if (!permissions) return false;
  if (permissions.includes(`${resource}.write`)) return true;
  return action === "read" && permissions.includes(resource);
}

/** A feature is enabled when present and neither `false` nor `0` nor `""`. */
export function hasFeature(claims: EntitlementClaims, key: string): boolean {
  const value = claims.features?.[key];
  return value !== undefined && value !== false && value !== 0 && value !== "";
}

export function getFeature(
  claims: EntitlementClaims,
  key: string,
): FeatureValue | undefined {
  return claims.features?.[key];
}
