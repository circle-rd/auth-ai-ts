import { z } from "zod";

const originSchema = z
  .string()
  .url()
  .refine((value) => {
    const url = new URL(value);
    return url.pathname === "/" && url.search === "" && url.hash === "";
  }, "must be an origin: no path, query, fragment or trailing slash");

const configSchema = z.object({
  PORT: z.coerce.number().int().gt(0).lt(65536).default(3000),
  PUBLIC_URL: originSchema,
  AUTH_ISSUER: z.string().url(),
  AUTH_CLIENT_ID: z.string().min(1),
  AUTH_CLIENT_SECRET: z.string().min(1),
  COOKIE_SECRET: z.string().min(32),
  // Only for the OpenID Foundation mock OP: accepts the sid-less ID tokens and the
  // logout tokens without `typ` that its plans issue. Never enable against auth-service.
  OIDF_MOCK_COMPAT: z
    .enum(["true", "false"])
    .default("false")
    .transform((value) => value === "true"),
});

export interface Config {
  readonly PORT: number;
  readonly PUBLIC_URL: string;
  readonly AUTH_ISSUER: string;
  readonly AUTH_CLIENT_ID: string;
  readonly AUTH_CLIENT_SECRET: string;
  readonly COOKIE_SECRET: string;
  readonly OIDF_MOCK_COMPAT: boolean;
}

export function loadConfig(env: NodeJS.ProcessEnv): Config {
  const parsed = configSchema.safeParse(env);
  if (!parsed.success) {
    const names = [
      ...new Set(
        parsed.error.issues.map((issue) => issue.path.map(String).join(".")),
      ),
    ];
    throw new Error(`Invalid environment: ${names.join(", ")}`);
  }
  return parsed.data;
}
