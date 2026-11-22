import type { z } from "zod";
import { ERR } from "./errors.js";

/** Parses an untrusted input, raising `CFG_001` with every issue path. */
export function parseInput<T>(
  what: string,
  schema: z.ZodType<T>,
  input: unknown,
): T {
  const parsed = schema.safeParse(input);
  if (parsed.success) return parsed.data;
  const issues = parsed.error.issues
    .map((issue) => `${issue.path.join(".") || "(root)"}: ${issue.message}`)
    .join("; ");
  throw ERR.CFG_001(`Invalid ${what}: ${issues}`, { cause: parsed.error });
}
