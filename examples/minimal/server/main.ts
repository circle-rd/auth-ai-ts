import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import Fastify from "fastify";
import type { FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import {
  AuthAiError,
  GrantManager,
  MemoryGrantStore,
  createAiClient,
  createAuthClient,
} from "@circle-rd/auth-ai";
import { authPlugin, requireAuth } from "@circle-rd/auth-ai/fastify";
import {
  bearerChallenge,
  createBearerVerifier,
  createMachineApi,
  protectedResourceMetadata,
  protectedResourceMetadataPath,
} from "@circle-rd/auth-ai/server";
import { MemorySessionStore, createAuthHandlers } from "@circle-rd/auth-ai/web";
import { loadConfig } from "./config.js";
import { runSelfTest } from "./selftest.js";

const config = loadConfig(process.env);
const origin = new URL(config.PUBLIC_URL).origin;
const publicDir = join(dirname(fileURLToPath(import.meta.url)), "../../public");

const auth = createAuthClient({
  issuer: config.AUTH_ISSUER,
  clientId: config.AUTH_CLIENT_ID,
  clientSecret: config.AUTH_CLIENT_SECRET,
  redirectUri: `${config.PUBLIC_URL}/auth/callback`,
  postLogoutRedirectUri: `${config.PUBLIC_URL}/auth/logout/callback`,
  gatewayUrl: config.GATEWAY_URL,
  resources: [config.PUBLIC_URL],
});

// In memory: a restart signs everyone out. Use a database store beyond a demo.
const grants = new GrantManager({ auth, store: new MemoryGrantStore() });
const ai = createAiClient({ auth, grants });
const machine = createMachineApi(auth);

const app = Fastify({
  trustProxy: true,
  logger: {
    // The authorization code travels in the callback query string.
    serializers: {
      req: (request: FastifyRequest) => ({
        method: request.method,
        path: request.url.split("?")[0],
      }),
    },
  },
});

const handlers = await createAuthHandlers({
  auth,
  grants,
  sessions: new MemorySessionStore(),
  secret: config.COOKIE_SECRET,
  ai,
  onError: (error) => {
    app.log.warn(
      { error: error instanceof AuthAiError ? error.toJSON() : String(error) },
      "auth handler error",
    );
  },
  onSessionsEnded: (sessions) => {
    app.log.info({ count: sessions.length }, "sessions ended");
  },
});
await app.register(authPlugin, { handlers });

const protect = requireAuth(handlers);

// The CSP forbids inline script and any other origin.
app.addHook("onSend", async (_request, reply) => {
  void reply.header(
    "content-security-policy",
    "default-src 'self'; frame-ancestors 'none'",
  );
  void reply.header("x-content-type-options", "nosniff");
});

// State-changing API calls must come from this site.
app.addHook("preHandler", async (request, reply) => {
  const mutating = request.method !== "GET" && request.method !== "HEAD";
  if (!mutating || !request.url.startsWith("/api/")) return;
  const requestOrigin = request.headers.origin;
  if (requestOrigin !== undefined && requestOrigin !== origin) {
    return reply.status(403).send({
      error: { code: "SES_004", message: "Cross-origin request refused" },
    });
  }
});

const staticFiles: Record<string, [string, string]> = {
  "/": ["index.html", "text/html; charset=utf-8"],
  "/app.js": ["app.js", "text/javascript; charset=utf-8"],
  "/style.css": ["style.css", "text/css; charset=utf-8"],
};
for (const [path, [file, type]] of Object.entries(staticFiles)) {
  const body = await readFile(join(publicDir, file));
  app.get(path, async (_request, reply) =>
    reply.header("content-type", type).send(body),
  );
}

app.get("/healthz", async () => ({ ok: true }));

const metadata = protectedResourceMetadata(auth, {
  resource: config.PUBLIC_URL,
  scopesSupported: ["openid", "profile", "email", "roles", "features"],
});
app.get(protectedResourceMetadataPath(config.PUBLIC_URL), async () => metadata);

const settle = async <T>(run: () => Promise<T>) =>
  run().then(
    (data) => ({ ok: true as const, data }),
    (err: unknown) => ({
      ok: false as const,
      error:
        err instanceof AuthAiError ? err.toPublicJSON() : { message: "failed" },
    }),
  );

function gatewayOf(request: FastifyRequest) {
  const userId = request.authSession?.userId;
  if (!userId) throw new Error("requireAuth did not set the session");
  return { userId, user: ai.forUser(userId) };
}

function replyWithError(reply: FastifyReply, err: unknown) {
  if (err instanceof AuthAiError) {
    const status = err.code === "GW_001" ? 402 : 502;
    return reply.status(status).send({ error: err.toPublicJSON() });
  }
  throw err;
}

app.get("/api/gateway", { preHandler: protect }, async (request) => {
  const { user } = gatewayOf(request);
  return {
    models: await settle(() => user.gateway.listModels()),
    agents: await settle(() => user.gateway.listAgents()),
    mcpServers: await settle(() => user.gateway.listMcpServers()),
  };
});

const chatSchema = z.object({
  model: z.string().min(1),
  message: z.string().min(1).max(2000),
});

app.post("/api/chat", { preHandler: protect }, async (request, reply) => {
  const body = chatSchema.parse(request.body);
  const { user } = gatewayOf(request);
  try {
    return await user.gateway.postJson("/v1/chat/completions", {
      model: body.model,
      max_tokens: 256,
      messages: [{ role: "user", content: body.message }],
      metadata: { session_id: request.authSession?.id },
    });
  } catch (err) {
    return replyWithError(reply, err);
  }
});

const embedSchema = z.object({
  model: z.string().min(1),
  input: z.string().min(1).max(2000),
});

app.post("/api/embed", { preHandler: protect }, async (request, reply) => {
  const body = embedSchema.parse(request.body);
  const { user } = gatewayOf(request);
  try {
    const answer = (await user.gateway.postJson("/v1/embeddings", {
      ...body,
      metadata: { session_id: request.authSession?.id },
    })) as { data?: { embedding?: unknown[] }[] };
    return { dimensions: answer.data?.[0]?.embedding?.length ?? 0 };
  } catch (err) {
    return replyWithError(reply, err);
  }
});

const consumeSchema = z.object({
  key: z.string().min(1),
  value: z.number().finite(),
});

app.post("/api/consume", { preHandler: protect }, async (request, reply) => {
  const body = consumeSchema.parse(request.body);
  const { userId } = gatewayOf(request);
  try {
    await machine.consumption.report({ userId, ...body });
    return await machine.consumption.list(userId);
  } catch (err) {
    return replyWithError(reply, err);
  }
});

app.post("/api/selftest", { preHandler: protect }, async (request) => {
  const session = request.authSession;
  if (!session) throw new Error("requireAuth did not set the session");
  const checks = await runSelfTest({
    auth,
    grants,
    ai,
    machine,
    publicUrl: config.PUBLIC_URL,
    gatewayUrl: config.GATEWAY_URL,
    session,
  });
  // The log keeps the detailed report for the developer; the browser gets the codes.
  app.log.info({ selftest: { user: session.userId, checks } }, "self-test");
  return {
    checks: checks.map(({ error, ...rest }) =>
      error ? { ...rest, error: { code: error.code } } : rest,
    ),
  };
});

// A Bearer-protected route, to exercise token verification and the challenge.
app.get("/api/bearer", async (request, reply) => {
  try {
    const verified = await createBearerVerifier(auth, {
      audience: config.PUBLIC_URL,
    }).verifyHeader(request.headers.authorization);
    return { userId: verified.userId, scopes: verified.scopes };
  } catch (err) {
    if (!(err instanceof AuthAiError)) throw err;
    return reply
      .status(401)
      .header(
        "www-authenticate",
        bearerChallenge({
          resourceMetadataUrl: `${config.PUBLIC_URL}${protectedResourceMetadataPath(config.PUBLIC_URL)}`,
          error: "invalid_token",
        }),
      )
      .send({ error: err.toPublicJSON() });
  }
});

await app.listen({ host: "0.0.0.0", port: config.PORT });
