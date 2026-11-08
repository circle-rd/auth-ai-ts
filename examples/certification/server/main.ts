import { readFile } from "node:fs/promises";
import { join } from "node:path";
import Fastify from "fastify";
import {
  AuthAiError,
  GrantManager,
  MemoryGrantStore,
  createAuthClient,
} from "@circle-rd/auth-ai";
import { authPlugin } from "@circle-rd/auth-ai/fastify";
import { MemorySessionStore, createAuthHandlers } from "@circle-rd/auth-ai/web";
import { loadConfig } from "./config.js";

const config = loadConfig(process.env);
const publicDir = join(process.cwd(), "examples/certification/public");

const auth = createAuthClient({
  issuer: config.AUTH_ISSUER,
  clientId: config.AUTH_CLIENT_ID,
  clientSecret: config.AUTH_CLIENT_SECRET,
  redirectUri: `${config.PUBLIC_URL}/auth/callback`,
  postLogoutRedirectUri: `${config.PUBLIC_URL}/auth/logout/callback`,
});

const grants = new GrantManager({ auth, store: new MemoryGrantStore() });

const app = Fastify({
  trustProxy: true,
  logger: {
    serializers: {
      req: (request: { method: string; url: string }) => ({
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
  requireProviderSession: !config.OIDF_MOCK_COMPAT,
  allowMissingLogoutTokenTyp: config.OIDF_MOCK_COMPAT,
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

app.addHook("onSend", async (_request, reply) => {
  void reply.header(
    "content-security-policy",
    "default-src 'none'; img-src 'self' https:; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
  );
  void reply.header("x-content-type-options", "nosniff");
  void reply.header("referrer-policy", "no-referrer");
});

const staticFiles: Record<string, readonly [string, string]> = {
  "/": ["index.html", "text/html; charset=utf-8"],
  "/app.js": ["app.js", "text/javascript; charset=utf-8"],
  "/style.css": ["style.css", "text/css; charset=utf-8"],
  "/alps.jpg": ["alps.jpg", "image/jpeg"],
  "/favicon.svg": ["favicon.svg", "image/svg+xml"],
};
for (const [path, [file, type]] of Object.entries(staticFiles)) {
  const body = await readFile(join(publicDir, file));
  app.get(path, async (_request, reply) =>
    reply.header("content-type", type).send(body),
  );
}

app.get("/healthz", async () => ({ ok: true }));

await app.listen({ host: "0.0.0.0", port: config.PORT });
