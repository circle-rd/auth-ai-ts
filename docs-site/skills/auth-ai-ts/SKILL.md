---
name: auth-ai-ts
description: "Use when: integrating, configuring or troubleshooting @circle-rd/auth-ai, the TypeScript SDK for applications that sign users in through a CIRCLE auth-service (backend-for-frontend OIDC sign-in with Fastify or Web-standard handlers, React/Vue bindings, Bearer token verification, back-channel logout, wallet, LiteLLM gateway, billing and consumption), or when an AuthAiError code such as SES_005, TOK_002 or GW_001 appears."
---

# CIRCLE auth-ai

TypeScript SDK (`@circle-rd/auth-ai`, MIT, Node.js >= 22, ESM only) for applications that rely on a CIRCLE auth-service identity provider. Full documentation: https://docs.circle-cyber.com/auth-ai/typescript/ . Every page is also served as markdown under `/raw/`, for example https://docs.circle-cyber.com/auth-ai/typescript/raw/docs/concepts/architecture.md ; the whole text is at https://docs.circle-cyber.com/auth-ai/typescript/llms-full.txt. Version 0.x: the API is not stable.

It is built for auth-service. It is not a client for arbitrary OIDC providers and not an identity provider. It has no debit API (the LiteLLM gateway debits the wallet), no Next.js adapter. For Python backends use the sibling Python SDK (`auth-ai` on PyPI, https://docs.circle-cyber.com/auth-ai/python/); for Rust backends use the Rust SDK (`auth-ai` on crates.io, https://docs.circle-cyber.com/auth-ai/rust/).

## Getting started

```sh
pnpm add @circle-rd/auth-ai   # or: npm install @circle-rd/auth-ai
# optional peers: fastify >=5.12.6, react >=18, vue >=3.4
```

Entry points (the only import paths that exist):

| Path | Purpose |
| --- | --- |
| `@circle-rd/auth-ai` | `createAuthClient`, `GrantManager`, `createAiClient`, claims helpers, `formatEuros`, `AuthAiError`/`ERR` |
| `@circle-rd/auth-ai/web` | `createAuthHandlers`, `MemorySessionStore`, `safeRedirectPath` |
| `@circle-rd/auth-ai/fastify` | `authPlugin`, `requireAuth`, `loadSession` |
| `@circle-rd/auth-ai/server` | `createBearerVerifier`, `requireScopes`, `protectedResourceMetadata`, `createBackchannelLogoutHandler`, `createMachineApi` |
| `@circle-rd/auth-ai/client` | `createBrowserAuth`, observable stores (no server code) |
| `@circle-rd/auth-ai/react` | `AuthProvider`, `useAuth`, `useUser`, `useEntitlements`, `useWallet`, `useWalletStats`, `useModels` |
| `@circle-rd/auth-ai/vue` | `createAuthPlugin` and the same composables |

## Register the application in auth-service first

- Confidential application, redirect URI `<origin><basePath>/callback` (`basePath` defaults to `/auth`).
- Back-channel logout URI `<origin><basePath>/backchannel-logout` (HTTPS, reachable by auth-service) and/or end-session enabled: sign-in refuses an ID token without `sid`.
- **LiteLLM support** on when `gatewayUrl` is set.
- Machine scopes `billing:read`, `consumption:read`, `consumption:write`, `resources:validate` for the machine API (default for new confidential apps; a superadmin must set them on older apps). `resources:authorize` is never a default: a superadmin grants it to a trusted enforcement point only.

## Minimal Fastify backend

```ts
import Fastify from "fastify";
import { GrantManager, MemoryGrantStore, createAuthClient } from "@circle-rd/auth-ai";
import { authPlugin, requireAuth } from "@circle-rd/auth-ai/fastify";
import { MemorySessionStore, createAuthHandlers } from "@circle-rd/auth-ai/web";

// A missing secret must stop the process (undefined would make a public client).
function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing environment variable ${name}`);
  return value;
}

const auth = createAuthClient({
  issuer: "https://auth.example.com", // HTTPS, no trailing slash
  clientId: "my-app",
  clientSecret: required("AUTH_CLIENT_SECRET"),
  redirectUri: "https://app.example.com/auth/callback",
});
const grants = new GrantManager({ auth, store: new MemoryGrantStore() }); // demo only
const handlers = await createAuthHandlers({
  auth,
  grants,
  sessions: new MemorySessionStore(), // demo only
  secret: required("AUTH_COOKIE_SECRET"), // >= 32 random characters
});

const app = Fastify();
await app.register(authPlugin, { handlers }); // /auth/login /callback /me /logout /backchannel-logout
app.get("/api/me", { preHandler: requireAuth(handlers) }, async (request) => request.authSession!.claims.sub);
await app.listen({ host: "0.0.0.0", port: 3000 });
```

Other frameworks: call `handlers.handle(request)` (Web `Request` in, `Response` or `null` out), build the `Request` on `handlers.origin`, forward every `Set-Cookie` with `response.headers.getSetCookie()`.

## Common tasks

- **Entitlements**: `hasRole(claims, "admin")`, `hasPermission(claims, "reports", "write")` (write implies read), `hasFeature(claims, "beta")`, `getFeature(claims, "seats")`. Enforce on the server.
- **Wallet and gateway** (needs `gatewayUrl`): `const user = createAiClient({ auth, grants }).forUser(sub)`; `user.wallet.getAccount()` (amounts are `bigint` micro-euros: use `formatEuros(balance)`; decide with `canSpend`); `user.gateway.postJson("/v1/chat/completions", { model, messages, metadata: { session_id } })`; OpenAI-compatible SDKs: `new OpenAI({ baseURL: user.gateway.openAiBaseUrl, apiKey: "unused", fetch: user.gateway.fetch })`. `402` is `GW_001` (`isInsufficientCredit`), `429` is `GW_002`.
- **Billing and consumption** (backend only, needs `clientSecret`): `createMachineApi(auth)`; `machine.billing.getSubscription(sub)`, `.getUsage(sub)`, `.listInvoices(sub, { limit })`; `machine.consumption.report({ userId, key, value, idempotencyKey })`, `.listAggregates(userId)`, `.getAggregate(userId, key)`.
- **Resource sharing** (backend only, needs `clientSecret` and an auth-service with `RESOURCE_SHARING_ENABLED`): every decision is taken for the application whose credential you use. `machine.resources.authorize({ subjectId, actorClientId?, resourceUri, audience, permission? })` returns `{ decision: "allow" | "deny" }` (take `subjectId` and `audience` from a verified token; only `allow` admits, a thrown error is a denial; an allow carries `permission` `read`/`write`, `decisionId` and `expiresAt`), `.listAccessible(subjectId, { scheme })`, `.validate(resourceId, { result, reason, evidence })` and `.invalidate(resourceId, reason)` for the validator of a resource scheme, and `.recordUsage({ decisionId, startedAt, resourceId, ... })` with the `decisionId` of the admitting `authorize`. The user client (`ai.forUser(id).resources`) has `createGrant({ permission })`, `updateGrant`, `deleteGrant`, `shareWithApplication`, and `delete` removes for good. `verifyResourceEvent` returns a union: `resource.grant.created|revoked|updated` and `resource.deleted`.
- **Protect an API**: `createBearerVerifier(auth, { audience: "https://api.example.com" }).verifyHeader(req.headers.authorization)`, then `requireScopes(token, "roles")`; serve `protectedResourceMetadata(auth, { resource })` at `protectedResourceMetadataPath(resource)` and answer 401/403 with `bearerChallenge({ resourceMetadataUrl, error })`.
- **Frontend**: React `<AuthProvider>` + `useAuth()`; Vue `app.use(createAuthPlugin())` + `useAuth()`; vanilla `createBrowserAuth()` + `createAuthStore()`. The browser only holds an opaque session cookie.

## Production rules

- Implement `SessionStore` and `GrantStore` on your database (memory stores are for demos and one instance); encrypt refresh tokens at rest.
- With several replicas, pass a distributed `GrantLock` to `GrantManager` and a shared `ReplayStore` to `createAuthHandlers`.
- Cookie secret >= 32 random characters from the environment; the SDK reads no environment variable itself.
- Set `onError` and log `error.toJSON()`; answer users with `error.toPublicJSON()` only. Do not log query strings (callback carries the code).
- Check `Origin` on your own state-changing routes. Keep `fastify` >= 5.12.6.

## Troubleshooting by error code

| Code | Likely cause and fix |
| --- | --- |
| `CFG_001` | Invalid config: `issuer` with trailing slash or not HTTPS, `redirectUri` not ending with `<basePath>/callback`, cookie secret < 32 chars, machine API without `clientSecret`, `gatewayUrl` missing for `.gateway`. |
| `SES_005` | Every failed `/auth/callback` answers this; the real cause is passed to `onError` (look for `SES_003`: ID token without `sid`, `OIDC_003`: wrong client secret, `SES_002`: expired or foreign handshake cookie). |
| `OIDC_001` | Discovery failed: check `issuer` is reachable. |
| `TOK_002` | No usable grant: the user must sign in again. |
| `TOK_004` | Missing scope: `details.missing` for `requireScopes`, `details.scope` for a machine scope a superadmin must grant. |
| `GW_001` | Wallet empty (402): send the user to `wallet.topupUrl()`. |
| `GW_003` | Gateway refused credentials or resource (401/403): check LiteLLM support and the user's plan. |

More: https://docs.circle-cyber.com/auth-ai/typescript/docs/reference/error-codes
