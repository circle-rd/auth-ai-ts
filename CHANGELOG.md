# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

Sections, when present, appear in this order: `Added`, `Changed`, `Removed`,
`Fixed`, `Security`. Per our no-backward-compatibility policy
([CONTRIBUTING.md](CONTRIBUTING.md#2-versioning-and-breaking-changes)) there is no
`Deprecated` section: incompatible changes go straight to `Removed` and bump the version.

## [Unreleased]

### Changed

- **`ConsumptionApi` renamed for parity with the Rust and Python SDKs**:
  `machine.consumption.list(userId)` is now `listAggregates(userId)` and
  `machine.consumption.get(userId, key)` is now `getAggregate(userId, key)`.
- **`ResourceSharingClient.list()` is now `listOwned()`**, the name the Rust and Python SDKs
  already use for the resources the user owns.

### Added

- **`isAuthAiErrorCode`**, **`sessionUserSchema`**, **`toSessionUser`** and the type
  **`SessionUser`** are exported from the package root, so the TS root entry point matches
  the Rust and Python ones. `@circle-rd/auth-ai/web` keeps exporting them.

- **`user.resources`** (class `ResourceSharingClient`) is the signed-in user's self-service
  client for resource sharing: list, read, declare, update and delete the user's own
  resources; request validation; list, create and revoke grants; list the resources the user
  may access; and read the resource catalogue and the user's organizations and applications.
  Every input is validated with Zod before any request (`CFG_001`); ids must be UUIDs, schemes
  match `^[a-z][a-z0-9]{0,49}$`, and a grant takes either a subject id or a subject e-mail,
  never both, with a future `expiresAt`. The client uses the user's token for the
  auth-service audience with the `resources:self:manage` scope.
- **`resourceSharing`** on `createAuthClient` adds `resources:self:manage` (exported as
  `RESOURCE_SELF_SCOPE`) to the sign-in scopes and the issuer to the requested audiences,
  without duplicates and alongside `gatewayUrl`.
- **`verifyResourceEvent`** (`@circle-rd/auth-ai/server`) verifies an auth-service
  resource webhook from its `X-Auth-Service-Signature` header: an HMAC-SHA256 digest of
  `<timestamp>.<raw body>`. The timestamp is bounded (300 seconds by default) and the
  function returns the typed `ResourceEvent` (`resource.grant.created` and
  `resource.grant.revoked`). A missing or malformed header, a stale timestamp or a bad
  signature is `REQ_001`; an empty secret or an invalid tolerance is `CFG_001`. It uses
  Web Crypto and returns a `Promise`, so the server entry stays usable on edge runtimes.
- The HTTP client behind the REST clients now sends `PUT`, `PATCH` and `DELETE` and accepts
  `204 No Content` answers.
- Guides: the resource-sharing guide documents the self-service client, `resourceSharing` and
  webhook verification, and the gateway guide states that listings and calls are decided by
  auth-service entitlements (ownership, grants and application membership).

## [0.4.0] - 2026-11-17

Aligns the SDK with auth-service resource sharing (generic resource registry, grants,
validation, LiteLLM entitlements). The new machine calls need an auth-service with
`RESOURCE_SHARING_ENABLED`.

### Added

- **`machine.resources.recordUsage`** reports the usage a provider billed for a shared resource
  to auth-service (`POST /api/internal/gateway/usage`, scope `resources:usage:write`, granted to
  the platform's metering components only). It returns a `UsageReceipt` (`usage`, `replayed`):
  replaying an event is idempotent, a payload that conflicts with the stored event is refused
  (`RES_012`), and so is a caller with no access to the resource (`RES_011`). The record is
  validated before any request (`CFG_001`): `requestId` is 64 lowercase hex characters,
  `occurredAt` is a `Date` at most five minutes ahead and 30 days back, `costUsd` is a plain
  decimal required for `provider` usage, and `unsupported` usage carries no cost and no tokens.
  Reads stay with auth-service.
- **`machine.resources`** (`@circle-rd/auth-ai/server`, class `ResourcesApi`): `authorize`
  asks whether a user may use a resource (`resources:authorize`) and returns a `deny` or an
  `allow` with `resourceId`, `resourceUri`, `applicationSlug`, `ownerType`, `ownerId` and
  `accessKind`; `listAccessible` lists the validated resources a user may use;
  `validate` and `invalidate` let the validator bound to a resource scheme report the
  outcome of an ownership check or its loss (`resources:validate`). Inputs are validated
  before any request (`CFG_001`). An answer that is neither a known `deny` nor a complete
  `allow` throws `API_002`, so it can never read as an admission.
- Guide [Resource sharing](docs-site/content/docs/3.guides/3.ai-and-billing/3.resource-sharing.md).

### Changed

- **`gateway.mcpUrl(name)` refuses the name `v1`** (any case) with `CFG_001`: the gateway's own
  `/v1/mcp/...` routes own that path segment and no MCP server can be named so.
- Gateway access is now decided by auth-service entitlements (ownership, grants, application
  membership) instead of plan teams and access groups: `listModels`, `listAgents` and
  `listMcpServers` return what the user is entitled to, and a refusal is still `GW_003`.
  The documentation no longer refers to plan teams, access groups or `team_model_access_denied`.
- The machine scope defaults documented for a new confidential application now include
  `resources:validate`; `resources:authorize` is never a default.

### Fixed

- A `200` answer of the auth-service API whose body is not JSON now throws `API_002` instead of
  a raw `SyntaxError`.

## [0.3.0] - 2026-11-07

### Added

- **UserInfo enrichment**: after the code exchange and during server-managed session renewals, the SDK calls the
  provider's `userinfo_endpoint` and fills claims the ID token omits (`email`, `email_verified`
  and the standard profile claims). The UserInfo `sub` is checked against the ID token before
  any claim is merged; claims already present in the ID token are never replaced. Sign-in and
  server-managed session renewal now fail with `OIDC_003` when the UserInfo endpoint is
  unreachable, returns an error, or answers an invalid body, so treat it as a sign-in dependency.

### Changed

- Path-based issuer identifiers, including their required trailing slash, are now accepted and
  still compared verbatim with the discovery document and token `iss` claim. Token responses
  without the optional `expires_in` use a conservative five-minute local expiry. JWKS refreshes
  immediately on a previously unknown key, with a short cooldown to bound refresh requests.
- ID tokens and logout tokens are verified using the provider's selected signing algorithm.
  Back-channel logout success returns HTTP 200.

- **RP-initiated logout state**: `POST /auth/logout` now generates a `state`, sends it to the
  provider's `end_session_endpoint`, and the new `<basePath>/logout/callback` route accepts the
  provider's redirect even when the state is missing or different. Applications must set
  `postLogoutRedirectUri` to `<origin><basePath>/logout/callback` and register the same absolute
  URI with the provider; the reference app and quick-start now do so.
- `createBackchannelLogoutHandler` and `AuthHandlers` accept an opt-in
  `allowMissingTyp` / `allowMissingLogoutTokenTyp` setting for known non-conforming providers.
  The default remains strict: a missing or incorrect logout-token `typ` is rejected.

## [0.2.0] - 2026-11-04

### Changed

- **Logout without a session**: `POST /auth/logout` answers the provider's logout URL even when
  the request carries no session, built without `id_token_hint`. The provider ends its single
  sign-on session for every application and asks the user to confirm. `logoutUrl` is `null`
  only when the provider advertises no `end_session_endpoint`.

## [0.1.2] - 2026-11-02

### Changed

- **Repository**: the GitHub repository is now `circle-rd/auth-ai-ts` (the Python SDK
  lives in `circle-rd/auth-ai-py`). The npm package name is unchanged.
- **Documentation URL**: the documentation moves to
  `https://docs.circle-cyber.com/auth-ai/typescript/` (the Python SDK is at
  `/auth-ai/python/`). The previous `/auth-ai/…` links, including those of 0.1.0 and
  0.1.1, are redirected.
- **Skill name**: the agent skill published with the documentation is now
  `auth-ai-ts` (the Python SDK ships `auth-ai-py`).

### Removed

- **`EdDSA` is no longer an accepted ID token or JWT algorithm**: RFC 9864 deprecates
  that name. A provider that only advertises it fails discovery (`OIDC_001`). auth-service
  signs with ES256 from now on; `RS256`, `PS*` and `ES*` stay accepted.

### Security

- A server-side failure (a 5xx answer) of the sign-in handlers and of the Fastify hooks
  is now reported to `onError` too, so the cause shows up in the application's logs
  while the response still carries only the public code. `AuthHandlers` exposes the
  `onError` it was created with.

<!-- Add user-visible changes here. Move to a dated section at release time. -->

## [0.1.1] - 2026-11-01

### Changed

- **Publishing**: a GitHub release `vX.Y.Z` created from `main` publishes `latest`
  (`next` for a pre-release); a manual _Nightly_ run publishes `nightly`. Both use
  npm Trusted Publishing (OIDC) with provenance, no stored npm token. Previous
  nightlies are no longer deprecated automatically.

## [0.1.0] - 2026-11-01

First release.

### Added

- **Core (`@circle-rd/auth-ai`)**: `createAuthClient` (discovery cache, PKCE login,
  callback with ID-token verification, refresh with RFC 8707 resource narrowing,
  logout URL, revoke, introspect, `client_credentials`), `GrantManager` (serialized
  refresh-token rotation, per-audience access tokens, pluggable `GrantStore` and
  `GrantLock`), typed claims with `hasRole` / `hasPermission` / `hasFeature` /
  `getFeature`, the error registry (`CFG_`, `OIDC_`, `TOK_`, `API_`, `GW_`, `SES_`,
  `REQ_`, `SRV_`) with `toPublicJSON()`.
- **Wallet and gateway**: `WalletClient` (balance, statistics, per-session usage,
  transactions, top-up options and link; `bigint` micro-euros, `formatEuros`),
  `GatewayClient` (origin-locked `fetch`, OpenAI-compatible base URL, models, agents,
  MCP servers, MCP URLs, `postJson`, gateway error mapping), `createAiClient().forUser()`,
  and the `gatewayUrl` option that adds the gateway and auth-service audiences and the
  `wallet:self:read` scope.
- **Server (`/server`)**: Bearer-token verifier, back-channel logout handler with replay
  protection, RFC 9728 protected-resource metadata and `WWW-Authenticate` challenges,
  machine API (subscription, metered usage, invoices, consumption reporting).
- **Backend-for-frontend (`/web`, `/fastify`)**: `createAuthHandlers` (`/login`,
  `/callback`, `/me`, `/logout`, `/backchannel-logout`, optional `/wallet`,
  `/wallet/stats`, `/models`), sealed one-shot login cookie, hashed session ids,
  `SessionStore` contract, scheduled claims renewal; Fastify plugin with `requireAuth`
  and `loadSession`.
- **Frontend (`/client`, `/react`, `/vue`)**: cookie-only browser client, observable
  stores, React hooks and Vue composables.
- Example application (`examples/minimal`) with an end-to-end self-test, and the
  Docus documentation site.

### Security

- Every failed sign-in callback answers one generic `403 SES_005`; messages and details
  stay in the application's logs.
- `__Host-` cookies, same-origin redirect targets, refused cross-site logout, URLs built
  on the registered origin, Fastify >= 5.12.6 required.

[Unreleased]: https://github.com/circle-rd/auth-ai-ts/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/circle-rd/auth-ai-ts/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/circle-rd/auth-ai-ts/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/circle-rd/auth-ai-ts/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/circle-rd/auth-ai-ts/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/circle-rd/auth-ai-ts/releases/tag/v0.1.0
