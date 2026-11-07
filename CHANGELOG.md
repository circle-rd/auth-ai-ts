# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

Sections, when present, appear in this order: `Added`, `Changed`, `Removed`,
`Fixed`, `Security`. Per our no-backward-compatibility policy
([CONTRIBUTING.md](CONTRIBUTING.md#2-versioning-and-breaking-changes)) there is no
`Deprecated` section: incompatible changes go straight to `Removed` and bump the version.

## [Unreleased]

## [0.3.0] - 2026-11-07

### Added

- **UserInfo enrichment**: after the code exchange and during server-managed session renewals, the SDK calls the
  provider's `userinfo_endpoint` and fills claims the ID token omits (`email`, `email_verified`
  and the standard profile claims). The UserInfo `sub` is checked against the ID token before
  any claim is merged; claims already present in the ID token are never replaced. Sign-in and
  server-managed session renewal now fail with `OIDC_003` when the UserInfo endpoint is
  unreachable, returns an error, or answers an invalid body, so treat it as a sign-in dependency.

### Changed

- **RP-initiated logout state**: `POST /auth/logout` now generates a `state`, sends it to the
  provider's `end_session_endpoint`, and the new `<basePath>/logout/callback` route accepts the
  provider's redirect even when the state is missing or different. Applications must set
  `postLogoutRedirectUri` to `<origin><basePath>/logout/callback` and register the same absolute
  URI with the provider; the reference app and quick-start now do so.

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
