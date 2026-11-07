# Minimal example

A Fastify backend and a vanilla-TypeScript page that exercise the SDK end to
end against a real auth-service: sign-in with PKCE, the session cookie,
entitlements, the wallet, the LiteLLM gateway (models, agents, MCP servers,
chat, embeddings), back-channel logout, machine tokens, billing and
consumption. **Self-test** runs every check and writes a report, free of any
token or secret, to the server log.

## Register the application in auth-service

- Confidential application at `https://<host>`, with **LiteLLM support** on.
- Redirect URI `https://<host>/auth/callback`, post-logout URI `https://<host>/auth/logout/callback`.
- Back-channel logout URI `https://<host>/auth/backchannel-logout`.
- Machine scopes (superadmin): `billing:read`, `consumption:read`, `consumption:write`.

## Run

```sh
pnpm install && pnpm build && pnpm example:build
cp examples/minimal/.env.example examples/minimal/.env   # then fill the two secrets
docker compose -f examples/minimal/compose.yml up -d --build
```

Sessions and grants are kept in memory: a restart signs everyone out. Use a
database-backed `SessionStore` and `GrantStore` in a real application.
