---
seo:
  title: CIRCLE auth-ai — TypeScript SDK for auth-service applications
  description: TypeScript SDK for applications relying on a CIRCLE auth-service identity provider. Backend-for-frontend OIDC sign-in, entitlements from claims, back-channel logout, Bearer verification, credit wallet, LiteLLM gateway client, billing and consumption.
---

:::u-page-hero{.circle-hero}
#title
CIRCLE auth-ai

#description
A TypeScript SDK for applications that sign their users in through a [CIRCLE auth-service](https://docs.circle-cyber.com/auth-service/). Run the OIDC flow on your backend, keep tokens off the browser, read roles and plan features, and let users call LLMs through the LiteLLM gateway against their credit wallet.

#links
::::u-button{to="/docs/getting-started/introduction" size="xl" trailing-icon="i-lucide-arrow-right" color="neutral"}
Get started
::::

::::u-button{to="https://docs.circle-cyber.com/auth-ai/python/" size="xl" variant="outline" color="neutral" icon="i-simple-icons-python"}
Python SDK
::::

::::u-button{to="https://github.com/circle-rd/auth-ai-ts" target="_blank" size="xl" variant="outline" color="neutral" icon="i-simple-icons-github"}
GitHub
::::
:::

:::u-page-section{.circle-section}
#title
What it does

#features
::::u-page-feature{icon="i-lucide-shield-check" title="Backend-for-frontend sign-in" description="Authorization code flow with PKCE on your server. The browser only holds an opaque, HttpOnly session cookie: access and refresh tokens never reach it."}
::::

::::u-page-feature{icon="i-lucide-key-round" title="Grants and per-audience tokens" description="One refresh-token chain per user, rotated under a lock, and short-lived access tokens minted per audience (RFC 8707) for your API, the gateway and auth-service."}
::::

::::u-page-feature{icon="i-lucide-users" title="Entitlements from claims" description="Roles, permissions, plan features and organisation are read from the ID token and renewed from the provider on a schedule. hasRole, hasPermission, hasFeature and getFeature work on both sides."}
::::

::::u-page-feature{icon="i-lucide-log-out" title="Back-channel logout" description="OIDC Back-Channel Logout verified and replay-protected: signing out of auth-service ends your local sessions and revokes the grant."}
::::

::::u-page-feature{icon="i-lucide-wallet" title="Credit wallet and LiteLLM gateway" description="Read the user's prepaid balance and spend, and call an OpenAI-compatible gateway with the user's own token. The gateway debits the wallet; your app never handles a debit."}
::::

::::u-page-feature{icon="i-lucide-receipt" title="Billing and consumption" description="From your backend with a machine token: read a user's subscription, metered usage and invoices, and report consumption with idempotency keys."}
::::

::::u-page-feature{icon="i-lucide-lock" title="Protect an API" description="Verify JWT Bearer tokens for your own audience, require scopes, and publish RFC 9728 protected-resource metadata so MCP and OAuth clients can discover the provider."}
::::

::::u-page-feature{icon="i-lucide-layers" title="Fastify, React, Vue" description="A Fastify plugin, Web-standard handlers for any other framework, a framework-agnostic browser client, and React and Vue bindings."}
::::

::::u-page-feature{icon="i-lucide-triangle-alert" title="Errors safe to show" description="Every failure is an AuthAiError with a stable code. Details stay in your logs; HTTP responses carry the code and a generic message only."}
::::
:::
