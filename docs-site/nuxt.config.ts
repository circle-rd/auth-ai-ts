export default defineNuxtConfig({
  extends: ["docus"],
  css: ["~/circle-theme.css"],
  fonts: {
    families: [
      {
        name: "Lato",
        provider: "google",
        weights: [100, 300, 400, 700],
      },
    ],
  },
  app: {
    baseURL: process.env.NUXT_APP_BASE_URL ?? "/auth-ai/typescript/",
  },
  site: {
    url: process.env.NUXT_SITE_URL ?? "https://docs.circle-cyber.com/auth-ai/typescript",
    name: "CIRCLE auth-ai",
  },
  robots: { robotsTxt: false },
  image: {
    provider: "passthrough",
    providers: {
      passthrough: { name: "passthrough", provider: "~/providers/passthrough" },
    },
  },
  meta: {
    title: "CIRCLE auth-ai",
    description:
      "TypeScript SDK for applications relying on a CIRCLE auth-service identity provider: OIDC sign-in (backend-for-frontend), entitlements, billing, credit wallet and LiteLLM gateway.",
    ogHost: process.env.NUXT_SITE_URL ?? "https://docs.circle-cyber.com/auth-ai/typescript",
  },
  llms: {
    title: "CIRCLE auth-ai",
    description:
      "TypeScript SDK (@circle-rd/auth-ai) for applications relying on a CIRCLE auth-service identity provider: OIDC sign-in (backend-for-frontend), entitlements, billing, credit wallet and LiteLLM gateway.",
    full: {
      title: "CIRCLE auth-ai — Complete Documentation",
      description:
        "Complete documentation for @circle-rd/auth-ai, a TypeScript SDK for applications that sign users in through a CIRCLE auth-service. Covers the backend-for-frontend sign-in handlers, the Fastify adapter, React and Vue bindings, Bearer token verification, back-channel logout, the credit wallet, the LiteLLM gateway client, billing and consumption, configuration and the error code registry.",
    },
    sections: [
      {
        title: "Developer Resources",
        description: "Machine-readable entry points for this project.",
        links: [
          {
            title: "CIRCLE auth-ai on GitHub",
            description: "Source, issues and releases.",
            href: "https://github.com/circle-rd/auth-ai-ts",
          },
          {
            title: "CIRCLE auth-ai (Python) documentation",
            description:
              "The Python SDK, with the same behaviours and wire contract, for Python backends.",
            href: "https://docs.circle-cyber.com/auth-ai/python/",
          },
          {
            title: "CIRCLE auth-service documentation",
            description:
              "The identity provider this SDK talks to: applications, claims, wallet, LiteLLM gateway.",
            href: "https://docs.circle-cyber.com/auth-service/",
          },
        ],
      },
    ],
    notes: [
      "When to use CIRCLE auth-ai: in an application that signs users in through a CIRCLE auth-service instance (OIDC authorization code with PKCE, backend-for-frontend) and, optionally, reads the user's credit wallet and calls the LiteLLM gateway on the user's behalf.",
      "CIRCLE auth-ai is built for auth-service (its claims and its wallet, billing and consumption REST routes): it is not a client for arbitrary OIDC providers, and it is not an identity provider. To run the provider, use the auth-service documentation at https://docs.circle-cyber.com/auth-service/.",
      "Tokens stay on the server: the browser only holds an opaque session cookie. The SDK has no debit API: the gateway debits the wallet after each call.",
      "The SDK is a 0.x release and its public API is not stable yet. There is no Next.js adapter; a Python SDK exists as a separate package (https://docs.circle-cyber.com/auth-ai/python/); the Web-standard handlers in @circle-rd/auth-ai/web can be mounted in any framework.",
      "Reading this documentation as an agent: every page is also served as markdown under /raw/, for example https://docs.circle-cyber.com/auth-ai/typescript/raw/docs/concepts/architecture.md. The full text is at https://docs.circle-cyber.com/auth-ai/typescript/llms-full.txt and a page index at https://docs.circle-cyber.com/auth-ai/typescript/llms.txt.",
    ],
  },
});
