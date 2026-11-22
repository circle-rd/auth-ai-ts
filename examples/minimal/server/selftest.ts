import { AuthAiError, formatEuros } from "@circle-rd/auth-ai";
import type { AiClient, AuthClient, GrantManager } from "@circle-rd/auth-ai";
import { createBearerVerifier } from "@circle-rd/auth-ai/server";
import type { MachineApi } from "@circle-rd/auth-ai/server";
import type { Session } from "@circle-rd/auth-ai/web";

export interface SelfTestContext {
  readonly auth: AuthClient;
  readonly grants: GrantManager;
  readonly ai: AiClient;
  readonly machine: MachineApi;
  readonly publicUrl: string;
  readonly gatewayUrl: string;
  readonly session: Session;
}

export interface CheckResult {
  readonly name: string;
  readonly ok: boolean;
  readonly detail?: unknown;
  readonly error?: { code?: string; message: string; details?: unknown };
}

function describeError(err: unknown): NonNullable<CheckResult["error"]> {
  if (err instanceof AuthAiError) return err.toJSON();
  return { message: err instanceof Error ? err.message : String(err) };
}

async function check(
  name: string,
  run: () => Promise<unknown>,
): Promise<CheckResult> {
  try {
    return { name, ok: true, detail: await run() };
  } catch (err) {
    return { name, ok: false, error: describeError(err) };
  }
}

/** Billing is asynchronous: poll until `done` holds or the time is up. */
async function settle<T>(
  read: () => Promise<T>,
  done: (value: T) => boolean,
  timeoutMs = 20_000,
): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  let value = await read();
  while (!done(value) && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 2_000));
    value = await read();
  }
  return value;
}

interface ChatAnswer {
  choices?: {
    finish_reason?: string;
    message?: { content?: string | null; reasoning_content?: string | null };
  }[];
  usage?: { prompt_tokens?: number; completion_tokens?: number };
}

const summarise = (answer: unknown): Record<string, unknown> => {
  const { choices, usage } = answer as ChatAnswer;
  const choice = choices?.[0];
  return {
    reply: (choice?.message?.content ?? "").slice(0, 80),
    replyLength: choice?.message?.content?.length ?? 0,
    hasReasoning: Boolean(choice?.message?.reasoning_content),
    finishReason: choice?.finish_reason,
    usage,
  };
};

/** Exercises every SDK brick for the signed-in user; the report holds no token. */
export async function runSelfTest(
  ctx: SelfTestContext,
): Promise<CheckResult[]> {
  const { auth, grants, ai, machine, session } = ctx;
  const { userId } = session;
  const user = ai.forUser(userId);
  const usageSessionId = `selftest-${crypto.randomUUID()}`;
  const resources = [auth.config.issuer, ctx.gatewayUrl, ctx.publicUrl];
  const results: CheckResult[] = [];
  const run = async (name: string, fn: () => Promise<unknown>) => {
    results.push(await check(name, fn));
  };

  await run("session-claims", async () => ({
    sub: userId,
    hasProviderSession: session.sessionId !== undefined,
    roles: session.claims.roles,
    permissions: session.claims.permissions,
    features: session.claims.features,
    plan: session.claims.plan,
    orgId: session.claims.org_id,
  }));

  await run("refresh-returns-id-token", async () => {
    const tokens = await grants.refreshTokens(userId);
    const claims = tokens.idToken
      ? await auth.verifyIdToken(tokens.idToken)
      : undefined;
    return {
      idTokenReturned: tokens.idToken !== undefined,
      rotated: tokens.refreshToken !== undefined,
      scope: tokens.scope,
      rolesInRenewedClaims: claims?.roles,
      planInRenewedClaims: claims?.plan,
      featuresInRenewedClaims: claims?.features,
    };
  });

  await run("tokens-per-audience", async () => {
    const out: Record<string, unknown> = {};
    for (const resource of resources) {
      const { accessToken, expiresAt } = await grants.getAccessToken(userId, {
        resource,
      });
      const claims = await auth.verifyJwt(accessToken, { audience: resource });
      out[resource] = {
        aud: claims.aud,
        azp: claims["azp"],
        scope: claims["scope"],
        lifetimeSeconds: expiresAt - Math.floor(Date.now() / 1000),
      };
    }
    return out;
  });

  await run("bearer-own-resource", async () => {
    const { accessToken } = await grants.getAccessToken(userId, {
      resource: ctx.publicUrl,
    });
    const verified = await createBearerVerifier(auth, {
      audience: ctx.publicUrl,
    }).verify(accessToken);
    return {
      userId: verified.userId,
      clientId: verified.clientId,
      scopes: verified.scopes,
    };
  });

  await run("introspection", async () => {
    const { accessToken } = await grants.getAccessToken(userId, {
      resource: auth.config.issuer,
    });
    const result = await auth.introspect(accessToken, "access_token");
    return { active: result.active, scope: result.scope };
  });

  await run("wallet", async () => {
    const account = await user.wallet.getAccount();
    const stats = await user.wallet.getStats({ days: 7 });
    const page = await user.wallet.listTransactions({ limit: 3 });
    const topup = await user.wallet.getTopupOptions();
    return {
      balanceEuros: formatEuros(account.balance, 6),
      isUnlimited: account.isUnlimited,
      canSpend: account.canSpend,
      spent7d: formatEuros(stats.total, 6),
      calls7d: stats.calls,
      lastTransactions: page.items.map((t) => `${t.type}:${t.delta}`),
      topupEnabled: topup.enabled,
      topupUrl: user.wallet.topupUrl(),
    };
  });

  let models: string[] = [];
  await run("gateway-models", async () => {
    models = (await user.gateway.listModels()).map((model) => model.id);
    return models;
  });
  await run("gateway-agents", async () =>
    (await user.gateway.listAgents()).map((agent) => agent.agent_name),
  );
  await run("gateway-mcp-servers", async () => ({
    servers: (await user.gateway.listMcpServers()).map(
      (server) => server.server_name ?? server.alias ?? server.server_id,
    ),
    mcpUrl: user.gateway.mcpUrl(),
  }));

  const chatModel = models.find((id) => /lagarde/i.test(id));
  await run("chat-free-model", async () => {
    if (!chatModel) throw new Error("no model matching /lagarde/ in the plan");
    const answer = await user.gateway.postJson("/v1/chat/completions", {
      model: chatModel,
      max_tokens: 512,
      messages: [{ role: "user", content: "Reply with the single word: pong" }],
      metadata: { session_id: usageSessionId },
    });
    return { model: chatModel, ...summarise(answer) };
  });

  const embedModel = models.find((id) => /pplx-embed/i.test(id));
  await run("embedding-billed-model", async () => {
    if (!embedModel)
      throw new Error("no model matching /pplx-embed/ in the plan");
    const before = await user.wallet.getAccount();
    const answer = (await user.gateway.postJson("/v1/embeddings", {
      model: embedModel,
      input: "auth-ai self-test",
      metadata: { session_id: usageSessionId },
    })) as { data?: { embedding?: unknown[] }[] };
    const after = await settle(
      () => user.wallet.getAccount(),
      (account) => account.balance !== before.balance,
    );
    return {
      model: embedModel,
      dimensions: answer.data?.[0]?.embedding?.length,
      balanceBefore: formatEuros(before.balance, 6),
      balanceAfter: formatEuros(after.balance, 6),
      debitedMicroEuros: (before.balance - after.balance).toString(),
    };
  });

  await run("wallet-session-usage", async () => {
    const usage = await settle(
      () => user.wallet.getSessionUsage(usageSessionId),
      (value) => value.calls > 0,
    );
    return {
      calls: usage.calls,
      totalMicroEuros: usage.total.toString(),
      models: usage.byModel.map((m) => `${m.model}:${m.totalTokens}tok`),
    };
  });

  await run("machine-token", async () => {
    const tokens = await auth.clientCredentials({ scope: "m2m" });
    return { issued: true, scope: tokens.scope };
  });

  await run("billing-subscription", async () => ({
    subscription: await machine.billing.getSubscription(userId),
    usage: await machine.billing.getUsage(userId),
    invoices: (await machine.billing.listInvoices(userId, { limit: 1 })).items
      .length,
  }));

  await run("consumption", async () => {
    const reported = await machine.consumption.report({
      userId,
      key: "selftest.calls",
      value: 1,
      idempotencyKey: usageSessionId,
    });
    const stored = await machine.consumption.getAggregate(
      userId,
      "selftest.calls",
    );
    return { reported, storedTotal: stored.total };
  });

  await run("consumption-metered-feature", async () => {
    const { features } = await machine.billing.getUsage(userId);
    const feature = features[0];
    if (!feature) throw new Error("the plan prices no metered feature");
    const reported = await machine.consumption.report({
      userId,
      key: feature.featureKey,
      value: 1,
      idempotencyKey: `${usageSessionId}-metered`,
    });
    const after = (await machine.billing.getUsage(userId)).features.find(
      (item) => item.featureKey === feature.featureKey,
    );
    return {
      featureKey: feature.featureKey,
      metered: reported.metered,
      usedBefore: feature.used,
      usedAfter: after?.used,
      limit: feature.usageLimit,
    };
  });

  return results;
}
