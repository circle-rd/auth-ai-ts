import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { AuthAiError } from "../errors.js";
import { verifyResourceEvent } from "./webhooks.js";

const SECRET = "whsec_test";
const NOW = 1_763_000_000;

const EVENT = {
  eventId: "3d2a0c4e-6b7f-4a1d-8e2c-3f5b6a7c8d90",
  type: "resource.grant.created",
  occurredAt: "2026-11-18T10:00:00.000Z",
  application: { id: "app-1", slug: "acme" },
  resource: {
    id: "4b1f6f3e-5a6c-4d0e-9c53-0a4c6f0f7a11",
    uri: "llm://acme/gpt-x",
    scheme: "llm",
    displayName: "gpt-x",
    ownerType: "user",
    ownerId: "user-1",
    status: "validated",
  },
  grant: {
    id: "9d2a0c4e-6b7f-4a1d-8e2c-3f5b6a7c8d90",
    subjectType: "user",
    subjectId: "user-2",
    permission: "read",
    previousPermission: null,
    expiresAt: null,
  },
  recipients: { userIds: ["user-2"], allMembers: false },
};

const DELETED_EVENT = {
  eventId: "5e2a0c4e-6b7f-4a1d-8e2c-3f5b6a7c8d90",
  type: "resource.deleted",
  occurredAt: "2026-11-18T10:05:00.000Z",
  application: { id: "app-2", slug: "chat" },
  resource: {
    id: EVENT.resource.id,
    uri: EVENT.resource.uri,
    scheme: "llm",
    displayName: "gpt-x",
    ownerType: "user",
  },
};

function signature(timestamp: number, body: string): string {
  const digest = createHmac("sha256", SECRET)
    .update(String(timestamp))
    .update(".")
    .update(body)
    .digest("hex");
  return `t=${timestamp},v1=${digest}`;
}

function headers(value: string): Headers {
  return new Headers({ "X-Auth-Service-Signature": value });
}

function body(value: unknown = EVENT): string {
  return JSON.stringify(value);
}

async function failure(promise: Promise<unknown>): Promise<AuthAiError> {
  try {
    await promise;
  } catch (err) {
    expect(err).toBeInstanceOf(AuthAiError);
    return err as AuthAiError;
  }
  throw new Error("expected the event to be rejected");
}

describe("verifyResourceEvent", () => {
  it("verifies and parses a signed event", async () => {
    const raw = body();
    await expect(
      verifyResourceEvent(headers(signature(NOW, raw)), raw, {
        secret: SECRET,
        now: NOW,
      }),
    ).resolves.toEqual(EVENT);
  });

  it("parses a level change with the previous level", async () => {
    const updated = {
      ...EVENT,
      type: "resource.grant.updated",
      grant: {
        ...EVENT.grant,
        permission: "write",
        previousPermission: "read",
      },
    };
    const raw = body(updated);
    const event = await verifyResourceEvent(headers(signature(NOW, raw)), raw, {
      secret: SECRET,
      now: NOW,
    });
    expect(event).toEqual(updated);
  });

  it("parses a deletion, which carries no grant and no owner for another application", async () => {
    const raw = body(DELETED_EVENT);
    const event = await verifyResourceEvent(headers(signature(NOW, raw)), raw, {
      secret: SECRET,
      now: NOW,
    });
    expect(event).toEqual(DELETED_EVENT);
    expect(event.type).toBe("resource.deleted");
    expect("grant" in event).toBe(false);
  });

  it("rejects a grant event without a permission", async () => {
    const { permission: _omit, ...grant } = EVENT.grant;
    const raw = body({ ...EVENT, grant });
    expect(
      (
        await failure(
          verifyResourceEvent(headers(signature(NOW, raw)), raw, {
            secret: SECRET,
            now: NOW,
          }),
        )
      ).code,
    ).toBe("REQ_001");
  });

  it("accepts a plain header record with any key case", async () => {
    const raw = body();
    const event = await verifyResourceEvent(
      { "x-auth-service-signature": signature(NOW, raw) },
      raw,
      { secret: SECRET, now: NOW },
    );
    expect(event.type).toBe("resource.grant.created");
  });

  it("accepts a Uint8Array body", async () => {
    const raw = body();
    const bytes = new TextEncoder().encode(raw);
    expect(
      (
        await verifyResourceEvent(headers(signature(NOW, raw)), bytes, {
          secret: SECRET,
          now: NOW,
        })
      ).eventId,
    ).toBe(EVENT.eventId);
  });

  it("accepts any matching v1 signature among several", async () => {
    const raw = body();
    const valid = signature(NOW, raw).split("v1=")[1];
    const header = `t=${NOW},v1=${"0".repeat(64)},v1=${valid}`;
    expect(
      (
        await verifyResourceEvent(headers(header), raw, {
          secret: SECRET,
          now: NOW,
        })
      ).eventId,
    ).toBe(EVENT.eventId);
  });

  it("uses five minutes as the default tolerance", async () => {
    const raw = body();
    const recent = NOW - 300;
    expect(
      (
        await verifyResourceEvent(headers(signature(recent, raw)), raw, {
          secret: SECRET,
          now: NOW,
        })
      ).eventId,
    ).toBe(EVENT.eventId);
    expect(
      (
        await failure(
          verifyResourceEvent(headers(signature(NOW - 301, raw)), raw, {
            secret: SECRET,
            now: NOW,
          }),
        )
      ).code,
    ).toBe("REQ_001");
  });

  it("rejects a missing header", async () => {
    expect(
      (
        await failure(
          verifyResourceEvent(new Headers(), body(), {
            secret: SECRET,
            now: NOW,
          }),
        )
      ).code,
    ).toBe("REQ_001");
  });

  it.each([
    ["a header without signature", `t=${NOW}`],
    ["a header without timestamp", `v1=${"0".repeat(64)}`],
    ["a non-numeric timestamp", "t=now,v1=abc"],
    ["a negative timestamp", "t=-1,v1=abc"],
  ])("rejects %s", async (_label, header) => {
    expect(
      (
        await failure(
          verifyResourceEvent(headers(header), body(), {
            secret: SECRET,
            now: NOW,
          }),
        )
      ).code,
    ).toBe("REQ_001");
  });

  it("rejects a signature that does not match", async () => {
    expect(
      (
        await failure(
          verifyResourceEvent(headers(signature(NOW, body())), body(), {
            secret: "another-secret",
            now: NOW,
          }),
        )
      ).code,
    ).toBe("REQ_001");
  });

  it("rejects a signature that is not hex", async () => {
    expect(
      (
        await failure(
          verifyResourceEvent(headers(`t=${NOW},v1=zz`), body(), {
            secret: SECRET,
            now: NOW,
          }),
        )
      ).code,
    ).toBe("REQ_001");
  });

  it("rejects a body that is not JSON", async () => {
    const raw = "<html>";
    expect(
      (
        await failure(
          verifyResourceEvent(headers(signature(NOW, raw)), raw, {
            secret: SECRET,
            now: NOW,
          }),
        )
      ).code,
    ).toBe("REQ_001");
  });

  it.each([
    ["an unknown event type", { type: "resource.created" }],
    [
      "an unknown owner type",
      { resource: { ...EVENT.resource, ownerType: "plan" } },
    ],
    [
      "an unknown subject type",
      { grant: { ...EVENT.grant, subjectType: "team" } },
    ],
    ["a missing recipient list", { recipients: { allMembers: false } }],
    ["a non-ISO date", { occurredAt: "yesterday" }],
  ])("rejects a payload with %s", async (_label, override) => {
    const raw = body({ ...EVENT, ...override });
    expect(
      (
        await failure(
          verifyResourceEvent(headers(signature(NOW, raw)), raw, {
            secret: SECRET,
            now: NOW,
          }),
        )
      ).code,
    ).toBe("REQ_001");
  });

  it("requires a non-empty secret and a valid tolerance", async () => {
    const raw = body();
    expect(
      (
        await failure(
          verifyResourceEvent(headers(signature(NOW, raw)), raw, {
            secret: "",
          }),
        )
      ).code,
    ).toBe("CFG_001");
    expect(
      (
        await failure(
          verifyResourceEvent(headers(signature(NOW, raw)), raw, {
            secret: SECRET,
            toleranceSeconds: -1,
          }),
        )
      ).code,
    ).toBe("CFG_001");
  });
});
