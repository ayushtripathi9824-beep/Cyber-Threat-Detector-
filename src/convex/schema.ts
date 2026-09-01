import { authTables } from "@convex-dev/auth/server";
import { defineSchema, defineTable } from "convex/server";
import { Infer, v } from "convex/values";

export const ROLES = {
  ADMIN: "admin",
  USER: "user",
  MEMBER: "member",
} as const;

export const roleValidator = v.union(
  v.literal(ROLES.ADMIN),
  v.literal(ROLES.USER),
  v.literal(ROLES.MEMBER),
);
export type Role = Infer<typeof roleValidator>;

const schema = defineSchema(
  {
    ...authTables,

    users: defineTable({
      name: v.optional(v.string()),
      image: v.optional(v.string()),
      email: v.optional(v.string()),
      emailVerificationTime: v.optional(v.number()),
      isAnonymous: v.optional(v.boolean()),
      role: v.optional(roleValidator),
    }).index("email", ["email"]),

    // ── Cyber Threat Detection Tables ──────────────────────────

    alerts: defineTable({
      timestamp: v.number(),
      flowId: v.string(),
      threatClass: v.string(),
      severity: v.union(
        v.literal("critical"),
        v.literal("high"),
        v.literal("medium"),
        v.literal("low"),
      ),
      confidence: v.number(),
      sourceIp: v.string(),
      destIp: v.string(),
      sourcePort: v.number(),
      destPort: v.number(),
      protocol: v.string(),
      evidence: v.string(),
      acknowledged: v.boolean(),
    })
      .index("by_timestamp", ["timestamp"])
      .index("by_threatClass", ["threatClass"])
      .index("by_severity", ["severity"])
      .index("by_acknowledged", ["acknowledged"]),

    flows: defineTable({
      timestamp: v.number(),
      flowId: v.string(),
      sourceIp: v.string(),
      destIp: v.string(),
      sourcePort: v.number(),
      destPort: v.number(),
      protocol: v.string(),
      bytesForward: v.number(),
      bytesBackward: v.number(),
      packetsForward: v.number(),
      packetsBackward: v.number(),
      duration: v.number(),
      flags: v.string(),
      tlsVersion: v.optional(v.string()),
      ja3Hash: v.optional(v.string()),
      dnsQuery: v.optional(v.string()),
      dnsRecordType: v.optional(v.string()),
    })
      .index("by_timestamp", ["timestamp"])
      .index("by_sourceIp", ["sourceIp"])
  },
  {
    schemaValidation: false,
  },
);

export default schema;
