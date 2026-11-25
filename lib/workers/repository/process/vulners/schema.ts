import { z } from 'zod/v4';
import { Nullish } from '../../../../util/schema-utils/index.ts';

// Enrichment fields only decorate the pull request; a field of an unexpected
// shape is dropped instead of failing the whole response.
export const VulnersAdvisory = z.object({
  id: z.string(),
  type: z.string(),
  title: Nullish(z.string()).catch(undefined),
  description: Nullish(z.string()).catch(undefined),
  registry: Nullish(z.string()).catch(undefined),
  cvelist: Nullish(z.array(z.string())).catch(undefined),
  metrics: Nullish(
    z.object({
      cvss: Nullish(
        z.object({
          score: Nullish(z.number()),
          severity: Nullish(z.string()),
          vector: Nullish(z.string()),
        }),
      ),
    }),
  ).catch(undefined),
  epss: Nullish(
    z.array(z.object({ epss: z.number(), percentile: Nullish(z.number()) })),
  ).catch(undefined),
  aiScore: Nullish(z.object({ value: z.number() })).catch(undefined),
  exploitation: Nullish(
    z.object({ wildExploited: Nullish(z.boolean()) }),
  ).catch(undefined),
});
export type VulnersAdvisory = z.infer<typeof VulnersAdvisory>;

export const VulnersAuditItem = z.object({
  package: z.string(),
  version: z.string(),
  fixedVersion: Nullish(z.string()),
  applicableAdvisories: z.array(VulnersAdvisory).default([]),
});
export type VulnersAuditItem = z.infer<typeof VulnersAuditItem>;

export const VulnersAuditResponse = z.object({
  result: z.object({ data: z.array(VulnersAuditItem) }),
});
export type VulnersAuditResponse = z.infer<typeof VulnersAuditResponse>;
