import { isString } from '@sindresorhus/is';
import { logger } from '../../../../logger/index.ts';
import * as hostRules from '../../../../util/host-rules.ts';
import { Http } from '../../../../util/http/index.ts';
import type { HttpResponse } from '../../../../util/http/types.ts';
import { Json } from '../../../../util/schema-utils/index.ts';
import { type VulnersPackage, vulnersKey } from './purl.ts';
import { type VulnersAdvisory, VulnersAuditResponse } from './schema.ts';

export const VULNERS_AUDIT_URL =
  'https://vulners.com/api/v4/audit/sbom?aiSummary=false';

export interface VulnersFinding {
  key: string;
  package: string;
  version: string;
  fixedVersion: string | null;
  advisories: VulnersAdvisory[];
}

export interface VulnersWallet {
  cost: number;
  amount: number;
}

export type VulnersOutcome =
  | { status: 'ok'; findings: VulnersFinding[]; wallet?: VulnersWallet }
  | { status: 'no-dependencies' }
  | { status: 'no-key' }
  | { status: 'out-of-credits' }
  | { status: 'failed'; reason: string };

const http = new Http('vulners');

export function toCycloneDx(packages: VulnersPackage[]): string {
  const components = new Map<string, Record<string, string>>();
  for (const { name, version, purl } of packages) {
    components.set(purl, {
      type: 'library',
      'bom-ref': purl,
      name,
      version,
      purl,
    });
  }
  return JSON.stringify({
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    components: [...components.values()],
  });
}

function headerNumber(res: HttpResponse, name: string): number {
  const value = res.headers[name];
  return isString(value) ? parseInt(value, 10) : NaN;
}

function getWallet(res: HttpResponse): VulnersWallet | undefined {
  const cost = headerNumber(res, 'x-vulners-wallet-cost');
  const amount = headerNumber(res, 'x-vulners-wallet-amount');
  if (Number.isNaN(cost) || Number.isNaN(amount)) {
    return undefined;
  }
  return { cost, amount };
}

function toFindings(body: VulnersAuditResponse): VulnersFinding[] {
  const findings: VulnersFinding[] = [];
  for (const item of body.result.data) {
    if (!item.applicableAdvisories.length) {
      continue;
    }
    const registry = item.applicableAdvisories.find(
      (advisory) => advisory.registry,
    )?.registry;
    if (!registry) {
      logger.debug(
        { package: item.package },
        'Vulners advisories without a registry - skipping',
      );
      continue;
    }
    findings.push({
      key: vulnersKey(registry, item.package, item.version),
      package: item.package,
      version: item.version,
      fixedVersion: item.fixedVersion ?? null,
      advisories: item.applicableAdvisories,
    });
  }
  return findings;
}

/**
 * Audits the packages with one call to Vulners. Never throws: a failure is an
 * outcome, so that Renovate carries on without the vulnerability check.
 */
export async function fetchVulnersAudit(
  packages: VulnersPackage[],
): Promise<VulnersOutcome> {
  if (!packages.length) {
    return { status: 'no-dependencies' };
  }
  const { token } = hostRules.find({
    hostType: 'vulners',
    url: VULNERS_AUDIT_URL,
  });
  if (!token) {
    return { status: 'no-key' };
  }

  const form = new FormData();
  form.append(
    'file',
    new Blob([toCycloneDx(packages)], { type: 'application/json' }),
    'bom.json',
  );

  let res: HttpResponse;
  try {
    res = await http.postText(VULNERS_AUDIT_URL, {
      body: form,
      noAuth: true,
      throwHttpErrors: false,
      headers: { 'x-api-key': token, accept: 'application/json' },
    });
  } catch (err) {
    return { status: 'failed', reason: `request failed: ${err.message}` };
  }

  if (res.statusCode === 402) {
    return { status: 'out-of-credits' };
  }
  if (res.statusCode !== 200) {
    return { status: 'failed', reason: `HTTP ${res.statusCode}` };
  }

  const parsed = Json.pipe(VulnersAuditResponse).safeParse(res.body);
  if (!parsed.success) {
    return { status: 'failed', reason: 'unexpected response from Vulners' };
  }

  const wallet = getWallet(res);
  return {
    status: 'ok',
    findings: toFindings(parsed.data),
    ...(wallet ? { wallet } : {}),
  };
}
