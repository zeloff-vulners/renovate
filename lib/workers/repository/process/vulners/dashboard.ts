import { isNullOrUndefined } from '@sindresorhus/is';
import type { RenovateConfig } from '../../../../config/types.ts';
import { sanitizeMarkdown } from '../../../../util/markdown.ts';
import { type VulnersOutcome, isWalletLow } from './client.ts';
import { getVulnersOutcome } from './index.ts';
import { vulnersAdvisoryUrl } from './rules.ts';

export const VULNERS_SALES_URL =
  'https://vulners.com/contact/?utm_source=renovate&utm_medium=plugin&utm_campaign=freemium&utm_content=talk_to_sales';

/** The only place which offers a Vulners license. */
export function getVulnersSalesOffer(): string {
  return `To keep checking, [talk to Vulners about a license](${VULNERS_SALES_URL}).`;
}

const MAX_ADVISORY_LINKS = 5;

function listUnfixed(
  config: RenovateConfig,
  outcome: Extract<VulnersOutcome, { status: 'ok' }>,
): string {
  const summary = config.dependencyDashboardOSVVulnerabilitySummary;
  if (isNullOrUndefined(summary) || summary === 'none') {
    return '';
  }
  let md = '';
  for (const finding of outcome.findings) {
    if (finding.fixedVersion) {
      continue;
    }
    const links = finding.advisories
      .slice(0, MAX_ADVISORY_LINKS)
      .map(({ id, type }) => `[${id}](${vulnersAdvisoryUrl(type, id)})`);
    const more = finding.advisories.length - MAX_ADVISORY_LINKS;
    if (more > 0) {
      links.push(`and ${more} more`);
    }
    md += `- ${finding.package} ${finding.version} — no fix available: ${links.join(', ')}\n`;
  }
  return md ? `Vulnerable packages without a fix:\n\n${md}\n` : '';
}

function describeOutcome(
  config: RenovateConfig,
  outcome: VulnersOutcome,
): string {
  switch (outcome.status) {
    case 'out-of-credits':
      return `> [!WARNING]\n> Vulners credits for this month are used up; vulnerability checks are paused.\n> ${getVulnersSalesOffer()}\n\n`;
    case 'no-key':
      return 'Add a Vulners API key to `hostRules` to check vulnerabilities with Vulners, see `vulnersVulnerabilityAlerts`.\n\n';
    case 'failed':
      return 'Renovate could not check vulnerabilities with Vulners this run.\n\n';
    case 'no-dependencies':
      return '';
    case 'ok': {
      let md = '';
      if (isWalletLow(outcome.wallet)) {
        md += `> [!NOTE]\n> Vulners credits are running low: ${outcome.wallet.amount} left, ${outcome.wallet.cost} per run.\n> ${getVulnersSalesOffer()}\n\n`;
      }
      return md + listUnfixed(config, outcome);
    }
  }
}

/**
 * The Vulners section of the Dependency Dashboard: credits, key and failures
 * always show when the option is on; packages without a fix follow
 * `dependencyDashboardOSVVulnerabilitySummary`.
 */
export async function getVulnersDashboardMarkdown(
  config: RenovateConfig,
): Promise<string> {
  if (!config.vulnersVulnerabilityAlerts) {
    return '';
  }
  const pending = getVulnersOutcome(config.repository);
  if (!pending) {
    return '';
  }
  const body = describeOutcome(config, await pending);
  return body ? sanitizeMarkdown(`## Vulners\n\n${body}`) : '';
}
