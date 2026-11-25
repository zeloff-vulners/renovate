import type { PackageRule, RenovateConfig } from '../../../../config/types.ts';
import { getDefaultVersioning } from '../../../../modules/datasource/common.ts';
import { coerceArray } from '../../../../util/array.ts';
import { sanitizeMarkdown } from '../../../../util/markdown.ts';
import { regEx } from '../../../../util/regex.ts';
import { titleCase } from '../../../../util/string.ts';
import {
  getFixedVersionConstraint,
  getHighestVulnerabilitySeverity,
} from '../../../../util/vulnerability/utils.ts';
import type { VulnersFinding } from './client.ts';
import type { VulnersPackage } from './purl.ts';
import type { VulnersAdvisory } from './schema.ts';

/** Pull requests list at most this many advisories per package in full. */
export const MAX_ADVISORIES_IN_PR = 10;

export interface VulnersDependency {
  pkg: VulnersPackage;
  datasource: string;
  packageName: string;
  versioning?: string;
  packageFileConfig: RenovateConfig;
}

export function vulnersAdvisoryUrl(type: string, id: string): string {
  return `https://vulners.com/${type}/${id}`;
}

export function vulnersCveUrl(cve: string): string {
  return `https://vulners.com/cve/${cve}`;
}

function cvssScore(advisory: VulnersAdvisory): number {
  return advisory.metrics?.cvss?.score ?? -1;
}

function worstSeverity(advisories: VulnersAdvisory[]): string {
  let severity: string | undefined;
  for (const advisory of advisories) {
    const current = advisory.metrics?.cvss?.severity;
    if (current) {
      severity = getHighestVulnerabilitySeverity(
        { vulnerabilitySeverity: severity },
        { vulnerabilitySeverity: current },
      );
    }
  }
  return severity ?? 'UNKNOWN';
}

function describeAdvisory(advisory: VulnersAdvisory): string {
  const links = [
    `[${advisory.id}](${vulnersAdvisoryUrl(advisory.type, advisory.id)})`,
    ...coerceArray(advisory.cvelist).map(
      (cve) => `[${cve}](${vulnersCveUrl(cve)})`,
    ),
  ];

  let content = '\n\n---\n\n';
  content += `### ${advisory.title ?? advisory.id}\n`;
  content += `${links.join(' / ')}\n`;
  if (advisory.exploitation?.wildExploited) {
    content += '\n**Exploited in the wild**\n';
  }
  content += '\n<details>\n<summary>More information</summary>\n';

  const details = advisory.description?.replace(regEx(/^#{1,4} /gm), '##### ');
  content += `#### Details\n${details ?? 'No details.'}\n`;

  content += '#### Severity\n';
  const cvss = advisory.metrics?.cvss;
  if (cvss?.score !== undefined) {
    const severity = cvss.severity ? ` (${titleCase(cvss.severity)})` : '';
    content += `- CVSS Score: ${cvss.score.toFixed(1)} / 10${severity}\n`;
  }
  if (cvss?.vector) {
    content += `- Vector String: \`${cvss.vector}\`\n`;
  }
  const epss = advisory.epss?.[0]?.epss;
  if (epss !== undefined) {
    content += `- EPSS: ${(epss * 100).toFixed(2)}%\n`;
  }
  if (advisory.aiScore) {
    content += `- AI Score: ${advisory.aiScore.value}\n`;
  }

  content += '\nData provided by [Vulners](https://vulners.com).\n';
  content += '</details>';
  return sanitizeMarkdown(content);
}

export function generateVulnersPrBodyNotes(
  advisories: VulnersAdvisory[],
): string[] {
  const sorted = [...advisories].sort((a, b) => cvssScore(b) - cvssScore(a));
  const notes = sorted.slice(0, MAX_ADVISORIES_IN_PR).map(describeAdvisory);
  const rest = sorted.length - MAX_ADVISORIES_IN_PR;
  if (rest > 0) {
    notes.push(`\n\n…and ${rest} more advisories.`);
  }
  return notes;
}

function fixedVersionFor(dep: VulnersDependency, fixedVersion: string): string {
  // Vulners answers Go fixes without the `v` the module versions carry
  if (
    dep.pkg.purlType === 'golang' &&
    dep.pkg.version.startsWith('v') &&
    !fixedVersion.startsWith('v')
  ) {
    return `v${fixedVersion}`;
  }
  return fixedVersion;
}

export function buildVulnersPackageRules(
  deps: VulnersDependency[],
  findings: VulnersFinding[],
): PackageRule[] {
  const byKey = new Map(findings.map((finding) => [finding.key, finding]));
  const seen = new Set<string>();
  const rules: PackageRule[] = [];

  for (const dep of deps) {
    const finding = byKey.get(dep.pkg.key);
    if (!finding?.fixedVersion) {
      continue;
    }
    const ruleKey = `${dep.datasource}:${dep.packageName}@${dep.pkg.version}`;
    if (seen.has(ruleKey)) {
      continue;
    }
    seen.add(ruleKey);

    const fixedVersion = fixedVersionFor(dep, finding.fixedVersion);
    rules.push({
      matchDatasources: [dep.datasource],
      matchPackageNames: [dep.packageName],
      matchCurrentVersion: dep.pkg.version,
      versioning: dep.versioning ?? getDefaultVersioning(dep.datasource),
      allowedVersions: getFixedVersionConstraint(fixedVersion, dep.datasource),
      isVulnerabilityAlert: true,
      vulnerabilitySeverity: worstSeverity(finding.advisories),
      prBodyNotes: generateVulnersPrBodyNotes(finding.advisories),
      force: {
        ...dep.packageFileConfig.vulnerabilityAlerts,
      },
    });
  }
  return rules;
}
