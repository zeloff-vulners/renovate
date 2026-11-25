import type { RenovateConfig } from '../../../../config/types.ts';
import type { VulnersFinding } from './client.ts';
import { toVulnersPackage } from './purl.ts';
import {
  MAX_ADVISORIES_IN_PR,
  type VulnersDependency,
  buildVulnersPackageRules,
  generateVulnersPrBodyNotes,
  vulnersAdvisoryUrl,
  vulnersCveUrl,
} from './rules.ts';
import type { VulnersAdvisory } from './schema.ts';

const packageFileConfig: RenovateConfig = {
  vulnerabilityAlerts: { labels: ['security'] },
};

function dependency(
  datasource: string,
  packageName: string,
  currentVersion: string,
): VulnersDependency {
  return {
    pkg: toVulnersPackage({ datasource, packageName, currentVersion })!,
    datasource,
    packageName,
    packageFileConfig,
  };
}

function advisory(fields: Partial<VulnersAdvisory> = {}): VulnersAdvisory {
  return {
    id: 'OSV:GHSA-3H9F-R86X-QVJX',
    type: 'osv_ghsa',
    title: 'Django: cache middleware may expose private responses',
    description: '## Impact\nPrivate responses may be cached.',
    registry: 'pypi',
    cvelist: ['CVE-2026-48588'],
    metrics: {
      cvss: { score: 7.5, severity: 'HIGH', vector: 'CVSS:3.1/AV:N' },
    },
    epss: [{ epss: 0.00429, percentile: 0.3548 }],
    aiScore: { value: 6.5 },
    exploitation: { wildExploited: false },
    ...fields,
  };
}

function finding(
  key: string,
  fixedVersion: string | null,
  advisories: VulnersAdvisory[] = [advisory()],
): VulnersFinding {
  return { key, package: '', version: '', fixedVersion, advisories };
}

describe('workers/repository/process/vulners/rules', () => {
  describe('buildVulnersPackageRules', () => {
    it('builds a vulnerability rule', () => {
      const rules = buildVulnersPackageRules(
        [dependency('pypi', 'Django', '3.2.0')],
        [finding('pypi:django@3.2.0', '5.2.17')],
      );
      expect(rules).toEqual([
        {
          matchDatasources: ['pypi'],
          matchPackageNames: ['Django'],
          matchCurrentVersion: '3.2.0',
          versioning: 'pep440',
          allowedVersions: '>= 5.2.17',
          isVulnerabilityAlert: true,
          vulnerabilitySeverity: 'HIGH',
          prBodyNotes: [expect.any(String)],
          force: { labels: ['security'] },
        },
      ]);
    });

    it('prefers the versioning of the dependency', () => {
      const dep = dependency('pypi', 'Django', '3.2.0');
      dep.versioning = 'loose';
      const [rule] = buildVulnersPackageRules(
        [dep],
        [finding('pypi:django@3.2.0', '5.2.17')],
      );
      expect(rule.versioning).toBe('loose');
    });

    it.each([
      [
        'maven',
        'org.apache.logging.log4j:log4j-core',
        '2.14.1',
        '2.25.4',
        '[2.25.4,)',
      ],
      ['nuget', 'Newtonsoft.Json', '12.0.1', '13.0.1', '[13.0.1,)'],
      ['go', 'github.com/gin-gonic/gin', 'v1.6.0', '1.9.1', '>= v1.9.1'],
      ['go', 'example.com/mod', '1.6.0', '1.9.1', '>= 1.9.1'],
    ])(
      '%s %s %s fixed in %s → %s',
      (datasource, packageName, version, fixedVersion, allowedVersions) => {
        const dep = dependency(datasource, packageName, version);
        const [rule] = buildVulnersPackageRules(
          [dep],
          [finding(dep.pkg.key, fixedVersion)],
        );
        expect(rule.allowedVersions).toBe(allowedVersions);
      },
    );

    it('uses the Maven range for Clojure', () => {
      const dep = dependency('clojure', 'io.netty/netty-all', '4.1.100.Final');
      const [rule] = buildVulnersPackageRules(
        [dep],
        [finding(dep.pkg.key, '4.1.108.Final')],
      );
      expect(rule.allowedVersions).toBe('[4.1.108.Final,)');
    });

    it('makes no rule from a fix the versioning can not express', () => {
      const dep = dependency('hackage', 'aeson', '2.1.0.0');
      expect(
        buildVulnersPackageRules([dep], [finding(dep.pkg.key, '2.1.2.1')]),
      ).toEqual([]);
    });

    it('makes no rule without a fix', () => {
      expect(
        buildVulnersPackageRules(
          [dependency('pypi', 'Django', '3.2.0')],
          [finding('pypi:django@3.2.0', null)],
        ),
      ).toEqual([]);
    });

    it('makes no rule for a clean dependency', () => {
      expect(
        buildVulnersPackageRules(
          [dependency('pypi', 'requests', '2.33.0')],
          [],
        ),
      ).toEqual([]);
    });

    it('makes one rule for a dependency found in several package files', () => {
      expect(
        buildVulnersPackageRules(
          [
            dependency('pypi', 'Django', '3.2.0'),
            dependency('pypi', 'Django', '3.2.0'),
          ],
          [finding('pypi:django@3.2.0', '5.2.17')],
        ),
      ).toHaveLength(1);
    });

    it('takes the worst severity', () => {
      const [rule] = buildVulnersPackageRules(
        [dependency('pypi', 'Django', '3.2.0')],
        [
          finding('pypi:django@3.2.0', '5.2.17', [
            advisory({ metrics: { cvss: { score: 3.1, severity: 'low' } } }),
            advisory({
              metrics: { cvss: { score: 9.8, severity: 'CRITICAL' } },
            }),
            advisory({ metrics: undefined }),
          ]),
        ],
      );
      expect(rule.vulnerabilitySeverity).toBe('CRITICAL');
    });

    it('has an unknown severity without CVSS', () => {
      const [rule] = buildVulnersPackageRules(
        [dependency('pypi', 'Django', '3.2.0')],
        [
          finding('pypi:django@3.2.0', '5.2.17', [
            advisory({ metrics: undefined }),
          ]),
        ],
      );
      expect(rule.vulnerabilitySeverity).toBe('UNKNOWN');
    });
  });

  describe('generateVulnersPrBodyNotes', () => {
    it('describes an advisory', () => {
      const [note] = generateVulnersPrBodyNotes([advisory()]);
      expect(note).toContain(
        '### Django: cache middleware may expose private responses',
      );
      expect(note).toContain(
        '[OSV:GHSA-3H9F-R86X-QVJX](https://vulners.com/osv_ghsa/OSV:GHSA-3H9F-R86X-QVJX)',
      );
      expect(note).toContain(
        '[CVE-2026-48588](https://vulners.com/cve/CVE-2026-48588)',
      );
      expect(note).toContain('- CVSS Score: 7.5 / 10 (High)');
      expect(note).toContain('- Vector String: `CVSS:3.1/AV:N`');
      expect(note).toContain('- EPSS: 0.43%');
      expect(note).toContain('- AI Score: 6.5');
      expect(note).not.toContain('Exploited in the wild');
      expect(note).toContain('<details>');
      expect(note).toContain('##### Impact');
      expect(note).toContain('Data provided by [Vulners](https://vulners.com)');
    });

    it('flags exploitation in the wild', () => {
      const [note] = generateVulnersPrBodyNotes([
        advisory({ exploitation: { wildExploited: true } }),
      ]);
      expect(note).toContain('Exploited in the wild');
    });

    it('falls back to the id and leaves out missing data', () => {
      const [note] = generateVulnersPrBodyNotes([
        advisory({
          title: undefined,
          description: undefined,
          cvelist: undefined,
          metrics: undefined,
          epss: undefined,
          aiScore: undefined,
        }),
      ]);
      expect(note).toContain('### OSV:GHSA-3H9F-R86X-QVJX');
      expect(note).toContain('No details.');
      expect(note).not.toContain('CVSS Score');
      expect(note).not.toContain('EPSS');
      expect(note).not.toContain('AI Score');
    });

    it('puts the worst advisories first and caps the list', () => {
      const advisories = Array.from({ length: 12 }, (_, i) =>
        advisory({ id: `ID-${i}`, metrics: { cvss: { score: i } } }),
      );
      const notes = generateVulnersPrBodyNotes(advisories);
      expect(notes).toHaveLength(MAX_ADVISORIES_IN_PR + 1);
      expect(notes[0]).toContain('[ID-11]');
      expect(notes[9]).toContain('[ID-2]');
      expect(notes[10]).toContain('…and 2 more advisories');
    });
  });

  it('formats the links in one place', () => {
    expect(vulnersAdvisoryUrl('osv_ghsa', 'OSV:GHSA-1')).toBe(
      'https://vulners.com/osv_ghsa/OSV:GHSA-1',
    );
    expect(vulnersCveUrl('CVE-2021-44228')).toBe(
      'https://vulners.com/cve/CVE-2021-44228',
    );
  });
});
