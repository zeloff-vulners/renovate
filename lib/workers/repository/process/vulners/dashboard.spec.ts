import type { RenovateConfig } from '../../../../config/types.ts';
import type { VulnersOutcome } from './client.ts';
import { getVulnersDashboardMarkdown } from './dashboard.ts';
import { getVulnersOutcome } from './index.ts';

vi.mock('./index.ts');

const outcome = vi.mocked(getVulnersOutcome);

function withOutcome(result: VulnersOutcome): void {
  outcome.mockReturnValue(Promise.resolve(result));
}

const unfixed: VulnersOutcome = {
  status: 'ok',
  findings: [
    {
      key: 'pypi:django@3.2.0',
      package: 'django',
      version: '3.2.0',
      fixedVersion: null,
      advisories: [{ id: 'OSV:GHSA-1', type: 'osv_ghsa' }],
    },
    {
      key: 'pypi:requests@2.25.0',
      package: 'requests',
      version: '2.25.0',
      fixedVersion: '2.33.0',
      advisories: [{ id: 'OSV:GHSA-2', type: 'osv_ghsa' }],
    },
  ],
};

let config: RenovateConfig;

describe('workers/repository/process/vulners/dashboard', () => {
  beforeEach(() => {
    config = { repository: 'some/repo', vulnersVulnerabilityAlerts: true };
  });

  it('is empty when the option is off', async () => {
    config.vulnersVulnerabilityAlerts = false;
    withOutcome({ status: 'out-of-credits' });
    await expect(getVulnersDashboardMarkdown(config)).resolves.toBe('');
  });

  it('is empty when Vulners was not asked this run', async () => {
    outcome.mockReturnValue(undefined);
    await expect(getVulnersDashboardMarkdown(config)).resolves.toBe('');
  });

  it('says the checks are paused when the credits are used up', async () => {
    withOutcome({ status: 'out-of-credits' });
    const md = await getVulnersDashboardMarkdown(config);
    expect(md).toStartWith('## Vulners\n\n');
    expect(md).toContain(
      'Vulners credits for this month are used up; vulnerability checks are paused.',
    );
    expect(md).not.toContain('vulners.com/contact');
    expect(md).not.toContain('license');
  });

  it('warns when the credits run low', async () => {
    withOutcome({
      status: 'ok',
      findings: [],
      wallet: { cost: 10, amount: 200 },
    });
    const md = await getVulnersDashboardMarkdown(config);
    expect(md).toContain('Vulners credits are running low');
    expect(md).not.toContain('vulners.com/contact');
    expect(md).not.toContain('license');
  });

  it('says nothing about enough credits', async () => {
    withOutcome({
      status: 'ok',
      findings: [],
      wallet: { cost: 10, amount: 240 },
    });
    await expect(getVulnersDashboardMarkdown(config)).resolves.toBe('');
  });

  it('asks for a key', async () => {
    withOutcome({ status: 'no-key' });
    const md = await getVulnersDashboardMarkdown(config);
    expect(md).toContain('Add a Vulners API key to `hostRules`');
  });

  it('reports a rejected key', async () => {
    withOutcome({ status: 'bad-key' });
    const md = await getVulnersDashboardMarkdown(config);
    expect(md).toContain('Vulners rejected the API key in `hostRules`');
  });

  it('reports a failed check', async () => {
    withOutcome({ status: 'failed', reason: 'HTTP 403' });
    const md = await getVulnersDashboardMarkdown(config);
    expect(md).toContain(
      'Renovate could not check vulnerabilities with Vulners this run.',
    );
  });

  it('is empty without dependencies', async () => {
    withOutcome({ status: 'no-dependencies' });
    await expect(getVulnersDashboardMarkdown(config)).resolves.toBe('');
  });

  it.each(['all', 'unresolved'] as const)(
    'lists vulnerable packages without a fix for %s',
    async (summary) => {
      config.dependencyDashboard = { osvVulnerabilitySummary: summary };
      withOutcome(unfixed);
      const md = await getVulnersDashboardMarkdown(config);
      expect(md).toContain(
        '- django 3.2.0 — no fix available: [OSV:GHSA-1](https://vulners.com/osv_ghsa/OSV:GHSA-1)',
      );
      expect(md).not.toContain('requests');
    },
  );

  it('links a few advisories of a package without a fix', async () => {
    config.dependencyDashboard = { osvVulnerabilitySummary: 'all' };
    withOutcome({
      status: 'ok',
      findings: [
        {
          ...unfixed.findings[0],
          advisories: Array.from({ length: 7 }, (_, i) => ({
            id: `ID-${i}`,
            type: 'osv_ghsa',
          })),
        },
      ],
    });
    const md = await getVulnersDashboardMarkdown(config);
    expect(md).toContain('[ID-4]');
    expect(md).not.toContain('[ID-5]');
    expect(md).toContain('and 2 more');
  });

  it('is empty when every vulnerable package has a fix', async () => {
    config.dependencyDashboard = { osvVulnerabilitySummary: 'all' };
    withOutcome({ status: 'ok', findings: [unfixed.findings[1]] });
    await expect(getVulnersDashboardMarkdown(config)).resolves.toBe('');
  });

  it('does not list packages without a fix when the summary is off', async () => {
    config.dependencyDashboard = { osvVulnerabilitySummary: 'none' };
    withOutcome({ ...unfixed, wallet: { cost: 10, amount: 1 } });
    const md = await getVulnersDashboardMarkdown(config);
    expect(md).not.toContain('no fix available');
    expect(md).toContain('Vulners credits are running low');
  });
});
