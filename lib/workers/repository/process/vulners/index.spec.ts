import { logger } from '~test/util.ts';
import { getConfig } from '../../../../config/defaults.ts';
import type { RenovateConfig } from '../../../../config/types.ts';
import type { PackageFile } from '../../../../modules/manager/types.ts';
import { fetchVulnersAudit } from './client.ts';
import {
  appendVulnersPackageRules,
  collectVulnersDependencies,
  getVulnersOutcome,
  prefetchVulnersAudit,
  resetVulnersAudit,
} from './index.ts';

vi.mock('./client.ts', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./client.ts')>()),
  fetchVulnersAudit: vi.fn(),
}));

const fetchAudit = vi.mocked(fetchVulnersAudit);

function packageFiles(
  ...deps: [string, string | undefined][]
): Record<string, PackageFile[]> {
  return {
    pip_requirements: [
      {
        packageFile: 'requirements.txt',
        deps: deps.map(([packageName, currentVersion]) => ({
          datasource: 'pypi',
          depName: packageName,
          packageName,
          currentVersion,
        })),
      },
    ],
  };
}

const djangoFinding = {
  key: 'pypi:django@3.2.0',
  package: 'django',
  version: '3.2.0',
  fixedVersion: '5.2.17',
  advisories: [
    {
      id: 'OSV:GHSA-1',
      type: 'osv_ghsa',
      metrics: { cvss: { score: 7.5, severity: 'HIGH' } },
    },
  ],
};

let config: RenovateConfig;

describe('workers/repository/process/vulners/index', () => {
  beforeEach(() => {
    resetVulnersAudit();
    config = {
      ...getConfig(),
      repository: 'some/repo',
      vulnersVulnerabilityAlerts: true,
    };
    fetchAudit.mockResolvedValue({ status: 'ok', findings: [djangoFinding] });
  });

  it('does nothing when the option is off', async () => {
    config.vulnersVulnerabilityAlerts = false;
    await prefetchVulnersAudit(config, [packageFiles(['Django', '3.2.0'])]);
    await appendVulnersPackageRules(config, packageFiles(['Django', '3.2.0']));
    expect(fetchAudit).not.toHaveBeenCalled();
    expect(config.packageRules).toBeEmptyArray();
  });

  it('collects the dependencies Vulners understands', () => {
    const deps = collectVulnersDependencies(config, [
      packageFiles(['Django', '3.2.0'], ['flask', undefined]),
    ]);
    expect(deps).toMatchObject([
      {
        pkg: { key: 'pypi:django@3.2.0' },
        datasource: 'pypi',
        packageName: 'Django',
      },
    ]);
  });

  it('adds a rule for a vulnerable dependency', async () => {
    await appendVulnersPackageRules(config, packageFiles(['Django', '3.2.0']));
    expect(config.packageRules).toEqual([
      expect.objectContaining({
        matchPackageNames: ['Django'],
        allowedVersions: '>= 5.2.17',
        isVulnerabilityAlert: true,
      }),
    ]);
  });

  it('asks once for all base branches', async () => {
    await prefetchVulnersAudit(config, [
      packageFiles(['Django', '3.2.0'], ['requests', '2.25.0']),
      packageFiles(['Django', '3.2.0'], ['urllib3', '1.26.0']),
    ]);
    await appendVulnersPackageRules(config, packageFiles(['Django', '3.2.0']));
    await appendVulnersPackageRules(
      config,
      packageFiles(['urllib3', '1.26.0']),
    );

    expect(fetchAudit).toHaveBeenCalledOnce();
    expect(fetchAudit.mock.calls[0][0].map((pkg) => pkg.key)).toEqual([
      'pypi:django@3.2.0',
      'pypi:requests@2.25.0',
      'pypi:django@3.2.0',
      'pypi:urllib3@1.26.0',
    ]);
  });

  it('asks once without a prefetch', async () => {
    await appendVulnersPackageRules(config, packageFiles(['Django', '3.2.0']));
    await appendVulnersPackageRules(config, packageFiles(['Django', '3.2.0']));
    expect(fetchAudit).toHaveBeenCalledOnce();
  });

  it('asks again after a reset', async () => {
    await appendVulnersPackageRules(config, packageFiles(['Django', '3.2.0']));
    resetVulnersAudit();
    await appendVulnersPackageRules(config, packageFiles(['Django', '3.2.0']));
    expect(fetchAudit).toHaveBeenCalledTimes(2);
  });

  it('has no outcome before the first call', () => {
    expect(getVulnersOutcome(undefined)).toBeUndefined();
  });

  it('keeps the outcome of each repository apart', async () => {
    await appendVulnersPackageRules(config, packageFiles(['Django', '3.2.0']));
    expect(getVulnersOutcome('some/repo')).toBeDefined();
    expect(getVulnersOutcome('other/repo')).toBeUndefined();
  });

  it.each([
    [{ status: 'out-of-credits' as const }, 'Vulners credits are used up'],
    [{ status: 'no-key' as const }, 'No Vulners API key'],
    [{ status: 'bad-key' as const }, 'Vulners rejected the API key'],
    [{ status: 'failed' as const, reason: 'HTTP 403' }, 'Vulners check failed'],
  ])('adds no rules and warns on %o', async (outcome, message) => {
    fetchAudit.mockResolvedValueOnce(outcome);
    await appendVulnersPackageRules(config, packageFiles(['Django', '3.2.0']));
    expect(config.packageRules).toBeEmptyArray();
    expect(logger.logger.warn.mock.calls.flat()).toContainEqual(
      expect.stringContaining(message),
    );
  });

  it('warns about used-up credits without an empty context', async () => {
    fetchAudit.mockResolvedValueOnce({ status: 'out-of-credits' });
    await appendVulnersPackageRules(config, packageFiles(['Django', '3.2.0']));
    expect(logger.logger.warn).toHaveBeenCalledWith(
      'Vulners credits are used up - skipping the Vulners check',
    );
  });

  it('turns a throw into a failed check', async () => {
    const broken: Record<string, PackageFile[]> = {
      pip_requirements: [
        {
          packageFile: 'requirements.txt',
          deps: [
            {
              datasource: 'pypi',
              packageName: 'Django',
              currentValue: '3.2.0',
              versioning: 'regex:^(?<major>\\d+',
            },
          ],
        },
      ],
    };
    await expect(
      prefetchVulnersAudit(config, [broken]),
    ).resolves.toBeUndefined();
    await expect(
      appendVulnersPackageRules(config, broken),
    ).resolves.toBeUndefined();
    expect(fetchAudit).not.toHaveBeenCalled();
    expect(config.packageRules).toBeEmptyArray();
    await expect(getVulnersOutcome('some/repo')).resolves.toMatchObject({
      status: 'failed',
    });
    expect(logger.logger.warn).toHaveBeenCalledWith(
      expect.anything(),
      expect.stringContaining('Vulners check failed'),
    );
  });

  it('warns when the rules of a branch can not be built', async () => {
    await prefetchVulnersAudit(config, [packageFiles(['Django', '3.2.0'])]);
    const broken = packageFiles(['Django', undefined]);
    broken.pip_requirements[0].deps[0].currentValue = '3.2.0';
    broken.pip_requirements[0].deps[0].versioning = 'regex:^(?<major>\\d+';
    await expect(
      appendVulnersPackageRules(config, broken),
    ).resolves.toBeUndefined();
    expect(config.packageRules).toBeEmptyArray();
    expect(logger.logger.warn).toHaveBeenCalledWith(
      expect.anything(),
      expect.stringContaining('Vulners check failed'),
    );
  });

  it('does not send skipped dependencies', () => {
    const files = packageFiles(['Django', '3.2.0'], ['internal-lib', '1.0.0']);
    files.pip_requirements[0].deps[1].skipReason = 'internal-package';
    expect(
      collectVulnersDependencies(config, [files]).map((dep) => dep.packageName),
    ).toEqual(['Django']);
  });

  it('stays quiet without dependencies', async () => {
    fetchAudit.mockResolvedValueOnce({ status: 'no-dependencies' });
    await appendVulnersPackageRules(config, {});
    expect(logger.logger.warn).not.toHaveBeenCalled();
  });

  it('tells when the credits run low', async () => {
    fetchAudit.mockResolvedValueOnce({
      status: 'ok',
      findings: [],
      wallet: { cost: 10, amount: 100 },
    });
    await appendVulnersPackageRules(config, packageFiles(['Django', '3.2.0']));
    expect(logger.logger.info).toHaveBeenCalledWith(
      { cost: 10, amount: 100 },
      expect.stringContaining('Vulners credits are running low'),
    );
  });
});
