import {
  getManagerConfig,
  mergeChildConfig,
} from '../../../../config/index.ts';
import type { PackageRule, RenovateConfig } from '../../../../config/types.ts';
import { logger } from '../../../../logger/index.ts';
import type { PackageFile } from '../../../../modules/manager/types.ts';
import {
  type VulnersOutcome,
  fetchVulnersAudit,
  isWalletLow,
} from './client.ts';
import { toVulnersPackage } from './purl.ts';
import { type VulnersDependency, buildVulnersPackageRules } from './rules.ts';

// One Vulners call per repository run: lookup() runs once per base branch, and
// the run restarts after an automerge. Not a cache: the next run asks again.
let audit:
  | { repository: string | undefined; outcome: Promise<VulnersOutcome> }
  | undefined;

export function resetVulnersAudit(): void {
  audit = undefined;
}

export function getVulnersOutcome(
  repository: string | undefined,
): Promise<VulnersOutcome> | undefined {
  if (audit && audit.repository === repository) {
    return audit.outcome;
  }
  return undefined;
}

export function collectVulnersDependencies(
  config: RenovateConfig,
  packageFilesList: Record<string, PackageFile[]>[],
): VulnersDependency[] {
  const deps: VulnersDependency[] = [];
  for (const packageFiles of packageFilesList) {
    for (const [manager, files] of Object.entries(packageFiles)) {
      const managerConfig = getManagerConfig(config, manager);
      for (const packageFile of files) {
        const packageFileConfig = mergeChildConfig(managerConfig, packageFile);
        for (const dep of packageFile.deps) {
          // ignored and internal dependencies are not sent to a third party
          if (dep.skipReason) {
            continue;
          }
          const pkg = toVulnersPackage(dep);
          if (pkg) {
            deps.push({
              pkg,
              datasource: dep.datasource!,
              packageName: pkg.name,
              versioning: dep.versioning,
              packageFileConfig,
            });
          }
        }
      }
    }
  }
  return deps;
}

function logOutcome(outcome: VulnersOutcome): void {
  switch (outcome.status) {
    case 'ok':
      logger.debug(
        { findings: outcome.findings.length },
        'Vulners vulnerability check done',
      );
      if (isWalletLow(outcome.wallet)) {
        logger.info(outcome.wallet, 'Vulners credits are running low');
      }
      break;
    case 'no-dependencies':
      logger.debug('No dependencies to check with Vulners');
      break;
    case 'no-key':
      logger.warn(
        { matchHost: 'vulners.com' },
        'No Vulners API key in hostRules - skipping the Vulners check',
      );
      break;
    case 'bad-key':
      logger.warn(
        { matchHost: 'vulners.com' },
        'Vulners rejected the API key in hostRules - skipping the Vulners check',
      );
      break;
    case 'out-of-credits':
      logger.warn('Vulners credits are used up - skipping the Vulners check');
      break;
    case 'failed':
      logger.warn({ reason: outcome.reason }, 'Vulners check failed');
      break;
  }
}

async function auditPackages(
  config: RenovateConfig,
  packageFilesList: Record<string, PackageFile[]>[],
): Promise<VulnersOutcome> {
  try {
    const packages = collectVulnersDependencies(config, packageFilesList).map(
      (dep) => dep.pkg,
    );
    return await fetchVulnersAudit(packages);
  } catch (err) {
    return { status: 'failed', reason: err.message };
  }
}

function startAudit(
  config: RenovateConfig,
  packageFilesList: Record<string, PackageFile[]>[],
): Promise<VulnersOutcome> {
  const existing = getVulnersOutcome(config.repository);
  if (existing) {
    return existing;
  }
  const outcome = auditPackages(config, packageFilesList).then((result) => {
    logOutcome(result);
    return result;
  });
  audit = { repository: config.repository, outcome };
  return outcome;
}

/**
 * Asks Vulners about the dependencies of all base branches at once, before
 * their lookups.
 */
export async function prefetchVulnersAudit(
  config: RenovateConfig,
  packageFilesList: Record<string, PackageFile[]>[],
): Promise<void> {
  if (config.vulnersVulnerabilityAlerts) {
    await startAudit(config, packageFilesList);
  }
}

export async function appendVulnersPackageRules(
  config: RenovateConfig,
  packageFiles: Record<string, PackageFile[]>,
): Promise<void> {
  if (!config.vulnersVulnerabilityAlerts) {
    return;
  }
  const outcome = await startAudit(config, [packageFiles]);
  if (outcome.status !== 'ok') {
    return;
  }
  let rules: PackageRule[];
  try {
    rules = buildVulnersPackageRules(
      collectVulnersDependencies(config, [packageFiles]),
      outcome.findings,
    );
  } catch (err) {
    logger.warn({ err }, 'Vulners check failed - no Vulners rules added');
    return;
  }
  config.packageRules ??= [];
  config.packageRules.push(...rules);
}
