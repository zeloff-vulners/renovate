import { ClojureDatasource } from '../../../../modules/datasource/clojure/index.ts';
import { getDefaultVersioning } from '../../../../modules/datasource/common.ts';
import { CrateDatasource } from '../../../../modules/datasource/crate/index.ts';
import { GoDatasource } from '../../../../modules/datasource/go/index.ts';
import { HackageDatasource } from '../../../../modules/datasource/hackage/index.ts';
import { HexDatasource } from '../../../../modules/datasource/hex/index.ts';
import { MavenDatasource } from '../../../../modules/datasource/maven/index.ts';
import { NpmDatasource } from '../../../../modules/datasource/npm/index.ts';
import { NugetDatasource } from '../../../../modules/datasource/nuget/index.ts';
import { PackagistDatasource } from '../../../../modules/datasource/packagist/index.ts';
import { PypiDatasource } from '../../../../modules/datasource/pypi/index.ts';
import { RubygemsDatasource } from '../../../../modules/datasource/rubygems/index.ts';
import type { PackageDependency } from '../../../../modules/manager/types.ts';
import { get as getVersioning } from '../../../../modules/versioning/index.ts';
import { regEx } from '../../../../util/regex.ts';

export type VulnersPurlType =
  | 'pypi'
  | 'npm'
  | 'maven'
  | 'golang'
  | 'nuget'
  | 'composer'
  | 'gem'
  | 'cargo'
  | 'hackage'
  | 'hex';

/**
 * Maps Renovate datasource IDs to package-url types understood by Vulners.
 *
 * The Go toolchain (`golang-version`) is left out: how Vulners names the Go
 * standard library is not known.
 *
 * @see https://github.com/package-url/purl-spec/blob/main/PURL-TYPES.rst
 */
export const datasourceToPurlType: Record<string, VulnersPurlType | undefined> =
  {
    [ClojureDatasource.id]: 'maven',
    [CrateDatasource.id]: 'cargo',
    [GoDatasource.id]: 'golang',
    [HackageDatasource.id]: 'hackage',
    [HexDatasource.id]: 'hex',
    [MavenDatasource.id]: 'maven',
    [NpmDatasource.id]: 'npm',
    [NugetDatasource.id]: 'nuget',
    [PackagistDatasource.id]: 'composer',
    [PypiDatasource.id]: 'pypi',
    [RubygemsDatasource.id]: 'gem',
  };

export interface VulnersPackage {
  purlType: VulnersPurlType;
  /** The name as Renovate knows it */
  name: string;
  version: string;
  purl: string;
  /** Matches a dependency to an entry of the Vulners response */
  key: string;
}

/**
 * Brings a package name into the form Vulners answers with.
 */
export function normalizeName(purlType: string, name: string): string {
  switch (purlType) {
    case 'pypi':
      // https://peps.python.org/pep-0503/#normalized-names
      return name.toLowerCase().replace(regEx(/[-_.]+/g), '-');
    case 'nuget':
    case 'composer':
      return name.toLowerCase();
    case 'maven':
      return name.replace('/', ':');
    default:
      return name;
  }
}

export function vulnersKey(
  purlType: string,
  name: string,
  version: string,
): string {
  return `${purlType}:${normalizeName(purlType, name)}@${version}`;
}

function purlPath(purlType: VulnersPurlType, name: string): string | null {
  if (purlType === 'maven') {
    const [group, artifact] = normalizeName(purlType, name).split(':', 2);
    return artifact ? `${group}/${artifact}` : null;
  }
  if (purlType === 'pypi') {
    return normalizeName(purlType, name);
  }
  return name;
}

/**
 * The exact version in use. Vulners is asked before the lookup sets
 * `currentVersion`, so an exact `currentValue` counts too, as for OSV.
 */
function exactVersion(dep: PackageDependency): string | undefined {
  const version = dep.lockedVersion ?? dep.currentVersion;
  if (version || !dep.currentValue) {
    return version;
  }
  const versioning = getVersioning(
    dep.versioning ?? getDefaultVersioning(dep.datasource),
  );
  return versioning.isVersion(dep.currentValue) ? dep.currentValue : undefined;
}

export function toVulnersPackage(
  dep: PackageDependency,
): VulnersPackage | null {
  const purlType = datasourceToPurlType[dep.datasource ?? ''];
  const name = dep.packageName ?? dep.depName;
  const version = exactVersion(dep);
  if (!purlType || !name || !version) {
    return null;
  }

  const path = purlPath(purlType, name);
  if (!path) {
    return null;
  }

  const encodedPath = path.split('/').map(encodeURIComponent).join('/');
  return {
    purlType,
    name,
    version,
    purl: `pkg:${purlType}/${encodedPath}@${encodeURIComponent(version)}`,
    key: vulnersKey(purlType, name, version),
  };
}
