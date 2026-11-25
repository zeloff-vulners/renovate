import type { PackageDependency } from '../../../../modules/manager/types.ts';
import { normalizeName, toVulnersPackage, vulnersKey } from './purl.ts';

function dep(fields: PackageDependency): PackageDependency {
  return fields;
}

describe('workers/repository/process/vulners/purl', () => {
  describe('toVulnersPackage', () => {
    it('normalizes PyPI names', () => {
      expect(
        toVulnersPackage(
          dep({
            datasource: 'pypi',
            packageName: 'Django',
            currentVersion: '3.2.0',
          }),
        ),
      ).toEqual({
        purlType: 'pypi',
        name: 'Django',
        version: '3.2.0',
        purl: 'pkg:pypi/django@3.2.0',
        key: 'pypi:django@3.2.0',
      });
    });

    it('encodes the npm scope', () => {
      expect(
        toVulnersPackage(
          dep({
            datasource: 'npm',
            packageName: '@babel/traverse',
            currentVersion: '7.22.0',
          }),
        )?.purl,
      ).toBe('pkg:npm/%40babel/traverse@7.22.0');
    });

    it('splits Maven group and artifact', () => {
      expect(
        toVulnersPackage(
          dep({
            datasource: 'maven',
            packageName: 'org.apache.logging.log4j:log4j-core',
            currentVersion: '2.14.1',
          }),
        ),
      ).toMatchObject({
        purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
        key: 'maven:org.apache.logging.log4j:log4j-core@2.14.1',
      });
    });

    it('accepts the Clojure group/artifact form', () => {
      expect(
        toVulnersPackage(
          dep({
            datasource: 'clojure',
            packageName: 'org.clojure/clojure',
            currentVersion: '1.11.1',
          }),
        ),
      ).toMatchObject({
        purl: 'pkg:maven/org.clojure/clojure@1.11.1',
        key: 'maven:org.clojure:clojure@1.11.1',
      });
    });

    it('keeps the Go module path', () => {
      expect(
        toVulnersPackage(
          dep({
            datasource: 'go',
            packageName: 'github.com/gin-gonic/gin',
            currentVersion: 'v1.6.0',
          }),
        )?.purl,
      ).toBe('pkg:golang/github.com/gin-gonic/gin@v1.6.0');
    });

    it('lowercases NuGet names in the key', () => {
      expect(
        toVulnersPackage(
          dep({
            datasource: 'nuget',
            packageName: 'Newtonsoft.Json',
            currentVersion: '12.0.1',
          }),
        )?.key,
      ).toBe('nuget:newtonsoft.json@12.0.1');
    });

    it('maps Packagist to composer', () => {
      expect(
        toVulnersPackage(
          dep({
            datasource: 'packagist',
            packageName: 'laravel/framework',
            currentVersion: '8.0.0',
          }),
        )?.purl,
      ).toBe('pkg:composer/laravel/framework@8.0.0');
    });

    it('falls back to depName', () => {
      expect(
        toVulnersPackage(
          dep({
            datasource: 'rubygems',
            depName: 'rails',
            currentVersion: '6.0.0',
          }),
        )?.purl,
      ).toBe('pkg:gem/rails@6.0.0');
    });

    it.each([
      ['npm', '@babel/traverse', '7.22.0'],
      ['maven', 'org.apache.logging.log4j:log4j-core', '2.14.1'],
      ['go', 'github.com/gin-gonic/gin', 'v1.6.0'],
    ])(
      'takes an exact %s currentValue before the lookup set currentVersion',
      (datasource, packageName, currentValue) => {
        expect(
          toVulnersPackage(dep({ datasource, packageName, currentValue }))
            ?.version,
        ).toBe(currentValue);
      },
    );

    it('uses the versioning of the dependency for currentValue', () => {
      expect(
        toVulnersPackage(
          dep({
            datasource: 'npm',
            packageName: 'lodash',
            currentValue: '1.2.3.4',
            versioning: 'loose',
          }),
        )?.version,
      ).toBe('1.2.3.4');
    });

    it('prefers the locked version', () => {
      expect(
        toVulnersPackage(
          dep({
            datasource: 'crate',
            packageName: 'smallvec',
            currentValue: '^1.2',
            lockedVersion: '1.2.3',
          }),
        )?.version,
      ).toBe('1.2.3');
    });

    it.each([
      [
        'an unknown datasource',
        { datasource: 'docker', packageName: 'node', currentVersion: '20' },
      ],
      [
        'the Go toolchain',
        {
          datasource: 'golang-version',
          packageName: 'go',
          currentVersion: '1.22.0',
        },
      ],
      [
        'a range without an exact version',
        { datasource: 'npm', packageName: 'lodash', currentValue: '^4.0.0' },
      ],
      [
        'a Maven name without a group',
        {
          datasource: 'maven',
          packageName: 'log4j-core',
          currentVersion: '2.14.1',
        },
      ],
      ['no name', { datasource: 'hex', currentVersion: '1.0.0' }],
      ['no datasource', { packageName: 'plug', currentVersion: '1.0.0' }],
    ])('skips %s', (_, fields: PackageDependency) => {
      expect(toVulnersPackage(dep(fields))).toBeNull();
    });
  });

  describe('normalizeName', () => {
    it.each([
      ['pypi', 'zope.interface', 'zope-interface'],
      ['pypi', 'Foo__Bar', 'foo-bar'],
      ['composer', 'Laravel/Framework', 'laravel/framework'],
      ['maven', 'org.clojure/clojure', 'org.clojure:clojure'],
      ['npm', '@Scope/Name', '@Scope/Name'],
    ])('%s %s → %s', (purlType, name, expected) => {
      expect(normalizeName(purlType, name)).toBe(expected);
    });
  });

  it('builds the key from the normalized name', () => {
    expect(vulnersKey('pypi', 'Django', '3.2.0')).toBe('pypi:django@3.2.0');
  });
});
