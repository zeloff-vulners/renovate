import * as httpMock from '~test/http-mock.ts';
import * as hostRules from '../../../../util/host-rules.ts';
import { fetchVulnersAudit, toCycloneDx } from './client.ts';
import type { VulnersPackage } from './purl.ts';

const baseUrl = 'https://vulners.com';
const path = '/api/v4/audit/sbom?aiSummary=false';

const django: VulnersPackage = {
  purlType: 'pypi',
  name: 'Django',
  version: '3.2.0',
  purl: 'pkg:pypi/django@3.2.0',
  key: 'pypi:django@3.2.0',
};
const requests: VulnersPackage = {
  purlType: 'pypi',
  name: 'requests',
  version: '2.33.0',
  purl: 'pkg:pypi/requests@2.33.0',
  key: 'pypi:requests@2.33.0',
};

const advisory = {
  id: 'OSV:GHSA-3H9F-R86X-QVJX',
  type: 'osv_ghsa',
  title: 'Django: cache middleware may expose private responses',
  registry: 'pypi',
  cvelist: ['CVE-2026-48588'],
  metrics: { cvss: { score: 3.1, severity: 'LOW', vector: 'CVSS:3.1/AV:N' } },
  epss: [{ cve: 'CVE-2026-48588', epss: 0.00429, percentile: 0.3548 }],
  aiScore: { value: 6.5, uncertainty: 1.1 },
  exploitation: { wildExploited: false },
  match: '=3.2',
};

const okBody = {
  result: {
    data: [
      {
        package: 'django',
        version: '3.2.0',
        fixedVersion: '5.2.17',
        applicableAdvisories: [advisory],
      },
      {
        package: 'requests',
        version: '2.33.0',
        fixedVersion: null,
        applicableAdvisories: [],
      },
    ],
    totalPackages: 2,
  },
};

describe('workers/repository/process/vulners/client', () => {
  beforeEach(() => {
    hostRules.clear();
    hostRules.add({ matchHost: 'vulners.com', token: 'test-key' });
  });

  it('does not ask Vulners about nothing', async () => {
    await expect(fetchVulnersAudit([])).resolves.toEqual({
      status: 'no-dependencies',
    });
  });

  it('needs a key', async () => {
    hostRules.clear();
    await expect(fetchVulnersAudit([django])).resolves.toEqual({
      status: 'no-key',
    });
  });

  it('returns the vulnerable packages with the wallet state', async () => {
    httpMock
      .scope(baseUrl, {
        reqheaders: { 'x-api-key': 'test-key', accept: 'application/json' },
        badheaders: ['authorization'],
      })
      .post(path, (body: string) =>
        body.includes('"purl":"pkg:pypi/django@3.2.0"'),
      )
      .reply(200, okBody, {
        'x-vulners-wallet-cost': '10',
        'x-vulners-wallet-amount': '12616',
      });

    await expect(fetchVulnersAudit([django, requests])).resolves.toEqual({
      status: 'ok',
      findings: [
        {
          key: 'pypi:django@3.2.0',
          package: 'django',
          version: '3.2.0',
          fixedVersion: '5.2.17',
          advisories: [
            {
              id: 'OSV:GHSA-3H9F-R86X-QVJX',
              type: 'osv_ghsa',
              title: 'Django: cache middleware may expose private responses',
              registry: 'pypi',
              cvelist: ['CVE-2026-48588'],
              metrics: {
                cvss: { score: 3.1, severity: 'LOW', vector: 'CVSS:3.1/AV:N' },
              },
              epss: [{ epss: 0.00429, percentile: 0.3548 }],
              aiScore: { value: 6.5 },
              exploitation: { wildExploited: false },
            },
          ],
        },
      ],
      wallet: { cost: 10, amount: 12616 },
    });
  });

  it('has no wallet without the headers', async () => {
    httpMock.scope(baseUrl).post(path).reply(200, okBody);
    const res = await fetchVulnersAudit([django]);
    expect(res).toMatchObject({ status: 'ok' });
    expect(res).not.toHaveProperty('wallet');
  });

  it('tolerates enrichment fields of an unexpected shape', async () => {
    const odd = { ...advisory, aiScore: 'n/a', epss: {}, metrics: [] };
    httpMock
      .scope(baseUrl)
      .post(path)
      .reply(200, {
        result: {
          data: [{ ...okBody.result.data[0], applicableAdvisories: [odd] }],
        },
      });
    const res = await fetchVulnersAudit([django]);
    expect(res).toMatchObject({
      status: 'ok',
      findings: [{ advisories: [{ id: 'OSV:GHSA-3H9F-R86X-QVJX' }] }],
    });
  });

  it('keeps a vulnerable package without a fix', async () => {
    httpMock
      .scope(baseUrl)
      .post(path)
      .reply(200, {
        result: {
          data: [{ ...okBody.result.data[0], fixedVersion: null }],
        },
      });
    await expect(fetchVulnersAudit([django])).resolves.toMatchObject({
      status: 'ok',
      findings: [{ key: 'pypi:django@3.2.0', fixedVersion: null }],
    });
  });

  it('skips an entry whose advisories name no registry', async () => {
    const { registry: _, ...noRegistry } = advisory;
    httpMock
      .scope(baseUrl)
      .post(path)
      .reply(200, {
        result: {
          data: [
            { ...okBody.result.data[0], applicableAdvisories: [noRegistry] },
          ],
        },
      });
    await expect(fetchVulnersAudit([django])).resolves.toEqual({
      status: 'ok',
      findings: [],
    });
  });

  it('reports used-up credits', async () => {
    httpMock.scope(baseUrl).post(path).reply(402, { result: 'error' });
    await expect(fetchVulnersAudit([django])).resolves.toEqual({
      status: 'out-of-credits',
    });
  });

  it.each([
    [403, '<html>Just a moment...</html>'],
    [401, '{"result":"error"}'],
    [500, 'oops'],
  ])('fails on HTTP %d', async (status, body) => {
    httpMock.scope(baseUrl).post(path).reply(status, body);
    const res = await fetchVulnersAudit([django]);
    expect(res).toMatchObject({ status: 'failed' });
    expect(res).toHaveProperty('reason', expect.stringContaining(`${status}`));
  });

  it('fails on a body which is not the expected JSON', async () => {
    httpMock
      .scope(baseUrl)
      .post(path)
      .reply(200, '<html>Just a moment...</html>');
    await expect(fetchVulnersAudit([django])).resolves.toMatchObject({
      status: 'failed',
    });
  });

  it('fails on a network error', async () => {
    httpMock.scope(baseUrl).post(path).replyWithError('ECONNRESET');
    await expect(fetchVulnersAudit([django])).resolves.toMatchObject({
      status: 'failed',
    });
  });

  it('lists each package once in the SBOM', () => {
    const sbom = JSON.parse(toCycloneDx([django, django, requests]));
    expect(sbom).toMatchObject({ bomFormat: 'CycloneDX', specVersion: '1.5' });
    expect(sbom.components).toEqual([
      {
        type: 'library',
        'bom-ref': 'pkg:pypi/django@3.2.0',
        name: 'Django',
        version: '3.2.0',
        purl: 'pkg:pypi/django@3.2.0',
      },
      {
        type: 'library',
        'bom-ref': 'pkg:pypi/requests@2.33.0',
        name: 'requests',
        version: '2.33.0',
        purl: 'pkg:pypi/requests@2.33.0',
      },
    ]);
  });
});
