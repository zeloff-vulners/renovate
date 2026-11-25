import { mock } from 'vitest-mock-extended';
import type { RenovateConfig } from '~test/util.ts';
import { getConfig } from '../../config/defaults.ts';
import { renovateRepository } from './index.ts';
import { initRepo } from './init/index.ts';
import type { ExtractResult } from './process/extract-update.ts';
import * as _process from './process/index.ts';
import { resetVulnersAudit } from './process/vulners/index.ts';

const process = vi.mocked(_process);

vi.mock('./init/index.ts');
vi.mock('./process/index.ts');
vi.mock('./result.ts');
vi.mock('./error.ts');
vi.mock('./process/vulners/index.ts');

describe('workers/repository/index', () => {
  describe('renovateRepository()', () => {
    let config: RenovateConfig;

    beforeEach(() => {
      config = getConfig();
      config.localDir = '';
    });

    it('forgets the Vulners outcome of the previous run', async () => {
      vi.mocked(initRepo).mockRejectedValueOnce(new Error('init error'));
      await renovateRepository(config);
      expect(resetVulnersAudit).toHaveBeenCalledOnce();
    });

    it('keeps the Vulners outcome when restarting after an automerge', async () => {
      vi.mocked(initRepo).mockRejectedValueOnce(new Error('init error'));
      await renovateRepository(config, false);
      expect(resetVulnersAudit).not.toHaveBeenCalled();
    });

    it('does not process a repository, but also does not error', async () => {
      process.extractDependencies.mockResolvedValue(mock<ExtractResult>());
      vi.mocked(initRepo).mockRejectedValueOnce(new Error('init error'));
      const res = await renovateRepository(config);
      // this returns `undefined`, as we do not actually process a repository, so no `ProcessResult` is returned
      // but importantly, no errors are thrown, either
      expect(res).toBeUndefined();
    });
  });
});
