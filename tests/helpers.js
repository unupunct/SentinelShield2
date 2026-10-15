import { readFileSync } from 'node:fs';
import { analyzeUrl } from '../src/lib/url-analyzer.js';
import { evaluate } from '../src/lib/risk-engine.js';
import { createLocalLists, createReputationService } from '../src/lib/reputation.js';
import { DEFAULT_CONFIG, validateConfig } from '../src/lib/config.js';

export const bundled = JSON.parse(readFileSync(new URL('../data/blocklist.json', import.meta.url), 'utf8'));
export const cfg = validateConfig(DEFAULT_CONFIG);
export function makeLists() { const l = createLocalLists(); l.setBundled(bundled); return l; }
export function assess(url, { lists = makeLists(), online = [], config = cfg, exception = null } = {}) {
  const analysis = analyzeUrl(url);
  const svc = createReputationService({ fetchImpl: async () => { throw new Error('rețea interzisă în teste'); }, lists });
  const local = svc.checkLocal(analysis);
  return { analysis, result: evaluate({ analysis, reputation: [local, ...online], config, exception }) };
}
export const codes = (r) => r.indicators.map((i) => i.code);
