import { beforeEach, describe, expect, it } from 'vitest';

import {
  MemoryStorageBackend,
  StorageManager,
  entryKey,
  findListMatch,
  matchEntry,
  normalizeEntry,
  sanitizeSettings,
  summarizeListStatus,
} from '../src/storage/storageManager.js';
import { DEFAULT_SETTINGS, ENTRY_SOURCE, STORAGE_KEYS } from '../src/shared/constants.js';

/** @returns {StorageManager} */
function makeManager(initial = {}) {
  return new StorageManager({
    backend: new MemoryStorageBackend(initial),
    now: () => '2026-01-01T00:00:00.000Z',
  });
}

describe('sanitizeSettings', () => {
  it('returnează valorile implicite pentru intrări goale sau invalide', () => {
    expect(sanitizeSettings(null)).toEqual(DEFAULT_SETTINGS);
    expect(sanitizeSettings({ warningLevel: 'ceva' }).warningLevel).toBe(DEFAULT_SETTINGS.warningLevel);
    expect(sanitizeSettings({ navigationCheckEnabled: 'da' }).navigationCheckEnabled).toBe(false);
  });

  it('nu activează reputația fără endpoint', () => {
    expect(sanitizeSettings({ reputation: { enabled: true, provider: 'custom_http', endpoint: '' } }).reputation.enabled).toBe(false);
    expect(sanitizeSettings({ reputation: { enabled: true, provider: 'custom_http', endpoint: 'https://x.example/check' } }).reputation.enabled).toBe(true);
  });

  it('limitează timeout-ul la un interval rezonabil', () => {
    expect(sanitizeSettings({ reputation: { timeoutMs: 10 } }).reputation.timeoutMs).toBe(500);
    expect(sanitizeSettings({ reputation: { timeoutMs: 999999 } }).reputation.timeoutMs).toBe(30000);
    expect(sanitizeSettings({ reputation: { timeoutMs: 'abc' } }).reputation.timeoutMs).toBe(DEFAULT_SETTINGS.reputation.timeoutMs);
  });

  it('păstrează setările de confidențialitate implicite', () => {
    expect(sanitizeSettings({}).privacy).toEqual(DEFAULT_SETTINGS.privacy);
    expect(sanitizeSettings({ privacy: { storeLastAnalysis: false } }).privacy.storeLastAnalysis).toBe(false);
  });
});

describe('setări persistate', () => {
  let manager;
  beforeEach(() => {
    manager = makeManager();
  });

  it('citește valorile implicite pe un backend gol', async () => {
    expect(await manager.getSettings()).toEqual(DEFAULT_SETTINGS);
  });

  it('salvează parțial, fără a pierde restul setărilor', async () => {
    await manager.saveSettings({ warningLevel: 'high' });
    const settings = await manager.saveSettings({ navigationCheckEnabled: true });
    expect(settings.warningLevel).toBe('high');
    expect(settings.navigationCheckEnabled).toBe(true);
    expect((await manager.getSettings()).navigationCheckEnabled).toBe(true);
  });
});

describe('normalizeEntry', () => {
  it('validează și completează o intrare', () => {
    const result = normalizeEntry({ host: 'exemplu.ro' }, 'allowlist');
    expect(result.ok).toBe(true);
    expect(result.entry).toMatchObject({
      host: 'exemplu.ro',
      includeSubdomains: false,
      listType: 'allowlist',
      source: ENTRY_SOURCE.USER,
      note: '',
    });
  });

  it('respinge intrările invalide', () => {
    expect(normalizeEntry('exemplu.ro', 'allowlist').ok).toBe(false);
    expect(normalizeEntry({ host: 'invalid' }, 'allowlist').ok).toBe(false);
    expect(normalizeEntry({ host: '' }, 'allowlist').ok).toBe(false);
  });

  it('acceptă intrarea liberă și o normalizează, dar respinge adresele complete în mod strict', () => {
    const loose = normalizeEntry({ host: 'https://Exemplu.ro/path' }, 'allowlist');
    expect(loose.ok).toBe(true);
    expect(loose.entry.host).toBe('exemplu.ro');

    const strict = normalizeEntry({ host: 'https://Exemplu.ro/path' }, 'allowlist', { strict: true });
    expect(strict.ok).toBe(false);
    expect(strict.error).toMatch(/doar domeniul/);

    const strictOk = normalizeEntry({ host: 'exemplu.ro' }, 'allowlist', { strict: true });
    expect(strictOk.ok).toBe(true);
  });

  it('acceptă doar sursele cunoscute', () => {
    expect(normalizeEntry({ host: 'exemplu.ro', source: 'necunoscut' }, 'allowlist').entry.source).toBe(ENTRY_SOURCE.USER);
    expect(normalizeEntry({ host: 'exemplu.ro', source: ENTRY_SOURCE.EXTERNAL }, 'allowlist').entry.source).toBe(ENTRY_SOURCE.EXTERNAL);
  });

  it('limitează lungimea notei', () => {
    const result = normalizeEntry({ host: 'exemplu.ro', note: 'x'.repeat(500) }, 'allowlist');
    expect(result.entry.note.length).toBeLessThanOrEqual(200);
  });
});

describe('operatiuni pe liste', () => {
  let manager;
  beforeEach(() => {
    manager = makeManager();
  });

  it('adaugă o intrare și o persistă', async () => {
    const result = await manager.addEntry('allowlist', 'exemplu.ro');
    expect(result.ok).toBe(true);
    const list = await manager.getList('allowlist');
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({ host: 'exemplu.ro', addedAt: '2026-01-01T00:00:00.000Z' });
  });

  it('detectează duplicatele', async () => {
    await manager.addEntry('allowlist', 'exemplu.ro');
    const duplicate = await manager.addEntry('allowlist', 'https://Exemplu.ro/path');
    expect(duplicate.ok).toBe(false);
    expect(duplicate.duplicate).toBe(true);
    expect(duplicate.error).toMatch(/există deja/);
  });

  it('tratează separat excepția de subdomenii', async () => {
    await manager.addEntry('allowlist', 'www.exemplu.ro');
    await manager.addEntry('allowlist', '*.www.exemplu.ro');
    const list = await manager.getList('allowlist');
    expect(list).toHaveLength(2);
    expect(list.map((e) => e.includeSubdomains).sort()).toEqual([false, true]);
  });

  it('respinge intrările invalide cu un mesaj clar', async () => {
    const result = await manager.addEntry('blocklist', 'nu-e-un-domeniu');
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/punct/);
  });

  it('șterge intrările exacte, păstrând excepția de subdomenii', async () => {
    await manager.addEntry('allowlist', 'exemplu.ro');
    await manager.addEntry('allowlist', '*.exemplu.ro');
    const removed = await manager.removeEntry('allowlist', 'exemplu.ro');
    expect(removed.ok).toBe(true);
    const list = await manager.getList('allowlist');
    expect(list).toHaveLength(1);
    expect(list[0].includeSubdomains).toBe(true);
  });

  it('raportează ștergerea unei intrări inexistente', async () => {
    const result = await manager.removeEntry('allowlist', 'inexistent.ro');
    expect(result.ok).toBe(false);
  });

  it('ignoră intrările corupte și duplicatele din stocare', async () => {
    const manager2 = makeManager({
      [STORAGE_KEYS.ALLOWLIST]: [
        { host: 'bun.ro', includeSubdomains: false, source: 'user', note: '', addedAt: '2026-01-01T00:00:00.000Z' },
        { host: 'bun.ro', includeSubdomains: false, source: 'user', note: '', addedAt: '2026-01-01T00:00:00.000Z' },
        { host: 'invalid host', includeSubdomains: false },
        'text',
        null,
      ],
    });
    const list = await manager2.getList('allowlist');
    expect(list).toHaveLength(1);
    expect(list[0].host).toBe('bun.ro');
  });

  it('filtrează după text și după sursă', async () => {
    await manager.addEntry('allowlist', 'altele.ro', { source: ENTRY_SOURCE.USER, note: 'de la muncă' });
    await manager.addEntry('allowlist', 'extern.ro', { source: ENTRY_SOURCE.EXTERNAL });
    const list = await manager.getList('allowlist');
    expect(StorageManager.filterEntries(list, { query: 'muncă' })).toHaveLength(1);
    expect(StorageManager.filterEntries(list, { source: ENTRY_SOURCE.EXTERNAL })).toHaveLength(1);
    expect(StorageManager.filterEntries(list, { query: 'ALTELE' })).toHaveLength(1);
    expect(StorageManager.filterEntries(list, {})).toHaveLength(2);
  });

  it('anunță ascultătorii la salvare', async () => {
    const events = [];
    const unsubscribe = manager.subscribe((payload) => events.push(payload));
    await manager.addEntry('blocklist', 'rau.example');
    unsubscribe();
    await manager.addEntry('blocklist', 'altrau.example');
    expect(events).toHaveLength(1);
    expect(events[0].event).toBe('blocklist');
  });

  it('șterge totul la resetare', async () => {
    await manager.addEntry('allowlist', 'exemplu.ro');
    await manager.saveSettings({ warningLevel: 'high' });
    await manager.resetAll();
    expect(await manager.getList('allowlist')).toEqual([]);
    expect(await manager.getSettings()).toEqual(DEFAULT_SETTINGS);
  });
});

describe('matchEntry / findListMatch', () => {
  const allowExact = { host: 'exemplu.ro', includeSubdomains: false, source: 'user' };
  const allowSub = { host: 'exemplu.ro', includeSubdomains: true, source: 'user' };
  const blockExact = { host: 'rau.example', includeSubdomains: false, source: 'user' };
  const blockSub = { host: 'rau.example', includeSubdomains: true, source: 'user' };

  it('potrivește exact sau prin subdomeniu, doar când este explicit', () => {
    expect(matchEntry('exemplu.ro', allowExact)).toEqual({ kind: 'exact' });
    expect(matchEntry('www.exemplu.ro', allowExact)).toBeNull();
    expect(matchEntry('www.exemplu.ro', allowSub)).toEqual({ kind: 'subdomain' });
    expect(matchEntry('exemplu.ro.ro', allowSub)).toBeNull();
  });

  it('blocklist-ul are prioritate față de allowlist pentru același host', () => {
    const match = findListMatch('exemplu.ro', { allowlist: [allowSub], blocklist: [allowExact] });
    expect(match.type).toBe('blocklist');
  });

  it('prioritizează potrivirea exactă în cadrul aceleiași liste', () => {
    const subEntry = { host: 'sub.exemplu.ro', includeSubdomains: true, source: 'user' };
    const exactEntry = { host: 'sub.exemplu.ro', includeSubdomains: false, source: 'user' };
    const match = findListMatch('sub.exemplu.ro', { allowlist: [], blocklist: [subEntry, exactEntry] });
    expect(match.matchKind).toBe('exact');
    expect(match.entry).toBe(exactEntry);
  });

  it('returnează null când nu există potrivire', () => {
    expect(findListMatch('necunoscut.example', { allowlist: [allowExact], blocklist: [blockExact] })).toBeNull();
    expect(findListMatch('', { allowlist: [allowExact] })).toBeNull();
  });

  it('summarizeListStatus raportează starea corectă', () => {
    expect(summarizeListStatus('rau.example', { allowlist: [], blocklist: [blockSub] }).status).toBe('blocklisted');
    expect(summarizeListStatus('exemplu.ro', { allowlist: [allowExact], blocklist: [] }).status).toBe('allowlisted');
    expect(summarizeListStatus('alt.example', { allowlist: [allowExact], blocklist: [] }).status).toBe('none');
  });

  it('managerul potrivește host-ul folosind listele curente', async () => {
    const manager = makeManager();
    await manager.addEntry('blocklist', 'rau.example');
    const match = await manager.matchHost('www.rau.example');
    expect(match).toBeNull();
    await manager.addEntry('blocklist', '*.altrau.example');
    expect((await manager.matchHost('www.altrau.example')).type).toBe('blocklist');
  });
});

describe('export / import', () => {
  let manager;
  beforeEach(async () => {
    manager = makeManager();
    await manager.addEntry('allowlist', 'bun.ro');
    await manager.saveSettings({ warningLevel: 'high' });
  });

  it('exportă configurația fără date personale', async () => {
    const config = await manager.exportConfig();
    expect(config.app).toBe('SentinelShield2');
    expect(config.allowlist).toHaveLength(1);
    expect(config.blocklist).toEqual([]);
    expect(config.settings.warningLevel).toBe('high');
    expect(config.exportedAt).toBe('2026-01-01T00:00:00.000Z');
  });

  it('respinge intrările care nu sunt obiect', async () => {
    const report = await manager.importConfig('nu e json');
    expect(report.ok).toBe(false);
    expect(report.error).toMatch(/obiect JSON valid/);
  });

  it('respinge fișierele provenite din altă aplicație', async () => {
    const report = await manager.importConfig({ app: 'Altceva', allowlist: [{ host: 'x.ro' }] });
    expect(report.ok).toBe(false);
    expect(report.error).toMatch(/SentinelShield2/);
  });

  it('respinge versiunile de schemă mai noi', async () => {
    const report = await manager.importConfig({ app: 'SentinelShield2', schemaVersion: 99, allowlist: [{ host: 'x.ro' }] });
    expect(report.ok).toBe(false);
    expect(report.error).toMatch(/versiune/);
  });

  it('raportează un fișier gol sau fără conținut relevant', async () => {
    const report = await manager.importConfig({ app: 'SentinelShield2' });
    expect(report.ok).toBe(false);
    expect(report.error).toMatch(/nu conține/);
  });

  it('importă validând fiecare intrare și raportând ce a fost respins', async () => {
    const report = await manager.importConfig({
      app: 'SentinelShield2',
      schemaVersion: 1,
      allowlist: [{ host: 'nou.ro' }, { host: 'invalid host' }, { host: 'https://alt.ro/path' }, { host: 'bun.ro' }],
      blocklist: [{ host: 'rau.example', note: 'raportat' }],
      settings: { warningLevel: 'moderate' },
    });
    expect(report.ok).toBe(true);
    expect(report.added.allowlist).toBe(1);
    expect(report.added.blocklist).toBe(1);
    expect(report.settingsImported).toBe(true);
    expect(report.skipped).toHaveLength(3);
    expect(report.skipped.map((s) => s.error).join(' ')).toMatch(/valid|doar domeniul|Duplicat/);

    expect((await manager.getList('allowlist')).map((e) => e.host).sort()).toEqual(['bun.ro', 'nou.ro']);
    expect((await manager.getSettings()).warningLevel).toBe('moderate');
  });

  it('poate înlocui complet listele', async () => {
    await manager.importConfig(
      { app: 'SentinelShield2', schemaVersion: 1, allowlist: [{ host: 'doar.ro' }] },
      { mode: 'replace' },
    );
    expect((await manager.getList('allowlist')).map((e) => e.host)).toEqual(['doar.ro']);
  });

  it('marchează intrările importate ca provenind din sursă externă', async () => {
    await manager.importConfig({
      app: 'SentinelShield2',
      schemaVersion: 1,
      allowlist: [{ host: 'extern2.ro', source: ENTRY_SOURCE.EXTERNAL }],
    });
    const list = await manager.getList('allowlist');
    expect(list.find((e) => e.host === 'extern2.ro').source).toBe(ENTRY_SOURCE.EXTERNAL);
  });

  it('exportul poate fi reimportat identic (round-trip)', async () => {
    const config = await manager.exportConfig();
    const fresh = makeManager();
    const report = await fresh.importConfig(config);
    expect(report.ok).toBe(true);
    expect(await fresh.getList('allowlist')).toEqual(await manager.getList('allowlist'));
    expect((await fresh.getSettings()).warningLevel).toBe('high');
  });
});

describe('entryKey', () => {
  it('distinge intrările exacte de cele cu subdomenii', () => {
    expect(entryKey({ host: 'a.ro', includeSubdomains: false })).toBe('a.ro|exact');
    expect(entryKey({ host: 'a.ro', includeSubdomains: true })).toBe('a.ro|sub');
  });
});
