/**
 * SentinelShield2 - storageManager.
 *
 * Gestionează:
 * - setările utilizatorului (cu valori implicite sigure: totul local);
 * - allowlist / blocklist (adăugare, ștergere, căutare, import/export);
 * - politica de potrivire a domeniilor (prioritatea listelor).
 *
 * Backend-ul este injectabil. În extensie se folosește `chrome.storage.local`;
 * în teste se folosește un backend în memorie. Astfel logica de liste poate fi
 * testată complet fără un browser.
 */

import {
  DEFAULT_SETTINGS,
  ENTRY_SOURCE,
  LIST_TYPES,
  STORAGE_KEYS,
  STORAGE_SCHEMA_VERSION,
} from '../shared/constants.js';
import { isPlainObject, normalizeDomainEntry, truncate } from '../shared/validators.js';

/** Lungimea maximă a unei note atașate unei intrări de listă. */
export const MAX_NOTE_LENGTH = 200;

/**
 * Backend de stocare în memorie, folosit în teste și ca rezervă.
 */
export class MemoryStorageBackend {
  constructor(initial = {}) {
    this.data = new Map(Object.entries(initial));
  }

  async get(keys) {
    const result = {};
    for (const key of [].concat(keys)) {
      if (this.data.has(key)) result[key] = this.data.get(key);
    }
    return result;
  }

  async set(items) {
    for (const [key, value] of Object.entries(items)) {
      this.data.set(key, value);
    }
  }

  async remove(keys) {
    for (const key of [].concat(keys)) this.data.delete(key);
  }
}

/**
 * Backend bazat pe chrome.storage.local.
 * Este evaluat leneș, pentru ca modulele să poată fi importate în Node.
 */
export class ChromeStorageBackend {
  constructor(area = null) {
    this.area = area ?? (typeof chrome !== 'undefined' && chrome.storage ? chrome.storage.local : null);
    if (!this.area) {
      throw new Error('chrome.storage.local nu este disponibil în acest context.');
    }
  }

  async get(keys) {
    return this.area.get(keys);
  }

  async set(items) {
    return this.area.set(items);
  }

  async remove(keys) {
    return this.area.remove(keys);
  }
}

/**
 * Normalizează o intrare de listă primită din stocare sau dintr-un import.
 * @param {unknown} value
 * @param {'allowlist'|'blocklist'} listType
 * @param {{ strict?: boolean }} [options] în modul strict, `host` trebuie să fie
 *   deja un domeniu canonic (fără cale, credențiale sau caractere Unicode).
 *   Este folosit la citirea din stocare și la import, unde intrările trebuie
 *   să fie deja normalizate; intrarea liberă a utilizatorului este permisă
 *   doar prin `addEntry`.
 * @returns {{ ok: true, entry: object } | { ok: false, error: string }}
 */
export function normalizeEntry(value, listType, options = {}) {
  if (!isPlainObject(value)) {
    return { ok: false, error: 'Intrarea nu este obiect.' };
  }
  const rawHost = typeof value.host === 'string' ? value.host : '';
  const normalized = normalizeDomainEntry(rawHost);
  if (!normalized.ok) return { ok: false, error: normalized.error };

  if (options.strict === true) {
    const canonicalInput = rawHost.trim().replace(/^\*\./, '').toLowerCase().replace(/\.$/, '');
    if (canonicalInput !== normalized.host) {
      return {
        ok: false,
        error: `Intrarea "${truncate(rawHost, 40)}" trebuie să conțină doar domeniul (fără cale, parametri, credențiale sau caractere Unicode).`,
      };
    }
  }

  const includeSubdomains = value.includeSubdomains === true;

  const source = Object.values(ENTRY_SOURCE).includes(value.source) ? value.source : ENTRY_SOURCE.USER;
  const note = typeof value.note === 'string' ? truncate(value.note.trim(), MAX_NOTE_LENGTH) : '';
  const addedAt = typeof value.addedAt === 'string' && !Number.isNaN(Date.parse(value.addedAt))
    ? value.addedAt
    : new Date(0).toISOString();

  return {
    ok: true,
    entry: {
      host: normalized.host,
      includeSubdomains: includeSubdomains || normalized.includeSubdomains,
      listType,
      source,
      note,
      addedAt,
    },
  };
}

/**
 * Cheia de deduplicare a unei intrări.
 * @param {object} entry
 * @returns {string}
 */
export function entryKey(entry) {
  return `${entry.host}|${entry.includeSubdomains ? 'sub' : 'exact'}`;
}

/**
 * Verifică dacă un host corespunde unei intrări de listă.
 * @param {string} host
 * @param {object} entry
 * @returns {{ kind: 'exact'|'subdomain' } | null}
 */
export function matchEntry(host, entry) {
  const target = String(host ?? '').toLowerCase();
  if (target === '') return null;
  if (target === entry.host) return { kind: 'exact' };
  if (entry.includeSubdomains && target.endsWith(`.${entry.host}`)) return { kind: 'subdomain' };
  return null;
}

/**
 * Găsește potrivirea relevantă pentru un host, aplicând prioritatea listelor.
 *
 * Prioritate (documentată și testată):
 * 1. blocklist potrivire exactă;
 * 2. blocklist potrivire de subdomeniu (dacă intrarea are `includeSubdomains`);
 * 3. allowlist potrivire exactă;
 * 4. allowlist potrivire de subdomeniu (dacă intrarea are `includeSubdomains`).
 *
 * Blocklist-ul are întotdeauna prioritate față de allowlist pentru același host.
 *
 * @param {string} host
 * @param {{ allowlist?: object[], blocklist?: object[] }} lists
 * @returns {{ type: 'allowlist'|'blocklist', entry: object, matchedHost: string, matchKind: 'exact'|'subdomain' } | null}
 */
export function findListMatch(host, lists = {}) {
  const target = String(host ?? '').toLowerCase();
  if (target === '') return null;
  const allowlist = Array.isArray(lists.allowlist) ? lists.allowlist : [];
  const blocklist = Array.isArray(lists.blocklist) ? lists.blocklist : [];
  const ordered = [
    ['blocklist', blocklist],
    ['allowlist', allowlist],
  ];
  for (const [type, entries] of ordered) {
    const valid = entries.filter((entry) => entry && typeof entry.host === 'string');
    // Prioritate în cadrul aceleiași liste: domeniu exact, apoi domeniu exact cu
    // excepție de subdomenii, apoi potrivire de subdomeniu.
    const hit = valid.find((entry) => entry.host === target && entry.includeSubdomains !== true)
      ?? valid.find((entry) => entry.host === target && entry.includeSubdomains === true)
      ?? valid.find((entry) => entry.includeSubdomains === true && target.endsWith(`.${entry.host}`));
    if (hit) {
      return {
        type,
        entry: hit,
        matchedHost: hit.host,
        matchKind: hit.host === target ? 'exact' : 'subdomain',
      };
    }
  }
  return null;
}

/**
 * Validare structurală a setărilor citite din stocare sau importate.
 * @param {unknown} value
 * @returns {object} setări valide, completate cu valorile implicite
 */
export function sanitizeSettings(value) {
  const input = isPlainObject(value) ? value : {};
  const reputationInput = isPlainObject(input.reputation) ? input.reputation : {};
  const privacyInput = isPlainObject(input.privacy) ? input.privacy : {};

  const warningLevel = ['none', 'low', 'moderate', 'high', 'confirmed_dangerous']
    .includes(input.warningLevel)
    ? input.warningLevel
    : DEFAULT_SETTINGS.warningLevel;

  const timeoutRaw = Number(reputationInput.timeoutMs);
  const timeoutMs = Number.isFinite(timeoutRaw) ? Math.min(30000, Math.max(500, timeoutRaw)) : DEFAULT_SETTINGS.reputation.timeoutMs;

  const provider = typeof reputationInput.provider === 'string' ? reputationInput.provider : DEFAULT_SETTINGS.reputation.provider;
  const endpoint = typeof reputationInput.endpoint === 'string' ? reputationInput.endpoint.slice(0, 2048) : '';
  const apiKey = typeof reputationInput.apiKey === 'string' ? reputationInput.apiKey.slice(0, 512) : '';

  return {
    schemaVersion: STORAGE_SCHEMA_VERSION,
    warningLevel,
    navigationCheckEnabled: input.navigationCheckEnabled === true,
    reputation: {
      enabled: reputationInput.enabled === true && endpoint !== '',
      provider,
      endpoint,
      timeoutMs,
      hostnameOnly: reputationInput.hostnameOnly !== false,
      confirmMalicious: reputationInput.confirmMalicious === true,
      apiKey,
    },
    privacy: {
      storeLastAnalysis: privacyInput.storeLastAnalysis !== false,
      redactQueryInEvidence: privacyInput.redactQueryInEvidence !== false,
    },
  };
}

/**
 * Managerul propriu-zis.
 */
export class StorageManager {
  /**
   * @param {{ backend?: object, now?: () => string }} [options]
   */
  constructor(options = {}) {
    this.backend = options.backend ?? null;
    this.now = options.now ?? (() => new Date().toISOString());
    this.listeners = new Set();
  }

  /** @returns {object} backend-ul activ (aruncă dacă nu există) */
  requireBackend() {
    if (!this.backend) {
      throw new Error('StorageManager nu are un backend configurat.');
    }
    return this.backend;
  }

  /**
   * Înregistrează un ascultător pentru schimbările de liste/setări (folosit de UI).
   * @param {(payload: object) => void} listener
   * @returns {() => void} funcția de dezabonare
   */
  subscribe(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /** @param {string} event @param {object} payload */
  notify(event, payload) {
    for (const listener of this.listeners) {
      try {
        listener({ event, ...payload });
      } catch {
        // Ascultătorii defectuoși nu trebuie să blocheze stocarea.
      }
    }
  }

  /**
   * Citește setările, completate cu valorile implicite.
   * @returns {Promise<object>}
   */
  async getSettings() {
    const backend = this.requireBackend();
    const stored = await backend.get(STORAGE_KEYS.SETTINGS);
    return sanitizeSettings(stored?.[STORAGE_KEYS.SETTINGS]);
  }

  /**
   * Salvează setări parțiale (merge cu cele existente, apoi validare).
   * @param {object} patch
   * @returns {Promise<object>} setările rezultate
   */
  async saveSettings(patch) {
    const backend = this.requireBackend();
    const current = await this.getSettings();
    const merged = {
      ...current,
      ...(isPlainObject(patch) ? patch : {}),
      reputation: {
        ...current.reputation,
        ...(isPlainObject(patch?.reputation) ? patch.reputation : {}),
      },
      privacy: {
        ...current.privacy,
        ...(isPlainObject(patch?.privacy) ? patch.privacy : {}),
      },
    };
    const sanitized = sanitizeSettings(merged);
    await backend.set({ [STORAGE_KEYS.SETTINGS]: sanitized });
    this.notify('settings', { settings: sanitized });
    return sanitized;
  }

  /**
   * Citește o listă validată.
   * @param {'allowlist'|'blocklist'} listType
   * @returns {Promise<object[]>}
   */
  async getList(listType) {
    const backend = this.requireBackend();
    const key = listType === LIST_TYPES.BLOCK ? STORAGE_KEYS.BLOCKLIST : STORAGE_KEYS.ALLOWLIST;
    const stored = await backend.get(key);
    const raw = stored?.[key];
    if (!Array.isArray(raw)) return [];
    const entries = [];
    const seen = new Set();
    for (const item of raw) {
      const normalized = normalizeEntry(item, listType, { strict: true });
      if (!normalized.ok) continue; // intrările corupte sunt ignorate, nu afișate
      const key2 = entryKey(normalized.entry);
      if (seen.has(key2)) continue; // deduplicare la citire
      seen.add(key2);
      entries.push(normalized.entry);
    }
    return entries.sort((a, b) => a.host.localeCompare(b.host));
  }

  /**
   * Citește ambele liste.
   * @returns {Promise<{ allowlist: object[], blocklist: object[] }>}
   */
  async getLists() {
    const [allowlist, blocklist] = await Promise.all([
      this.getList(LIST_TYPES.ALLOW),
      this.getList(LIST_TYPES.BLOCK),
    ]);
    return { allowlist, blocklist };
  }

  /**
   * Salvează o listă (deduplicată și validată).
   * @param {'allowlist'|'blocklist'} listType
   * @param {object[]} entries
   * @returns {Promise<object[]>}
   */
  async saveList(listType, entries) {
    const backend = this.requireBackend();
    const key = listType === LIST_TYPES.BLOCK ? STORAGE_KEYS.BLOCKLIST : STORAGE_KEYS.ALLOWLIST;
    const normalized = [];
    const seen = new Set();
    for (const item of Array.isArray(entries) ? entries : []) {
      const result = normalizeEntry(item, listType);
      if (!result.ok) continue;
      const key2 = entryKey(result.entry);
      if (seen.has(key2)) continue;
      seen.add(key2);
      normalized.push(result.entry);
    }
    normalized.sort((a, b) => a.host.localeCompare(b.host));
    await backend.set({ [key]: normalized });
    this.notify(listType, { listType, entries: normalized });
    return normalized;
  }

  /**
   * Adaugă o intrare, dacă nu există deja.
   * @param {'allowlist'|'blocklist'} listType
   * @param {string|object} input
   * @param {{ source?: string, note?: string }} [options]
   * @returns {Promise<{ ok: boolean, entry?: object, error?: string, duplicate?: boolean }>}
   */
  async addEntry(listType, input, options = {}) {
    const asObject = isPlainObject(input) ? input : { host: input };
    const normalized = normalizeEntry(
      {
        ...asObject,
        source: options.source ?? asObject.source ?? ENTRY_SOURCE.USER,
        note: options.note ?? asObject.note ?? '',
        addedAt: this.now(),
      },
      listType,
    );
    if (!normalized.ok) return { ok: false, error: normalized.error };

    const entries = await this.getList(listType);
    const key = entryKey(normalized.entry);
    if (entries.some((e) => entryKey(e) === key)) {
      return { ok: false, duplicate: true, error: `Domeniul ${normalized.entry.host} există deja în listă.` };
    }
    entries.push(normalized.entry);
    await this.saveList(listType, entries);
    return { ok: true, entry: normalized.entry };
  }

  /**
   * Șterge o intrare după host (și tipul de extindere).
   * @param {'allowlist'|'blocklist'} listType
   * @param {string} host
   * @param {{ includeSubdomains?: boolean }} [options]
   * @returns {Promise<{ ok: boolean, removed?: object, error?: string }>}
   */
  async removeEntry(listType, host, options = {}) {
    const normalized = normalizeDomainEntry(host);
    if (!normalized.ok) return { ok: false, error: normalized.error };
    const includeSubdomains = options.includeSubdomains === true || normalized.includeSubdomains;
    const targetKey = entryKey({ host: normalized.host, includeSubdomains });
    const entries = await this.getList(listType);
    const remaining = entries.filter((e) => entryKey(e) !== targetKey);
    if (remaining.length === entries.length) {
      return { ok: false, error: `Domeniul ${normalized.host} nu a fost găsit în listă.` };
    }
    await this.saveList(listType, remaining);
    return { ok: true, removed: { host: normalized.host, includeSubdomains } };
  }

  /**
   * Filtrează o listă după text și/sau sursă.
   * @param {object[]} entries
   * @param {{ query?: string, source?: string }} [filter]
   * @returns {object[]}
   */
  static filterEntries(entries, filter = {}) {
    const query = String(filter.query ?? '').trim().toLowerCase();
    return (Array.isArray(entries) ? entries : []).filter((entry) => {
      if (filter.source && entry.source !== filter.source) return false;
      if (query === '') return true;
      return entry.host.includes(query) || String(entry.note ?? '').toLowerCase().includes(query);
    });
  }

  /**
   * Exportă configurația completă (liste + setări), fără date personale.
   * @returns {Promise<object>}
   */
  async exportConfig() {
    const [settings, lists] = await Promise.all([this.getSettings(), this.getLists()]);
    return {
      app: 'SentinelShield2',
      schemaVersion: STORAGE_SCHEMA_VERSION,
      exportedAt: this.now(),
      settings,
      allowlist: lists.allowlist,
      blocklist: lists.blocklist,
    };
  }

  /**
   * Importă o configurație, cu validare strictă.
   * @param {unknown} payload
   * @param {{ mode?: 'merge'|'replace' }} [options]
   * @returns {Promise<object>} raport de import
   */
  async importConfig(payload, options = {}) {
    const mode = options.mode === 'replace' ? 'replace' : 'merge';
    const report = {
      ok: false,
      mode,
      added: { allowlist: 0, blocklist: 0 },
      skipped: [],
      settingsImported: false,
      error: '',
    };

    if (!isPlainObject(payload)) {
      report.error = 'Fișierul importat nu conține un obiect JSON valid.';
      return report;
    }
    if (payload.app && payload.app !== 'SentinelShield2') {
      report.error = 'Fișierul nu pare să fie exportat de SentinelShield2.';
      return report;
    }
    if (payload.schemaVersion !== undefined && Number(payload.schemaVersion) > STORAGE_SCHEMA_VERSION) {
      report.error = `Fișierul folosește o versiune de schemă mai nouă (${payload.schemaVersion}) decât cea suportată (${STORAGE_SCHEMA_VERSION}).`;
      return report;
    }

    const current = await this.getLists();
    const incoming = {
      allowlist: Array.isArray(payload.allowlist) ? payload.allowlist : [],
      blocklist: Array.isArray(payload.blocklist) ? payload.blocklist : [],
    };
    if (incoming.allowlist.length === 0 && incoming.blocklist.length === 0 && !isPlainObject(payload.settings)) {
      report.error = 'Fișierul nu conține liste sau setări de importat.';
      return report;
    }

    for (const [listType, source] of [
      [LIST_TYPES.ALLOW, incoming.allowlist],
      [LIST_TYPES.BLOCK, incoming.blocklist],
    ]) {
      const base = mode === 'replace' ? [] : current[listType];
      const merged = [...base];
      const seen = new Set(merged.map(entryKey));
      for (const item of source) {
        const normalized = normalizeEntry(item, listType, { strict: true });
        if (!normalized.ok) {
          report.skipped.push({ listType, entry: truncate(JSON.stringify(item), 120), error: normalized.error });
          continue;
        }
        const key = entryKey(normalized.entry);
        if (seen.has(key)) {
          report.skipped.push({ listType, entry: normalized.entry.host, error: 'Duplicat sau deja prezent.' });
          continue;
        }
        seen.add(key);
        merged.push({ ...normalized.entry, source: normalized.entry.source || ENTRY_SOURCE.EXTERNAL });
        report.added[listType] += 1;
      }
      await this.saveList(listType, merged);
    }

    if (isPlainObject(payload.settings)) {
      await this.saveSettings(payload.settings);
      report.settingsImported = true;
    }

    report.ok = true;
    return report;
  }

  /**
   * Șterge tot (liste + setări), cu confirmare făcută în interfață.
   * @returns {Promise<void>}
   */
  async resetAll() {
    const backend = this.requireBackend();
    await backend.remove([STORAGE_KEYS.SETTINGS, STORAGE_KEYS.ALLOWLIST, STORAGE_KEYS.BLOCKLIST]);
    this.notify('reset', {});
  }

  /**
   * Potrivirea pentru un host, pe baza listelor curente.
   * @param {string} host
   * @returns {Promise<object|null>}
   */
  async matchHost(host) {
    const lists = await this.getLists();
    return findListMatch(host, lists);
  }
}

/**
 * Rezumat pentru popup: starea listelor pentru un domeniu.
 * @param {string} host
 * @param {{ allowlist?: object[], blocklist?: object[] }} lists
 * @returns {{ status: 'allowlisted'|'blocklisted'|'none', match: object|null }}
 */
export function summarizeListStatus(host, lists) {
  const match = findListMatch(host, lists);
  if (!match) return { status: 'none', match: null };
  return { status: match.type === LIST_TYPES.BLOCK ? 'blocklisted' : 'allowlisted', match };
}
