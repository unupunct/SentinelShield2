// Jurnal local al evenimentelor de securitate. Se înregistrează DOAR evenimente cu semnificație (suspect/periculos/
// neverificat, descărcări riscante, constatări comportamentale) — nu istoricul complet de navigare.
// Pentru pagini „SAFE" se păstrează doar un contor, fără URL.
import { redactUrl } from './sanitize.js';
import { createMutex } from './storage.js';

const KEY_EVENTS = 'events';
const KEY_COUNTERS = 'counters';

export function createEventLog({ store, getConfig, now = () => Date.now(), uuid = () => crypto.randomUUID() }) {
  const lock = createMutex();

  const prune = (events, cfg) => {
    const cutoff = now() - cfg.privacy.retentionDays * 86400000;
    return events.filter((e) => e.ts >= cutoff).slice(-cfg.privacy.maxEvents);
  };

  return {
    /** Contor anonim: câte pagini au fost analizate pe nivel (fără URL). */
    countAnalysis(level) {
      return lock(async () => {
        const c = await store.get(KEY_COUNTERS, { analyzed: 0, byLevel: {}, since: now() });
        c.analyzed++; c.byLevel[level] = (c.byLevel[level] ?? 0) + 1;
        await store.set(KEY_COUNTERS, c);
      });
    },

    async record(evt) {
      const cfg = await getConfig();
      if (!cfg.privacy.logEnabled) return null;
      return lock(async () => {
        let events = await store.get(KEY_EVENTS, []);
        const url = evt.url ? redactUrl(evt.url, cfg.privacy.logUrlMode) : null;
        const prev = events[events.length - 1];
        if (prev && prev.url === url && prev.type === evt.type && prev.level === evt.level && prev.summary === evt.summary && now() - prev.ts < 30000) return prev; // dedup
        const e = {
          id: uuid(), ts: now(), type: evt.type, level: evt.level, url,
          host: evt.host ?? null, summary: String(evt.summary ?? '').slice(0, 300), userExplanation: String(evt.userExplanation ?? '').slice(0, 1200),
          action: evt.action ?? 'observed', recommendation: String(evt.recommendation ?? '').slice(0, 400),
          indicators: (evt.indicators ?? []).slice(0, 30).map((i) => ({ code: i.code, category: i.category, severity: i.severity, classification: i.classification, title: String(i.title ?? '').slice(0, 200), explain: String(i.explain ?? i.explainUser ?? '').slice(0, 600), technical: i.technical ?? {} })),
          sources: (evt.sources ?? []).slice(0, 10).map((s) => ({ source: s.source, name: s.name, status: s.status, checkedAt: s.checkedAt ?? null, detail: String(s.detail ?? '').slice(0, 200) }))
        };
        events.push(e);
        events = prune(events, cfg);
        await store.set(KEY_EVENTS, events);
        return e;
      });
    },

    async query({ levels = [], type = null, search = '', limit = 100 } = {}) {
      const cfg = await getConfig();
      const events = prune(await store.get(KEY_EVENTS, []), cfg);
      const q = search.toLowerCase();
      return events.filter((e) => (!levels.length || levels.includes(e.level)) && (!type || e.type === type) && (!q || `${e.host ?? ''} ${e.summary} ${e.indicators.map((i) => i.code).join(' ')}`.toLowerCase().includes(q)))
        .slice(-limit).reverse();
    },

    /** Statistici calculate exclusiv din date reale; fără date => `total: 0` (UI afișează „Nu există încă date"). */
    async stats() {
      const cfg = await getConfig();
      const events = prune(await store.get(KEY_EVENTS, []), cfg);
      const counters = await store.get(KEY_COUNTERS, null);
      const byLevel = {}; const byType = {}; const byDay = {}; const codes = {};
      for (const e of events) {
        byLevel[e.level] = (byLevel[e.level] ?? 0) + 1; byType[e.type] = (byType[e.type] ?? 0) + 1;
        const day = new Date(e.ts).toISOString().slice(0, 10); byDay[day] = (byDay[day] ?? 0) + 1;
        for (const i of e.indicators) if (i.severity !== 'info') codes[i.code] = (codes[i.code] ?? 0) + 1;
      }
      const topIndicators = Object.entries(codes).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([code, count]) => ({ code, count }));
      return { total: events.length, byLevel, byType, byDay, topIndicators, analyzed: counters?.analyzed ?? 0, analyzedByLevel: counters?.byLevel ?? {}, since: counters?.since ?? null, firstAt: events[0]?.ts ?? null, lastAt: events[events.length - 1]?.ts ?? null };
    },

    clear() { return lock(async () => { await store.set(KEY_EVENTS, []); await store.set(KEY_COUNTERS, { analyzed: 0, byLevel: {}, since: now() }); }); },

    /** Export controlat: „summary" = fără detalii tehnice; URL-urile respectă setarea de confidențialitate. Nu conține chei API. */
    async exportJson(detail = 'summary') {
      const events = await this.query({ limit: 5000 });
      const cfg = await getConfig();
      return {
        generator: 'Sentinel Shield', generatedAt: new Date(now()).toISOString(), detail,
        privacyNote: `URL-urile sunt redactate conform modului „${cfg.privacy.logUrlMode}”. Parolele, conținutul formularelor și cheile API nu sunt stocate sau exportate.`,
        count: events.length,
        events: events.map((e) => (detail === 'full' ? e : { ts: new Date(e.ts).toISOString(), type: e.type, level: e.level, host: e.host, summary: e.summary, action: e.action, indicators: e.indicators.map((i) => i.code), sources: e.sources.map((s) => `${s.name}: ${s.status}`) }))
      };
    }
  };
}
