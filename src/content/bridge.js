// Sentinel Shield — content script (isolated world). Colectează observații despre pagină și le trimite service worker-ului.
// NU citește valorile câmpurilor de formular, parole, cookie-uri sau conținutul clipboardului; nu modifică pagina.
// Trimite doar: numere, nume de gazde, tipuri de resurse și coduri de semnale.
(() => {
  'use strict';
  if (window.__sentinelShieldBridge) return;
  try { Object.defineProperty(window, '__sentinelShieldBridge', { value: true }); } catch { return; }

  const EVT = '__ss_event';
  const hostname = location.hostname.toLowerCase();
  const PERM_NAMES = { geolocation: 'geolocation', camera: 'camera', microphone: 'microphone', notifications: 'notifications', 'clipboard-read': 'clipboard-read', 'clipboard-write': 'clipboard-write' };
  const REQ = {};
  const state = { requests: {}, clipboardCommandLike: 0, windowOpens: { total: 0, noGesture: 0 }, downloads: { total: 0, noGesture: 0 }, observed: new Map(), declared: new Map(), submits: [], text: new Set(), permissions: {}, scans: 0 };
  const req = (p) => (state.requests[p] ??= { count: 0, granted: 0, denied: 0, errors: 0, noGesture: 0 });
  const REQ_KEYS = new Set(['geolocation', 'camera', 'microphone', 'screen', 'clipboard-read', 'clipboard-write', 'notifications', 'device-enumeration']);

  // ---- evenimente din hook.js (NEÎNCREDERE: pagina le poate falsifica) -> validare strictă
  document.addEventListener(EVT, (e) => {
    let o; try { o = JSON.parse(e.detail); } catch { return; }
    if (!o || typeof o !== 'object') return;
    if (o.k === 'req' && REQ_KEYS.has(o.p)) { const r = req(o.p); r.count++; if (o.ng === true) r.noGesture++; }
    else if (o.k === 'res' && REQ_KEYS.has(o.p)) { const r = req(o.p); if (o.r === 'granted') r.granted++; else if (o.r === 'denied') r.denied++; else r.errors++; }
    else if (o.k === 'cmd') state.clipboardCommandLike = Math.min(1000, state.clipboardCommandLike + 1);
    else if (o.k === 'open') { state.windowOpens.total++; if (o.ng === true) state.windowOpens.noGesture++; }
    else if (o.k === 'dl') { state.downloads.total++; if (o.ng === true) state.downloads.noGesture++; }
    else if (o.k === 'net' && Array.isArray(o.items)) {
      for (const it of o.items.slice(0, 100)) {
        if (!it || typeof it.h !== 'string' || typeof it.t !== 'string') continue;
        addObserved(it.h, it.t, Number(it.c) || 1, Number(it.b) || 0);
      }
    }
    schedule();
  }, true);

  function addObserved(host, type, count, withBody) {
    if (state.observed.size >= 150) return;
    const key = `${host}|${type}`;
    const e = state.observed.get(key) ?? { host, type, count: 0, withBody: 0 };
    e.count += count; e.withBody += withBody; state.observed.set(key, e);
  }

  // ---- Resource Timing: domenii efectiv contactate (observat)
  try {
    const TYPE = { script: 'script', xmlhttprequest: 'xhr', fetch: 'fetch', beacon: 'beacon', img: 'img', image: 'img', css: 'css', link: 'css', iframe: 'iframe', frame: 'iframe', audio: 'media', video: 'media', font: 'font' };
    const po = new PerformanceObserver((list) => {
      for (const en of list.getEntries()) {
        try { const u = new URL(en.name); if (u.hostname.toLowerCase() === hostname || !/^https?:$/.test(u.protocol)) continue; addObserved(u.hostname.toLowerCase(), TYPE[en.initiatorType] ?? 'other', 1, 0); } catch { /* ignorat */ }
      }
      schedule();
    });
    po.observe({ type: 'resource', buffered: true });
  } catch { /* ignorat */ }

  // ---- Trimiteri de formulare: doar destinația și natura câmpurilor (nu valorile)
  document.addEventListener('submit', (e) => {
    try {
      const f = e.target; if (!(f instanceof HTMLFormElement)) return;
      const a = new URL(f.getAttribute('action') || location.href, location.href);
      if (state.submits.length < 10) state.submits.push({ host: a.hostname.toLowerCase(), hasPassword: !!f.querySelector('input[type="password"]'), hasCard: !!f.querySelector(CARD_SEL) });
      sendNow();
    } catch { /* ignorat */ }
  }, true);

  const CARD_SEL = 'input[autocomplete^="cc-"], input[name*="cardnumber" i], input[name*="card-number" i], input[id*="cardnumber" i], input[name*="cvv" i], input[name*="cvc" i], input[id*="cvv" i], input[name*="iban" i]';

  // ---- Semnale text (tipare, fără a păstra textul)
  const TEXT_RULES = [
    ['virus-warning', /(your (computer|device|pc|phone) (is|has been|may be) (infected|compromised|at risk)|(virus|malware|trojan)s? (detected|found|alert)|\b\d+ viruses? found|dispozitivul (t[ăa]u )?este infectat|calculatorul (t[ăa]u )?este infectat|am detectat (viru|malware))/i],
    ['tech-support', /(call (now|us|microsoft|apple|support|a technician)[^.\n]{0,40}\+?\d[\d\s().-]{7,}|sun[ăa] (acum|la)[^.\n]{0,40}\d[\d\s().-]{7,}|toll[- ]free[^.\n]{0,30}\d{3})/i],
    ['run-command', /(press\s+(the\s+)?(win(dows)?\s*(key)?\s*\+\s*r)|win\s*\+\s*r\b|paste (it |the (command|code) )?(in|into) (the )?(run|terminal|powershell|command prompt)|ctrl\s*\+\s*v[^.\n]{0,40}enter|open (the )?(terminal|powershell|command prompt)[^.\n]{0,60}paste|lipe[șs]te[^.\n]{0,40}(terminal|powershell|run))/i],
    ['disable-protection', /(disable|turn off|deactivate|dezactiveaz[ăa]|opre[șs]te)[^.\n]{0,30}(antivirus|firewall|windows defender|smartscreen|safe browsing|protec[țt]i)/i],
    ['extension-install', /(install (the |our |this )?(chrome )?(browser )?(extension|plugin)|add to chrome to (continue|view|watch)|instaleaz[ăa] (extensia|programul|aplica[țt]ia) (pentru a|ca s[ăa]) continua)/i]
  ];
  function scanText() {
    if (state.scans >= 3 || !document.body) return;
    state.scans++;
    try {
      const t = (document.body.innerText || '').slice(0, 30000);
      for (const [code, re] of TEXT_RULES) if (re.test(t)) state.text.add(code);
    } catch { /* ignorat */ }
  }

  // ---- Scanarea DOM-ului: câmpuri, destinații de formular, resurse declarate
  function scanDom() {
    const out = { passwordFields: 0, cardFields: 0, crossSiteActions: [], hiddenFrames: 0 };
    try {
      out.passwordFields = document.querySelectorAll('input[type="password"]').length;
      out.cardFields = document.querySelectorAll(CARD_SEL).length;
      for (const f of document.forms) {
        if (out.crossSiteActions.length >= 10) break;
        const act = f.getAttribute('action'); if (!act) continue;
        const u = new URL(act, location.href);
        if (/^https?:$/.test(u.protocol) && u.hostname.toLowerCase() !== hostname) out.crossSiteActions.push({ host: u.hostname.toLowerCase(), hasPassword: !!f.querySelector('input[type="password"]') });
      }
      for (const fr of document.querySelectorAll('iframe[src]')) {
        try {
          const u = new URL(fr.getAttribute('src'), location.href);
          if (!/^https?:$/.test(u.protocol) || u.hostname.toLowerCase() === hostname) continue;
          const cs = getComputedStyle(fr); const r = fr.getBoundingClientRect();
          if ((r.width <= 2 && r.height <= 2) || cs.display === 'none' || cs.visibility === 'hidden') out.hiddenFrames++;
        } catch { /* ignorat */ }
      }
      const decl = (sel, attr, kind) => {
        for (const el of document.querySelectorAll(sel)) {
          if (state.declared.size >= 150) return;
          try { const u = new URL(el.getAttribute(attr), location.href); if (/^https?:$/.test(u.protocol) && u.hostname.toLowerCase() !== hostname) state.declared.set(`${u.hostname.toLowerCase()}|${kind}`, { host: u.hostname.toLowerCase(), kind }); } catch { /* ignorat */ }
        }
      };
      decl('script[src]', 'src', 'script'); decl('iframe[src]', 'src', 'iframe'); decl('link[rel~="stylesheet"][href]', 'href', 'link'); decl('form[action]', 'action', 'form');
    } catch { /* ignorat */ }
    return out;
  }

  async function readPermissions() {
    const out = {};
    for (const [key, name] of Object.entries(PERM_NAMES)) {
      try { out[key] = (await navigator.permissions.query({ name })).state; } catch { out[key] = 'unknown'; }
    }
    return out;
  }

  function hints() {
    let hasMap = false, hasVideo = false;
    try {
      hasMap = !!document.querySelector('.leaflet-container, .mapboxgl-map, .gm-style, iframe[src*="maps"], [aria-label*="map" i]');
      hasVideo = !!document.querySelector('video');
    } catch { /* ignorat */ }
    return { hasMap, hasVideo, title: (document.title || '').slice(0, 120) };
  }

  let timer = null; let lastSent = 0;
  function schedule() { if (timer) return; timer = setTimeout(() => { timer = null; sendNow(); }, 2000); }

  async function sendNow() {
    if (Date.now() - lastSent < 800) { schedule(); return; }
    lastSent = Date.now();
    scanText();
    const dom = scanDom();
    const permissions = await readPermissions();
    const api = [];
    try { if ('geolocation' in navigator) api.push('geolocation'); if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) api.push('mediaDevices'); if (navigator.clipboard) api.push('clipboard'); if ('Notification' in window) api.push('notifications'); } catch { /* ignorat */ }
    const snapshot = {
      permissions, api, requests: state.requests, clipboardCommandLike: state.clipboardCommandLike, windowOpens: state.windowOpens, downloads: state.downloads,
      net: { observed: [...state.observed.values()], declared: [...state.declared.values()] },
      forms: { passwordFields: dom.passwordFields, cardFields: dom.cardFields, crossSiteActions: dom.crossSiteActions, submits: state.submits, hiddenFrames: dom.hiddenFrames },
      text: [...state.text], hints: hints()
    };
    try { chrome.runtime.sendMessage({ type: 'ss.observation', snapshot }); } catch { /* extensia reîncărcată */ }
  }

  // la cererea explicită a extensiei („Analizează pagina"); se acceptă doar mesaje de la propria extensie
  try {
    chrome.runtime.onMessage.addListener((msg, sender) => {
      if (sender.id === chrome.runtime.id && msg && msg.type === 'ss.requestSnapshot') { state.scans = 0; sendNow(); }
    });
  } catch { /* ignorat */ }

  const start = () => { setTimeout(sendNow, 1500); setTimeout(sendNow, 6000); };
  if (document.readyState === 'complete') start(); else window.addEventListener('load', start, { once: true });
  addEventListener('pagehide', () => { try { sendNow(); } catch { /* ignorat */ } });
  void REQ;
})();
