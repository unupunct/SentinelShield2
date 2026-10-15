// Sentinel Shield — observator în contextul paginii (world: MAIN).
// JUSTIFICARE: cererile de permisiuni (geolocation, getUserMedia, clipboard, notificări) se produc prin API-uri JavaScript
// ale paginii; un content script din „isolated world" nu le poate vedea. Acest script doar ÎNVELEȘTE API-urile pentru a
// număra apelurile și rezultatul lor, apoi apelează funcția originală neschimbată.
// LIMITĂRI: (1) pagina poate detecta sau ocoli aceste învelișuri și poate chiar falsifica evenimentele; de aceea observațiile
// sunt tratate ca NEÎNCREDERE (validate strict în bridge și service worker, nu pot produce singure verdict „confirmat").
// (2) Nu citește și nu transmite conținut: nici coordonate, nici fluxuri media, nici text din clipboard, nici câmpuri de formular.
(() => {
  'use strict';
  if (window.__sentinelShieldHook) return;
  try { Object.defineProperty(window, '__sentinelShieldHook', { value: true }); } catch { return; }

  const EVT = '__ss_event';
  let budget = 500;
  const send = (o) => {
    if (budget-- <= 0) return;
    try { document.dispatchEvent(new CustomEvent(EVT, { detail: JSON.stringify(o) })); } catch { /* ignorat */ }
  };
  const gesture = () => { try { return !!navigator.userActivation && navigator.userActivation.isActive; } catch { return false; } };

  function patch(target, name, factory) {
    try {
      const orig = target && target[name];
      if (typeof orig !== 'function') return;
      const wrapped = factory(orig);
      try { Object.defineProperty(wrapped, 'name', { value: orig.name }); wrapped.toString = () => Function.prototype.toString.call(orig); } catch { /* ignorat */ }
      target[name] = wrapped;
    } catch { /* un eșec de învelire nu trebuie să strice pagina */ }
  }
  // Ramură laterală: observă rezultatul fără a modifica promisiunea returnată paginii.
  function side(promise, onOk, onFail) {
    try { if (promise && typeof promise.then === 'function') promise.then(onOk, onFail); } catch { /* ignorat */ }
  }
  const isDenied = (e) => !!e && (e.name === 'NotAllowedError' || e.name === 'PermissionDeniedError' || e.name === 'SecurityError');
  const res = (p, r) => send({ k: 'res', p, r });

  // ---- Locație
  try {
    const G = window.Geolocation && Geolocation.prototype;
    for (const fn of ['getCurrentPosition', 'watchPosition']) {
      patch(G, fn, (orig) => function (success, error, opts) {
        send({ k: 'req', p: 'geolocation', ng: !gesture() });
        const ok = typeof success === 'function' ? function (pos) { res('geolocation', 'granted'); return success.apply(this, arguments); } : success;
        const fail = function (err) { res('geolocation', err && err.code === 1 ? 'denied' : 'error'); if (typeof error === 'function') return error.apply(this, arguments); };
        return Reflect.apply(orig, this, [ok, fail, opts]);
      });
    }
  } catch { /* ignorat */ }

  // ---- Cameră / microfon / ecran
  try {
    const M = window.MediaDevices && MediaDevices.prototype;
    patch(M, 'getUserMedia', (orig) => function (constraints) {
      const kinds = [];
      try { if (constraints && constraints.audio) kinds.push('microphone'); if (constraints && constraints.video) kinds.push('camera'); } catch { /* ignorat */ }
      const ng = !gesture();
      kinds.forEach((p) => send({ k: 'req', p, ng }));
      const pr = Reflect.apply(orig, this, arguments);
      side(pr, () => kinds.forEach((p) => res(p, 'granted')), (e) => kinds.forEach((p) => res(p, isDenied(e) ? 'denied' : 'error')));
      return pr;
    });
    patch(M, 'getDisplayMedia', (orig) => function () {
      send({ k: 'req', p: 'screen', ng: !gesture() });
      const pr = Reflect.apply(orig, this, arguments);
      side(pr, () => res('screen', 'granted'), (e) => res('screen', isDenied(e) ? 'denied' : 'error'));
      return pr;
    });
    patch(M, 'enumerateDevices', (orig) => function () { send({ k: 'req', p: 'device-enumeration', ng: !gesture() }); return Reflect.apply(orig, this, arguments); });
  } catch { /* ignorat */ }

  // ---- Clipboard
  const CMD_LIKE = /(powershell|pwsh|cmd(\.exe)?\s*\/c|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|curl\s+[^|]{0,200}\|\s*(ba)?sh|wget\s+[^|]{0,200}\|\s*(ba)?sh|\biex\b\s*\(|invoke-expression|invoke-webrequest|-enc(odedcommand)?\s|frombase64string|\bsh\s+-c\b|\bbash\s+-c\b|osascript|\/bin\/(ba)?sh)/i;
  const cmdLike = (t) => { try { return typeof t === 'string' && t.length < 5000 && CMD_LIKE.test(t); } catch { return false; } };
  try {
    const C = window.Clipboard && Clipboard.prototype;
    for (const fn of ['readText', 'read']) {
      patch(C, fn, (orig) => function () {
        send({ k: 'req', p: 'clipboard-read', ng: !gesture() });
        const pr = Reflect.apply(orig, this, arguments);
        side(pr, () => res('clipboard-read', 'granted'), (e) => res('clipboard-read', isDenied(e) ? 'denied' : 'error'));
        return pr;
      });
    }
    patch(C, 'writeText', (orig) => function (text) {
      send({ k: 'req', p: 'clipboard-write', ng: !gesture() });
      if (cmdLike(text)) send({ k: 'cmd' }); // se raportează doar faptul, niciodată textul
      const pr = Reflect.apply(orig, this, arguments);
      side(pr, () => res('clipboard-write', 'granted'), (e) => res('clipboard-write', isDenied(e) ? 'denied' : 'error'));
      return pr;
    });
    patch(window.DataTransfer && DataTransfer.prototype, 'setData', (orig) => function (type, data) {
      try { if (String(type).toLowerCase().startsWith('text/plain') && cmdLike(data)) send({ k: 'cmd' }); } catch { /* ignorat */ }
      return Reflect.apply(orig, this, arguments);
    });
  } catch { /* ignorat */ }

  // ---- Notificări
  try {
    if (window.Notification && typeof Notification.requestPermission === 'function') {
      const orig = Notification.requestPermission;
      const wrapped = function () {
        send({ k: 'req', p: 'notifications', ng: !gesture() });
        const pr = Reflect.apply(orig, this, arguments);
        side(pr, (r) => res('notifications', r === 'granted' ? 'granted' : r === 'denied' ? 'denied' : 'error'), () => res('notifications', 'error'));
        return pr;
      };
      try { wrapped.toString = () => Function.prototype.toString.call(orig); } catch { /* ignorat */ }
      Notification.requestPermission = wrapped;
    }
  } catch { /* ignorat */ }

  // ---- Ferestre noi și descărcări programatice
  patch(window, 'open', (orig) => function () { send({ k: 'open', ng: !gesture() }); return Reflect.apply(orig, this, arguments); });
  patch(window.HTMLAnchorElement && HTMLAnchorElement.prototype, 'click', (orig) => function () {
    try { if (this.hasAttribute('download')) send({ k: 'dl', ng: !gesture() }); } catch { /* ignorat */ }
    return Reflect.apply(orig, this, arguments);
  });

  // ---- Rețea: doar NUMELE gazdei, tipul și dacă are corp. Niciodată URL-ul complet, antetele sau conținutul.
  const net = new Map();
  let flushTimer = null;
  const hostOf = (u) => { try { const x = new URL(String(u), location.href); return /^(https?|wss?):$/.test(x.protocol) ? x.hostname.toLowerCase() : null; } catch { return null; } };
  const flush = () => {
    flushTimer = null;
    if (!net.size) return;
    const items = [...net.entries()].slice(0, 100).map(([k, v]) => { const [h, t] = k.split('|'); return { h, t, c: v.c, b: v.b }; });
    net.clear();
    send({ k: 'net', items });
  };
  const note = (u, t, hasBody) => {
    const h = hostOf(u); if (!h) return;
    const key = `${h}|${t}`; const e = net.get(key) ?? { c: 0, b: 0 };
    e.c++; if (hasBody) e.b++; net.set(key, e);
    if (!flushTimer) flushTimer = setTimeout(flush, 1500);
  };
  try {
    patch(window, 'fetch', (orig) => function (input, init) {
      try {
        const url = typeof input === 'string' ? input : (input && input.url) || String(input);
        const method = (init && init.method) || (input && input.method) || 'GET';
        note(url, 'fetch', !/^(GET|HEAD)$/i.test(method));
      } catch { /* ignorat */ }
      return Reflect.apply(orig, this, arguments);
    });
    const X = window.XMLHttpRequest && XMLHttpRequest.prototype;
    const meta = new WeakMap();
    patch(X, 'open', (orig) => function (method, url) { try { meta.set(this, { url }); } catch { /* ignorat */ } return Reflect.apply(orig, this, arguments); });
    patch(X, 'send', (orig) => function (body) { try { const m = meta.get(this); if (m) note(m.url, 'xhr', body != null); } catch { /* ignorat */ } return Reflect.apply(orig, this, arguments); });
    patch(navigator, 'sendBeacon', (orig) => function (url) { note(url, 'beacon', true); return Reflect.apply(orig, this, arguments); });
    if (window.WebSocket) {
      window.WebSocket = new Proxy(window.WebSocket, { construct(t, args, nt) { note(args[0], 'websocket', false); return Reflect.construct(t, args, nt); } });
    }
  } catch { /* ignorat */ }
})();
