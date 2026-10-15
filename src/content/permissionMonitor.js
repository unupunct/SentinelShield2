/**
 * SentinelShield2 - permissionMonitor.
 *
 * Rol: observă permisiunile WEB ale paginii curente și le explică utilizatorului.
 *
 * Decizii de proiectare (least privilege + confidențialitate):
 * - NU se declară un content script global pentru toate site-urile. Funcția
 *   `permissionProbe` este injectată la cerere, doar în tab-ul activ, prin
 *   `chrome.scripting.executeScript`, folosind permisiunea `activeTab`
 *   (acordată de browser în momentul în care utilizatorul apasă pictograma
 *   extensiei, folosește meniul contextual sau o comandă rapidă).
 * - Se citesc DOAR stări de permisiuni raportate de browser și numărul de
 *   dispozitive multimedia. NU se citesc formulare, parole, cookie-uri,
 *   conținutul paginii sau etichetele dispozitivelor.
 * - `permissionProbe` este scrisă ca funcție auto-conținută (fără variabile
 *   din afara ei), pentru că `chrome.scripting.executeScript` serialisează
 *   doar corpul funcției.
 */

/** Permisiunile interogate prin `navigator.permissions.query`. */
export const PROBEABLE_PERMISSIONS = Object.freeze([
  'camera',
  'microphone',
  'geolocation',
  'notifications',
  'clipboard-read',
  'clipboard-write',
  'midi',
  'usb',
  'bluetooth',
  'serial',
  'hid',
  'idle-detection',
  'background-sync',
  'persistent-storage',
  'push',
  'screen-wake-lock',
  'storage-access',
  'local-fonts',
  'window-management',
]);

/**
 * Etichete și explicații în română pentru fiecare permisiune web.
 * `risk` este doar o indicație de sensibilitate, NU un verdict de phishing.
 */
export const PERMISSION_INFO = Object.freeze({
  camera: { label: 'Cameră', impact: 'Pagina poate folosi camera pentru a filma sau fotografia.' },
  microphone: { label: 'Microfon', impact: 'Pagina poate asculta sunetul din jur.' },
  geolocation: { label: 'Locație', impact: 'Pagina poate afla poziția ta geografică.' },
  notifications: { label: 'Notificări', impact: 'Pagina îți poate trimite notificări pe desktop.' },
  'clipboard-read': { label: 'Citirea clipboardului', impact: 'Pagina poate citi ce ai copiat ultima dată.' },
  'clipboard-write': { label: 'Scrierea în clipboard', impact: 'Pagina poate modifica ce ai în clipboard.' },
  midi: { label: 'Dispozitive MIDI', impact: 'Pagina poate folosi instrumente muzicale conectate.' },
  usb: { label: 'Dispozitive USB', impact: 'Pagina poate cere acces la dispozitive USB conectate.' },
  bluetooth: { label: 'Dispozitive Bluetooth', impact: 'Pagina poate cere acces la dispozitive Bluetooth din apropiere.' },
  serial: { label: 'Port serial', impact: 'Pagina poate cere acces la porturi seriale (echipamente).' },
  hid: { label: 'Dispozitive de intrare (HID)', impact: 'Pagina poate cere acces direct la tastatură sau la alte dispozitive de intrare.' },
  'idle-detection': { label: 'Detectarea inactivității', impact: 'Pagina poate estima când nu mai folosești dispozitivul.' },
  'background-sync': { label: 'Sincronizare în fundal', impact: 'Pagina poate sincroniza date în fundal.' },
  'persistent-storage': { label: 'Stocare persistentă', impact: 'Datele paginii nu sunt șterse automat de browser.' },
  push: { label: 'Notificări push', impact: 'Pagina poate primi mesaje de la un server, chiar și închisă.' },
  'screen-wake-lock': { label: 'Menținerea ecranului activ', impact: 'Pagina poate împiedica stingerea ecranului.' },
  'storage-access': { label: 'Acces la stocarea site-ului', impact: 'Pagina poate accesa date stocate de alte site-uri (folosit în iframe-uri).' },
  'local-fonts': { label: 'Fonturi locale', impact: 'Pagina poate citi lista de fonturi instalate pe acest dispozitiv.' },
  'window-management': { label: 'Gestionarea ferestrelor', impact: 'Pagina poate muta sau redimensiona ferestre.' },
});

/**
 * Funcția injectată în pagina web. Trebuie să fie auto-conținută.
 * @returns {Promise<object>} raport despre permisiuni, fără date sensibile
 */
export async function permissionProbe() {
  const names = [
    'camera', 'microphone', 'geolocation', 'notifications',
    'clipboard-read', 'clipboard-write', 'midi', 'usb', 'bluetooth',
    'serial', 'hid', 'idle-detection', 'background-sync',
    'persistent-storage', 'push', 'screen-wake-lock', 'storage-access',
    'local-fonts', 'window-management',
  ];

  const permissions = [];
  for (const name of names) {
    try {
      const status = await navigator.permissions.query({ name });
      permissions.push({ name, state: status.state, supported: true });
    } catch {
      permissions.push({ name, state: 'unsupported', supported: false });
    }
  }

  // Doar numărul de dispozitive, niciodată etichetele (care pot conține date
  // personale precum numele unui dispozitiv personal).
  const devices = { camera: null, microphone: null, speaker: null };
  try {
    const list = await navigator.mediaDevices.enumerateDevices();
    devices.camera = list.filter((d) => d.kind === 'videoinput').length;
    devices.microphone = list.filter((d) => d.kind === 'audioinput').length;
    devices.speaker = list.filter((d) => d.kind === 'audiooutput').length;
  } catch {
    // enumerateDevices poate lipsi în contexte nesigure; nu este o eroare.
  }

  return {
    host: typeof location !== 'undefined' ? location.host : '',
    origin: typeof location !== 'undefined' ? location.origin : '',
    secureContext: typeof window !== 'undefined' ? window.isSecureContext : false,
    permissions,
    devices,
    collectedAt: new Date().toISOString(),
  };
}

/**
 * Normalizează un raport primit din pagină (date neîncrezătoare!).
 * @param {unknown} report
 * @returns {{ host: string, origin: string, secureContext: boolean, permissions: Array<object>, devices: object, collectedAt: string } | null}
 */
export function sanitizePermissionReport(report) {
  if (typeof report !== 'object' || report === null) return null;
  const permissions = Array.isArray(report.permissions)
    ? report.permissions
      .filter((p) => p && typeof p.name === 'string')
      .map((p) => ({
        name: p.name.slice(0, 64),
        state: ['granted', 'denied', 'prompt', 'unsupported'].includes(p.state) ? p.state : 'unsupported',
        supported: p.supported === true,
      }))
    : [];
  const deviceValue = (value) => (Number.isInteger(value) && value >= 0 && value < 1000 ? value : null);
  const devices = typeof report.devices === 'object' && report.devices !== null
    ? {
      camera: deviceValue(report.devices.camera),
      microphone: deviceValue(report.devices.microphone),
      speaker: deviceValue(report.devices.speaker),
    }
    : { camera: null, microphone: null, speaker: null };

  return {
    host: typeof report.host === 'string' ? report.host.slice(0, 255) : '',
    origin: typeof report.origin === 'string' ? report.origin.slice(0, 512) : '',
    secureContext: report.secureContext === true,
    permissions,
    devices,
    collectedAt: typeof report.collectedAt === 'string' ? report.collectedAt.slice(0, 40) : '',
  };
}

/**
 * Rezumă raportul pentru afișare, cu explicații în română.
 * @param {unknown} rawReport
 * @returns {object}
 */
export function summarizePermissionReport(rawReport) {
  const report = sanitizePermissionReport(rawReport);
  const empty = {
    available: false,
    host: '',
    origin: '',
    secureContext: false,
    granted: [],
    prompt: [],
    denied: [],
    unsupported: [],
    devices: { camera: null, microphone: null, speaker: null },
    notes: [
      'Permisiunile paginii nu au putut fi citite. Extensia nu are acces la acest tab sau API-ul nu este disponibil.',
    ],
  };
  if (!report) return empty;

  const decorate = (entry) => {
    const info = PERMISSION_INFO[entry.name] ?? { label: entry.name, impact: 'Permisiune web.' };
    return { name: entry.name, state: entry.state, label: info.label, impact: info.impact };
  };

  const granted = report.permissions.filter((p) => p.state === 'granted').map(decorate);
  const prompt = report.permissions.filter((p) => p.state === 'prompt').map(decorate);
  const denied = report.permissions.filter((p) => p.state === 'denied').map(decorate);
  const unsupported = report.permissions.filter((p) => p.supported === false).map(decorate);

  const notes = [
    'Acestea sunt permisiuni raportate de browser pentru pagină. Faptul că o permisiune este disponibilă NU înseamnă că pagina o și folosește acum.',
  ];
  if (!report.secureContext) {
    notes.push('Pagina nu rulează într-un context securizat (HTTPS), deci anumite API-uri sunt oricum blocate de browser.');
  }
  if (report.devices.camera !== null || report.devices.microphone !== null) {
    notes.push('Numărul de dispozitive multimedia detectate este informativ; etichetele dispozitivelor nu sunt citite.');
  }
  if (granted.length > 0) {
    notes.push('Permisiunile marcate "deja acordate" au fost acordate de tine (sau sunt implicite) pentru acest site.');
  }
  if (unsupported.length > 0) {
    notes.push('Unele permisiuni nu sunt suportate de acest browser și nu au putut fi verificate.');
  }

  return {
    available: true,
    host: report.host,
    origin: report.origin,
    secureContext: report.secureContext,
    granted,
    prompt,
    denied,
    unsupported,
    devices: report.devices,
    notes,
  };
}

/**
 * Construiește lista de indicatori de afișare pentru pagină de detalii.
 * IMPORTANT: acestea NU sunt indicatori de risc de phishing și NU intră în scor.
 * @param {object} summary rezultatul `summarizePermissionReport`
 * @returns {Array<{ level: string, title: string, detail: string }>}
 */
export function buildPermissionFindings(summary) {
  if (!summary?.available) {
    return [{ level: 'info', title: 'Permisiunile paginii nu au putut fi citite', detail: summary?.notes?.[0] ?? '' }];
  }
  const findings = [];
  for (const permission of summary.granted) {
    findings.push({
      level: 'granted',
      title: `${permission.label}: deja acordată`,
      detail: permission.impact,
    });
  }
  for (const permission of summary.prompt) {
    findings.push({
      level: 'prompt',
      title: `${permission.label}: poate fi cerută`,
      detail: `${permission.impact} Browserul îți va cere acordul înainte de a acorda accesul.`,
    });
  }
  for (const permission of summary.denied) {
    findings.push({
      level: 'denied',
      title: `${permission.label}: blocată`,
      detail: 'Ai refuzat această permisiune pentru acest site.',
    });
  }
  return findings;
}
