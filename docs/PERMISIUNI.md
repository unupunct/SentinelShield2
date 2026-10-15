# Matricea permisiunilor Chrome

Principiu: *least privilege*. `host_permissions` este **gol**. Extensia nu cere acces la toate site-urile pentru funcționarea de bază.

## Permisiuni obligatorii

| Permisiune | De ce e necesară | Impact asupra confidențialității | Alternative respinse |
|---|---|---|---|
| `storage` | Config, jurnal local, liste, excepții, stare de sesiune | Date doar pe dispozitiv | — |
| `webNavigation` | Primește URL-ul fiecărei navigări de cadru principal ca să-l evalueze **înainte** de încărcare și să vadă redirecționările (`transitionQualifiers`). Nu cere acces la gazde. | Extensia vede URL-urile navigate (necesar scopului). Procesate local; nu se transmit. Se jurnalizează doar alertele. | `webRequest` (cere host permissions; blocarea e limitată în MV3) |
| `downloads` | `onCreated`/`onChanged` pentru metadate; `pause`/`cancel`/`resume` pentru descărcări cu risc ridicat | Vede nume, URL sursă, tip MIME; nu citește conținutul | — |
| `alarms` | Actualizare periodică a feed-urilor, doar dacă utilizatorul le-a activat | Niciun impact | `setInterval` (nu supraviețuiește opririi service worker-ului) |
| `activeTab` | La click pe iconiță, popup-ul poate citi URL-ul filei active | Acces temporar, declanșat de utilizator | `tabs` (acces permanent la URL/titlu pentru toate filele) |

## Content scripts (nu sunt `host_permissions`)
`matches: http://*/*, https://*/*`, `document_start`, `all_frames`:
- **`hook.js`** (`world: MAIN`) — învelește `geolocation`, `getUserMedia/getDisplayMedia`, `clipboard`, `Notification.requestPermission`, `window.open`, `fetch/XHR/sendBeacon/WebSocket` pentru a **număra** apeluri și a nota **numele gazdei** țintă. Nu citește coordonate, fluxuri, text din clipboard, valori din formulare.
- **`bridge.js`** (isolated world) — scanează DOM-ul (număr de câmpuri parolă/card, destinația formularelor, resurse declarate), Resource Timing (gazde contactate), tipare în text vizibil. Trimite doar numere, nume de gazde, enumerări.

**Justificare:** analiza „Ce vrea să acceseze pagina?" nu e posibilă fără cod în pagină. Aceasta face ca Chrome să afișeze la instalare avertismentul „citește datele de pe toate site-urile" — este costul funcției; poate fi evitat dezactivând extensia sau eliminând secțiunea `content_scripts` (protecția URL/descărcări rămâne funcțională, dar fără analiză comportamentală).

## Permisiuni opționale (cerute la momentul activării, cu gest al utilizatorului)

| Permisiune | Când se cere | De ce |
|---|---|---|
| `https://urlhaus-api.abuse.ch/*` | Activarea URLhaus (cu cheie + consimțământ) | Cerere `POST` cu numele domeniului |
| `https://safebrowsing.googleapis.com/*` | Activarea Safe Browsing | Cerere `POST` cu URL-ul fără parametri |
| `https://urlhaus.abuse.ch/*`, `https://openphish.com/*` | Activarea feed-urilor | `GET` pentru descărcarea listelor (nu trimite date despre utilizator) |
| `declarativeNetRequestWithHostAccess` + `<all_urls>` | „Blocare timpurie" în *Protecție* | Redirecționare DNR a domeniilor listate, inclusiv în lanțuri de redirecționări |

Toate pot fi refuzate; funcția respectivă rămâne inactivă, iar protecția locală continuă.

## Resurse web-accesibile
Doar `warning.html` + `warning.js/css` + `src/shared/*`, pentru ca redirecționarea DNR să poată afișa pagina de avertizare. Riscuri (încadrare, navigare cu parametri) și atenuări: [MODEL-AMENINTARI.md](MODEL-AMENINTARI.md).

## CSP
`script-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'` — fără `eval`, fără scripturi sau handleri inline, fără cod descărcat dinamic. `npm run validate` verifică absența `eval`, `new Function`, `innerHTML`, `document.write`.
