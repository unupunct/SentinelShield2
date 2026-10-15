# Arhitectură

## Alegeri tehnice
- **Manifest V3**, JavaScript modern (module ES), HTML/CSS. **Fără pas de compilare**: ce vezi în repository este ce rulează (reproductibil). TypeScript nu a fost folosit tocmai pentru a evita un lanț de build; modulele sunt mici, pure și testate.
- Stocare: `chrome.storage.local` (config, jurnal, liste, excepții) și `chrome.storage.session` (stare per filă, avertizări emise — dispar la închiderea browserului).
- Teste: Vitest (unitare + integrare cu Chrome simulat) și puppeteer-core pentru verificări în Chrome real.

## Componente

```
manifest.json
data/blocklist.json          listă SINTETICĂ de test
src/lib/                     logică pură, fără API Chrome (testabilă)
  punycode.js  psl.js  confusables.js  brands.js
  url-analyzer.js            normalizare + indicatori URL
  risk-engine.js             scor, niveluri, verdict, combinarea cu comportamentul, lanțuri de redirecționare
  reputation.js              liste locale, parsare feed-uri, furnizori online, cache/rate-limit/timeout
  behavior.js                interpretarea observațiilor paginii
  download-analyzer.js       analiză de metadate de descărcare
  messages.js                validarea strictă a mesajelor
  sanitize.js  config.js  storage.js  event-log.js
src/background/
  core.js                    coordonator injectabil (testat fără browser)
  service-worker.js          doar legătura evenimentelor Chrome → core
src/content/
  hook.js   (world: MAIN)    învelește API-uri JS pentru a observa cereri de permisiuni
  bridge.js (isolated)       DOM, Resource Timing, formulare; trimite observații la service worker
src/pages/{warning,popup,dashboard}   interfață
src/shared/{ui.js,ui.css}             componente UI (doar textContent, fără HTML dinamic)
```

## Fluxul unei navigări

1. `webNavigation.onBeforeNavigate` (cadrul principal): URL → `analyzeUrl` (pur) → verificare locală (liste) → `evaluate`. Procesarea este **serializată per filă**.
2. Dacă verdictul cere avertizare și nu există un permis valid: se creează o intrare opacă (UUID) în `storage.session` și fila este redirecționată către `warning.html?id=<uuid>`. URL-ul destinației **nu** apare în URL-ul paginii de avertizare.
3. În paralel (doar dacă utilizatorul a configurat și consimțit): verificări online. Dacă aduc o amenințare, fila este redirecționată după fapt.
4. `onCommitted`: înregistrează redirecționările de server/client, reevaluează URL-ul final și lanțul (`redirect-to-flagged`).
5. Content scripts trimit observații (după încărcare și la cerere). Service worker-ul le validează, le combină pe cadre și rulează `analyzeBehavior`; `combinePage` poate ridica nivelul cel mult până la „Suspect" — **doar o confirmare a reputației** (ex. conexiune observată către un domeniu listat) poate produce „Periculos confirmat".

## Scorul de risc
- Fiecare indicator are severitate (info/low/medium/high), clasificare (confirmat/suspect/risc potențial/legitim/insuficient) și o greutate configurabilă (suprascrieri per cod).
- Praguri implicite: Suspect ≥ 15; Periculos ≥ 60 **și** cel puțin un indicator sever.
- Surse de reputație → `confirmed`; o amenințare confirmată duce la „Periculos" indiferent de scor.
- „Neverificat" = intrare invalidă/internă sau verificare online eșuată fără alte concluzii. Starea fiecărei surse e afișată distinct: *amenințare găsită* / *nicio amenințare găsită* / *nu a putut fi verificat (eroare/timeout/limită)* / *necesită consimțământ*.

## Pagina de avertizare — protecții
Datele vin din service worker după `id` opac; textele se afișează doar cu `textContent`; pagina refuză să funcționeze într-un cadru; `grantPass` verifică: expeditor = pagina extensiei din **aceeași filă**, cadru principal, intrare neutilizată, timp minim scurs (măsurat de service worker), confirmare corectă, politica permite. Permisul este per filă + origine (schemă+gazdă+port) și expiră (implicit 10 min).

## Blocare timpurie opțională (declarativeNetRequest)
Redirecționarea DNR către o pagină a extensiei necesită acces la gazde. Se activează explicit din *Protecție*, cu permisiuni opționale (`declarativeNetRequestWithHostAccess` + `<all_urls>`), și instalează reguli de redirecționare `main_frame` pentru domeniile din liste. Acestea văd **tot lanțul de redirecționări**. Fără ea, protecția folosește `webNavigation` (vezi [LIMITARI.md](LIMITARI.md)).
