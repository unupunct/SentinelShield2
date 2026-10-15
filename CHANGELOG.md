# Istoricul versiunilor

Formatul se bazează pe [Keep a Changelog](https://keepachangelog.com/ro/1.1.0/),
iar versiunile urmează [Semantic Versioning](https://semver.org/lang/ro/).

## [0.1.0] — MVP inițial

### Adăugat

- **Manifest V3** cu permisiuni minime (`storage`, `activeTab`, `scripting`, `contextMenus`) și permisiuni opționale
  (`webNavigation`, `*://*/*`), CSP strict fără cod de la distanță.
- **Analizor local, explicabil:**
  - `urlAnalyzer` — fapte despre URL (schemă, host, IP, credențiale, caractere neobișnuite, parametri).
  - `domainAnalyzer` — domeniu registrabil, homoglife/Punycode, typosquatting (Levenshtein), brand în subdomeniu.
  - `phishingRules` — 26 de reguli (`URL-001..005`, `HOST-001..015`, `PATH-001..004`, `PRIV-001`, `DOM-001..006`),
    fiecare cu explicație, limite și recomandare.
  - `riskScorer` — deduplicare pe familii, scor determinist, politică de liste, verdict de reputație.
  - `analyzer/index.js` — fațada `analyzeTarget()`.
  - `shared/idn.js` — decodor Punycode (RFC 3492) validat față de `node:punycode`.
- **Service worker:** rutare de mesaje, meniuri contextuale, monitorizare de navigare (opțională), pagină de
  avertizare, excepții temporare pe host (10 minute), badge cu nivelul de risc.
- **Interfață (temă întunecată, accente portocalii):** popup, pagină de detalii, pagină de avertizare, pagină de
  setări. Riscul este comunicat prin culoare + simbol + etichetă + scor.
- **Inspecția permisiunilor web**, la cerere, prin `chrome.scripting.executeScript` (nu citește formulare, parole sau
  cookie-uri).
- **Liste locale** allowlist/blocklist cu adăugare, ștergere, căutare, deduplicare, import/export JSON și validare
  strictă.
- **Sursă de reputație opțională** (HTTP/HTTPS), dezactivată implicit; trimite doar numele de domeniu.
- **Documentație:** `README.md`, `PRIVACY.md`, `SECURITY.md`, `CHANGELOG.md`.
- **Teste:** suită Vitest (`npm run test`) pentru validatoare, IDN/Punycode, URL-uri sigure/suspecte/malițioase/
  invalide, reguli, scor, liste, reputație, monitor de permisiuni, redare sigură a textului și validarea manifestului.
- **Scripturi:** generare iconițe, validare manifest (`npm run validate`), build în `dist/SentinelShield2`.

### Note

- Monitorizarea navigării este, prin natura API-ului, o intervenție ulterioară (best-effort), nu o oprire sincronă.
- Eticheta „Periculos confirmat” se acordă exclusiv pe baza unei surse de reputație configurate explicit.
