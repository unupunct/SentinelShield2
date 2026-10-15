# SentinelShield2

Extensie Chrome **Manifest V3** pentru analiză **locală, explicabilă** a linkurilor și a paginilor, cu scopul de a
recunoaște indiciile de phishing înainte de a deschide o adresă sau de a introduce date.

- **Fără cont, fără telemetrie, fără colectare implicită de date.**
- Analiza este **euristică și locală**; rezultatul este explicat în limba română, cu limitele fiecărui indicator.
- Extensia **nu** citește formulare, parole, cookie-uri sau conținutul paginilor.

> **Principiu de onestitate:** niciun rezultat nu este prezentat ca „sigur” în mod garantat. Lipsa indicatorilor nu
> înseamnă siguranță, iar eticheta „Periculos confirmat” se acordă **exclusiv** pe baza unei surse de reputație
> configurate explicit de utilizator.

---

## Cuprins

1. [Funcționalități](#funcționalități)
2. [Instalare (load unpacked)](#instalare-load-unpacked)
3. [Utilizare](#utilizare)
4. [Niveluri de risc și scor](#niveluri-de-risc-și-scor)
5. [Permisiuni și justificare](#permisiuni-și-justificare)
6. [Confidențialitate](#confidențialitate)
7. [Structura proiectului](#structura-proiectului)
8. [Dezvoltare: instalare, teste, build](#dezvoltare-instalare-teste-build)
9. [Testare manuală](#testare-manuală)
10. [Limite cunoscute](#limite-cunoscute)
11. [Documente conexe](#documente-conexe)

---

## Funcționalități

| Funcție | Descriere |
| --- | --- |
| Analiză la cerere | Analizează tab-ul activ sau un link lipit manual, din popup. |
| Meniu contextual | „Verifică linkul” pe un link, „Analizează această pagină”, adăugare rapidă în liste. |
| Detecție de domenii suspecte | Homoglife/Punycode, typosquatting (distanță Levenshtein), brand inclus în subdomeniu, TLD-uri riscante, IP-uri literale etc. |
| Reguli explicabile | 26 de reguli (`URL-*`, `HOST-*`, `PATH-*`, `PRIV-*`, `DOM-*`), fiecare cu „de ce contează”, „limite / fals pozitiv posibil” și „ce poți face”. |
| Pagină de avertizare | Afișată înainte de navigare, **doar** dacă activezi monitorizarea (permisiuni opționale). |
| Inspecția permisiunilor web | Citește, la cerere, stările de permisiuni raportate de browser pentru pagina curentă. |
| Liste locale | Allowlist / blocklist cu adăugare, ștergere, căutare, import/export JSON, validare și deduplicare. |
| Interfață | Temă întunecată cu accente portocalii; riscul este comunicat prin **culoare + simbol + etichetă + scor**. |

### Distincții respectate explicit

- **Indicator ≠ risc posibil ≠ amenințare confirmată.** Indicatorii sunt observații; nivelul agregat este „risc
  posibil”; „confirmat” vine doar din reputație.
- **HTTP ≠ periculos** și **HTTPS ≠ sigur.** HTTP este un indicator de confidențialitate (pondere mică), nu o dovadă
  de phishing.
- **Domeniile noi, necunoscute sau cu multe subdomenii NU sunt marcate automat ca periculoase.** Ele produc cel mult
  indicatori informativi sau cu pondere mică.

---

## Instalare (load unpacked)

Se recomandă încărcarea directorului construit prin `npm run build`.

1. Clonează / copiază proiectul local.
2. Instalează dependențele și construiește pachetul de rulare:

   ```powershell
   npm install
   npm run build
   ```

3. Deschide `chrome://extensions` în Chrome.
4. Activează **Modul dezvoltator** (dreapta sus).
5. Apasă **Load unpacked** / **Încarcă extensia neîmpachetată**.
6. Selectează directorul **`dist/SentinelShield2`** (conține doar manifestul, sursele și iconițele).

> Poți încărca și directorul rădăcină al proiectului, dar Chrome va semnala fișierele suplimentare
> (`node_modules`, `tests`, `scripts`). Directorul din `dist/` este varianta curată.

---

## Utilizare

### Analiza paginii curente

1. Apasă pictograma extensiei.
2. Apasă **Analizează pagina**. Verdictul este afișat pe scurt.
3. Apasă **Vezi toate detaliile** pentru explicații complete, dovezi și permisiuni web.

### Verificarea unui link înainte de a-l deschide

1. În popup, lipește adresa în câmpul **Verifică un link**.
2. Apasă **Verifică linkul** (sau **Verifică + reputație**, dacă ai configurat o sursă).

### Meniu contextual

- Click dreapta pe un link → **Verifică linkul cu SentinelShield2**.
- Click dreapta pe pagină → **Analizează această pagină**, **Adaugă domeniul în lista de încredere**,
  **Blochează acest domeniu**.

### Monitorizarea navigării (opțional)

Se activează din **Setări → Monitorizare navigare**. Necesită două permisiuni opționale (`webNavigation` + acces la
site-uri), acordate explicit de tine. Când riscul depășește pragul ales, se afișează pagina de avertizare, cu opțiunile:

- **Înapoi la siguranță** — revine la pagina anterioară.
- **Continuă oricum (10 minute)** — acordă o excepție temporară, **doar pentru acel domeniu**, timp de 10 minute.

---

## Niveluri de risc și scor

Scorul euristic este determinist. Indicii din **aceeași familie** nu se însumează: se păstrează ponderea maximă
(indicatorii mai slabi rămân vizibili, marcați „atenuați”).

| Scor | Nivel |
| --- | --- |
| 0 | Fără indicatori evidenți de risc |
| 1–19 | Risc scăzut |
| 20–49 | Risc moderat |
| 50–100 | Risc ridicat |
| — | Periculos confirmat *(doar din sursa de reputație, cu confirmare explicită)* |

### Prioritatea listelor

1. blocklist — potrivire exactă
2. blocklist — potrivire de subdomeniu
3. allowlist — potrivire exactă
4. allowlist — potrivire de subdomeniu

O intrare din lista de blocare are mereu prioritate pentru același domeniu. Lista de încredere reduce severitatea
euristicii (nivel maxim „risc scăzut”), dar **nu** ascunde indicatorii și **nu** anulează un verdict confirmat.

---

## Permisiuni și justificare

| Permisiune | Tip | Justificare |
| --- | --- | --- |
| `storage` | obligatorie | Setări, liste, starea sesiunii (ultima analiză, avertisment pending). |
| `activeTab` | obligatorie | Acces la tab-ul activ **doar** când apeși pictograma, folosești meniul contextual sau o comandă. |
| `scripting` | obligatorie | Injectează sonda de permisiuni în tab-ul activ, la cerere. |
| `contextMenus` | obligatorie | Adaugă opțiunile din meniul contextual. |
| `webNavigation` | **opțională** | Necesară pentru avertismentul înainte de navigare. |
| `*://*/*` (host) | **opțională** | Accesul la site-uri este cerut doar când activezi monitorizarea navigării. |

**Least privilege:** nu se solicită implicit acces la toate site-urile (`host_permissions` lipsește), iar extensia
funcționează complet pentru analiza inițiată manual fără permisiunile opționale.

---

## Confidențialitate

Pe scurt: **totul este local** în mod implicit. Fără telemetrie, fără cont, fără urcarea istoricului. Detalii complete
în [PRIVACY.md](PRIVACY.md). Aspecte de securitate a implementării în [SECURITY.md](SECURITY.md).

---

## Structura proiectului

```
SentinelShield2/
├─ manifest.json                 # Manifest V3
├─ assets/icons/                 # iconițe 16/32/48/128 (generate procedural)
├─ src/
│  ├─ analyzer/                  # logica pură de analiză (fără API Chrome)
│  │  ├─ index.js                # fațada analyzeTarget()
│  │  ├─ urlAnalyzer.js          # fapte despre URL
│  │  ├─ domainAnalyzer.js       # domeniu, homoglife, typosquatting
│  │  ├─ phishingRules.js        # 26 de reguli explicabile
│  │  ├─ riskScorer.js           # scor, liste, reputație, verdict
│  │  └─ reputationProvider.js   # adaptor HTTP opțional
│  ├─ background/serviceWorker.js
│  ├─ content/permissionMonitor.js
│  ├─ popup/                     # popup.html/css/js
│  ├─ details/                   # pagina de detalii
│  ├─ warning/                   # pagina de avertizare
│  ├─ options/                   # pagina de setări
│  ├─ storage/storageManager.js
│  └─ shared/                    # constante, validatoare, IDN, UI
├─ scripts/                      # build, validare manifest, generare iconițe
├─ tests/                        # Vitest
└─ docs: README, PRIVACY, SECURITY, CHANGELOG
```

### Abateri documentate față de structura minimă cerută

Structura din cerință include `urlAnalyzer.js`, `phishingRules.js`, `storageManager.js` etc. Am adăugat, justificat:

- `src/shared/idn.js` — decodor Punycode (RFC 3492) pentru afișarea corectă a domeniilor Unicode.
- `src/shared/messages.js` — tipurile de mesaje și cheile de sesiune, centralizate.
- `src/shared/ui.css`, `src/shared/ui.js`, `src/shared/verdictView.js` — temă și redare partajate, pentru explicații
  consecvente și pentru a evita `innerHTML`.
- `src/analyzer/index.js` — un singur punct de compunere a analizei, ca să nu existe logică duplicată.
- `src/details/` — pagina de detalii (cerută implicit prin linkul „detalii”).
- `scripts/` — generare iconițe, build, validare.

---

## Dezvoltare: instalare, teste, build

Cerințe: **Node >= 20** (testat pe Node 24.19.0, npm 11.17.0).

```powershell
npm install       # doar pentru dezvoltare (Vitest, jsdom)
npm run test      # rulează suita de teste
npm run validate  # validează manifestul și sursele
npm run build     # construiește dist/SentinelShield2
```

> Pe Windows/PowerShell, dacă `npm` este blocat de politica de execuție, folosește `npm.cmd run test` sau
> direct `node node_modules/vitest/vitest.mjs run`.

Suita de teste acoperă, printre altele: URL-uri sigure / suspecte / malițioase / invalide, URL-uri Unicode și
Punycode, prioritatea allow/block, stocarea și importul configurației, tratarea erorilor, redarea sigură a textului
(fără `innerHTML`) și validarea manifestului.

---

## Testare manuală

După încărcarea extensiei:

| Pas | Acțiune | Rezultat așteptat |
| --- | --- | --- |
| 1 | Popup pe `https://www.google.com/` → **Analizează pagina** | „Fără indicatori evidenți de risc”, cu precizarea că nu este o garanție. |
| 2 | Verifică `http://example.com/` | Risc scăzut; indicator despre HTTP (confidențialitate, nu phishing). |
| 3 | Verifică `https://xn--pypal-4ve.com/` | Risc ridicat; domeniu afișat cu forma Unicode „paypal” și evidențierea caracterelor. |
| 4 | Verifică `javascript:alert(1)` | Risc ridicat; schemă periculoasă. |
| 5 | Verifică `nu este un url` | Mesaj de eroare clar, fără verdict inventat. |
| 6 | Adaugă un domeniu în blocklist, apoi analizează-l | Risc ridicat, cu nota că vine din lista ta. |
| 7 | Adaugă același domeniu și în allowlist | Blocklist-ul are prioritate. |
| 8 | Exportă configurația, apoi importă fișierul | Raport de import; fără duplicate. |
| 9 | Importă un fișier JSON invalid | Eroare clară; nimic nu se modifică. |
| 10 | Setări → activează monitorizarea, vizitează un link blocat | Pagina de avertizare; „Continuă oricum” acordă 10 minute. |

---

## Limite cunoscute

- Analiza este **euristică**: poate produce atât ratări, cât și fals pozitive.
- **Nu** poate confirma intenția proprietarului unui site; „confirmat” necesită o sursă externă de reputație.
- Monitorizarea navigării **nu este sincronă**: `webNavigation.onBeforeNavigate` nu poate anula o navigare deja
  pornită. Intervenția este o redirecționare imediată către pagina de avertizare; o parte din pagină se poate încărca
  înainte. Nu toate tipurile de navigare pot fi interceptate.
- Listele de branduri și de cuvinte-cheie sunt **incomplete** prin natura lor.
- Extensia **nu** inspectează formulare, parole sau cookie-uri și **nu** încearcă.

---

## Documente conexe

- [PRIVACY.md](PRIVACY.md) — ce date sunt prelucrate, unde rămân și cum sunt protejate.
- [SECURITY.md](SECURITY.md) — model de amenințare, decizii de securitate și cum raportezi o vulnerabilitate.
- [CHANGELOG.md](CHANGELOG.md) — istoricul versiunilor.
