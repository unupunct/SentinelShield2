# Securitate — SentinelShield2

Acest document descrie modelul de amenințare, deciziile de securitate ale implementării și modul de raportare a unei
probleme. Versiune document: 0.1.0.

---

## 1. Model de amenințare

Extensia analizează **intrări neîncrezute**: adrese URL lipite de utilizator, linkuri din pagini, răspunsuri de la
surse de reputație și fișiere JSON importate.

Adversari luați în considerare:

| Adversar | Scop | Apărare |
| --- | --- | --- |
| Autor de phishing | Să facă un link să pară legitim (homoglife, typosquatting, brand în subdomeniu) | `idn.js`, `domainAnalyzer.js`, reguli dedicate |
| Pagină web ostilă | Să execute cod în contextul extensiei prin texte afișate | Nu se folosește niciodată `innerHTML`; doar noduri de text |
| Fișier de configurație malițios | Să injecteze intrări „otrăvite” în liste | Validare strictă la import; intrările invalide sunt ignorate |
| Sursă de reputație compromisă | Să forțeze „Periculos confirmat” | Confirmarea cere un pas explicit de încredere din partea utilizatorului |
| Adversar care modul de detecție | Să evite detecția cu caractere Unicode/periculoase | Normalizare + afișare cu evidențiere; limitele sunt documentate, nu ascunse |

**Nu** face parte din modelul de amenințare: un adversar cu acces la dispozitiv sau la profilul Chrome (poate citi
`chrome.storage`), și nici un adversar care poate modifica codul extensiei.

## 2. Decizii de securitate

- **Manifest V3**, fără cod de la distanță. CSP: `script-src 'self'; object-src 'self'`.
- **Fără `innerHTML` / `eval` / `new Function` / `document.write`.** Textul extern trece exclusiv prin `textContent`
  și noduri de text. Verificat automat în `tests/manifest.test.js` și de `scripts/validate-manifest.mjs`.
- **Least privilege.** Permisiuni minime; accesul la toate site-urile este opțional.
- **Validare strictă a intrărilor.** URL-uri, domenii și JSON importat sunt validate; intrările corupte sunt ignorate.
- **Redactare.** Valorile parametrilor sensibili (tokenuri, parole) sunt redactate din dovezi și jurnale
  (`redactUrl`).
- **Confidențialitate implicită.** Reputația este dezactivată implicit; se trimite doar numele de domeniu, niciodată
  parametrii.
- **Fără evaluare de HTML din date.** Intervalele suspecte din adrese sunt afișate cu elemente `<mark>` construite în
  siguranță, nu prin șabloane de HTML.
- **Erori explicite.** Nicio operațiune nu „pretinde” un succes; erorile sunt afișate utilizatorului.

## 3. Zone sensibile ale codului

| Fișier | De ce este sensibil |
| --- | --- |
| `src/shared/ui.js` | Singurul loc care creează DOM din texte externe. Nu folosește `innerHTML`. |
| `src/shared/validators.js` | Validare URL/domeniu, redactare. Intrare neîncrezută. |
| `src/storage/storageManager.js` | Import de configurație; normalizare strictă. |
| `src/content/permissionMonitor.js` | Script injectat în pagini; citește doar stări de permisiuni, sanitizează răspunsul. |
| `src/background/serviceWorker.js` | Interceptarea navigării, excepții temporare, redirecționare. |
| `src/analyzer/reputationProvider.js` | Singurul loc care face cereri de rețea. |

## 4. Limitări de securitate cunoscute (documentate, nu ascunse)

- **Navigarea nu poate fi anulată sincron.** `webNavigation.onBeforeNavigate` nu poate opri o navigare deja pornită.
  Intervenția este o redirecționare imediată către pagina de avertizare; o parte din pagină se poate încărca înainte.
- **Detecția este euristică.** Ratări și fals pozitive sunt posibile.
- **Cheile API ale sursei de reputație** stocate într-o extensie distribuită **nu sunt protejate** față de cine
  inspectează extensia. Nu include chei în cod; folosește un endpoint propriu.
- **Sursa de reputație** poate avea fals pozitive/negative; „confirmat” reflectă încrederea ta în sursă, nu un fapt
  absolut.

## 5. Cum raportezi o problemă de securitate

1. Nu deschide un issue public pentru vulnerabilități exploatabile.
2. Descrie: versiunea extensiei, pașii de reproducere, impactul estimat și, dacă se poate, o dovadă minimă.
3. Dacă rulezi din sursă, include rezultatul `npm run validate` și al suitei de teste.

## 6. Verificări automate

`npm run test` și `npm run validate` verifică:

- manifest MV3 valid, fără chei MV2,
- absența `innerHTML`, `eval`, `new Function`, `document.write` în codul sursă,
- CSP fără `unsafe-eval` / `unsafe-inline` / origini de la distanță,
- inexistența resurselor externe în paginile HTML,
- redarea sigură a textului ostil (teste pe `el`, `showMessage`, `renderHighlightedText`).
