# Model de amenințări

## Active protejate
Parolele și datele introduse de utilizator · istoricul de navigare · integritatea verdictelor · integritatea paginii de avertizare și a deciziilor utilizatorului · cheile API ale utilizatorului.

## Adversari
1. **Site malițios** (phishing, malware, scareware).
2. **Site care țintește extensia**: falsifică observații, încearcă să ocolească avertizarea, să-și adauge domeniul în lista de încredere, să încadreze pagina de avertizare.
3. **Rețea / furnizor de reputație curios sau compromis**: poate vedea ce se trimite.
4. **Alte extensii / pagini web** care încearcă să trimită mesaje extensiei.

## Amenințări și atenuări

| # | Amenințare | Atenuare | Test |
|---|---|---|---|
| T1 | Site falsifică mesaje de la content script („am cerut cameră", nume de gazde ostile, valori uriașe) | Validare strictă: construire de obiect nou, whitelist de câmpuri, enumerări, limite, regex pentru gazde; limită de rată per filă; ignorare documente de altă origine decât navigarea; **observațiile nu pot produce singure „Periculos/confirmat"** (plafon la „Suspect") | `core-flow` (14) |
| T2 | Site detectează/ocolește învelișurile din `hook.js` | Acceptat: protecția URL și reputația nu depind de el. Lipsa observației ≠ dovadă de siguranță (documentat) | LIMITARI §3 |
| T3 | Site încearcă să trimită comenzi privilegiate către service worker (adăugare în lista de încredere, setări, grantPass) | Orice mesaj în afara `ss.observation` e acceptat **doar** dacă `sender.id` = extensia și `sender.url` începe cu originea extensiei; content scripts și pagini web primesc `forbidden-sender`. Nu există `externally_connectable` | `core-flow` (17), e2e |
| T4 | Manipularea conținutului paginii de avertizare prin parametri URL (XSS/spoofing) | Pagina primește doar un UUID opac; datele vin din service worker; afișare exclusiv prin `textContent`; CSP strictă | e2e, `validate` |
| T5 | Clickjacking: pagină web încadrează `warning.html` | Pagina refuză în cadru; service worker respinge `getWarning/grantPass/goSafe` din cadre ≠ 0; continuarea cere scriere de text / apăsare prelungită (nu un click) | `core-flow` |
| T6 | Click accidental pe „Continuă" | Secțiune închisă, separată, la distanță de butonul sigur; timp de gândire impus **în service worker**; confirmare prin scrierea domeniului (confirmat) / apăsare 2 s (euristic) | e2e |
| T7 | Reutilizare / predare a unei avertizări între file | Verificare filă, intrare de unică folosință, TTL; permis per filă+origine; expirare | `core-flow` |
| T8 | Site își adaugă domeniul în lista de încredere | Doar paginile extensiei pot trimite `ss.addException`; excepție exactă pe schemă+gazdă (fără subdomenii); pentru amenințări confirmate cere confirmare explicită distinctă | `core-flow` |
| T9 | URL cu tokenuri în jurnal/export/servicii externe | Redactare implicită, credențiale eliminate întotdeauna, fragment eliminat; URL-urile cu tokenuri/credențiale/interne nu se trimit; export fără chei | `core-flow` (18), `downloads-reputation` |
| T10 | Furnizor extern primește mai mult decât se aștepta | Dezactivat implicit; consimțământ bifat + cheie + permisiune de rețea; URLhaus primește doar gazda; Safe Browsing URL fără query; `credentials: omit`, `no-referrer`; informare afișată | `downloads-reputation` |
| T11 | Disponibilitate: servicii lente/indisponibile blochează protecția | Verificarea locală e sincronă și independentă; timeout, cache, rate limit, întrerupător după 3 erori; „nu a putut fi verificat" ≠ „curat" | `downloads-reputation` (12, 13) |
| T12 | Feed-uri externe ostile (blocarea domeniilor oficiale, volum uriaș) | Limită de dimensiune și număr; omiterea domeniilor oficiale ale brandurilor și a platformelor de găzduire partajată; potrivire URL exactă pentru platforme partajate; la eșec total se păstrează lista veche | `downloads-reputation` |
| T13 | Cod executabil descărcat dinamic / injecție | Fără `eval`, fără scripturi inline, fără cod la distanță; feed-urile sunt doar date (text) | `validate` |
| T14 | Conflict de sincronizare a stării (redirecționări pierdute) | Procesare serializată per filă | e2e (redirecționare) |

## Riscuri reziduale (acceptate, documentate)
Falsuri pozitive/negative euristice; liste implicite doar de test; interceptare incompletă fără modul DNR; un site poate fi evaluat „Risc redus" și totuși periculos. Vezi [LIMITARI.md](LIMITARI.md).
