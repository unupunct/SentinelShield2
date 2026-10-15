# 🛡 Sentinel Shield

Extensie Google Chrome (Manifest V3) care protejează împotriva phishingului, a site-urilor malițioase și a descărcărilor periculoase, **explicând** de ce o pagină este considerată riscantă. Procesare locală implicită, fără reclame, fără tracking, fără secrete în cod.

> **Stare:** versiune 0.1.0, încărcabilă prin Developer Mode. **Nu este publicată în Chrome Web Store.**

## Ce face

| Funcție | Detalii |
|---|---|
| Verificare URL înainte de navigare | Normalizare, IDN/Punycode, omografe, imitații de brand (inclusiv branduri românești), `@`/credențiale, IP obfuscat, scurtatoare, parametri de redirecționare, combinații de tip phishing |
| Reputație | Liste locale (mereu active) + feed-uri importate de utilizator + furnizori online **opționali** (URLhaus, Google Safe Browsing) cu consimțământ explicit |
| Scor transparent | 4 niveluri: Risc redus / Suspect / Periculos / Neverificat; verdictul surselor de reputație e separat de scorul euristic |
| Pagină de avertizare | Locală, cu explicații pe două niveluri, indicatori, surse; continuarea cere acțiune deliberată |
| „Ce vrea să acceseze?" | Permisiuni cerute (observat) vs. API disponibil vs. acordat; formulare, clipboard, ferestre, domenii terțe, mesaje scareware |
| Descărcări | Extensii înșelătoare, executabile, arhive din surse riscante, nepotrivire MIME; descărcările cu risc ridicat sunt puse în pauză pentru decizia ta |
| Panou local | Statistici reale, istoric, filtre, export controlat, excepții, surse externe, confidențialitate |

## Instalare ușoară (2 minute, fără compilare)

1. Descarcă **`sentinel-shield-0.1.0.zip`** din [Releases](https://github.com/unupunct/SentinelShield2/releases/latest) și dezarhivează-l într-un folder pe care îl păstrezi (Chrome îl citește de acolo; nu-l șterge).
2. În Chrome deschide `chrome://extensions` și pornește **Developer mode** (colțul din dreapta sus).
3. Apasă **Load unpacked** și alege folderul dezarhivat (cel care conține `manifest.json`).
4. Fixează iconița 🛡 în bara Chrome.

> Chrome nu permite instalarea extensiilor din afara magazinului fără Developer mode (decât prin politici de întreprindere). Singura instalare „cu un click" ar fi publicarea în Chrome Web Store, care nu a fost făcută.

## Instalare din cod sursă (Developer Mode)

1. Deschide `chrome://extensions` și activează **Developer mode**.
2. **Load unpacked** → alege folderul acestui proiect (cel care conține `manifest.json`).
3. Fixează iconița 🛡 din bara Chrome. Gata: protecția locală funcționează imediat.

Alternativ, din ZIP: rulează `npm run build:zip`, dezarhivează `dist/sentinel-shield-0.1.0.zip` într-un folder și folosește **Load unpacked** pe acel folder.

## Ghid de utilizare

- **Popup** (click pe iconiță): nivelul paginii curente, explicația, permisiuni observate, domenii terțe, ultimele evenimente, „Analizează pagina", „Vezi raportul complet".
- **Avertizare**: apare când un site este confirmat ca periculos sau are indicatori puternici. „Înapoi la siguranță" este acțiunea principală. „Continuă oricum" este ascuns într-o secțiune separată și cere: pentru amenințări confirmate, scrierea domeniului + 8 s de așteptare; pentru risc euristic, apăsare prelungită după 3 s.
- **Panou** (Setări): Prezentare · Istoric alerte · Raport pagină · Liste de încredere · Surse externe · Confidențialitate · Protecție.

### Detecție reală: listele
Lista inclusă în repository conține **doar intrări sintetice de test** (`*.sentinel-test.example`). Pentru a bloca domenii reale cunoscute:
- activează **feed-uri** în *Surse externe* (presetări: URLhaus hostfile, OpenPhish) sau
- importă o listă în *Liste de încredere → Listă proprie de domenii blocate* (hosts / domenii / URL-uri).

Detecția euristică (omografe, imitații de brand, `@` etc.) funcționează fără liste și fără rețea.

## Configurarea opțională a serviciilor externe

Toate sunt **dezactivate implicit**. În *Surse externe* fiecare furnizor arată exact ce date se transmit, cui și de ce; activarea cere cheia ta, consimțământul bifat și permisiunea de rețea a browserului.

| Serviciu | Ce se trimite | Cheie |
|---|---|---|
| URLhaus (abuse.ch) | doar **numele domeniului** (`POST https://urlhaus-api.abuse.ch/v1/host/`) | `Auth-Key` din portalul abuse.ch (obligatorie conform documentației) |
| Google Safe Browsing v4 (Lookup) | adresa paginii **fără parametri/fragment** (implicit) către `safebrowsing.googleapis.com` | cheie API Google Cloud; verifică termenii de utilizare |
| PhishTank | nu este integrat live (endpoint HTTP necriptat; emiterea de chei noi nedocumentată). Poți importa o listă exportată. | — |

URL-urile interne, cu credențiale sau cu tokenuri nu sunt trimise niciodată. Detalii: [docs/CONFIDENTIALITATE.md](docs/CONFIDENTIALITATE.md).

## Dezvoltare și teste

```bash
npm install
npm test              # 109 teste unitare/integrare (Vitest, Chrome simulat)
npm run validate      # manifest, permisiuni, fișiere referite, absența eval/innerHTML/secrete
npm run test:e2e      # 32 verificări în Chrome real (puppeteer-core, domenii *.example mapate local)
npm run icons         # regenerează pictogramele
npm run build:zip     # dist/sentinel-shield-<versiune>.zip
```

`test:e2e` folosește Chrome-ul instalat (sau calea dată ca argument) cu un profil temporar și mapează toate gazdele `*.example` către un server local: **nu accesează infrastructură externă**. Capturile rezultate sunt în `tests/e2e/out/`.

## Documentație

- [Arhitectură](docs/ARHITECTURA.md)
- [Matricea permisiunilor](docs/PERMISIUNI.md)
- [Model de amenințări](docs/MODEL-AMENINTARI.md)
- [Confidențialitate](docs/CONFIDENTIALITATE.md)
- [Limitări cunoscute](docs/LIMITARI.md)
- [Testare și rezultate](docs/TESTARE.md)
