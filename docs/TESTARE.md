# Testare

Rulare: `npm test` (unitare + integrare simulată) și `npm run test:e2e` (Chrome real).

## Acoperirea scenariilor obligatorii

| # | Scenariu | Unde |
|---|---|---|
| 1 | Domeniu legitim HTTPS | `url-engine` |
| 2 | Domeniu confirmat malițios (listă de test) | `url-engine`, `core-flow`, e2e |
| 3 | Imitație de brand | `url-engine` |
| 4 | Unicode confuzabil / omograf | `url-engine`, e2e (avertizare cu caractere evidențiate) |
| 5 | `@` și credențiale | `url-engine` |
| 6 | Redirecționare către domeniu suspect | `core-flow` (server + parametru), e2e (redirecționare reală 302) |
| 7 | Cameră/microfon | `behavior`, e2e |
| 8 | Locație | `behavior`, e2e |
| 9 | Citire clipboard / scriere de comandă | `behavior`, e2e |
| 10 | Formular de autentificare suspect | `behavior`, e2e |
| 11 | Descărcare cu extensie înșelătoare | `downloads-reputation`, e2e (descărcare reală pusă în pauză și anulată) |
| 12 | Serviciu de reputație indisponibil | `downloads-reputation` |
| 13 | Timeout și lipsă de conectivitate | `downloads-reputation` |
| 14 | Mesaje manipulate | `core-flow` |
| 15 | Site legitim cu multe scripturi terțe | `behavior` |
| 16 | Site necunoscut fără indicatori | `url-engine`, `behavior` |
| 17 | Încercare de ocolire a avertizării | `core-flow`, e2e |
| 18 | URL cu tokenuri/parametri sensibili | `core-flow`, `downloads-reputation` |

Fiecare test verifică și **explicația** afișată (ex. „Dacă aprobi cererea…", „nu a fost salvat"), nu doar nivelul.

## Rezultate la data livrării
- `npm test`: 109/109 teste trec.
- `npm run validate`: manifest valid, 0 probleme.
- `npm run test:e2e` (Chrome 155 stabil, profil temporar, domenii `*.example` mapate la server local): 32/32 verificări trec. Capturi în `tests/e2e/out/`.
- **Neverificat în Chrome real:** modul DNR „Blocare timpurie" (cere acordarea interactivă a permisiunilor), apeluri către URLhaus/Safe Browsing/feed-uri reale, Chrome pe macOS/Linux.
