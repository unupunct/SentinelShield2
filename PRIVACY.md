# Politica de confidențialitate — SentinelShield2

**Pe scurt:** SentinelShield2 funcționează **local**. Nu are cont, nu trimite telemetrie și nu colectează implicit
date despre tine. Singurele date care părăsesc dispozitivul sunt cele pe care le trimiți **explicit** către o sursă de
reputație pe care ai configurat-o tu însuți.

Versiune document: 0.1.0.

---

## 1. Ce date prelucrează extensia

| Date | Scop | Unde ajung |
| --- | --- | --- |
| Adresa (URL-ul) analizat | Analiză locală, afișare verdict | Rămân local |
| Numele de domeniu | Analiză, potrivire cu listele | Rămân local |
| Setările tale | Comportamentul extensiei | `chrome.storage.local` |
| Listele allowlist / blocklist | Analiză, prioritate | `chrome.storage.local` |
| Ultima analiză pentru un tab | Afișare rapidă | `chrome.storage.session` (se șterge la închiderea browserului / a sesiunii) |

Extensia **nu** prelucrează: formulare, câmpuri de parolă, cookie-uri, conținutul paginilor, istoricul de navigare
dincolo de adresa analizată la cerere.

## 2. Ce NU face niciodată extensia

- **Nu** urcă istoricul de navigare nicăieri.
- **Nu** citește și **nu** colectează formulare, parole sau cookie-uri.
- **Nu** are telemetrie, analytics sau „phone home”.
- **Nu** folosește cod de la distanță (fără `eval`, fără scripturi remote).
- **Nu** citește conținutul paginii decât pentru a **număra** dispozitive multimedia și pentru a citi stările de
  permisiuni raportate de browser, la cerere.

## 3. Analiza locală

Analiza URL-urilor este realizată integral în browser, de module pure (`src/analyzer/*`). Niciun rezultat nu este
trimis în rețea pentru a produce un verdict. Verdictul este explicat local, cu regulile care l-au produs.

## 4. Sursa de reputație (opțională, dezactivată implicit)

Dacă **și numai dacă** activezi această opțiune și configurezi un endpoint HTTPS, la cerere extensia trimite:

- **implicit:** doar **numele de domeniu** (ex. `exemplu.ro`), plus forma Unicode și domeniul registrabil;
- dacă dezactivezi opțiunea „doar numele de domeniu”: se adaugă **calea** și **schema** (ex. `/cont/login`),
  **fără** parametri de query și **fără** fragment.

Nu sunt trimise niciodată: parametrii din URL (care pot conține tokenuri), cookie-uri, capul cererii sau alte date
personale. Sursa este aleasă de tine; extensia nu impune niciun furnizor terț.

Eticheta „Periculos confirmat” se acordă doar dacă ai bifat explicit că ai încredere în sursă (`confirmMalicious`).

## 5. Unde sunt stocate datele și cât timp

- **`chrome.storage.local`** — setări și liste, până când le ștergi (resetare sau ștergerea extensiei).
- **`chrome.storage.session`** — ultima analiză pe tab, avertismentul în curs și excepțiile temporare (max. 10
  minute). Se curăță automat la închiderea sesiunii browserului.
- Paginile de interfață (popup, detalii, avertisment) primesc verdictul prin `chrome.storage.session`, **nu** prin
  parametri de URL, pentru ca adresa analizată să nu ajungă în istoricul browserului.

## 6. Injectarea de scripturi

Extensia nu are un content script permanent. `permissionProbe` este injectat **la cerere**, doar în tab-ul activ, prin
`chrome.scripting.executeScript`, folosind `activeTab`. Sonda citește:

- stările de permisiuni raportate de browser (`navigator.permissions`),
- **numărul** de dispozitive multimedia (fără etichete, care pot conține date personale),
- dacă pagina rulează într-un context securizat.

## 7. Export și import

Exportul produce un fișier JSON cu setările și listele tale. Acest fișier **nu conține** adrese vizitate sau istoric.
Importul validează strict structura și ignoră intrările invalide sau duplicate.

## 8. Permisiuni

Vezi justificarea fiecărei permisiuni în [README.md](README.md#permisiuni-și-justificare). Accesul la toate site-urile
este **opțional** și se acordă doar când activezi monitorizarea navigării.

## 9. Modificări ale acestei politici

Orice schimbare este consemnată în [CHANGELOG.md](CHANGELOG.md). Politica reflectă comportamentul codului din acest
repository.

## 10. Contact

Acesta este un proiect local. Pentru întrebări legate de date, inspectează direct codul sursă: este singura dovadă
relevantă a comportamentului.
