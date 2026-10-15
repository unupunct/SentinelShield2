# Limitări cunoscute

Spus direct, ca să nu existe pretenții false.

## 1. Interceptarea navigării (Manifest V3)
- Fără permisiuni extinse, extensia folosește `webNavigation`. La `onBeforeNavigate` fila e redirecționată către avertizare, dar **cererea poate porni** și, în cazul **redirecționărilor de server**, doar **destinația finală** este raportată (la `onCommitted`, observat în Chrome 155): pagina finală poate fi încărcată scurt înainte să fie înlocuită cu avertizarea. Hop-urile intermediare nu sunt vizibile fără `webRequest`/DNR.
- **Atenuare:** modul opțional „Blocare timpurie" (DNR cu acces la gazde) redirecționează înainte de încărcare, inclusiv în lanțuri. Necesită permisiuni extinse; **cererea și instalarea regulilor sunt acoperite de teste cu Chrome simulat, dar nu au putut fi verificate în Chrome real** (acordarea permisiunilor cere gest utilizator, imposibil în testarea automată). Verifică manual după activare.
- Verificările online asincrone redirecționează după fapt.
- Subcadrele (`iframe`) nu primesc avertizare de navigare; resursele către domenii listate sunt raportate doar ca observație comportamentală.
- Nu putem intercepta pagini `chrome://`, Chrome Web Store, PDF-uri interne sau navigări înaintea pornirii service worker-ului la rece (prima navigare după repornire poate fi evaluată cu o mică întârziere).

## 2. Reputație
- Lista inclusă este **sintetică**. Fără feed-uri/liste importate sau furnizori online, nu se cunosc domenii malițioase reale; funcționează doar euristica.
- Presetările de feed (URLhaus hostfile, OpenPhish) **nu au fost testate live** de dezvoltator (nu s-a accesat infrastructură externă); verifică adresa și licența.
- URLhaus API cere `Auth-Key`; Safe Browsing Lookup trimite URL-ul (vezi confidențialitate). Implementările respectă documentația oficială consultată la data dezvoltării (15.10.2026), dar nu au fost rulate împotriva serviciilor reale — doar împotriva unor răspunsuri simulate.
- PhishTank nu este integrat (endpoint HTTP necriptat; chei noi nedocumentate).
- Domeniu înregistrabil: se folosește un subset din Public Suffix List (sufixe multi-etichetă frecvente + platforme de găzduire partajată). Sufixe necunoscute → ultima etichetă.

## 3. Analiza comportamentală
- Se observă ce poate vedea JavaScript din pagină. Pagina poate detecta/ocoli învelișurile `hook.js`; atunci cererile ei nu sunt observate. **Lipsa unei observații nu e dovadă de siguranță.**
- Nu se poate stabili intenția operatorului, ce date citește pagina sau ce conține o cerere de rețea. Interfața spune doar ce s-a observat.
- „Utilizare confirmată" a unei permisiuni nu poate fi stabilită; cel mai ridicat nivel e „acces obținut (apel reușit)".
- Pentru camera/microfon/clipboard, API-urile există doar în contexte securizate (HTTPS/localhost).
- Cadrele cu `sandbox`, `about:blank` și documentele fără content script nu sunt acoperite. Domeniile terțe sunt cele din Resource Timing (limitat de buffer-ul browserului) și din DOM.
- Detectarea textului (scareware/„rulează comanda") e bazată pe tipare în RO/EN: poate rata variante sau avea fals pozitive.
- Justificarea unei permisiuni („probabil justificată / neobișnuită") e o euristică simplă (hartă/video/parolă în pagină).

## 4. Descărcări
- Nu se scanează conținutul și nu se verifică „magic bytes" (extensiile nu pot citi fișiere descărcate fără permisiuni suplimentare). Nepotrivirea MIME ↔ nume se bazează doar pe tipul declarat de server.
- Nu se execută niciodată fișiere. Nu se dezactivează și nu se suprascriu avertizările Chrome; „Reia" doar reia descărcarea.
- Numele final al fișierului e cunoscut uneori abia după `onCreated`; se reanalizează la schimbarea numelui, dar descărcarea poate fi deja finalizată (atunci pauza nu mai are efect).
- Pagina inițiatoare e dedusă din `referrer` → poate lipsi.

## 5. Euristici URL
- Falsuri pozitive posibile (ex. domenii care conțin numele unui brand în mod legitim, IDN legitime foarte asemănătoare); falsuri negative sigure (domenii noi fără indicatori). „Risc redus" **nu garantează siguranța**.
- Lista de branduri e un set inițial (≈40, inclusiv RO), nu exhaustivă.
- URL-urile scurtate nu sunt expandate (nu se accesează URL-uri suspecte).

## 6. Altele
- Interfața este în română; nu există localizare.
- Capacitate: liste până la ≈100.000 intrări (limită de stocare locală).
- Testele end-to-end rulează în Chrome 155 pe Windows; alte platforme/versiuni neverificate.
- Extensia nu este publicată în Chrome Web Store.
