# Confidențialitate

## Principii
- **Procesare locală implicită.** Analiza URL-urilor, a descărcărilor și a comportamentului rulează în browser. Fără servere proprii, fără telemetrie, fără reclame, fără tracking.
- **Fără colectarea parolelor.** Extensia nu citește valorile câmpurilor de formular, nu intercepteaza tastarea, nu citește conținutul clipboardului.
- **Fără istoric complet.** Jurnalul păstrează doar alerte (Suspect/Periculos/Neverificat), descărcări riscante și constatări comportamentale. Paginile cu risc redus sunt doar *numărate* (contor fără URL).
- **Fără secrete în cod/repository.** Cheile API sunt introduse de utilizator, stocate în `chrome.storage.local`, nu sunt returnate către interfață după salvare și nu apar în exporturi sau jurnal.

## Ce se stochează local
| Date | Unde | Retenție |
|---|---|---|
| Alerte (URL redactat, indicatori, surse, explicații, acțiune) | `storage.local` | implicit 30 zile / max. 1000 evenimente; ștergere manuală oricând |
| Contor anonim de pagini analizate | `storage.local` | până la ștergerea jurnalului |
| Excepții utilizator (gazdă, schemă, tip, expirare) | `storage.local` | expiră (implicit 30 zile) sau ștergere manuală |
| Liste proprii/feed-uri | `storage.local` | până la ștergere/actualizare |
| Configurare, chei API | `storage.local` | până la modificare |
| Stare per filă, avertizări emise (conțin URL complet), permise | `storage.session` | doar în memoria browserului; dispar la închidere |

**URL în jurnal** (setabil): elimină doar parametrii sensibili (implicit) · elimină toți parametrii · doar domeniul · URL complet. În toate modurile: credențialele `user:parolă@` și fragmentul sunt eliminate (cu excepția „URL complet", unde fragmentul rămâne; credențialele tot nu).

**Redactate implicit:** parametri precum `token`, `access_token`, `id_token`, `password`, `session`, `sid`, `code`, `key`, `api_key`, `signature`, `jwt`, `email`, `card`, `iban`… și orice valoare care seamănă cu un JWT / șir hex / token lung.

## Ce nu se stochează niciodată
Parole, conținutul formularelor, textul din clipboard, coordonate, fluxuri media, cookie-uri, conținutul paginilor (doar *coduri* de tipare, ex. `virus-warning`), chei API în export.

## Transmiteri către terți (toate opționale, dezactivate implicit)

| Serviciu | Ce se trimite | Către cine | Scop |
|---|---|---|---|
| URLhaus | Numele domeniului vizitat + cheia ta `Auth-Key` | `urlhaus-api.abuse.ch` | Aflarea dacă domeniul distribuie malware |
| Google Safe Browsing v4 | URL-ul paginii, implicit fără parametri și fragment, + cheia ta | `safebrowsing.googleapis.com` | Aflarea dacă URL-ul e listat pentru phishing/malware |
| Feed-uri (URLhaus hostfile, OpenPhish) | Nimic despre tine: doar `GET` pentru lista publică | gazda feed-ului | Reîmprospătarea listelor locale |

Garanții: consimțământ explicit per furnizor (retras automat la dezactivare) · permisiune de rețea acordată separat în browser · URL-urile interne (IP privat, `.local`, fără sufix public), cu credențiale, cu tokenuri sau cu segmente de tip token **nu se trimit niciodată** · fără cookie-uri (`credentials: omit`), fără `Referer` · cache cu expirare pentru a reduce cererile · limită de cereri/minut.

> Conform recomandării de design: un URL trimis unui furnizor extern poate expune informații din adrese private sau linkuri cu tokenuri. De aceea modul local rămâne complet funcțional, iar trimiterea este opt-in.

## Drepturile tale
Poți vedea tot ce e stocat (Istoric), exporta (rezumat/complet, local, nu se trimite nicăieri), șterge jurnalul, șterge excepțiile și listele, retrage consimțământul sau dezinstala extensia (toate datele locale dispar).
