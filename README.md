# ValidareSemnatura-eCI (Windows)

<img src="assets/sample.png" width="600" />

## Pe scurt

**ValidareSemnatura-eCI** este o aplicație Windows portabilă (executabil `.exe`) care verifică dacă un PDF a fost semnat corect cu **certificatul de semnătură electronică avansată din Cartea Electronică de Identitate (CEI)**, emis de MAI.

Aplicația face **doar validare tehnică criptografică**:
– integritatea semnăturii
– validitatea lanțului de certificate
– încrederea în Root CA + Sub CA MAI
– (opțional) emitentul exact al certificatului semnatar

Nu autentifică persoane, nu face login, nu trimite date și nu modifică documente.

**Notă rețea / confidențialitate:**
Aplicația **nu trimite niciodată PDF-ul** și nu încarcă documente.
Poți alege verificarea revocării fie prin **rețea** (CRL/AIA/OCSP), fie folosind **CRL locale** din `assets/certs/*.crl`.
Dacă activezi opțiunea de rețea, aplicația poate face **cereri HTTP** către URL‑uri publicate în certificate pentru verificarea revocării sau a lanțului.
Aceste cereri nu conțin documentul, doar cer informații despre certificate.

---

## Cel mai important lucru de știut (eCI only)

Aplicația este construită **strict pentru semnături eCI** (Root/Sub MAI).

- Dacă un PDF are semnături mixte (ex: eCI + alt certificat calificat / eSeal / altă CA), atunci:
  - cu **Root/Sub MAI** încărcate, semnăturile eCI pot fi VALID, iar cele non‑eCI vor fi INVALID.
  - dacă încarci **alte Root/Sub** (non‑MAI), semnăturile eCI vor apărea INVALID.

Concluzie: rezultatele sunt corecte doar dacă **toate semnăturile** sunt așteptate să provină din eCI.

---

## Cum se folosește (GUI – recomandat)

1. Rulează `ValidareSemnatura-eCI.exe`
2. Alege sursa certificatelor:
   - certificate MAI incluse (assets/certs) **sau**
   - selectare manuală (Root CA + Sub CA)
3. Selectează:
   - PDF-ul semnat
   - certificatul Root CA
   - certificatul Sub CA
4. (Opțional) bifează opțiunile dorite (rețea, revocare, emitent strict, strict eCI, CRL local, timestamp).
5. Apasă **Validează**
6. Primești rezultatul **VALID / INVALID + detalii complete**
   - tabul **Certificat** afișează Subject/Issuer/SHA256 + EKU/Policy OIDs
   - poți copia detaliile certificatului sau exporta certificatul semnatarului
   - dacă există **mai multe semnături**, apare tabul **Semnături multiple**
     cu status pentru fiecare semnătură + export/copie pe semnătură

---

## Ce verifică (tehnic)

1. **Integritatea semnăturii**
   – documentul nu a fost modificat după semnare

2. **Validitatea criptografică**
   – semnătura este matematic corectă

3. **Lanțul de încredere**
   – semnătura duce la Root CA MAI prin Sub CA MAI

4. **Certificatul semnatarului**
   – extrage DN-ul și amprenta SHA256

5. **(Opțional) Emitent strict**
   – respinge semnătura dacă NU este emisă exact de Sub CA-ul furnizat

6. **Semnături multiple**
   – dacă PDF-ul are mai multe semnături, aplicația le verifică pe fiecare separat

---

## Opțiuni importante

- **Acces la rețea (CRL/AIA/OCSP)**
  – permite verificări de revocare folosind URL‑urile din certificate
- **CRL local (assets/certs/*.crl)**
  – verificare revocare fără internet (dacă ai CRL‑urile local)
- **Mod revocare**
  – soft‑fail / hard‑fail / require (se aplică atunci când rețeaua este activă)
- **Emitent strict (pin Sub CA)**
  – respinge semnătura dacă emitentul nu este exact Sub CA-ul furnizat
- **Mod strict eCI**
  – pin Root/Sub la amprentele MAI + revocare obligatorie
- **Verificare timestamp/LTV (dacă există)**
  – cere un timestamp valid și de încredere; altfel semnătura va eșua

---

## Certificatele MAI

Certificatele Root și Sub CA se pot descărca oficial de aici:

https://hub.mai.gov.ro/cei/info/descarca-cert

Aplicația este compatibilă cu fișiere:
- `.cer`
- `.crt`
- `.pem`

### Certificate incluse (assets/certs)

Dacă alegi varianta „certificate incluse”, aplicația folosește aceste fișiere:

| Fișier | SHA256 |
|---|---|
| `ro_cei_mai_root-ca.cer` | `b7a766f52218c8083e936f9ab085e97c67671ecd4fd3069b641c638072e44b1d` |
| `ro_cei_mai_sub-ca.cer` | `b512f92a6d156008d93ab5ff9690be874afc3401ce0306f477f187799593da80` |

Aplicația afișează aceste amprente în UI și îți permite să le copiezi rapid.

---

## Verificare timestamp/LTV (opțional)

Când este activată, aplicația cere un **timestamp valid și de încredere** în semnătură (sau content timestamp).
Dacă nu există timestamp sau acesta nu este valid/trusted, validarea eșuează.

Limitare: această verificare nu înlocuiește validarea completă LTV la momentul semnării și nu poate garanta statutul legal
în timp; este un control tehnic asupra token‑ului de timestamp.

---

## Mod CLI (opțional)

Aplicația poate fi folosită și din linia de comandă:

```bash
ValidareSemnatura-eCI.exe --pdf document.pdf --root root.cer --sub sub.cer
```

Pentru output JSON:

```
--json
```

---

## Descărcare și utilizare (Windows)

### 1. Descarcă aplicația
Descarcă prima versiune oficială de aici:

👉 https://github.com/24vlh/Validare-Sematura-eCI/releases/download/v2.0.1/ValidareSemnatura-eCI-v2.0.1.zip

---

### 2. Dezarhivează
– click dreapta pe fișierul ZIP
– **Extract All / Extrage tot**
– alege un folder (ex: Desktop)

---

### 3. Rulează aplicația
În folderul extras:
- dublu-click pe **ValidareSemnatura-eCI.exe**
- aplicația pornește direct (nu necesită instalare)

---

### 4. Dacă apare avertisment Windows
Este normal pentru aplicații portabile ne-semnate:

1. Click **More info / Mai multe informații**
2. Click **Run anyway / Rulează oricum**

Aplicația este locală, offline și nu modifică sistemul.

---

### 5. Folosire rapidă
1. Selectează PDF-ul semnat
2. Selectează certificatele Root + Sub CA MAI
3. Apasă **Validează**
4. Primești rezultatul instant

---

### Dezinstalare
Șterge pur și simplu folderul.
Nu rămâne nimic instalat în sistem.

---

## Limitări (intenționate)

Aceasta **NU** este:
- aplicație de producție
- aplicație certificată
- aplicație juridică oficială
- înlocuitor pentru servicii de încredere calificate
- instrument de autentificare a persoanei

Este un **instrument de verificare tehnică**, creat pentru claritate, control și transparență.

### Mod strict eCI (opțional)
Modul strict eCI activează automat:
- pinning Root/Sub la amprentele oficiale MAI
- revocare obligatorie (CRL/OCSP)
- emitent strict (pin Sub CA)

Opțional, poți configura filtrarea EKU/Policy OID direct în cod (`ECI_REQUIRED_EKU_OIDS`, `ECI_REQUIRED_POLICY_OIDS`).

---

## Disclaimer

Această aplicație este oferită **ca utilitar tehnic de ajutor**, fără garanții explicite sau implicite.
Rezultatul este informativ și nu substituie evaluarea juridică sau procedurală oficială.

Folosirea aplicației este pe propria răspundere.

---

## Filosofie

Un document semnat electronic trebuie să poată fi verificat:
- local
- independent
- fără cont
- fără furnizor
- fără magie

Această aplicație face exact asta.
**Nimic mai mult. Nimic mai puțin.**

---

## Verificare integritate & autenticitate fișiere

Pentru a putea verifica că arhiva și executabilul provin **exact din build-ul publicat de mine** și nu au fost modificate, mai jos sunt amprentele criptografice complete ale fișierelor.

Poți recalcula aceste hash-uri local (cu `certutil`, `sha256sum`, `7zip`, etc.) și compara rezultatul.

---

### ValidareSemnatura-eCI-v2.0.1.zip

**Dimensiune:** 29,815,744 bytes
**Data build:** 31/01/2026 01:56:16

| Algoritm | Hash |
|---------|------|
| MD5 | `9478ed29809583a3bea9eae38993d663` |
| SHA1 | `a6e1f46207834acb8b35ed023220a2350aafd26f` |
| CRC32 | `099c216b` |
| SHA256 | `cd567fdec4d3129f3e01d8d855a70c5cb28c483272a8a5ead37d7a7796278126` |
| SHA512 | `70d2e37cdd53d94edb2123de9b79eddb545b6a19151c7f0617ebdd6a02607b2231fd3d12e5f09460a81dd5a0c1a1ec4607a2df76f41b2bd2d831b782442b2554` |
| SHA3-256 | `1a5c5d291258d34575519c07e28ebf356253b12b8074fd5e2724592962c18810470437a13f51132d1c7476c21e71169b` |

---

### ValidareSemnatura-eCI.exe v2.0.1

**Dimensiune:** 6,876,439 bytes
**Data build:** 31/01/2026 01:56:09

| Algoritm | Hash |
|---------|------|
| MD5 | `f344f832cf30e62015545f9c7f951d70` |
| SHA1 | `02af23a66c520e3641d869f9d9a1d37a4848eba1` |
| CRC32 | `52b7194d` |
| SHA256 | `b6e9038dd3d284b59b7af9d7138938b02b7e739819c3a2e8ba307e501f3f019b` |
| SHA512 | `50dcacca88eca3dd3458bf8b984b41853c7a749410eee2d443b01a62fd49e29db22c9b5953f2e952fca7c0ecac46c443ebcbc0ac4e50de31b9e2f6f669066e22` |
| SHA3-256 | `8416a3ea5c906a99fd029909393d2c4f7bd678c398bdf37c7dfcc2e37595b88bbf881db65e4722d296d40066251f0a12` |

---

### Exemplu verificare pe Windows

```powershell
certutil -hashfile ValidareSemnatura-eCI-v2.0.1.zip SHA256
certutil -hashfile ValidareSemnatura-eCI.exe SHA256
```

**Notă:**
Aceste hash-uri sunt publicate pentru transparență și verificabilitate.
Dacă nu se potrivesc, **nu rula aplicația** și descarcă din nou arhiva doar din secțiunea oficială GitHub: https://github.com/24vlh/Validare-Sematura-eCI/releases.
