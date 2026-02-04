# ValidareSemnaturaAvansata-eCI (Windows)

<img src="assets/sample.png" width="600" />

## Pe scurt

### [Descărcare](https://github.com/24vlh/ValidareSemnaturaAvansata-eCI/releases/download/v2.0.3/ValidareSemnaturaAvansata-eCI-v2.0.3-portable-folder-build.zip)

**ValidareSemnaturaAvansata-eCI** este o aplicație Windows portabilă (executabil `.exe`) care verifică dacă un PDF a fost semnat corect cu **certificatul de semnătură electronică avansată din Cartea Electronică de Identitate (CEI)**, emis de MAI.

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

1. Rulează `ValidareSemnaturaAvansata-eCI.exe`
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
ValidareSemnaturaAvansata-eCI.exe --pdf document.pdf --root root.cer --sub sub.cer
```

Pentru output JSON:

```
--json
```

Pentru a salva output-ul într-un fișier:
```
--output raport.json
```

Notă: dacă folosești `--output` fără `--json`, fișierul va conține textul uman (identic cu cel afișat în consolă).

Pentru a nu mai afișa output în consolă (doar în fișier):
```
--no-stdout
```
Notă: `--no-stdout` necesită `--output`.

---

## Descărcare și utilizare (Windows)

### 1. Descarcă aplicația
Descarcă prima versiune oficială de aici:

👉 https://github.com/24vlh/ValidareSemnaturaAvansata-eCI/releases/download/v2.0.3/ValidareSemnaturaAvansata-eCI-v2.0.3-portable-folder-build.zip

---

### 2. Dezarhivează
– click dreapta pe fișierul ZIP
– **Extract All / Extrage tot**
– alege un folder (ex: Desktop)

---

### 3. Rulează aplicația
În folderul extras:
- dublu-click pe **ValidareSemnaturaAvansata-eCI.exe**
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

### ValidareSemnaturaAvansata-eCI-v2.0.3-portable.exe (one-file build)

**Dimensiune:** 29,546,190 bytes
**Data build:** 02/02/2026 21:46:25

| Algoritm | Hash |
|---------|------|
| MD5 | `82ab0c51ab67a8adfb13ba66270ad0b8` |
| SHA1 | `996d2b710ef85105541a07b4cd210c555c4c79d0` |
| CRC32 | `80f69134` |
| SHA256 | `9b58355c7a58536a427a5f9ce8f5eeba8791b2ee3bd8e96a0eaa3ef19642e5dd` |
| SHA512 | `32a6a400e06b4e3be76b4e0d253ebba291c8445e8eaaf8e99a6a6946d5a247ee6bd44f37ad1e26a5a6f178bc0be8b1fa21db7c68ecc276fbba4f36ecc01c6d94` |
| SHA3-256 | `9ed0cc20e5e1c42d2b081e19c58d8671174c1cbdf1f08bf4aad76f48d99fac5180ac97fd6141fad70938d68f73dc6350` |

---

### ValidareSemnaturaAvansata-eCI-v2.0.3-portable-folder-build.zip

**Dimensiune:** 29,848,488 bytes
**Data build:** 02/02/2026 21:46:35

| Algoritm | Hash |
|---------|------|
| MD5 | `6f86e5a5247ab5a4f4862ac8e24c31e0` |
| SHA1 | `d62cb7f6b1adc72bf1a4450d353eece6269a0778` |
| CRC32 | `0b0c5c00` |
| SHA256 | `15f6c7d845162f2a0dd1874140d3224781e76be86de6228223e5f4a4c44c5812` |
| SHA512 | `d84b4a8f0c873c3cf2c4357bc242e1c0d57095d2e29d4ef53415b6764e44a1ab3527ec3a1ecc555c3992aa0f5d29b95d039a2f1ca2a4f3c88735d46c9460781e` |
| SHA3-256 | `e7287687c2181fff66b017aa4e53619b75c63fc2308e49181cea3b03f86b1f6ce274a86a9adb1134eba3c5f834f5bdd7` |

Notă: această arhivă ZIP conține **varianta folder build** (executabilul + dependențele din folder).

---

### ValidareSemnaturaAvansata-eCI.exe v2.0.3 (folder build)

**Dimensiune:** 6,880,741 bytes
**Data build:** 02/02/2026 21:45:34

| Algoritm | Hash |
|---------|------|
| MD5 | `45617e106eccfa402108124c2a4d7cf7` |
| SHA1 | `6da249af5d1197ea14fcfc6dc47babda172d1d61` |
| CRC32 | `4270d080` |
| SHA256 | `ccd4c706cd413c1ad441eb452ca3edf84f803740bbe930decfd6afe1eff6a760` |
| SHA512 | `034ef5187d1dd2a3a015b07b14c2a42ad8dbffa3df2f46a2ed34b957850dcb5654546545c82522191e746d668b69c7e1c2ca8757f2d8806d68f58aaa3b7960fd` |
| SHA3-256 | `93cca9005d5ea0ef8ae75b1d576a9900dc6c6772564b1a8388393746b2fd21a3b057e294a19ce5ae83bd8a2e5ceaef8f` |

---

### Exemplu verificare pe Windows

```powershell
certutil -hashfile ValidareSemnaturaAvansata-eCI-v2.0.3-portable.exe SHA256
certutil -hashfile ValidareSemnaturaAvansata-eCI-v2.0.3-portable-folder-build.zip SHA256
certutil -hashfile ValidareSemnaturaAvansata-eCI.exe SHA256
```

**Notă:**
Aceste hash-uri sunt publicate pentru transparență și verificabilitate.
Dacă nu se potrivesc, **nu rula aplicația** și descarcă din nou arhiva doar din secțiunea oficială GitHub: https://github.com/24vlh/ValidareSemnaturaAvansata-eCI/releases.

