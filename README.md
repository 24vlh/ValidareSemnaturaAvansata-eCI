# Validare Semnătură Avansată cu eCI (Windows)

<img src="assets/sample.png" width="600" />

## Pe scurt

### [Descărcare](https://github.com/24vlh/ValidareSemnaturaAvansata-eCI/releases/download/v2.0.5/ValidareSemnaturaAvansata-eCI-v2.0.5-portable-folder-build.zip)

**Validare Semnătură Avansată cu eCI** (`ValidareSemnaturaAvansata-eCI`) este o aplicație Windows portabilă (executabil `.exe`) care verifică dacă un PDF a fost semnat corect cu **certificatul de semnătură electronică avansată din Cartea Electronică de Identitate (CEI)**, emis de MAI.

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
   - tabul **Certificat** afișează Subject/Issuer/SHA256 + data semnării raportată de semnatar + EKU/Policy OIDs
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
   – extrage DN-ul, amprenta SHA256 și, dacă este prezentă, data semnării raportată de semnatar

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
Descarcă versiunea oficială curentă de aici:

👉 https://github.com/24vlh/ValidareSemnaturaAvansata-eCI/releases/download/v2.0.5/ValidareSemnaturaAvansata-eCI-v2.0.5-portable-folder-build.zip

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

### ValidareSemnaturaAvansata-eCI-v2.0.5-portable.exe (one-file build)

**Dimensiune:** 29,546,921 bytes
**Data build:** 17/03/2026 19:16:08

| Algoritm | Hash |
|---------|------|
| MD5 | `458910e8fd27f22a0d0d403147eb189e` |
| SHA1 | `5fdf396ea08c104a272ecdbea526b0eb56c1b025` |
| CRC32 | `ddaac01f` |
| SHA256 | `f791c515c2081a2b58b76aa7c646703a46d40f69d332dc86894b6b4ecb9d7d64` |
| SHA512 | `4d0944b23403f7833f767cef05be4157ae28e6a38d71ed5578f8965e6c0225365e8039370fc5146da4a7bc495d0fc0dd6c75080e77b6c4113931e88eadb81e1c` |
| SHA384 | `b455d560908a4fe0fbe5dd646222296adeccd78d56914cbd84883485d33f116c8f6df82c4a64346178101671be356dad` |

---

### ValidareSemnaturaAvansata-eCI-v2.0.5-portable-folder-build.zip

**Dimensiune:** 29,721,986 bytes
**Data build:** 17/03/2026 19:14:57

| Algoritm | Hash |
|---------|------|
| MD5 | `ece279f7d6ecdedfca3f81bcfbb03151` |
| SHA1 | `d0155be5020a7f139d18303886ab9d51aeac368d` |
| CRC32 | `c3618c02` |
| SHA256 | `83d672db1c59ffa2f548add8dedeab9655546a17cca4bdd998ddea1e1b471eb8` |
| SHA512 | `da9d4625c3824a4c9cf7f27bf77747eb416466d512bd79e3224542ae09dd17f90eae91e76868dc10a27ec1ec7ec0bb2172b54dd037eb326b4fc7bf5aa2533507` |
| SHA384 | `291c61894928ae1da5ea470deb81988b5ba7e22bb2cccc3d32d8e561502722774e4adbc62dfc400489cc7f6fb3b3a5f9` |

Notă: această arhivă ZIP conține **varianta folder build** (executabilul + dependențele din folder).

---

### ValidareSemnaturaAvansata-eCI.exe v2.0.5 (folder build)

**Dimensiune:** 6,881,415 bytes
**Data build:** 17/03/2026 19:14:55

| Algoritm | Hash |
|---------|------|
| MD5 | `0cff6ade552c355cb3938d8b8136183f` |
| SHA1 | `c17c4ac278954d5bc5038f515537e879126076b3` |
| CRC32 | `2178bb75` |
| SHA256 | `6ff37d312c8adb0663cc1146e83338ce8de55ed2512b9f1ae4c17ac40888b82e` |
| SHA512 | `864e22b5d6cad824cad114a1c99f40db8df4f8ff3094b0ca12231c0a273e852babdb01a8bcd432a3bb54e58483a38bddcc11bd8741f9db616bfaa724aa66542c` |
| SHA384 | `0ec47a3e8f3e79269aededfc07e8422aa69bd6e12c8e263b538544646f29e4b46b764fd915c2b75d441de03e3d21812d` |

---

### Exemplu verificare pe Windows

```powershell
certutil -hashfile ValidareSemnaturaAvansata-eCI-v2.0.5-portable.exe SHA256
certutil -hashfile ValidareSemnaturaAvansata-eCI-v2.0.5-portable-folder-build.zip SHA256
certutil -hashfile ValidareSemnaturaAvansata-eCI.exe SHA256
```

**Notă:**
Aceste hash-uri sunt publicate pentru transparență și verificabilitate.
Dacă nu se potrivesc, **nu rula aplicația** și descarcă din nou arhiva doar din secțiunea oficială GitHub: https://github.com/24vlh/ValidareSemnaturaAvansata-eCI/releases.
