# ValidareSemnatura-eCI (Windows)

<img src="assets/sample.png" width="600" />

## Ce este această aplicație

**ValidareSemnatura-eCI** este o aplicație Windows portabilă (executabil `.exe`) care verifică dacă un document PDF a fost semnat corect cu **certificatul de semnătură electronică avansată din Cartea Electronică de Identitate (CEI)**, emis de MAI.

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

## De ce există

Portalurile oficiale arată **că există o semnătură**, dar nu oferă:
- verificare locală, offline
- control asupra lanțului de încredere
- validare strictă a emitentului
- dovadă tehnică reproductibilă

Această aplicație permite **verificare independentă**, locală, cu un singur click, fără cont, fără internet (opțional).

Este utilă în special când:
- primești documente semnate cu eCI
- vrei să verifici că PDF-ul NU a fost modificat
- vrei să verifici că semnătura este chiar emisă de MAI
- ai nevoie de o confirmare tehnică înainte de a folosi documentul

---

## Cine o poate folosi

Aplicația este destinată:
- cetățenilor care primesc documente semnate cu eCI
- avocaților / juriștilor / experților
- instituțiilor sau firmelor care verifică documente
- dezvoltatorilor și persoanelor tehnice
- oricărei persoane care vrea să verifice un PDF semnat

Nu este nevoie de:
- token
- PIN
- card eID
- driver special
- cont
- drepturi de admin

---

## Ce face concret (tehnic)

Aplicația verifică:

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

6. **Regulă de siguranță**
   – PDF-ul trebuie să conțină exact **o singură semnătură**

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
4. (Opțional) bifează:
   - validare strictă emitent
   - acces la rețea pentru revocare (CRL / AIA)
   - mod strict eCI (pin MAI + revocare obligatorie)
   - CRL local (assets/certs/*.crl)
   - mod revocare: soft-fail / hard-fail / require
   - verificare timestamp/LTV (dacă există)
5. Apasă **Validează**
6. Primești rezultatul **VALID / INVALID + detalii complete**
   - tabul **Certificat** afișează Subject/Issuer/SHA256 + EKU/Policy OIDs
   - poți copia detaliile certificatului sau exporta certificatul semnatarului

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

👉 https://github.com/24vlh/Validare-Sematura-eCI/releases/download/v1.0.0/ValidareSemnatura-eCI.zip

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
- strict issuer + hard mode

Opțional, poți configura filtrarea EKU/Policy OID direct în cod (`ECI_REQUIRED_EKU_OIDS`, `ECI_REQUIRED_POLICY_OIDS`).

### Verificare timestamp/LTV (opțional)
Când este activată, aplicația cere un **timestamp valid și de încredere** în semnătură (sau content timestamp).
Dacă nu există timestamp sau acesta nu este valid/trusted, validarea eșuează.

Limitare: această verificare nu înlocuiește validarea completă LTV la momentul semnării și nu poate garanta statutul legal
în timp; este un control tehnic asupra token‑ului de timestamp.

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

### ValidareSemnatura-eCI.zip

**Dimensiune:** 29,572,547 bytes  
**Data build:** 30/01/2026 13:36:29  

| Algoritm | Hash |
|---------|------|
| MD5 | `eacff72f83b5b5636728554339d274d3` |
| SHA1 | `7b619c3cc6b788e751af4355246e39b85314fd69` |
| CRC32 | `ff05cfe2` |
| SHA256 | `3afac61c640af2443be99fce9892675ba8d98dbe2c071314a6951dfbbfafed1a` |
| SHA512 | `742696d57f70a2f06c9889396ef7d6f171df55b6d021531837057451564383885b4d6664d2cbed0500ef8b5bec99505910f31bfa510e69130305917ca0e2f626` |
| SHA3-256 | `bd99b5235098d886c8e8b169157769d14c2faabcfb1a643488223c80991f7af5` |

---

### ValidareSemnatura-eCI.exe v1.0.0

**Dimensiune:** 6,811,194 bytes  
**Data build:** 30/01/2026 13:35:56  

| Algoritm | Hash |
|---------|------|
| MD5 | `d9c55d8412314fdbe29a69260ea26749` |
| SHA1 | `68e15836351beeafa326fe075ffd83a73e20a1d0` |
| CRC32 | `d3bcd084` |
| SHA256 | `f5e4cd2ca8ca1dce0528ff439246e22264944b384269b588c1683f0cd5f080d9` |
| SHA512 | `7c10041f342661f820d0ccaab3069bb21055cc53613a0ea023922c4d2fcb226a50cc06516c18dab6650dd115a1d932d9324606501a3a2614ec708e16ea0becb4` |
| SHA3-256 | `35b9c63e0df0d5610496cbb2ab025e7302eb98898b5515827850129814ecca53` |

---

### Exemplu verificare pe Windows

```powershell
certutil -hashfile ValidareSemnatura-eCI.zip SHA256
certutil -hashfile ValidareSemnatura-eCI.exe SHA256
```

**Notă:**
Aceste hash-uri sunt publicate pentru transparență și verificabilitate.
Dacă nu se potrivesc, **nu rula aplicația** și descarcă din nou arhiva doar din secțiunea oficială GitHub: https://github.com/24vlh/Validare-Sematura-eCI/releases.
