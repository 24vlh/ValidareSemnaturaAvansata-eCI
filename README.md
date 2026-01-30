# ValidareSemnatura-eCI (Windows)

## Ce este această aplicație

**ValidareSemnatura-eCI** este o aplicație Windows portabilă (executabil `.exe`) care verifică dacă un document PDF a fost semnat corect cu **certificatul de semnătură electronică avansată din Cartea Electronică de Identitate (CEI)**, emis de MAI.

Aplicația face **doar validare tehnică criptografică**:
– integritatea semnăturii  
– validitatea lanțului de certificate  
– încrederea în Root CA + Sub CA MAI  
– (opțional) emitentul exact al certificatului semnatar  

Nu autentifică persoane, nu face login, nu trimite date și nu modifică documente.

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
2. Selectează:
   - PDF-ul semnat
   - certificatul Root CA
   - certificatul Sub CA
3. (Opțional) bifează:
   - validare strictă emitent
   - acces la rețea pentru revocare (CRL / AIA)
4. Apasă **Validează**
5. Primești rezultatul **VALID / INVALID + detalii complete**

---

## Certificatele MAI

Certificatele Root și Sub CA se pot descărca oficial de aici:

https://hub.mai.gov.ro/cei/info/descarca-cert

Aplicația este compatibilă cu fișiere:
- `.cer`
- `.crt`
- `.pem`

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
