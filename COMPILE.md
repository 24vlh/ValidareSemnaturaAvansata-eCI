# COMPILE.md

Step-by-step instructions for a **fresh Windows 11 PC** with **no Python installed**, starting from only `ValidareSemnatura-eCI.py` (no `.spec` file).

The goal: produce a Windows GUI executable using PyInstaller.

---

## 0) What you need to have (files)
Minimum:
- `ValidareSemnatura-eCI.py`

Recommended for full functionality and correct UI:
- `assets\app.ico` (app icon)
- `assets\logo.png` (UI logo)
- `assets\sample.png` (README image, not required by app)
- `assets\certs\*.cer` and `assets\certs\*.crl` (included MAI Root/Sub + CRLs)

If you only have the `.py`, the app can still run, but:
- it will show a missing icon/logo
- it will not have the bundled certificates or CRLs

---

## 1) Install Python (fresh Windows 11)
Pick **one** of these methods. Both install the **latest Python 3.x** available at the time you run them.

### Option A: Install via PowerShell (winget)
```powershell
winget install -e --id Python.Python.3
```

### Option B: Install via browser
1. Download the latest Python 3.x from python.org.
2. During install, **check** “Add Python to PATH”.
3. Finish install.

To verify:
```powershell
python --version
where.exe python
```
You should see Python 3.x.

---

## 2) Prepare a build folder
Create a new folder (example: `C:\ValidareSemnatura-eCI`) and place the files inside:

```
C:\ValidareSemnatura-eCI\
  ValidareSemnatura-eCI.py
  assets\    (optional but recommended)
```

Open PowerShell in that folder:
```powershell
cd C:\ValidareSemnatura-eCI
```

---

## 3) Create and activate a virtual environment
If PowerShell blocks activation, allow local scripts for the current user:
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

---

## 4) Install dependencies
You can install **latest** dependencies (simpler) or **pinned** dependencies (reproducible).

### Option A: Latest versions
These are the packages required by the script:
```powershell
python -m pip install --upgrade pip
python -m pip install `
  asn1crypto `
  cryptography `
  pillow `
  pyHanko `
  pyhanko-certvalidator `
  lxml `
  oscrypto `
  requests `
  tzlocal `
  PyYAML `
  pyinstaller
```

### Option B: Pinned versions (reproducible)
If you want to match the exact versions used in the last known build, pin them:
```powershell
python -m pip install `
  altgraph==0.17.5 `
  asn1crypto==1.5.1 `
  certifi==2026.1.4 `
  cffi==2.0.0 `
  charset-normalizer==3.4.4 `
  cryptography==46.0.4 `
  idna==3.11 `
  lxml==6.0.2 `
  oscrypto==1.3.0 `
  packaging==26.0 `
  pefile==2024.8.26 `
  pillow==12.1.0 `
  pycparser==3.0 `
  pyHanko==0.32.0 `
  pyhanko-certvalidator==0.29.0 `
  pyinstaller==6.18.0 `
  pyinstaller-hooks-contrib==2026.0 `
  pywin32-ctypes==0.2.3 `
  PyYAML==6.0.3 `
  requests==2.32.5 `
  setuptools==80.10.2 `
  tzdata==2025.3 `
  tzlocal==5.3.1 `
  uritools==6.0.1 `
  urllib3==2.6.3
```

---

## 5) Build the executable (no .spec file)
Use PyInstaller directly from the `.py` file.

### Recommended build (GUI, with assets, with icon)
```powershell
pyinstaller `
  --noconsole `
  --name "ValidareSemnatura-eCI" `
  --icon "assets\app.ico" `
  --add-data "assets;assets" `
  ValidareSemnatura-eCI.py
```

Notes:
- `--noconsole` makes it a Windows GUI app.
- `--add-data "assets;assets"` bundles the assets folder.
- If you do not have `assets\app.ico`, remove the `--icon` line.
- If you do not have the `assets` folder, remove the `--add-data` line.

Optional flags you can add:
- `--clean` wipes PyInstaller's build cache before packaging (avoids stale artifacts).
- `--windowed` is the same as `--noconsole` on Windows (GUI-only, no console window).

### Minimal build (no assets)
```powershell
pyinstaller --noconsole --name "ValidareSemnatura-eCI" ValidareSemnatura-eCI.py
```

### One-file build (optional)
```powershell
pyinstaller `
  --onefile `
  --noconsole `
  --name "ValidareSemnatura-eCI" `
  --icon "assets\app.ico" `
  --add-data "assets;assets" `
  ValidareSemnatura-eCI.py
```

Note: one-file builds unpack to a temp folder at runtime. If you do not have `assets`, remove `--icon` and `--add-data`.

---

## 6) Where the EXE is produced
PyInstaller outputs to:
```
dist\ValidareSemnatura-eCI\ValidareSemnatura-eCI.exe
```

If you included assets, the folder will also contain:
```
dist\ValidareSemnatura-eCI\assets\
```

Keep the `assets` folder **next to** the EXE if you used `--add-data`.

---

## 7) Run the application
```powershell
.\dist\ValidareSemnatura-eCI\ValidareSemnatura-eCI.exe
```

---

## 8) Clean rebuild (optional)
```powershell
Remove-Item -Recurse -Force .\build, .\dist
```

---

## Behavior notes
- GUI by default. CLI is available with `--cli` (or any CLI flags like `--pdf`).
- The app uses `assets/` for icon/logo and for bundled certificates/CRLs.
- Network access for CRL/AIA/OCSP validation is optional and controlled by the user in the UI.
