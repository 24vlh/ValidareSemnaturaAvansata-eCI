# COMPILE.md

Build and release notes for `ValidareSemnaturaAvansata-eCI`.

This project now has two canonical build entrypoints:

- PowerShell: `scripts\build-release.ps1`
- WSL wrapper: `scripts/build-release.sh`
- Pinned build requirements: `requirements-build.txt`

The PowerShell script is the source of truth. The WSL script simply invokes it through `powershell.exe`, so there is only one build implementation to maintain.

---

## Paths

Project-local paths:

- Windows repo path: `W:\public_html\24vlh\ValidareSemnaturaAvansata-eCI`
- WSL repo path: `/mnt/w/public_html/24vlh/ValidareSemnaturaAvansata-eCI`

Clean Windows machine example path:

- `C:\ValidareSemnaturaAvansata-eCI`

If you are building from a fresh Windows PC outside the 24VLH workspace, use the `C:\...` example path. If you are building from the shared workspace, use the `W:\...` / `/mnt/w/...` paths above.

---

## Output conventions

The build scripts follow the current `dist` naming already used by this project:

- Folder build directory: `dist\ValidareSemnaturaAvansata-eCI\`
- Zipped folder build: `dist\ValidareSemnaturaAvansata-eCI-v<version>-portable-folder-build.zip`
- Portable one-file EXE: `dist\ValidareSemnaturaAvansata-eCI-v<version>-portable.exe`

Example for version `2.0.4`:

- `dist\ValidareSemnaturaAvansata-eCI\`
- `dist\ValidareSemnaturaAvansata-eCI-v2.0.4-portable-folder-build.zip`
- `dist\ValidareSemnaturaAvansata-eCI-v2.0.4-portable.exe`

The non-versioned folder build is kept as the live PyInstaller output. The portable `.exe` is renamed to the versioned release artifact name.

---

## Build targets

Both scripts accept the same logical targets:

- `all`: build folder output, zip the folder build, and build the portable EXE
- `folder`: build folder output and zip it
- `portable`: build only the portable EXE

The release version comes from `APP_VERSION` in `ValidareSemnaturaAvansata-eCI.py`.
You may also pass a version parameter explicitly as a consistency check.

By default, the script also:

- creates `.\.venv\` automatically if it is missing
- installs or refreshes the pinned Windows build dependencies from `requirements-build.txt`
- uses that managed Windows virtual environment for the build

---

## Version discipline

`APP_VERSION` in `ValidareSemnaturaAvansata-eCI.py` is the single source of truth.

Recommended rule:

1. Update `APP_VERSION` in `ValidareSemnaturaAvansata-eCI.py`
2. Run the build script without a version argument

Optional strict check:

- You may also pass `-Version` / `--version`.
- If provided, it must match `APP_VERSION`.
- If it does not match, the build stops immediately.

The script also regenerates `assets\build_info.json` on each run with:

- `build_date`
- `version`
- `target`

The app currently reads `build_date`; the extra metadata is retained for release tracking.

Important runtime boundary:

- WSL is the default command entrypoint.
- The actual packaging environment is still a Windows Python virtual environment in `.\.venv\`.
- Linux packages installed into WSL Python are not reused by Windows PyInstaller.
- The scripts handle that by provisioning and updating the Windows `.venv` automatically.

---

## Files required in the project

Minimum:

- `ValidareSemnaturaAvansata-eCI.py`

Recommended for the real release build:

- `assets\app.ico`
- `assets\logo.png`
- `assets\sample.png`
- `assets\certs\*.cer`
- `assets\certs\*.crl`

The scripts automatically add the whole `assets` folder to the PyInstaller bundle when it exists.

---

## 1) Install Python on Windows

Use a native Windows Python installation or the Windows `py` launcher. PyInstaller must run on Windows because this project produces Windows executables.

Option A, via PowerShell:

```powershell
winget install -e --id Python.Python.3
```

Option B, via python.org:

1. Download the latest Python 3.x installer.
2. Check `Add Python to PATH`.
3. Complete the install.

Verify:

```powershell
python --version
where.exe python
py --version
```

---

## 2) Open the project

Project-local workspace:

```powershell
cd W:\public_html\24vlh\ValidareSemnaturaAvansata-eCI
```

Fresh Windows machine example:

```powershell
cd C:\ValidareSemnaturaAvansata-eCI
```

WSL:

```sh
cd /mnt/w/public_html/24vlh/ValidareSemnaturaAvansata-eCI
```

---

## 3) Automatic environment bootstrap

You do not need to create `.\.venv\` manually for the normal release flow.

When you run the build scripts without `-PythonExe`:

1. the script locates Windows Python or the Windows `py` launcher
2. it creates `.\.venv\` if missing
3. it upgrades `pip`
4. it installs the pinned Windows build dependencies from `requirements-build.txt`
5. it runs PyInstaller from that Windows `.venv`

This is the recommended path, especially when launching from WSL.

---

## 4) Manual environment setup (optional)

Use this only if you want to inspect or maintain the Windows build environment yourself.

If PowerShell blocks activation:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

Create and activate:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install the pinned build requirements:

```powershell
python -m pip install --upgrade pip
python -m pip install -r .\requirements-build.txt
```

---

## 5) Run the build scripts

### Preferred on Windows PowerShell

Build everything:

```powershell
.\scripts\build-release.ps1 -Target all
```

Build only folder output plus ZIP:

```powershell
.\scripts\build-release.ps1 -Target folder
```

Build only the portable EXE:

```powershell
.\scripts\build-release.ps1 -Target portable
```

### Preferred from WSL

Build everything:

```sh
./scripts/build-release.sh --target all
```

Build only folder output plus ZIP:

```sh
./scripts/build-release.sh --target folder
```

Build only the portable EXE:

```sh
./scripts/build-release.sh --target portable
```

Optional explicit version check:

```powershell
.\scripts\build-release.ps1 -Target all -Version 2.0.4
```

```sh
./scripts/build-release.sh --target all --version 2.0.4
```

Important:

- The WSL script still builds with Windows PowerShell.
- The WSL script provisions `.\.venv\` automatically when it is missing.
- The WSL script is the correct project-local entrypoint when following the WSL-first command policy from `AGENTS.md`.
- If you are launching from a Windows terminal and want to follow the exact repo policy, use:

```powershell
wsl sh -lc "cd /mnt/w/public_html/24vlh/ValidareSemnaturaAvansata-eCI && ./scripts/build-release.sh --target all"
```

---

## 6) What the scripts do

The PowerShell script:

1. Resolves the project root from the script location
2. Reads `APP_VERSION` from the Python source
3. Optionally validates a provided version parameter against `APP_VERSION`
4. Creates `.\.venv\` automatically if it is missing
5. Installs or refreshes the pinned Windows build dependencies from `requirements-build.txt`
6. Regenerates `assets\build_info.json`
7. Runs PyInstaller with the project assets bundled
8. Produces the requested artifact set
9. Creates the versioned ZIP and/or versioned portable EXE names

PyInstaller is invoked with:

- `--clean`
- `--noconfirm`
- `--noconsole`
- `--name ValidareSemnaturaAvansata-eCI`
- `--add-data "assets;assets"` when `assets\` exists
- `--icon assets\app.ico` when `assets\app.ico` exists

The script uses separate PyInstaller work/spec directories for folder and portable builds to avoid collisions.

---

## 7) Output locations

After `-Target all` with `APP_VERSION = "2.0.4"`, expect:

```text
dist\ValidareSemnaturaAvansata-eCI\
dist\ValidareSemnaturaAvansata-eCI-v2.0.4-portable-folder-build.zip
dist\ValidareSemnaturaAvansata-eCI-v2.0.4-portable.exe
```

Folder build executable:

```powershell
.\dist\ValidareSemnaturaAvansata-eCI\ValidareSemnaturaAvansata-eCI.exe
```

Portable executable:

```powershell
.\dist\ValidareSemnaturaAvansata-eCI-v2.0.4-portable.exe
```

---

## 8) Clean rebuild

If you want to wipe previous build outputs:

```powershell
Remove-Item -Recurse -Force .\build, .\dist
```

or from WSL:

```sh
rm -rf build dist
```

---

## 9) Behavioral notes

- The app is GUI-first; CLI support is still available through the executable.
- The build scripts assume a Windows build host, even when launched from WSL.
- The folder ZIP is intended for release packaging and should preserve the folder-build layout.
- The app uses the bundled `assets/` directory for UI images and included MAI certificates/CRLs.
