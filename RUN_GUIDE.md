# TRACEINTEL: Run & Important Commands (Windows / PowerShell / VS Code)

Project folder: `C:\Users\LENOVO\Downloads\traceintel-repo`  (this is the real git repo; ignore `traceintel-ps05-main`)

## 0. VS Code ko sahi folder mein kholo (sabse zaroori)
1. VS Code: **File → Open Folder → `traceintel-repo`**.
2. Terminal: **Ctrl + `** (backtick). Prompt mein `...\traceintel-repo>` dikhna chahiye.
3. Ek baar ka setup, taaki venv har naye terminal mein khud activate ho:
   - `Ctrl+Shift+P` → **Python: Select Interpreter** → `.venv`
   - PowerShell script permission (ek baar): `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`

## 1. Sabse aasaan: server start (venv activate kiye bina)
```powershell
.\.venv\Scripts\python.exe -m uvicorn traceintel.api:app --reload
```
ya `start.ps1` se (pehli baar venv aur packages khud install karta hai):
```powershell
powershell -ExecutionPolicy Bypass -File .\start.ps1
```
Phir browser mein: **http://127.0.0.1:8000/ui/**  (API docs: http://127.0.0.1:8000/docs)
Server band karna: terminal mein **Ctrl + C**.

## 2. Pehli baar setup (ek hi baar)
```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```
(`python` na chale toh `py -m venv .venv`)

## 3. Roz ke commands
| Kaam | Command |
|---|---|
| Venv activate | `.\.venv\Scripts\Activate.ps1` (aage `(.venv)` dikhega) |
| Saare tests | `.\.venv\Scripts\python.exe -W error::DeprecationWarning -m unittest discover -s tests` (88 tests OK) |
| Demo report (PDF+Excel+drafts) | `.\.venv\Scripts\python.exe -m traceintel.report_cli --out reports` |
| Financial engine CLI | `.\.venv\Scripts\python.exe -m traceintel.cli data\synthetic\statements_all.csv --utr 699999999001` |
| Infra demo (offline, synthetic) | `.\.venv\Scripts\python.exe -m traceintel.infra.cli --demo` |
| Infra live lookup | `.\.venv\Scripts\python.exe -m traceintel.infra.cli --domain github.com` |
| Infra cache only | `.\.venv\Scripts\python.exe -m traceintel.infra.cli --domain github.com --offline` |
| Synthetic data dobara banao | `.\.venv\Scripts\python.exe -m traceintel.synthetic` |
| Fresh start (saare cases hata do) | server band karo, phir `Remove-Item traceintel.db -ErrorAction SilentlyContinue` |
| Infra cache saaf | `Remove-Item infra_cache.db -ErrorAction SilentlyContinue` |

## 4. Demo flow (judges ko dikhane ke liye)
1. Server start → http://127.0.0.1:8000/ui/
2. **Load synthetic demo case** (ya `POST /demo/seed` in /docs)
3. Tabs: Overview → Mule Account Intelligence → Money Trail (UTR `699999999001`, Trace) → Digital Infrastructure → Evidence & Audit → Reports (PDF/Excel/drafts)

## 5. Git (hamesha `traceintel-repo` ke andar; `&&` PowerShell 5 mein nahi chalta, alag lines mein chalao)
```powershell
git status
git add .
git commit -m "your message"
git push
```
- Tests ke baad data files "modified" dikhein toh: `git restore data/`
- Commit se pehle `git status --short` dekho: `.venv`, `*.db`, `reports/`, `uploads/`, `*.zip` nahi dikhne chahiye.
- Latest GitHub code lana: `git pull`

## 6. Zip update lagana (jab mai koi zip du)
```powershell
Expand-Archive -Path $env:USERPROFILE\Downloads\<zipname>.zip -DestinationPath . -Force
```
Frontend (`frontend/index.html`) ke liye server restart nahi chahiye, browser mein **Ctrl+F5**. Python files ke liye `--reload` khud restart karta hai.

## 7. Common errors
| Error | Matlab / Fix |
|---|---|
| `uvicorn is not recognized` | Venv active nahi. Section 1 ki command use karo (`.\.venv\Scripts\python.exe -m uvicorn ...`) |
| `Activate.ps1 ... not recognized` | Galat folder mein ho. `cd C:\Users\LENOVO\Downloads\traceintel-repo` |
| `running scripts is disabled` | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` |
| `fatal: not a git repository` | `traceintel-ps05-main` mein ho (zip folder). `traceintel-repo` mein jao |
| `&&` ... not a valid statement separator | PowerShell 5: alag lines mein chalao ya `;` use karo |
| UI mein "API unreachable" | Server nahi chal raha, ya UI `file://` se khola. `http://127.0.0.1:8000/ui/` kholo |
| `Address already in use` (port 8000) | Purana server chal raha hai: usko Ctrl+C karo, ya `--port 8001` |
| `curl` ajeeb output | PowerShell mein `curl.exe` likho |
| Infra `crtsh ... Network is unreachable` | crt.sh optional source hai; baaki lookups chalte hain |

## 8. Important rules (demo/evaluators ke liye)
- Sirf **synthetic data** use karo; asli personal data kabhi nahi.
- Indicators = review-priority, proof nahi. Money trail = possible paths, proven fund movement nahi.
- Draft requests sirf drafts hain; officer legal process se issue karta hai.
- Repo public hai: `.venv`, `*.db`, `reports/`, `uploads/` commit mat karo.
