# Sentinel Zero

A passive website security assessment tool built with React, TypeScript, and FastAPI.

## Features
- HTTP security header analysis
- TLS certificate checks
- Cookie security checks
- Findings with severity and remediation guidance
- URL validation and request safety controls

## Tech Stack
- Frontend: React, TypeScript, Vite
- Backend: Python, FastAPI, HTTPX
- Tests: pytest

## Run Backend
From the project root, run:
```powershell
cd backend
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

API docs: http://127.0.0.1:8000/docs

## Run Frontend
In a second PowerShell window:
```powershell
cd backend\frontend
npm install
npm run dev
```

Configure VITE_API_BASE_URL=http://localhost:8000 in your local .env file.

## Responsible Use
Scan only websites you own or have explicit permission to assess. This tool performs passive configuration checks and is not a substitute for a professional security audit. Review outbound connection protections before public deployment.
