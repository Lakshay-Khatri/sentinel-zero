# Sentinel Zero — Frontend

The React + TypeScript + Vite dashboard for Sentinel Zero. See the
[main README](../../README.md) for the full project description and setup.

```powershell
npm install
Copy-Item .env.example .env   # sets VITE_API_BASE_URL (default http://localhost:8000)
npm run dev                   # http://localhost:5173
npm run build                 # type-check and build into dist/
npm run lint
```

| Folder | Contents |
|---|---|
| `src/pages/` | `DashboardPage.tsx`: the single page, its state and the scan form |
| `src/components/` | Navbar, Footer, Layout |
| `src/components/report/` | Summary, severity badge, finding card, findings section, TLS details |
| `src/services/api.ts` | Calls to `/health` and `/scan`, and readable error messages |
| `src/utils/` | URL checks before scanning; grouping, sorting and counting findings |
| `src/types/` | TypeScript types matching the backend's JSON |

The dashboard only displays what the backend returns; it never invents scores
or certificate data.
