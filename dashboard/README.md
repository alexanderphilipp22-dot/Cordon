# C.O.R.D.O.N. — Security Workbench (Dashboard)

React 19 + TypeScript + Vite + Tailwind CSS v4 Frontend für das
Cordon Windows Agent Gateway. Es ist eine **interaktive Security Workbench**,
die den Gateway-Zustand, die Policy-Verwaltung, den Human-in-the-Loop
Choke Point, das binäre Frame-Protokoll, das Threat Lab und die
HMAC-Audit-Kette visualisiert.

> **Status:** Die Daten werden derzeit von einer lokalen
> `simulationEngine` (Mock-Daten) geliefert. Eine echte Anbindung an den
> laufenden C#-Gateway-Prozess (z. B. via WebSocket über den Dienst) ist als
> Folgeiteration vorgesehen.

## Entwicklung

```powershell
npm install
npm run dev      # http://localhost:3000
```

## Typ-Prüfung & Build

```powershell
npm run lint     # tsc --noEmit
npm run build    # vite build (Production-Bundle in dist/)
```

## Struktur

```
dashboard/
  src/
    App.tsx                     Root-Layout + Tab-Routing
    main.tsx                    Einstiegspunkt
    index.css                   Tailwind-Import
    types/cordon.ts             Gemeinsame Typdefinitionen
    services/
      simulationEngine.ts       Mock-Zustand & Aktionen
      crypto.ts                 WebCrypto HMAC + Audit-Verifikation
      csharpSourceCode.ts       Anzeigbare C#-Roadmap-Quelltexte
    components/
      Header.tsx                Top-Navigation
      DashboardView.tsx         KPI-Übersicht + Agenten-Monitoring
      PolicyManagerView.tsx     Scope-/JSON-/Learn-Mode-Verwaltung
      HitlChokePointView.tsx    Human-in-the-Loop Warteschlange
      ProtocolInspectorView.tsx Frame-Hex-Inspektor
      ThreatLabView.tsx         Threat-Szenarien (T1–T10)
      AuditLogView.tsx          HMAC-Ketten-Verifizierung
      CodebaseView.tsx          C#-Quellcode-Exporter
      HumanApprovalModal.tsx    Freigabe-Dialog
      NewRequestModal.tsx       Verbindungs-Simulation
```
