<div align="center">

# C.O.R.D.O.N.
### Capability-Operated Restriction & Defense Operations Network

**A Kernel-Enforced Zero-Trust Isolation & Mediation Gateway for Autonomous AI Agents on Windows.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows%2010%2F11-informational)](https://www.microsoft.com)
[![Status: Developer Preview](https://img.shields.io/badge/Status-Developer%20Preview%20(Iteration%201)-orange)](docs/ARCHITECTURE.md)

</div>

---

## 📌 Status: Developer Preview (Iteration 1)
Cordon befindet sich in der **Iteration 1**. Der Fokus dieser Version liegt auf einem kompromisslosen, betriebssystembasierten Sicherheitsfundament (AppContainer-Sandbox, Named-Pipe-Choke-Point, Kernel-PID-Verbindung und HMAC-Audit-Kette). 

Dieses Repository lädt Entwickler und Sicherheitsforscher ein, die Architektur zu prüfen, zu testen und aktiv am Projekt mitzuwirken.

---

## 🚨 Das Problem
Autonome KI-Agenten in Entwickler-Workflows (gesteuert durch LLMs, Skripte oder Tools) sind anfällig für **Prompt Injection** und unerwünschten Tool-Missbrauch. 

Herkömmliche User-Mode-Proxys oder In-Process-Guards sind unzureichend: Ein kompromittierter Prozess mit Standard-Nutzerrechten kann direkte Syscalls absetzen (`socket()`, `connect()`), Hooks umgehen oder unüberwachte Kindprozese starten. **User-Mode-Sicherheit kann einen feindseligen Prozess nicht autoritativ stoppen.**

## 🛡️ Die Lösung: C.O.R.D.O.N.
Cordon verlagert die Sicherheitsdurchsetzung vom gefährdeten User-Space in den **Windows-Kernel**:
* **AppContainer-Isolation:** Agenten laufen in strikten AppContainern mit `CapabilityCount = 0`. Jeder direkte Versuch, rohe Sockets zu öffnen, wird im Kernel mit `E_ACCESSDENIED` abgewiesen.
* **Named Pipe Choke Point:** Der einzige Egress- und Interop-Kanal ist ein sicherer Windows Named Pipe (`\\.\pipe\CordonGateway`), dessen DACL exklusiv an die AppContainer-SID des Agenten gebunden ist.
* **Kernel-Level Identity Verification:** Client-PIDs werden direkt aus dem Kernel (`GetNamedPipeClientProcessId`) ausgelesen und mit dem Prozess-Erstellungszeitstempel gekoppelt, um PID-Reuse und Header-Spoofing zu verhindern.
* **Job Object Lineage:** Agenten und alle Kindprozesse (`python.exe`, `node.exe`) laufen in Job Objects (`KILL_ON_JOB_CLOSE`). Breakaway-Versuche werden unterbunden.
* **Manipulationssicherer Audit-Trail:** Alle Gateway-Interaktionen und blockierten Aktionen werden in einen Append-Only JSONL-Stream geschrieben, geschützt durch eine **HMAC-SHA256-Kette** und Windows DPAPI.

---

## 🛑 Ehrliche Grenzen (Out-of-Scope)
Cordon bietet harte Netzwerksicherheit, schützt jedoch **nicht** gegen:
1. **Lokales Dateisystem:** Sofern dem Agenten explizit Schreibrechte auf dem Dateisystem gewährt wurden, greift Cordon dort nicht ein.
2. **Datenabfluss über erlaubte Kanäle:** Ist ein externer API-Kanal (z. B. GitHub) explizit freigegeben, kann ein Agent über diesen legalen Kanal Daten übertragen.
3. **Administrator-Rechte & Kernel-Exploits:** Prozesse mit vollen Administratorrechten oder Angriffe über Kernel-Treiber (BYOVD) liegen außerhalb des Schutzmodells.

---

## 🚀 Schnellstart

### Voraussetzungen
* Windows 10 / 11 (x64)
* .NET 8.0 SDK

### Ausführung
```cmd
# Repository klonen
git clone [https://github.com/DEIN-BENUTZERNAME/Cordon.git](https://github.com/DEIN-BENUTZERNAME/Cordon.git)
cd Cordon

# Gateway bauen und starten
dotnet run --project src/Cordon.Gateway