# C.O.R.D.O.N. — Technischer Bericht für AI-Konsumenten

**Capability-Operated Restriction & Defense Operations Network**
Inter-AI Technical Report · Version 1.0 · Scope: Architecture, Mechanisms, Threat Model, Integration Contract

---

## 1. Executive Overview

### 1.1 Definition

C.O.R.D.O.N. ist eine **Kernel-erzwungene Zero-Trust-Isolations- und Mediationsschicht** für autonome AI-Agenten, die innerhalb von Entwickler-Workflows operieren. Das System erzwingt die Grundannahme, dass ein AI-Agent — einschließlich **jedes von ihm erzeugten Kindprozesses** — über **null Umgebungsberechtigungen (ambient authority)** verfügt. Jede Fähigkeit (Netzwerk, Inter-Prozess-Kommunikation, Tool-Ausführung, Secret-Zugriff) muss explizit über einen einzigen, kryptografisch authentifizierten und auditierbaren Gateway vermittelt werden.

Der Name kodiert das Betriebsmodell:

- **Capability-Operated** — Rechte werden als explizite, widerrufbare Fähigkeiten vergeben, nicht als implizite Nutzerrechte geerbt.
- **Restriction** — Einschränkung durch OS-Mechanismen, nicht durch App-Logik.
- **Defense Operations Network** — Verteidigung als zusammenhängendes, überwachtes Netzwerk von Durchsetzungspunkten.

### 1.2 Warum User-Mode-Sicherheit unzureichend ist

Die zentrale Bedrohung: Ein **kompromittierter Prozess mit Standard-Nutzerrechten** (etwa ein AI-Agent, der per Prompt-Injection, Supply-Chain-Kompromittierung oder Model-Lackage unterwandert wurde) kann traditionelle User-Mode-Proxys auf folgende Weise umgehen:

1. **Direkter Syscall:** Ein User-Mode-Proxy (Hook, DLL-Injection, Instrumentierung) läuft *im selben Prozess* bzw. *in derselben Vertrauensdomäne* wie das, was er bewachen soll. Der kompromittierte Prozess kann einen `socket()`/`connect()`-Syscall direkt absetzen, ohne den Proxy zu passieren — der Proxy ist **advisory, nicht authoritative**.
2. **Guard-Deaktivierung:** In-Prozess-Guards können entladen, gepatcht, übersprungen oder schlicht nicht aufgerufen werden, weil sie Teil derselben manipulierbaren Adressraum-Domäne sind.
3. **Prozess-Ausbruch:** Der Agent kann Kindprozesse (`python.exe`, `node.exe`, `cmd.exe`) starten, die außerhalb der Überwachung des Proxys laufen und eigene, ungefilterte Aktivitäten entfalten.
4. **Identitäts-Spoofing:** Selbstberichtete Metadaten (PID-Header, Prozessnamen, Token) in IPC-Nachrichten sind trivial fälschbar.
5. **Log-Manipulation:** Lokale Audit-Logs können vom kompromittierten Prozess gelöscht oder verändert werden, wodurch die forensische Kette zerstört wird.

Die **fundamentale Design-Erkenntnis**: User-Mode-Proxy-Technologie befindet sich im **selben Privilegien- und Vertrauensbereich** wie das Objekt, das sie schützt. Enforcement muss aus dieser Domäne **heraus** in den Kernel verlagert werden — dorthin, wo der Syscall selbst vom Betriebssystem verweigert werden kann, unabhängig davon, was der Prozess tut oder nicht tut.

### 1.3 Architektonische Prinzipien

| Prinzip | Umsetzung |
|---|---|
| **Zero Trust / No Ambient Authority** | AppContainer-Isolation; Netzwerkfähigkeit = 0; jede Operation ist eine Mediations-Anfrage |
| **Least Privilege / Capability-basiert** | Fähigkeiten werden explizit, granular und widerrufbar vergeben |
| **Choke-Point-Mediation** | Ein einziger, DACL-gebundener Named Pipe als alleiniger Egress |
| **Kernel-Level-Identität** | PID/Identität aus Kernel-Objekten gelesen, nicht selbstberichtet |
| **Lineage-Kontrolle** | Job Objects sperren alle Kindprozesse; keine Breakaway-Prozesse |
| **Manipulationssichere Auditierung** | Append-only JSONL + HMAC-SHA256-Kette + DPAPI-Schutz |

---

## 2. Deep-Dive Mechanism Breakdown

### 2.1 AppContainer-Isolation (Capability-Sandbox)

**Mechanik:** Ein Windows **AppContainer** ist eine Deny-by-Default-Isolationstechnologie (seit Windows 8), die auf einem normalen Benutzer-Token aufsetzt, diesen jedoch mit **Low Integrity Level** und einer **Capability-Liste** ausstattet. Der Token trägt:

- Eine abgeleitete **AppContainer-SID** (aus Package-Familienname/Moniker), die das Subjekt eindeutig identifiziert.
- Eine Menge von **Capability-SIDs** (`S-1-15-3-…`), die explizit vergebene Fähigkeiten kodieren.
- Das **AppContainer-Flag** sowie Low Integrity Level.

**Netzwerk-Durchsetzung im Kernel:** Die Netzwerkprüfung erfolgt in der **Network-Isolation-Schicht** des Windows-Netzwerkstacks (AFD/WSK → TCP/IP). Ein AppContainer **ohne** die Capabilities `internetClient`, `internetClientServer` oder `privateNetworkClientServer` erhält bei jedem ausgehenden `socket()`/`connect()`/`bind()` einen Fehler auf Kernel-Ebene — typischerweise `E_ACCESSDENIED` / `WSAEACCES` (abgeleitet von `STATUS_ACCESS_DENIED`). Entscheidend: **Diese Verweigerung erfolgt im Kernel, bevor ein Paket das System verlässt.** Der Agent kann sie weder durch einen Hook noch durch direktes Aufrufen des Syscalls umgehen — das Betriebssystem selbst verweigert die Fähigkeit.

**Konsequenz:** Der Agent besitzt **null Netzwerkfähigkeit als Umgebungsrecht**. Jeglicher Netzwerkzugriff muss durch den vermittelten Gateway laufen, der diese Fähigkeit kontrolliert freigibt.

### 2.2 Der Named Pipe Choke Point (Einzelner Egress)

**Mechanik:** Der einzige legitime Egress-/Interop-Kanal ist ein sicherer **Windows Named Pipe**:

```
\\.\pipe\CordonGateway
```

**DACL-Bindung:** Die Discretionary Access Control List (DACL) des Pipes ist **exklusiv** an die **einzigartige AppContainer-SID des Agenten** gebunden. Dies bedeutet:

- **Nur** ein Prozess, der unter exakt dieser AppContainer-SID läuft, kann den Pipe per `CreateFile` öffnen.
- Jeder andere Prozess — normale Nutzerprozesse, andere Agenten, eine andere Inkarnation desselben Agenten — erhält `ACCESS_DENIED` bereits beim Öffnen (vor jeder Anwendungslogik).

**Choke-Point-Eigenschaft:** Da Netzwerk auf Kernel-Ebene verweigert wird und sonstige IPC/Datei-Zugriffe eingeschränkt sind, wird der Pipe zum **einzigen Pfad**, über den der Agent kommunizieren oder Fähigkeiten anfordern kann. Damit konzentriert sich sämtliche sicherheitsrelevante Logik auf einen einzigen, überwachbaren und auditierbaren Punkt — anstatt über eine unüberschaubare Fläche von Angriffsvektoren verteilt zu sein.

**Konsequenz:** Die gesamte Sicherheitsarchitektur reduziert sich auf die Frage „Wer darf diesen einen Pipe öffnen und was darf darüber fließen?" — beides ist deterministisch beantwortbar.

### 2.3 Kernel-Level-Identitätsverifikation (Anti-PID-Reuse / Anti-Spoofing)

**Problem:** Ein Angreifer könnte versuchen, sich als legitimer Agent auszugeben, indem er (a) einen selbstberichteten PID-Wert fälscht oder (b) eine **PID-Reuse** ausnutzt: Nachdem der echte Agent beendet wurde, kann das Betriebssystem dieselbe numerische PID an einen neuen, böswilligen Prozess vergeben, der dann versucht, als der alte Agent zu erscheinen.

**Mechanik:**

1. **Kernel-Objekt-Lesen statt Header-Vertrauen:** Der Server ruft `GetNamedPipeClientProcessId()` auf. Diese Funktion liest die Client-PID **direkt aus dem internen File-Object-Zustand des Pipes im Kernel** — nicht aus irgendeinem vom Client gesendeten Header. Ein Client kann diesen Wert **nicht** fälschen, da er vom Kernel aus der tatsächlichen Verbindung abgeleitet wird.
2. **Creation-Timestamp-Kopplung:** Der Server verknüpft die gelesene PID zusätzlich mit dem **Prozess-Erstellungszeitstempel** (via `GetProcessTimes`). Dieser Zeitstempel wurde beim Spawnen des echten Agenten aufgezeichnet. Besitzt die von `GetNamedPipeClientProcessId` gelieferte PID inzwischen einen **anderen** Erstellungszeitstempel, wurde die PID recycelt → der Verbindungsversuch wird verworfen.

**Konsequenz:** Identität wird **im Kernel verankert** und an einen unveränderlichen Zeitstempel gebunden. Header-Spoofing (gefälschte PID) und PID-Reuse-Angriffe werden beide bereits auf der Verbindungs-Ebene neutralisiert.

### 2.4 Job Object Lineage Enforcement (Anti-Breakaway)

**Problem:** Ein AI-Agent ist typischerweise ein Orchestrator, der Interpreter-Kindprozesse (`python.exe`, `node.exe`) erzeugt. Diese Kinder könnten versuchen, sich der Überwachung zu entziehen („breakaway") und eigenständig zu agieren.

**Mechanik:** Agent **und alle erzeugten Kindprozesse** werden in ein Windows **Job Object** gesperrt (`AssignProcessToJobObject`), konfiguriert mit:

- **`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`:** Wird der letzte Handle auf das Job Object geschlossen (bzw. das Job Object terminiert), **terminiert der Kernel automatisch alle** im Job befindlichen Prozesse. Es gibt keine verwaisten Prozesse, die den Lebenszyklus des Agenten überleben.
- **Breakaway-Verhinderung:** Das Flag `JOB_OBJECT_LIMIT_BREAKAWAY_OK` wird **nicht** gesetzt. Damit ist es Kindprozessen **nicht** gestattet, sich mittels `CREATE_BREAKAWAY_FROM_JOB` aus dem Job zu lösen. Die Kindprozesse erben die Job-Zugehörigkeit zwangsläufig.

**Konsequenz:** Die Isolation erstreckt sich auf die **gesamte Prozess-Linie (lineage)** des Agenten. Es existiert kein Mechanismus, über den ein Kindprozess der Sandbox entkommen und außerhalb des kontrollierten Lebenszyklus weiterleben könnte. Das Beenden des Agents reißt deterministisch die gesamte Prozesskette mit.

### 2.5 Manipulationssicherer Audit-Trail (HMAC-SHA256-Kette + DPAPI)

**Mechanik:** Sämtliche Kommunikation und **alle blockierten Aktionen** werden in einen **Append-only-JSONL-Stream** (JSON Lines) geschrieben. Die Manipulationssicherheit wird über eine **kryptografische Hash-Kette** hergestellt:

1. **Verkettung:** Jeder Datensatz `i` erhält einen `MAC_i = HMAC-SHA256(secret, record_i ‖ MAC_{i-1})`. Jeder MAC deckt also sowohl den eigenen Inhalt als auch den **MAC des Vorgängers** ab. Es entsteht eine hash-verlinkte Liste (Hash Chain).
2. **Eigenschaft (Tamper-Evidence):** Jede nachträgliche Änderung eines Datensatzes invalidiert dessen MAC **und** kaskadierend alle nachfolgenden MACs. Löschen eines Datensatzes bricht die Verkettung (der Nachfolger referenziert einen nicht mehr vorhandenen Vorgänger-MAC). Einfügen eines Datensatzes erzeugt einen nicht in der Kette verankerten MAC. **Umordnung** bricht die Vorwärtsreferenz. Damit sind Modifikation, Deletion, Insertion und Reordering **detektierbar**.
3. **Schlüsselschutz via DPAPI:** Das HMAC-Geheimnis (bzw. das Ketten-Root-Material) ist mittels **Windows DPAPI** (`CryptProtectData`) geschützt. DPAPI bindet die Verschlüsselung an den **Benutzer-/Master-Key- und Systemkontext**, sodass das Geheimnis (a) nicht im Klartext persistiert wird und (b) nur innerhalb desselben Sicherheitskontexts entschlüsselbar ist.

**Konsequenz:** Der Audit-Trail ist **append-only** und **non-repudiable** (nicht abstreitbar). Ein kompromittierter Prozess kann Logs weder unsichtbar verändern noch löschen, ohne die kryptografische Kette zu brechen — was sofort erkennbar ist.

### 2.6 Erweiterte Module (Kurzprofile)

| Modul | Funktion |
|---|---|
| **Genotype Rotation** | Ephemere, dynamisch generierte AppContainer-SIDs **pro Agent-Inkarnation**. Jede neue Inkarnation erhält eine frische SID; die Pipe-DACL bindet an exakt diese SID. Eine veraltete/wiederverwendete SID einer früheren Inkarnation kann sich daher nicht mehr authentifizieren — die Identität „rotiert" wie ein Genotyp. |
| **Entropy Tax Choke** | Traffic- und Timing-Überwachung, die **automatisiertes Reconnaissance/Probing** drosselt. Hoch-entropische Anfragemuster (z. B. hohe Shannon-Entropie der Request-Intervalle, Payload-Größen oder Befehlsvielfalt) werden mit Latenz/Throttling belegt — ein „Steuer"-Mechanismus gegen maschinelle Aufzählung. |
| **Credential Vault & MCP Policy Filter** | **In-Memory-Secret-Injection** (Secrets werden zur Laufzeit in den Agenten-Kontext injiziert, nie auf Platte persistiert) plus **feingranulares MCP-Tool-Whitelisting** (Model Context Protocol). Nur explizit erlaubte MCP-Tools sind aufrufbar. |
| **AST-Based Code Inspector** | **Pre-Execution Static Analysis** generierter Code-Payloads: Der Code wird vor Ausführung in einen Abstract Syntax Tree geparst und auf gefährliche Muster (Netzwerkaufrufe, Subprozess-Spawn, Dateizugriff, dynamische Auswertung) untersucht; verdächtige Payloads werden blockiert. |

---

## 3. Security Boundaries & Threat Matrix

### 3.1 Was blockiert wird (Garantien)

| Bedrohung | Durchsetzungsmechanismus | Ergebnis |
|---|---|---|
| Rohe Socket-Erstellung / Netzwerk-Egress | AppContainer ohne Netzwerk-Capabilities | Kernel-`E_ACCESSDENIED` beim `socket()`/`connect()` |
| Beliebige IPC / Interop außerhalb des Gateways | DACL-gebundener Named Pipe als einziger Kanal | `ACCESS_DENIED` für alle anderen Subjekte |
| PID-Reuse / Header-Spoofing | `GetNamedPipeClientProcessId` + Creation-Timestamp | Gefälschte/recycelte Identität verworfen |
| Breakaway-/Kindprozess-Ausbruch | Job Object + `KILL_ON_JOB_CLOSE`, kein Breakaway-Flag | Kindprozesse untrennbar an Agenten-Lebenszyklus gebunden |
| Audit-Trail-Manipulation | Append-only JSONL + HMAC-SHA256-Kette + DPAPI | Jede Manipulation bricht die Kette (detektierbar) |
| Unautorisierte Tool-Ausführung | MCP Policy Filter (Whitelist) | Nicht gelistete Tools abgelehnt |
| Secret-Exfiltration von Platte | Credential Vault in-memory | Keine persistierten Secrets vorhanden |
| Ausführung gefährlichen generierten Codes | AST-Based Code Inspector | Blockierung vor Ausführung |

### 3.2 Ehrliche Grenzen (Out-of-Scope)

Diese Grenzen sind **bewusst deklariert** und dürfen von keinem AI-Konsumenten als abgedeckt angenommen werden:

1. **Lokaler Dateisystem-Schreibzugriff:** Wenn dieser explizit gewährt wurde, kontrolliert Cordon ihn **nicht**. Die AppContainer-Low-Integrity-Level-Eigenschaft schränkt Schreibzugriffe auf Objekte höherer Integrity Level ein, aber ein explizit gewährter Schreibpfad liegt außerhalb der Enforcement-Grenze.
2. **Data Smuggling über legal erlaubte Kanäle:** Exfiltration über einen **genehmigten Kanal** (z. B. eine erlaubte GitHub-API) ist **technisch möglich**. Der Choke Point kontrolliert, *welche* Kanäle offen sind, nicht den *Inhalt*, der über einen offenen Kanal fließt. Ein Agent, der Zugriff auf eine erlaubte API hat, kann Daten prinzipiell darüber transportieren.
3. **Vollständige Administrator-Rechte:** Ein Prozess, der mit vollständigen Administrator-Rechten läuft, steht **außerhalb** des Schutzmodells. AppContainer/Job-Object/Integrity-Level basieren auf einer Privilegien-Reduktion, die ein Administrator umgehen kann.
4. **Kernel-Level-Exploits (BYOVD):** „Bring Your Own Vulnerable Driver" und vergleichbare Kernel-Angriffe, die einen verwundbaren Treiber laden, um Kernel-Code auszuführen, liegen **außerhalb** des Schutzbereichs. Cordon schützt gegen den *kompromittierten User-Mode-Prozess*, nicht gegen einen *kompromittierten Kernel*.

### 3.3 Zusammenfassung des Bedrohungsmodells

- **Angenommener Angreifer:** Ein mit Standard-Nutzerrechten laufender, kompromittierter AI-Agent-Prozess (Prompt-Injection, Supply-Chain, Model-Lackage).
- **Durchsetzungspunkt:** Windows-Kernel (nicht User-Mode-Proxys).
- **Residualrisiko:** Inhaltsbasierte Exfiltration über legitime Kanäle; vollprivilegierte Konten; Kernel-Exploits.

---

## 4. Implementation Blueprint für AI-Konsumenten

### 4.1 Vertrauensmodell — was ein externes AI/Automatisierungssystem *annehmen darf*

Ein externes AI oder Automatisierungssystem, das Cordon-gemanagte Agenten steuert oder deren Ergebnisse konsumiert, darf **begründet annehmen**, dass:

1. **Kein Netzwerk-Egress ohne Gateway** erfolgt ist — der Agent konnte keine rohen Sockets öffnen.
2. **Keine nicht-vermittelte IPC** außerhalb des `CordonGateway`-Pipes stattfand.
3. **Keine Identitäts-Fälschung** auf Pipe-Ebene möglich war (Kernel-PID + Creation-Timestamp).
4. **Keine überlebenden Kindprozesse** nach Agenten-Terminierung existieren (Job Object).
5. **Der Audit-Trail unverändert** ist — jede Manipulation ist durch die HMAC-Kette erkennbar und überprüfbar.
6. **Secrets nie persistent** auf Platte lagen (in-memory Vault).
7. **Nur whitelistete MCP-Tools** ausgeführt wurden und **gefährlicher generierter Code** per AST-Analyse vor Ausführung blockiert wurde.

Ein externes AI darf **nicht** annehmen, dass:

- lokale Schreibzugriffe verhindert wurden (sofern gewährt);
- Exfiltration über einen erlaubten API-Kanal unmöglich ist;
- der Schutz gegen Administrator-Rechte oder Kernel-Exploits (BYOVD) gilt.

### 4.2 Schnittstellen-Vertrag (Interface Contract)

Ein automatisiertes System, das mit einem Cordon-Agenten interagiert, muss folgende Regeln einhalten:

1. **Eindeutiger Kanal:** Sämtliche Kommunikation läuft ausschließlich über `\\.\pipe\CordonGateway`. Es gibt keinen zweiten Egress.
2. **Authentifizierung = AppContainer-SID:** Der Client-Prozess muss unter der **exakt aktuellen** AppContainer-SID der laufenden Inkarnation laufen (Genotype Rotation beachten). Die SID rotiert pro Inkarnation; eine gespeicherte SID einer früheren Inkarnation ist ungültig.
3. **Identität wird serverseitig verifiziert:** Der Konsument sollte sich niemals auf selbstberichtete Client-Metadaten verlassen. Der Server leitet Identität ausschließlich aus `GetNamedPipeClientProcessId` + Creation-Timestamp ab.
4. **Capability-Modell:** Jede Operation (Netzwerk, Tool, Secret, Code-Ausführung) ist eine **explizite Mediations-Anfrage** an den Gateway. Es existiert kein „implizit erlaubter" Pfad. Der Konsument muss pro Operation eine Policy-Prüfung erwarten.
5. **Policy-Abfragen:** Der Konsument sollte die drei Policy-Schichten als Filterkette modellieren:
   - **MCP-Tool-Whitelist** (welche Tools erlaubt sind),
   - **AST-Code-Inspector** (ob eine Code-Payload ausführbar ist),
   - **Entropy Tax Choke** (ob ein Anfragemuster gedrosselt wird — hohe Anfrage-Entropie führt zu Throttling).
6. **Audit-Konsum:** Der Konsument kann den JSONL-Stream lesen und die HMAC-SHA256-Kette **selbst verifizieren** (bei Zugriff auf das DPAPI-entschlüsselte Geheimnis), um die Integrität der Ereignishistorie zu bestätigen. Jeder Kettenbruch signalisiert Manipulation.

### 4.3 Ereignis-/Audit-Datenmodell (empfohlenes Reasoning)

Beim Verarbeiten von Audit-Ereignissen sollte ein Konsument mindestens zwischen folgenden Klassen unterscheiden:

- **Vermittelte Aktionen** (erlaubte, protokollierte Gateway-Operationen),
- **Blockierte Aktionen** (verweigerte Netzwerk-/IPC-/Tool-/Code-Versuche — ein Indikator für Kompromittierung oder Reconnaissance),
- **Ketten-/Integritätsereignisse** (Nachweis der Log-Unversehrtheit oder Bruch derselben).

### 4.4 Reasoning-Leitfaden für Sicherheitsentscheidungen

| Frage des Konsumenten | Ableitung aus Cordon |
|---|---|
| „Kann der Agent eigenständig ins Netz?" | Nein — Kernel-`E_ACCESSDENIED`, kein Ambient-Netzwerk. |
| „Kann der Agent sich als anderer Prozess ausgeben?" | Nein — Identität aus Kernel-Objekten + Creation-Timestamp. |
| „Können Kindprozesse überleben?" | Nein — Job Object `KILL_ON_JOB_CLOSE`, kein Breakaway. |
| „Sind Logs vertrauenswürdig?" | Ja, sofern die HMAC-Kette intakt verifiziert wird. |
| „Können Daten trotzdem abfließen?" | Ja, **über einen explizit erlaubten Kanal** (z. B. genehmigte API) — Out-of-Scope. |
| „Schützt es gegen Admin/Kernel-Exploits?" | Nein — Administrator und BYOVD liegen außerhalb des Modells. |
