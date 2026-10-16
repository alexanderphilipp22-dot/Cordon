# Cordon — Architektur, Bedrohungsmodell und Grenzen

Dieses Dokument beschreibt, **warum** Cordon so aufgebaut ist, wie es ist,
welche Zusicherungen es gibt und — ebenso wichtig — welche **nicht**. Es ist
die verbindliche Referenz für Sicherheitsaussagen. Die Abschnittsnummern sind
stabil und werden aus `README.md` referenziert.

---

## 1. Designziele

Cordon ist ein lokales, capability-basiertes Gateway, das autonome KI-Agenten
isoliert. Die Kernaussage lautet:

> Ein kompromittierter Agent kann keine eigene Netzwerkverbindung öffnen —
> nicht, weil eine Konvention ihn davon abhält, sondern weil der **Kernel** es
> verweigert.

Daraus folgen drei nicht verhandelbare Prinzipien:

1. **Die Grenze liegt im Betriebssystem, nicht in User-Mode-Logik.** Ein
   Proxy mit Header-Token ist wertlos, weil der Agent den Token selbst lesen
   und setzen kann. Cordon zieht die Grenze in den AppContainer, das Job
   Object und die Named-Pipe-DACL.
2. **Identität kommt aus dem Kernelobjekt.** Die PID stammt aus
   `GetNamedPipeClientProcessId` am Pipe-Handle, niemals aus der Nutzlast.
3. **Fail closed.** Es gibt keinen „permit all"-Fallback. Ohne ladbare Policy
   lauscht das Gateway nicht; ein Agent ohne AppContainer wird abgelehnt.

---

## 2. Netzwerkgrenze: AppContainer + WFP (kein Kernel-Callout)

Die primäre Grenze ist der **AppContainer ohne Netzwerk-Capabilities**. Der
Agent wird über `CreateProcessW` mit
`PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` erzeugt, wobei
`Capabilities = NULL` und `CapabilityCount = 0` gesetzt sind. Ohne
`internetClient` / `privateNetworkClientServer` verweigert der Kernel jeden
`socket()`-, `connect()`- und `sendto()`-Aufruf für `AF_INET`/`AF_INET6` —
inklusive UDP:53 (DNS) und Loopback.

Diese Grenze ist bewusst **grob**: sie blockt *alle* Netzwerkzugriffe, nicht
„nur Port 443 zu diesen fünf Hosts". Die feine Granularität entsteht erst
hinter der Pipe, in der Policy-Engine. Ein präziser **WFP-Callout**
(Kernelmodus) könnte das direkt am Socket erledigen, hätte aber drei hohe
Kosten:

- **Signierung/WHQL** für den Kernelmodus-Treiber.
- **Kernel-Angriffsfläche** im Pfad jedes Agenten-Pakets.
- **Wartungskomplexität** weit über den Nutzen eines lokal betriebenen
  Kontrollpunkts hinaus.

Deshalb ist die Entscheidung: AppContainer als *kategorische* Grenze, Policy
als *feine* Grenze. Die optionale WFP-Regel (§2.1) ist eine zweite,
redundante Verteidigungslinie.

### 2.1 WFP-Default-Deny (Defense in Depth)

Zusätzlich kann `WfpEnforcement` eine Blockierregel pro Package-SID in den
Layern `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` setzen. Sie fängt den Fall ab, dass
ein Agent versehentlich *mit* Netzwerk-Capability gestartet wird, und gilt für
jeden Prozess der Package-SID — auch außerhalb des Job Objects.

- **Dynamisch per Default** (`FWPM_SESSION_FLAG_DYNAMIC`): die Regel stirbt
  mit dem Cordon-Prozess. Ein Agent bleibt nie dauerhaft netzlos zurück, nur
  weil Cordon abstürzte.
- **`--wfp-persistent`** überlebt einen Neustart und muss manuell entfernt
  werden.
- Die Struct-Layouts sind auf **x64** ausgelegt; `ApplyTo` wirft auf x86
  `PlatformNotSupportedException` statt still falsche Layouts zu verwenden.

---

## 3. Datenpfad und Identitätsmodell

```
Agent (AppContainer, KEINE Netzwerk-Capabilities)
   │  SslStream / HttpClient
   ▼
Cordon.AgentSdk  ──►  Named Pipe  \\.\pipe\CordonGateway.<agentId>
   │                   (Byte-Modus, DACL = Package-SID)
   │                        │  GetNamedPipeClientProcessId → PID
   │                        │  GetProcessTimes → Erzeugungszeit
   │                        │  OpenProcess → Image, Token, Package-SID, Integrität
   │                        ▼
                   Cordon-Gateway (LocalSystem)
                        │  Upstream-Socket, TLS-Passthrough
                        ▼
                      Internet
```

Es gibt **keinen lokalen TCP-Proxy-Port**. TCP trägt keine Prozessidentität;
ein lokaler Proxy müsste den Aufrufer über einen fälschbaren Bearer-Token im
ersten Paket identifizieren. Die Named Pipe liefert die Identität aus dem
Kernel und ist daher **zugleich Identitäts- und Datenkanal**.

### 3.1 Zwei unabhängige Bindungen

Die Identität eines Agenten beruht auf zwei getrennten Mechanismen:

1. **Pipe-DACL auf die Package-SID.** Nur der eine Agent, dem die Pipe gehört,
   kann sie überhaupt öffnen. Kein `Everyone`, keine `Authenticated Users`.
2. **Token-Inspektion.** Das Gateway liest Image-Pfad, Package-SID,
   Integritätslevel und Capabilities direkt aus dem Token und vergleicht die
   Package-SID mit der erwarteten. Eine fehlerhaft gesetzte DACL wird damit
   als *zweite, unabhängige* Prüfung erkannt.

Die Validierung (`IdentityValidator`) sammelt **alle** Verstöße, statt beim
ersten abzubrechen — das Audit zeigt, wie weit ein Angreifer gekommen ist.

---

## 4. PID-Reuse und Erzeugungszeit

Eine PID ist **keine Identität über die Zeit**. Windows vergibt PIDs nach dem
Ende eines Prozesses neu. Würde Cordon nur die PID merken und später erneut
auflösen, könnte zwischen beiden Schritten der Agent sterben und ein fremder
Prozess dieselbe PID erhalten; Cordon läse dann dessen Token.

### 4.1 Die Erzeugungszeit als Instanzbindung

Die Gegenmaßnahme ist eine doppelte Erfassung mit Erzeugungszeit-Vergleich:

1. Unmittelbar nach dem Verbindungsaufbau liest
   `PipeClientCaptureReader.Capture` PID **und** Erzeugungszeit
   (`GetProcessTimes`) am Pipe-Handle und bindet beides als
   `PipeClientSignature` an die Verbindung.
2. Beim Handshake löst `PipeClientResolver.Resolve` die Identität erneut auf
   und prüft:
   - eine **zweite Erfassung am Pipe-Handle** ergibt dieselbe Signatur, und
   - `GetProcessTimes` des geöffneten Prozesses liefert **exakt** dieselbe
     Erzeugungszeit.

Weicht einer der Werte ab, wurde die PID zwischenzeitlich neu vergeben; die
Auflösung wird mit `identity.process_reused` verworfen (fail closed). Die
Erzeugungszeit wird als roher `FILETIME`-Wert (100-ns-Intervalle) verglichen,
nicht als `DateTime` — so kommen keine Rundungs- oder Zeitzonenfehler in den
Vergleich.

---

## 5. Policy-Engine und Host-Matching

Die Policy (`scopes.json`) wird beim Laden vollständig validiert und
kompiliert. **Ein einziger ungültiger Scope verhindert das Laden der ganzen
Datei** — ein Teil-Load würde Regeln still verschwinden lassen.

- **Default Deny.** `defaultVerdict` muss `deny` sein; `*` als Hostmuster ist
  verboten; leere Principals sind ein Konfigurationsfehler.
- **Host-Matching ist absichtlich streng.** `*.example.com` matcht Subdomains,
  **nicht** den Apex. Kurzform-IPs (`1`, `1.2`, `127.1`), Userinfo-Tricks
  (`evil.com@127.0.0.1`), Zone-Indizes (`fe80::1%eth0`) und IDN-Homographen
  werden normalisiert oder abgelehnt.
- **Die Adressprüfung läuft nach der Namensauflösung auf der konkreten IP.**
  Damit ist DNS-Rebinding ausgeschlossen: geprüft wird die tatsächlich
  verbundene Adresse, nicht der Name. Loopback, Link-Local, IPv4-mapped
  (`::ffff:0:0/96`), NAT64 (`64:ff9b::/96`) und reservierte Bereiche sind
  unabhängig von der Policy gesperrt.
- **Image-Pfad-Bindung.** `PathStartsWith` erzwingt eine Verzeichnisgrenze:
  `C:\Agents\res` erfasst nicht `C:\Agents\research-evil\`.
- **JSON-Kontrakt.** Sammlungen und eingebettete Objekte des Modells sind auch
  nach dem Laden **nie `null`**: die `init`-Accessoren setzen einen
  Rückfallwert, weil der Source-Generator für fehlende Schlüssel sonst
  `default` übergibt und den Initialisierer `= []` überschreibt. Das gilt auch
  für die DTOs der Frames. Abgesichert durch `RunJsonDefaultsTests` in
  `test/Cordon.Tests`.

---

## 6. TLS: Passthrough und optionale Interception

- **Default: Passthrough.** Cordon liest nur `host:port` aus einem JSON-Frame
  und kopiert danach opake Bytes. Es sieht **keinen Klartext** und hält
  **keinen Schlüssel**. Die Serverauthentifizierung bleibt beim Agenten aktiv.
- **Opt-In: Interception.** Nur wenn der Scope `tls=intercept` setzt **und**
  der Host in `interceptAllowlist` steht. Die Leaf-Zertifikate stammen aus
  einer **lokalen** CA, die **niemals** in den Windows-Trust-Store geschrieben
  wird. Damit gewinnt kein anderer Prozess Vertrauen.
- Interception beschränkt sich auf **einen** HTTP-Request pro Tunnel;
  `Transfer-Encoding: chunked` in Requests wird mit `501` abgelehnt. Ein halb
  implementierter Chunked-Parser wäre ein Request-Smuggling-Risiko.

---

## 7. Audit-Kette

JSON Lines unter `%ProgramData%\Cordon\audit\cordon-YYYYMMDD.jsonl`. Jeder
Ausgang wird protokolliert — auch `allow`.

Die Einträge bilden eine **HMAC-SHA256-Kette**:

```
hmac_n = HMAC(K, hmac_{n-1} ‖ kanonische_form(event_n))
```

- Der Schlüssel wird mit **DPAPI (LocalMachine)** geschützt und liegt unter
  `%ProgramData%\Cordon\config\audit-hmac.key`; die ACL beschränkt den Zugriff
  auf LocalSystem/Administratoren.
- Die kanonische Form ist **handgeschrieben** und umfasst alle
  sicherheitsrelevanten Felder — inklusive `isAppContainer`, `capabilities`
  (sortiert), `rawHost`, `durationMs` — damit ein Umschreiben dieser Felder
  die Kette bricht. Sie ist in `AuditLog` und `AuditVerifier` bewusst
  dupliziert, damit eine Änderung an einer Stelle die Prüfung bricht.
- Die Prüfung belegt, dass die Datei nicht *stückweise* verändert wurde. Sie
  belegt **nicht**, dass ein Administrator die Datei nicht konsistent neu
  erzeugt hat — der Insider-Admin ist **außerhalb** des Bedrohungsmodells.

---

## 8. Startpfad (AppContainer + Job Object + WFP)

Die Reihenfolge beim Start ist sicherheitskritisch und fest:

1. `CreateProcessW` mit `CREATE_SUSPENDED` — der Prozess läuft noch nicht.
2. AppContainer über `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` binden
   (ohne Capabilities).
3. `AssignProcessToJobObject`.
4. Erst jetzt `ResumeThread`.

Würde zwischen Schritt 1 und 3 fortgesetzt, könnte der Agent in diesem Fenster
einen Kindprozess außerhalb des Jobs erzeugen. Das Job Object setzt
`KILL_ON_JOB_CLOSE` und setzt **nicht** `BREAKAWAY_OK`/`SILENT_BREAKAWAY_OK` —
Kindprozesse können nicht aus der Grenze austreten.

---

## 9. Named-Pipe-Härtung und `PIPE_REJECT_REMOTE_CLIENTS`

Die Pipe wird mit `NamedPipeServerStreamAcl.Create` im Byte-Modus erzeugt. Die
DACL enthält ausschließlich die Package-SID des Agenten (minimale Rechte),
LocalSystem und Administratoren. Der Agent erhält **kein** `ChangePermissions`
und **kein** `TakeOwnership` — er kann die Grenze nicht umkonfigurieren.

**Offener Punkt (Iteration 2):** `PIPE_REJECT_REMOTE_CLIENTS` lässt sich über
die öffentliche `NamedPipeServerStream`-API nicht setzen. In Iteration 1 wird
der Schutz allein von der DACL getragen. Da die DACL **keine
Netzwerk-Identitäten** enthält (Package-SIDs sind maschinenlokale
AppContainer-SIDs), kann ein SMB-Aufrufer von einem anderen Rechner die Pipe
nicht öffnen. Für Iteration 2 ist die Pipe über `CreateNamedPipeW` mit
explizitem `PIPE_REJECT_REMOTE_CLIENTS` zu erzeugen.

---

## 10. Bedrohungsmodell

**Abgedeckt (Zusicherungen):**

- Ein kompromittierter Agent kann keine direkte Netzwerkverbindung öffnen
  (AppContainer, Kernel-erzwungen).
- Ein Agent kann sich nicht als ein anderer Agent ausgeben (Pipe-DACL +
  Package-SID + PID/Erzeugungszeit).
- Ein Agent kann DNS-Rebinding nicht ausnutzen (Adressprüfung auf der
  verbundenen IP).
- Ein Agent kann keine SSRF auf Loopback/Link-Local/Cloud-Metadata ausführen
  (global gesperrt, Default aus).
- Ein Agent kann die Audit-Kette nicht unbemerkt stückweise verändern
  (HMAC-Kette + DPAPI + ACL).

**Explizit NICHT abgedeckt:**

- **Der Insider-Administrator.** Ein Admin kann die Audit-Datei konsistent neu
  erzeugen, die Policy ändern oder das Gateway deaktivieren. Schutz gegen den
  Admin ist kein Ziel.
- **Kernel-0-days im AppContainer-/Netzwerk-Stack.** Cordon verlässt sich auf
  die vom Betriebssystem gelieferte Isolation.
- **PPL-Härtung des Dienstprozesses** (erfordert ELAM-Signierung).
- **Datei-/Registry-Isolation** über das hinaus, was AppContainer + Low-IL
  automatisch geben.

---

## 11. Bekannte Grenzen (Iteration 1)

1. **Nicht kompiliert.** Die Entstehungsumgebung hatte kein .NET-SDK; der
   erste `dotnet build` ist ein echter Schritt (P/Invoke-Layouts).
2. **`PIPE_REJECT_REMOTE_CLIENTS` fehlt** (siehe §9).
3. **`MaxConcurrentConnections` und `SessionTtlSeconds` werden validiert,
   aber noch nicht durchgesetzt.** `MaxBytesUp`/`MaxBytesDown` sind wirksam;
   die Verbindungszahl- und TTL-Limits sind dokumentierte Konfiguration ohne
   Durchsetzung und in Iteration 2 zu implementieren.
4. **`--no-wait` terminiert den Agenten.** Wegen `KILL_ON_JOB_CLOSE` wird der
   Agent beim Schließen des Job-Handles beendet; ein „detached" laufender
   Agent bräuchte einen langlebigen Supervisor (den Dienst).
5. **`requireSignature` prüft die Kette offline**, liest den
   Signer-Subject aber noch nicht aus.
6. **WFP-Regeln sind global pro Package-SID** (pro Agent ein Profil, daher
   akzeptabel, aber eine globale Ressource).
7. **Kein Fuzzing** des Frame-Parsers. Die Grenzen sind gesetzt (1 MiB
   Frame-Body, 256 KiB Payload), ein Fuzz-Durchlauf steht aus.
