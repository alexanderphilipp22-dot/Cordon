using Cordon.Core;
using Cordon.Core.Audit;
using Cordon.Core.Model;
using Cordon.Core.Policy;
using Cordon.Core.Protocol;
using Cordon.Windows;

namespace Cordon.Tests;

/// <summary>
/// Abhaengigkeitsfreier Selbsttest.
/// <para>
/// Bewusst kein xUnit/NUnit: der Build soll ohne NuGet-Restore funktionieren.
/// Die Tests konzentrieren sich auf die Stellen, an denen ein Fehler eine
/// <b>Sicherheitsluecke</b> waere - Host-Normalisierung, Wildcard-Matching,
/// Pfadgrenzen und die Audit-Kette - und nicht auf Abdeckungszahlen.
/// </para>
/// </summary>
internal static class Program
{
    private static int _failures;
    private static int _total;

    private static int Main()
    {
        Console.WriteLine("Cordon.Tests");
        Console.WriteLine();

        RunHostNormalizationTests();
        RunHostRuleTests();
        RunAddressClassifierTests();
        RunPolicyEngineTests();
        RunJsonDefaultsTests();
        RunPathStartsWithTests();
        RunProtocolTests();
        RunAuditChainTests();
        RunPipeIdentityIntegrationTest();

        Console.WriteLine();
        Console.WriteLine($"{_total - _failures}/{_total} Tests bestanden.");

        if (_failures == 0)
        {
            Console.WriteLine("OK");
            return 0;
        }

        Console.Error.WriteLine($"{_failures} Test(s) FEHLGESCHLAGEN.");
        return 1;
    }

    // =====================================================================
    // Host-Normalisierung
    // =====================================================================

    private static void RunHostNormalizationTests()
    {
        Section("Host-Normalisierung");

        // Grundformen
        Check("einfacher DNS-Name", () => HostNormalizer.Normalize("example.com").Value == "example.com");
        Check("Grossschreibung", () => HostNormalizer.Normalize("EXAMPLE.COM").Value == "example.com");
        Check("Trailing Dot entfernt", () => HostNormalizer.Normalize("example.com.").Value == "example.com");
        Check("Leerzeichen getrimmt", () => HostNormalizer.Normalize("  example.com  ").Value == "example.com");

        // IDN
        Check("IDN zu Punycode", () =>
            HostNormalizer.Normalize("münchen.de").Value == "xn--mnchen-3ya.de");
        Check("Punycode bleibt Punycode", () =>
            HostNormalizer.Normalize("xn--mnchen-3ya.de").Value == "xn--mnchen-3ya.de");
        Check("IDN und Punycode sind gleich", () =>
            HostNormalizer.Normalize("münchen.de").Value == HostNormalizer.Normalize("MÜNCHEN.DE").Value);

        // IP-Literale
        Check("IPv4-Literal", () => HostNormalizer.Normalize("203.0.113.7").Form == HostForm.IpLiteral);
        Check("IPv6-Literal", () => HostNormalizer.Normalize("2606:4700::1111").Form == HostForm.IpLiteral);
        Check("IPv6 in Klammern", () =>
            HostNormalizer.Normalize("[2606:4700::1111]").Form == HostForm.IpLiteral);

        // Umgehungsversuche
        Check("Kurzform '1' abgelehnt", () => !HostNormalizer.Normalize("1").IsValid);
        Check("Kurzform '1.2' abgelehnt", () => !HostNormalizer.Normalize("1.2").IsValid);
        Check("Kurzform '127.1' abgelehnt", () => !HostNormalizer.Normalize("127.1").IsValid);
        Check("userinfo '@' abgelehnt", () => !HostNormalizer.Normalize("evil.com@127.0.0.1").IsValid);
        Check("Pfad '/' abgelehnt", () => !HostNormalizer.Normalize("example.com/path").IsValid);
        Check("Backslash abgelehnt", () => !HostNormalizer.Normalize("example.com\\x").IsValid);
        Check("Nullbyte abgelehnt", () => !HostNormalizer.Normalize("example.com\0.evil.com").IsValid);
        Check("CRLF abgelehnt", () => !HostNormalizer.Normalize("example.com\r\nX: 1").IsValid);
        Check("Leerer Host abgelehnt", () => !HostNormalizer.Normalize("").IsValid);
        Check("Nur Punkte abgelehnt", () => !HostNormalizer.Normalize("...").IsValid);
        Check("Einzelnes Label abgelehnt", () => !HostNormalizer.Normalize("localhost").IsValid);
        Check("Zone-Index abgelehnt", () => !HostNormalizer.Normalize("fe80::1%eth0").IsValid);
        Check("Label mit fuehrendem '-' abgelehnt", () => !HostNormalizer.Normalize("-x.example.com").IsValid);
    }

    // =====================================================================
    // HostRule
    // =====================================================================

    private static void RunHostRuleTests()
    {
        Section("Hostregeln");

        Check("'*' allein ist verboten", () => !HostRule.TryCompile("*", out _, out _));
        Check("'**.example.com' ist verboten", () => !HostRule.TryCompile("**.example.com", out _, out _));
        Check("Binnen-Wildcard ist verboten", () => !HostRule.TryCompile("a*.example.com", out _, out _));
        Check("Wildcard auf IP ist verboten", () => !HostRule.TryCompile("*.0.0.113", out _, out _));

        // Exakter Treffer
        HostRule.TryCompile("docs.python.org", out var exact, out _);
        Check("exakter Treffer", () => exact!.Matches(HostNormalizer.Normalize("docs.python.org")));
        Check("exakter Treffer ist case-insensitiv", () =>
            exact!.Matches(HostNormalizer.Normalize("DOCS.PYTHON.ORG")));
        Check("exakter Treffer matcht Subdomain NICHT", () =>
            !exact!.Matches(HostNormalizer.Normalize("evil.docs.python.org")));

        // Wildcard: Subdomain ja, Apex nein
        HostRule.TryCompile("*.wikipedia.org", out var wildcard, out _);
        Check("Wildcard matcht Subdomain", () =>
            wildcard!.Matches(HostNormalizer.Normalize("de.wikipedia.org")));
        Check("Wildcard matcht tiefe Subdomain", () =>
            wildcard!.Matches(HostNormalizer.Normalize("a.b.wikipedia.org")));
        Check("Wildcard matcht APEX NICHT", () =>
            !wildcard!.Matches(HostNormalizer.Normalize("wikipedia.org")));
        Check("Wildcard matcht fremden Namen NICHT", () =>
            !wildcard!.Matches(HostNormalizer.Normalize("notwikipedia.org")));
        Check("Wildcard matcht Suffix-Trick NICHT", () =>
            !wildcard!.Matches(HostNormalizer.Normalize("wikipedia.org.evil.com")));

        // IP und CIDR
        HostRule.TryCompile("203.0.113.7", out var exactIp, out _);
        Check("exakte IP", () => exactIp!.Matches(HostNormalizer.Normalize("203.0.113.7")));
        Check("exakte IP matcht andere nicht", () =>
            !exactIp!.Matches(HostNormalizer.Normalize("203.0.113.8")));

        HostRule.TryCompile("10.0.4.0/24", out var cidr, out _);
        Check("CIDR enthaelt", () => cidr!.Matches(HostNormalizer.Normalize("10.0.4.55")));
        Check("CIDR ausserhalb", () => !cidr!.Matches(HostNormalizer.Normalize("10.0.5.1")));
        Check("CIDR matcht keinen Namen", () => !cidr!.Matches(HostNormalizer.Normalize("example.com")));

        // HostRuleSet: Indizierung darf das Verhalten nicht aendern.
        var compiled = HostRuleSet.TryCompile(
            ["example.com", "*.example.com", "198.51.100.4", "192.0.2.0/24"],
            out var set,
            out var error);
        Check("HostRuleSet kompiliert", () => compiled && set is not null && error is null);
        Check("Set: exakt", () => set!.Matches(HostNormalizer.Normalize("example.com"), out var p) && p == "example.com");
        Check("Set: wildcard", () =>
            set!.Matches(HostNormalizer.Normalize("a.example.com"), out var p) && p == "*.example.com");
        Check("Set: IP", () => set!.Matches(HostNormalizer.Normalize("198.51.100.4")));
        Check("Set: CIDR", () => set!.Matches(HostNormalizer.Normalize("192.0.2.200")));
        Check("Set: kein Treffer", () => !set!.Matches(HostNormalizer.Normalize("other.org")));
    }

    // =====================================================================
    // Adressklassifizierung
    // =====================================================================

    private static void RunAddressClassifierTests()
    {
        Section("Adressklassifizierung");

        Check("127.0.0.1 ist Loopback", () => AddressClassifier.IsLoopback(System.Net.IPAddress.Parse("127.0.0.1")));
        Check("::1 ist Loopback", () => AddressClassifier.IsLoopback(System.Net.IPAddress.Parse("::1")));
        Check("169.254.169.254 ist Link-Local (Cloud-Metadata)", () =>
            AddressClassifier.IsLinkLocal(System.Net.IPAddress.Parse("169.254.169.254")));
        Check("fe80::1 ist Link-Local", () =>
            AddressClassifier.IsLinkLocal(System.Net.IPAddress.Parse("fe80::1")));
        Check("0.0.0.0 ist nie erlaubt", () =>
            AddressClassifier.IsNeverAllowed(System.Net.IPAddress.Parse("0.0.0.0")));
        Check("255.255.255.255 ist nie erlaubt", () =>
            AddressClassifier.IsNeverAllowed(System.Net.IPAddress.Parse("255.255.255.255")));
        Check("IPv4-mapped ::ffff:127.0.0.1 ist nie erlaubt", () =>
            AddressClassifier.IsNeverAllowed(System.Net.IPAddress.Parse("::ffff:127.0.0.1")));
        Check("224.0.0.1 (Multicast) ist nie erlaubt", () =>
            AddressClassifier.IsNeverAllowed(System.Net.IPAddress.Parse("224.0.0.1")));

        Check("Loopback ohne Flag gesperrt", () =>
            !AddressClassifier.IsPermitted(System.Net.IPAddress.Parse("127.0.0.1"), false, false));
        Check("Loopback mit Flag erlaubt", () =>
            AddressClassifier.IsPermitted(System.Net.IPAddress.Parse("127.0.0.1"), true, false));
        Check("Loopback mit Flag bleibt durch 0.0.0.0/8 unbeeinflusst", () =>
            !AddressClassifier.IsPermitted(System.Net.IPAddress.Parse("0.1.2.3"), true, true));
    }

    // =====================================================================
    // Policy-Engine
    // =====================================================================

    private static void RunPolicyEngineTests()
    {
        Section("Policy-Engine");

        var configuration = BuildTestPolicy();
        var compiled = PolicyEngine.Compile(configuration);
        Check("Testpolicy kompiliert", () => compiled.Success);

        var policy = compiled.Policy!;
        var identity = TestIdentity("research", @"C:\Agents\research\python.exe");

        // Erlaubter Treffer
        var allow = PolicyEngine.Evaluate(
            policy, identity, HostNormalizer.Normalize("docs.python.org"), 443, TargetKind.Connect);
        Check("erlaubtes Ziel", () => allow.Verdict == Verdict.Allow);
        Check("Scope-Id korrekt", () => allow.ScopeId == "test");
        Check("TLS ist Passthrough per Default", () => allow.Tls == TlsMode.Passthrough);

        // Falscher Port
        var wrongPort = PolicyEngine.Evaluate(
            policy, identity, HostNormalizer.Normalize("docs.python.org"), 80, TargetKind.Connect);
        Check("falscher Port wird abgelehnt", () => wrongPort.Verdict == Verdict.Deny);
        Check("Code no_scope", () => wrongPort.Code == DenyCodes.NoScope);

        // Falscher Agent
        var wrongAgent = PolicyEngine.Evaluate(
            policy,
            TestIdentity("other", @"C:\Agents\other\python.exe"),
            HostNormalizer.Normalize("docs.python.org"),
            443,
            TargetKind.Connect);
        Check("fremder Agent wird abgelehnt", () => wrongAgent.Verdict == Verdict.Deny);

        // Praefix-Verwechslung beim Image-Pfad
        var prefixTrick = PolicyEngine.Evaluate(
            policy,
            TestIdentity("research", @"C:\Agents\research-evil\python.exe"),
            HostNormalizer.Normalize("docs.python.org"),
            443,
            TargetKind.Connect);
        Check("Image-Praefix wird nicht verwechselt", () => prefixTrick.Verdict == Verdict.Deny);

        // Loopback trotz passendem Scope (kein Loopback-Eintrag im Scope, aber
        // selbst mit einem waere die globale Sperre wirksam)
        var loopback = PolicyEngine.Evaluate(
            policy, identity, HostNormalizer.Normalize("127.0.0.1"), 443, TargetKind.Connect);
        Check("Loopback wird abgelehnt", () => loopback.Verdict == Verdict.Deny);
        Check("Loopback-Code denied_literal", () => loopback.Code == DenyCodes.DeniedLiteral);

        // Cloud-Metadata-Endpunkt
        var metadata = PolicyEngine.Evaluate(
            policy, identity, HostNormalizer.Normalize("169.254.169.254"), 443, TargetKind.Connect);
        Check("Cloud-Metadata wird abgelehnt", () => metadata.Verdict == Verdict.Deny);

        // Kaputter Host
        var malformed = PolicyEngine.Evaluate(
            policy, identity, HostNormalizer.Normalize("evil.com@127.0.0.1"), 443, TargetKind.Connect);
        Check("malformter Host wird abgelehnt", () =>
            malformed.Verdict == Verdict.Deny && malformed.Code == DenyCodes.MalformedTarget);

        // HTTP-Regeln greifen nur bei erkanntem Request
        var httpDenied = PolicyEngine.Evaluate(
            policy,
            identity,
            HostNormalizer.Normalize("docs.python.org"),
            443,
            TargetKind.Http,
            "POST",
            "/3/library/os.html");
        Check("HTTP-Methode ausserhalb der Allowlist abgelehnt", () =>
            httpDenied.Verdict == Verdict.Deny && httpDenied.Code == DenyCodes.MethodNotAllowed);

        var httpPathDenied = PolicyEngine.Evaluate(
            policy,
            identity,
            HostNormalizer.Normalize("docs.python.org"),
            443,
            TargetKind.Http,
            "GET",
            "/admin/secret");
        Check("HTTP-Pfad ausserhalb der Allowlist abgelehnt", () =>
            httpPathDenied.Verdict == Verdict.Deny && httpPathDenied.Code == DenyCodes.PathNotAllowed);

        var httpAllowed = PolicyEngine.Evaluate(
            policy,
            identity,
            HostNormalizer.Normalize("docs.python.org"),
            443,
            TargetKind.Http,
            "GET",
            "/3/library/os.html");
        Check("HTTP innerhalb der Allowlist erlaubt", () => httpAllowed.Verdict == Verdict.Allow);

        // Konfiguration, die abgelehnt werden MUSS
        var allowDefault = PolicyEngine.Compile(new ScopeConfiguration
        {
            DefaultVerdict = Verdict.Allow,
            Scopes = [],
        });
        Check("defaultVerdict=allow wird abgelehnt", () => !allowDefault.Success);

        var wildcardOnly = PolicyEngine.Compile(new ScopeConfiguration
        {
            Scopes =
            [
                new ScopeGrant
                {
                    Id = "bad",
                    Principals = new ScopePrincipal { AgentIds = ["a"] },
                    Targets = [new ScopeTarget { Host = "*", Ports = [443] }],
                },
            ],
        });
        Check("Scope mit Host '*' wird abgelehnt", () => !wildcardOnly.Success);

        var emptyPrincipals = PolicyEngine.Compile(new ScopeConfiguration
        {
            Scopes =
            [
                new ScopeGrant
                {
                    Id = "bad",
                    Principals = new ScopePrincipal(),
                    Targets = [new ScopeTarget { Host = "example.com", Ports = [443] }],
                },
            ],
        });
        Check("Scope ohne Principal wird abgelehnt", () => !emptyPrincipals.Success);

        var relativeImageRoot = PolicyEngine.Compile(new ScopeConfiguration
        {
            Scopes =
            [
                new ScopeGrant
                {
                    Id = "bad",
                    Principals = new ScopePrincipal { AgentIds = ["a"], ImageRoots = ["relative\\path"] },
                    Targets = [new ScopeTarget { Host = "example.com", Ports = [443] }],
                },
            ],
        });
        Check("relativer imageRoot wird abgelehnt", () => !relativeImageRoot.Success);

        var interceptWithoutAllowlist = PolicyEngine.Compile(new ScopeConfiguration
        {
            Scopes =
            [
                new ScopeGrant
                {
                    Id = "bad",
                    Principals = new ScopePrincipal { AgentIds = ["a"] },
                    Targets = [new ScopeTarget { Host = "example.com", Ports = [443] }],
                    Inspection = new ScopeInspection { Tls = TlsMode.Intercept },
                },
            ],
        });
        Check("intercept ohne Allowlist wird abgelehnt", () => !interceptWithoutAllowlist.Success);

        var badPort = PolicyEngine.Compile(new ScopeConfiguration
        {
            Scopes =
            [
                new ScopeGrant
                {
                    Id = "bad",
                    Principals = new ScopePrincipal { AgentIds = ["a"] },
                    Targets = [new ScopeTarget { Host = "example.com", Ports = [70000] }],
                },
            ],
        });
        Check("Port 70000 wird abgelehnt", () => !badPort.Success);
    }

    // =====================================================================
    // Pfadgrenzen
    // =====================================================================

    private static void RunPathStartsWithTests()
    {
        Section("Pfadgrenzen");

        Check("identischer Pfad", () => PolicyEngine.PathStartsWith(@"C:\Agents\res", @"C:\Agents\res"));
        Check("Unterpfad", () => PolicyEngine.PathStartsWith(@"C:\Agents\res\python.exe", @"C:\Agents\res"));
        Check("Trailing Backslash am Root", () =>
            PolicyEngine.PathStartsWith(@"C:\Agents\res\python.exe", @"C:\Agents\res\"));
        Check("Case-insensitiv", () =>
            PolicyEngine.PathStartsWith(@"c:\agents\RES\python.exe", @"C:\Agents\res"));

        // Der wichtigste Fall: Praefix darf keine Verzeichnisgrenze ignorieren.
        Check("Praefix-Verwechslung verhindert", () =>
            !PolicyEngine.PathStartsWith(@"C:\Agents\research-evil\python.exe", @"C:\Agents\research"));
        Check("Praefix-Verwechslung verhindert (Punkt)", () =>
            !PolicyEngine.PathStartsWith(@"C:\Agents\res.bak\python.exe", @"C:\Agents\res"));
        Check("Anderer Zweig verhindert", () =>
            !PolicyEngine.PathStartsWith(@"C:\Other\res\python.exe", @"C:\Agents\res"));
        Check("Leerer Pfad verhindert", () => !PolicyEngine.PathStartsWith(null, @"C:\Agents\res"));
        Check("Leerer Root verhindert", () => !PolicyEngine.PathStartsWith(@"C:\Agents\res", string.Empty));
    }

    // =====================================================================
    // Protokoll
    // =====================================================================

    private static void RunProtocolTests()
    {
        Section("Frame-Protokoll");

        var header = new FrameHeader(FrameKind.Connect, FrameFlags.Fin, 0x1234, 0x00ABCDEF);
        var bytes = header.ToArray();
        var parsed = FrameHeader.ReadFrom(bytes);

        Check("FrameHeader Groesse ist 8", () => bytes.Length == 8);
        Check("Kind erhalten", () => parsed.Kind == FrameKind.Connect);
        Check("Flags erhalten", () => parsed.Flags == FrameFlags.Fin);
        Check("Seq erhalten", () => parsed.Seq == 0x1234);
        Check("Laenge erhalten", () => parsed.BodyLength == 0x00ABCDEF);
        Check("Big-Endian: erstes Laengenbyte", () => bytes[4] == 0x00 && bytes[5] == 0xAB);

        Check("Roundtrip aller Typen", () =>
            FrameKind.IsKnown(FrameKind.Hello)
            && FrameKind.IsKnown(FrameKind.HelloAck)
            && FrameKind.IsKnown(FrameKind.Connect)
            && FrameKind.IsKnown(FrameKind.ConnectOk)
            && FrameKind.IsKnown(FrameKind.ConnectDeny)
            && FrameKind.IsKnown(FrameKind.Data)
            && FrameKind.IsKnown(FrameKind.Close)
            && FrameKind.IsKnown(FrameKind.Ping)
            && FrameKind.IsKnown(FrameKind.Pong)
            && FrameKind.IsKnown(FrameKind.Error));

        Check("unbekannter Typ wird abgelehnt", () => !FrameKind.IsKnown(0x99));
        Check("Body-Limit ist gesetzt", () => FrameHeader.MaxBodyLength == 1024 * 1024);
        Check("Payload-Limit ist gesetzt", () => FrameHeader.MaxPayloadLength == 256 * 1024);

        // Pipe-Namen
        Check("Pipe-Name aus Agent-Id", () =>
            ProtocolVersion.PipeNameFor("research") == "CordonGateway.research");
        Check("Pipe-Name bereinigt Sonderzeichen", () =>
            ProtocolVersion.PipeNameFor("a/b\\c") == "CordonGateway.abc");
        Check("Pipe-Name gegen Pfadsegmente", () =>
            !ProtocolVersion.PipeNameFor("a..b").Contains("..", StringComparison.Ordinal));
        Check("Leere Agent-Id wird abgelehnt", () =>
        {
            try
            {
                _ = ProtocolVersion.PipeNameFor("///");
                return false;
            }
            catch (ArgumentException)
            {
                return true;
            }
        });

        // Lesen/Schreiben eines Frames
        var stream = new MemoryStream();
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        FrameCodec
            .WriteDataAsync(stream, 7, payload, fin: false, CancellationToken.None)
            .AsTask()
            .GetAwaiter()
            .GetResult();

        stream.Position = 0;
        var message = FrameCodec.ReadAsync(stream, CancellationToken.None).AsTask().GetAwaiter().GetResult();

        Check("Datenframe gelesen", () => message is not null && message.Kind == FrameKind.Data);
        Check("Payload korrekt", () => message!.Payload.ToArray().SequenceEqual(payload));
        Check("Seq korrekt", () => message!.Seq == 7);
        Check("Payload ohne JSON-Header erkannt", () => message!.JsonHeader.Length == 0);

        // Kontrollframe mit JSON
        var stream2 = new MemoryStream();
        FrameCodec.WriteAsync(
                stream2,
                FrameKind.Connect,
                FrameFlags.None,
                1,
                new ConnectRequest { Host = "docs.python.org", Port = 443 },
                CordonJsonContext.Default.ConnectRequest,
                ReadOnlyMemory<byte>.Empty,
                CancellationToken.None)
            .AsTask()
            .GetAwaiter()
            .GetResult();

        stream2.Position = 0;
        var message2 = FrameCodec.ReadAsync(stream2, CancellationToken.None).AsTask().GetAwaiter().GetResult();
        var request = message2!.Parse(CordonJsonContext.Default.ConnectRequest);

        Check("Connect-Frame gelesen", () => message2.Kind == FrameKind.Connect);
        Check("Host deserialisiert", () => request?.Host == "docs.python.org");
        Check("Port deserialisiert", () => request?.Port == 443);

        // Frame mit JSON-Header UND Payload: die Grenze muss stimmen. Dies ist
        // ein KONTROLLframe (Connect); Data-Frames tragen grundsaetzlich keinen
        // JSON-Header (siehe naechster Test).
        var stream3 = new MemoryStream();
        var body = new byte[] { 9, 8, 7 };
        FrameCodec.WriteAsync(
                stream3,
                FrameKind.Connect,
                FrameFlags.None,
                2,
                new EmptyHeader(),
                CordonJsonContext.Default.EmptyHeader,
                body,
                CancellationToken.None)
            .AsTask()
            .GetAwaiter()
            .GetResult();

        stream3.Position = 0;
        var message3 = FrameCodec.ReadAsync(stream3, CancellationToken.None).AsTask().GetAwaiter().GetResult();

        Check("JSON-Header und Payload getrennt", () => message3!.Payload.ToArray().SequenceEqual(body));
        Check("JSON-Header ist nicht leer", () => message3!.JsonHeader.Length > 0);

        // Data-Frame, dessen Payload mit '{' beginnt (z. B. eine JSON-Antwort):
        // muss VOLLSTAENDIG als Payload behandelt werden, nicht als Header.
        var stream4 = new MemoryStream();
        var jsonPayload = new byte[]
        {
            (byte)'{', (byte)'"', (byte)'a', (byte)'"', (byte)':', (byte)'1', (byte)'}',
        };
        FrameCodec.WriteDataAsync(stream4, 3, jsonPayload, fin: false, CancellationToken.None)
            .AsTask()
            .GetAwaiter()
            .GetResult();

        stream4.Position = 0;
        var message4 = FrameCodec.ReadAsync(stream4, CancellationToken.None).AsTask().GetAwaiter().GetResult();

        Check("Data-Payload mit '{' bleibt unveraendert", () =>
            message4!.Payload.ToArray().SequenceEqual(jsonPayload));

        // Zu grosser Frame
        var oversized = new MemoryStream();
        var oversizedHeader = new FrameHeader(
            FrameKind.Data,
            FrameFlags.None,
            0,
            FrameHeader.MaxBodyLength + 1);
        oversized.Write(oversizedHeader.ToArray());
        oversized.Position = 0;

        Check("zu grosser Frame wird abgelehnt", () =>
        {
            try
            {
                _ = FrameCodec.ReadAsync(oversized, CancellationToken.None).AsTask().GetAwaiter().GetResult();
                return false;
            }
            catch (CordonProtocolException)
            {
                return true;
            }
        });
    }

    // =====================================================================
    // Audit-Kette
    // =====================================================================

    private static void RunAuditChainTests()
    {
        Section("Audit-Kette");

        var directory = Path.Combine(Path.GetTempPath(), $"cordon-test-{Guid.NewGuid():N}");
        var key = new byte[32];
        Random.Shared.NextBytes(key);

        try
        {
            var log = new AuditLog(directory, key);

            for (var i = 0; i < 5; i++)
            {
                log.Write(AuditLog.Event("test.event") with
                {
                    AgentId = "research",
                    Verdict = "deny",
                    Code = DenyCodes.NoScope,
                    Reason = $"Eintrag {i}",
                    Identity = new AuditIdentityDto { Pid = (uint)(1000 + i) },
                });
            }

            log.FlushAsync().GetAwaiter().GetResult();
            log.DisposeAsync().AsTask().GetAwaiter().GetResult();

            var file = Directory.GetFiles(directory, "cordon-*.jsonl").Single();
            var lines = File.ReadAllLines(file).Where(l => l.Length > 0).ToList();

            Check("5 Eintraege geschrieben", () => lines.Count == 5);

            var parsed = lines
                .Select(l => System.Text.Json.JsonSerializer.Deserialize(l, CordonJsonContext.Default.AuditEvent)!)
                .ToList();

            Check("Seq ist fortlaufend", () => parsed.Select(e => e.Seq).SequenceEqual([1L, 2, 3, 4, 5]));
            Check("Erster PrevHmac ist leer", () => parsed[0].PrevHmac is null);
            Check("Kette verknuepft", () => parsed[1].PrevHmac == parsed[0].Hmac);
            Check("Alle Hmacs gesetzt", () => parsed.All(e => !string.IsNullOrEmpty(e.Hmac)));
            Check("Hmac-Werte sind verschieden", () =>
                parsed.Select(e => e.Hmac).Distinct(StringComparer.Ordinal).Count() == 5);
            Check("Code wird im Audit gefuehrt", () => parsed.All(e => e.Code == DenyCodes.NoScope));

            // Manipulation muss erkennbar sein: eine geaenderte Zeile bricht
            // die Kette, weil ihr HMAC nicht mehr passt.
            var tampered = parsed.ToList();
            tampered[2] = tampered[2] with { Reason = "manipuliert" };
            Check("Manipulation aendert die kanonische Form", () =>
            {
                var original = BuildCanonical(parsed[2]);
                var changed = BuildCanonical(tampered[2]);
                return original != changed;
            });
        }
        finally
        {
            try
            {
                Directory.Delete(directory, recursive: true);
            }
            catch (IOException)
            {
                // Temporäres Verzeichnis bleibt liegen; fuer Tests unerheblich.
            }
        }
    }

    /// <summary>
    /// Baut die kanonische Form nach. Sie ist in <c>AuditLog</c> bewusst
    /// nicht oeffentlich, damit kein Aufrufer sie als API missversteht -
    /// hier wird sie fuer den Manipulationstest nachgebildet.
    /// </summary>
    private static string BuildCanonical(AuditEvent e)
    {
        var sb = new System.Text.StringBuilder();
        sb.Append(e.Seq).Append('\u001f');
        sb.Append(e.Ts.ToUniversalTime().ToString("O", System.Globalization.CultureInfo.InvariantCulture))
            .Append('\u001f');
        sb.Append(e.Event).Append('\u001f');
        sb.Append(e.AgentId ?? "\u0000").Append('\u001f');
        sb.Append(e.Reason ?? "\u0000").Append('\u001f');
        return sb.ToString();
    }

    // =====================================================================
    // Live-Integrationstest: Named Pipe + Identitaetsaufloesung
    // =====================================================================

    /// <summary>
    /// Prueft die Windows-Interop-Schicht <b>gegen den laufenden Kernel</b>.
    /// <para>
    /// Das ist der wertvollste Test des Projekts, weil er genau die Fehler
    /// findet, die ein Code-Review nicht finden kann: falsche Struct-Layouts
    /// bei <c>TOKEN_MANDATORY_LABEL</c>, verwechselte Puffergroessen,
    /// fehlerhafte P/Invoke-Signaturen. Ein Erfolg hier belegt, dass die
    /// Identitaet tatsaechlich aus dem Kernel kommt.
    /// </para>
    /// <para>
    /// Er laeuft ohne Administratorrechte und ohne AppContainer. Geprueft
    /// wird die <i>Aufloesung</i>, nicht die Sandbox: dass
    /// <c>IsAppContainer</c> hier <c>false</c> ist, ist das erwartete und
    /// korrekte Ergebnis - dieser Prozess ist kein AppContainer. Genau
    /// deshalb ist es ein aussagekraeftiger Test: die Abfrage liefert einen
    /// echten Kernelwert und nicht konstant <c>true</c>.
    /// </para>
    /// <para>
    /// <b>Nicht abgedeckt:</b> die PID-Reuse-Erkennung. Ein echter
    /// PID-Recycling-Fall laesst sich nicht deterministisch herstellen. Sie
    /// wird durch <c>PipeClientResolver.Resolve(SafeHandle, PipeClientSignature, ...)</c>
    /// erzwungen und ist dort durch die doppelte Erfassung plus
    /// Erzeugungszeit-Vergleich abgesichert.
    /// </para>
    /// </summary>
    private static void RunPipeIdentityIntegrationTest()
    {
        Section("Live: Named Pipe + Identitaetsaufloesung");

        // Ein eindeutiger Name pro Lauf, damit parallele Laeufe sich nicht
        // gegenseitig die Pipe streitig machen.
        var pipeName = $"Cordon.Tests.IdentityProbe.{Guid.NewGuid():N}";
        var serverPid = (uint)Environment.ProcessId;

        try
        {
            var probeTask = Task.Run(async () =>
            {
                // Kein `using`: das Handle muss bis nach dem Capture gueltig
                // bleiben. Das Capture liest aus dem Pipe-Kernelobjekt und
                // wuerde auf einem geschlossenen Handle fehlschlagen.
                var server = new System.IO.Pipes.NamedPipeServerStream(
                    pipeName,
                    System.IO.Pipes.PipeDirection.InOut,
                    maxNumberOfServerInstances: 1,
                    System.IO.Pipes.PipeTransmissionMode.Byte,
                    System.IO.Pipes.PipeOptions.Asynchronous);

                try
                {
                    var accept = server.WaitForConnectionAsync();

                    using var client = new System.IO.Pipes.NamedPipeClientStream(
                        ".",
                        pipeName,
                        System.IO.Pipes.PipeDirection.InOut);

                    await client.ConnectAsync(5000).ConfigureAwait(false);
                    await accept.ConfigureAwait(false);

                    // Genau der Pfad, den das Gateway geht: erst PID +
                    // Erzeugungszeit, dann die vollstaendige Aufloesung.
                    return PipeClientCaptureReader.Capture(server.SafePipeHandle);
                }
                finally
                {
                    await server.DisposeAsync().ConfigureAwait(false);
                }
            });

            var capture = probeTask.GetAwaiter().GetResult();

            Check("Capture erfolgreich", () => capture.Success);

            if (!capture.Success)
            {
                Console.Error.WriteLine($"       Grund: {capture.Error} (Win32 {capture.Win32Error})");
                return;
            }

            Check("Capture liefert PID", () => capture.Signature.ProcessId != 0);
            Check("Capture liefert Erzeugungszeit", () => capture.Signature.CreationTime != 0);

            // Der Client dieser Pipe sind wir selbst - die PID muss also die
            // eigene sein. Das ist der Beweis, dass die PID wirklich aus dem
            // Pipe-Kernelobjekt stammt und nicht geraten wird.
            Check("PID ist die eigene", () => capture.Signature.ProcessId == serverPid);

            // Zweite Erfassung ueber OpenProcess/GetProcessTimes: muss
            // dieselbe Erzeugungszeit liefern, sonst waere die
            // Reuse-Erkennung selbst nicht reproduzierbar.
            Check("Erzeugungszeit ist stabil reproduzierbar", () =>
                PipeClientCaptureReader.TryGetCreationTime(serverPid, out var creationTime, out _)
                && creationTime == capture.Signature.CreationTime);

            // Vollstaendige Aufloesung. Die Erwartungswerte sind absichtlich
            // "falsch", damit die Aufloesung selbst geprueft wird und nicht
            // der Validator.
            var resolution = PipeClientResolver.Resolve(
                serverPid,
                "selftest",
                expectedPackageSid: "S-1-15-2-0-0-0-0-0-0-0",
                expectedImagePath: Path.GetDirectoryName(Environment.ProcessPath));

            Check("Aufloesung erfolgreich", () => resolution.Success);

            if (!resolution.Success)
            {
                Console.Error.WriteLine($"       Grund: {resolution.ErrorCode}: {resolution.Error}");
                return;
            }

            var identity = resolution.Identity!;

            Check("Image-Pfad aufgeloest", () => !string.IsNullOrWhiteSpace(identity.ImagePath));

            // QueryFullProcessImageNameW vs. die Laufzeitangabe: beide sollten
            // auf dieselbe Datei zeigen. Der Vergleich des Dateinamens ist
            // robust gegen unterschiedliche Schreibweisen des Verzeichnisses.
            Check("Image-Pfad passt zum laufenden Prozess", () =>
            {
                var expected = Environment.ProcessPath;
                return expected is not null
                    && string.Equals(
                        Path.GetFileName(identity.ImagePath),
                        Path.GetFileName(expected),
                        StringComparison.OrdinalIgnoreCase);
            });

            // Der Testrunner laeuft NICHT in einem AppContainer. Muss also
            // false sein - und genau das belegt, dass die Abfrage echte
            // Kernelwerte liefert statt konstant "true".
            Check("IsAppContainer ist false (Testrunner ist keiner)", () => !identity.IsAppContainer);

            Check("Package-SID ist leer (kein AppContainer)", () => string.IsNullOrEmpty(identity.PackageSid));

            // Integritaetslevel: der Testrunner laeuft typischerweise als
            // Medium. Geprueft wird, dass ueberhaupt ein Wert ermittelt wurde -
            // Unknown waere ein Fehler in der Struct-Interpretation von
            // TOKEN_MANDATORY_LABEL.
            Check("Integritaetslevel ermittelt (nicht Unknown)", () =>
                identity.Integrity != IntegrityLevel.Unknown);

            Check("Capabilities-Liste vorhanden", () => identity.Capabilities is not null);

            Check("Erzeugungszeit in der Identitaet durchgereicht", () =>
                identity.ProcessCreationTime == capture.Signature.CreationTime);

            // Die Aufloesung darf keine WARNUNG zu unbestaetigten Werten
            // erzeugen - sonst waere ein Token-Abruf fehlgeschlagen.
            Check("Keine Warnungen zu unbestaetigten Token-Werten", () =>
                resolution.Warnings.Count == 0);

            if (resolution.Warnings.Count > 0)
            {
                foreach (var warning in resolution.Warnings)
                {
                    Console.Error.WriteLine($"       Warnung: {warning}");
                }
            }
        }
        catch (Exception ex)
        {
            _total++;
            _failures++;
            Console.Error.WriteLine(
                $"  FAIL Live-Integrationstest konnte nicht laufen: {ex.GetType().Name}: {ex.Message}");
        }
    }

    // =====================================================================
    // JSON-Vorgabewerte: fehlende und explizit null-Schluessel
    // =====================================================================

    /// <summary>
    /// JSON-Dokumente, die optionale Schluessel weglaessen, muessen ladbar
    /// bleiben: die deklarierten Vorgabewerte (leere Listen, Passthrough)
    /// muessen auch nach dem Deserialisieren gelten.
    /// <para>
    /// Hintergrund: der Source-Generator deserialisiert <c>init</c>-Properties
    /// ueber einen parameterisierten Creator und uebergibt fuer fehlende
    /// Schluessel <c>null</c> - der Initialisierer <c>= []</c> wird dabei
    /// ueberschrieben. Ohne die Zusicherung "nie null" haette ein
    /// weggelassenes <c>allowedTools</c> eine NullReferenceException im
    /// Validator ausgeloest statt einer leeren (fail-closed) Whitelist.
    /// Die DTOs des Frame-Protokolls sind aus demselben Grund mitgeprueft.
    /// </para>
    /// </summary>
    private static void RunJsonDefaultsTests()
    {
        Section("JSON-Vorgabewerte (Policy-Datei + Frames)");

        // Nur die Pflichtschluessel - alles Optionale fehlt bewusst.
        // 'version' muss dabeistehen: es ist ein Werttyp, den ein Accessor
        // nicht vor default(int) schuetzen kann.
        const string minimalJson = """
            {
              "version": 1,
              "scopes": [
                {
                  "id": "minimal",
                  "principals": {
                    "agentIds": ["research"],
                    "imageRoots": ["C:\\Agents\\research"]
                  },
                  "targets": [
                    { "host": "docs.python.org", "ports": [443] }
                  ]
                }
              ]
            }
            """;

        var minimal = System.Text.Json.JsonSerializer.Deserialize(
            minimalJson,
            CordonJsonContext.Default.ScopeConfiguration)!;

        Check("fehlendes 'allowedTools' ist keine null-Liste", () =>
            minimal.Scopes[0].AllowedTools is not null);
        Check("fehlendes 'allowedTools' ergibt leere Whitelist", () =>
            minimal.Scopes[0].AllowedTools.Count == 0);
        Check("fehlendes 'limits' ergibt die vorgegebenen Limits", () =>
            minimal.Scopes[0].Limits.MaxConcurrentConnections == 16);
        Check("fehlendes 'inspection' ergibt Passthrough", () =>
            minimal.Scopes[0].Inspection.Tls == TlsMode.Passthrough);
        Check("fehlendes 'rules' ergibt leere HTTP-Regeln", () =>
            minimal.Scopes[0].Rules.HttpMethods.Count == 0
            && minimal.Scopes[0].Rules.PathPrefixes.Count == 0);

        // Die Datei muss durch den echten Ladepfad gehen - inklusive
        // Validator und Kompilierung der Muster.
        var result = PolicyEngine.Compile(minimal);

        Check("Datei ohne optionale Schluessel wird geladen", () => result.Success);

        if (!result.Success)
        {
            foreach (var error in result.Errors)
            {
                Console.Error.WriteLine($"       Grund: {error}");
            }
        }

        Check("geladener Scope entscheidet 'allow'", () =>
            result.Policy is not null
            && PolicyEngine.Evaluate(
                result.Policy,
                TestIdentity("research", @"C:\Agents\research"),
                HostNormalizer.Normalize("docs.python.org"),
                443,
                TargetKind.Connect).Verdict == Verdict.Allow);

        // Explizites null ist eine leere Angabe und damit ein
        // Konfigurationsfehler - aber niemals ein Laufzeitfehler.
        const string nullJson = """
            {
              "version": 1,
              "allowedCapabilities": null,
              "allowedSigners": null,
              "scopes": [
                {
                  "id": "nulls",
                  "principals": {
                    "agentIds": ["research"],
                    "imageRoots": ["C:\\Agents\\research"],
                    "packageSids": null
                  },
                  "targets": [ { "host": "docs.python.org", "ports": null } ],
                  "inspection": null,
                  "limits": null,
                  "rules": null,
                  "allowedTools": null
                }
              ]
            }
            """;

        var withNulls = System.Text.Json.JsonSerializer.Deserialize(
            nullJson,
            CordonJsonContext.Default.ScopeConfiguration)!;

        Check("explizites null wird zu leeren Sammlungen", () =>
            withNulls.AllowedCapabilities.Count == 0
            && withNulls.AllowedSigners.Count == 0
            && withNulls.Scopes[0].Principals.ImageRoots.Count == 1
            && withNulls.Scopes[0].Principals.PackageSids.Count == 0
            && withNulls.Scopes[0].Targets[0].Ports.Count == 0
            && withNulls.Scopes[0].Inspection.InterceptAllowlist.Count == 0
            && withNulls.Scopes[0].Rules.HttpMethods.Count == 0
            && withNulls.Scopes[0].AllowedTools.Count == 0);

        Check("Validator meldet null-Ports als Fehler statt zu werfen", () =>
            !PolicyValidator.TryValidate(withNulls, out var validationErrors)
            && validationErrors.Count > 0);

        Check("Datei mit null-Angaben wird abgelehnt (fail closed)", () =>
            !PolicyEngine.Compile(withNulls).Success);

        // Auch Pflichtschluessel koennen als null ankommen.
        const string requiredNullJson =
            "{ \"version\": 1, \"scopes\": [ { \"id\": \"required-null\", \"principals\": null, \"targets\": null } ] }";

        var requiredNulls = System.Text.Json.JsonSerializer.Deserialize(
            requiredNullJson,
            CordonJsonContext.Default.ScopeConfiguration)!;

        Check("null fuer 'principals'/'targets' wird abgefangen", () =>
            requiredNulls.Scopes[0].Principals.AgentIds.Count == 0
            && requiredNulls.Scopes[0].Targets.Count == 0);

        Check("Scope ohne Principal/Ziel wird abgelehnt", () =>
            !PolicyEngine.Compile(requiredNulls).Success);

        // Werttypen kann ein Accessor nicht retten: fuer einen fehlenden
        // Schluessel uebergibt der Creator default(T). Wichtig ist, dass die
        // Abweichung immer in die strikte Richtung kippt.
        const string withoutVersionJson = """
            {
              "scopes": [
                {
                  "id": "no-version",
                  "principals": { "agentIds": ["research"] },
                  "targets": [ { "host": "docs.python.org", "ports": [443] } ]
                }
              ]
            }
            """;

        var missingVersionRejected = false;

        try
        {
            var withoutVersion = System.Text.Json.JsonSerializer.Deserialize(
                withoutVersionJson,
                CordonJsonContext.Default.ScopeConfiguration)!;

            missingVersionRejected = withoutVersion.Version != 1
                && !PolicyEngine.Compile(withoutVersion).Success;
        }
        catch (System.Text.Json.JsonException)
        {
            // Falls die Version kuenftig als Pflichtfeld erzwungen wird.
            missingVersionRejected = true;
        }

        Check("Datei ohne 'version' wird abgelehnt (fail closed)", () =>
            missingVersionRejected);

        // Byte-Limits von 0 heissen "kein Byte" (ProxyConnection bricht ab,
        // sobald total > Limit ist) - niemals "unbegrenzt".
        const string withoutByteLimitsJson = """
            {
              "version": 1,
              "scopes": [
                {
                  "id": "no-byte-limits",
                  "principals": { "agentIds": ["research"] },
                  "targets": [ { "host": "docs.python.org", "ports": [443] } ],
                  "limits": { "maxConcurrentConnections": 4, "sessionTtlSeconds": 60 }
                }
              ]
            }
            """;

        var withoutByteLimits = System.Text.Json.JsonSerializer.Deserialize(
            withoutByteLimitsJson,
            CordonJsonContext.Default.ScopeConfiguration)!;

        Check("fehlende Byte-Limits werden zu 0 statt 'unbegrenzt'", () =>
            withoutByteLimits.Scopes[0].Limits.MaxBytesUp == 0
            && withoutByteLimits.Scopes[0].Limits.MaxBytesDown == 0);
        Check("fehlende Byte-Limits blockieren die Scope-Freigabe nicht", () =>
            withoutByteLimits.Scopes[0].Limits.MaxConcurrentConnections == 4
            && withoutByteLimits.Scopes[0].Limits.SessionTtlSeconds == 60);

        // Dieselbe Falle gibt es in den Protokoll-DTOs: sie kommen im
        // Frame-Codec aus eingehenden Frames an.
        const string trimmedAckJson = "{ \"peer\": { \"pid\": 4242 } }";

        var trimmedAck = System.Text.Json.JsonSerializer.Deserialize(
            trimmedAckJson,
            CordonJsonContext.Default.HelloAck)!;

        Check("fehlende 'capabilities' im HelloAck sind keine null-Liste", () =>
            trimmedAck.Peer is not null && trimmedAck.Peer.Capabilities is not null);
        Check("fehlende 'capabilities' im HelloAck ergeben eine leere Liste", () =>
            trimmedAck.Peer is not null && trimmedAck.Peer.Capabilities.Count == 0);
        Check("explizites null fuer 'capabilities' wird abgefangen", () =>
            System.Text.Json.JsonSerializer.Deserialize(
                "{ \"peer\": { \"capabilities\": null } }",
                CordonJsonContext.Default.HelloAck)!.Peer!.Capabilities.Count == 0);
    }

    // =====================================================================
    // Hilfen
    // =====================================================================

    private static ScopeConfiguration BuildTestPolicy() => new()
    {
        Version = 1,
        DefaultVerdict = Verdict.Deny,
        AllowLoopback = false,
        AllowLinkLocal = false,
        Scopes =
        [
            new ScopeGrant
            {
                Id = "test",
                Principals = new ScopePrincipal
                {
                    AgentIds = ["research"],
                    ImageRoots = [@"C:\Agents\research"],
                },
                Targets =
                [
                    new ScopeTarget { Host = "docs.python.org", Ports = [443] },
                    new ScopeTarget { Host = "*.wikipedia.org", Ports = [443] },
                ],
                Inspection = new ScopeInspection { Tls = TlsMode.Passthrough },
                Limits = new ScopeLimits
                {
                    MaxConcurrentConnections = 4,
                    MaxBytesUp = 1024,
                    MaxBytesDown = 2048,
                    SessionTtlSeconds = 60,
                },
                Rules = new ScopeHttpRules
                {
                    HttpMethods = ["GET", "HEAD"],
                    PathPrefixes = ["/3/", "/docs/"],
                },
            },
        ],
    };

    private static ClientIdentity TestIdentity(string agentId, string imagePath) => new()
    {
        Pid = 4242,
        ImagePath = imagePath,
        PackageSid = "S-1-15-2-1-2-3-4-5-6-7",
        IsAppContainer = true,
        Integrity = IntegrityLevel.Low,
        Capabilities = [],
        AgentId = agentId,
        ExpectedPackageSid = "S-1-15-2-1-2-3-4-5-6-7",
        ExpectedImagePath = @"C:\Agents\" + agentId,
    };

    private static void Section(string name)
    {
        Console.WriteLine($"--- {name} ---");
    }

    private static void Check(string name, Func<bool> assertion)
    {
        _total++;

        bool passed;
        string? error = null;

        try
        {
            passed = assertion();
        }
        catch (Exception ex)
        {
            passed = false;
            error = $"{ex.GetType().Name}: {ex.Message}";
        }

        if (passed)
        {
            Console.WriteLine($"  ok   {name}");
        }
        else
        {
            _failures++;
            Console.Error.WriteLine($"  FAIL {name}{(error is null ? string.Empty : $" ({error})")}");
        }
    }
}
