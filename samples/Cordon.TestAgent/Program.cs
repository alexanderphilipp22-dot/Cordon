using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using Cordon.AgentSdk;

namespace Cordon.TestAgent;

/// <summary>
/// Red-Team-Harness zum Beweis der OS-Grenze.
/// <para>
/// Der Agent verhaelt sich wie ein <b>kompromittierter</b> Agent: er
/// versucht, direkt ins Netz zu gehen, DNS zu benutzen und rohe Sockets zu
/// oeffnen. Jeder dieser Versuche <b>muss</b> vom Betriebssystem scheitern.
/// Wenn einer gelingt, ist die Grenze nicht wirksam - und das ist ein
/// Befund, kein Testfehler.
/// </para>
/// </summary>
internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        Console.WriteLine("Cordon.TestAgent - Nachweis der Isolationsgrenze");
        Console.WriteLine($"  PID      : {Environment.ProcessId}");
        Console.WriteLine($"  Prozess  : {Environment.ProcessPath}");
        Console.WriteLine();

        var options = ParseOptions(args);

        var attemptExit = 0;

        // ------------------------------------------------------------------
        // 1. Direkte Netzwerkversuche - MUESSEN scheitern
        // ------------------------------------------------------------------
        Console.WriteLine("=== 1. Direkte Netzwerkversuche (muessen scheitern) ===");
        var directResults = await ProveDirectNetworkBlockedAsync().ConfigureAwait(false);
        ReportProbes(directResults, ref attemptExit);

        // ------------------------------------------------------------------
        // 2. DNS - MUSS scheitern
        // ------------------------------------------------------------------
        Console.WriteLine();
        Console.WriteLine("=== 2. Namensauflösung (muss scheitern) ===");
        var dnsResult = await ProveDnsBlockedAsync().ConfigureAwait(false);
        ReportProbes([dnsResult], ref attemptExit);

        // ------------------------------------------------------------------
        // 3. Gateway-Weg - MUSS funktionieren
        // ------------------------------------------------------------------
        Console.WriteLine();
        Console.WriteLine("=== 3. Zugriff ueber das Cordon-Gateway ===");
        var gatewayExit = await ProbeGatewayAsync(options).ConfigureAwait(false);

        Console.WriteLine();
        Console.WriteLine("=== Ergebnis ===");
        Console.WriteLine(attemptExit == 0
            ? "Die OS-Grenze haelt: kein direkter Netzwerkzugriff moeglich."
            : "BEFUND: Mindestens ein direkter Netzwerkzugriff war moeglich. Die Grenze haelt NICHT.");

        // Ein erfolgreicher Direktzugriff ist der schwerere Befund und
        // bestimmt den Exitcode.
        return attemptExit != 0 ? 3 : gatewayExit;
    }

    private static async Task<List<ProbeResult>> ProveDirectNetworkBlockedAsync()
    {
        var results = new List<ProbeResult>();

        // Rohes Socket erzeugen.
        results.Add(Probe("socket(AF_INET, SOCK_STREAM)", () =>
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            return "Socket erzeugt - das allein ist noch kein Netzzugriff.";
        }));

        // Verbindung zu einer oeffentlichen Adresse. Ein IP-Literal wird
        // verwendet, damit kein DNS-Erfolg noetig ist.
        results.Add(await ProbeAsync("connect(1.1.1.1:443)", async () =>
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await socket.ConnectAsync(new IPEndPoint(IPAddress.Parse("1.1.1.1"), 443), timeout.Token)
                .ConfigureAwait(false);
            return "VERBUNDEN - die Grenze haelt NICHT.";
        }).ConfigureAwait(false));

        // UDP: der Pfad fuer DNS-Tunneling.
        results.Add(await ProbeAsync("sendto(8.8.8.8:53, UDP)", async () =>
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            await socket.SendToAsync(
                    new byte[32],
                    SocketFlags.None,
                    new IPEndPoint(IPAddress.Parse("8.8.8.8"), 53))
                .ConfigureAwait(false);
            return "UDP gesendet - die Grenze haelt NICHT.";
        }).ConfigureAwait(false));

        // IPv6, um zu pruefen, dass die Grenze nicht nur IPv4 abdeckt.
        results.Add(await ProbeAsync("connect([2606:4700:4700::1111]:443)", async () =>
        {
            using var socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await socket.ConnectAsync(
                    new IPEndPoint(IPAddress.Parse("2606:4700:4700::1111"), 443),
                    timeout.Token)
                .ConfigureAwait(false);
            return "VERBUNDEN - die Grenze haelt NICHT.";
        }).ConfigureAwait(false));

        // Loopback: muss ebenfalls scheitern, sonst ist lokaler SSRF moeglich.
        results.Add(await ProbeAsync("connect(127.0.0.1:445)", async () =>
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 445), timeout.Token)
                .ConfigureAwait(false);
            return "VERBUNDEN - Loopback ist erreichbar.";
        }).ConfigureAwait(false));

        return results;
    }

    private static async Task<ProbeResult> ProveDnsBlockedAsync()
    {
        return await ProbeAsync("Dns.GetHostAddresses(example.com)", async () =>
        {
            var addresses = await Dns.GetHostAddressesAsync("example.com").ConfigureAwait(false);
            return $"AUFGELOEST nach {addresses.Length} Adresse(n) - DNS ist erreichbar. "
                + "Das waere ein DNS-Tunneling-Pfad.";
        }).ConfigureAwait(false);
    }

    private static async Task<int> ProbeGatewayAsync(TestOptions options)
    {
        if (options.AgentId is null)
        {
            Console.WriteLine("  [ uebersprungen ] Kein --agent angegeben.");
            Console.WriteLine("  Aufruf: Cordon.TestAgent --agent <id> --url https://host/pfad");
            return 0;
        }

        await using var client = new CordonAgentClient(options.AgentId);

        try
        {
            await ConnectWithRetryAsync(client, options.ConnectRetries).ConfigureAwait(false);
        }
        catch (CordonDeniedException ex)
        {
            Console.WriteLine($"  [ABGELEHNT] Handshake: {ex.Code} - {ex.Message}");
            return 1;
        }

        var identity = client.Identity!;
        Console.WriteLine("  [ ok ] Handshake akzeptiert.");
        Console.WriteLine($"         PID          : {identity.Pid}");
        Console.WriteLine($"         Image        : {identity.ImagePath}");
        Console.WriteLine($"         Package-SID  : {identity.PackageSid}");
        Console.WriteLine($"         AppContainer : {identity.IsAppContainer}");
        Console.WriteLine($"         Integritaet  : {identity.Integrity}");
        Console.WriteLine(
            $"         Capabilities : {(identity.Capabilities.Count == 0 ? "keine" : string.Join(", ", identity.Capabilities))}");

        // ------------------------------------------------------------------
        // Gegenprobe: Das Gateway hat die Identitaet aus dem KERNEL gelesen.
        // Hier wird geprueft, dass diese Werte zum eigenen Prozess passen.
        // Wuerde die Aufloesung raten oder verwechseln, faellt es hier auf.
        // ------------------------------------------------------------------
        Console.WriteLine();
        Console.WriteLine("  Gegenprobe der Kernel-Identitaet:");

        var identityProblems = 0;

        Check(ref identityProblems, "PID", identity.Pid == (uint)Environment.ProcessId,
            $"{identity.Pid} == eigene {Environment.ProcessId}");

        Check(ref identityProblems, "AppContainer", identity.IsAppContainer,
            identity.IsAppContainer
                ? "bestaetigt - die Netzwerkgrenze ist aktiv"
                : "NICHT bestaetigt - der Agent laeuft ohne Netzwerkgrenze!");

        Check(ref identityProblems, "Integritaet",
            identity.Integrity is "Low" or "Untrusted",
            $"{identity.Integrity} (erwartet Low/Untrusted)");

        Check(ref identityProblems, "Capabilities", identity.Capabilities.Count == 0,
            identity.Capabilities.Count == 0
                ? "keine - keine Netzwerk-Capability"
                : string.Join(", ", identity.Capabilities));

        if (identityProblems > 0)
        {
            Console.WriteLine();
            Console.WriteLine(
                $"  BEFUND: {identityProblems} Abweichung(en). Die Identitaetsaufloesung liefert "
                + "nicht die erwartete Kernel-Identitaet.");
            Console.WriteLine(
                "  Ohne bestaetigten AppContainer ist die Netzwerkgrenze NICHT wirksam - "
                + "unabhaengig davon, was die Direktversuche oben gezeigt haben.");
            return 4;
        }

        if (options.Url is null)
        {
            return 0;
        }

        Console.WriteLine();
        Console.WriteLine($"  HTTP GET {options.Url}");

        using var handler = new CordonHttpHandler(client);
        using var http = new HttpClient(handler)
        {
            Timeout = Timeout.InfiniteTimeSpan,
        };

        try
        {
            using var response = await http.GetAsync(options.Url).ConfigureAwait(false);
            Console.WriteLine($"  [ ok ] HTTP {(int)response.StatusCode} {response.ReasonPhrase}");

            var body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            Console.WriteLine($"         {body.Length} Byte empangen.");

            var preview = body.Length > 200 ? body[..200] : body;
            Console.WriteLine("         --- Anfang ---");
            Console.WriteLine(preview.Replace("\r", string.Empty, StringComparison.Ordinal));
            Console.WriteLine("         --- Ende ---");

            return 0;
        }
        catch (CordonDeniedException ex)
        {
            Console.WriteLine($"  [ABGELEHNT] {ex.Code}: {ex.Message}");
            return 1;
        }
        catch (HttpRequestException ex)
        {
            Console.WriteLine($"  [FEHLER] {ex.Message}");
            return 1;
        }
    }

    private static async Task ConnectWithRetryAsync(CordonAgentClient client, int retries)
    {
        CordonDeniedException? last = null;

        for (var attempt = 0; attempt <= retries; attempt++)
        {
            try
            {
                await client.ConnectAsync().ConfigureAwait(false);
                return;
            }
            catch (CordonDeniedException ex) when (ex.Code == "connect_timeout" && attempt < retries)
            {
                // Das Gateway braucht einen Moment, um nach einem
                // Policy-Reload einen Listener fuer diesen Agenten zu
                // oeffnen. Ein Timeout ist deshalb kein endgueltiges
                // Urteil - eine Ablehnung aus der Policy schon.
                last = ex;
                await Task.Delay(TimeSpan.FromMilliseconds(500)).ConfigureAwait(false);
            }
        }

        throw last ?? new CordonDeniedException("unknown", "Verbindung fehlgeschlagen.");
    }

    /// <summary>
    /// Prueft eine Zusicherung ueber die eigene Identitaet. Erhoeht
    /// <paramref name="failures"/> bei Abweichung.
    /// </summary>
    private static void Check(ref int failures, string label, bool condition, string detail)
    {
        if (condition)
        {
            Console.WriteLine($"    [ ok ] {label,-14}: {detail}");
        }
        else
        {
            Console.WriteLine($"    [FAIL] {label,-14}: {detail}");
            failures++;
        }
    }

    private static void ReportProbes(List<ProbeResult> results, ref int failures)    {
        foreach (var result in results)
        {
            if (result.Blocked)
            {
                Console.WriteLine($"  [ blockiert ] {result.Name}");
                Console.WriteLine($"                {result.Detail}");
            }
            else
            {
                Console.WriteLine($"  [MOEGLICH!  ] {result.Name}");
                Console.WriteLine($"                {result.Detail}");
                failures++;
            }
        }
    }

    private static ProbeResult Probe(string name, Func<string> action)
    {
        try
        {
            var detail = action();
            return new ProbeResult(name, Blocked: false, detail);
        }
        catch (Exception ex)
        {
            return new ProbeResult(name, Blocked: true, $"{ex.GetType().Name}: {ex.Message}");
        }
    }

    private static async Task<ProbeResult> ProbeAsync(string name, Func<Task<string>> action)
    {
        try
        {
            var detail = await action().ConfigureAwait(false);
            return new ProbeResult(name, Blocked: false, detail);
        }
        catch (Exception ex)
        {
            return new ProbeResult(name, Blocked: true, $"{ex.GetType().Name}: {ex.Message}");
        }
    }

    private static TestOptions ParseOptions(string[] args)
    {
        string? agentId = null;
        string? url = null;
        var retries = 20;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--agent" when i + 1 < args.Length:
                    agentId = args[++i];
                    break;

                case "--url" when i + 1 < args.Length:
                    url = args[++i];
                    break;

                case "--connect-retries" when i + 1 < args.Length:
                    _ = int.TryParse(args[++i], out retries);
                    break;

                case "--prove-boundary":
                    // Standardverhalten; Schalter nur zur Klarheit.
                    break;

                default:
                    break;
            }
        }

        if (agentId is null && Environment.GetEnvironmentVariable("CORDON_AGENT_ID") is { } fromEnvironment)
        {
            agentId = fromEnvironment;
        }

        return new TestOptions(agentId, url, retries);
    }

    private sealed record TestOptions(string? AgentId, string? Url, int ConnectRetries);

    private sealed record ProbeResult(string Name, bool Blocked, string Detail);
}
