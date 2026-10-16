using System.ComponentModel;
using Cordon.Core.Model;
using Cordon.Windows;

namespace Cordon.Launcher;

/// <summary>Optionen fuer den Start eines Agenten.</summary>
public sealed record AgentRunOptions
{
    public required string AgentId { get; init; }

    /// <summary>Programm plus Argumente.</summary>
    public required IReadOnlyList<string> Command { get; init; }

    /// <summary>WFP-Default-Deny zusaetzlich zur AppContainer-Grenze setzen.</summary>
    public bool HardeningEnabled { get; init; } = true;

    /// <summary>
    /// Persistente WFP-Regel. <b>Default aus.</b> Eine persistente Regel
    /// ueberlebt einen Neustart und wuerde einen Agenten dauerhaft netzlos
    /// machen, wenn Cordon nicht wieder startet.
    /// </summary>
    public bool PersistentWfp { get; init; }

    public string? WorkingDirectory { get; init; }

    public int ActiveProcessLimit { get; init; } = 64;

    public long ProcessMemoryLimitBytes { get; init; } = 4L * 1024 * 1024 * 1024;

    public long JobMemoryLimitBytes { get; init; } = 8L * 1024 * 1024 * 1024;

    public long CpuTimeSeconds { get; init; }

    public bool WaitForExit { get; init; } = true;
}

/// <summary>
/// Fuehrt den kompletten Startpfad fuer einen Agenten aus.
/// <para>
/// Die Reihenfolge ist die Sicherheitszusage dieser Klasse:
/// </para>
/// <list type="number">
/// <item>AppContainer-Profil sicherstellen (ohne Capabilities).</item>
/// <item>Job Object mit Limits erzeugen.</item>
/// <item>Optional WFP-Default-Deny setzen - <b>vor</b> dem Prozessstart.</item>
/// <item>Prozess suspendiert starten, in den Job setzen, dann fortsetzen.</item>
/// </list>
/// <para>
/// Die eigentliche Zusage steckt in <see cref="ProcessLauncher.Launch"/>:
/// zwischen <c>CreateProcess(CREATE_SUSPENDED)</c> und <c>ResumeThread</c>
/// liegt <c>AssignProcessToJobObject</c>. In diesem Fenster laeuft kein
/// Agentencode.
/// </para>
/// </summary>
public static class AgentRunOrchestrator
{
    /// <summary>Ergebnis eines Starts.</summary>
    public sealed record RunResult(int ExitCode, int? ProcessId, AppContainerProfile? Profile);

    public static async Task<RunResult> ExecuteAsync(
        AgentRunOptions options,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);

        if (options.Command.Count == 0)
        {
            await error.WriteLineAsync("Fehler: kein Befehl angegeben.").ConfigureAwait(false);
            return new RunResult(2, null, null);
        }

        // ------------------------------------------------------------------
        // 1. AppContainer-Profil (ohne Capabilities = Netzwerkgrenze)
        // ------------------------------------------------------------------
        AppContainerProfile profile;
        try
        {
            profile = AppContainerProfile.Ensure(options.AgentId);
        }
        catch (Exception ex) when (ex is Win32Exception or UnauthorizedAccessException)
        {
            await error.WriteLineAsync(
                $"Fehler: AppContainer-Profil konnte nicht erstellt werden: {ex.Message}")
                .ConfigureAwait(false);
            await error.WriteLineAsync(
                "Hinweis: Die Profilerstellung erfordert in der Regel erhoehte Rechte.")
                .ConfigureAwait(false);
            return new RunResult(3, null, null);
        }

        await output.WriteLineAsync($"[cordon] Agent       : {options.AgentId}").ConfigureAwait(false);
        await output.WriteLineAsync($"[cordon] AppContainer: {profile.Name}").ConfigureAwait(false);
        await output.WriteLineAsync($"[cordon] Package-SID : {profile.SidString}").ConfigureAwait(false);
        await output.WriteLineAsync(
            "[cordon] Netzwerk    : KEINE Capabilities - jeder AF_INET/AF_INET6-Zugriff "
            + "wird vom Kernel verweigert.").ConfigureAwait(false);

        // ------------------------------------------------------------------
        // 2. Job Object
        // ------------------------------------------------------------------
        var limits = new SandboxLimits
        {
            ActiveProcessLimit = options.ActiveProcessLimit,
            ProcessMemoryLimitBytes = options.ProcessMemoryLimitBytes,
            JobMemoryLimitBytes = options.JobMemoryLimitBytes,
            JobCpuTimeSeconds = options.CpuTimeSeconds,
        };

        using var job = JobObject.Create(limits);

        await output.WriteLineAsync(
            $"[cordon] Job Object: ActiveProcessLimit={limits.ActiveProcessLimit}, "
            + $"ProcessMemory={limits.ProcessMemoryLimitBytes / (1024 * 1024)} MiB, "
            + "KILL_ON_JOB_CLOSE=an, BREAKAWAY=aus").ConfigureAwait(false);

        // ------------------------------------------------------------------
        // 3. Optionale WFP-Haertung (Defense in Depth)
        // ------------------------------------------------------------------
        WfpEnforcement? enforcement = null;

        if (options.HardeningEnabled)
        {
            if (!FileAcl.IsElevated())
            {
                await output.WriteLineAsync(
                    "[cordon] WFP-Haertung uebersprungen: keine erhoehten Rechte. "
                    + "Die AppContainer-Grenze ist davon unberuehrt und weiterhin aktiv.")
                    .ConfigureAwait(false);
            }
            else
            {
                try
                {
                    enforcement = WfpEnforcement.ApplyTo(profile.PackageSid, options.PersistentWfp);
                    await output.WriteLineAsync(
                        $"[cordon] WFP-Default-Deny aktiv ({enforcement.FilterCount} Filter, "
                        + $"{(options.PersistentWfp ? "persistent" : "dynamisch")}).")
                        .ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is Win32Exception or UnauthorizedAccessException
                    or PlatformNotSupportedException or InvalidOperationException)
                {
                    await error.WriteLineAsync(
                        $"[cordon] WARNUNG: WFP-Haertung fehlgeschlagen: {ex.Message}")
                        .ConfigureAwait(false);
                    await error.WriteLineAsync(
                        "[cordon] Der Agent startet trotzdem. Die primaere Grenze (AppContainer) "
                        + "ist unabhaengig davon wirksam.").ConfigureAwait(false);
                }
            }
        }

        // ------------------------------------------------------------------
        // 4. Start (suspendiert -> Job -> fortsetzen)
        // ------------------------------------------------------------------
        AgentLaunchResult launch;
        try
        {
            launch = ProcessLauncher.Launch(
                new AgentLaunchRequest
                {
                    AgentId = options.AgentId,
                    ApplicationPath = options.Command[0],
                    Arguments = options.Command.Skip(1).ToList(),
                    WorkingDirectory = options.WorkingDirectory,
                    Limits = limits,
                },
                job);
        }
        catch (Exception ex) when (ex is Win32Exception or FileNotFoundException
            or UnauthorizedAccessException or ArgumentException)
        {
            enforcement?.Dispose();
            await error.WriteLineAsync($"Fehler beim Start: {ex.Message}").ConfigureAwait(false);
            return new RunResult(4, null, profile);
        }

        await output.WriteLineAsync(
            $"[cordon] Gestartet : pid={launch.ProcessId} {launch.CommandLine}").ConfigureAwait(false);
        await output.WriteLineAsync(
            $"[cordon] Pipe      : \\\\.\\pipe\\{Core.Protocol.ProtocolVersion.PipeNameFor(options.AgentId)}")
            .ConfigureAwait(false);

        if (!options.WaitForExit)
        {
            await output.WriteLineAsync(
                "[cordon] --no-wait: dieser Prozess beendet sich sofort. Wegen "
                + "KILL_ON_JOB_CLOSE wird der Agent (und alle Kindprozesse) beim "
                + "Schliessen des Job-Handles TERMINIERT - er laeuft also NICHT "
                + "weiter. Fuer einen dauerhaft laufenden Agenten den Dienst "
                + "(cordon serve) verwenden.").ConfigureAwait(false);

            enforcement?.Dispose();
            return new RunResult(0, launch.ProcessId, profile);
        }

        // ------------------------------------------------------------------
        // 5. Grenze offen halten, bis der Agent endet
        // ------------------------------------------------------------------
        try
        {
            using var registration = cancellationToken.Register(() =>
            {
                // Strg+C beendet den Agenten, indem der Job geschlossen wird.
                // Das ist der einzige Weg, der alle Kindprozesse mitnimmt.
                job.Dispose();
            });

            var exitCode = ProcessLauncher.WaitForExit(
                (uint)launch.ProcessId,
                Timeout.InfiniteTimeSpan);

            await output.WriteLineAsync($"[cordon] Agent beendet mit Exitcode {exitCode}.")
                .ConfigureAwait(false);

            return new RunResult(unchecked((int)exitCode), launch.ProcessId, profile);
        }
        catch (Exception ex) when (ex is Win32Exception or TimeoutException or ObjectDisposedException)
        {
            await error.WriteLineAsync($"Fehler beim Warten: {ex.Message}").ConfigureAwait(false);
            return new RunResult(5, launch.ProcessId, profile);
        }
        finally
        {
            // Reihenfolge: erst die WFP-Regeln entfernen, dann den Job
            // schliessen. Andersherum wuerden die Kindprozesse sterben,
            // waehrend die Regel noch steht - unnoetig, aber harmlos; in
            // dieser Reihenfolge ist der Zustand zu jedem Zeitpunkt konsistent.
            enforcement?.Dispose();
        }
    }
}
