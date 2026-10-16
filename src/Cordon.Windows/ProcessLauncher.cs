using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using Cordon.Core.Model;
using Cordon.Windows.Interop;

namespace Cordon.Windows;

/// <summary>Beschreibung eines zu startenden Agenten.</summary>
public sealed record AgentLaunchRequest
{
    /// <summary>Agent-Id. Bestimmt den AppContainer-Profilnamen.</summary>
    public required string AgentId { get; init; }

    /// <summary>Ausfuehrbare Datei oder zu startender Befehl.</summary>
    public required string ApplicationPath { get; init; }

    /// <summary>Argumente <b>ohne</b> den Programmnamen.</summary>
    public IReadOnlyList<string> Arguments { get; init; } = [];

    public string? WorkingDirectory { get; init; }

    public SandboxLimits Limits { get; init; } = new();
}

/// <summary>Ergebnis eines Starts.</summary>
public sealed record AgentLaunchResult
{
    public required int ProcessId { get; init; }

    public required AppContainerProfile Profile { get; init; }

    public required string ResolvedApplicationPath { get; init; }

    public required string CommandLine { get; init; }
}

/// <summary>
/// Startet einen Agenten in einer OS-erzwungenen Grenze.
/// <para>
/// Die Reihenfolge im Spawn ist sicherheitskritisch und daher fest:
/// </para>
/// <list type="number">
/// <item><c>CREATE_SUSPENDED</c> — der Prozess laeuft noch nicht.</item>
/// <item>AppContainer ueber <c>PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES</c>
///       an das Kind binden (ohne Capabilities).</item>
/// <item><c>AssignProcessToJobObject</c>.</item>
/// <item>Erst jetzt <c>ResumeThread</c>.</item>
/// </list>
/// <para>
/// Wuerde zwischen Schritt 1 und 3 fortgesetzt, koennte der Agent in diesem
/// Fenster einen Kindprozess ausserhalb des Jobs erzeugen.
/// </para>
/// </summary>
public static class ProcessLauncher
{
    /// <summary>
    /// Startet den Agenten. Der Aufrufer muss das zurueckgegebene
    /// <see cref="JobObject"/> am Leben halten: solange es offen ist, gelten
    /// die Limits; beim Schliessen werden alle Prozesse beendet.
    /// </summary>
    public static AgentLaunchResult Launch(AgentLaunchRequest request, JobObject job)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(job);

        var profile = AppContainerProfile.Ensure(request.AgentId);
        var resolvedApplication = ResolveApplicationPath(request.ApplicationPath);
        var commandLine = BuildCommandLine(resolvedApplication, request.Arguments);
        var commandLinePtr = Marshal.StringToHGlobalUni(commandLine);
        var appContainerSid = profile.AcquireNativeSid();
        var attributeList = IntPtr.Zero;

        try
        {
            var securityCapabilities = new NativeMethods.SECURITY_CAPABILITIES
            {
                AppContainerSid = appContainerSid,

                // Keine Capability. Das ist die Netzwerkgrenze: ohne
                // internetClient/privateNetworkClientServer verweigert der
                // Kernel jeden AF_INET/AF_INET6-Zugriff.
                Capabilities = IntPtr.Zero,
                CapabilityCount = 0,
                Reserved = 0,
            };

            var capabilitiesSize = Marshal.SizeOf<NativeMethods.SECURITY_CAPABILITIES>();
            var capabilitiesPtr = Marshal.AllocHGlobal(capabilitiesSize);

            try
            {
                Marshal.StructureToPtr(securityCapabilities, capabilitiesPtr, fDeleteOld: false);

                attributeList = BuildAttributeList(capabilitiesPtr, capabilitiesSize);

                var startupInfo = new NativeMethods.STARTUPINFOEXW
                {
                    lpAttributeList = attributeList,
                };
                startupInfo.StartupInfo.cb = (uint)Marshal.SizeOf<NativeMethods.STARTUPINFOEXW>();

                // CREATE_SUSPENDED ist nicht verhandelbar: ohne suspendierten
                // Start gaebe es ein Fenster, in dem der Agent bereits laeuft,
                // aber noch nicht im Job ist.
                var creationFlags = NativeMethods.EXTENDED_STARTUPINFO_PRESENT
                    | NativeMethods.CREATE_SUSPENDED
                    | NativeMethods.CREATE_UNICODE_ENVIRONMENT;

                var workingDirectory = request.WorkingDirectory;

                if (!NativeMethods.CreateProcessW(
                        resolvedApplication,
                        commandLinePtr,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        inheritHandles: false,
                        creationFlags,
                        // nullptr = Umgebung des aufrufenden Prozesses erben.
                        // Cordon setzt dem Agenten keine Secrets in die
                        // Umgebung - es gibt keine Tokens weiterzugeben.
                        IntPtr.Zero,
                        workingDirectory,
                        ref startupInfo,
                        out var processInformation))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        $"CreateProcessW('{resolvedApplication}') fehlgeschlagen.");
                }

                using var processHandle = new SafeProcessHandle(processInformation.hProcess, ownsHandle: true);
                using var threadHandle = new SafeThreadHandle(processInformation.hThread, ownsHandle: true);

                try
                {
                    // Schritt 3: Job zuweisen, SOLANGE der Prozess suspendiert ist.
                    job.AssignProcess(processHandle);

                    // Schritt 4: erst jetzt laufen lassen.
                    if (NativeMethods.ResumeThread(threadHandle) == uint.MaxValue)
                    {
                        throw new Win32Exception(
                            Marshal.GetLastWin32Error(),
                            "ResumeThread fehlgeschlagen. Der Agent bleibt suspendiert und wird "
                            + "beim Schliessen des Job-Handles beendet.");
                    }
                }
                catch
                {
                    // Der Prozess laeuft entweder noch nicht oder ohne Job.
                    // In beiden Faellen darf er nicht weiterleben.
                    _ = NativeMethods.TerminateProcess(processHandle, 1);
                    throw;
                }

                return new AgentLaunchResult
                {
                    ProcessId = (int)processInformation.dwProcessId,
                    Profile = profile,
                    ResolvedApplicationPath = resolvedApplication,
                    CommandLine = commandLine,
                };
            }
            finally
            {
                Marshal.FreeHGlobal(capabilitiesPtr);
            }
        }
        finally
        {
            if (attributeList != IntPtr.Zero)
            {
                NativeMethods.DeleteProcThreadAttributeList(attributeList);
                Marshal.FreeHGlobal(attributeList);
            }

            AppContainerProfile.ReleaseNativeSid(appContainerSid);
            Marshal.FreeHGlobal(commandLinePtr);
        }
    }

    /// <summary>
    /// Wartet auf das Ende eines Prozesses und liefert den Exitcode.
    /// </summary>
    public static uint WaitForExit(uint processId, TimeSpan timeout)
    {
        using var process = NativeMethods.OpenProcess(
            NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION | NativeMethods.SYNCHRONIZE,
            inheritHandle: false,
            processId);

        if (process.IsInvalid)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                $"OpenProcess(pid={processId}) fehlgeschlagen.");
        }

        var milliseconds = timeout == Timeout.InfiniteTimeSpan
            ? NativeMethods.INFINITE
            : (uint)Math.Clamp(timeout.TotalMilliseconds, 0, uint.MaxValue - 1);

        var wait = NativeMethods.WaitForSingleObject(process, milliseconds);
        if (wait == NativeMethods.WAIT_TIMEOUT)
        {
            throw new TimeoutException($"Prozess {processId} war nicht innerhalb von {timeout} beendet.");
        }

        if (!NativeMethods.GetExitCodeProcess(process, out var exitCode))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                $"GetExitCodeProcess(pid={processId}) fehlgeschlagen.");
        }

        return exitCode;
    }

    /// <summary>
    /// Loest einen Programmnamen ueber <c>PATH</c> auf, damit der Audit den
    /// vollstaendigen Pfad zeigen kann. Ein blosses "python.exe" ist im Log
    /// wertlos.
    /// </summary>
    public static string ResolveApplicationPath(string applicationPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(applicationPath);

        if (Path.IsPathFullyQualified(applicationPath))
        {
            var full = Path.GetFullPath(applicationPath);
            if (!File.Exists(full))
            {
                throw new FileNotFoundException($"Anwendung nicht gefunden: {full}", full);
            }

            return full;
        }

        var pathVariable = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        foreach (var directory in pathVariable.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            string candidate;
            try
            {
                candidate = Path.Combine(directory.Trim('"'), applicationPath);
            }
            catch (ArgumentException)
            {
                continue;
            }

            if (File.Exists(candidate))
            {
                return Path.GetFullPath(candidate);
            }
        }

        throw new FileNotFoundException(
            $"'{applicationPath}' wurde nicht gefunden und ist auch nicht ueber PATH aufloesbar.",
            applicationPath);
    }

    /// <summary>
    /// Baut eine Windows-Kommandozeile nach den Regeln von
    /// <c>CommandLineToArgvW</c>. Ein Agent-Argument mit Leerzeichen oder
    /// Anfuehrungszeichen darf die Argumentgrenzen nicht verschieben.
    /// </summary>
    public static string BuildCommandLine(string applicationPath, IReadOnlyList<string> arguments)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(applicationPath);
        ArgumentNullException.ThrowIfNull(arguments);

        var builder = new StringBuilder();
        AppendQuoted(builder, applicationPath);

        foreach (var argument in arguments)
        {
            builder.Append(' ');
            AppendQuoted(builder, argument);
        }

        return builder.ToString();
    }

    private static void AppendQuoted(StringBuilder builder, string value)
    {
        if (value.Length == 0)
        {
            builder.Append("\"\"");
            return;
        }

        if (!value.Any(c => c is ' ' or '\t' or '"'))
        {
            builder.Append(value);
            return;
        }

        builder.Append('"');
        var backslashes = 0;

        foreach (var c in value)
        {
            if (c == '\\')
            {
                backslashes++;
                continue;
            }

            if (c == '"')
            {
                // Backslashes vor einem Anfuehrungszeichen muessen verdoppelt
                // werden, plus ein weiterer fuer das escapte Zeichen selbst.
                builder.Append('\\', (backslashes * 2) + 1);
                builder.Append('"');
                backslashes = 0;
                continue;
            }

            builder.Append('\\', backslashes);
            backslashes = 0;
            builder.Append(c);
        }

        // Abschliessende Backslashes duerfen das schliessende
        // Anfuehrungszeichen nicht escapen.
        builder.Append('\\', backslashes * 2);
        builder.Append('"');
    }

    private static IntPtr BuildAttributeList(IntPtr capabilitiesPtr, int capabilitiesSize)
    {
        var size = IntPtr.Zero;

        // Erster Aufruf schlaegt bewusst fehl und liefert die benoetigte
        // Groesse in `size`.
        _ = NativeMethods.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
        if (size == IntPtr.Zero)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "InitializeProcThreadAttributeList lieferte keine Groesse.");
        }

        var attributeList = Marshal.AllocHGlobal(size);

        if (!NativeMethods.InitializeProcThreadAttributeList(attributeList, 1, 0, ref size))
        {
            var error = Marshal.GetLastWin32Error();
            Marshal.FreeHGlobal(attributeList);
            throw new Win32Exception(error, "InitializeProcThreadAttributeList fehlgeschlagen.");
        }

        if (!NativeMethods.UpdateProcThreadAttribute(
                attributeList,
                0,
                NativeMethods.ProcThreadAttributeSecurityCapabilities,
                capabilitiesPtr,
                capabilitiesSize,
                IntPtr.Zero,
                IntPtr.Zero))
        {
            var error = Marshal.GetLastWin32Error();
            NativeMethods.DeleteProcThreadAttributeList(attributeList);
            Marshal.FreeHGlobal(attributeList);
            throw new Win32Exception(
                error,
                "UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES) fehlgeschlagen.");
        }

        return attributeList;
    }
}
