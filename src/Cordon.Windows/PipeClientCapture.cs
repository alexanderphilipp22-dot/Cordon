using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Cordon.Windows.Interop;

namespace Cordon.Windows;

/// <summary>
/// Die serverseitig erfasste Identitaetssignatur eines Pipe-Clients.
/// <para>
/// Der Wert wird <b>einmal</b> erfasst, naemlich direkt nach dem
/// Verbindungsaufbau am Pipe-Handle, und danach durch die gesamte
/// Autorisierung getragen. Er ist bewusst ein eigener Typ und wird nicht
/// durch eine blosse PID ersetzt.
/// </para>
/// <para>
/// <b>Warum die Erzeugungszeit mitgefuehrt wird:</b> Eine PID ist keine
/// Identitaet ueber die Zeit. Windows vergibt PIDs nach dem Ende eines
/// Prozesses neu. Wuerde Cordon nur die PID merken und spaeter erneut
/// aufloesen, koennte zwischen beiden Schritten der Agent sterben und ein
/// fremder Prozess dieselbe PID erhalten - Cordon wuerde dann das Token des
/// Fremdprozesses lesen und dessen Capabilities als die des Agenten
/// behandeln. (<c>OpenProcess</c> adressiert einen <i>Prozess</i>, nicht den
/// urspruenglichen <i>Client</i>.)
/// </para>
/// <para>
/// <c>OpenProcess</c> auf eine tote PID schlaegt fehl und ist damit
/// ungefaehrlich; die Gefahr ist ausschliesslich die Wiederverwendung. Die
/// Erzeugungszeit macht diese Wiederverwendung erkennbar.
/// </para>
/// </summary>
public readonly record struct PipeClientSignature(uint ProcessId, long CreationTime)
{
    /// <summary>Die PID ist 0 - kein gueltiger Aufrufer.</summary>
    public bool IsEmpty => ProcessId == 0;

    public override string ToString() =>
        $"pid={ProcessId} created={CreationTime}";
}

/// <summary>Ergebnis einer Erfassung am Pipe-Handle.</summary>
public sealed record PipeClientCapture
{
    /// <summary>Die Signatur. Bei <see cref="Success"/> = <c>false</c> leer.</summary>
    public required PipeClientSignature Signature { get; init; }

    public required bool Success { get; init; }

    /// <summary>Win32-Fehlercode, falls die Erfassung fehlschlug.</summary>
    public int Win32Error { get; init; }

    public string? Error { get; init; }

    public static PipeClientCapture Ok(PipeClientSignature signature) => new()
    {
        Signature = signature,
        Success = true,
    };

    public static PipeClientCapture Failed(int win32Error, string error) => new()
    {
        Signature = default,
        Success = false,
        Win32Error = win32Error,
        Error = error,
    };
}

/// <summary>
/// Erfasst die Identitaetssignatur eines Pipe-Clients aus dem
/// Pipe-<b>Kernelobjekt</b>.
/// <para>
/// Das ist die einzige Stelle im System, an der eine Identitaet
/// <i>entsteht</i>. Alles Weitere leitet sich daraus ab. Die PID wird nicht
/// vom Agenten uebermittelt und kann daher nicht gefaelscht werden.
/// </para>
/// <para>
/// <b>Reihenfolge ist sicherheitskritisch:</b> PID lesen und
/// Erzeugungszeit lesen muessen unmittelbar nacheinander erfolgen. Wird
/// zwischen beiden Schritten neu verbunden, gehoert die Erzeugungszeit zu
/// einem anderen Prozess und die spaetere Pruefung in
/// <see cref="PipeClientResolver"/> schlaegt fehl - das ist der gewuenschte
/// Ausgang (fail closed), kein Fehler.
/// </para>
/// </summary>
public static class PipeClientCaptureReader
{
    /// <summary>
    /// Liest PID und Erzeugungszeit des Prozesses, der das andere Ende
    /// dieser Pipe haelt.
    /// </summary>
    /// <param name="pipeHandle">
    /// Handle der <b>verbundenen</b> Server-Pipe-Instanz
    /// (z. B. <c>NamedPipeServerStream.SafePipeHandle</c>).
    /// </param>
    public static PipeClientCapture Capture(SafeHandle pipeHandle)
    {
        ArgumentNullException.ThrowIfNull(pipeHandle);

        if (pipeHandle.IsInvalid || pipeHandle.IsClosed)
        {
            return PipeClientCapture.Failed(0, "Pipe-Handle ist ungueltig oder bereits geschlossen.");
        }

        // Das SafeHandle wird direkt an die P/Invoke uebergeben. Der
        // P/Invoke-Marshaller pinnt es waehrend des Aufrufs (AddRef/Release),
        // sodass weder ein Handle-Recycling zwischen Erfassung und
        // Kernel-Aufruf moeglich ist noch ein `DangerousGetHandle`-Wrapper
        // noetig wird (der das Pipe-Handle versehentlich haette schliessen
        // koennen, wenn er jemals disposed wuerde).
        if (!NativeMethods.GetNamedPipeClientProcessId(pipeHandle, out var pid))
        {
            var error = Marshal.GetLastWin32Error();
            return PipeClientCapture.Failed(
                error,
                $"GetNamedPipeClientProcessId fehlgeschlagen (Win32 {error}). "
                + "Die Pipe ist vermutlich nicht verbunden.");
        }

        if (pid == 0)
        {
            // Kommt vor, wenn die Gegenseite bereits weg ist oder wenn kein
            // wirklicher Clientprozess existiert (z. B. bei manchen
            // Kernel-Clients). Nicht als Identitaet verwenden.
            return PipeClientCapture.Failed(0, "GetNamedPipeClientProcessId lieferte PID 0.");
        }

        if (!TryGetCreationTime(pid, out var creationTime, out var timeError))
        {
            return PipeClientCapture.Failed(
                timeError,
                $"Erzeugungszeit fuer pid={pid} nicht lesbar (Win32 {timeError}).");
        }

        return PipeClientCapture.Ok(new PipeClientSignature(pid, creationTime));
    }

    /// <summary>
    /// Liest die Erzeugungszeit eines Prozesses als roher
    /// <c>FILETIME</c>-Wert (100-ns-Intervalle seit 1601).
    /// <para>
    /// Gibt absichtlich <see cref="long"/> und keine <see cref="DateTime"/>
    /// zurueck: die Umrechnung wuerde Rundung und Zeitzonenlogik einfuehren,
    /// und hier wird ausschliesslich auf <i>Gleichheit</i> geprueft.
    /// </para>
    /// </summary>
    public static bool TryGetCreationTime(uint pid, out long creationTime, out int win32Error)
    {
        creationTime = 0;
        win32Error = 0;

        using var process = NativeMethods.OpenProcess(
            NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION,
            inheritHandle: false,
            pid);

        if (process.IsInvalid)
        {
            win32Error = Marshal.GetLastWin32Error();
            return false;
        }

        if (!NativeMethods.GetProcessTimes(
                process,
                out creationTime,
                out _,
                out _,
                out _))
        {
            win32Error = Marshal.GetLastWin32Error();
            return false;
        }

        return true;
    }

    /// <summary>
    /// Wie <see cref="TryGetCreationTime(uint, out long, out int)"/>, ohne den
    /// Win32-Fehlercode. Fuer Aufrufer, die nur an Erfolg und Wert
    /// interessiert sind.
    /// </summary>
    public static bool TryGetCreationTime(uint pid, out long creationTime) =>
        TryGetCreationTime(pid, out creationTime, out _);

    /// <summary>
    /// Bequeme Variante: erfasst die Signatur und wirft bei einem Fehler.
    /// Fuer Aufrufer, die einen Fehler nicht als Kontrollflussabbildung
    /// behandeln wollen.
    /// </summary>
    /// <exception cref="Win32Exception">Wenn die Erfassung fehlschlaegt.</exception>
    public static PipeClientSignature CaptureOrThrow(SafeHandle pipeHandle)
    {
        var capture = Capture(pipeHandle);
        if (!capture.Success)
        {
            throw new Win32Exception(capture.Win32Error, capture.Error);
        }

        return capture.Signature;
    }
}
