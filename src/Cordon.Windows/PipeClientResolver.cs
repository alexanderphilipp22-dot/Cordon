using System.Buffers;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Cordon.Core;
using Cordon.Core.Model;
using Cordon.Windows.Interop;

namespace Cordon.Windows;

/// <summary>Stabile Fehlercodes der Identitaetsaufloesung.</summary>
public static class IdentityResolutionErrors
{
    /// <summary>Pipe-Handle ungueltig oder nicht verbunden.</summary>
    public const string PipeNotConnected = "identity.pipe_not_connected";

    /// <summary>Der Clientprozess existiert nicht mehr.</summary>
    public const string ProcessGone = "identity.process_gone";

    /// <summary>
    /// Die PID wurde zwischen Erfassung und Aufloesung neu vergeben.
    /// </summary>
    public const string ProcessReused = "identity.process_reused";

    /// <summary>Zugriff auf den Prozess verweigert.</summary>
    public const string AccessDenied = "identity.access_denied";

    /// <summary>Image-Pfad nicht ermittelbar.</summary>
    public const string ImagePathUnavailable = "identity.image_path_unavailable";

    /// <summary>Token nicht lesbar.</summary>
    public const string TokenUnavailable = "identity.token_unavailable";

    /// <summary>Integritaetslevel nicht bestimmbar.</summary>
    public const string IntegrityUnknown = "identity.integrity_unknown";

    /// <summary>Die Klasse <c>TokenIsAppContainer</c> wird nicht unterstuetzt.</summary>
    public const string AppContainerClassUnsupported = "identity.appcontainer_unsupported";
}

/// <summary>
/// Ergebnis der serverseitigen Identitaetsaufloesung.
/// <para>
/// Bei <see cref="Success"/> = <c>false</c> ist <see cref="Identity"/>
/// <c>null</c> - es gibt bewusst <b>keine</b> teilweise gefuellte Identitaet,
/// die ein Aufrufer versehentlich als gueltig behandeln koennte.
/// </para>
/// </summary>
public sealed record IdentityResolution
{
    public ClientIdentity? Identity { get; init; }

    public required bool Success { get; init; }

    /// <summary>Einer der Werte aus <see cref="IdentityResolutionErrors"/>.</summary>
    public string? ErrorCode { get; init; }

    public string? Error { get; init; }

    public int Win32Error { get; init; }

    /// <summary>Zusatzhinweise, die die Aufloesung nicht ungültig machen.</summary>
    public IReadOnlyList<string> Warnings { get; init; } = [];

    public static IdentityResolution Ok(ClientIdentity identity, IReadOnlyList<string>? warnings = null) => new()
    {
        Identity = identity,
        Success = true,
        Warnings = warnings ?? [],
    };

    public static IdentityResolution Failed(string code, string error, int win32Error = 0) => new()
    {
        Success = false,
        ErrorCode = code,
        Error = error,
        Win32Error = win32Error,
    };
}

/// <summary>
/// Loest die Identitaet eines Pipe-Clients aus seinem Pipe-Handle auf.
/// <para>
/// <b>Das ist die zentrale Identitaetszusage des Systems.</b> Der Rueckgabewert
/// enthaelt ausschliesslich Werte, die aus Kernel-Abfragen stammen:
/// </para>
/// <list type="bullet">
/// <item>PID aus <c>GetNamedPipeClientProcessId</c> (Pipe-Kernelobjekt)</item>
/// <item>Erzeugungszeit aus <c>GetProcessTimes</c> (Prozess-Kernelobjekt)</item>
/// <item>Image-Pfad aus <c>QueryFullProcessImageNameW</c></item>
/// <item>Integritaetslevel, Package-SID und Capabilities aus <c>GetTokenInformation</c></item>
/// </list>
/// <para>
/// <b>Nichts</b> davon stammt aus der Nutzlast des Agenten. Ein kompromittierter
/// Agent kann daher nur seine echte Identitaet verwenden.
/// </para>
/// </summary>
public static class PipeClientResolver
{
    /// <summary>
    /// Maximale Laenge eines Image-Pfads in Zeichen. <c>QueryFullProcessImageNameW</c>
    /// kann Pfade bis 32767 Zeichen liefern (erweiterte Pfadlaenge).
    /// </summary>
    public const int MaxImagePathChars = 32768;

    /// <summary>
    /// Loest die Identitaet auf, ohne die PID-Wiederverwendung zu pruefen.
    /// <para>
    /// Nur fuer Faelle verwenden, in denen unmittelbar nach
    /// <see cref="PipeClientCaptureReader.Capture"/> aufgeloest wird und keine
    /// Signatur vorliegt. Der regulaere Weg ist
    /// <see cref="Resolve(SafeHandle, PipeClientSignature, string, string?, string?, string?)"/>.
    /// </para>
    /// </summary>
    public static IdentityResolution Resolve(
        uint pid,
        string agentId,
        string? expectedPackageSid = null,
        string? expectedImagePath = null,
        string? imageSha256 = null,
        string? signerSubject = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(agentId);

        if (pid == 0)
        {
            return IdentityResolution.Failed(
                IdentityResolutionErrors.ProcessGone,
                "PID 0 ist kein gueltiger Clientprozess.");
        }

        if (!PipeClientCaptureReader.TryGetCreationTime(pid, out var creationTime, out var timeError))
        {
            return ClassifyProcessFailure(pid, timeError, "Erzeugungszeit nicht lesbar");
        }

        return ResolveCore(
            new PipeClientSignature(pid, creationTime),
            creationTime,
            verifyCreationTime: false,
            agentId,
            expectedPackageSid,
            expectedImagePath,
            imageSha256,
            signerSubject);
    }

    /// <summary>
    /// Loest die Identitaet auf und prueft dabei, dass die PID seit der
    /// Erfassung am Pipe-Handle <b>nicht neu vergeben</b> wurde.
    /// <para>
    /// <b>Das ist der zu bevorzugende Weg.</b> Die Pruefung ist der Grund,
    /// warum eine PID hier als Identitaetsnachweis taugt: ohne sie koennte
    /// zwischen dem Verbindungsaufbau und dieser Aufloesung der Agent enden
    /// und ein fremder Prozess dieselbe PID erhalten.
    /// </para>
    /// </summary>
    public static IdentityResolution Resolve(
        SafeHandle pipeHandle,
        PipeClientSignature signature,
        string agentId,
        string? expectedPackageSid = null,
        string? expectedImagePath = null,
        string? imageSha256 = null,
        string? signerSubject = null)
    {
        ArgumentNullException.ThrowIfNull(pipeHandle);
        ArgumentException.ThrowIfNullOrWhiteSpace(agentId);

        if (signature.IsEmpty)
        {
            return IdentityResolution.Failed(
                IdentityResolutionErrors.ProcessGone,
                "Die uebergebene Client-Signatur ist leer.");
        }

        // Zweite Erfassung am Handle. Stimmt sie nicht mit der ersten
        // ueberein, hat in der Zwischenzeit eine andere Verbindung
        // bestanden - dann ist die Zuordnung unklar und wird verworfen.
        var current = PipeClientCaptureReader.Capture(pipeHandle);
        if (!current.Success)
        {
            return IdentityResolution.Failed(
                IdentityResolutionErrors.PipeNotConnected,
                current.Error ?? "Erneute Erfassung am Pipe-Handle fehlgeschlagen.",
                current.Win32Error);
        }

        if (current.Signature != signature)
        {
            return IdentityResolution.Failed(
                IdentityResolutionErrors.ProcessReused,
                $"Die Client-Signatur hat sich waehrend der Aufloesung geaendert "
                + $"(erfasst: {signature}, jetzt: {current.Signature}). "
                + "Die Verbindung wurde zwischenzeitlich ersetzt.");
        }

        return ResolveCore(
            signature,
            signature.CreationTime,
            verifyCreationTime: true,
            agentId,
            expectedPackageSid,
            expectedImagePath,
            imageSha256,
            signerSubject);
    }

    private static IdentityResolution ResolveCore(
        PipeClientSignature signature,
        long expectedCreationTime,
        bool verifyCreationTime,
        string agentId,
        string? expectedPackageSid,
        string? expectedImagePath,
        string? imageSha256,
        string? signerSubject)
    {
        var warnings = new List<string>();

        // PROCESS_QUERY_LIMITED_INFORMATION ist die minimale Zugriffsmaske,
        // die fuer Image-Pfad und Token-Abfragen genuegt. Bewusst NICHT
        // PROCESS_ALL_ACCESS: das waere mehr Recht als noetig und wuerde
        // gegenueber hoeher integren Prozessen scheitern.
        using var process = NativeMethods.OpenProcess(
            NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION,
            inheritHandle: false,
            signature.ProcessId);

        if (process.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            return ClassifyProcessFailure(signature.ProcessId, error, "OpenProcess fehlgeschlagen");
        }

        if (verifyCreationTime)
        {
            if (!NativeMethods.GetProcessTimes(process, out var actual, out _, out _, out _))
            {
                var error = Marshal.GetLastWin32Error();
                return IdentityResolution.Failed(
                    IdentityResolutionErrors.ProcessGone,
                    $"GetProcessTimes fuer pid={signature.ProcessId} fehlgeschlagen (Win32 {error}).",
                    error);
            }

            if (actual != expectedCreationTime)
            {
                // Der entscheidende Abbruch: dieselbe PID, andere
                // Prozessinstanz.
                return IdentityResolution.Failed(
                    IdentityResolutionErrors.ProcessReused,
                    $"pid={signature.ProcessId} wurde neu vergeben: erwartete Erzeugungszeit "
                    + $"{expectedCreationTime}, gefunden {actual}. Der urspruengliche Client "
                    + "existiert nicht mehr; die Aufloesung wird verworfen.");
            }
        }

        if (!TryQueryImagePath(process, out var imagePath, out var imageError))
        {
            return IdentityResolution.Failed(
                IdentityResolutionErrors.ImagePathUnavailable,
                imageError ?? "Image-Pfad nicht ermittelbar.",
                Marshal.GetLastWin32Error());
        }

        var tokenResult = ReadToken(process, warnings);
        if (tokenResult is null)
        {
            return IdentityResolution.Failed(
                IdentityResolutionErrors.TokenUnavailable,
                $"OpenProcessToken fuer pid={signature.ProcessId} fehlgeschlagen.",
                Marshal.GetLastWin32Error());
        }

        var token = tokenResult.Value;

        var identity = new ClientIdentity
        {
            Pid = signature.ProcessId,
            ProcessCreationTime = signature.CreationTime,
            ImagePath = imagePath,
            ImageSha256 = imageSha256,
            PackageSid = token.PackageSid,
            IsAppContainer = token.IsAppContainer,
            Integrity = token.Integrity,
            Capabilities = token.Capabilities,
            SignerSubject = signerSubject,
            AgentId = agentId,
            ExpectedPackageSid = expectedPackageSid ?? string.Empty,
            ExpectedImagePath = expectedImagePath ?? string.Empty,
        };

        return IdentityResolution.Ok(identity, warnings);
    }

    /// <summary>
    /// Klassifiziert einen Prozessfehler. <c>ERROR_INVALID_PARAMETER</c> bei
    /// <c>OpenProcess</c> bedeutet in aller Regel, dass die PID nicht (mehr)
    /// existiert - das ist der haeufigste und harmloseste Fall: ein Agent,
    /// der sich waehrend des Handshakes beendet hat.
    /// </summary>
    private static IdentityResolution ClassifyProcessFailure(uint pid, int win32Error, string context)
    {
        const int ERROR_INVALID_PARAMETER = 87;
        const int ERROR_ACCESS_DENIED = 5;
        const int ERROR_PARTIAL_COPY = 299;

        return win32Error switch
        {
            ERROR_INVALID_PARAMETER => IdentityResolution.Failed(
                IdentityResolutionErrors.ProcessGone,
                $"{context}: pid={pid} existiert nicht mehr (Win32 {win32Error}).",
                win32Error),

            ERROR_ACCESS_DENIED or ERROR_PARTIAL_COPY => IdentityResolution.Failed(
                IdentityResolutionErrors.AccessDenied,
                $"{context}: Zugriff auf pid={pid} verweigert (Win32 {win32Error}). "
                + "Ein geschuetzter Prozess (PPL) ist kein zulaessiger Agent.",
                win32Error),

            _ => IdentityResolution.Failed(
                IdentityResolutionErrors.ProcessGone,
                $"{context}: pid={pid} nicht abfragbar (Win32 {win32Error}).",
                win32Error),
        };
    }

    /// <summary>
    /// Vollstaendiger Image-Pfad eines Prozesses.
    /// </summary>
    public static bool TryQueryImagePath(
        SafeProcessHandle processHandle,
        out string imagePath,
        out string? error)
    {
        ArgumentNullException.ThrowIfNull(processHandle);

        imagePath = string.Empty;
        error = null;

        // Der Puffer wird aus dem Pool geholt. Frueher wurde hier bei jedem
        // Aufruf ein 64-KiB-Array neu alloziert; bei einer Aufloesung pro
        // Pipe-Verbindung ist das unnoetiger GC-Druck auf dem kritischen Pfad.
        var buffer = ArrayPool<char>.Shared.Rent(MaxImagePathChars);

        try
        {
            var size = (uint)buffer.Length;

            if (!NativeMethods.QueryFullProcessImageNameW(processHandle, 0, buffer, ref size))
            {
                var win32Error = Marshal.GetLastWin32Error();
                error = $"QueryFullProcessImageNameW fehlgeschlagen (Win32 {win32Error}).";
                return false;
            }

            // Vertrag der API: `size` erhaelt die Laenge OHNE das
            // abschliessende Null-Zeichen. Ist sie groesser als der Puffer,
            // wurde der Pfad abgeschnitten - dann ist der Wert unbrauchbar,
            // weil ein abgeschnittener Pfad die Image-Bindung aushebeln
            // koennte (Praefix eines erlaubten Pfades).
            if (size == 0 || size > buffer.Length)
            {
                error = $"QueryFullProcessImageNameW lieferte eine unplausible Laenge ({size} "
                    + $"bei Puffergroesse {buffer.Length}).";
                return false;
            }

            imagePath = new string(buffer, 0, (int)size);
            return true;
        }
        finally
        {
            // clearArray: der Pfad ist nicht geheim, aber der Puffer wird
            // geteilt - Reste eines fremden Pfades sollen nicht in einer
            // spaeteren Nutzung als gueltig erscheinen koennen.
            ArrayPool<char>.Shared.Return(buffer, clearArray: true);
        }
    }

    /// <summary>
    /// Vollstaendiger Image-Pfad, werfende Variante.
    /// </summary>
    /// <exception cref="Win32Exception">Wenn der Pfad nicht ermittelbar ist.</exception>
    public static string QueryImagePath(SafeProcessHandle processHandle)
    {
        if (!TryQueryImagePath(processHandle, out var path, out var error))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), error);
        }

        return path;
    }
    private static TokenSnapshot? ReadToken(SafeProcessHandle processHandle, List<string> warnings)
    {
        if (!NativeMethods.OpenProcessToken(processHandle, NativeMethods.TOKEN_QUERY, out var token))
        {
            return null;
        }

        using (token)
        {
            return new TokenSnapshot(
                ReadIsAppContainer(token, warnings),
                ReadIntegrity(token, warnings),
                ReadAppContainerSid(token, warnings),
                ReadCapabilities(token, warnings));
        }
    }

    /// <summary>
    /// Liest <c>TokenIsAppContainer</c>.
    /// <para>
    /// <b>Unterscheidet "nicht unterstuetzt" von "ist kein AppContainer".</b>
    /// Frueher gab ein Fehler hier <c>false</c> zurueck, also dieselbe Antwort
    /// wie ein echter Negativ-Befund. Damit war eine fehlende
    /// API-Unterstuetzung nicht von einem normalen Prozess unterscheidbar -
    /// und eine Fehlermeldung im Audit haette gefehlt.
    /// </para>
    /// </summary>
    private static bool ReadIsAppContainer(SafeAccessTokenHandle token, List<string> warnings)
    {
        var buffer = Marshal.AllocHGlobal(sizeof(int));

        try
        {
            if (!NativeMethods.GetTokenInformation(
                    token,
                    NativeMethods.TokenIsAppContainer,
                    buffer,
                    sizeof(int),
                    out _))
            {
                var error = Marshal.GetLastWin32Error();

                // ERROR_INVALID_PARAMETER (87) bedeutet hier: die
                // Informationsklasse ist unbekannt (Windows < 8).
                if (error == 87)
                {
                    warnings.Add(
                        "GetTokenInformation(TokenIsAppContainer) wird von diesem Windows "
                        + "nicht unterstuetzt. Die AppContainer-Eigenschaft konnte nicht "
                        + "bestaetigt werden; der Aufrufer wird abgelehnt.");
                }
                else
                {
                    warnings.Add(
                        $"GetTokenInformation(TokenIsAppContainer) fehlgeschlagen "
                        + $"(Win32 {error}).");
                }

                return false;
            }

            return Marshal.ReadInt32(buffer) != 0;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>
    /// Liest das Integritaetslevel aus <c>TokenIntegrityLevel</c>.
    /// <para>
    /// Ein unbekanntes Level ist ein <b>Fehler</b>, kein Default. Wuerde hier
    /// stillschweigend <see cref="IntegrityLevel.Unknown"/> zurueckkommen und
    /// der Validator Unknown durchlassen, waere die
    /// Integritaetsanforderung umgehbar.
    /// </para>
    /// </summary>
    private static IntegrityLevel ReadIntegrity(SafeAccessTokenHandle token, List<string> warnings)
    {
        var size = QueryRequiredSize(token, NativeMethods.TokenIntegrityLevel, out var sizeError);
        if (size == 0)
        {
            warnings.Add(
                $"TokenIntegrityLevel nicht bestimmbar (Win32 {sizeError}). "
                + "Das Integritaetslevel ist damit unbestaetigt.");
            return IntegrityLevel.Unknown;
        }

        var buffer = Marshal.AllocHGlobal((int)size);

        try
        {
            if (!NativeMethods.GetTokenInformation(
                    token,
                    NativeMethods.TokenIntegrityLevel,
                    buffer,
                    size,
                    out _))
            {
                warnings.Add(
                    $"GetTokenInformation(TokenIntegrityLevel) fehlgeschlagen "
                    + $"(Win32 {Marshal.GetLastWin32Error()}).");
                return IntegrityLevel.Unknown;
            }

            var label = Marshal.PtrToStructure<NativeMethods.TOKEN_MANDATORY_LABEL>(buffer);
            var level = SidHelper.ReadIntegrityLevel(label.Label.Sid);

            if (level == IntegrityLevel.Unknown)
            {
                warnings.Add("Das Integritaetslevel-SID war nicht interpretierbar.");
            }

            return level;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>
    /// Liest die Package-SID aus <c>TokenAppContainerSid</c>. Ein leeres
    /// Ergebnis ist kein Fehler: ein Nicht-AppContainer hat keine.
    /// </summary>
    private static string ReadAppContainerSid(SafeAccessTokenHandle token, List<string> warnings)
    {
        var size = QueryRequiredSize(token, NativeMethods.TokenAppContainerSid, out var sizeError);

        // Kleiner als ein SID_AND_ATTRIBUTES bedeutet: kein Wert vorhanden.
        if (size < (uint)Marshal.SizeOf<NativeMethods.SID_AND_ATTRIBUTES>())
        {
            if (sizeError != 0)
            {
                warnings.Add(
                    $"TokenAppContainerSid nicht lesbar (Win32 {sizeError}); kein AppContainer.");
            }

            return string.Empty;
        }

        var buffer = Marshal.AllocHGlobal((int)size);

        try
        {
            if (!NativeMethods.GetTokenInformation(
                    token,
                    NativeMethods.TokenAppContainerSid,
                    buffer,
                    size,
                    out _))
            {
                warnings.Add(
                    $"GetTokenInformation(TokenAppContainerSid) fehlgeschlagen "
                    + $"(Win32 {Marshal.GetLastWin32Error()}).");
                return string.Empty;
            }

            var entry = Marshal.PtrToStructure<NativeMethods.SID_AND_ATTRIBUTES>(buffer);
            if (entry.Sid == IntPtr.Zero)
            {
                return string.Empty;
            }

            try
            {
                return SidHelper.ToStringSid(entry.Sid);
            }
            catch (Win32Exception ex)
            {
                warnings.Add($"Package-SID nicht formatierbar: {ex.Message}");
                return string.Empty;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>
    /// Liest die Capability-SIDs aus <c>TokenCapabilities</c>. Eine leere
    /// Liste ist der Normalfall fuer einen Agenten.
    /// </summary>
    private static List<string> ReadCapabilities(SafeAccessTokenHandle token, List<string> warnings)
    {
        var entrySize = Marshal.SizeOf<NativeMethods.SID_AND_ATTRIBUTES>();
        var size = QueryRequiredSize(token, NativeMethods.TokenCapabilities, out var sizeError);

        if (size < (uint)entrySize)
        {
            if (sizeError != 0)
            {
                warnings.Add(
                    $"TokenCapabilities nicht lesbar (Win32 {sizeError}). "
                    + "Ob der Prozess Netzwerk-Capabilities besitzt, ist damit unbestaetigt.");
            }

            return [];
        }

        var buffer = Marshal.AllocHGlobal((int)size);

        try
        {
            if (!NativeMethods.GetTokenInformation(
                    token,
                    NativeMethods.TokenCapabilities,
                    buffer,
                    size,
                    out _))
            {
                warnings.Add(
                    $"GetTokenInformation(TokenCapabilities) fehlgeschlagen "
                    + $"(Win32 {Marshal.GetLastWin32Error()}).");
                return [];
            }

            var count = (int)(size / (uint)entrySize);
            var capabilities = new List<string>(count);

            for (var i = 0; i < count; i++)
            {
                var entry = Marshal.PtrToStructure<NativeMethods.SID_AND_ATTRIBUTES>(
                    buffer + (i * entrySize));

                if (entry.Sid == IntPtr.Zero)
                {
                    continue;
                }

                try
                {
                    capabilities.Add(SidHelper.ToStringSid(entry.Sid));
                }
                catch (Win32Exception ex)
                {
                    warnings.Add($"Capability-SID nicht formatierbar: {ex.Message}");
                }
            }

            return capabilities;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>
    /// Ermittelt die benoetigte Puffergroesse fuer eine
    /// Token-Informationsklasse.
    /// </summary>
    /// <returns>
    /// Die Groesse in Byte, oder 0 wenn sie nicht ermittelbar ist.
    /// <paramref name="win32Error"/> traegt dann den Fehlercode - und ist 0,
    /// wenn die Abfrage erfolgreich war und die Groesse schlicht 0 ist.
    /// </returns>
    private static uint QueryRequiredSize(
        SafeAccessTokenHandle token,
        int informationClass,
        out int win32Error)
    {
        win32Error = 0;

        // Ein Aufruf mit Laenge 0 liefert erwartungsgemaess
        // ERROR_INSUFFICIENT_BUFFER und die benoetigte Groesse in `required`.
        if (NativeMethods.GetTokenInformation(token, informationClass, IntPtr.Zero, 0, out var required))
        {
            return required;
        }

        var error = Marshal.GetLastWin32Error();
        if (error == NativeMethods.ERROR_INSUFFICIENT_BUFFER)
        {
            return required;
        }

        win32Error = error;
        return 0;
    }

    private readonly record struct TokenSnapshot(
        bool IsAppContainer,
        IntegrityLevel Integrity,
        string PackageSid,
        IReadOnlyList<string> Capabilities);
}
