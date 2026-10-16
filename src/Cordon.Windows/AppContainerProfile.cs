using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Cordon.Windows.Interop;

namespace Cordon.Windows;

/// <summary>
/// Ein AppContainer-Profil. Das Profil ist die OS-Identitaet des Agenten:
/// seine Package-SID ist der Schluessel sowohl fuer die Pipe-DACL als auch
/// fuer die - vom Kernel durchgesetzte - Netzwerkgrenze.
/// <para>
/// Cordon legt <b>pro Agent ein eigenes Profil</b> an
/// (<c>Cordon.Sandbox.&lt;agentId&gt;</c>). Das ist der Grund, warum eine
/// globale WFP-Regel pro Package-SID ueberhaupt akzeptabel ist: die SID
/// gehoert genau einem Agenten.
/// </para>
/// </summary>
public sealed class AppContainerProfile
{
    private AppContainerProfile(string name, SecurityIdentifier packageSid, string displayName)
    {
        Name = name;
        PackageSid = packageSid;
        DisplayName = displayName;
    }

    /// <summary>Profilname, z. B. <c>Cordon.Sandbox.research</c>.</summary>
    public string Name { get; }

    /// <summary>Package-SID, z. B. <c>S-1-15-2-...</c>.</summary>
    public SecurityIdentifier PackageSid { get; }

    public string SidString => PackageSid.Value;

    public string DisplayName { get; }

    /// <summary>Name des Profils fuer einen Agenten.</summary>
    public static string NameForAgent(string agentId) =>
        $"Cordon.Sandbox.{Cordon.Core.Protocol.ProtocolVersion.Sanitize(agentId)}";

    /// <summary>
    /// Oeffnet ein vorhandenes Profil oder legt es an.
    /// <para>
    /// Wichtig: es wird <b>ohne</b> Capabilities angelegt. Ein AppContainer
    /// mit <c>internetClient</c> haette vollen Netzzugang und wuerde die
    /// gesamte Architektur aufheben.
    /// </para>
    /// </summary>
    public static AppContainerProfile Ensure(string agentId)
    {
        var name = NameForAgent(agentId);
        var displayName = $"Cordon Sandbox ({agentId})";

        var sidPtr = CreateOrGet(name, displayName, $"Isolationsprofil fuer Agent '{agentId}'.");
        try
        {
            var sid = new SecurityIdentifier(SidHelper.ToStringSid(sidPtr));
            return new AppContainerProfile(name, sid, displayName);
        }
        finally
        {
            FreeProfileSid(sidPtr);
        }
    }

    /// <summary>Loest die Package-SID eines Profils auf, ohne es anzulegen.</summary>
    public static SecurityIdentifier? TryResolve(string agentId)
    {
        var name = NameForAgent(agentId);
        var hr = NativeMethods.DeriveAppContainerSidFromAppContainerName(name, out var sidPtr);

        if (hr != 0 || sidPtr == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            return new SecurityIdentifier(SidHelper.ToStringSid(sidPtr));
        }
        finally
        {
            FreeProfileSid(sidPtr);
        }
    }

    /// <summary>
    /// Loescht das Profil. Die SID bleibt danach als Waise im System, bis
    /// das naechste Mal ein Profil mit demselben Namen erzeugt wird - das ist
    /// Windows-Verhalten und wird hier nicht umgangen.
    /// </summary>
    public static bool Delete(string agentId)
    {
        var name = NameForAgent(agentId);
        var hr = NativeMethods.DeleteAppContainerProfile(name);

        // S_OK oder "existiert nicht" gelten beide als Erfolg.
        return hr is 0 or NativeMethods.HRESULT_ALREADY_EXISTS or unchecked((int)0x80070002);
    }

    /// <summary>
    /// Uebernimmt die SID in ein neu allokiertes, eigenstaendig
    /// freigebbares Handle. Wird fuer <c>CreateProcess</c> benoetigt, weil
    /// die dort uebergebene <c>SECURITY_CAPABILITIES</c>-Struktur bis zum
    /// Ende der Erzeugung gueltig bleiben muss.
    /// </summary>
    public IntPtr AcquireNativeSid()
    {
        return SidHelper.FromStringSid(SidString);
    }

    /// <summary>Gibt eine mit <see cref="AcquireNativeSid"/> geholte SID frei.</summary>
    public static void ReleaseNativeSid(IntPtr sid)
    {
        if (sid != IntPtr.Zero)
        {
            _ = NativeMethods.LocalFree(sid);
        }
    }

    private static IntPtr CreateOrGet(string name, string displayName, string description)
    {
        // Keine Capabilities: das ist die gesamte Netzwerkgrenze.
        // capabilities = nullptr, capabilityCount = 0
        var hr = NativeMethods.CreateAppContainerProfile(
            name,
            displayName,
            description,
            IntPtr.Zero,
            0,
            out var sidPtr);

        if (hr == 0 && sidPtr != IntPtr.Zero)
        {
            return sidPtr;
        }

        if (hr == NativeMethods.HRESULT_ALREADY_EXISTS || hr == unchecked((int)0x800700B7))
        {
            // Profil existiert bereits: SID ableiten statt neu anlegen.
            var deriveHr = NativeMethods.DeriveAppContainerSidFromAppContainerName(name, out var existing);
            if (deriveHr == 0 && existing != IntPtr.Zero)
            {
                return existing;
            }

            throw new Win32Exception(
                deriveHr,
                $"AppContainer-Profil '{name}' existiert, aber die SID liess sich nicht ableiten.");
        }

        throw new Win32Exception(
            hr,
            $"CreateAppContainerProfile('{name}') fehlgeschlagen. "
            + "Benoetigt Windows 8 oder neuer und ausreichende Rechte.");
    }

    private static void FreeProfileSid(IntPtr sidPtr)
    {
        if (sidPtr != IntPtr.Zero)
        {
            // Die von CreateAppContainerProfile /
            // DeriveAppContainerSidFromAppContainerName gelieferten SIDs
            // werden von Windows mit LocalAlloc erzeugt und daher mit
            // LocalFree freigegeben (nicht mit FreeSid).
            _ = NativeMethods.LocalFree(sidPtr);
        }
    }
}
