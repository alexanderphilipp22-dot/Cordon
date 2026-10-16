using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Cordon.Gateway;

/// <summary>
/// Erzeugt die ACL fuer eine Agent-Pipe.
/// <para>
/// Die DACL ist die <b>erste</b> der beiden Identitaetsbindungen: sie laesst
/// ausschliesslich die Package-SID des Agenten und LocalSystem/Administratoren
/// zu. Kein <c>Everyone</c>, keine <c>Authenticated Users</c>.
/// </para>
/// </summary>
public static class PipeSecurityFactory
{
    /// <summary>
    /// Rechte, die ein Agent auf der Pipe benoetigt: Lesen, Schreiben und
    /// Synchronisieren. <b>Kein</b> <c>ChangePermissions</c> und kein
    /// <c>TakeOwnership</c> - der Agent darf die Grenze nicht umkonfigurieren.
    /// </summary>
    private const PipeAccessRights AgentRights =
        PipeAccessRights.ReadData
        | PipeAccessRights.WriteData
        | PipeAccessRights.ReadAttributes
        | PipeAccessRights.ReadExtendedAttributes
        | PipeAccessRights.WriteExtendedAttributes
        | PipeAccessRights.Synchronize;

    /// <summary>
    /// Baut die Sicherheitsbeschreibung fuer die Pipe eines Agenten.
    /// </summary>
    /// <param name="packageSid">Package-SID des AppContainers.</param>
    public static PipeSecurity Create(SecurityIdentifier packageSid)
    {
        ArgumentNullException.ThrowIfNull(packageSid);

        var security = new PipeSecurity();

        // Der Agent selbst: minimale Rechte.
        security.AddAccessRule(new PipeAccessRule(
            packageSid,
            AgentRights,
            AccessControlType.Allow));

        // LocalSystem: Vollzugriff, damit der Dienst Administrationsaufgaben
        // (z. B. kontrolliertes Trennen) ausfuehren kann.
        var localSystem = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        security.AddAccessRule(new PipeAccessRule(
            localSystem,
            PipeAccessRights.FullControl,
            AccessControlType.Allow));

        // Administratoren: Vollzugriff fuer Diagnose. Bewusst kein Vollzugriff
        // fuer "Authenticated Users".
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        security.AddAccessRule(new PipeAccessRule(
            administrators,
            PipeAccessRights.FullControl,
            AccessControlType.Allow));

        return security;
    }

    /// <summary>
    /// Erzeugt eine Server-Instanz der Agent-Pipe.
    /// </summary>
    /// <param name="agentId">Agent-Id; bestimmt den Pipe-Namen.</param>
    /// <param name="packageSid">Package-SID fuer die DACL.</param>
    /// <param name="maxInstances">Maximale Anzahl gleichzeitiger Instanzen.</param>
    /// <remarks>
    /// Die DACL ist die einzige Zugriffsgrenze auf dieser Pipe. Der Dienst
    /// laeuft als LocalSystem; ein Agent kann die ACL nicht aendern, weil
    /// ihm <c>ChangePermissions</c> und <c>TakeOwnership</c> fehlen.
    /// <para>
    /// <b>Offener Punkt:</b> <c>PIPE_REJECT_REMOTE_CLIENTS</c> laesst sich
    /// ueber die oeffentliche <see cref="NamedPipeServerStream"/>-API nicht
    /// setzen. In Iteration 1 wird der Schutz allein von der DACL getragen -
    /// sie enthaelt keine Netzwerk-Identitaeten, also kann kein
    /// SMB-Aufrufer von einem anderen Rechner die Pipe oeffnen. Fuer
    /// Iteration 2 ist die Pipe ueber <c>CreateNamedPipeW</c> mit explizitem
    /// <c>PIPE_REJECT_REMOTE_CLIENTS</c> zu erzeugen (siehe
    /// docs/ARCHITECTURE.md, Abschnitt 9).
    /// </para>
    /// </remarks>
    public static NamedPipeServerStream CreateInstance(
        string agentId,
        SecurityIdentifier packageSid,
        int maxInstances = 4)
    {
        var pipeName = Core.Protocol.ProtocolVersion.PipeNameFor(agentId);
        var security = Create(packageSid);

        return NamedPipeServerStreamAcl.Create(
            pipeName,
            PipeDirection.InOut,
            maxInstances,
            // Byte-Modus: Cordon rahmt selbst und bleibt damit unabhaengig
            // von der Nachrichten-Semantik des OS.
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.WriteThrough,
            inBufferSize: 64 * 1024,
            outBufferSize: 64 * 1024,
            pipeSecurity: security,
            HandleInheritability.None);
    }
}
