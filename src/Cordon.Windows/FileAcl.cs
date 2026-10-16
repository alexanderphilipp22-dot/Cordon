using System.Security.AccessControl;
using System.Security.Principal;

namespace Cordon.Windows;

/// <summary>
/// Setzt Datei- und Verzeichnis-ACLs fuer Cordon-Daten.
/// <para>
/// Die ACLs sind sicherheitsrelevant: das Audit-Verzeichnis darf fuer einen
/// Agenten nicht schreibbar sein, und der CA-Schluessel nicht lesbar. Beide
/// Rechte sind im Bedrohungsmodell vorausgesetzt und wuerden ohne
/// explizite ACL von der Vererbung des uebergeordneten Verzeichnisses
/// abhaengen.
/// </para>
/// </summary>
public static class FileAcl
{
    /// <summary>
    /// Beschraenkt eine Datei auf LocalSystem (Vollzugriff) und
    /// Administratoren (Lesen). Vererbung wird abgeschaltet.
    /// </summary>
    public static void RestrictFileToAdministrators(string filePath, bool administratorsCanWrite = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        ApplyStandardRules(security, administratorsCanWrite);

        new FileInfo(filePath).SetAccessControl(security);
    }

    /// <summary>
    /// Wie <see cref="RestrictFileToAdministrators"/>, aber fuer ein
    /// Verzeichnis und mit Vererbung auf neue Dateien.
    /// </summary>
    public static void RestrictDirectoryToAdministrators(string directoryPath, bool administratorsCanWrite = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directoryPath);

        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        ApplyStandardRules(security, administratorsCanWrite);

        new DirectoryInfo(directoryPath).SetAccessControl(security);
    }

    /// <summary>
    /// Ergibt die ACL fuer das Audit-Verzeichnis: LocalSystem schreibt,
    /// Administratoren lesen. Ein Agent hat hier keinen Eintrag und damit
    /// keinen Zugriff - die Voraussetzung dafuer, dass das Audit-Log als
    /// Beweismittel taugt.
    /// </summary>
    public static void SecureAuditDirectory(string directoryPath) =>
        RestrictDirectoryToAdministrators(directoryPath, administratorsCanWrite: false);

    /// <summary>Ergibt die ACL fuer das CA-Verzeichnis: nur LocalSystem.</summary>
    public static void SecureCaDirectory(string directoryPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directoryPath);

        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        var localSystem = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        security.AddAccessRule(new FileSystemAccessRule(
            localSystem,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));

        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        security.AddAccessRule(new FileSystemAccessRule(
            administrators,
            FileSystemRights.Read | FileSystemRights.Write,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));

        new DirectoryInfo(directoryPath).SetAccessControl(security);
    }

    /// <summary>
    /// Prueft, ob der aktuell ausfuehrende Prozess erhoehte Rechte hat.
    /// Die WFP- und AppContainer-Profil-Erstellung scheitert ohne sie.
    /// </summary>
    public static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>Name des aktuellen Benutzers fuer Diagnoseausgaben.</summary>
    public static string CurrentUserName()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.Name;
    }

    private static void ApplyStandardRules(FileSystemSecurity security, bool administratorsCanWrite)
    {
        var localSystem = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

        security.AddAccessRule(new FileSystemAccessRule(
            localSystem,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));

        security.AddAccessRule(new FileSystemAccessRule(
            administrators,
            administratorsCanWrite
                ? FileSystemRights.FullControl
                : FileSystemRights.ReadAndExecute,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
    }
}
